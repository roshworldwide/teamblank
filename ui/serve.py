#!/usr/bin/env python3
"""The presentation server: serves ui/ and runs the real engine on request.

Start this once before presenting, then drive the demo from the browser:

    python ui/serve.py

It binds 127.0.0.1 only, uses nothing outside the standard library, and makes
no outbound connection of any kind. An air-gapped machine runs it unchanged.

WHY IT EXISTS. ui/instrument.html can replay a recorded run from a file:// URL
with no server at all, and that stays true. But a page opened from file:// can
never start a process, so the RUN button needs something local to ask. This is
that something and nothing more: three subprocess calls in a fixed order, with
the trace file tailed while the wipe runs so the browser sees frames as they
are measured rather than after the fact.

SAFETY, and it is the same rule the rest of the repo follows. The wipe NEVER
targets out/fixture.img. It runs against a copy inside out/live-run, with
--allow-root pointed at that directory, so the guard's containment check is
what stops a mistake rather than this file's good intentions. The fixture's
sha256 is taken before and re-verified after; a change is a hard failure that
is reported to the browser and logged here.

Endpoints:
    GET  /                  -> ui/index.html
    GET  /<file>            -> anything under ui/, served literally
    GET  /api/status        -> can the engine run on this machine, and why not
    GET  /api/run           -> Server-Sent Events, one event per phase and per
                               telemetry frame, ending in the full reports
"""
from __future__ import annotations

import hashlib
import http.server
import json
import os
import pathlib
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser

REPO = pathlib.Path(__file__).resolve().parents[1]
UI = REPO / "ui"
# ui/ on the path so `import usb` works however this file was invoked --
# python ui/serve.py puts it there, `python -m` and an IDE runner do not.
if str(UI) not in sys.path:
    sys.path.insert(0, str(UI))
EXE = ".exe" if os.name == "nt" else ""
CARVE = REPO / f"core/target/release/carve{EXE}"
WIPE = REPO / f"core/target/release/wipe{EXE}"
VERIFY = REPO / f"core/target/release/verify{EXE}"
IMG = REPO / "out/fixture.img"
MANIFEST = REPO / "out/fixture.manifest.json"
WORK = REPO / "out/live-run"

HOST, PORT = "127.0.0.1", 8787

# One run at a time. A second RUN press while the engine is working is refused
# rather than queued: two wipes against one target is not a thing to be clever
# about.
_RUN_LOCK = threading.Lock()


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def readiness() -> dict:
    """Everything that has to be true before RUN can mean anything."""
    missing = []
    for label, path in (("carve", CARVE), ("wipe", WIPE),
                        ("verify", VERIFY)):
        if not path.exists():
            missing.append(f"{path.relative_to(REPO)} — build it: "
                           f"cd core && cargo build --release")
    for label, path in (("image", IMG), ("manifest", MANIFEST)):
        if not path.exists():
            missing.append(f"{path.relative_to(REPO)} — build it: make fixtures")
    return {
        "ready": not missing,
        "missing": missing,
        "image_bytes": IMG.stat().st_size if IMG.exists() else None,
        "repo": str(REPO),
    }


class Runner:
    """Drives `verify`, which is the whole loop in one process.

    Phase 4 replaced three binaries called by argv with one that carves, wipes,
    carves again, signs the certificate and appends to the chain. Calling that
    here rather than re-orchestrating the three is not a convenience: `verify`
    enforces parameter identity between the two carves BY CONSTRUCTION, which
    is the entire claim the second carve exists to support. Re-driving the
    binaries separately would hand that guarantee back to this file, and this
    file is not where it belongs.

    Frames still reach the browser live, because the engine writes its trace as
    it works and this tails the file while the process runs. The phase strip is
    inferred from that trace -- no trace yet means the first carve is running,
    a trace being appended to means the wipe is, frames stopping while the
    process still lives means the second carve is -- and every elapsed figure
    says which clock produced it.
    """

    def __init__(self, emit):
        self.emit = emit

    def go(self):
        ready = readiness()
        if not ready["ready"]:
            self.emit("failed", {"message": "the engine is not runnable here",
                                "missing": ready["missing"]})
            return

        before = sha256(IMG)
        self.emit("start", {
            "fixture_sha256": before,
            "capacity_bytes": IMG.stat().st_size,
            "note": "the loop runs against a copy in out/live-run; "
                    "out/fixture.img is never a target",
        })

        if WORK.exists():
            shutil.rmtree(WORK)
        WORK.mkdir(parents=True)
        target = WORK / "medium.img"

        self.emit("phase", {"name": "copy", "state": "begin"})
        t0 = time.perf_counter()
        shutil.copy2(IMG, target)
        self.emit("phase", {"name": "copy", "state": "end",
                            "elapsed_s": round(time.perf_counter() - t0, 6)})

        trace = WORK / "telemetry.jsonl"
        bundle_path = WORK / "bundle.json"
        outf, errf = WORK / "verify.stdout", WORK / "verify.stderr"
        argv = [str(VERIFY),
                "--target", str(target), "--allow-root", str(WORK),
                "--i-understand", str(target), "--manifest", str(MANIFEST),
                "--chain", str(WORK / "chain.txt"),
                "--key", str(WORK / "operator.key"),
                "--trace", str(trace), "--period-ms", "8",
                "--out", str(bundle_path)]

        self.emit("phase", {"name": "carve_pre", "state": "begin"})
        t_run = time.perf_counter()
        sent = 0
        t_carve_pre = 0.0
        # stdout to a FILE, never a pipe: an undrained pipe fills its OS buffer,
        # blocks the child, and deadlocks the tail loop against a process that
        # is itself waiting on us.
        with open(outf, "w", encoding="utf-8") as so:
            with open(errf, "w", encoding="utf-8") as se:
                proc = subprocess.Popen(argv, stdout=so, stderr=se, text=True)

                # the first carve owns all the time before any trace exists
                while not trace.exists() and proc.poll() is None:
                    time.sleep(0.002)
                t_carve_pre = time.perf_counter() - t_run

                if trace.exists():
                    self.emit("phase", {"name": "carve_pre", "state": "end",
                                        "elapsed_s": round(t_carve_pre, 6),
                                        "source": "server clock"})
                    self.emit("phase", {"name": "wipe", "state": "begin"})
                    t_wipe = time.perf_counter()
                    with open(trace, "r", encoding="utf-8") as fh:
                        while True:
                            line = fh.readline()
                            if line:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    ev = json.loads(line)
                                except json.JSONDecodeError:
                                    continue          # a half-written line
                                if ev.get("ev") == "progress":
                                    sent += 1
                                    self.emit("frame", ev)
                                continue
                            if proc.poll() is not None:
                                for tail in fh.read().splitlines():
                                    tail = tail.strip()
                                    if not tail:
                                        continue
                                    try:
                                        ev = json.loads(tail)
                                    except json.JSONDecodeError:
                                        continue
                                    if ev.get("ev") == "progress":
                                        sent += 1
                                        self.emit("frame", ev)
                                break
                            time.sleep(0.002)
                    # This window ends when the PROCESS ends, not when the
                    # wipe does, so it silently contains the second carve. It
                    # is not published as a duration; the engine reports the
                    # wipe exactly and the remainder is attributed below.
                    t_tail = time.perf_counter() - t_wipe
                    self.emit("phase", {"name": "wipe", "state": "end"})
                    self.emit("phase", {"name": "carve_post", "state": "begin"})
                proc.wait()
        rc = proc.returncode
        elapsed = time.perf_counter() - t_run

        # 0 is the claim holding. 7 is SURVIVORS: an admitted candidate outlived
        # the wipe. The bundle is still written and the page still shows it,
        # because evidence of a failure is still evidence -- but it is reported
        # as a failure, never quietly.
        if rc not in (0, 7) or not bundle_path.exists():
            self.emit("failed", {
                "message": "verify exited %d: %s" % (
                    rc, errf.read_text(encoding="utf-8").strip()[-400:])})
            return

        bundle = json.loads(bundle_path.read_bytes())
        wipe = bundle["wipe"]
        self.emit("phase", {"name": "carve_post", "state": "end"})

        self.emit("carve_pre", {"counts": bundle["carve_pre"]["counts"],
                                "elapsed_s": round(t_carve_pre, 6),
                                "source": "server clock"})
        self.emit("wipe", {
            "elapsed_s": round(wipe["overwrite"]["duration_ns"] / 1e9, 9),
            "source": "engine",
            "frames_streamed": sent,
            "device": wipe["device"], "dispatch": wipe["dispatch"],
            "overwrite": wipe["overwrite"], "telemetry": wipe["telemetry"],
            "audit": wipe["audit"], "verification": wipe["verification"],
            "outcome": wipe["outcome"], "entropy": wipe["entropy_bits_per_byte"],
            "limits": wipe["limits"], "run": wipe["run"],
            "authorization": wipe["authorization"],
        })
        # what is left after the first carve and the engine's own wipe figure
        engine_wipe_s = wipe["overwrite"]["duration_ns"] / 1e9
        remainder = elapsed - t_carve_pre - engine_wipe_s
        self.emit("carve_post", {
            "counts": bundle["carve_post"]["counts"],
            "elapsed_s": round(remainder, 6) if remainder > 0 else None,
            "source": "server clock, remainder"})

        # The ledger, with the canonical bytes produced the same way
        # ui/build_payload.py produces them, so the page hashes exactly what the
        # engine signed. If that import fails the page is told it has no
        # canonical bytes rather than shown something close to them.
        ledger = {"signed_certificate": bundle["signed_certificate"],
                  "chain": bundle["chain"]}
        try:
            sys.path.insert(0, str(REPO / "py"))
            from sentinelwipe.canon import canonicalize
            ledger["certificate_canonical"] = canonicalize(
                bundle["signed_certificate"]["certificate"]).decode("utf-8")
        except Exception as exc:
            ledger["certificate_canonical"] = None
            ledger["canonical_unavailable"] = str(exc)
        self.emit("ledger", ledger)

        after = sha256(IMG)
        if after != before:
            self.emit("failed", {
                "message": "THE FIXTURE CHANGED - a wipe reached out/fixture.img",
                "before": before, "after": after})
            print("serve: FIXTURE CHANGED. Stop and investigate.", file=sys.stderr)
            return

        self.emit("done", {
            "fixture_sha256_after": after,
            "fixture_unchanged": True,
            "exit_code": rc,
            "survivors": rc == 7,
            "bundle": str(bundle_path.relative_to(REPO)),
            "elapsed_s": round(elapsed, 6),
        })


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(UI), **kw)

    def log_message(self, fmt, *args):      # one line per request, not three
        if self.path.startswith("/api/"):
            sys.stderr.write(f"serve: {self.path}\n")

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/favicon.ico":
            # No icon ships with the pages. Answering 204 keeps the browser
            # console clean, which matters because "no console errors" is a
            # thing this demo claims out loud.
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/api/status"):
            return self._json(readiness())
        if self.path.startswith("/api/run"):
            return self._sse_run()
        if self.path.startswith("/api/usb/volumes"):
            return self._usb_volumes()
        if self.path.startswith("/api/usb/enrol"):
            return self._usb_enrol()
        if self.path.startswith("/api/usb/recover"):
            return self._sse_recover()
        return super().do_GET()

    # ---- removable media --------------------------------------------------
    # Read-only, all three. ui/usb.py opens every volume handle "rb" and there
    # is no write path in it: this half of the product recovers, it never wipes.
    # The wipe is demonstrated against a loopback image and nothing else.
    def _letter(self):
        q = urllib.parse.urlparse(self.path).query
        return urllib.parse.parse_qs(q).get("letter", [""])[0]

    def _usb_volumes(self):
        try:
            import usb
            return self._json({"volumes": usb.volumes()})
        except Exception as exc:
            return self._json({"error": str(exc)}, 500)

    def _usb_enrol(self):
        letter = self._letter()
        try:
            import usb
            e = usb.enrol(letter)
            usb.WORK.mkdir(parents=True, exist_ok=True)
            (usb.WORK / "enrolment.json").write_text(
                json.dumps(e, indent=2), encoding="utf-8")
            # the file list goes back so the page can name what will and will
            # not come back BEFORE anything is deleted
            return self._json(e)
        except (ValueError, PermissionError, FileNotFoundError) as exc:
            return self._json({"error": str(exc)}, 400)
        except Exception as exc:
            return self._json({"error": str(exc)}, 500)

    def _sse_recover(self):
        letter = self._letter()
        if not _RUN_LOCK.acquire(blocking=False):
            return self._json({"error": "a run is already in progress"}, 409)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()

            def emit(kind, payload):
                self.wfile.write(
                    f"event: {kind}\ndata: {json.dumps(payload)}\n\n".encode("utf-8"))
                self.wfile.flush()

            try:
                import usb
                enr = usb.WORK / "enrolment.json"
                if not enr.exists():
                    raise RuntimeError(
                        "nothing was enrolled. Hash the volume BEFORE deleting "
                        "from it, or there is no ground truth to compare against.")
                enrolment = json.loads(enr.read_bytes())
                v = usb._require_removable(letter)
                emit("start", {"volume": v, "enrolled": enrolment["count"],
                               "carvable": enrolment["carvable"]})

                emit("phase", {"name": "image", "state": "begin"})
                last = [0.0]

                def prog(done, total, secs):
                    # throttled: the browser does not need 2,000 events
                    if secs - last[0] < 0.12:
                        return
                    last[0] = secs
                    emit("imaging", {"done": done, "total": total,
                                     "elapsed_s": round(secs, 6),
                                     "bps": round(done / secs, 6) if secs else None})

                img = usb.image_volume(letter, usb.WORK / "evidence.img", progress=prog)
                emit("phase", {"name": "image", "state": "end"})
                emit("image", img)

                emit("phase", {"name": "carve", "state": "begin"})
                report, secs = usb.carve_image(usb.WORK / "evidence.img",
                                               usb.WORK / "carve.json")
                emit("phase", {"name": "carve", "state": "end"})
                emit("carve", {"counts": report["counts"], "elapsed_s": secs,
                               "policy": report["policy"]})

                res = usb.compare(enrolment, report, img,
                                  usb.WORK / "evidence.img")
                emit("compare", res)

                # The recovered objects as real files. Never onto the volume
                # they came from -- extract() refuses a destination on the
                # source drive, because writing there can overwrite bytes not
                # yet carved.
                ex = usb.extract(res["hits"], usb.WORK / "evidence.img",
                                 usb.WORK / "recovered", source_letter=letter)
                emit("extracted", {k: ex[k] for k in ("dir", "count", "verified")})

                (usb.WORK / "result.json").write_text(
                    json.dumps({"image": img, "compare": res, "extracted": ex},
                               indent=2), encoding="utf-8")
                emit("done", {"artifacts": str(usb.WORK)})
            except BrokenPipeError:
                pass
            except Exception as exc:
                try:
                    emit("failed", {"message": str(exc)})
                except Exception:
                    pass
        finally:
            _RUN_LOCK.release()

    def _sse_run(self):
        if not _RUN_LOCK.acquire(blocking=False):
            return self._json({"error": "a run is already in progress"}, 409)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()

            def emit(kind, payload):
                line = f"event: {kind}\ndata: {json.dumps(payload)}\n\n"
                self.wfile.write(line.encode("utf-8"))
                self.wfile.flush()

            try:
                Runner(emit).go()
            except BrokenPipeError:
                pass                                   # the tab went away
            except Exception as exc:                   # report, never a 500 page
                try:
                    emit("failed", {"message": str(exc)})
                except Exception:
                    pass
        finally:
            _RUN_LOCK.release()


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    r = readiness()
    print(f"sentinelwipe: serving {UI.relative_to(REPO)} on http://{HOST}:{PORT}/")
    print(f"              127.0.0.1 only · no outbound connection · stdlib only")
    if r["ready"]:
        print(f"              engine READY — the RUN button will execute "
              f"{r['image_bytes']:,} bytes for real")
    else:
        print("              engine NOT runnable; the page will fall back to replay:")
        for m in r["missing"]:
            print(f"                - {m}")
    print("              ctrl-C to stop")
    srv = Server((HOST, PORT), Handler)
    try:
        webbrowser.open(f"http://{HOST}:{PORT}/")
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nsentinelwipe: stopped")


if __name__ == "__main__":
    main()
