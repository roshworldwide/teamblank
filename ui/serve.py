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
import webbrowser

REPO = pathlib.Path(__file__).resolve().parents[1]
UI = REPO / "ui"
EXE = ".exe" if os.name == "nt" else ""
CARVE = REPO / f"core/target/release/carve{EXE}"
WIPE = REPO / f"core/target/release/wipe{EXE}"
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
    for label, path in (("carve", CARVE), ("wipe", WIPE)):
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
    """Runs carve -> wipe -> carve and yields events as it goes.

    Every event carries only values the engine produced. The elapsed figures are
    measured here with perf_counter and labelled as this server's measurement,
    never as the engine's own.
    """

    def __init__(self, emit):
        self.emit = emit

    def _run(self, argv, ok=(0,)):
        t0 = time.perf_counter()
        proc = subprocess.run([str(a) for a in argv], capture_output=True, text=True)
        elapsed = time.perf_counter() - t0
        if proc.returncode not in ok:
            raise RuntimeError(
                f"{pathlib.Path(argv[0]).name} exited {proc.returncode}: "
                f"{proc.stderr.strip()[-400:]}")
        return elapsed, proc.stdout

    def _wipe_with_live_trace(self, target):
        """Start the wipe, tail its trace file, forward frames as they land.

        The engine writes one JSON object per line as it works. Reading that
        file while the process runs is what makes the browser's numbers live
        rather than a re-enactment: each frame reaches the page within a few
        milliseconds of the sector range it describes being written.
        """
        trace = WORK / "telemetry.jsonl"
        # The engine opens the trace with mode "x" and refuses a path that
        # already exists — DENY_TARGET_ALREADY_EXISTS. So it must not be
        # pre-created here; wait for the engine to make it, then tail it.
        argv = [str(WIPE), "--target", str(target), "--allow-root", str(WORK),
                "--i-understand", str(target), "--period-ms", "8",
                "--trace", str(trace)]
        # stdout goes to a FILE, never a pipe. The wipe report is ~90 KB and a
        # pipe nobody drains fills its OS buffer, blocks the writer, and the
        # process never exits — which deadlocks the tail loop below against a
        # child that is waiting on us.
        rep = WORK / "wipe.json"
        errf = WORK / "wipe.stderr"
        t0 = time.perf_counter()
        with open(rep, "w", encoding="utf-8") as so, open(errf, "w", encoding="utf-8") as se:
            proc = subprocess.Popen(argv, stdout=so, stderr=se, text=True)
            while not trace.exists():
                if proc.poll() is not None:
                    break                              # it failed before writing
                time.sleep(0.002)
            sent = 0
            if not trace.exists():
                proc.wait()
                raise RuntimeError(f"wipe exited {proc.returncode}: "
                                   f"{errf.read_text(encoding='utf-8').strip()[-400:]}")
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
                        continue                      # a half-written line
                    if ev.get("ev") == "progress":
                        sent += 1
                        self.emit("frame", ev)
                    continue
                if proc.poll() is not None:
                    # drain whatever landed between the last read and exit
                    rest = fh.read()
                    for tail in rest.splitlines():
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
            proc.wait()
        elapsed = time.perf_counter() - t0
        if proc.returncode != 0:
            raise RuntimeError(f"wipe exited {proc.returncode}: "
                               f"{errf.read_text(encoding='utf-8').strip()[-400:]}")
        return elapsed, rep.read_text(encoding="utf-8"), sent

    def go(self):
        ready = readiness()
        if not ready["ready"]:
            self.emit("error", {"message": "the engine is not runnable here",
                                "missing": ready["missing"]})
            return

        before = sha256(IMG)
        self.emit("start", {
            "fixture_sha256": before,
            "capacity_bytes": IMG.stat().st_size,
            "note": "the wipe runs against a copy in out/live-run; "
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

        self.emit("phase", {"name": "carve_pre", "state": "begin"})
        el, out = self._run([CARVE, "--phase", "pre-wipe", "--manifest", MANIFEST,
                             "--image-path", IMG, target])
        pre = json.loads(out)
        (WORK / "carve_pre.json").write_text(out)
        self.emit("carve_pre", {"counts": pre["counts"], "elapsed_s": round(el, 6)})

        self.emit("phase", {"name": "wipe", "state": "begin"})
        el, out, frames = self._wipe_with_live_trace(target)
        wipe = json.loads(out)
        self.emit("wipe", {
            "elapsed_s": round(el, 6),
            "frames_streamed": frames,
            "device": wipe["device"],
            "dispatch": wipe["dispatch"],
            "overwrite": wipe["overwrite"],
            "telemetry": wipe["telemetry"],
            "audit": wipe["audit"],
            "verification": wipe["verification"],
            "outcome": wipe["outcome"],
            "entropy": wipe["entropy_bits_per_byte"],
            "limits": wipe["limits"],
            "run": wipe["run"],
            "authorization": wipe["authorization"],
            "probe": wipe.get("calibration_probe"),
        })

        self.emit("phase", {"name": "carve_post", "state": "begin"})
        # exit 1 from carve post-wipe means "no candidate reached the gate",
        # which is the result this whole demo exists to produce, not a failure.
        el, out = self._run([CARVE, "--phase", "post-wipe", "--manifest", MANIFEST,
                             "--image-path", IMG, target], ok=(0, 1))
        post = json.loads(out)
        (WORK / "carve_post.json").write_text(out)
        self.emit("carve_post", {"counts": post["counts"], "elapsed_s": round(el, 6)})

        after = sha256(IMG)
        if after != before:
            self.emit("error", {
                "message": "THE FIXTURE CHANGED — a wipe reached out/fixture.img",
                "before": before, "after": after})
            print("serve: FIXTURE CHANGED. Stop and investigate.", file=sys.stderr)
            return

        self.emit("done", {
            "fixture_sha256_after": after,
            "fixture_unchanged": True,
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
        return super().do_GET()

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
                    emit("error", {"message": str(exc)})
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
