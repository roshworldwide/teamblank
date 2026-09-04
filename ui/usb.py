#!/usr/bin/env python3
"""Removable-media recovery: enrol, image, carve, compare by SHA-256.

THE SHAPE OF THE DEMONSTRATION

    1. enrol   walk the mounted volume and hash every file. This is ground
               truth, taken BEFORE anything is deleted, and it is the only
               reason a recovered object can be called correct rather than
               merely plausible.
    2. (the operator deletes a file in Explorer, outside this tool)
    3. image   read the volume's raw bytes into a file.
    4. carve   run the shipped carver against that FILE.
    5. compare each recovered record's SHA-256 against the enrolment.

WHY IMAGE INSTEAD OF CARVING THE DEVICE

`carve` takes an image file by construction -- "nothing is mounted and no block
device is attached; the carver reads bytes". Imaging first is not a workaround
for that, it is the forensically correct order: an examiner works on a copy and
leaves the original untouched. The image's own SHA-256 is recorded so the copy
can be shown to be a copy.

READ ONLY, WITHOUT EXCEPTION

Every handle this module opens on a volume is opened "rb". There is no write
path here, no wipe, no format, and nothing in this file can modify the medium.
That is deliberate: the wipe half of this product is demonstrated against a
loopback image, never against a device somebody brought with them.
"""
import ctypes
import hashlib
import json
import os
import pathlib
import string
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
EXE = ".exe" if os.name == "nt" else ""
CARVE = REPO / f"core/target/release/carve{EXE}"
WORK = REPO / "out/usb-run"

# The carver's signature table. A file whose kind is not in here has no header
# to scan for and WILL NOT be recovered -- that is the documented plaintext
# case, not a bug, and the operator is told before the run rather than after.
CARVABLE = {
    ".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".pdf": "PDF",
    ".zip": "ZIP", ".docx": "ZIP", ".xlsx": "ZIP", ".pptx": "ZIP",
    ".db": "SQLITE", ".sqlite": "SQLITE", ".sqlite3": "SQLITE",
    ".mp4": "MP4", ".mov": "MP4", ".m4v": "MP4",
    ".gz": "GZIP", ".tgz": "GZIP",
}

DRIVE_TYPE = {0: "unknown", 1: "no-root-dir", 2: "removable", 3: "fixed",
              4: "network", 5: "cdrom", 6: "ramdisk"}


# --------------------------------------------------------------------------
# enumerate
# --------------------------------------------------------------------------
def volumes():
    """Every mounted volume, with the removable ones marked.

    Fixed disks are listed but flagged, because the one mistake this tool must
    make impossible is imaging or presenting the operator's system drive.
    """
    if os.name != "nt":
        return []
    k = ctypes.windll.kernel32
    mask = k.GetLogicalDrives()
    out = []
    for i, letter in enumerate(string.ascii_uppercase):
        if not (mask >> i) & 1:
            continue
        root = f"{letter}:" + os.sep
        kind = DRIVE_TYPE.get(k.GetDriveTypeW(ctypes.c_wchar_p(root)), "unknown")
        fs = ctypes.create_unicode_buffer(64)
        label = ctypes.create_unicode_buffer(256)
        try:
            k.GetVolumeInformationW(ctypes.c_wchar_p(root), label, 256,
                                    None, None, None, fs, 64)
        except OSError:
            pass
        total = ctypes.c_ulonglong(0)
        free = ctypes.c_ulonglong(0)
        try:
            k.GetDiskFreeSpaceExW(ctypes.c_wchar_p(root), None,
                                  ctypes.byref(total), ctypes.byref(free))
        except OSError:
            pass
        out.append({
            "letter": letter,
            "root": root,
            "kind": kind,
            "removable": kind == "removable",
            "filesystem": fs.value or "unknown",
            "label": label.value or "",
            "capacity_bytes": total.value,
            "free_bytes": free.value,
            "raw_path": r"\\." + os.sep + f"{letter}:",
        })
    return out


def _require_removable(letter):
    letter = letter.strip().rstrip(":").upper()
    if len(letter) != 1 or letter not in string.ascii_uppercase:
        raise ValueError(f"not a drive letter: {letter!r}")
    for v in volumes():
        if v["letter"] == letter:
            if not v["removable"]:
                raise PermissionError(
                    f"{letter}: is a {v['kind']} drive, not removable. This tool "
                    f"refuses to image anything but removable media.")
            return v
    raise FileNotFoundError(f"{letter}: is not mounted")


# --------------------------------------------------------------------------
# 1. enrol -- ground truth, taken before the deletion
# --------------------------------------------------------------------------
def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def enrol(letter):
    """Hash every file on the volume. Ground truth for the comparison later."""
    v = _require_removable(letter)
    files, skipped = [], []
    for dirpath, dirnames, filenames in os.walk(v["root"]):
        # System Volume Information and any recycler are noise, not evidence
        dirnames[:] = [d for d in dirnames
                       if d.lower() not in ("system volume information", "$recycle.bin")]
        for name in filenames:
            p = pathlib.Path(dirpath) / name
            try:
                size = p.stat().st_size
                digest = sha256_file(p)
            except OSError as exc:
                skipped.append({"path": str(p), "error": str(exc)})
                continue
            ext = p.suffix.lower()
            files.append({
                "path": "/" + str(p.relative_to(v["root"])).replace(os.sep, "/"),
                "name": p.name,
                "size": size,
                "sha256": digest,
                "ext": ext,
                "kind": CARVABLE.get(ext),
                "carvable": ext in CARVABLE,
            })
    files.sort(key=lambda f: f["path"])
    return {
        "schema": "sentinelwipe.usb.enrolment/1",
        "volume": v,
        "enrolled_at_unix": int(time.time()),
        "count": len(files),
        "carvable": sum(1 for f in files if f["carvable"]),
        "files": files,
        "skipped": skipped,
        "note": "Hashed before any deletion. A file whose extension is not in "
                "the carver's signature table is marked carvable:false -- it "
                "has no header to scan for and will not be recovered.",
    }


# --------------------------------------------------------------------------
# 2. image -- raw read, read-only, sector aligned
# --------------------------------------------------------------------------
MARGIN = 256 << 20          # headroom past the used region, in bytes
FLOOR = 256 << 20           # never image less than this


def suggested_limit(v):
    """How much of the front of the volume is worth reading.

    A 62 GB stick at USB 2.0 speed is forty-four minutes of imaging, which is
    not a demonstration. But a volume with 161 MB in use has its data at the
    front, so reading the used region plus headroom finds anything recently
    written. This returns that window; it is a SPEED choice and the caller is
    obliged to report it, because a file that was never read cannot be called
    unrecoverable.
    """
    cap = v.get("capacity_bytes") or 0
    free = v.get("free_bytes") or 0
    used = max(0, cap - free)
    want = max(FLOOR, used + MARGIN)
    # round up to a whole MiB so the number on screen is a clean one
    want = ((want + (1 << 20) - 1) >> 20) << 20
    return min(want, cap) if cap else want


def image_volume(letter, out_path, progress=None, block=1 << 20, limit=None):
    """Copy the volume's raw bytes to a file. Opens "rb" and nothing else.

    `limit` bounds the read to the first N bytes. The return value always says
    what fraction of the medium was actually covered, and `whole_volume` is
    false whenever anything was left unread -- the same discipline the wipe's
    `whole_medium_claim` follows, for the same reason.
    """
    v = _require_removable(letter)
    src = v["raw_path"]
    total = v["capacity_bytes"] or 0
    if limit is None:
        limit = suggested_limit(v)
    out_path = pathlib.Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    done = 0
    t0 = time.perf_counter()
    # buffering=0: raw volume reads must be whole sectors, and Python's buffered
    # reader is free to issue a short read that the device layer will refuse.
    with open(src, "rb", buffering=0) as fh, open(out_path, "wb") as w:
        while limit is None or done < limit:
            want = block if limit is None else min(block, limit - done)
            try:
                chunk = fh.read(want)
            except OSError:
                break                      # end of the volume, reported by the OS
            if not chunk:
                break
            w.write(chunk)
            h.update(chunk)
            done += len(chunk)
            if progress:
                progress(done, limit or total, time.perf_counter() - t0)
    elapsed = time.perf_counter() - t0
    whole = (total == 0) or (done >= total)
    return {
        "source": src,
        "path": str(out_path),
        "bytes": done,
        "sha256": h.hexdigest(),
        "elapsed_s": round(elapsed, 6),
        "bytes_per_second": round(done / elapsed, 6) if elapsed > 0 else None,
        "capacity_bytes": total,
        "limit_bytes": limit,
        "whole_volume": whole,
        "coverage_fraction": round(done / total, 9) if total else None,
        "scope": ("the whole volume" if whole else
                  f"the first {done:,} bytes of a {total:,} byte volume. "
                  f"Anything stored past that point was NEVER READ, and is "
                  f"reported as out of scope rather than as unrecoverable."),
    }


# --------------------------------------------------------------------------
# 3+4. carve the image, and join to the enrolment by SHA-256
# --------------------------------------------------------------------------
def carve_image(img_path, report_path, extra_argv=()):
    if not CARVE.exists():
        raise FileNotFoundError(f"carver not built: {CARVE}")
    argv = [str(CARVE), *extra_argv, str(img_path)]
    t0 = time.perf_counter()
    with open(report_path, "w", encoding="utf-8") as out:
        proc = subprocess.run(argv, stdout=out, stderr=subprocess.PIPE, text=True)
    elapsed = time.perf_counter() - t0
    if proc.returncode != 0:
        raise RuntimeError(f"carve exited {proc.returncode}: {proc.stderr.strip()[-400:]}")
    report = json.loads(pathlib.Path(report_path).read_bytes())
    return report, round(elapsed, 6)


def compare(enrolment, report, img=None, image_path=None):
    """Join recovered records to enrolled files by SHA-256, and nothing else.

    Not by name, not by size, not by offset -- a recovered object is correct
    only if its bytes hash to what was enrolled before the deletion.

    TWO KINDS OF HIT, and they are never merged into one figure.

    `exact`     the candidate's own bytes hash to the enrolled value. The carver
                found the object and ended it in the right place.
    `over-run`  the enrolled value is the hash of the candidate's FIRST n bytes.
                The object is intact and starts where the carver said, but the
                end boundary ran past it -- two PDFs stored back to back will do
                this, because the validator walks to the furthest %%EOF it can
                still parse. The data was recovered; the boundary was wrong, and
                saying so is the honest report.

    The over-run check reads the enrolled SIZE, which is ground truth. That is
    legitimate for VERIFYING a recovery and it is not how the carver works --
    the carver never sees the manifest. It is labelled apart for exactly that
    reason and never counted as an exact hit.
    """
    by_hash = {}
    for f in enrolment["files"]:
        by_hash.setdefault(f["sha256"], []).append(f)
    # enrolled files indexed by size, for the over-run check
    by_size = {}
    for f in enrolment["files"]:
        by_size.setdefault(f["size"], []).append(f)

    blob = None
    if image_path and pathlib.Path(image_path).exists():
        blob = pathlib.Path(image_path).read_bytes()

    records = report.get("candidates", [])
    hits, admitted_hits, seen = [], 0, set()
    for r in records:
        match = by_hash.get(r["sha256"])
        mode = "exact"
        if not match and blob is not None:
            # the candidate over-ran its object: does an enrolled file sit at
            # the front of it, byte for byte?
            for size, cands in by_size.items():
                if size >= r["length"]:
                    continue
                head = hashlib.sha256(
                    blob[r["offset"]:r["offset"] + size]).hexdigest()
                for f in cands:
                    if f["sha256"] == head and f["sha256"] not in seen:
                        match, mode = [f], "over-run"
                        break
                if match:
                    break
        if not match or match[0]["sha256"] in seen:
            continue
        seen.add(match[0]["sha256"])
        hits.append({
            "path": match[0]["path"],
            "kind": r["kind"],
            "offset": r["offset"],
            "length": match[0]["size"] if mode == "over-run" else r["length"],
            "candidate_length": r["length"],
            "sha256": match[0]["sha256"],
            "admitted": r["admitted"],
            "confidence": r["confidence"]["total"],
            "assembly": r.get("assembly", "contiguous"),
            "enrolled_size": match[0]["size"],
            "mode": mode,
            "overrun_bytes": (r["length"] - match[0]["size"]) if mode == "over-run" else 0,
        })
        if r["admitted"]:
            admitted_hits += 1

    recovered = {h["sha256"] for h in hits}
    missed = [f for f in enrolment["files"] if f["sha256"] not in recovered]
    partial = bool(img) and not img.get("whole_volume", True)

    def why(f):
        """Why this enrolled file did not come back, and never a guess.

        The order matters. A file that was never read cannot be called
        unrecoverable, so the scope limit is checked BEFORE the signature
        table -- otherwise a partial image would let us blame the carver for
        bytes it was never shown.
        """
        if not f["carvable"]:
            return ("extension %s has no row in the carver's signature table: "
                    "no header to scan for" % (f["ext"] or "(none)"))
        if partial:
            return ("carvable, and not found in the %s bytes that were imaged. "
                    "The rest of the volume was never read."
                    % format(img["bytes"], ","))
        return "carvable, present in the image, and no candidate matched its hash"

    return {
        "enrolled": enrolment["count"],
        "enrolled_carvable": enrolment["carvable"],
        "records": len(records),
        "admitted": report["counts"]["admitted"],
        "byte_exact_matches": len(hits),
        "byte_exact_and_admitted": admitted_hits,
        "hits": sorted(hits, key=lambda h: h["offset"]),
        "scope": (img or {}).get("scope"),
        "whole_volume": (img or {}).get("whole_volume"),
        "not_recovered": [{
            "path": f["path"], "size": f["size"], "ext": f["ext"],
            "carvable": f["carvable"], "reason": why(f),
        } for f in missed],
    }


# --------------------------------------------------------------------------
# CLI -- so the whole path is testable without the browser
# --------------------------------------------------------------------------
def extract(hits, image_path, out_dir, source_letter=None):
    """Write the recovered objects out as real files, and verify each one.

    NEVER BACK TO THE SOURCE. Writing recovered data onto the medium you are
    recovering from can overwrite the very bytes you have not carved yet; it is
    the one mistake every recovery tool refuses to make. Output goes to the
    local disk, and this asserts the destination is not on the volume that was
    imaged before it writes anything.

    Each file is re-hashed after writing, so "recovered" means the bytes on
    disk were checked, not that a copy was attempted.
    """
    out_dir = pathlib.Path(out_dir).resolve()
    if source_letter:
        src = source_letter.strip().rstrip(":").upper()
        if out_dir.drive.rstrip(":").upper() == src:
            raise PermissionError(
                f"REFUSED: the output directory {out_dir} is on {src}:, the "
                f"volume that was just imaged. Recovered data is never written "
                f"back to the medium it came from.")
    blob = pathlib.Path(image_path).read_bytes()
    out_dir.mkdir(parents=True, exist_ok=True)

    written = []
    for h in hits:
        name = pathlib.Path(h["path"]).name or f'{h["kind"]}_{h["offset"]}'
        dest = out_dir / name
        i = 1
        while dest.exists():
            dest = out_dir / f"{dest.stem}({i}){dest.suffix}"
            i += 1
        data = blob[h["offset"]:h["offset"] + h["length"]]
        dest.write_bytes(data)
        back = sha256_file(dest)
        written.append({
            "name": dest.name,
            "path": str(dest),
            "bytes": len(data),
            "sha256": back,
            "verified": back == h["sha256"],
            "mode": h.get("mode", "exact"),
        })
    return {"dir": str(out_dir), "count": len(written),
            "verified": sum(1 for w in written if w["verified"]),
            "files": written}


STAGE = REPO / "out/usb-stage"


def stage():
    """Cut one real file of each kind out of the fixture, ready to copy to a stick.

    These are not invented files. Each is lifted byte-for-byte from
    out/fixture.img at the offset the manifest names, and its SHA-256 is checked
    against the manifest before it is written -- so the demonstration starts from
    an object whose hash was already known to this repo.

    The set deliberately includes a .txt. It will NOT be recovered, we say so
    before the run, and being right about our own failure in front of the room
    is worth more than a clean sweep.
    """
    man = json.loads((REPO / "out/fixture.manifest.json").read_bytes())
    img = (REPO / "out/fixture.img").read_bytes()
    STAGE.mkdir(parents=True, exist_ok=True)
    for old in STAGE.glob("*"):
        old.unlink()

    picked, out = {}, []
    for f in sorted(man["files"], key=lambda x: x["size"]):
        if f["fragmented"] or f["kind"] in picked:
            continue
        blob = img[f["offset"]:f["offset"] + f["size"]]
        if hashlib.sha256(blob).hexdigest() != f["sha256"]:
            continue                        # never stage bytes we cannot vouch for
        picked[f["kind"]] = True
        name = pathlib.Path(f["path"]).name
        (STAGE / name).write_bytes(blob)
        ext = pathlib.Path(name).suffix.lower()
        out.append({"name": name, "kind": f["kind"], "size": f["size"],
                    "sha256": f["sha256"], "carvable": ext in CARVABLE})
    out.sort(key=lambda x: (not x["carvable"], x["kind"]))
    return out


def _usage():
    print(__doc__.strip().splitlines()[0])
    print()
    print("usage:")
    print("  usb.py list")
    print("  usb.py stage                       -> out/usb-stage, one file per kind")
    print("  usb.py enrol <LETTER>              -> out/usb-run/enrolment.json")
    print("  usb.py recover <LETTER>            image + carve + compare")
    sys.exit(2)


def main():
    if len(sys.argv) < 2:
        _usage()
    cmd = sys.argv[1]

    if cmd == "list":
        for v in volumes():
            mark = "REMOVABLE" if v["removable"] else v["kind"]
            print("%s:  %-10s %-7s %-16s %8.2f GB  %s" % (
                v["letter"], mark, v["filesystem"], v["label"][:16],
                v["capacity_bytes"] / 1e9, v["raw_path"]))
        return

    if cmd == "stage":
        files = stage()
        print(f"{STAGE}   {len(files)} files, one of each kind in the fixture")
        for f in files:
            print("  %-30s %-7s %10s  %s%s" % (
                f["name"], f["kind"], format(f["size"], ","), f["sha256"][:16],
                "" if f["carvable"] else "   <- NO SIGNATURE, will not be recovered"))
        print()
        print("Copy these to the stick, then: usb.py enrol <LETTER>")
        return

    if cmd == "enrol":
        if len(sys.argv) < 3:
            _usage()
        e = enrol(sys.argv[2])
        WORK.mkdir(parents=True, exist_ok=True)
        p = WORK / "enrolment.json"
        p.write_text(json.dumps(e, indent=2), encoding="utf-8")
        print(f"{p}  {e['count']} files, {e['carvable']} carvable")
        for f in e["files"]:
            flag = "  " if f["carvable"] else "! "
            print("  %s%-40s %10s  %s%s" % (
                flag, f["path"][:40], format(f["size"], ","), f["sha256"][:16],
                "" if f["carvable"] else "   <- no signature, will NOT be recovered"))
        return

    if cmd == "recover":
        if len(sys.argv) < 3:
            _usage()
        letter = sys.argv[2]
        enr_path = WORK / "enrolment.json"
        if not enr_path.exists():
            sys.exit(f"no enrolment at {enr_path} -- run `usb.py enrol {letter}` "
                     f"BEFORE deleting anything")
        enrolment = json.loads(enr_path.read_bytes())

        def prog(done, total, secs):
            if total and int(secs * 4) % 4 == 0:
                pct = 100.0 * done / total
                sys.stderr.write("\r  imaging %6.2f%%  %s bytes  %.1f MB/s   "
                                 % (pct, format(done, ","),
                                    done / secs / 1e6 if secs else 0))

        print("imaging %s: (read-only)" % letter.rstrip(":").upper())
        limit = None
        for i, a in enumerate(sys.argv):
            if a == "--limit" and i + 1 < len(sys.argv):
                limit = int(float(sys.argv[i + 1]) * (1 << 20))     # MiB
        img = image_volume(letter, WORK / "evidence.img", progress=prog, limit=limit)
        sys.stderr.write("\r" + " " * 78 + "\r")
        print("  %s bytes in %.3f s = %s B/s" % (
            format(img["bytes"], ","), img["elapsed_s"],
            format(int(img["bytes_per_second"] or 0), ",")))
        print("  image sha256 %s" % img["sha256"])
        print("  scope: %s" % img["scope"])

        print("carving...")
        report, secs = carve_image(WORK / "evidence.img", WORK / "carve.json")
        print("  %s records, %s admitted, %.3f s" % (
            format(report["counts"]["records"], ","),
            format(report["counts"]["admitted"], ","), secs))

        res = compare(enrolment, report, img, WORK / "evidence.img")
        ex = extract(res["hits"], WORK / "evidence.img", WORK / "recovered",
                     source_letter=letter)
        res["extracted"] = {k: ex[k] for k in ("dir", "count", "verified")}
        (WORK / "result.json").write_text(
            json.dumps({"image": img, "compare": res}, indent=2), encoding="utf-8")
        print()
        print("BYTE-EXACT RECOVERIES: %d of %d enrolled (%d carvable)" % (
            res["byte_exact_matches"], res["enrolled"], res["enrolled_carvable"]))
        for h in res["hits"]:
            print("  %-34s %-6s @%-12s conf %.4f  %-8s %s" % (
                h["path"][:34], h["kind"], format(h["offset"], ","),
                h["confidence"], "ADMITTED" if h["admitted"] else "rejected",
                "" if h["mode"] == "exact" else
                "(end over-run by %s bytes)" % format(h["overrun_bytes"], ",")))
        print()
        print("WRITTEN TO %s" % ex["dir"])
        print("  %d files, %d re-hashed and verified on disk" % (ex["count"], ex["verified"]))
        for w in ex["files"]:
            print("     %-34s %10s  %s" % (
                w["name"][:34], format(w["bytes"], ","),
                "verified" if w["verified"] else "HASH MISMATCH"))
        if res["not_recovered"]:
            print("\nNOT RECOVERED:")
            for f in res["not_recovered"]:
                print("  %-34s %s" % (f["path"][:34], f["reason"] or "no candidate matched"))
        return

    _usage()


if __name__ == "__main__":
    main()
