#!/usr/bin/env python3
"""Run the engine, then rebuild the UI from what it produced.

This is what makes the frontend part of the product rather than a picture of it:
the pages ship showing the output of a real run, and `make ui` re-runs the engine
and re-inlines. Nothing here is a fixture of a fixture.

SAFETY. The wipe never touches out/fixture.img. It runs against a COPY inside a
scratch directory, with --allow-root pointed at that directory, so the guard's
containment check is what stops a mistake rather than this script's good
intentions. The fixture's sha256 is recorded before and re-verified after, and a
change is a hard failure.
"""
import hashlib, json, pathlib, shutil, subprocess, sys

REPO = pathlib.Path(__file__).resolve().parents[1]
CARVE = REPO / "core/target/release/carve"
WIPE  = REPO / "core/target/release/wipe"
IMG   = REPO / "out/fixture.img"
MAN   = REPO / "out/fixture.manifest.json"
WORK  = REPO / "out/ui-run"

def die(msg, code=4):
    print(f"refresh: {msg}", file=sys.stderr); raise SystemExit(code)

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()

def run(argv, out=None, label="", ok=(0,)):
    print(f"  $ {' '.join(str(a) for a in argv[:4])} …" if len(argv) > 4
          else f"  $ {' '.join(str(a) for a in argv)}")
    r = subprocess.run(argv, capture_output=True, text=True)
    if r.returncode not in ok:
        sys.stderr.write(r.stderr[-1200:])
        die(f"{label or argv[0]} exited {r.returncode}", r.returncode)
    if out:
        out.write_text(r.stdout)
    return r.stdout

def main():
    for p in (CARVE, WIPE):
        if not p.exists():
            die(f"missing {p.relative_to(REPO)} — run: cd core && cargo build --release", 3)
    for p in (IMG, MAN):
        if not p.exists():
            die(f"missing {p.relative_to(REPO)} — run: make fixtures", 3)

    before = sha256(IMG)
    print(f"refresh: fixture sha256 {before[:16]}…  (never a wipe target)")

    if WORK.exists(): shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    target = WORK / "medium.img"
    shutil.copy2(IMG, target)

    print("refresh: carve, before")
    run([CARVE, "--phase", "pre-wipe", "--manifest", MAN, "--image-path", IMG, target],
        out=WORK / "carve_pre.json", label="carve(pre)")

    print("refresh: wipe")
    run([WIPE, "--target", target, "--allow-root", WORK, "--i-understand", target,
         "--period-ms", "8", "--trace", WORK / "telemetry.jsonl"],
        out=WORK / "wipe.json", label="wipe")

    print("refresh: carve, after — the same engine, the same parameters")
    # exit 1 from carve means "no candidate reached the gate". On the POST-wipe
    # pass that is not a failure, it is the result the whole demo exists to
    # produce, and the engine says so itself: "a complete report, not an error".
    run([CARVE, "--phase", "post-wipe", "--manifest", MAN, "--image-path", IMG, target],
        out=WORK / "carve_post.json", label="carve(post)", ok=(0, 1))

    after = sha256(IMG)
    if after != before:
        die(f"THE FIXTURE CHANGED. before {before} after {after}. "
            "A wipe reached out/fixture.img; stop and investigate.", 9)
    print(f"refresh: fixture sha256 re-verified unchanged")

    print("refresh: payload")
    run([sys.executable, REPO / "ui/build_payload.py", WORK], label="build_payload")
    print("refresh: inline")
    run([sys.executable, REPO / "ui/inline.py"], label="inline")

    w = json.loads((WORK / "wipe.json").read_text())
    post = json.loads((WORK / "carve_post.json").read_text())
    pre = json.loads((WORK / "carve_pre.json").read_text())
    print()
    print(f"  carve before   {pre['counts']['records']:>3} scanned  "
          f"{pre['counts']['admitted']:>3} admitted")
    print(f"  carve after    {post['counts']['records']:>3} scanned  "
          f"{post['counts']['admitted']:>3} admitted")
    print(f"  entropy        {w['entropy_bits_per_byte']['before']} -> "
          f"{w['entropy_bits_per_byte']['after']} bits/byte")
    print(f"  outcome        {w['outcome']['code']}  "
          f"coverage {w['verification']['coverage_fraction']}")
    print(f"  timing         {w['audit']['overwrite']['code']}  ratio "
          f"{w['audit']['overwrite']['ratio_measured_over_expected_min']}")
    print(f"  telemetry      {w['telemetry']['events']} frames @ "
          f"{w['telemetry']['achieved_hz']:.3f} Hz measured")
    print()
    print("  ui/approach.html and ui/instrument.html now show THIS run.")

main()
