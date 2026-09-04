#!/usr/bin/env python3
"""Run the adversarial loop, then rebuild the UI from what it produced.

Phase 4 rewired this file: it used to drive three binaries by argv and is now a
thin caller of `verify`, which runs the loop with parameter identity enforced
by construction, signs the certificate, and appends to the chain. This script
splits the bundle into the files the payload builder reads and nothing more.

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
VERIFY = REPO / "core/target/release/verify"
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
    """Returns the exit code (always in `ok`). A tolerated non-zero is the
    caller's to handle LOUDLY -- tolerance is for pipelines, not for silence."""
    print(f"  $ {' '.join(str(a) for a in argv[:4])} …" if len(argv) > 4
          else f"  $ {' '.join(str(a) for a in argv)}")
    r = subprocess.run(argv, capture_output=True, text=True)
    if r.returncode not in ok:
        sys.stderr.write(r.stderr[-1200:])
        die(f"{label or argv[0]} exited {r.returncode}", r.returncode)
    if out:
        out.write_text(r.stdout)
    return r.returncode

def main():
    for p in (CARVE, WIPE, VERIFY):
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

    print("refresh: the loop — carve, wipe, carve again; sign; chain")
    rc_verify = run([VERIFY,
         "--target", target, "--allow-root", WORK, "--i-understand", target,
         "--manifest", MAN,
         "--chain", WORK / "chain.txt", "--key", WORK / "operator.key",
         "--trace", WORK / "telemetry.jsonl", "--period-ms", "8",
         "--out", WORK / "bundle.json"],
        label="verify", ok=(0, 7))
    # exit 7 is SURVIVORS: an admitted candidate outlived the wipe. The bundle
    # is still written and the pages still rebuild -- evidence of a failure is
    # still evidence, and the instrument exists to SHOW it -- but this script
    # must not pretend the claim held: it re-raises at the end, after the
    # pages are rebuilt, so a human sees the evidence and automation the red.

    after = sha256(IMG)
    if after != before:
        die(f"THE FIXTURE CHANGED. before {before} after {after}. "
            "A wipe reached out/fixture.img; stop and investigate.", 9)
    print("refresh: fixture sha256 re-verified unchanged")

    # Split the bundle into the files the payload builder reads. json round-trip
    # is fine here: these copies feed the DISPLAY payload; the signed artifact
    # is the bundle itself and is carried through byte-untouched.
    bundle = json.loads((WORK / "bundle.json").read_bytes())
    for key, name in (("carve_pre", "carve_pre.json"), ("carve_post", "carve_post.json"),
                      ("wipe", "wipe.json")):
        (WORK / name).write_text(json.dumps(bundle[key]))
    (WORK / "ledger.json").write_text(json.dumps({
        "signed_certificate": bundle["signed_certificate"],
        "chain": bundle["chain"],
    }))

    print("refresh: payload")
    run([sys.executable, REPO / "ui/build_payload.py", WORK], label="build_payload")
    print("refresh: inline")
    run([sys.executable, REPO / "ui/inline.py"], label="inline")

    w = bundle["wipe"]; pre = bundle["carve_pre"]; post = bundle["carve_post"]
    print()
    print(f"  carve before   {pre['counts']['records']:>3} scanned  "
          f"{pre['counts']['admitted']:>3} admitted")
    print(f"  carve after    {post['counts']['records']:>3} scanned  "
          f"{post['counts']['admitted']:>3} admitted")
    print(f"  entropy        {w['entropy_bits_per_byte']['before']} -> "
          f"{w['entropy_bits_per_byte']['after']} bits/byte")
    print(f"  outcome        {w['outcome']['code']}  "
          f"coverage {w['verification']['coverage_fraction']}")
    print(f"  chain          index {bundle['chain']['index']}  head "
          f"{bundle['chain']['head'][:20]}…")
    print(f"  telemetry      {w['telemetry']['events']} frames @ "
          f"{w['telemetry']['achieved_hz']:.3f} Hz measured")
    print()
    print("  ui/approach.html and ui/instrument.html now show THIS run,")
    print("  signed, chained, and auditable with: verify --audit "
          + str((WORK / 'bundle.json').relative_to(REPO)))
    if rc_verify == 7:
        print()
        print("  *** SURVIVORS: at least one admitted candidate outlived the wipe.")
        print("  *** The pages above show that failure -- which is their job --")
        print("  *** and this exit is non-zero because the claim did not hold.")
        raise SystemExit(7)

main()
