#!/usr/bin/env python3
import hashlib, json, os, pathlib, shutil, subprocess, sys

REPO = pathlib.Path(__file__).resolve().parents[1]
EXE = ".exe" if os.name == "nt" else ""
CARVE  = REPO / f"core/target/release/carve{EXE}"
WIPE   = REPO / f"core/target/release/wipe{EXE}"
VERIFY = REPO / f"core/target/release/verify{EXE}"
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

    after = sha256(IMG)
    if after != before:
        die(f"THE FIXTURE CHANGED. before {before} after {after}. "
            "A wipe reached out/fixture.img; stop and investigate.", 9)
    print("refresh: fixture sha256 re-verified unchanged")

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
