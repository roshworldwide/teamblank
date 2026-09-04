#!/usr/bin/env python3
"""Re-inline ui/payload.json into the shipped pages, and refuse on token drift.

The pages are self-contained on purpose: one file, no build step, no network, so
they open from a USB stick on an air-gapped machine. That property is worth
keeping, but it means the payload and the token layer are COPIES, and a copy that
nobody regenerates goes stale silently.

So: this script is the regeneration step, and it is also the drift detector.
  - the payload block is rewritten from ui/payload.json every run
  - every primitive in ui/tokens.css is checked against each page, and a single
    mismatch exits 4 naming the token. A page whose gold is one digit off from
    the standard is exactly the defect nobody notices by eye.

Exit codes:  0 ok  ·  3 nothing to do  ·  4 token drift  ·  5 malformed page
"""
import json, pathlib, re, sys

REPO = pathlib.Path(__file__).resolve().parents[1]
PAGES = ("ui/index.html", "ui/approach.html", "ui/instrument.html",
         "ui/recover.html")
OPEN_RE = re.compile(r'(<script[^>]*id="payload"[^>]*>)(.*?)(</script>)', re.S)

def die(code, msg):
    print(f"inline: {msg}", file=sys.stderr); raise SystemExit(code)

def primitives(css):
    """Every --name:value the token layer declares, as a dict."""
    out = {}
    for m in re.finditer(r'(--[a-z0-9-]+)\s*:\s*([^;\n}]+)', css):
        out[m.group(1)] = m.group(2).strip()
    return out

def main():
    tok_path = REPO / "ui/tokens.css"
    pl_path  = REPO / "ui/payload.json"
    for p in (tok_path, pl_path):
        if not p.exists(): die(3, f"missing {p.relative_to(REPO)}")

    payload = json.loads(pl_path.read_bytes())          # parse == validate
    compact = json.dumps(payload, separators=(",", ":"))
    tokens  = primitives(tok_path.read_text())
    # only the primitives are checked: the semantic roles reference them, and a
    # page is allowed to add page-scoped custom properties of its own.
    prim = {k: v for k, v in tokens.items()
            if re.match(r'--(ti|au|vp|sig|space|radius|dur|ease|size|lh)-', k)}

    changed, drift = [], []
    for rel in PAGES:
        f = REPO / rel
        if not f.exists(): die(3, f"missing {rel}")
        h = f.read_text()

        # A live-only surface carries no payload and could not: ui/recover.html
        # recovers files the OPERATOR chose, so every figure on it is measured
        # during the run or does not exist. Its token layer is still checked --
        # that is the part a page can drift on.
        m = OPEN_RE.search(h)
        if not m and rel != "ui/recover.html":
            die(5, f'{rel}: no <script id="payload"> block')

        page_tok = primitives(h[:h.index("</style>")] if "</style>" in h else h)
        for k, v in prim.items():
            if k not in page_tok:
                drift.append(f"{rel}: {k} missing from the page")
            elif page_tok[k].split("/*")[0].strip() != v.split("/*")[0].strip():
                drift.append(f"{rel}: {k} is {page_tok[k]!r}, tokens.css says {v!r}")

        if m and m.group(2).strip() != compact:
            f.write_text(h[:m.start(2)] + compact + h[m.end(2):])
            changed.append(rel)

    if drift:
        for d in drift[:12]: print(f"  DRIFT  {d}", file=sys.stderr)
        die(4, f"{len(drift)} token(s) drifted from ui/tokens.css. "
               "The pages and the standard disagree; fix the page, not this check.")

    print(f"inline: {len(prim)} primitives verified against ui/tokens.css in {len(PAGES)} pages")
    if changed:
        for c in changed: print(f"inline: payload re-inlined into {c}")
    else:
        print(f"inline: payload already current in all {len(PAGES)} pages")
    a = payload["audit"]["overwrite"]; o = payload["outcome"]; v = payload["verification"]
    print(f"inline: showing  {o['code']}  coverage {v['coverage_fraction']}  "
          f"ratio {a['ratio']}  {a['code']}  ·  {len(payload['frames'])} telemetry frames")

main()
