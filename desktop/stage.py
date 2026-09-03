#!/usr/bin/env python3
"""Stage exactly what the shell bundles: the two pages, nothing else.

frontendDist has no include filter, and pointing it at ui/ would bundle the
pipeline's Python alongside the pages — harmless, but a bundle should contain
what it ships and nothing it happens to sit next to. Refuses to stage a page
whose payload block is missing, because an empty shell is worse than no shell.
"""
import pathlib, re, shutil, sys

REPO = pathlib.Path(__file__).resolve().parents[1]
DIST = REPO / "desktop/dist"
PAGES = ("approach.html", "instrument.html")

def die(m): print(f"stage: {m}", file=sys.stderr); raise SystemExit(4)

DIST.mkdir(exist_ok=True)
for old in DIST.iterdir(): old.unlink()
for name in PAGES:
    src = REPO / "ui" / name
    if not src.exists(): die(f"missing ui/{name}")
    h = src.read_text()
    if not re.search(r'<script[^>]*id="payload"[^>]*>\s*\{', h):
        die(f"ui/{name} carries no payload block — run `make ui` first")
    shutil.copy2(src, DIST / name)
    print(f"stage: {name}  {src.stat().st_size:,} bytes")
print(f"stage: {len(PAGES)} pages -> desktop/dist")
