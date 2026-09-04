#!/usr/bin/env python3
"""Plant an operator-supplied file in the fixture's free space, for a live demo.

The demo this exists for: a judge types a sentence nobody has seen before, it goes
into the image, the carver pulls it back out of unallocated space and puts their own
words on the screen. Then the wipe runs, the carver runs again with identical
parameters, and it is gone.

That is worth more than the same sequence over a file we prepared, because the one
thing an evaluator cannot check about a prepared fixture is whether it was prepared to
succeed.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It does not touch `fixtures/corpus.py` or `fixtures/plan.py`. The seeded corpus is
exactly forty files and asserts as much in three places, and every measured figure in
this project — 33 admitted, 28 of 40 recovered, the 0.9000/0.6500 separation, the
0.0357 binding margin — is a statement about that set. Adding a forty-first file to the
corpus would move all of them at once and invalidate the documentation silently.

So this is an overlay. It writes into free space *after* the build, records itself in a
separate sidecar, and is excluded from `counted_set` by construction because the
planner never knew about it. The forty stay forty.

THE CONTAINER IS A ZIP, AND THAT IS THE INTERESTING PART
--------------------------------------------------------
docs/architecture.md is careful about a distinction: a confidence score says "this is a
well-formed object of this type", not "these are the original bytes". For JPEG entropy
data and MP4 sample data the two genuinely diverge — `handover_briefing.mov` is admitted
at 0.9000 with a perfect structural score and a different SHA-256.

ZIP is one of the three formats where they nearly coincide, because the CRC-32 covers
the payload. So when the carver recovers the judge's sentence, the CRC proves the bytes
are *their* bytes and not merely a plausible ZIP. The demo closes the gap the
documentation is honest about, instead of walking into it.

SEED IDENTITY
-------------
`make fixtures` regenerates a byte-identical image from a seed, and the committed digest
is checked on every build. This tool breaks that by design, so it refuses to run without
`--i-understand-this-breaks-seed-identity`, prints the old and new digests, and tells
the operator how to get back. Run `make fixtures` afterwards and the image returns to
the committed one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from fixtures import corpus as corpus_mod          # noqa: E402
from fixtures import guard as guard_mod            # noqa: E402

SIDECAR_SCHEMA = "sentinelwipe.fixtures.operator/1"
SIDECAR_NAME = "operator.json"
DEFAULT_OUT = "out"
IMAGE_NAME = "fixture.img"
MANIFEST_NAME = "fixture.manifest.json"

# Leave the first 8 MiB alone. The reserved region, both FATs and the root directory
# live down there; the planner's own data region starts well above it, and a demo is
# not the place to discover an off-by-one in someone else's arithmetic.
FLOOR_BYTES = 8 << 20

# Keep clear of every planted file by a wide margin, so a bifragment search that walks
# past the end of a neighbour cannot wander into the operator's payload and confuse a
# figure that is quoted in the documentation.
CLEARANCE_CLUSTERS = 8


class PlantError(RuntimeError):
    """Refusal. Always says what to do next."""


# ── free space ──────────────────────────────────────────────────────────────────────

def occupied_ranges(manifest: dict) -> list[tuple[int, int]]:
    """Every byte range the planner claims, from the extents it published.

    Read from the manifest rather than recomputed from the FAT, because the manifest is
    what the carver and every test already agree on. Two readings of the same truth is
    one reading too many.
    """
    spans: list[tuple[int, int]] = []
    for f in manifest["files"]:
        for e in f["extents"]:
            start = int(e["byte_offset"])
            length = int(e["byte_length"])
            if length <= 0:
                raise PlantError(f"{f['path']}: extent length {length} is not positive")
            spans.append((start, start + length))
    spans.sort()
    return spans


def largest_free_run(manifest: dict) -> tuple[int, int]:
    """The biggest contiguous gap between planted extents, cluster-aligned.

    Returns (start, length). Clearance is applied on both sides of every neighbour.
    """
    cluster = int(manifest["bytes_per_cluster"])
    total = int(manifest["image_bytes"])
    pad = CLEARANCE_CLUSTERS * cluster

    merged: list[list[int]] = []
    for start, end in occupied_ranges(manifest):
        lo, hi = start - pad, end + pad
        if merged and lo <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])

    best = (0, 0)
    cursor = FLOOR_BYTES
    for lo, hi in merged + [[total, total]]:
        if lo > cursor:
            start = (cursor + cluster - 1) // cluster * cluster
            end = lo // cluster * cluster
            if end - start > best[1]:
                best = (start, end - start)
        cursor = max(cursor, hi)
    return best


# ── the payload ─────────────────────────────────────────────────────────────────────

def build_container(text: bytes, name: str) -> bytes:
    """Wrap the operator's bytes in a ZIP, using the fixture's own encoder.

    `fixtures/deflate.py` exists so the corpus does not depend on the linked zlib, whose
    output varies between builds. Using it here keeps the operator's file byte-identical
    on any machine that plants the same text, which is the property the sidecar's
    sha256 claims.
    """
    return corpus_mod._build_zip([(name, text)])


# ── the write ───────────────────────────────────────────────────────────────────────

def plant(image_path: str, manifest_path: str, payload: bytes, out_dir: str,
          source_text: bytes, entry_name: str, quiet: bool = False) -> dict:
    def say(msg: str) -> None:
        if not quiet:
            print(msg)

    manifest = json.loads(open(manifest_path, "rb").read().decode("utf-8"))
    image = open(image_path, "rb").read()

    if len(image) != int(manifest["image_bytes"]):
        raise PlantError(
            f"{image_path} is {len(image)} bytes, manifest says "
            f"{manifest['image_bytes']}. Run `make fixtures` first.")

    before = hashlib.sha256(image).hexdigest()
    if before != manifest["image_sha256"]:
        raise PlantError(
            "the image on disk does not match its manifest digest, so something has "
            "already modified it — possibly a previous run of this tool. Planting on "
            "top would leave two payloads and a sidecar that describes one.\n"
            "  Run `make fixtures` to restore the committed image, then plant once.")

    start, room = largest_free_run(manifest)
    if room < len(payload):
        raise PlantError(
            f"the largest free run is {room} bytes and the container needs "
            f"{len(payload)}. Shorten the text.")

    say(f"free run   {room:,} B at offset {start:,} "
        f"(cluster {start // int(manifest['bytes_per_cluster']):,})")

    patched = bytearray(image)
    patched[start:start + len(payload)] = payload
    patched = bytes(patched)

    out_abs = os.path.abspath(out_dir)
    policy = guard_mod.Policy(roots=[out_abs])
    say(f"guard      policy digest {policy.digest()[:16]} root {out_abs}")

    fd = guard_mod.open_authorized(policy, image_path, "w")
    try:
        os.ftruncate(fd, 0)
        n = 0
        while n < len(patched):
            n += os.write(fd, patched[n:n + (1 << 20)])
        os.fsync(fd)
    finally:
        os.close(fd)
    if n != len(patched):
        raise PlantError(f"short write: {n} of {len(patched)} bytes")

    after = hashlib.sha256(patched).hexdigest()

    sidecar = {
        "schema": SIDECAR_SCHEMA,
        "note": ("An operator-supplied file planted in free space AFTER the seeded "
                 "build. It is not part of the forty-file corpus and is absent from "
                 "counted_set, so no figure in docs/ or the README moves because of "
                 "it. The image is no longer byte-identical to the seed; "
                 "`make fixtures` restores it."),
        "entry_name": entry_name,
        "kind": "ZIP",
        "offset": start,
        "size": len(payload),
        "container_sha256": hashlib.sha256(payload).hexdigest(),
        "plaintext_sha256": hashlib.sha256(source_text).hexdigest(),
        "plaintext_bytes": len(source_text),
        "crc_covers_payload": True,
        "why_zip": ("ZIP carries a CRC-32 over the payload, so a recovered copy is "
                    "provably the original bytes rather than merely a well-formed "
                    "object of the right type. See docs/architecture.md on what a "
                    "confidence score does and does not mean."),
        "image_sha256_before": before,
        "image_sha256_after": after,
        "seed_identity": "BROKEN — this image no longer matches the committed digest",
    }
    sidecar_path = os.path.join(out_abs, SIDECAR_NAME)
    fd = guard_mod.open_authorized(policy, sidecar_path, "w")
    try:
        os.ftruncate(fd, 0)
        os.write(fd, (json.dumps(sidecar, indent=1) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

    say(f"planted    {len(payload):,} B ZIP at {start:,}, entry {entry_name!r}")
    say(f"plaintext  {len(source_text):,} B, sha256 {sidecar['plaintext_sha256'][:32]}…")
    say(f"wrote      {sidecar_path}")
    say("")
    say(f"image sha256 was  {before}")
    say(f"image sha256 now  {after}")
    say("")
    say("SEED IDENTITY IS BROKEN. This image no longer matches the committed digest.")
    say("Restore with: make fixtures")
    return sidecar


# ── CLI ─────────────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="plant_operator_file",
        description="Plant an operator-supplied file in the fixture's free space.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--text", help="the sentence to plant, taken from the command line")
    src.add_argument("--file", help="a file to plant instead of --text")
    ap.add_argument("--entry-name", default="operator_note.txt",
                    help="the name inside the ZIP (default: operator_note.txt)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="fixture directory (default: out)")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--i-understand-this-breaks-seed-identity", action="store_true",
                    dest="ack",
                    help="required. The image will stop matching the committed digest.")
    a = ap.parse_args(argv)

    if not a.ack:
        print("plant_operator_file: refusing.\n"
              "  This rewrites out/fixture.img, which is reproduced byte-identically\n"
              "  from a seed and whose digest is checked on every build. Pass\n"
              "  --i-understand-this-breaks-seed-identity to proceed, and run\n"
              "  `make fixtures` afterwards to restore it.", file=sys.stderr)
        return 2

    if a.file:
        text = open(a.file, "rb").read()
        entry = a.entry_name if a.entry_name != "operator_note.txt" \
            else os.path.basename(a.file)
    else:
        text = a.text.encode("utf-8")
        entry = a.entry_name

    if not text:
        print("plant_operator_file: nothing to plant", file=sys.stderr)
        return 2

    out_abs = os.path.abspath(a.out)
    image_path = os.path.join(out_abs, IMAGE_NAME)
    manifest_path = os.path.join(out_abs, MANIFEST_NAME)
    for p in (image_path, manifest_path):
        if not os.path.exists(p):
            print(f"plant_operator_file: {p} is absent; run `make fixtures`",
                  file=sys.stderr)
            return 2

    try:
        payload = build_container(text, entry)
        plant(image_path, manifest_path, payload, a.out, text, entry, a.quiet)
    except (PlantError, guard_mod.PolicyError) as e:
        print(f"plant_operator_file: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
