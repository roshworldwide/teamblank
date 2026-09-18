#!/usr/bin/env python3

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

FLOOR_BYTES = 8 << 20

CLEARANCE_CLUSTERS = 8


class PlantError(RuntimeError):
    pass


def occupied_ranges(manifest: dict) -> list[tuple[int, int]]:
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


def build_container(text: bytes, name: str) -> bytes:
    return corpus_mod._build_zip([(name, text)])


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
