"""Build a byte-identical-from-seed raw disk image with a planted, hashed corpus.

This is the Phase-1 CLI. It owns no forensic logic of its own: it wires the four
components together in the one order the contract fixes, and every byte it emits
leaves through a descriptor issued by ``fixtures.guard``.

    guard   -> the write policy, constructed FIRST, before anything is generated
    corpus  -> 40 files of known SHA-256, own fixed-Huffman DEFLATE, no zlib
    plan    -> every extent of every file chosen BEFORE a byte is written
    fat32   -> the on-disk structure, obeying that plan exactly

Order matters and is asserted below: the policy exists before the image bytes
do, so there is no window in which a 256 MiB buffer is holding data no allowlist
has been asked about.

Outputs, both into the ``--out`` directory (gitignored):

    fixture.img              the image
    fixture.manifest.json    sentinelwipe.fixtures.manifest/1

The tracked ``fixtures/manifest.json`` is NOT written here. It is a short
pointer to this output plus the expected digests, committed so a checker can
compare a hash instead of trusting a rebuild. See its ``note`` field.

Determinism: no time, no random, no host stat, no locale, no uuid, no
PYTHONHASHSEED dependence. Everything derived from --seed via hashlib. The
manifest is written in BINARY through the guard's raw descriptor with explicit
b"\\n", so CPython text-mode newline translation cannot move its hash.

Exit status -- the build FAILS on drift, it does not merely mention it:

    0  built, and it matches the digests committed in fixtures/manifest.json
       (or that record carries none / is for a different seed and size)
    1  a build-time invariant failed
    2  bad argument
    3  the write guard refused --out
    4  built, but it does NOT match the committed digests. The comparison runs
       in --quiet as well; --no-check-expected turns this back into 0 for a
       deliberate fixture change, which then updates the record in the same
       commit.

Usage:
    uv run python fixtures/build_image.py --seed sentinelwipe/fixture/v1 \\
        --size 256MiB --out out
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
from fixtures import fat32 as fat32_mod            # noqa: E402
from fixtures import guard as guard_mod            # noqa: E402
from fixtures import plan as plan_mod              # noqa: E402

__all__ = [
    "DEFAULT_SEED",
    "DEFAULT_SIZE_BYTES",
    "IMAGE_NAME",
    "MANIFEST_NAME",
    "MANIFEST_SCHEMA",
    "BuildResult",
    "build",
    "parse_size",
    "main",
]

DEFAULT_SEED = "sentinelwipe/fixture/v1"
DEFAULT_SIZE_BYTES = 256 * 1024 * 1024
DEFAULT_OUT = "out"

IMAGE_NAME = "fixture.img"
MANIFEST_NAME = "fixture.manifest.json"
MANIFEST_SCHEMA = "sentinelwipe.fixtures.manifest/1"
FILESYSTEM = "FAT32"

_UNITS = {
    "": 1, "B": 1,
    "K": 1000, "KB": 1000, "M": 1000 ** 2, "MB": 1000 ** 2,
    "G": 1000 ** 3, "GB": 1000 ** 3,
    "KI": 1 << 10, "KIB": 1 << 10,
    "MI": 1 << 20, "MIB": 1 << 20,
    "GI": 1 << 30, "GIB": 1 << 30,
}


def parse_size(text: str) -> int:
    """'256MiB' / '268435456' / '256M' -> bytes. Binary and decimal both
    spelled explicitly, because a fixture size that means two things is a
    reproducibility hazard."""
    s = str(text).strip().replace("_", "")
    i = 0
    while i < len(s) and (s[i].isdigit()):
        i += 1
    if i == 0:
        raise ValueError("size %r has no leading number" % text)
    unit = s[i:].strip().upper()
    if unit not in _UNITS:
        raise ValueError("size %r: unknown unit %r (use B, KiB, MiB, GiB, KB, MB, GB)"
                         % (text, s[i:]))
    n = int(s[:i]) * _UNITS[unit]
    if n <= 0:
        raise ValueError("size %r is not positive" % text)
    return n


def _seed_volume_id(seed: str) -> int:
    """FAT32 volume serial, derived from the seed so it is a function of the
    fixture and of nothing else. Never a clock reading -- the usual source for
    this field, and the usual reason two 'identical' images differ."""
    return int.from_bytes(hashlib.shake_128(
        ("%s|volume-id" % seed).encode("utf-8")).digest(4), "big")


# --------------------------------------------------------------------------
# The residue adapter -- where two components disagreed
# --------------------------------------------------------------------------


def _residue_adapter(placements, residue_fn):
    """Reconcile plan.make_residue_fn with fat32.build_image.

    plan's residue_fn returns ``None`` for "do not write this cluster";
    fat32.build_image requires exactly ``nbytes`` and raises otherwise. Both
    are defensible on their own and they do not compose, so the join is made
    here, in the caller, explicitly rather than by loosening either side.

    Measured disagreement at 256 MiB / 2048 B clusters: exactly two clusters,
    4 and 5. plan reserves clusters 2..5 for the root directory chain
    (ROOT_DIR_CLUSTERS = 4); fat32 measures the chain at 2 clusters for the
    40 real corpus names and takes 2..3, leaving 4 and 5 free-and-unclaimed
    and therefore offered to residue. Those two are the head-room plan
    deliberately keeps empty, so they are written as zeros -- an unwritten
    cluster, which is what they are.

    The other None case is the one that must never be quietly absorbed: a
    cluster claimed by a planted extent. plan returns None there as its own
    last line of defence for the 12 deleted files, whose FAT chains are freed
    and whose clusters therefore read as FAT-free. If fat32 ever offers one,
    this raises instead of zero-filling it. That is the 40-to-28 defect, and
    silence is exactly how it happened last time.

    Returns (fn, stats) where stats counts what actually happened.
    """
    claimed = plan_mod.claimed_clusters(placements)
    stats = {"residue_written": 0, "root_reserve_zeroed": 0}

    def fn(cluster: int, nbytes: int) -> bytes:
        blob = residue_fn(cluster, nbytes)
        if blob is None:
            if cluster in claimed:
                raise RuntimeError(
                    "residue was offered cluster %d, which a planted extent claims. "
                    "Refusing to fill it: this is the defect that silently reduced "
                    "40 planted files to 28 recoverable." % cluster)
            stats["root_reserve_zeroed"] += 1
            return b"\x00" * nbytes
        stats["residue_written"] += 1
        return blob

    return fn, stats


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------


class BuildResult:
    """What the build measured. Every field here is a measurement, not a
    parameter that was hoped for."""

    __slots__ = ("seed", "geo", "placements", "image", "manifest", "manifest_bytes",
                 "image_sha256", "manifest_sha256", "entropy", "stats",
                 "image_path", "manifest_path", "policy")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


def build(seed: str = DEFAULT_SEED,
          size_bytes: int = DEFAULT_SIZE_BYTES,
          out_dir: str = DEFAULT_OUT,
          bytes_per_cluster: int = 0,
          write: bool = True,
          progress=None) -> BuildResult:
    """Generate the fixture. With ``write=False`` nothing touches the disk and
    no Policy is constructed -- that path exists for the reproducibility test,
    which builds twice in one process and compares hashes."""

    def say(msg: str) -> None:
        if progress is not None:
            progress(msg)

    out_abs = os.path.abspath(out_dir)
    image_path = os.path.join(out_abs, IMAGE_NAME)
    manifest_path = os.path.join(out_abs, MANIFEST_NAME)

    policy = None
    if write:
        # The guard is constructed FIRST, before a single byte is generated.
        # Policy() refuses a root that does not exist and never creates its
        # own, so the directory is made here and the allowlist is asked about
        # it immediately afterwards.
        try:
            os.makedirs(out_abs, exist_ok=True)
        except OSError as e:
            raise guard_mod.PolicyError(
                "cannot create the output root %r: %s" % (out_abs, e.strerror)) from None
        policy = guard_mod.Policy(roots=[out_abs])
        say("guard      policy digest %s root %s" % (policy.digest()[:16], out_abs))

    if bytes_per_cluster <= 0:
        bytes_per_cluster = fat32_mod.largest_valid_cluster_size(size_bytes)
    geo = fat32_mod.compute_geometry(size_bytes, bytes_per_cluster)
    say("geometry   %d B/cluster, %d clusters, data at %d"
        % (geo.bytes_per_cluster, geo.cluster_count, geo.data_start_offset))

    files = corpus_mod.generate_corpus(seed)
    say("corpus     %d files, %d bytes" % (len(files), sum(len(f.data) for f in files)))

    placements = plan_mod.build_plan(geo, files, seed)
    facts = plan_mod.validate_plan(geo, placements)
    say("plan       %d clusters planted, %d fragmented, %d deleted"
        % (facts["planted_clusters"], facts["fragmented"], facts["deleted"]))

    residue_fn, stats = _residue_adapter(placements, plan_mod.make_residue_fn(
        geo, placements, seed))

    image = fat32_mod.build_image(
        geo, placements, residue_fn,
        volume_id=_seed_volume_id(seed),
        verify=True,
    )
    if len(image) != size_bytes:
        raise AssertionError("image is %d bytes, expected %d" % (len(image), size_bytes))
    say("image      %d bytes, %d residue clusters, %d root-reserve clusters zeroed"
        % (len(image), stats["residue_written"], stats["root_reserve_zeroed"]))

    image_sha = hashlib.sha256(image).hexdigest()
    entropy = corpus_mod.shannon_bits_per_byte(image)
    say("entropy    %.4f bits/byte, measured over all %d bytes" % (entropy, len(image)))

    # Two things Phase 2 would otherwise have to guess, both measured here so
    # the carver reads them instead of hardcoding them:
    #
    #  max_gap_clusters / max_gap_is_inclusive -- FRAG-03's gap is EXACTLY the
    #  budget, so `gap < budget` silently costs one file. The convention is
    #  published rather than implied.
    #
    #  residue_signature_false_positives -- the 3-byte magics (JPEG, GZIP, BZ2)
    #  DO occur by chance in the SHAKE residue. Counted on the finished image,
    #  so a precision figure has a floor to subtract rather than a surprise.
    false_positives = plan_mod.measure_signature_false_positives(placements, image)
    say("residue FP %s" % ", ".join("%s %d" % (k, v)
                                    for k, v in sorted(false_positives.items())))

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "seed": seed,
        "filesystem": FILESYSTEM,
        "bytes_per_cluster": geo.bytes_per_cluster,
        "image_bytes": len(image),
        "image_sha256": image_sha,
        "whole_image_entropy_bits_per_byte": round(entropy, 6),
        "max_gap_clusters": plan_mod.MAX_GAP_BUDGET_CLUSTERS,
        "max_gap_is_inclusive": plan_mod.MAX_GAP_IS_INCLUSIVE,
        "residue_signature_false_positives": false_positives,
        "counted_set": plan_mod.counted_set(placements),
        "files": [p.as_manifest() for p in placements],
    }
    manifest_bytes = _encode_manifest(manifest)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()

    if write:
        _guarded_write(policy, image_path, image)
        _guarded_write(policy, manifest_path, manifest_bytes)
        say("wrote      %s" % image_path)
        say("wrote      %s" % manifest_path)

    return BuildResult(seed=seed, geo=geo, placements=placements, image=image,
                       manifest=manifest, manifest_bytes=manifest_bytes,
                       image_sha256=image_sha, manifest_sha256=manifest_sha,
                       entropy=entropy, stats=stats, image_path=image_path,
                       manifest_path=manifest_path, policy=policy)


def _encode_manifest(manifest: dict) -> bytes:
    """JSON -> bytes, with every newline placed by hand.

    json.dumps(indent=2) emits "\\n"; encoding to UTF-8 here and handing the
    result to os.write means no text layer ever sees it. On Windows a text-mode
    write would turn each of those into "\\r\\n" and change the manifest hash,
    which is rule 5. ensure_ascii keeps the bytes independent of any locale.
    """
    text = json.dumps(manifest, indent=2, ensure_ascii=True, sort_keys=False,
                      separators=(",", ": "))
    return text.encode("utf-8").replace(b"\r\n", b"\n") + b"\n"


def _guarded_write(policy, path: str, payload: bytes) -> int:
    """Every byte of the fixture leaves through a descriptor the guard issued.

    Mode "w": creates the target if absent, truncates it if a previous build
    left one. The descriptor is a raw int and the caller closes it, so the
    close is in a finally.
    """
    fd = guard_mod.open_authorized(policy, path, "w")
    try:
        os.ftruncate(fd, 0)
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:written + (1 << 20)])
        os.fsync(fd)
    finally:
        os.close(fd)
    if written != len(payload):
        raise IOError("short write: %d of %d bytes to %s" % (written, len(payload), path))
    return written


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


MATCH = "match"
MISMATCH = "mismatch"
NO_RECORD = "no-record"
NOT_COMPARABLE = "not-comparable"


def _compare_expected(res: BuildResult, expected_path: str) -> tuple:
    """Compare the build against the committed digest record.

    Returns (verdict, expected_or_None). The verdict is the ONLY thing the
    exit status is derived from, and it is computed here rather than inside
    the printer, so --quiet cannot skip the comparison. That was the defect:
    `make fixtures` printed "committed sha256 match  NO" and exited 0, and in
    --quiet -- the advertised scripting mode -- it never compared at all.
    """
    exp = _read_expected(expected_path)
    if exp is None:
        return NO_RECORD, None
    if exp.get("seed") != res.seed or exp.get("size_bytes") != res.manifest["image_bytes"]:
        return NOT_COMPARABLE, exp
    ok = (exp.get("image_sha256") == res.image_sha256
          and exp.get("manifest_sha256") == res.manifest_sha256)
    return (MATCH if ok else MISMATCH), exp


def _write_mismatch(res: BuildResult, exp: dict, expected_path: str) -> None:
    """The two hash pairs, on stderr, in both quiet and loud modes."""
    w = sys.stderr.write
    w("build_image: BUILT FIXTURE DOES NOT MATCH %s\n"
      % os.path.relpath(expected_path, _REPO))
    w("  committed image       %s\n" % exp.get("image_sha256"))
    w("  built image           %s\n" % res.image_sha256)
    w("  committed manifest    %s\n" % exp.get("manifest_sha256"))
    w("  built manifest        %s\n" % res.manifest_sha256)
    w("  If the fixture changed ON PURPOSE, rebuild with --no-check-expected and\n")
    w("  update the `expected` block in fixtures/manifest.json in the same commit.\n")


def _report(res: BuildResult, expected_path: str, verdict: str, exp) -> None:
    cs = res.manifest["counted_set"]
    frag = [p for p in res.placements if p.fragmented]
    unrec = [p for p in res.placements if p.expected_recoverable == plan_mod.UNRECOVERABLE]
    w = sys.stdout.write
    w("\n")
    w("  seed                      %s\n" % res.seed)
    w("  filesystem                %s, %d B/cluster, %d clusters\n"
      % (FILESYSTEM, res.geo.bytes_per_cluster, res.geo.cluster_count))
    w("  image                     %d bytes\n" % res.manifest["image_bytes"])
    w("  image sha256              %s\n" % res.image_sha256)
    w("  manifest sha256           %s\n" % res.manifest_sha256)
    w("  whole-image entropy       %.4f bits/byte\n"
      % res.manifest["whole_image_entropy_bits_per_byte"])
    w("  planted                   %d files, %d fragmented, %d deleted\n"
      % (cs["total"], len(frag), sum(1 for p in res.placements if p.deleted)))
    w("  expected recoverable      %d of %d\n" % (cs["expected_recoverable"], cs["total"]))
    nosig = [p for p in unrec if not p.frag_id]
    byfrag = [p for p in unrec if p.frag_id]
    w("  unrecoverable by design   %d\n" % cs["unrecoverable_by_design"])
    if nosig:
        w("    no signature to carve   %d  (%s)\n"
          % (len(nosig), ", ".join(p.name for p in nosig)))
    for p in byfrag:
        w("    %-23s %s\n" % (p.frag_id, p.name))
    w("  residue clusters written  %d\n" % res.stats["residue_written"])
    w("  root reserve zeroed       %d clusters\n" % res.stats["root_reserve_zeroed"])
    w("\n")

    rel = os.path.relpath(expected_path, _REPO)
    if verdict == NO_RECORD:
        w("  expected digests          %s carries none; nothing to compare\n" % rel)
        return
    if verdict == NOT_COMPARABLE:
        w("  expected digests          not comparable: committed record is for seed %r "
          "at %s bytes\n" % (exp.get("seed"), exp.get("size_bytes")))
        return
    w("  committed sha256 match    %s  (%s)\n"
      % ("yes" if verdict == MATCH else "NO", rel))


def _read_expected(path: str):
    """The committed expectation record, or None. Read-only; nothing in the
    build path writes it."""
    try:
        with open(path, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError):
        return None
    exp = doc.get("expected")
    return exp if isinstance(exp, dict) else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="build_image.py",
        description="Build the SENTINELWIPE forensic fixture: a FAT32 image with "
                    "40 planted files of known SHA-256, and its manifest.")
    ap.add_argument("--seed", default=DEFAULT_SEED,
                    help="fixture seed; every byte is a function of it (default: %(default)s)")
    ap.add_argument("--size", default="256MiB",
                    help="image size, e.g. 256MiB or 268435456 (default: %(default)s)")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="output directory for the image and manifest, and the only "
                         "path the write guard allows (default: %(default)s)")
    ap.add_argument("--bytes-per-cluster", type=int, default=0,
                    help="cluster size; 0 picks the largest valid for the image size "
                         "(2048 at 256 MiB -- 4096 falls below the FAT32 minimum of "
                         "65525 clusters)")
    ap.add_argument("--quiet", action="store_true", help="suppress progress lines")
    ap.add_argument("--no-check-expected", action="store_true",
                    help="build without failing on a mismatch against the committed "
                         "digests in fixtures/manifest.json. The escape hatch for a "
                         "DELIBERATE fixture change: rebuild with this, then update "
                         "the expected block in the same commit. Without it a "
                         "mismatch exits 4.")
    args = ap.parse_args(argv)

    try:
        size_bytes = parse_size(args.size)
    except ValueError as e:
        sys.stderr.write("build_image: %s\n" % e)
        return 2

    progress = None if args.quiet else (lambda m: sys.stdout.write("  %s\n" % m))
    try:
        res = build(seed=args.seed, size_bytes=size_bytes, out_dir=args.out,
                    bytes_per_cluster=args.bytes_per_cluster, progress=progress)
    except guard_mod.PolicyError as e:
        # --out named a place no fixture may be written to. The allowlist said
        # so before anything was generated, which is the point of building the
        # policy first.
        sys.stderr.write("build_image: refusing --out %r: %s\n" % (args.out, e))
        return 3
    except guard_mod.GuardError as e:
        sys.stderr.write("build_image: write refused by the guard: %s (%s)\n"
                         % (e.decision.code, e.decision.resolved))
        return 3
    except (ValueError, RuntimeError, AssertionError) as e:
        sys.stderr.write("build_image: %s\n" % e)
        return 1

    # The comparison runs in BOTH modes. Exit status carries it, so `make
    # fixtures` and any script that shells out here fail on drift instead of
    # printing "NO" and returning success.
    expected_path = os.path.join(_REPO, "fixtures", "manifest.json")
    verdict, exp = _compare_expected(res, expected_path)

    if not args.quiet:
        _report(res, expected_path, verdict, exp)
    else:
        sys.stdout.write("%s  %s\n" % (res.image_sha256, res.image_path))

    if verdict == MISMATCH:
        sys.stdout.flush()                 # so the report precedes the stderr block
        _write_mismatch(res, exp, expected_path)
        if args.no_check_expected:
            sys.stderr.write("build_image: --no-check-expected given; "
                             "exiting 0 on a deliberate change.\n")
            return 0
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
