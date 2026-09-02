"""End-to-end suite for the Phase-1 forensic fixture.

Five of these tests exist because the previous round shipped the defect they
catch. Each says so in its own docstring; none of them is decoration.

The expensive part -- generating the 40-file corpus and assembling a 256 MiB
image -- happens once, in a session-scoped fixture, and every assertion is made
against that one build. The determinism test pays for a second build on
purpose: a hash compared against itself proves nothing.

Run: uv run pytest -q tests/test_fixtures.py
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

# fixtures/ is a directory at the repo root, not on pythonpath (pyproject sets
# pythonpath = ["py"]). Import it as a namespace package from the repo root.
_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from fixtures import build_image as B  # noqa: E402
from fixtures import corpus as C       # noqa: E402
from fixtures import fat32 as F        # noqa: E402
from fixtures import plan as P         # noqa: E402

SEED = B.DEFAULT_SEED
SIZE = B.DEFAULT_SIZE_BYTES
TRACKED_POINTER = _REPO / "fixtures" / "manifest.json"


# --------------------------------------------------------------------------
# One build, shared
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def built():
    """The fixture, built in-process with write=False: no Policy, no bytes on
    disk, nothing for a test to leave behind. Every on-disk write in this
    project goes through the guard, and a test suite is not an exception -- so
    it does not write at all."""
    return B.build(seed=SEED, size_bytes=SIZE, write=False)


@pytest.fixture(scope="session")
def manifest(built):
    """The manifest exactly as it is written: decoded from the emitted bytes,
    not from the dict, so the tests read what the file will contain."""
    return json.loads(built.manifest_bytes.decode("utf-8"))


# --------------------------------------------------------------------------
# 1 · Determinism
# --------------------------------------------------------------------------


def test_two_builds_from_one_seed_are_byte_identical(built):
    """CLAUDE.md rule 6. A second build, same seed, same everything."""
    again = B.build(seed=SEED, size_bytes=SIZE, write=False)
    assert again.image_sha256 == built.image_sha256
    assert again.manifest_sha256 == built.manifest_sha256
    assert again.image == built.image
    assert again.manifest_bytes == built.manifest_bytes


def test_a_second_seed_moves_every_hash(built):
    """The determinism test above is vacuous if the seed is not actually
    driving the bytes. A different seed must produce a different image."""
    other = B.build(seed=SEED + "/v2-probe", size_bytes=SIZE, write=False)
    assert other.image_sha256 != built.image_sha256
    assert other.manifest_sha256 != built.manifest_sha256
    assert len(other.image) == len(built.image)


def test_a_fresh_interpreter_under_a_hostile_environment_agrees(built, tmp_path):
    """In-process repetition cannot see interpreter-level nondeterminism.
    This one runs the real CLI in a new process with PYTHONHASHSEED, TZ, LANG
    and umask all changed, which is where hash-order and locale drift would
    show up."""
    env = dict(os.environ)
    env.update(PYTHONHASHSEED="12345", TZ="Pacific/Chatham",
               LANG="tr_TR.UTF-8", LC_ALL="tr_TR.UTF-8")
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(_REPO / "fixtures" / "build_image.py"),
         "--seed", SEED, "--size", str(SIZE), "--out", str(out), "--quiet"],
        cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=900)
    # returncode 0 now asserts TWO things: the build ran, and it matched the
    # digests committed in fixtures/manifest.json. A drifted fixture exits 4.
    assert proc.returncode == 0, proc.stderr
    printed = proc.stdout.split()[0]
    assert printed == built.image_sha256, proc.stdout
    on_disk = (out / B.IMAGE_NAME).read_bytes()
    assert hashlib.sha256(on_disk).hexdigest() == built.image_sha256


# --------------------------------------------------------------------------
# 2 · The manifest describes the image that exists
# --------------------------------------------------------------------------

REQUIRED_FILE_FIELDS = ("path", "offset", "size", "sha256", "fragmented",
                        "expected_recoverable")


def test_every_file_carries_all_six_required_fields(manifest):
    """The build pack names six per-file fields. A manifest missing one is a
    manifest a downstream consumer has to guess at."""
    assert manifest["files"], "manifest lists no files"
    for entry in manifest["files"]:
        missing = [k for k in REQUIRED_FILE_FIELDS if k not in entry]
        assert not missing, "%s missing %r" % (entry.get("path"), missing)
        assert entry["path"].startswith("/")
        assert isinstance(entry["size"], int) and entry["size"] > 0
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
        assert isinstance(entry["fragmented"], bool)
        assert entry["expected_recoverable"] in (
            P.SIG_ONLY, P.BIFRAGMENT, P.UNRECOVERABLE)
        assert entry["offset"] == entry["extents"][0]["byte_offset"]


def test_manifest_header_matches_the_measured_image(built, manifest):
    assert manifest["schema"] == B.MANIFEST_SCHEMA
    assert manifest["seed"] == SEED
    assert manifest["filesystem"] == "FAT32"
    assert manifest["bytes_per_cluster"] == built.geo.bytes_per_cluster
    assert manifest["image_bytes"] == len(built.image) == SIZE
    assert manifest["image_sha256"] == hashlib.sha256(built.image).hexdigest()
    assert len(manifest["files"]) == 40


def test_whole_image_entropy_is_measured_on_the_real_bytes(built, manifest):
    """CLAUDE.md rule 2: every number on screen traces to a measurement. The
    demo's entropy line reads this field, so it must be the entropy of the
    image that was actually assembled -- not of a simulation, and not of the
    corpus alone."""
    got = manifest["whole_image_entropy_bits_per_byte"]
    assert got == pytest.approx(C.shannon_bits_per_byte(built.image), abs=1e-6)
    # Sanity band: an all-zero image is 0.0 and a SHAKE-filled one is ~8.0.
    # A pre-wipe fixture that already sits at 8.0 leaves the wipe nothing to
    # demonstrate, which is the reason the residue is a mix.
    assert 5.0 < got < 7.9


def test_counted_set_is_consistent_with_the_file_list(manifest):
    cs = manifest["counted_set"]
    files = manifest["files"]
    unrec = [f for f in files if f["expected_recoverable"] == P.UNRECOVERABLE]
    assert cs["total"] == len(files) == 40
    assert cs["unrecoverable_by_design"] == len(unrec) == 2
    assert cs["expected_recoverable"] == len(files) - len(unrec) == 38
    # The operator's decision, asserted rather than trusted to the narration:
    # the demo never reports a round 40 of 40.
    assert cs["expected_recoverable"] != cs["total"]


def test_the_manifest_bytes_carry_no_carriage_return(built):
    """Rule 5. The manifest is written in binary with explicit b"\\n". A
    text-mode write on Windows would translate every newline and move the
    manifest hash, and no test on this laptop would have noticed."""
    assert b"\r" not in built.manifest_bytes
    assert built.manifest_bytes.endswith(b"\n")
    assert json.loads(built.manifest_bytes.decode("utf-8"))["schema"] == B.MANIFEST_SCHEMA


# --------------------------------------------------------------------------
# 3 · Every extent offset holds the bytes the manifest claims
# --------------------------------------------------------------------------

# Magic at byte 0 of the file, by corpus kind. MP4 is the exception: its
# signature is 'ftyp' at offset 4, which is why the carver keys on the box
# tree and not on byte 0.
MAGIC_AT_0 = {
    "GZIP": b"\x1f\x8b\x08",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "PDF": b"%PDF-",
    "DOCX": b"PK\x03\x04",
    "SQLITE": b"SQLite format 3\x00",
}


def test_first_extent_offset_holds_the_files_magic_bytes(built, manifest):
    """The manifest's offsets are what Phase 2 carves against. If one is wrong
    the carver finds nothing and the failure looks like a carver bug."""
    img = built.image
    checked = {}
    for entry in manifest["files"]:
        off = entry["extents"][0]["byte_offset"]
        kind = entry["kind"]
        if kind == "MP4":
            assert img[off + 4:off + 8] == b"ftyp", entry["path"]
        elif kind == "TXT":
            head = img[off:off + 64]
            head.decode("ascii")                      # raises if it is not text
            assert head.strip(), entry["path"]
        else:
            magic = MAGIC_AT_0[kind]
            assert img[off:off + len(magic)] == magic, entry["path"]
        checked[kind] = checked.get(kind, 0) + 1
    assert sorted(checked) == sorted(C.KINDS), checked
    assert set(checked.values()) == {5}, checked


def test_every_extent_holds_its_own_slice_and_the_file_reassembles(built, manifest):
    """Not only the first extent. Reading every extent in LOGICAL order out of
    the image and concatenating must reproduce the recorded SHA-256 -- which is
    the operation the carver has to perform, done here against the manifest."""
    img = built.image
    by_name = {"/" + p.name: p for p in built.placements}
    for entry in manifest["files"]:
        p = by_name[entry["path"]]
        pos = 0
        chunks = []
        for ext in entry["extents"]:
            blob = img[ext["byte_offset"]:ext["byte_offset"] + ext["byte_length"]]
            assert blob == p.data[pos:pos + ext["byte_length"]], (
                "%s: extent at %d does not hold its slice" % (entry["path"],
                                                              ext["byte_offset"]))
            chunks.append(blob)
            pos += ext["byte_length"]
        rebuilt = b"".join(chunks)
        assert len(rebuilt) == entry["size"]
        assert hashlib.sha256(rebuilt).hexdigest() == entry["sha256"], entry["path"]


def test_extent_arithmetic_agrees_with_the_geometry(built, manifest):
    geo = built.geo
    bpc = geo.bytes_per_cluster
    seen = {}
    for entry in manifest["files"]:
        total = 0
        for ext in entry["extents"]:
            assert ext["byte_offset"] == geo.cluster_offset(ext["cluster_start"])
            assert ext["cluster_count"] == -(-ext["byte_length"] // bpc)
            assert geo.first_cluster <= ext["cluster_start"]
            assert ext["cluster_start"] + ext["cluster_count"] - 1 <= geo.last_cluster
            for c in range(ext["cluster_start"],
                           ext["cluster_start"] + ext["cluster_count"]):
                assert c not in seen, "cluster %d claimed by %s and %s" % (
                    c, seen[c], entry["path"])
                seen[c] = entry["path"]
            total += ext["byte_length"]
        assert total == entry["size"]


# --------------------------------------------------------------------------
# 4 · THE REGRESSION TEST: the deleted files survive the residue fill
# --------------------------------------------------------------------------


def _fat_entry(geo, img, cluster: int) -> int:
    off = geo.reserved * geo.bytes_per_sector + cluster * 4
    return struct.unpack_from("<I", img, off)[0] & 0x0FFFFFFF


def test_deleted_files_survive_the_residue_fill(built, manifest):
    """THE regression test. Deletion sets the dirent to 0xE5 and frees the FAT
    chain, so all 12 deleted files' clusters read FREE. A residue rule keyed on
    "FAT-free" alone overwrites every one of them and the demo degrades from 40
    planted to 28 recoverable WITH NO ERROR ANYWHERE. The rule is FAT-free AND
    not claimed by any planted extent, and this asserts the outcome of it."""
    img = built.image
    deleted = [e for e in manifest["files"] if e["deleted"]]
    assert len(deleted) == 12, "expected 12 deleted files, got %d" % len(deleted)

    survived = 0
    for entry in deleted:
        rebuilt = b"".join(
            img[x["byte_offset"]:x["byte_offset"] + x["byte_length"]]
            for x in entry["extents"])
        assert hashlib.sha256(rebuilt).hexdigest() == entry["sha256"], (
            "%s was overwritten by the residue fill" % entry["path"])
        survived += 1
    assert survived == 12


def test_the_naive_residue_rule_would_have_destroyed_all_twelve(built, manifest):
    """The negative control for the test above. If the deleted files' clusters
    were NOT FAT-free, the previous defect could not have happened and the test
    above would be passing for the wrong reason. Measured: every cluster of
    every deleted file is marked FREE in both FAT copies, i.e. every one of
    them is in the naive rule's path."""
    geo, img = built.geo, built.image
    free = 0
    total = 0
    for entry in manifest["files"]:
        if not entry["deleted"]:
            continue
        for ext in entry["extents"]:
            for c in range(ext["cluster_start"],
                           ext["cluster_start"] + ext["cluster_count"]):
                total += 1
                if _fat_entry(geo, img, c) == 0:
                    free += 1
    assert total > 0
    assert free == total, ("%d of %d deleted clusters are FAT-free; the naive "
                           "rule's blast radius is not what it was" % (free, total))


def test_the_survival_check_can_actually_fail(built, manifest):
    """The other half of the negative control. The two tests above assert that
    the deleted files survived and that the naive rule would have reached them;
    this one applies the naive rule to a copy and confirms the survival check
    then FAILS. Without it, `test_deleted_files_survive_the_residue_fill` could
    be green because the assertion is unreachable rather than because the rule
    is right.

    Only the deleted files' own clusters are overwritten -- that is precisely
    the subset the naive "FAT-free" rule adds over the correct rule -- so the
    control costs 12 files' worth of bytes, not a second 256 MiB image.
    """
    geo = built.geo
    img = bytearray(built.image)
    deleted = [e for e in manifest["files"] if e["deleted"]]
    naive = P.make_residue_fn(geo, [], SEED)          # no placements: nothing claimed
    touched = 0
    for entry in deleted:
        for ext in entry["extents"]:
            for c in range(ext["cluster_start"],
                           ext["cluster_start"] + ext["cluster_count"]):
                assert _fat_entry(geo, built.image, c) == 0
                blob = naive(c, geo.bytes_per_cluster)
                assert blob is not None, (
                    "cluster %d is FAT-free and unclaimed under the naive rule, so "
                    "the naive fill really does reach it" % c)
                off = geo.cluster_offset(c)
                img[off:off + geo.bytes_per_cluster] = blob
                touched += 1
    assert touched > 0

    destroyed = 0
    for entry in deleted:
        rebuilt = b"".join(
            bytes(img[x["byte_offset"]:x["byte_offset"] + x["byte_length"]])
            for x in entry["extents"])
        if hashlib.sha256(rebuilt).hexdigest() != entry["sha256"]:
            destroyed += 1
    assert destroyed == len(deleted) == 12, (
        "the naive rule destroyed %d of %d deleted files; the survival test is "
        "not measuring what it claims" % (destroyed, len(deleted)))


def test_deleted_entries_carry_no_allocation_information(built, manifest):
    """A deleted file must exist ONLY as unreferenced data -- a stated Phase-1
    acceptance criterion.

    MEASURED defect this catches. Marking the first byte 0xE5 and freeing the
    FAT chain is only half a delete: the short entry still held
    DIR_FstClusHI/LO and DIR_FileSize, so a metadata reader needed no carving
    at all. The Sleuth Kit's `icat` recovered 8 of the 12 deleted files
    byte-perfect from the directory alone -- every contiguous one -- which
    makes "unreferenced" false and is falsifiable by a jury in five seconds.

    Asserted on the directory bytes rather than through TSK, so the check runs
    with no external tool. Measured with TSK afterwards: 0 of 12, each icat
    emitting 0 bytes, while all 28 live files still recover byte-perfect."""
    got = F.read_image(built.image)
    by_name = {(e["long_name"] or e["short_name"]): e for e in got["files"]}
    gone = [e["path"].lstrip("/") for e in manifest["files"] if e["deleted"]]
    assert len(gone) == 12

    for name in gone:
        e = by_name[name]
        assert e["deleted"] is True, name
        assert e["first_cluster"] == 0, (
            "%s keeps start cluster %d; a metadata reader follows it with no "
            "carving" % (name, e["first_cluster"]))
        assert e["size"] == 0, "%s keeps its file size %d" % (name, e["size"])
        assert e["chain"] == [], name
        # The long name must SURVIVE, or `fls` shows a stub during the
        # independent cross-check and blocker (a) reopens.
        assert e["long_name"] == name

    # The data itself is untouched -- unreferenced, not erased. That is the
    # whole point: the carver has to find it.
    img = built.image
    for entry in manifest["files"]:
        if not entry["deleted"]:
            continue
        rebuilt = b"".join(img[x["byte_offset"]:x["byte_offset"] + x["byte_length"]]
                           for x in entry["extents"])
        assert hashlib.sha256(rebuilt).hexdigest() == entry["sha256"], entry["path"]


def test_live_entries_still_carry_their_allocation_fields(built, manifest):
    """The negative control for the test above. If the zeroing reached live
    entries the volume would be broken, and 'deleted' would not be
    distinguishable from 'corrupt'."""
    got = F.read_image(built.image)
    by_name = {(e["long_name"] or e["short_name"]): e for e in got["files"]}
    live = [e for e in manifest["files"] if not e["deleted"]]
    assert len(live) == 28
    for entry in live:
        e = by_name[entry["path"].lstrip("/")]
        assert e["first_cluster"] == entry["extents"][0]["cluster_start"]
        assert e["size"] == entry["size"]
        assert e["sha256"] == entry["sha256"]


def test_live_files_still_have_their_fat_chains(built, manifest):
    """The other half of deletion: a live file must be reachable through the
    FAT, or 'deleted' is not distinguishable from 'broken'."""
    geo, img = built.geo, built.image
    for entry in manifest["files"]:
        if entry["deleted"]:
            continue
        first = entry["extents"][0]["cluster_start"]
        assert _fat_entry(geo, img, first) != 0, entry["path"]


def test_the_residue_never_wrote_into_a_planted_cluster(built):
    """Belt and braces on the rule itself rather than on its outcome: the
    adapter counts every cluster it filled, and planted clusters plus residue
    clusters plus the root reserve must exactly account for the data area."""
    geo = built.geo
    planted = len(P.claimed_clusters(built.placements))
    residue = built.stats["residue_written"]
    zeroed = built.stats["root_reserve_zeroed"]
    root = F.root_directory_clusters(geo, [p.name for p in built.placements])
    assert planted + residue + zeroed + root == geo.cluster_count, (
        planted, residue, zeroed, root, geo.cluster_count)


def test_the_reserved_region_is_untouched_by_residue(built):
    """The residue writer must never touch the boot sector, either FAT, the
    FSInfo sectors, the backup boot region or the root directory. A
    cluster-indexed function structurally cannot reach the first four -- they
    live below data_start_offset -- so this asserts the structure holds."""
    geo, img = built.geo, built.image
    sec = geo.bytes_per_sector
    assert img[510:512] == b"\x55\xaa"                     # boot signature
    assert img[6 * sec:6 * sec + 512] == img[0:512]        # backup boot sector
    assert img[sec:sec + 4] == b"RRaA"                     # FSInfo lead
    assert img[7 * sec:7 * sec + 4] == b"RRaA"             # backup FSInfo
    fat0 = geo.reserved * sec
    fat1 = fat0 + geo.fat_sectors * sec
    n = geo.fat_sectors * sec
    assert img[fat0:fat0 + n] == img[fat1:fat1 + n], "the two FAT copies differ"


# --------------------------------------------------------------------------
# 5 · fragmented means NON-ADJACENT
# --------------------------------------------------------------------------


def test_fragmented_means_non_adjacent_not_multiple_extents(manifest):
    """A previous harness read fragmented as len(extents) > 1. Two runs that
    abut are one physical run and a carver reading forward never notices them,
    so that definition overstates the fixture's difficulty."""
    for entry in manifest["files"]:
        runs = sorted(entry["extents"], key=lambda e: e["cluster_start"])
        non_adjacent = any(
            b["cluster_start"] != a["cluster_start"] + a["cluster_count"]
            for a, b in zip(runs, runs[1:]))
        assert entry["fragmented"] == non_adjacent, entry["path"]
        if entry["fragmented"]:
            assert len(entry["extents"]) > 1


def test_the_two_definitions_actually_differ(built):
    """The test above is only meaningful if the two definitions can disagree.
    Two touching extents: len(extents) == 2 but fragmented is False."""
    bpc = built.geo.bytes_per_cluster
    touching = [P.Extent(cluster_start=100, cluster_count=2,
                         byte_offset=0, byte_length=2 * bpc),
                P.Extent(cluster_start=102, cluster_count=1,
                         byte_offset=2 * bpc, byte_length=10)]
    assert len(touching) > 1
    assert P.is_fragmented(touching) is False
    apart = [touching[0], P.Extent(cluster_start=103, cluster_count=1,
                                   byte_offset=3 * bpc, byte_length=10)]
    assert P.is_fragmented(apart) is True

    # Third case, and the one a sort-then-compare implementation gets wrong:
    # two TOUCHING runs in reverse logical order. Physically contiguous, so
    # adjacency alone says "not fragmented", but the file reassembles
    # backwards and a forward-reading carver produces a wrong hash. FRAG-07's
    # entire reason for existing is direction, so a flag blind to direction
    # would mislabel exactly the case the fixture was built to test.
    reversed_adjacent = [
        P.Extent(cluster_start=110, cluster_count=5,
                 byte_offset=110 * bpc, byte_length=5 * bpc),
        P.Extent(cluster_start=105, cluster_count=5,
                 byte_offset=105 * bpc, byte_length=10),
    ]
    runs = sorted(reversed_adjacent, key=lambda e: e.cluster_start)
    assert runs[1].cluster_start == runs[0].cluster_start + runs[0].cluster_count, \
        "the probe is only meaningful if the two runs really do touch"
    assert P.is_fragmented(reversed_adjacent) is True


def test_the_fragmentation_ladder_is_present_and_attributable(manifest, built):
    """All seven rungs, and the two deliberate failures named. FRAG-06 and
    FRAG-07 must fail for their structural reason -- fragment count and
    fragment direction -- never for exceeding the carver's max_gap budget, or
    the demo cannot attribute the failure on screen."""
    frag = [e for e in manifest["files"] if e["fragmented"]]
    assert len(frag) == 7
    by_fid = {p.frag_id: p for p in built.placements if p.frag_id}
    assert sorted(by_fid) == ["FRAG-0%d" % i for i in range(1, 8)]

    def gaps(p):
        return [b.cluster_start - (a.cluster_start + a.cluster_count)
                for a, b in zip(p.extents, p.extents[1:])]

    assert gaps(by_fid["FRAG-01"]) == [1]
    assert gaps(by_fid["FRAG-02"]) == [16]
    assert gaps(by_fid["FRAG-03"]) == [128] == [P.MAX_GAP_BUDGET_CLUSTERS]
    assert gaps(by_fid["FRAG-04"]) == [50]
    assert gaps(by_fid["FRAG-05"]) == [70]
    assert len(by_fid["FRAG-06"].extents) == 3
    assert max(gaps(by_fid["FRAG-06"])) <= P.MAX_GAP_BUDGET_CLUSTERS

    p7 = by_fid["FRAG-07"]
    assert p7.extents[0].cluster_start > p7.extents[1].cluster_start, \
        "FRAG-07 must be physically out of order"
    back = p7.extents[0].cluster_start - (p7.extents[1].cluster_start
                                          + p7.extents[1].cluster_count)
    assert back <= P.MAX_GAP_BUDGET_CLUSTERS

    unrec = {p.frag_id for p in built.placements
             if p.expected_recoverable == P.UNRECOVERABLE}
    assert unrec == {"FRAG-06", "FRAG-07"}
    # The mutual interleave, and the fact that it straddles the deleted line.
    a0, a1 = by_fid["FRAG-04"].extents
    b0, b1 = by_fid["FRAG-05"].extents
    assert a0.cluster_start + a0.cluster_count <= b0.cluster_start
    assert b0.cluster_start + b0.cluster_count <= a1.cluster_start
    assert a1.cluster_start + a1.cluster_count <= b1.cluster_start
    assert by_fid["FRAG-04"].kind == by_fid["FRAG-05"].kind
    assert by_fid["FRAG-06"].deleted and not by_fid["FRAG-07"].deleted


def test_the_max_gap_budget_is_published_with_its_convention(manifest):
    """FRAG-03's gap is EXACTLY the budget, which is the only way a rung can
    prove a budget rather than merely respect it -- and that makes the
    comparison operator load-bearing. A Phase-2 carver implementing
    `gap < budget` instead of `gap <= budget` loses disposal_certificate.pdf,
    the counted set drops from 38 to 37 with no error raised, and the demo's
    attribution (FRAG-06 fails on fragment COUNT, FRAG-07 on DIRECTION,
    neither on distance) becomes false on stage.

    So the convention is published in the manifest for the carver to read
    instead of hardcode, and asserted here."""
    assert manifest["max_gap_clusters"] == P.MAX_GAP_BUDGET_CLUSTERS == 128
    assert manifest["max_gap_is_inclusive"] is True

    budget = manifest["max_gap_clusters"]
    on_the_boundary = []
    for entry in manifest["files"]:
        runs = sorted(entry["extents"], key=lambda e: e["cluster_start"])
        for a, b in zip(runs, runs[1:]):
            gap = b["cluster_start"] - (a["cluster_start"] + a["cluster_count"])
            assert gap <= budget, (entry["path"], gap)
            if gap == budget:
                on_the_boundary.append(entry["path"])
    assert on_the_boundary == ["/disposal_certificate.pdf"], on_the_boundary


def test_the_file_sitting_on_the_budget_is_counted_as_recoverable(manifest):
    """The off-by-one, made to fail loudly. disposal_certificate.pdf is
    counted in expected_recoverable at a gap of exactly max_gap_clusters; if
    that ever stops being true the fixture and the carver disagree about the
    convention, and one file goes missing quietly."""
    pdf = [e for e in manifest["files"]
           if e["path"] == "/disposal_certificate.pdf"][0]
    assert pdf["expected_recoverable"] == P.BIFRAGMENT
    assert pdf["fragmented"] is True
    assert len(pdf["extents"]) == 2
    a, b = pdf["extents"]
    assert b["cluster_start"] - (a["cluster_start"] + a["cluster_count"]) == \
        manifest["max_gap_clusters"]


def test_the_residue_false_positive_floor_is_measured_and_published(built, manifest):
    """CLAUDE.md rule 2, applied to a number Phase 2 will otherwise discover
    on stage. 52% of the eligible clusters are SHAKE output, and the expected
    count of a magic in ~134 MB of uniform bytes depends by orders of
    magnitude on its LENGTH: ~0.03 for a 4-byte magic, ~8 for a 3-byte one.
    JPEG, GZIP and BZ2 are 3-byte signatures, so they DO occur by chance.

    Recomputed here from the image bytes with an independent scan, so the
    published floor is a measurement of this fixture rather than a figure
    copied forward."""
    published = manifest["residue_signature_false_positives"]
    assert set(published) == {n for n, _sig in P.CARVER_SIGNATURES}

    img = built.image
    ranges = P.planted_byte_ranges(built.placements)
    for name, sig in P.CARVER_SIGNATURES:
        n, pos = 0, img.find(sig)
        while pos >= 0:
            if not any(lo <= pos < hi for lo, hi in ranges):
                n += 1
            pos = img.find(sig, pos + 1)
        assert published[name] == n, name

    # The 4-byte-and-longer signatures must be clean, or the carver's
    # precision on them is not a property of the carver.
    for name in ("PNG", "PDF", "ZIP", "SQLITE", "MP4"):
        assert published[name] == 0, (name, published[name])
    # And the 3-byte ones must NOT be, or the floor is a fiction and Phase 2
    # would be tuned against a fixture that cannot produce a false positive.
    assert published["JPEG"] > 0 and published["GZIP"] > 0


# --------------------------------------------------------------------------
# 6 · Rule 1: no zlib compressor anywhere in the fixture path
# --------------------------------------------------------------------------

# zlib.compress output is a property of the linked libz, not of the input:
# Info-ZIP and zlib produced 13,937 and 14,066 bytes from identical input.
# PNG, DOCX and GZIP all ride on DEFLATE, so a compressor here would make the
# corpus differ per laptop. crc32, adler32 and decompress are fixed algorithms
# and stay allowed.
_BANNED = re.compile(
    r"zlib\.compress|compressobj|zlib\.compressobj|gzip\.(open|compress|GzipFile)"
    r"|zipfile\.|ZipFile|ZIP_DEFLATED|bz2\.|lzma\.|import\s+random\b|random\.(?!$)"
    r"|time\.time\(|datetime\.|uuid\.|os\.urandom")

_FIXTURE_MODULES = ("guard.py", "deflate.py", "corpus.py", "fat32.py", "plan.py",
                    "build_image.py")


def _code_lines(path: Path):
    """Source lines with comments and docstring bodies removed, so a rule that
    is DESCRIBED in prose does not read as a rule that is BROKEN in code."""
    text = path.read_text(encoding="utf-8")
    text = re.sub(r'"""(?:.|\n)*?"""', '""', text)
    text = re.sub(r"'''(?:.|\n)*?'''", "''", text)
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.split("#", 1)[0]
        if stripped.strip():
            yield i, stripped


def test_no_compressor_and_no_clock_in_the_fixture_path():
    """Rule 1, enforced as a grep test the way the spec asks for it."""
    hits = []
    for name in _FIXTURE_MODULES:
        path = _REPO / "fixtures" / name
        for i, line in _code_lines(path):
            m = _BANNED.search(line)
            if m:
                hits.append("fixtures/%s:%d: %s  (%s)" % (name, i, line.strip(),
                                                          m.group(0)))
    assert not hits, "banned call in the fixture path:\n  " + "\n  ".join(hits)


def test_the_compressor_grep_is_not_vacuous(tmp_path):
    """A grep control that matches nothing is indistinguishable from one that
    does not work."""
    probe = tmp_path / "probe.py"
    probe.write_bytes(b"import zlib\nx = zlib.compress(b'a')\ny = time.time()\n")
    hits = [i for i, line in _code_lines(probe) if _BANNED.search(line)]
    assert len(hits) == 2, hits


# --------------------------------------------------------------------------
# 6b · The SAME rules, resolved through the import graph instead of the text
# --------------------------------------------------------------------------
# MEASURED gap this section closes. The regex above is textual and
# module-qualified, so the exact defect it exists to prevent survives a
# one-line alias: `import zlib as _z; _z.compress(data, 9)` and
# `from zlib import compress; compress(data)` both walk straight through it,
# and so do 14 of the 17 clock/entropy spellings rule 5 names -- `import
# time`, `time.monotonic()`, `secrets.token_bytes`, `os.getpid()`,
# `datetime.now()`, `locale.getlocale()`, `Random(0).random()` and the rest.
# The regex is kept as a cheap textual net; THIS is the enforcing control.
#
# It parses each module, builds the alias map from every Import/ImportFrom
# node (so `_z` is known to be zlib and a bare `compress` is known to be
# zlib.compress), then resolves every Name and Attribute back through that map
# before testing it. Attribute access is checked, not only calls, because
# `os.environ["TZ"]` is a Subscript and never a Call.

_BANNED_IMPORTS = {
    "random", "secrets", "uuid", "time", "datetime", "locale", "gzip",
    "zipfile", "bz2", "lzma", "platform", "socket", "subprocess", "resource",
    "getpass", "pwd", "grp", "calendar", "sched", "tempfile",
}
# zlib is permitted ONLY for fixed algorithms. crc32 and adler32 are defined
# by the standard and decompress is inflate, which is unique; compress is not.
_ZLIB_ALLOWED = {"crc32", "adler32", "decompress"}
# Host state, in every module.
_OS_BANNED_ALWAYS = {
    "urandom", "getpid", "getppid", "getuid", "geteuid", "getgid", "getlogin",
    "uname", "times", "cpu_count", "getloadavg", "system", "popen", "fork",
}
# Host state that fixtures/guard.py legitimately needs -- it is the write
# guard, it stats targets and reads SENTINELWIPE_DEVICE_MODE, and it produces
# no image bytes. Banned in the five modules that DO produce image bytes.
_OS_BANNED_OUTSIDE_GUARD = {
    "stat", "lstat", "fstat", "statvfs", "environ", "getenv", "putenv",
    "listdir", "scandir", "walk",
}


def _dotted(node):
    """ast node -> ['os', 'path', 'abspath'], or None if the head is not a
    plain name (e.g. self.x, f(x).y)."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return list(reversed(parts))


def resolve_banned_uses(source: str, filename: str, os_exempt: bool = False):
    """Every use of a banned module or attribute, with import aliases resolved.

    Returns a sorted list of (lineno, resolved dotted name).
    """
    tree = ast.parse(source, filename)
    aliases, hits = {}, []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                head = a.name.split(".")[0]
                aliases[a.asname or head] = a.name if a.asname else head
                if head in _BANNED_IMPORTS:
                    hits.append((node.lineno, "import %s" % a.name))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.split(".")[0] in _BANNED_IMPORTS:
                hits.append((node.lineno, "from %s import ..." % mod))
            for a in node.names:
                aliases[a.asname or a.name] = ("%s.%s" % (mod, a.name)) if mod else a.name

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        parts = _dotted(node)
        if not parts or parts[0] not in aliases:
            continue
        full = aliases[parts[0]]
        if len(parts) > 1:
            full = full + "." + ".".join(parts[1:])
        seg = full.split(".")
        if seg[0] in _BANNED_IMPORTS:
            hits.append((node.lineno, full))
        elif seg[0] == "zlib" and len(seg) > 1 and seg[1] not in _ZLIB_ALLOWED:
            hits.append((node.lineno, full))
        elif seg[0] == "os" and len(seg) > 1:
            if seg[1] in _OS_BANNED_ALWAYS:
                hits.append((node.lineno, full))
            elif seg[1] in _OS_BANNED_OUTSIDE_GUARD and not os_exempt:
                hits.append((node.lineno, full))
    return sorted(set(hits))


def test_no_banned_module_survives_an_import_alias():
    """Rules 1 and 5, enforced through the import graph rather than the text."""
    hits = []
    for name in _FIXTURE_MODULES:
        path = _REPO / "fixtures" / name
        for lineno, full in resolve_banned_uses(
                path.read_text(encoding="utf-8"), name,
                os_exempt=(name == "guard.py")):
            hits.append("fixtures/%s:%d: %s" % (name, lineno, full))
    assert not hits, "banned use in the fixture path:\n  " + "\n  ".join(hits)


# The alias spellings the regex misses, verbatim from the finding that
# produced this control. Every one must be caught, or the resolver has
# regressed to being a grep with extra steps.
_ALIAS_ATTACKS = [
    "import time",
    "import time\nstamp = time.monotonic()",
    "import time\nns = time.time_ns()",
    "import time\nlt = time.localtime()",
    "import secrets",
    "import secrets\nsalt = secrets.token_bytes(16)",
    "import os\npid = os.getpid()",
    "import os\nst = os.stat(path).st_mtime",
    "from datetime import datetime as _d",
    "from datetime import datetime as _d\nnow = _d.now()",
    "import locale",
    "import locale\nloc = locale.getlocale()",
    "from random import Random as _R",
    "from random import Random as _R\nr = _R(0).random()",
    "import zlib as _z\nblob = _z.compressobj().compress(b'x')",
    "import zlib as _z\nout = _z.compress(data, 9)",
    "from zlib import compress\nout = compress(data)",
    "from zlib import compress as _c\nout = _c(data)",
    "import zipfile\nz = zipfile.ZipFile(p)",
    "import gzip\nb = gzip.compress(d)",
    "import os\nk = os.urandom(16)",
    "import uuid\nu = uuid.uuid4()",
    "import os\ne = os.environ['TZ']",
    "from os import getenv\nv = getenv('LANG')",
]

# Spellings that are legitimate and must NOT fire. A control that flags
# everything is as useless as one that flags nothing.
_ALLOWED_SPELLINGS = [
    "import zlib\nc = zlib.crc32(b'a')",
    "import zlib\nx = zlib.adler32(b'a')",
    "import zlib\nx = zlib.decompress(b'')",
    "import zlib as _z",                      # importing zlib is allowed; using
    "from zlib import compress",              # it to COMPRESS is not
    "import os\nos.write(1, b'a')",
    "import os\np = os.path.abspath('.')",
    "import hashlib\nh = hashlib.shake_128(b'a')",
    "import stat as statmod\nstatmod.S_ISBLK(0)",
]


@pytest.mark.parametrize("src", _ALIAS_ATTACKS)
def test_the_alias_resolver_catches_every_known_bypass(src):
    assert resolve_banned_uses(src, "<probe>"), src


@pytest.mark.parametrize("src", _ALLOWED_SPELLINGS)
def test_the_alias_resolver_does_not_fire_on_permitted_calls(src):
    assert resolve_banned_uses(src, "<probe>") == [], src


def test_the_guard_exemption_is_narrow():
    """guard.py is exempt from os.stat/os.environ and from NOTHING else. If
    the exemption ever widens to os.urandom the guard becomes a place a
    nondeterminism could hide."""
    assert resolve_banned_uses("import os\nk = os.urandom(4)", "<p>",
                               os_exempt=True)
    assert resolve_banned_uses("import time\nt = time.time()", "<p>",
                               os_exempt=True)
    assert resolve_banned_uses("import os\ns = os.stat('/')", "<p>",
                               os_exempt=True) == []
    assert resolve_banned_uses("import os\ns = os.stat('/')", "<p>") != []


def test_zlib_is_used_only_for_fixed_algorithms():
    """The permitted uses, enumerated: crc32, adler32, decompress. Anything
    else calling into libz would make the bytes a property of the build host."""
    allowed = re.compile(r"zlib\.(crc32|adler32|decompress)\b")
    for name in _FIXTURE_MODULES:
        path = _REPO / "fixtures" / name
        for i, line in _code_lines(path):
            for m in re.finditer(r"zlib\.\w+", line):
                assert allowed.match(m.group(0)), "fixtures/%s:%d: %s" % (
                    name, i, line.strip())


# --------------------------------------------------------------------------
# 7 · The image is a real FAT32 volume, re-parsed independently
# --------------------------------------------------------------------------


def test_an_independent_reparse_finds_the_live_files_and_marks_the_deleted(built,
                                                                          manifest):
    """fat32.read_image walks the on-disk BPB and FAT with no reference to the
    plan or the manifest. Every live file is read back THROUGH ITS FAT CHAIN and
    SHA-256 compared, which is the check that a fragmented file's chain is real
    and not merely described. If the manifest and the image ever disagree, this
    is where it shows."""
    got = F.read_image(built.image)
    assert got["cluster_count"] == built.geo.cluster_count
    assert got["data_start_offset"] == built.geo.data_start_offset
    assert got["bytes_per_sector"] == built.geo.bytes_per_sector
    assert got["fats_identical"] is True
    assert got["backup_boot_matches"] is True

    by_name = {(e["long_name"] or e["short_name"]): e for e in got["files"]}
    live = {e["path"].lstrip("/"): e for e in manifest["files"] if not e["deleted"]}
    gone = {e["path"].lstrip("/"): e for e in manifest["files"] if e["deleted"]}

    assert set(live) <= set(by_name), sorted(set(live) - set(by_name))
    for name, entry in live.items():
        found = by_name[name]
        assert found["deleted"] is False, name
        assert found["size"] == entry["size"], name
        assert found["sha256"] == entry["sha256"], (
            "%s does not read back through its FAT chain" % name)
    for name in gone:
        # VFAT keeps the long-name entries; the short name lost its first byte
        # to 0xE5 and read_image solves the LFN checksum to recover it.
        assert name in by_name, "deleted file %s left no directory trace" % name
        assert by_name[name]["deleted"] is True, name
        assert by_name[name]["chain"] == [], name

    assert sum(1 for e in got["files"] if not e["deleted"]) == 28
    assert sum(1 for e in got["files"] if e["deleted"]) == 12


# --------------------------------------------------------------------------
# 8 · The build FAILS on drift. It does not merely mention it.
# --------------------------------------------------------------------------
# MEASURED defect this section closes: build_image.py printed
# "committed sha256 match  NO" and exited 0, so `make fixtures` reported
# success while shipping a fixture that does not match the committed digests
# -- and in --quiet, the advertised scripting mode, the comparison was never
# performed at all. Nothing in the `make` surface caught it: `make test` is a
# Phase-2 stub that exits 1, so the pytest check that DOES fail on drift was
# unreachable through make.
#
# These tests drive main() with the real argument parser and the real exit
# path, substituting only the expensive build, so the wiring is tested without
# a second 256 MiB image per case.


def _expected_block(res, image=None, man=None):
    return {"seed": res.seed, "size_bytes": res.manifest["image_bytes"],
            "bytes_per_cluster": res.geo.bytes_per_cluster,
            "image_sha256": image or res.image_sha256,
            "manifest_sha256": man or res.manifest_sha256}


@pytest.fixture()
def cli(monkeypatch, built, tmp_path):
    """main() with the build stubbed to the already-built fixture and the
    committed record under the test's control."""
    def run(record, argv_extra=()):
        monkeypatch.setattr(B, "build", lambda **kw: built)
        monkeypatch.setattr(B, "_read_expected", lambda path: record)
        argv = ["--seed", SEED, "--size", str(SIZE),
                "--out", str(tmp_path / "out")] + list(argv_extra)
        return B.main(argv)
    return run


def test_a_mismatch_against_the_committed_digests_exits_nonzero(cli, built, capsys):
    """THE test for the defect. A build that does not reproduce the committed
    fixture must fail, so `make fixtures` fails with it."""
    bad = _expected_block(built, image="0" * 64, man="1" * 64)
    code = cli(bad)
    assert code == 4, "a drifted fixture exited %r" % code
    err = capsys.readouterr().err
    assert "DOES NOT MATCH" in err
    assert "0" * 64 in err and built.image_sha256 in err
    assert "1" * 64 in err and built.manifest_sha256 in err


def test_the_mismatch_is_detected_in_quiet_mode_too(cli, built, capsys):
    """--quiet is the advertised scripting mode and it skipped the comparison
    entirely, which is the easier half of the defect: a script that shells out
    here saw only a hash on stdout and a zero exit."""
    code = cli(_expected_block(built, image="0" * 64), ["--quiet"])
    assert code == 4
    cap = capsys.readouterr()
    assert cap.out.split()[0] == built.image_sha256
    assert "DOES NOT MATCH" in cap.err


def test_no_check_expected_is_the_typed_escape_for_a_deliberate_change(cli, built,
                                                                       capsys):
    """A deliberate fixture change still has to be rebuilt. The escape is a
    flag someone typed, not a silent fall-through -- and it still PRINTS the
    mismatch, so the operator cannot use it without seeing what moved."""
    code = cli(_expected_block(built, image="0" * 64), ["--no-check-expected"])
    assert code == 0
    err = capsys.readouterr().err
    assert "DOES NOT MATCH" in err
    assert "--no-check-expected given" in err


def test_a_matching_build_exits_zero(cli, built, capsys):
    """The positive control: the three tests above are only meaningful if the
    comparison can also say yes."""
    code = cli(_expected_block(built))
    assert code == 0
    out = capsys.readouterr().out
    assert "committed sha256 match    yes" in out


def test_absent_or_incomparable_records_are_not_failures(cli, built, capsys):
    """A missing record and a record for a different seed or size are not
    mismatches, and turning them into failures would make the first build of a
    new fixture impossible."""
    assert cli(None) == 0
    assert "nothing to compare" in capsys.readouterr().out
    other = _expected_block(built)
    other["seed"] = "some/other/seed"
    assert cli(other) == 0
    assert "not comparable" in capsys.readouterr().out
    smaller = _expected_block(built)
    smaller["size_bytes"] = 64 * 1024 * 1024
    assert cli(smaller) == 0
    assert "not comparable" in capsys.readouterr().out


def test_the_committed_expectation_matches_this_build(built):
    """out/ is gitignored, so the only thing a checker can compare against
    without trusting a rebuild is the digest committed in the repo. If this
    fails, either the fixture changed on purpose -- update the record -- or it
    changed by accident, which is exactly what the record is for."""
    doc = json.loads(TRACKED_POINTER.read_bytes().decode("utf-8"))
    exp = doc.get("expected")
    assert isinstance(exp, dict), "fixtures/manifest.json carries no expected block"
    assert exp["seed"] == SEED
    assert exp["size_bytes"] == SIZE
    assert exp["bytes_per_cluster"] == built.geo.bytes_per_cluster
    assert exp["image_sha256"] == built.image_sha256, (
        "committed image sha256 %s, built %s" % (exp["image_sha256"],
                                                 built.image_sha256))
    assert exp["manifest_sha256"] == built.manifest_sha256
    assert exp["whole_image_entropy_bits_per_byte"] == \
        built.manifest["whole_image_entropy_bits_per_byte"]
    assert exp["counted_set"] == built.manifest["counted_set"]
    # The carver contract travels with the digests, so a checker that never
    # rebuilds still gets the max_gap convention and the false-positive floor.
    assert exp["max_gap_clusters"] == built.manifest["max_gap_clusters"]
    assert exp["max_gap_is_inclusive"] is built.manifest["max_gap_is_inclusive"]
    assert exp["residue_signature_false_positives"] == \
        built.manifest["residue_signature_false_positives"]
    assert exp["deleted_entries_carry_no_allocation_fields"] is True
