"""Extent planner for the SENTINELWIPE forensic fixture.

Every cluster every planted file will occupy is chosen HERE, before a single
byte is written.  ``build_plan`` returns the complete extent list; the image
writer obeys it and the manifest reports it.  The fragment layout is therefore
an input, not an allocator outcome discovered afterwards -- which is the only
reason the tri-fragment and out-of-order cases are buildable at all.

Ported from the plan-obeying allocator in the Phase-0 investigation
(``scratchpad/fixture/build_fat32.py``), whose ``frag(fid, name, data, splits,
gaps, order)`` is the only prototype allocator able to express gaps,
cross-file interleave and out-of-order fragments.  The cursor-only allocator in
``scratchpad/fat32/fat32img.py`` cannot express any of the three.

Determinism contract: hashlib.shake_128 over the seed string is the only
entropy source.  No ``random``, no time, no host state, no locale, no
PYTHONHASHSEED dependence.  Integer arithmetic only -- no floats anywhere in a
value that reaches the image.

This module deliberately imports nothing from the rest of the fixture package.
``geo`` and ``corpus`` are duck-typed, so the planner is testable on its own.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Sequence

__all__ = [
    "Extent",
    "Placement",
    "build_plan",
    "make_residue_fn",
    "claimed_clusters",
    "residue_clusters",
    "validate_plan",
    "counted_set",
    "ROOT_DIR_CLUSTERS",
    "FIRST_PLANTED_CLUSTER",
    "LADDER",
    "DELETED_NAMES",
    "RESIDUE_MIX",
    "MAX_GAP_BUDGET_CLUSTERS",
    "MAX_GAP_IS_INCLUSIVE",
    "CARVER_SIGNATURES",
    "KIND_SIGNATURE",
    "NO_SIGNATURE_KINDS",
    "planted_byte_ranges",
    "measure_signature_false_positives",
    "is_fragmented",
    "SIG_ONLY",
    "BIFRAGMENT",
    "UNRECOVERABLE",
]

# --------------------------------------------------------------------------
# expected_recoverable vocabulary (manifest schema)
# --------------------------------------------------------------------------

SIG_ONLY = "signature-only"
BIFRAGMENT = "bifragment"
UNRECOVERABLE = "unrecoverable-by-design"

# Which corpus kind maps to which signature row a carver would key on.  DOCX is
# carved as ZIP, since a .docx IS a zip archive.  TXT maps to nothing: plain text
# has no magic bytes, so signature carving cannot reach it at any offset.
#
# Our TXT corpus does open with an ASCII banner, and keying on that would lift
# recall from 33 to 38 in an afternoon.  We do not, because a carver tuned to a
# marker we planted ourselves measures nothing about carving.  Recorded in
# docs/ai-log/entries/2026-09-03.md.
KIND_SIGNATURE = {
    "PNG": "PNG", "JPEG": "JPEG", "PDF": "PDF", "DOCX": "ZIP",
    "GZIP": "GZIP", "SQLITE": "SQLITE", "MP4": "MP4",
    "TXT": None,
}
NO_SIGNATURE_KINDS = frozenset(k for k, v in KIND_SIGNATURE.items() if v is None)

# --------------------------------------------------------------------------
# Reserved region at the head of the data area
# --------------------------------------------------------------------------
# Cluster 2 is the first cluster of the FAT32 root directory.  40 files with
# VFAT long names need 3 directory entries each (2 LFN + 1 short, since every
# corpus name is <= 26 characters) plus one volume-label entry: 121 * 32 =
# 3872 bytes.  At the 2 KiB cluster size a 256 MiB FAT32 volume is forced into
# (see FAT32_MIN_CLUSTERS = 65525) that is two clusters with no headroom, so
# the planner reserves four and never plants inside them.  The residue writer
# refuses this whole range as well, so growth of the root chain can never
# collide with planted data or with decoy fill.
ROOT_DIR_CLUSTERS = 4
FIRST_PLANTED_CLUSTER = 2 + ROOT_DIR_CLUSTERS  # 6

# Fraction (per mille) of the data area the 40 files are spread across.  The
# remaining tail is pure residue.  Kept at 88% so that an off-by-one in the
# writer's cluster_count convention can never push a planted extent out of
# range.
SPREAD_PER_MILLE = 880

# --------------------------------------------------------------------------
# The fragmentation ladder
# --------------------------------------------------------------------------
# Gaps are denominated in CLUSTERS, so the ladder means the same thing at any
# cluster size.  FRAG-03's 128-cluster gap sets the max_gap budget the Phase-2
# carver will be configured with; every other gap in the fixture sits under it
# ON PURPOSE, so that FRAG-06 and FRAG-07 fail for their structural reason
# (fragment count, fragment direction) and not because a distance limit was
# exceeded.  A failure we cannot attribute is not evidence.
MAX_GAP_BUDGET_CLUSTERS = 128

# FRAG-03 sits EXACTLY on the budget, which is the only way a rung can prove a
# budget rather than merely respect it.  That makes the comparison operator
# load-bearing: a Phase-2 carver implementing `gap < budget` instead of
# `gap <= budget` loses disposal_certificate.pdf and the counted set drops from
# 38 to 37 with no error, and the demo's attribution -- FRAG-06 fails on
# fragment count, FRAG-07 on direction, neither on distance -- becomes false on
# stage.  The convention is therefore INCLUSIVE, stated here, published in the
# manifest as max_gap_clusters / max_gap_is_inclusive, and asserted in the
# tests.  The carver reads it from the manifest; it does not hardcode 128.
MAX_GAP_IS_INCLUSIVE = True

LADDER = {
    # id          corpus file             shape
    "FRAG-01": ("entropy_heatmap.png", "bifragment, gap 1 cluster"),
    "FRAG-02": ("imaging_transcript.txt.gz", "bifragment, gap 16 clusters"),
    "FRAG-03": ("disposal_certificate.pdf", "bifragment, gap 128 clusters (sets max_gap)"),
    "FRAG-04": ("sealing_procedure.mov", "bifragment, gap 50 clusters holding FRAG-05 fragment 0"),
    "FRAG-05": ("handover_briefing.mov", "bifragment, gap 70 clusters holding FRAG-04 fragment 1"),
    "FRAG-06": ("media_inventory.docx", "TRIfragment, gaps 11 and 29 clusters"),
    "FRAG-07": ("evidence_bag_seal.jpg", "bifragment OUT OF ORDER, fragment 1 precedes fragment 0"),
}

FRAG01_GAP = 1
FRAG02_GAP = 16
FRAG03_GAP = 128
FRAG04_GAP = 50
FRAG05_GAP = 70
FRAG06_GAPS = (11, 29)
FRAG07_SEPARATION = 24  # clusters between fragment 1's end and fragment 0's start

# --------------------------------------------------------------------------
# The deleted set -- 12 files, and the design that produces the number 12
# --------------------------------------------------------------------------
# The previous round inherited "12 deleted" from a CLI flag with no design
# behind it.  Here 12 is a derived quantity: 4 + 8.
#
# The carver never parses filesystem metadata, so deletion changes nothing it
# can see.  The deleted set therefore exists to answer two specific objections
# a jury or an evaluator will raise, and its relationship to the FRAGMENTED set
# is what does the answering.  The two sets are CROSSED, not nested:
#
#   (a) 4 of the 7 fragmented files are deleted, 3 are live.  The two
#       deliberately unsolvable cases straddle that boundary -- FRAG-06
#       (tri-fragment DOCX) is DELETED and FRAG-07 (out-of-order JPEG) is LIVE.
#       So "your two failures are just the deleted ones" is refuted on the
#       manifest, and so is the converse.  The interleaved pair straddles it
#       too: FRAG-05 is deleted and lies physically inside live FRAG-04's gap,
#       which is the sharpest single picture of "deletion is not erasure" the
#       fixture can produce.
#
#   (b) The other 8 deleted files are one contiguous file of EACH of the eight
#       corpus kinds.  Every format is represented in the deleted set, so no
#       carve result can be explained away with "they only deleted the formats
#       that carve easily".  Index 01 of each kind is used throughout -- a
#       fixed, boring rule, so the choice cannot be read as cherry-picking.
#
# 4 fragmented + 8 kinds x 1 contiguous = 12.  Deleted 12, live 28.
DELETED_FRAGMENTED = ("FRAG-01", "FRAG-03", "FRAG-05", "FRAG-06")

DELETED_CONTIGUOUS = (
    "evidence_log_2026-01-14.txt",   # TXT
    "audit_trail.log.gz",  # GZIP
    "sector_map_01.png",     # PNG
    "seizure_photo_b.jpg",          # JPEG
    "chain_of_custody.pdf",        # PDF
    "sanitization_report.docx",        # DOCX
    "custody_ledger.db",         # SQLITE
    "bodycam_intake.mov",           # MP4
)

DELETED_NAMES = frozenset(
    DELETED_CONTIGUOUS + tuple(LADDER[fid][0] for fid in DELETED_FRAGMENTED)
)


# --------------------------------------------------------------------------
# Deterministic byte source
# --------------------------------------------------------------------------


def _shake(material: str, nbytes: int) -> bytes:
    return hashlib.shake_128(material.encode("utf-8")).digest(nbytes)


def _u32(material: str) -> int:
    return int.from_bytes(_shake(material, 4), "big")


def _shuffled(items: Sequence, material: str) -> list:
    """Fisher-Yates driven by shake_128.  No random module, no PRNG state."""
    a = list(items)
    for i in range(len(a) - 1, 0, -1):
        j = _u32("%s|swap|%d" % (material, i)) % (i + 1)
        a[i], a[j] = a[j], a[i]
    return a


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Extent:
    """One physically contiguous run of clusters holding one slice of a file.

    Extents are stored in LOGICAL order -- extent[0] holds the first bytes of
    the file.  For FRAG-07 that means extent[0] has the HIGHER cluster_start,
    which is the whole point of the case.
    """

    cluster_start: int
    cluster_count: int
    byte_offset: int
    byte_length: int

    @property
    def cluster_end(self) -> int:
        """One past the last cluster of this extent."""
        return self.cluster_start + self.cluster_count

    def as_manifest(self) -> dict:
        return {
            "byte_offset": self.byte_offset,
            "byte_length": self.byte_length,
            "cluster_start": self.cluster_start,
            "cluster_count": self.cluster_count,
        }


@dataclass
class Placement:
    """One planted file, with its complete chosen layout."""

    name: str
    kind: str
    data: bytes
    sha256: str
    deleted: bool
    extents: list
    fragmented: bool
    expected_recoverable: str
    # Non-contract, additive: provenance for the manifest and the demo caption.
    frag_id: Optional[str] = None
    note: str = ""

    @property
    def path(self) -> str:
        return "/" + self.name

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def first_byte_offset(self) -> int:
        """Byte offset of the file's FIRST logical byte (manifest 'offset')."""
        return self.extents[0].byte_offset

    def as_manifest(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "offset": self.first_byte_offset,
            "size": self.size,
            "sha256": self.sha256,
            "deleted": self.deleted,
            "fragmented": self.fragmented,
            "expected_recoverable": self.expected_recoverable,
            "extents": [e.as_manifest() for e in self.extents],
        }


def is_fragmented(extents: Sequence[Extent]) -> bool:
    """fragmented == the extents are NON-ADJACENT on disk.

    NOT ``len(extents) > 1``.  A previous harness got exactly this wrong and
    reported a file as fragmented because the planner happened to emit two
    touching runs.  Two runs that abut are one physical run; a carver reading
    forward never notices them.
    """
    if len(extents) < 2:
        return False
    # Direction first.  ``extents`` is in LOGICAL order, so a later fragment
    # sitting physically BELOW an earlier one is fragmented however close the
    # two runs are -- even if they touch.  Sorting before the adjacency test
    # (below) throws that information away: two touching runs read backwards
    # are physically contiguous but reassemble in the wrong order, so a
    # forward-reading carver produces a wrong hash while the flag says
    # "signature-only".  FRAG-07 exists precisely to punish direction, and a
    # flag blind to direction cannot describe it.
    for prev, nxt in zip(extents, extents[1:]):
        if nxt.cluster_start < prev.cluster_start:
            return True
    ordered = sorted(extents, key=lambda e: e.cluster_start)
    for prev, nxt in zip(ordered, ordered[1:]):
        if nxt.cluster_start != prev.cluster_end:
            return True
    return False


# --------------------------------------------------------------------------
# The allocator -- port of frag(fid, name, data, splits, gaps, order)
# --------------------------------------------------------------------------


class _Allocator:
    """Plan-obeying cluster allocator.

    Takes an EXTENT PLAN (cluster counts per fragment, and the gap in clusters
    to skip after each), never a fragment count.  ``place_runs`` accepts
    absolute cluster numbers so a caller can put a fragment anywhere, including
    behind the cursor -- that is what makes FRAG-04/05 interleave and FRAG-07
    reversal expressible.
    """

    def __init__(self, geo, first_cluster: int):
        self.bpc = geo.bytes_per_sector * geo.sectors_per_cluster
        self.data_start = geo.data_start_offset
        self.last_cluster = geo.cluster_count + 1  # clusters are 2..cluster_count+1
        self.cursor = first_cluster
        self.claimed: dict = {}  # cluster -> owning file name, for overlap detection

    # -- geometry -------------------------------------------------------
    def clusters_for(self, nbytes: int) -> int:
        return -(-nbytes // self.bpc) if nbytes else 1

    def offset_of(self, cluster: int) -> int:
        return self.data_start + (cluster - 2) * self.bpc

    # -- allocation -----------------------------------------------------
    def runs_from_plan(self, start: int, splits: Sequence[int],
                       gaps: Sequence[int]) -> list:
        """(start_cluster, cluster_count) runs from a splits/gaps plan."""
        runs, c = [], start
        for i, s in enumerate(splits):
            runs.append((c, s))
            c += s + (gaps[i] if i < len(gaps) else 0)
        return runs

    def to_extents(self, runs: Sequence, nbytes: int, owner: str) -> list:
        """Turn (cluster_start, cluster_count) runs into byte-mapped Extents.

        Runs are consumed in LOGICAL order; byte_offset comes from the cluster
        number, so a run that lies earlier on disk than its predecessor gets
        the lower offset with the later bytes.  Sum of byte_length == nbytes.
        """
        extents, pos = [], 0
        for start, count in runs:
            if start < 2 or start + count - 1 > self.last_cluster:
                raise ValueError(
                    "%s: run %d..%d outside cluster range 2..%d"
                    % (owner, start, start + count - 1, self.last_cluster))
            take = min(count * self.bpc, nbytes - pos)
            if take <= 0:
                raise ValueError("%s: extent plan allocates more runs than data" % owner)
            for c in range(start, start + count):
                if c in self.claimed:
                    raise ValueError(
                        "%s: cluster %d already claimed by %s"
                        % (owner, c, self.claimed[c]))
                self.claimed[c] = owner
            extents.append(Extent(cluster_start=start, cluster_count=count,
                                  byte_offset=self.offset_of(start),
                                  byte_length=take))
            pos += take
        if pos != nbytes:
            raise ValueError("%s: extent plan covers %d of %d bytes" % (owner, pos, nbytes))
        return extents

    def advance_to(self, cluster: int) -> None:
        if cluster > self.cursor:
            self.cursor = cluster

    def skip(self, clusters: int) -> None:
        self.cursor += clusters


# --------------------------------------------------------------------------
# Fragment split rules (adapt to whatever cluster size geometry chose)
# --------------------------------------------------------------------------


def _split_two(n: int, per_mille: int) -> tuple:
    a = max(1, min(n - 1, (n * per_mille) // 1000))
    return (a, n - a)


def _split_three(n: int) -> tuple:
    if n < 3:
        raise ValueError("tri-fragment case needs >= 3 clusters, got %d" % n)
    s0 = max(1, n // 4)
    s1 = max(1, n // 3)
    if s0 + s1 >= n:
        s0, s1 = 1, 1
    return (s0, s1, n - s0 - s1)


def _interleave_layout(base: int, n_a: int, n_b: int) -> tuple:
    """Runs for the mutual-interleave pair FRAG-04 / FRAG-05.

    FRAG-04 (A) has a 50-cluster gap that holds FRAG-05 fragment 0.
    FRAG-05 (B) has a 70-cluster gap that holds FRAG-04 fragment 1.
    Physical order on disk is A0, B0, A1, B1 -- each file's second fragment
    lies beyond the other file's first, so neither can be carved without
    stepping over the other.  Both files are the same kind (MP4), so the decoy
    in each gap carries the same signature as the file being carved.
    """
    b0 = min(max(1, n_b // 2), 40)
    g = FRAG04_GAP - b0 - 6          # residue clusters between A0 and B0
    if g < 1:
        raise ValueError("interleave: B fragment 0 does not fit inside A's gap")
    a1_max = g + b0 + 20
    a0 = max(1, n_a // 3, n_a - a1_max)
    if a0 >= n_a:
        raise ValueError("interleave: FRAG-04 too large for a 50-cluster gap")
    a1 = n_a - a0
    b1 = n_b - b0
    if b1 < 1:
        raise ValueError("interleave: FRAG-05 too small to split")

    a0_start = base
    b0_start = base + a0 + g
    a1_start = base + a0 + FRAG04_GAP
    b1_start = b0_start + b0 + FRAG05_GAP

    # The two properties the case exists to demonstrate, asserted not assumed.
    if not (a0_start + a0 <= b0_start and b0_start + b0 <= a1_start):
        raise ValueError("interleave: FRAG-05 fragment 0 not inside FRAG-04's gap")
    if not (b0_start + b0 <= a1_start and a1_start + a1 <= b1_start):
        raise ValueError("interleave: FRAG-04 fragment 1 not inside FRAG-05's gap")

    runs_a = [(a0_start, a0), (a1_start, a1)]
    runs_b = [(b0_start, b0), (b1_start, b1)]
    return runs_a, runs_b, (b1_start + b1) - base   # third value is the SPAN, relative to base


# --------------------------------------------------------------------------
# build_plan
# --------------------------------------------------------------------------


def build_plan(geo, corpus, seed) -> list:
    """Choose every extent of every planted file.  Nothing is written here.

    geo     -- fixtures.fat32.Geometry (duck-typed: bytes_per_sector,
               sectors_per_cluster, cluster_count, data_start_offset)
    corpus  -- list[CorpusFile] of exactly 40 files (name, kind, data, sha256)
    seed    -- the fixture seed string; every derived choice hangs off it

    Returns list[Placement] in the corpus's own order (stable, so the manifest
    file list does not depend on the physical layout).
    """
    files = list(corpus)
    if len(files) != 40:
        raise ValueError("fixture expects exactly 40 corpus files, got %d" % len(files))
    by_name = {}
    for f in files:
        if f.name in by_name:
            raise ValueError("duplicate corpus name %r" % f.name)
        by_name[f.name] = f
    for fid, (name, _note) in LADDER.items():
        if name not in by_name:
            raise ValueError("ladder entry %s names %r, absent from the corpus" % (fid, name))
    for name in DELETED_CONTIGUOUS:
        if name not in by_name:
            raise ValueError("deleted-set entry %r absent from the corpus" % name)

    alloc = _Allocator(geo, FIRST_PLANTED_CLUSTER)
    ladder_names = {LADDER[fid][0]: fid for fid in LADDER}

    # ---- layout units ------------------------------------------------
    # A unit is one thing the allocator lays down in one go.  FRAG-04 and
    # FRAG-05 are a single unit because they are physically interwoven.
    units = []
    for f in files:
        fid = ladder_names.get(f.name)
        if fid in ("FRAG-04", "FRAG-05"):
            continue
        units.append(("frag" if fid else "contig", fid, [f.name]))
    units.append(("interleave", "FRAG-04/05", [LADDER["FRAG-04"][0], LADDER["FRAG-05"][0]]))

    # ---- intrinsic span of each unit ---------------------------------
    def n_clusters(name: str) -> int:
        return alloc.clusters_for(len(by_name[name].data))

    def unit_span(kind: str, fid, names) -> int:
        if kind == "contig":
            return n_clusters(names[0])
        if kind == "interleave":
            n_a, n_b = n_clusters(names[0]), n_clusters(names[1])
            _ra, _rb, span = _interleave_layout(FIRST_PLANTED_CLUSTER, n_a, n_b)
            return span
        n = n_clusters(names[0])
        if fid == "FRAG-01":
            return n + FRAG01_GAP
        if fid == "FRAG-02":
            return n + FRAG02_GAP
        if fid == "FRAG-03":
            return n + FRAG03_GAP
        if fid == "FRAG-06":
            return n + sum(FRAG06_GAPS)
        if fid == "FRAG-07":
            return n + FRAG07_SEPARATION
        raise ValueError("unknown fragmented unit %r" % fid)

    # NB: keyed by index, not by (kind, fid) -- all 33 contiguous units share
    # fid None and a dict keyed on it collapses them to one entry, understating
    # `occupied` by ~2000 clusters and overshooting the spread target.
    spans = [unit_span(kind, fid, names) for kind, fid, names in units]
    occupied = sum(spans)

    # ---- spread the 40 files across the data area ---------------------
    # A corpus packed into the first 2% of a 256 MiB image is not a forensic
    # image, it is a header.  Files are spread over 88% of the data area with
    # deterministic jitter, so every planted file is surrounded by residue and
    # the carver has to find it rather than trip over it.
    last_cluster = geo.cluster_count + 1
    usable = last_cluster - FIRST_PLANTED_CLUSTER + 1
    target_span = (usable * SPREAD_PER_MILLE) // 1000
    slack_total = target_span - occupied
    if slack_total < len(units):
        raise ValueError(
            "corpus (%d clusters incl. gaps) does not fit in %d planted clusters"
            % (occupied, target_span))
    # Slack is shared between the 39 units; jitter below is +/-40% of base, so
    # the worst-case total span is occupied + 1.4 * slack_total, which is why
    # SPREAD_PER_MILLE is 880 and not 1000.
    base_slack = slack_total // len(units)

    order = _shuffled(units, "%s|layout-order" % seed)

    placements_by_name = {}

    for idx, (kind, fid, names) in enumerate(order):
        cur = alloc.cursor
        if kind == "contig":
            name = names[0]
            f = by_name[name]
            runs = [(cur, alloc.clusters_for(len(f.data)))]
            ext = alloc.to_extents(runs, len(f.data), name)
            placements_by_name[name] = (ext, None, "contiguous")
            alloc.advance_to(runs[0][0] + runs[0][1])

        elif kind == "interleave":
            na_name, nb_name = names
            fa, fb = by_name[na_name], by_name[nb_name]
            n_a = alloc.clusters_for(len(fa.data))
            n_b = alloc.clusters_for(len(fb.data))
            runs_a, runs_b, span = _interleave_layout(cur, n_a, n_b)
            ext_a = alloc.to_extents(runs_a, len(fa.data), na_name)
            ext_b = alloc.to_extents(runs_b, len(fb.data), nb_name)
            placements_by_name[na_name] = (ext_a, "FRAG-04", LADDER["FRAG-04"][1])
            placements_by_name[nb_name] = (ext_b, "FRAG-05", LADDER["FRAG-05"][1])
            alloc.advance_to(cur + span)

        else:  # a single fragmented file
            name = names[0]
            f = by_name[name]
            n = alloc.clusters_for(len(f.data))
            if fid == "FRAG-01":
                runs = alloc.runs_from_plan(cur, _split_two(n, 400), [FRAG01_GAP])
            elif fid == "FRAG-02":
                runs = alloc.runs_from_plan(cur, _split_two(n, 550), [FRAG02_GAP])
            elif fid == "FRAG-03":
                runs = alloc.runs_from_plan(cur, _split_two(n, 300), [FRAG03_GAP])
            elif fid == "FRAG-06":
                runs = alloc.runs_from_plan(cur, _split_three(n), list(FRAG06_GAPS))
            elif fid == "FRAG-07":
                # OUT OF ORDER: fragment 1 is laid down FIRST, at the lower
                # cluster.  A forward-only bifragment search starting at
                # fragment 0's header runs off the end of the data area and
                # never looks backwards.  The separation stays inside the
                # max_gap budget so the failure is direction, not distance.
                f0, f1 = _split_two(n, 350)
                runs = [(cur + f1 + FRAG07_SEPARATION, f0), (cur, f1)]
            else:
                raise ValueError("unknown fragmented id %r" % fid)
            ext = alloc.to_extents(runs, len(f.data), name)
            placements_by_name[name] = (ext, fid, LADDER[fid][1])
            alloc.advance_to(max(s + c for s, c in runs))

        jitter = _u32("%s|slack|%d" % (seed, idx)) % 801  # 0..800
        alloc.skip(max(1, (base_slack * (600 + jitter)) // 1000))

    # ---- assemble placements in corpus order --------------------------
    out = []
    for f in files:
        ext, fid, note = placements_by_name[f.name]
        frag = is_fragmented(ext)
        if fid in ("FRAG-06", "FRAG-07"):
            expect = UNRECOVERABLE
        elif f.kind in NO_SIGNATURE_KINDS:
            expect = UNRECOVERABLE
        elif frag:
            expect = BIFRAGMENT
        else:
            expect = SIG_ONLY
        out.append(Placement(
            name=f.name,
            kind=f.kind,
            data=f.data,
            sha256=f.sha256,
            deleted=f.name in DELETED_NAMES,
            extents=ext,
            fragmented=frag,
            expected_recoverable=expect,
            frag_id=fid,
            note=note,
        ))

    validate_plan(geo, out)
    return out


# --------------------------------------------------------------------------
# Claimed clusters and the residue rule
# --------------------------------------------------------------------------


def claimed_clusters(placements: Iterable[Placement]) -> set:
    """Every cluster held by a planted extent, deleted files INCLUDED.

    This is the set the residue must never write into.  Deleting a file frees
    its FAT chain, so all 12 deleted files' clusters read as FAT-free; a
    residue fill keyed on "FAT-free" alone overwrites every one of them and the
    demo silently degrades from 40 planted to 28 recoverable with no error
    raised anywhere.  That is a measured defect from the previous round, and it
    is the reason this function exists.
    """
    claimed = set()
    for p in placements:
        for e in p.extents:
            claimed.update(range(e.cluster_start, e.cluster_end))
    return claimed


def residue_clusters(geo, placements: Iterable[Placement]) -> list:
    """Data clusters eligible for residue: not root-reserved, not planted."""
    claimed = claimed_clusters(placements)
    last = geo.cluster_count + 1
    return [c for c in range(FIRST_PLANTED_CLUSTER, last + 1) if c not in claimed]


# The residue mix, per mille of eligible clusters.  Tuned by measurement
# against whole-image Shannon entropy.  A single-pass random wipe drives the
# image to the MEASURED ceiling of a 100% SHAKE fill, 7.9977 bits/byte, so a
# pre-wipe fixture already sitting there would leave the wipe nothing to
# demonstrate.  The mix puts the pre-wipe image at a measured 7.06169 while
# still reading as a used disk rather than a blank one.  Both figures are
# measurements; neither is the round 8.0 that appears in narration.
# Per-class Shannon entropy, measured over 3000 clusters of each class at the
# 2048-byte cluster size:  unwritten 0.0000, sparse 1.5377, text 4.8162,
# record 7.3911, high 8.0000 bits/byte.  The weights below were chosen against
# the resulting whole-image figure, not the other way round.
RESIDUE_MIX = (
    ("unwritten", 120),  # never-written clusters: some of a used disk is still blank
    ("high", 520),       # deleted compressed/encrypted remains, indistinguishable from ciphertext
    ("text", 170),       # deleted plaintext logs and mail spool fragments
    ("record", 140),     # old directory tables / database pages: structured, repetitive
    ("sparse", 50),      # a written header on an otherwise untouched cluster
)

_RESIDUE_WORDS = (
    b"session", b"handoff", b"custody", b"operator", b"sector", b"volume",
    b"checksum", b"transfer", b"pending", b"archive", b"restore", b"unit",
    b"chassis", b"serial", b"interface", b"payload", b"channel", b"cursor",
    b"segment", b"journal", b"replica", b"snapshot", b"lease", b"quota",
    b"partition", b"descriptor", b"allocation", b"threshold", b"latency",
    b"retry", b"parity", b"scrub",
)


def _residue_text(material: str, n: int) -> bytes:
    """ASCII log-shaped filler.  Low entropy on purpose: real deleted text is
    text, and an image where every free cluster is uniform noise is a
    laboratory artefact, not a used disk."""
    src = _shake(material, max(64, n // 3 + 64))
    out = bytearray()
    i = 0
    line = 0
    while len(out) < n:
        rec = bytearray()
        rec += b"%08X " % ((int.from_bytes(src[i:i + 4], "big") if i + 4 <= len(src) else line) & 0xFFFFFFFF)
        i = (i + 4) % max(1, len(src) - 8)
        for _ in range(6):
            rec += _RESIDUE_WORDS[src[i] % len(_RESIDUE_WORDS)]
            rec += b"." if src[i] & 1 else b" "
            i = (i + 1) % max(1, len(src) - 8)
        rec += b"\n"
        out += rec
        line += 1
    return bytes(out[:n])


def _residue_record(material: str, n: int) -> bytes:
    """32-byte fixed-layout records: magic, counter, a little entropy, padding.
    Shaped like an old directory table or a database freelist page."""
    src = _shake(material, max(32, (n // 32 + 1) * 12))
    out = bytearray()
    k = 0
    while len(out) < n:
        j = k * 12
        out += b"\xa5REC"
        out += (k & 0xFFFFFFFF).to_bytes(4, "little")
        out += src[j:j + 12].ljust(12, b"\x00")
        out += bytes([src[j % max(1, len(src))]]) * 12
        k += 1
    return bytes(out[:n])


def _residue_sparse(material: str, n: int) -> bytes:
    head = min(256, n)
    return _shake(material, head) + b"\x00" * (n - head)


def make_residue_fn(geo, placements: Iterable[Placement], seed: str) -> Callable:
    """Build the residue_fn handed to ``fixtures.fat32.build_image``.

    Signature of the returned callable:

        residue_fn(cluster_index: int, cluster_bytes: int) -> bytes | None

    Return value:
        bytes  -- exactly ``cluster_bytes`` long; write it at that cluster.
        None   -- DO NOT WRITE.  The cluster is either root-directory reserve
                  or claimed by a planted extent.

    The writer is expected to call this only for clusters it believes are free,
    but the None return makes the function self-protecting: even if the writer
    hands it every FAT-free cluster -- which INCLUDES all 12 deleted files,
    whose chains were freed -- not one planted byte can be overwritten.  The
    check lives here, on the side that owns the plan, because the failure mode
    it prevents is silent.

    Structurally, a cluster-indexed function cannot reach the boot sector, the
    FSInfo sector, the backup boot region or either FAT: all of those live
    below ``geo.data_start_offset``, and cluster 2 is the first byte after it.
    The root directory chain is inside the data area, so it is excluded here
    by number (clusters 2 .. FIRST_PLANTED_CLUSTER-1).
    """
    claimed = claimed_clusters(placements)
    reserved = frozenset(range(2, FIRST_PLANTED_CLUSTER))
    last_cluster = geo.cluster_count + 1

    names = [n for n, _w in RESIDUE_MIX]
    edges, acc = [], 0
    for _n, w in RESIDUE_MIX:
        acc += w
        edges.append(acc)
    if acc != 1000:
        raise ValueError("RESIDUE_MIX weights sum to %d, expected 1000" % acc)

    def residue_fn(cluster_index: int, cluster_bytes: int):
        if cluster_index in reserved or cluster_index in claimed:
            return None
        if cluster_index < 2 or cluster_index > last_cluster:
            return None
        roll = _u32("%s|residue-class|%d" % (seed, cluster_index)) % 1000
        for name, edge in zip(names, edges):
            if roll < edge:
                cls = name
                break
        material = "%s|residue|%s|%d" % (seed, cls, cluster_index)
        if cls == "unwritten":
            return b"\x00" * cluster_bytes
        if cls == "high":
            return _shake(material, cluster_bytes)
        if cls == "text":
            return _residue_text(material, cluster_bytes)
        if cls == "record":
            return _residue_record(material, cluster_bytes)
        return _residue_sparse(material, cluster_bytes)

    residue_fn.claimed_clusters = claimed        # exposed for the writer's own assertions
    residue_fn.reserved_clusters = reserved
    residue_fn.mix = RESIDUE_MIX
    return residue_fn


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# The residue's signature false-positive floor -- MEASURED, not estimated
# --------------------------------------------------------------------------
# 52% of the eligible clusters are filled with SHAKE output, so a short magic
# will occur in them by chance.  The arithmetic differs by an order of
# magnitude with signature LENGTH, which is the trap: over ~134 MB of uniform
# bytes the expected count of a given 4-byte magic is ~0.03, but for a 3-byte
# magic it is ~8.  JPEG (FF D8 FF), GZIP (1F 8B 08) and BZ2 (42 5A 68) are
# 3-byte signatures and therefore DO occur in the residue.
#
# Phase 2 measures precision against this fixture, so the floor has to be a
# published number rather than a surprise.  It is measured on the finished
# image at build time and written into the manifest, so the figure the carver
# subtracts is the figure this image actually contains.
CARVER_SIGNATURES = (
    ("PNG", b"\x89PNG\r\n\x1a\x0a"),
    ("JPEG", b"\xff\xd8\xff"),
    ("PDF", b"%PDF-"),
    ("ZIP", b"PK\x03\x04"),
    ("GZIP", b"\x1f\x8b\x08"),
    ("SQLITE", b"SQLite format 3\x00"),
    ("MP4", b"ftyp"),
    ("BZ2", b"BZh"),
)


def planted_byte_ranges(placements: Iterable[Placement]) -> list:
    """Sorted, merged [start, end) byte ranges of every planted extent."""
    spans = sorted((e.byte_offset, e.byte_offset + e.byte_length)
                   for p in placements for e in p.extents)
    merged: list = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


def measure_signature_false_positives(placements: Sequence[Placement], image) -> dict:
    """Count each carver signature's occurrences OUTSIDE every planted extent.

    A hit inside a planted extent is a true positive (or an interior byte of a
    real file); everything else -- residue, root directory, FAT, boot sector --
    is a false positive for a signature scanner, and this is the number Phase 2
    has to subtract before it reports precision.  Counted on the finished image
    bytes, so it is a measurement of this fixture and not a model of it.
    """
    ranges = planted_byte_ranges(placements)
    starts = [lo for lo, _hi in ranges]
    blob = bytes(image)
    out = {}
    for name, sig in CARVER_SIGNATURES:
        n, pos = 0, blob.find(sig)
        while pos >= 0:
            i = _bisect_right(starts, pos)
            if not (i and ranges[i - 1][0] <= pos < ranges[i - 1][1]):
                n += 1
            pos = blob.find(sig, pos + 1)
        out[name] = n
    return out


def _bisect_right(a: Sequence[int], x: int) -> int:
    lo, hi = 0, len(a)
    while lo < hi:
        mid = (lo + hi) // 2
        if x < a[mid]:
            hi = mid
        else:
            lo = mid + 1
    return lo


def counted_set(placements: Sequence[Placement]) -> dict:
    return {
        "total": len(placements),
        "expected_recoverable": sum(
            1 for p in placements if p.expected_recoverable != UNRECOVERABLE),
        "unrecoverable_by_design": sum(
            1 for p in placements if p.expected_recoverable == UNRECOVERABLE),
    }


def validate_plan(geo, placements: Sequence[Placement]) -> dict:
    """Every property the fixture claims, checked against the plan itself."""
    bpc = geo.bytes_per_sector * geo.sectors_per_cluster
    last_cluster = geo.cluster_count + 1
    owner = {}
    problems = []

    if len(placements) != 40:
        problems.append("expected 40 placements, got %d" % len(placements))

    for p in placements:
        total = 0
        for e in p.extents:
            if e.cluster_start < FIRST_PLANTED_CLUSTER:
                problems.append("%s: extent at cluster %d intrudes on the root reserve"
                                % (p.name, e.cluster_start))
            if e.cluster_end - 1 > last_cluster:
                problems.append("%s: extent ends at cluster %d, past %d"
                                % (p.name, e.cluster_end - 1, last_cluster))
            if e.byte_offset != geo.data_start_offset + (e.cluster_start - 2) * bpc:
                problems.append("%s: byte_offset does not match cluster_start" % p.name)
            if e.byte_length > e.cluster_count * bpc:
                problems.append("%s: byte_length %d exceeds its %d clusters"
                                % (p.name, e.byte_length, e.cluster_count))
            for c in range(e.cluster_start, e.cluster_end):
                if c in owner:
                    problems.append("cluster %d claimed by both %s and %s"
                                    % (c, owner[c], p.name))
                owner[c] = p.name
            total += e.byte_length
        if total != len(p.data):
            problems.append("%s: extents cover %d of %d bytes" % (p.name, total, len(p.data)))
        if p.fragmented != is_fragmented(p.extents):
            problems.append("%s: fragmented flag does not match adjacency" % p.name)
        if hashlib.sha256(p.data).hexdigest() != p.sha256:
            problems.append("%s: sha256 does not match data" % p.name)
        if p.expected_recoverable not in (SIG_ONLY, BIFRAGMENT, UNRECOVERABLE):
            problems.append("%s: bad expected_recoverable %r" % (p.name, p.expected_recoverable))
        if p.fragmented and p.expected_recoverable == SIG_ONLY:
            problems.append("%s: fragmented but labelled signature-only" % p.name)
        if (not p.fragmented and p.kind not in NO_SIGNATURE_KINDS
                and p.expected_recoverable != SIG_ONLY):
            problems.append("%s: contiguous but labelled %r" % (p.name, p.expected_recoverable))
        if p.kind in NO_SIGNATURE_KINDS and p.expected_recoverable != UNRECOVERABLE:
            problems.append("%s: %s carries no signature but is labelled %r"
                            % (p.name, p.kind, p.expected_recoverable))

    frag = [p for p in placements if p.fragmented]
    if len(frag) != 7:
        problems.append("expected 7 fragmented files, got %d" % len(frag))
    deleted = [p for p in placements if p.deleted]
    if len(deleted) != 12:
        problems.append("expected 12 deleted files, got %d" % len(deleted))
    unrec = [p for p in placements if p.expected_recoverable == UNRECOVERABLE]
    unrec_frag = sorted(p.frag_id for p in unrec if p.frag_id)
    if unrec_frag != ["FRAG-06", "FRAG-07"]:
        problems.append("unrecoverable-by-fragmentation set is %r, expected "
                        "FRAG-06 and FRAG-07" % unrec_frag)
    unrec_nosig = sorted(p.name for p in unrec if not p.frag_id)
    nosig = sorted(p.name for p in placements if p.kind in NO_SIGNATURE_KINDS)
    if unrec_nosig != nosig:
        problems.append("unrecoverable-by-no-signature set is %r, expected %r"
                        % (unrec_nosig, nosig))

    by_fid = {p.frag_id: p for p in placements if p.frag_id}

    # ladder gaps
    def gap(p, i):
        a, b = p.extents[i], p.extents[i + 1]
        return b.cluster_start - a.cluster_end

    for fid, want in (("FRAG-01", FRAG01_GAP), ("FRAG-02", FRAG02_GAP),
                      ("FRAG-03", FRAG03_GAP)):
        p = by_fid.get(fid)
        if p is None or len(p.extents) != 2:
            problems.append("%s: expected 2 extents" % fid)
        elif gap(p, 0) != want:
            problems.append("%s: gap %d clusters, expected %d" % (fid, gap(p, 0), want))

    p4, p5 = by_fid.get("FRAG-04"), by_fid.get("FRAG-05")
    if p4 and p5:
        if gap(p4, 0) != FRAG04_GAP:
            problems.append("FRAG-04: gap %d, expected %d" % (gap(p4, 0), FRAG04_GAP))
        if gap(p5, 0) != FRAG05_GAP:
            problems.append("FRAG-05: gap %d, expected %d" % (gap(p5, 0), FRAG05_GAP))
        if p4.kind != p5.kind:
            problems.append("FRAG-04/05 must be the same kind, got %s/%s" % (p4.kind, p5.kind))
        a0, a1 = p4.extents
        b0, b1 = p5.extents
        if not (a0.cluster_end <= b0.cluster_start and b0.cluster_end <= a1.cluster_start):
            problems.append("FRAG-05 fragment 0 is not inside FRAG-04's gap")
        if not (b0.cluster_end <= a1.cluster_start and a1.cluster_end <= b1.cluster_start):
            problems.append("FRAG-04 fragment 1 is not inside FRAG-05's gap")

    p6 = by_fid.get("FRAG-06")
    if p6 is not None:
        if len(p6.extents) != 3:
            problems.append("FRAG-06: %d extents, expected 3" % len(p6.extents))
        else:
            got = (gap(p6, 0), gap(p6, 1))
            if got != FRAG06_GAPS:
                problems.append("FRAG-06: gaps %r, expected %r" % (got, FRAG06_GAPS))
            if max(got) > MAX_GAP_BUDGET_CLUSTERS:
                problems.append("FRAG-06: a gap exceeds the max_gap budget, so the "
                                "failure would not be attributable to fragment count")

    p7 = by_fid.get("FRAG-07")
    if p7 is not None:
        if len(p7.extents) != 2:
            problems.append("FRAG-07: %d extents, expected 2" % len(p7.extents))
        elif p7.extents[0].cluster_start <= p7.extents[1].cluster_start:
            problems.append("FRAG-07: fragment 1 does not precede fragment 0 on disk")
        else:
            back = p7.extents[0].cluster_start - p7.extents[1].cluster_end
            if back > MAX_GAP_BUDGET_CLUSTERS:
                problems.append("FRAG-07: separation %d exceeds the max_gap budget, so the "
                                "failure would not be attributable to direction" % back)

    # the deleted/fragmented cross
    if by_fid:
        df = sorted(fid for fid, p in by_fid.items() if p.deleted)
        if df != sorted(DELETED_FRAGMENTED):
            problems.append("deleted fragmented set is %r, expected %r"
                            % (df, sorted(DELETED_FRAGMENTED)))
        if not (by_fid["FRAG-06"].deleted and not by_fid["FRAG-07"].deleted):
            problems.append("the two unrecoverable cases must straddle the deleted boundary")
    kinds_deleted = {p.kind for p in placements if p.deleted and not p.fragmented}
    all_kinds = {p.kind for p in placements}
    if kinds_deleted != all_kinds:
        problems.append("deleted contiguous set misses kinds %r"
                        % sorted(all_kinds - kinds_deleted))

    if problems:
        raise ValueError("plan invalid:\n  " + "\n  ".join(problems))

    used = len(owner)
    return {
        "planted_clusters": used,
        "planted_bytes": sum(len(p.data) for p in placements),
        "fragmented": len(frag),
        "deleted": len(deleted),
        "counted_set": counted_set(placements),
        "first_planted_cluster": min(owner),
        "last_planted_cluster": max(owner),
        "residue_clusters": (last_cluster - FIRST_PLANTED_CLUSTER + 1) - used,
    }
