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

SIG_ONLY = "signature-only"
BIFRAGMENT = "bifragment"
UNRECOVERABLE = "unrecoverable-by-design"

KIND_SIGNATURE = {
    "PNG": "PNG", "JPEG": "JPEG", "PDF": "PDF", "DOCX": "ZIP",
    "GZIP": "GZIP", "SQLITE": "SQLITE", "MP4": "MP4",
    "TXT": None,
}
NO_SIGNATURE_KINDS = frozenset(k for k, v in KIND_SIGNATURE.items() if v is None)

ROOT_DIR_CLUSTERS = 4
FIRST_PLANTED_CLUSTER = 2 + ROOT_DIR_CLUSTERS

SPREAD_PER_MILLE = 880

MAX_GAP_BUDGET_CLUSTERS = 128

MAX_GAP_IS_INCLUSIVE = True

LADDER = {
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
FRAG07_SEPARATION = 24

DELETED_FRAGMENTED = ("FRAG-01", "FRAG-03", "FRAG-05", "FRAG-06")

DELETED_CONTIGUOUS = (
    "evidence_log_2026-01-14.txt",
    "audit_trail.log.gz",
    "sector_map_01.png",
    "seizure_photo_b.jpg",
    "chain_of_custody.pdf",
    "sanitization_report.docx",
    "custody_ledger.db",
    "bodycam_intake.mov",
)

DELETED_NAMES = frozenset(
    DELETED_CONTIGUOUS + tuple(LADDER[fid][0] for fid in DELETED_FRAGMENTED)
)


def _shake(material: str, nbytes: int) -> bytes:
    return hashlib.shake_128(material.encode("utf-8")).digest(nbytes)


def _u32(material: str) -> int:
    return int.from_bytes(_shake(material, 4), "big")


def _shuffled(items: Sequence, material: str) -> list:
    a = list(items)
    for i in range(len(a) - 1, 0, -1):
        j = _u32("%s|swap|%d" % (material, i)) % (i + 1)
        a[i], a[j] = a[j], a[i]
    return a


@dataclass(frozen=True)
class Extent:
    cluster_start: int
    cluster_count: int
    byte_offset: int
    byte_length: int

    @property
    def cluster_end(self) -> int:
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
    name: str
    kind: str
    data: bytes
    sha256: str
    deleted: bool
    extents: list
    fragmented: bool
    expected_recoverable: str
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
    if len(extents) < 2:
        return False
    for prev, nxt in zip(extents, extents[1:]):
        if nxt.cluster_start < prev.cluster_start:
            return True
    ordered = sorted(extents, key=lambda e: e.cluster_start)
    for prev, nxt in zip(ordered, ordered[1:]):
        if nxt.cluster_start != prev.cluster_end:
            return True
    return False


class _Allocator:
    def __init__(self, geo, first_cluster: int):
        self.bpc = geo.bytes_per_sector * geo.sectors_per_cluster
        self.data_start = geo.data_start_offset
        self.last_cluster = geo.cluster_count + 1
        self.cursor = first_cluster
        self.claimed: dict = {}

    def clusters_for(self, nbytes: int) -> int:
        return -(-nbytes // self.bpc) if nbytes else 1

    def offset_of(self, cluster: int) -> int:
        return self.data_start + (cluster - 2) * self.bpc

    def runs_from_plan(self, start: int, splits: Sequence[int],
                       gaps: Sequence[int]) -> list:
        runs, c = [], start
        for i, s in enumerate(splits):
            runs.append((c, s))
            c += s + (gaps[i] if i < len(gaps) else 0)
        return runs

    def to_extents(self, runs: Sequence, nbytes: int, owner: str) -> list:
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
    b0 = min(max(1, n_b // 2), 40)
    g = FRAG04_GAP - b0 - 6
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

    if not (a0_start + a0 <= b0_start and b0_start + b0 <= a1_start):
        raise ValueError("interleave: FRAG-05 fragment 0 not inside FRAG-04's gap")
    if not (b0_start + b0 <= a1_start and a1_start + a1 <= b1_start):
        raise ValueError("interleave: FRAG-04 fragment 1 not inside FRAG-05's gap")

    runs_a = [(a0_start, a0), (a1_start, a1)]
    runs_b = [(b0_start, b0), (b1_start, b1)]
    return runs_a, runs_b, (b1_start + b1) - base


def build_plan(geo, corpus, seed) -> list:
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

    units = []
    for f in files:
        fid = ladder_names.get(f.name)
        if fid in ("FRAG-04", "FRAG-05"):
            continue
        units.append(("frag" if fid else "contig", fid, [f.name]))
    units.append(("interleave", "FRAG-04/05", [LADDER["FRAG-04"][0], LADDER["FRAG-05"][0]]))

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

    spans = [unit_span(kind, fid, names) for kind, fid, names in units]
    occupied = sum(spans)

    last_cluster = geo.cluster_count + 1
    usable = last_cluster - FIRST_PLANTED_CLUSTER + 1
    target_span = (usable * SPREAD_PER_MILLE) // 1000
    slack_total = target_span - occupied
    if slack_total < len(units):
        raise ValueError(
            "corpus (%d clusters incl. gaps) does not fit in %d planted clusters"
            % (occupied, target_span))
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

        else:
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
                f0, f1 = _split_two(n, 350)
                runs = [(cur + f1 + FRAG07_SEPARATION, f0), (cur, f1)]
            else:
                raise ValueError("unknown fragmented id %r" % fid)
            ext = alloc.to_extents(runs, len(f.data), name)
            placements_by_name[name] = (ext, fid, LADDER[fid][1])
            alloc.advance_to(max(s + c for s, c in runs))

        jitter = _u32("%s|slack|%d" % (seed, idx)) % 801
        alloc.skip(max(1, (base_slack * (600 + jitter)) // 1000))

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


def claimed_clusters(placements: Iterable[Placement]) -> set:
    claimed = set()
    for p in placements:
        for e in p.extents:
            claimed.update(range(e.cluster_start, e.cluster_end))
    return claimed


def residue_clusters(geo, placements: Iterable[Placement]) -> list:
    claimed = claimed_clusters(placements)
    last = geo.cluster_count + 1
    return [c for c in range(FIRST_PLANTED_CLUSTER, last + 1) if c not in claimed]


RESIDUE_MIX = (
    ("unwritten", 120),
    ("high", 520),
    ("text", 170),
    ("record", 140),
    ("sparse", 50),
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

    residue_fn.claimed_clusters = claimed
    residue_fn.reserved_clusters = reserved
    residue_fn.mix = RESIDUE_MIX
    return residue_fn


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
