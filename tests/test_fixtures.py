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


@pytest.fixture(scope="session")
def built():
    return B.build(seed=SEED, size_bytes=SIZE, write=False)


@pytest.fixture(scope="session")
def manifest(built):
    return json.loads(built.manifest_bytes.decode("utf-8"))


def test_two_builds_from_one_seed_are_byte_identical(built):
    again = B.build(seed=SEED, size_bytes=SIZE, write=False)
    assert again.image_sha256 == built.image_sha256
    assert again.manifest_sha256 == built.manifest_sha256
    assert again.image == built.image
    assert again.manifest_bytes == built.manifest_bytes


def test_a_second_seed_moves_every_hash(built):
    other = B.build(seed=SEED + "/v2-probe", size_bytes=SIZE, write=False)
    assert other.image_sha256 != built.image_sha256
    assert other.manifest_sha256 != built.manifest_sha256
    assert len(other.image) == len(built.image)


def test_a_fresh_interpreter_under_a_hostile_environment_agrees(built, tmp_path):
    env = dict(os.environ)
    env.update(PYTHONHASHSEED="12345", TZ="Pacific/Chatham",
               LANG="tr_TR.UTF-8", LC_ALL="tr_TR.UTF-8")
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(_REPO / "fixtures" / "build_image.py"),
         "--seed", SEED, "--size", str(SIZE), "--out", str(out), "--quiet"],
        cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=900)
    assert proc.returncode == 0, proc.stderr
    printed = proc.stdout.split()[0]
    assert printed == built.image_sha256, proc.stdout
    on_disk = (out / B.IMAGE_NAME).read_bytes()
    assert hashlib.sha256(on_disk).hexdigest() == built.image_sha256


REQUIRED_FILE_FIELDS = ("path", "offset", "size", "sha256", "fragmented",
                        "expected_recoverable")


def test_every_file_carries_all_six_required_fields(manifest):
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
    got = manifest["whole_image_entropy_bits_per_byte"]
    assert got == pytest.approx(C.shannon_bits_per_byte(built.image), abs=1e-6)
    assert 5.0 < got < 7.9


def test_counted_set_is_consistent_with_the_file_list(manifest):
    cs = manifest["counted_set"]
    files = manifest["files"]
    unrec = [f for f in files if f["expected_recoverable"] == P.UNRECOVERABLE]
    assert cs["total"] == len(files) == 40
    assert cs["unrecoverable_by_design"] == len(unrec) == 7
    assert cs["expected_recoverable"] == len(files) - len(unrec) == 33

    nosig = [f for f in unrec if f["kind"].upper() == "TXT"]
    byfrag = sorted(f["path"] for f in unrec if f["kind"].upper() != "TXT")
    assert len(nosig) == 5, "expected 5 plaintext files with no signature"
    assert byfrag == ["/evidence_bag_seal.jpg", "/media_inventory.docx"], byfrag

    for f in files:
        if f["kind"].upper() == "TXT":
            assert f["expected_recoverable"] == P.UNRECOVERABLE, f["path"]

    assert cs["expected_recoverable"] != cs["total"]


def test_the_manifest_bytes_carry_no_carriage_return(built):
    assert b"\r" not in built.manifest_bytes
    assert built.manifest_bytes.endswith(b"\n")
    assert json.loads(built.manifest_bytes.decode("utf-8"))["schema"] == B.MANIFEST_SCHEMA


MAGIC_AT_0 = {
    "GZIP": b"\x1f\x8b\x08",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "PDF": b"%PDF-",
    "DOCX": b"PK\x03\x04",
    "SQLITE": b"SQLite format 3\x00",
}


def test_first_extent_offset_holds_the_files_magic_bytes(built, manifest):
    img = built.image
    checked = {}
    for entry in manifest["files"]:
        off = entry["extents"][0]["byte_offset"]
        kind = entry["kind"]
        if kind == "MP4":
            assert img[off + 4:off + 8] == b"ftyp", entry["path"]
        elif kind == "TXT":
            head = img[off:off + 64]
            head.decode("ascii")
            assert head.strip(), entry["path"]
        else:
            magic = MAGIC_AT_0[kind]
            assert img[off:off + len(magic)] == magic, entry["path"]
        checked[kind] = checked.get(kind, 0) + 1
    assert sorted(checked) == sorted(C.KINDS), checked
    assert set(checked.values()) == {5}, checked


def test_every_extent_holds_its_own_slice_and_the_file_reassembles(built, manifest):
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


def _fat_entry(geo, img, cluster: int) -> int:
    off = geo.reserved * geo.bytes_per_sector + cluster * 4
    return struct.unpack_from("<I", img, off)[0] & 0x0FFFFFFF


def test_deleted_files_survive_the_residue_fill(built, manifest):
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
    geo = built.geo
    img = bytearray(built.image)
    deleted = [e for e in manifest["files"] if e["deleted"]]
    naive = P.make_residue_fn(geo, [], SEED)
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
        assert e["long_name"] == name

    img = built.image
    for entry in manifest["files"]:
        if not entry["deleted"]:
            continue
        rebuilt = b"".join(img[x["byte_offset"]:x["byte_offset"] + x["byte_length"]]
                           for x in entry["extents"])
        assert hashlib.sha256(rebuilt).hexdigest() == entry["sha256"], entry["path"]


def test_live_entries_still_carry_their_allocation_fields(built, manifest):
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
    geo, img = built.geo, built.image
    for entry in manifest["files"]:
        if entry["deleted"]:
            continue
        first = entry["extents"][0]["cluster_start"]
        assert _fat_entry(geo, img, first) != 0, entry["path"]


def test_the_residue_never_wrote_into_a_planted_cluster(built):
    geo = built.geo
    planted = len(P.claimed_clusters(built.placements))
    residue = built.stats["residue_written"]
    zeroed = built.stats["root_reserve_zeroed"]
    root = F.root_directory_clusters(geo, [p.name for p in built.placements])
    assert planted + residue + zeroed + root == geo.cluster_count, (
        planted, residue, zeroed, root, geo.cluster_count)


def test_the_reserved_region_is_untouched_by_residue(built):
    geo, img = built.geo, built.image
    sec = geo.bytes_per_sector
    assert img[510:512] == b"\x55\xaa"
    assert img[6 * sec:6 * sec + 512] == img[0:512]
    assert img[sec:sec + 4] == b"RRaA"
    assert img[7 * sec:7 * sec + 4] == b"RRaA"
    fat0 = geo.reserved * sec
    fat1 = fat0 + geo.fat_sectors * sec
    n = geo.fat_sectors * sec
    assert img[fat0:fat0 + n] == img[fat1:fat1 + n], "the two FAT copies differ"


def test_fragmented_means_non_adjacent_not_multiple_extents(manifest):
    for entry in manifest["files"]:
        runs = sorted(entry["extents"], key=lambda e: e["cluster_start"])
        non_adjacent = any(
            b["cluster_start"] != a["cluster_start"] + a["cluster_count"]
            for a, b in zip(runs, runs[1:]))
        assert entry["fragmented"] == non_adjacent, entry["path"]
        if entry["fragmented"]:
            assert len(entry["extents"]) > 1


def test_the_two_definitions_actually_differ(built):
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

    unrec_frag = {p.frag_id for p in built.placements
                  if p.expected_recoverable == P.UNRECOVERABLE and p.frag_id}
    assert unrec_frag == {"FRAG-06", "FRAG-07"}
    unrec_nosig = {p.name for p in built.placements
                   if p.expected_recoverable == P.UNRECOVERABLE and not p.frag_id}
    assert unrec_nosig == {p.name for p in built.placements
                           if p.kind in P.NO_SIGNATURE_KINDS}
    assert len(unrec_nosig) == 5
    a0, a1 = by_fid["FRAG-04"].extents
    b0, b1 = by_fid["FRAG-05"].extents
    assert a0.cluster_start + a0.cluster_count <= b0.cluster_start
    assert b0.cluster_start + b0.cluster_count <= a1.cluster_start
    assert a1.cluster_start + a1.cluster_count <= b1.cluster_start
    assert by_fid["FRAG-04"].kind == by_fid["FRAG-05"].kind
    assert by_fid["FRAG-06"].deleted and not by_fid["FRAG-07"].deleted


def test_the_max_gap_budget_is_published_with_its_convention(manifest):
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
    pdf = [e for e in manifest["files"]
           if e["path"] == "/disposal_certificate.pdf"][0]
    assert pdf["expected_recoverable"] == P.BIFRAGMENT
    assert pdf["fragmented"] is True
    assert len(pdf["extents"]) == 2
    a, b = pdf["extents"]
    assert b["cluster_start"] - (a["cluster_start"] + a["cluster_count"]) == \
        manifest["max_gap_clusters"]


def test_the_residue_false_positive_floor_is_measured_and_published(built, manifest):
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

    for name in ("PNG", "PDF", "ZIP", "SQLITE", "MP4"):
        assert published[name] == 0, (name, published[name])
    assert published["JPEG"] > 0 and published["GZIP"] > 0


_BANNED = re.compile(
    r"zlib\.compress|compressobj|zlib\.compressobj|gzip\.(open|compress|GzipFile)"
    r"|zipfile\.|ZipFile|ZIP_DEFLATED|bz2\.|lzma\.|import\s+random\b|random\.(?!$)"
    r"|time\.time\(|datetime\.|uuid\.|os\.urandom")

_FIXTURE_MODULES = ("guard/__init__.py", "guard/posix.py", "guard/windows.py",
                    "deflate.py", "corpus.py", "fat32.py", "plan.py",
                    "build_image.py")

_OS_EXEMPT_PREFIX = "guard/"


def _code_lines(path: Path):
    text = path.read_text(encoding="utf-8")
    text = re.sub(r'"""(?:.|\n)*?"""', '""', text)
    text = re.sub(r"'''(?:.|\n)*?'''", "''", text)
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.split("#", 1)[0]
        if stripped.strip():
            yield i, stripped


def test_no_compressor_and_no_clock_in_the_fixture_path():
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
    probe = tmp_path / "probe.py"
    probe.write_bytes(b"import zlib\nx = zlib.compress(b'a')\ny = time.time()\n")
    hits = [i for i, line in _code_lines(probe) if _BANNED.search(line)]
    assert len(hits) == 2, hits


_BANNED_IMPORTS = {
    "random", "secrets", "uuid", "time", "datetime", "locale", "gzip",
    "zipfile", "bz2", "lzma", "platform", "socket", "subprocess", "resource",
    "getpass", "pwd", "grp", "calendar", "sched", "tempfile",
}
_ZLIB_ALLOWED = {"crc32", "adler32", "decompress"}
_OS_BANNED_ALWAYS = {
    "urandom", "getpid", "getppid", "getuid", "geteuid", "getgid", "getlogin",
    "uname", "times", "cpu_count", "getloadavg", "system", "popen", "fork",
}
_OS_BANNED_OUTSIDE_GUARD = {
    "stat", "lstat", "fstat", "statvfs", "environ", "getenv", "putenv",
    "listdir", "scandir", "walk",
}


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return list(reversed(parts))


def resolve_banned_uses(source: str, filename: str, os_exempt: bool = False):
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
    hits = []
    for name in _FIXTURE_MODULES:
        path = _REPO / "fixtures" / name
        for lineno, full in resolve_banned_uses(
                path.read_text(encoding="utf-8"), name,
                os_exempt=name.startswith(_OS_EXEMPT_PREFIX)):
            hits.append("fixtures/%s:%d: %s" % (name, lineno, full))
    assert not hits, "banned use in the fixture path:\n  " + "\n  ".join(hits)


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

_ALLOWED_SPELLINGS = [
    "import zlib\nc = zlib.crc32(b'a')",
    "import zlib\nx = zlib.adler32(b'a')",
    "import zlib\nx = zlib.decompress(b'')",
    "import zlib as _z",
    "from zlib import compress",
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
    assert resolve_banned_uses("import os\nk = os.urandom(4)", "<p>",
                               os_exempt=True)
    assert resolve_banned_uses("import time\nt = time.time()", "<p>",
                               os_exempt=True)
    assert resolve_banned_uses("import os\ns = os.stat('/')", "<p>",
                               os_exempt=True) == []
    assert resolve_banned_uses("import os\ns = os.stat('/')", "<p>") != []


def test_zlib_is_used_only_for_fixed_algorithms():
    allowed = re.compile(r"zlib\.(crc32|adler32|decompress)\b")
    for name in _FIXTURE_MODULES:
        path = _REPO / "fixtures" / name
        for i, line in _code_lines(path):
            for m in re.finditer(r"zlib\.\w+", line):
                assert allowed.match(m.group(0)), "fixtures/%s:%d: %s" % (
                    name, i, line.strip())


def test_an_independent_reparse_finds_the_live_files_and_marks_the_deleted(built,
                                                                          manifest):
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
        assert name in by_name, "deleted file %s left no directory trace" % name
        assert by_name[name]["deleted"] is True, name
        assert by_name[name]["chain"] == [], name

    assert sum(1 for e in got["files"] if not e["deleted"]) == 28
    assert sum(1 for e in got["files"] if e["deleted"]) == 12


def _expected_block(res, image=None, man=None):
    return {"seed": res.seed, "size_bytes": res.manifest["image_bytes"],
            "bytes_per_cluster": res.geo.bytes_per_cluster,
            "image_sha256": image or res.image_sha256,
            "manifest_sha256": man or res.manifest_sha256}


@pytest.fixture()
def cli(monkeypatch, built, tmp_path):
    def run(record, argv_extra=()):
        monkeypatch.setattr(B, "build", lambda **kw: built)
        monkeypatch.setattr(B, "_read_expected", lambda path: record)
        argv = ["--seed", SEED, "--size", str(SIZE),
                "--out", str(tmp_path / "out")] + list(argv_extra)
        return B.main(argv)
    return run


def test_a_mismatch_against_the_committed_digests_exits_nonzero(cli, built, capsys):
    bad = _expected_block(built, image="0" * 64, man="1" * 64)
    code = cli(bad)
    assert code == 4, "a drifted fixture exited %r" % code
    err = capsys.readouterr().err
    assert "DOES NOT MATCH" in err
    assert "0" * 64 in err and built.image_sha256 in err
    assert "1" * 64 in err and built.manifest_sha256 in err


def test_the_mismatch_is_detected_in_quiet_mode_too(cli, built, capsys):
    code = cli(_expected_block(built, image="0" * 64), ["--quiet"])
    assert code == 4
    cap = capsys.readouterr()
    assert cap.out.split()[0] == built.image_sha256
    assert "DOES NOT MATCH" in cap.err


def test_no_check_expected_is_the_typed_escape_for_a_deliberate_change(cli, built,
                                                                       capsys):
    code = cli(_expected_block(built, image="0" * 64), ["--no-check-expected"])
    assert code == 0
    err = capsys.readouterr().err
    assert "DOES NOT MATCH" in err
    assert "--no-check-expected given" in err


def test_a_matching_build_exits_zero(cli, built, capsys):
    code = cli(_expected_block(built))
    assert code == 0
    out = capsys.readouterr().out
    assert "committed sha256 match    yes" in out


def test_absent_or_incomparable_records_are_not_failures(cli, built, capsys):
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
    assert exp["max_gap_clusters"] == built.manifest["max_gap_clusters"]
    assert exp["max_gap_is_inclusive"] is built.manifest["max_gap_is_inclusive"]
    assert exp["residue_signature_false_positives"] == \
        built.manifest["residue_signature_false_positives"]
    assert exp["deleted_entries_carry_no_allocation_fields"] is True
