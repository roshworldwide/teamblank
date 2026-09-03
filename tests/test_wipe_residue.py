"""Post-wipe raw scan: no planted hash prefix or ASCII marker survives anywhere in the image.

This is demo step 4 reduced to an assertion.  The demo runs the carver over the
wiped image and shows an empty table; this runs something blunter and stricter
underneath it -- a raw byte search for material we planted ourselves and whose
exact bytes we hold -- because a carver finding nothing is evidence about the
carver as well as about the wipe, and a ``bytes.find`` is evidence only about the
wipe.

WHAT IS SEARCHED FOR, and why each one is worth searching for

  * The first 64 bytes of every one of the 40 planted files, read out of
    ``out/fixture.img`` at the offset the manifest names.  These are the headers a
    signature carver keys on and the first thing a partial overwrite leaves behind.
  * The ASCII markers the corpus writes into its own content -- ``SENTINELWIPE
    FIXTURE RECORD``, ``SENTINELWIPE fixture generator``, and the bare word
    ``SENTINELWIPE``, which the built image carries 25 times.  A marker survives a
    misaligned or partial pass that a 64-byte header might straddle.
  * The FAT32 boot signature and the volume label, which live in the reserved
    region at the very front of the image -- the region an off-by-one wipe that
    starts at sector 1 would leave untouched.

Every probe is asserted to be present in the SOURCE image before it is asserted
absent from the wiped one.  A search that finds nothing because it was looking for
nothing proves nothing, and that is the failure mode this file is most exposed to.

SAFETY, which outranks everything above

``out/fixture.img`` is read-only input to this file and is never a target.  The
wipe runs against a COPY in a temporary directory, and the allowlist handed to the
binary names that temporary directory and nothing else -- so the guard, not this
file's care, is what stands between the run and the repository.  Two independent
checks enforce it:

  * ``test_the_committed_fixture_is_byte_identical_afterwards`` re-hashes
    ``out/fixture.img`` and ``out/fixture.manifest.json`` against the digests
    committed in ``fixtures/manifest.json``.  It is ordered last by name so it runs
    after the wipe, and it fails loudly rather than quietly if the fixture was ever
    the target.
  * ``test_no_command_this_file_issues_ever_names_the_repository`` inspects the
    argument list of every command actually executed and refuses any that mentions
    a path inside the repository.  It checks what ran, not what was intended.

When ``core/target/release/wipe`` is absent these tests SKIP, loudly, naming the
missing path.  Set ``SENTINELWIPE_REQUIRE_WIPER=1`` to turn the absence into a
failure, which is what CI should do.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "out"
IMAGE = OUT / "fixture.img"
MANIFEST = OUT / "fixture.manifest.json"
COMMITTED = REPO / "fixtures" / "manifest.json"
#: Cargo appends `.exe` on Windows. Without this the binaries are never found
#: there, every clause in this file skips for a reason that is not true, and
#: `test_no_command_this_file_issues_ever_names_the_repository` then fails
#: because nothing ran -- a red that says "vacuous" when the real answer is
#: "looked for the wrong filename".
_EXE = ".exe" if os.name == "nt" else ""

WIPE_BIN = REPO / "core" / "target" / "release" / ("wipe" + _EXE)
CARVE_BIN = REPO / "core" / "target" / "release" / ("carve" + _EXE)

RUN_ID = "sentinelwipe/test/residue/v1"

# How much of each planted file's head to search for.  64 bytes is long enough
# that a chance collision in 256 MiB of high-entropy noise is not a thing that
# happens (2^-512 per position) and short enough to fit inside the smallest
# planted extent.
HEAD_BYTES = 64

# Markers the corpus writes into its own content.  Counted in the built image at
# test time, asserted present, then asserted gone.
ASCII_MARKERS = [
    b"SENTINELWIPE FIXTURE RECORD",
    b"SENTINELWIPE fixture generator",
    b"SENTINELWIPE",
]

# Structures at the very front of the image, outside any planted file.  A wipe
# that started one sector late would leave these and every other check here would
# still pass.
# Every probe here is 64 bytes for the same reason the file heads are.  A two-byte
# probe is not evidence: the FAT32 boot signature 0x55 0xAA is expected roughly
# 4,096 times by chance in 256 MiB of high-entropy bytes, and asserting its absence
# fails against a perfectly wiped image.  Measured, not reasoned about -- the first
# version of this file asserted exactly that and the wiped image failed it.
FRONT_OF_IMAGE_PROBES = [
    # The OEM name and the head of the BPB, which no planted file overlaps.
    ("bpb_head", 0, 64),
    # The tail of the boot sector, ending on the 0x55 0xAA signature at 510.
    ("boot_sector_tail_through_signature", 448, 64),
]

# Every command this file actually ran, recorded for
# test_no_command_this_file_issues_ever_names_the_repository.
_COMMANDS: list[list[str]] = []


def _run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    _COMMANDS.append(list(argv))
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _require_binary(path: Path, flag: str) -> None:
    if path.exists():
        return
    msg = "%s is not built. Run: cd core && cargo build --release" % path
    if os.environ.get(flag) == "1":
        pytest.fail(msg)
    pytest.skip(msg)


@pytest.fixture(scope="module")
def manifest() -> dict:
    if not MANIFEST.exists():
        pytest.skip("%s is absent; run `make fixtures`" % MANIFEST)
    return json.loads(MANIFEST.read_text())


@pytest.fixture(scope="module")
def probes(manifest: dict) -> list[tuple[str, bytes]]:
    """(label, bytes) for every planted file head and every front-of-image probe.

    Read out of the SOURCE image.  This fixture opens ``out/fixture.img`` for
    reading and never for writing.
    """
    out: list[tuple[str, bytes]] = []
    with IMAGE.open("rb") as fh:
        for f in manifest["files"]:
            ext = f["extents"][0]
            n = min(HEAD_BYTES, ext["byte_length"])
            fh.seek(ext["byte_offset"])
            head = fh.read(n)
            assert len(head) == n, "short read of %s" % f["path"]
            out.append(("head:%s" % f["path"], head))
        for label, off, n in FRONT_OF_IMAGE_PROBES:
            fh.seek(off)
            out.append(("front:%s" % label, fh.read(n)))
    return out


@pytest.fixture(scope="module")
def source_bytes() -> bytes:
    if not IMAGE.exists():
        pytest.skip("%s is absent; run `make fixtures`" % IMAGE)
    return IMAGE.read_bytes()


@pytest.fixture(scope="module")
def wiped(manifest: dict) -> dict:
    """Copy the fixture into a temporary directory, wipe the COPY, return the run.

    The allowlist handed to the binary is the temporary directory and nothing
    else.  Every path in the command line is under it.
    """
    _require_binary(WIPE_BIN, "SENTINELWIPE_REQUIRE_WIPER")
    if not IMAGE.exists():
        pytest.skip("%s is absent; run `make fixtures`" % IMAGE)

    lab = Path(tempfile.mkdtemp(prefix="sentinelwipe-residue-"))
    # realpath, because the guard resolves and compares by inode; on macOS the
    # temporary directory is reached through a symlinked /var.
    lab = lab.resolve()
    target = lab / "target.img"
    shutil.copyfile(IMAGE, target)
    assert _sha256(target) == _sha256(IMAGE), "the copy is not a copy"

    trace = lab / "trace.jsonl"
    proc = _run(
        [
            str(WIPE_BIN),
            "--target", str(target),
            "--allow-root", str(lab),
            "--i-understand", str(target),
            "--run-id", RUN_ID,
            "--sanitize", "ata-secure-erase",
            "--trace", str(trace),
        ]
    )
    try:
        assert proc.returncode == 0, (
            "wipe exited %d\nstderr:\n%s" % (proc.returncode, proc.stderr)
        )
        report = json.loads(proc.stdout)
        data = target.read_bytes()
        yield {
            "lab": lab,
            "target": target,
            "report": report,
            "data": data,
            "trace": trace.read_text() if trace.exists() else "",
            "stderr": proc.stderr,
        }
    finally:
        shutil.rmtree(lab, ignore_errors=True)


# ---------------------------------------------------------------------------
# The probes are real before they are used as evidence of absence
# ---------------------------------------------------------------------------


def test_the_probe_set_covers_every_planted_file_and_the_front_of_the_image(
    probes, manifest
):
    heads = [p for p in probes if p[0].startswith("head:")]
    assert len(heads) == len(manifest["files"]) == 40
    assert len([p for p in probes if p[0].startswith("front:")]) == len(
        FRONT_OF_IMAGE_PROBES
    )
    for label, data in probes:
        # 32 bytes is the floor at which absence from 2^28 random bytes is
        # evidence rather than coincidence.
        assert len(data) >= 32, "%s is too short to be evidence of anything" % label


def test_every_probe_is_present_in_the_source_image(probes, source_bytes):
    """The guard on the guard.

    If these bytes were not in the image to begin with, the absence test below
    would pass against an empty search and prove nothing.
    """
    for label, data in probes:
        assert data in source_bytes, "%s was never in the source image" % label


def test_every_ascii_marker_is_present_in_the_source_image(source_bytes):
    for marker in ASCII_MARKERS:
        n = source_bytes.count(marker)
        assert n > 0, "%r is not in the source image" % marker
    # Measured, not asserted from memory: the built image carries the bare marker
    # 25 times.  A change in the corpus moves this and should be noticed here.
    assert source_bytes.count(b"SENTINELWIPE") == 25


# ---------------------------------------------------------------------------
# The wipe ran, and it says what it did
# ---------------------------------------------------------------------------


def test_the_wipe_reports_read_back_verification_and_not_a_return_code(wiped):
    r = wiped["report"]
    assert r["schema"] == "sentinelwipe.wipe.report/1"
    # The outcome code carries the COVERAGE of its own evidence.  This run is the
    # shipped default, which is sampled, so the whole-medium code must not appear:
    # a 0.195%-coverage run and a 100% exhaustive run once produced byte-identical
    # outcome fields, and "sanitized" is a whole-medium word in SP 800-88.
    assert r["outcome"]["code"] == "OVERWRITE_VERIFIED_ON_SAMPLE"
    assert r["outcome"]["passes_verified"] is True
    assert r["outcome"]["sanitized"] is True
    assert r["outcome"]["whole_medium_claim"] is False
    assert r["outcome"]["sanitized_scope"] == "sampled_sectors_only"
    assert 0.0 < r["outcome"]["verification_coverage_fraction"] < 1.0
    assert r["verification"]["mode"] == "sampled"
    assert r["verification"]["coverage_fraction"] == \
        r["outcome"]["verification_coverage_fraction"]
    assert r["verification"]["all_passes_verified"] is True
    for v in r["verification"]["passes"]:
        assert v["mismatched_sectors"] == 0
        assert v["sectors_verified"] > 0
        assert v["verdict"] == "PATTERN_CONFIRMED_ON_SAMPLE"
    assert r["provenance"]["is_wipe_run"] is True


def test_the_simulated_sanitize_is_labelled_in_its_own_fields(wiped):
    sa = wiped["report"]["sanitize"]
    assert sa is not None
    assert sa["simulated"] is True
    assert "simulated" in sa["operation"]
    assert sa["device_support"] == "simulated"
    assert sa["return_code_trusted"] is False
    # Measured, not assumed: the command changed nothing, and the witness digest
    # taken before and after says so.
    assert sa["medium_unchanged"] is True
    assert sa["medium_witness_before"] == sa["medium_witness_after"]


def test_the_behavioural_audit_refuses_the_instant_sanitize(wiped):
    a = wiped["report"]["audit"]["sanitize"]
    assert a["code"] in ("UNVERIFIED_TIMING", "UNVERIFIED_SIMULATED")
    assert a["code"] != "VERIFIED_TIMING"
    assert a["severity"] != "verified"
    assert a["device_reported_success"] is True, (
        "the device said success; the point is that the verdict ignored it"
    )
    if a["code"] == "UNVERIFIED_TIMING":
        assert a["measured_duration_ns"] * 20 < a["expected_min_duration_ns"]


def test_the_overwrite_audit_is_not_judged_against_the_overwrite(wiped):
    a = wiped["report"]["audit"]["overwrite"]
    assert a["baseline"]["source"] == "calibration_probe"
    assert a["baseline"]["probe_bytes"] == wiped["report"]["calibration_probe"]["bytes"]


def test_the_entropy_figures_are_the_manifest_figure_and_a_climb(wiped, manifest):
    e = wiped["report"]["entropy_bits_per_byte"]
    assert e["bytes_measured"] == manifest["image_bytes"] == 268435456
    # The same estimator over the same support as fixtures/corpus.py, to the six
    # places the report publishes.
    assert abs(e["before"] - manifest["whole_image_entropy_bits_per_byte"]) < 5e-6
    assert e["after"] > 7.99
    assert e["delta"] > 0.9


# ---------------------------------------------------------------------------
# What the sampled verification does NOT cover, joined against the manifest
# ---------------------------------------------------------------------------

# Domain strings from core/wipe/src/passes.rs and core/wipe/src/verify.rs.  This
# is an INDEPENDENT re-implementation of the sampling plan, in Python, from the
# published run id alone -- the same thing a third party auditing the certificate
# would have to write.  If it agrees with the shipped sample_digest_hex, the
# certificate's claim that anyone can re-check exactly which sectors were read is
# true; and the same LBAs then say which planted files were never looked at.
RUN_SEED_DOMAIN = b"SENTINELWIPE/run-seed/v1"
SAMPLING_DOMAIN = b"SENTINELWIPE/verify-sample/v1"
METHOD_ID_SEEDED_RANDOM = 2
SECTOR_BYTES = 512
REGION_SECTORS = 2048          # 1 MiB regions
SECTORS_PER_MIB = 4            # the shipped default


def _sample_region(seed: bytes, region_index: int, first_lba: int, n: int, k: int) -> list:
    """core/wipe/src/verify.rs::sample_region, re-implemented.

    Rejection sampling, not a raw modulo: the modulo of a uniform 64-bit value is
    biased toward low indices whenever the bound does not divide 2**64, and a
    sampler biased toward the start of every region under-reads the end of it.
    """
    x = hashlib.shake_128()
    x.update(SAMPLING_DOMAIN)
    x.update(seed)
    x.update(bytes([METHOD_ID_SEEDED_RANDOM]))
    x.update((1).to_bytes(4, "little"))              # pass 1
    x.update(region_index.to_bytes(8, "little"))
    x.update(n.to_bytes(8, "little"))
    zone = (2 ** 64 // n) * n
    chosen: list = []
    nbytes, stream, i = 1024, x.digest(1024), 0
    while len(chosen) < k:
        if i + 8 > len(stream):                      # SHAKE output is prefix-stable
            nbytes *= 2
            stream = x.digest(nbytes)
        word = int.from_bytes(stream[i:i + 8], "little")
        i += 8
        if word >= zone:
            continue
        lba = first_lba + (word % n)
        if lba not in chosen:
            chosen.append(lba)
    return sorted(chosen)


def _rederive_plan(run_id: str, sector_count: int) -> list:
    seed = hashlib.shake_128(RUN_SEED_DOMAIN + run_id.encode()).digest(32)
    out: list = []
    for r in range(sector_count // REGION_SECTORS):
        out += _sample_region(seed, r, r * REGION_SECTORS, REGION_SECTORS, SECTORS_PER_MIB)
    return out


def test_the_sampling_plan_is_reproducible_by_a_third_party(wiped):
    """The certificate says a reader can re-check which sectors were read.  This
    is that reader, holding only the run id."""
    r = wiped["report"]
    lbas = _rederive_plan(RUN_ID, r["device"]["total_sectors"])
    d = hashlib.shake_128()
    d.update(SAMPLING_DOMAIN)
    for lba in lbas:
        d.update(lba.to_bytes(8, "little"))
    v = r["verification"]["passes"][0]
    assert len(lbas) == v["sectors_verified"] == 1024
    assert d.digest(32).hex() == v["sample_digest_hex"], (
        "the published sample digest does not match a plan re-derived from the "
        "run id alone; the reproducibility claim is false"
    )


def test_the_sampled_verification_never_looked_at_27_of_the_40_planted_files(
    wiped, manifest
):
    """THE LIMITATION, MEASURED ON THIS FIXTURE, AS A TEST.

    At the shipped default of 4 sampled sectors per MiB the read-back covers
    0.1953% of the medium, and the sectors it covers are decided by the seed --
    not by where the data is.  Joining the re-derived plan against the manifest's
    extents: 27 of the 40 planted files have NOT ONE of their sectors in the
    sample, and the longest run of consecutive sectors the plan never touches is
    2,780 sectors (1,423,360 bytes, 0.53% of the medium) -- larger than 33 of the
    40 planted files.  A file left unwiped inside such a run produces
    PATTERN_CONFIRMED_ON_SAMPLE with zero mismatches, which an adversarial
    verifier demonstrated by restoring one 208 kB planted file into an otherwise
    wiped image and watching the sampled verdict stay green while the project's
    own carver recovered the file byte-exact.

    The engine's answer is not to hide this: `--verify exhaustive` reads every
    sector, and the report publishes the size of the blind spot in `limits` and
    in `verification.largest_unsampled_run_sectors`.  The mechanism regression is
    core/wipe/src/verify.rs::
    a_region_left_unwiped_between_sample_points_survives_a_confirmed_sample;
    this test is the fixture-specific figure, so the figure cannot drift
    unnoticed.
    """
    r = wiped["report"]
    sector_count = r["device"]["total_sectors"]
    sampled = set(_rederive_plan(RUN_ID, sector_count))

    missed = []
    for f in manifest["files"]:
        sectors = set()
        for e in f["extents"]:
            first = e["byte_offset"] // SECTOR_BYTES
            last = (e["byte_offset"] + e["byte_length"] - 1) // SECTOR_BYTES
            sectors.update(range(first, last + 1))
        if not (sectors & sampled):
            missed.append(f["path"])

    assert len(manifest["files"]) == 40
    assert len(missed) == 27, (
        "MEASURED FIGURE MOVED: %d of 40 planted files carry no sampled sector "
        "(was 27). Re-measure it and update the number, never the assertion: %r"
        % (len(missed), sorted(missed)[:5])
    )

    # The blind spot the report publishes is the one the plan actually has.
    ordered = sorted(sampled)
    largest, prev = 0, None
    for lba in ordered:
        run = lba if prev is None else lba - prev - 1
        largest = max(largest, run)
        prev = lba
    largest = max(largest, sector_count - prev - 1)
    assert largest == 2780, largest
    assert r["verification"]["largest_unsampled_run_sectors"] == largest
    assert r["verification"]["passes"][0]["largest_unsampled_run_sectors"] == largest

    # ...and it is published in prose a reader will actually meet, with the
    # measured number in it rather than a hedge.
    limit = [l for l in r["limits"] if "BLIND SPOT" in l]
    assert len(limit) == 1, r["limits"]
    assert "%d sectors" % largest in limit[0], limit[0]
    assert str(largest * SECTOR_BYTES) in limit[0]
    assert "PATTERN_CONFIRMED_ON_SAMPLE" in limit[0]
    assert "--verify exhaustive" in limit[0]


# ---------------------------------------------------------------------------
# The residue scan
# ---------------------------------------------------------------------------


def test_no_planted_file_head_survives_the_wipe(wiped, probes):
    survivors = []
    data = wiped["data"]
    for label, needle in probes:
        if not label.startswith("head:"):
            continue
        at = data.find(needle)
        if at != -1:
            survivors.append((label, at))
    assert survivors == [], "%d planted heads survived: %r" % (
        len(survivors),
        survivors[:5],
    )


def test_no_front_of_image_structure_survives_the_wipe(wiped, probes):
    """The off-by-one-sector check.

    A wipe that began at LBA 1 would pass every planted-file check in this file
    and leave the boot sector intact.
    """
    survivors = [
        label
        for label, needle in probes
        if label.startswith("front:") and needle in wiped["data"]
    ]
    assert survivors == [], "front-of-image structures survived: %r" % survivors


def test_no_ascii_marker_survives_the_wipe(wiped):
    counts = {m: wiped["data"].count(m) for m in ASCII_MARKERS}
    assert all(n == 0 for n in counts.values()), "markers survived: %r" % counts


def test_the_wiped_image_is_the_same_length_and_entirely_different(wiped):
    assert len(wiped["data"]) == IMAGE.stat().st_size == 268435456
    # Not a residue check -- a check that the wipe wrote the whole medium rather
    # than a prefix of it.  Sampled at the last sector, which is the one a
    # length-truncated pass would miss.
    original_tail = IMAGE.open("rb").read()[-512:]
    assert wiped["data"][-512:] != original_tail


def test_the_carver_finds_nothing_in_the_wiped_image(wiped):
    """Demo step 4, run as a test.

    The same engine that recovers 28 of 40 from the fixture is pointed at the
    wiped copy with identical parameters.  Exit 1 is `no candidate admitted` and
    is the expected, meaningful result.
    """
    _require_binary(CARVE_BIN, "SENTINELWIPE_REQUIRE_CARVER")
    proc = _run(
        [
            str(CARVE_BIN),
            "--phase", "post-wipe",
            str(wiped["target"]),
        ]
    )
    assert proc.returncode in (0, 1), "carve failed: %s" % proc.stderr
    report = json.loads(proc.stdout)
    assert report["counts"]["admitted"] == 0, (
        "the carver admitted %d candidates from a wiped image"
        % report["counts"]["admitted"]
    )


def test_the_telemetry_trace_was_recorded_and_covers_the_medium(wiped):
    lines = [ln for ln in wiped["trace"].splitlines() if ln.strip()]
    assert lines, "no telemetry trace was written"
    header = json.loads(lines[0])
    assert header["ev"] == "header"
    assert header["schema"] == "sentinelwipe.wipe.telemetry/1"
    assert header["total_sectors"] == 524288
    progress = [json.loads(ln) for ln in lines if '"progress"' in ln]
    assert progress, "the trace carries no progress frames"
    # Every sector appears in exactly one delivered frame: the ranges tile.
    covered = sorted((p["first_sector"], p["sector_count"]) for p in progress)
    cursor = 0
    for first, count in covered:
        assert first == cursor, "telemetry gap or overlap at sector %d" % cursor
        cursor += count
    assert cursor == header["total_sectors"]


# ---------------------------------------------------------------------------
# The binary refuses what it must refuse
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def sacrificial(tmp_path_factory) -> Path:
    """A small file in a temporary directory, for the refusal tests.

    Never the fixture, and never even a copy of it: these tests must not depend
    on anything the repository owns.
    """
    d = Path(tmp_path_factory.mktemp("sentinelwipe-refusals")).resolve()
    f = d / "sacrificial.img"
    f.write_bytes(b"\xa5" * (64 * 1024))
    return f


def test_the_binary_destroys_nothing_without_all_three_conjunctions(sacrificial):
    _require_binary(WIPE_BIN, "SENTINELWIPE_REQUIRE_WIPER")
    before = _sha256(sacrificial)
    lab = str(sacrificial.parent)
    cases = [
        ([], 2, "no arguments at all"),
        ([str(sacrificial)], 2, "a bare path as a positional"),
        (["--target", str(sacrificial)], 2, "a target with no allowlist"),
        (
            ["--target", str(sacrificial), "--allow-root", lab],
            2,
            "an allowlisted target with no typed confirmation",
        ),
        (
            [
                "--target", str(sacrificial),
                "--allow-root", lab,
                "--i-understand", "yes",
            ],
            3,
            "a confirmation that does not name the resolved target",
        ),
        (
            [
                "--target", str(sacrificial),
                "--allow-root", lab,
                "--i-understand", str(sacrificial).upper(),
            ],
            3,
            "a confirmation in the wrong case",
        ),
    ]
    for args, expected, why in cases:
        proc = _run([str(WIPE_BIN)] + args)
        assert proc.returncode == expected, (
            "%s: expected exit %d, got %d\n%s"
            % (why, expected, proc.returncode, proc.stderr or proc.stdout[:400])
        )
        assert not proc.stdout.startswith("{"), (
            "%s produced a report; a refused run must emit nothing on stdout" % why
        )
    assert _sha256(sacrificial) == before, (
        "a refused run changed the file it refused"
    )


def test_a_target_outside_every_allowed_root_is_refused_by_the_guard(
    sacrificial, tmp_path
):
    """The clause that keeps the repository out of reach.

    The allowlist names an empty directory; the target is elsewhere.  This is the
    same clause that refuses ``out/fixture.img`` when the allowlist names a
    scratch directory, exercised against a file nobody needs so that a broken
    guard destroys nothing that matters.
    """
    _require_binary(WIPE_BIN, "SENTINELWIPE_REQUIRE_WIPER")
    before = _sha256(sacrificial)
    elsewhere = Path(tmp_path).resolve() / "empty-root"
    elsewhere.mkdir()
    proc = _run(
        [
            str(WIPE_BIN),
            "--target", str(sacrificial),
            "--allow-root", str(elsewhere),
            "--i-understand", str(sacrificial),
        ]
    )
    assert proc.returncode == 3, proc.stderr
    assert "DENY_NOT_ALLOWLISTED" in proc.stderr, proc.stderr
    assert _sha256(sacrificial) == before


def test_the_trace_recorder_refuses_to_truncate_an_existing_file(sacrificial):
    """The second destructive path, closed.

    ``--trace`` creates a file, and a recorder opened for writing truncates one
    that is already there -- with a confirmation the binary supplies for itself
    rather than one the operator typed.  Left open, that would be a way to
    destroy a file inside the allowlist without naming it.  The guard is asked
    the exclusive-create question and answers in its own vocabulary.
    """
    _require_binary(WIPE_BIN, "SENTINELWIPE_REQUIRE_WIPER")
    lab = sacrificial.parent
    occupied = lab / "already-here.jsonl"
    occupied.write_bytes(b"do not truncate me")
    before = _sha256(occupied)
    target_before = _sha256(sacrificial)
    proc = _run(
        [
            str(WIPE_BIN),
            "--target", str(sacrificial),
            "--allow-root", str(lab),
            "--i-understand", str(sacrificial),
            "--trace", str(occupied),
        ]
    )
    assert proc.returncode == 3, proc.stderr
    assert "DENY_TARGET_ALREADY_EXISTS" in proc.stderr, proc.stderr
    assert _sha256(occupied) == before, "the recorder truncated an existing file"
    assert _sha256(sacrificial) == target_before, (
        "a run refused at the recorder still wrote to the medium"
    )


def test_plan_prints_the_decision_and_opens_nothing(sacrificial):
    _require_binary(WIPE_BIN, "SENTINELWIPE_REQUIRE_WIPER")
    before = _sha256(sacrificial)
    proc = _run(
        [
            str(WIPE_BIN),
            "--target", str(sacrificial),
            "--allow-root", str(sacrificial.parent),
            "--plan",
        ]
    )
    assert proc.returncode == 0, proc.stderr
    assert "DENY_CONFIRMATION_ABSENT" in proc.stdout
    assert str(sacrificial) in proc.stdout
    assert "never opens a writable descriptor" in proc.stdout
    assert _sha256(sacrificial) == before


# ---------------------------------------------------------------------------
# Safety.  Named to sort last so it runs after everything above.
# ---------------------------------------------------------------------------


def test_no_command_this_file_issues_ever_names_the_repository():
    """Inspect what actually ran, not what was intended.

    Every argument of every command this module executed is checked against the
    repository root.  A future edit that points the wipe at ``out/fixture.img``
    fails here whether or not the guard would have caught it.
    """
    # Nothing ran is a legitimate state -- the binaries may not be built, in
    # which case every clause above skipped and there is nothing to inspect.
    # Say so rather than failing: a red here would name vacuity when the real
    # answer is "there was nothing to check yet", and that misdirects whoever
    # reads it. With the binaries present, an empty list IS vacuity and fails.
    if not _COMMANDS:
        if not WIPE_BIN.exists() and not CARVE_BIN.exists():
            pytest.skip(
                "NOT VERIFIED: no command ran because neither %s nor %s is built. "
                "Run: cd core && cargo build --release"
                % (WIPE_BIN.name, CARVE_BIN.name)
            )
        pytest.fail(
            "no command was recorded even though the binaries exist; this check "
            "would be vacuous"
        )
    repo = str(REPO)
    for argv in _COMMANDS:
        binary, args = argv[0], argv[1:]
        assert binary.startswith(str(REPO / "core" / "target")), binary
        for a in args:
            if not a.startswith("/"):
                continue
            resolved = os.path.realpath(a)
            assert not resolved.startswith(repo + os.sep), (
                "a command named a path inside the repository: %r in %r" % (a, argv)
            )


def test_zz_the_committed_fixture_is_byte_identical_afterwards():
    """The fixture is sacred and this is where that is enforced.

    Named ``zz`` so pytest's file order runs it after every wipe above.  It
    re-hashes both artifacts against the digests committed in
    ``fixtures/manifest.json`` -- not against a value captured earlier in this
    process, which a run that damaged the fixture before capture would satisfy.
    """
    expected = json.loads(COMMITTED.read_text())["expected"]
    if not IMAGE.exists():
        pytest.skip("%s is absent; run `make fixtures`" % IMAGE)
    assert _sha256(IMAGE) == expected["image_sha256"], (
        "out/fixture.img CHANGED. Phase 1 and Phase 2 are measured against it and "
        "its digest is committed. Rebuild with `make fixtures` and find out what "
        "wrote to it."
    )
    assert _sha256(MANIFEST) == expected["manifest_sha256"]
    assert IMAGE.stat().st_size == expected["size_bytes"]
