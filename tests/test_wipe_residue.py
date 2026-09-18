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
_EXE = ".exe" if os.name == "nt" else ""

WIPE_BIN = REPO / "core" / "target" / "release" / ("wipe" + _EXE)
CARVE_BIN = REPO / "core" / "target" / "release" / ("carve" + _EXE)

RUN_ID = "sentinelwipe/test/residue/v1"

HEAD_BYTES = 64

ASCII_MARKERS = [
    b"SENTINELWIPE FIXTURE RECORD",
    b"SENTINELWIPE fixture generator",
    b"SENTINELWIPE",
]

FRONT_OF_IMAGE_PROBES = [
    ("bpb_head", 0, 64),
    ("boot_sector_tail_through_signature", 448, 64),
]

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
    _require_binary(WIPE_BIN, "SENTINELWIPE_REQUIRE_WIPER")
    if not IMAGE.exists():
        pytest.skip("%s is absent; run `make fixtures`" % IMAGE)

    lab = Path(tempfile.mkdtemp(prefix="sentinelwipe-residue-"))
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


def test_the_probe_set_covers_every_planted_file_and_the_front_of_the_image(
    probes, manifest
):
    heads = [p for p in probes if p[0].startswith("head:")]
    assert len(heads) == len(manifest["files"]) == 40
    assert len([p for p in probes if p[0].startswith("front:")]) == len(
        FRONT_OF_IMAGE_PROBES
    )
    for label, data in probes:
        assert len(data) >= 32, "%s is too short to be evidence of anything" % label


def test_every_probe_is_present_in_the_source_image(probes, source_bytes):
    for label, data in probes:
        assert data in source_bytes, "%s was never in the source image" % label


def test_every_ascii_marker_is_present_in_the_source_image(source_bytes):
    for marker in ASCII_MARKERS:
        n = source_bytes.count(marker)
        assert n > 0, "%r is not in the source image" % marker
    assert source_bytes.count(b"SENTINELWIPE") == 25


def test_the_wipe_reports_read_back_verification_and_not_a_return_code(wiped):
    r = wiped["report"]
    assert r["schema"] == "sentinelwipe.wipe.report/1"
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
    assert abs(e["before"] - manifest["whole_image_entropy_bits_per_byte"]) < 5e-6
    assert e["after"] > 7.99
    assert e["delta"] > 0.9


RUN_SEED_DOMAIN = b"SENTINELWIPE/run-seed/v1"
SAMPLING_DOMAIN = b"SENTINELWIPE/verify-sample/v1"
METHOD_ID_SEEDED_RANDOM = 2
SECTOR_BYTES = 512
REGION_SECTORS = 2048
SECTORS_PER_MIB = 4


def _sample_region(seed: bytes, region_index: int, first_lba: int, n: int, k: int) -> list:
    x = hashlib.shake_128()
    x.update(SAMPLING_DOMAIN)
    x.update(seed)
    x.update(bytes([METHOD_ID_SEEDED_RANDOM]))
    x.update((1).to_bytes(4, "little"))
    x.update(region_index.to_bytes(8, "little"))
    x.update(n.to_bytes(8, "little"))
    zone = (2 ** 64 // n) * n
    chosen: list = []
    nbytes, stream, i = 1024, x.digest(1024), 0
    while len(chosen) < k:
        if i + 8 > len(stream):
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

    limit = [l for l in r["limits"] if "BLIND SPOT" in l]
    assert len(limit) == 1, r["limits"]
    assert "%d sectors" % largest in limit[0], limit[0]
    assert str(largest * SECTOR_BYTES) in limit[0]
    assert "PATTERN_CONFIRMED_ON_SAMPLE" in limit[0]
    assert "--verify exhaustive" in limit[0]


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
    original_tail = IMAGE.open("rb").read()[-512:]
    assert wiped["data"][-512:] != original_tail


def test_the_carver_finds_nothing_in_the_wiped_image(wiped):
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
    covered = sorted((p["first_sector"], p["sector_count"]) for p in progress)
    cursor = 0
    for first, count in covered:
        assert first == cursor, "telemetry gap or overlap at sector %d" % cursor
        cursor += count
    assert cursor == header["total_sectors"]


@pytest.fixture(scope="module")
def sacrificial(tmp_path_factory) -> Path:
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


def test_no_command_this_file_issues_ever_names_the_repository():
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
