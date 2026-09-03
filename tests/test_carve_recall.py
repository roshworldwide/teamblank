"""Recall and false-positive rate of the carver against the planted fixture manifest.

Two properties live here.  Both are measured through shipped code.

THE MARGIN.  The carving engine admits a candidate at ``confidence::MIN_CONFIDENCE``.
What protects that gate is not the gap between the planted and residue populations --
that is a distance nothing enforces.  It is the structural credit a decoy would need
in order to clear the gate on its own, given that a decoy already scores full marks
on signature, entropy and size.  These tests assert the gate the Rust code actually
enforces, by running its CI measurement rather than restating its numbers.

RECALL (re-measured 2026-09-03, through the shipped ``carve`` binary, after
``bifragment.rs`` was wired into the pipeline behind ``--reassemble``).  DEMONSTRATED
RECALL is what a run measurably recovered, joined to the manifest BY SHA-256 -- never
by row count, because this run still admits three records whose bytes are not the
planted bytes and only the digest sees the difference.

There are now two runs and they are two measurements, never averaged and never
conflated:

  DEFAULT (reassembly OFF)   demonstrated recall (contiguous engine)  28 of 40
  --reassemble               demonstrated recall (contiguous engine
                             + two-fragment reassembly)               30 of 40

Reassembly is OFF by default in the shipped binary.  That is a deliberate state and
it is asserted here as one, not merely observed: the default run must reassemble
nothing, and it must still recover its published 28.

The reachability CEILING of 33 of 40 and either demonstrated recall figure are
different numbers.  They live in different fields, they are printed on different
lines, and ``test_the_two_numbers_are_never_in_one_sentence`` enforces that they are
never rendered as one -- in stderr, in the report notes, or in the recall block.

When the binary is absent these tests SKIP, loudly, with the reason naming the
missing path -- never silently.  Set SENTINELWIPE_REQUIRE_CARVER=1 to turn the
absence into a failure, which is what CI should do.

COST.  The reassembling runs are slow by construction: 59 of 63 searches walk a whole
split-point x gap-length lattice and return nothing.  Two of them are run here (one
with the manifest, one blind) at roughly 63 s each, and that is the price of measuring
a search rather than trusting it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "out"
IMAGE = OUT / "fixture.img"
MANIFEST = OUT / "fixture.manifest.json"
#: Cargo appends `.exe` on Windows; without this the binary is never found
#: there and every measurement in this file skips for a reason that is not true.
_EXE = ".exe" if os.name == "nt" else ""
CARVE_BIN = REPO / "core" / "target" / "release" / ("carve" + _EXE)

# The four weights and the gate, as published in docs/architecture.md D2 and
# exported from core/carve/src/confidence.rs.  Duplicated here deliberately: if
# these drift from the Rust constants, test_the_rust_gate_matches_this_file
# fails, which is the point.
W_SIGNATURE, W_STRUCTURE, W_ENTROPY, W_SIZE = 0.40, 0.35, 0.15, 0.10
MIN_CONFIDENCE = 0.75
NON_STRUCTURE_CEILING = W_SIGNATURE + W_ENTROPY + W_SIZE          # 0.65
STRUCTURAL_BREACH_POINT = (MIN_CONFIDENCE - NON_STRUCTURE_CEILING) / W_STRUCTURE

# ---------------------------------------------------------------------------
# The five files the manifest tags `bifragment`, one at a time.
#
# MEASURED 2026-09-03 through `carve --reassemble --cluster-bytes 2048
# --max-gap-clusters 128` against out/fixture.img.  Recorded here per file and
# asserted per file, because "2 of 5" is a score and this is a finding.  The gap
# in each reason is re-derived from the manifest at run time and asserted against
# the number written here, so no figure below is a claim the fixture does not back.
#
# RECOVERED is measured.  REASON, for a file not recovered, is what the search
# reported: `carve` prints solved/ambiguous/exhausted/refused-contiguous counts on
# stderr and those aggregates are asserted; the per-file attribution comes from
# core/carve/src/bifragment.rs's own per-plant measurement and is labelled as
# such, never as something this file measured.
# ---------------------------------------------------------------------------
BIFRAGMENT_OUTCOME = {
    "/entropy_heatmap.png": (
        True, 1,
        "gap 1 cluster. Solved: one splice validated and was pinned in both "
        "dimensions. PNG carries a CRC over every chunk, so a wrong join cannot "
        "validate."),
    "/imaging_transcript.txt.gz": (
        True, 16,
        "gap 16 clusters. Solved: DEFLATE plus the trailing CRC-32 and ISIZE pin "
        "the join."),
    "/disposal_certificate.pdf": (
        False, 128,
        "gap 128 clusters, exactly on the INCLUSIVE bound, so it is inside the "
        "searched lattice and was searched. AMBIGUOUS: splices validated and none "
        "was pinned in both dimensions, which is a refusal and never a guess. "
        "structure/pdf.rs never decodes a stream body, so several joins parse."),
    "/sealing_procedure.mov": (
        False, 50,
        "gap 50 clusters, interleaved with handover_briefing.mov. AMBIGUOUS: "
        "QuickTime carries no checksum over sample data, so many joins parse and "
        "none is pinned."),
    "/handover_briefing.mov": (
        False, 70,
        "gap 70 clusters. NEVER SEARCHED: its contiguous read validates, so the "
        "precondition refuses it before a search is entered. Sequential carving "
        "owns it and emits a record of its exact planted length with a wrong "
        "digest -- see MP4@65943552 in the table."),
}

# The two files the fixture fragments in shapes this algorithm cannot solve.
BY_DESIGN = ["/media_inventory.docx", "/evidence_bag_seal.jpg"]

# The run's one genuine false positive.  Named here so that a change in it is a
# change to this file and not a silent drift.
GENUINE_FALSE_POSITIVE = "ZIP@1228603"


def _require_fixture():
    if not (IMAGE.exists() and MANIFEST.exists()):
        pytest.fail(
            "NOT VERIFIED -- the fixture is absent, so nothing here was measured.\n"
            "  expected %s and %s\n  run: make fixtures" % (IMAGE, MANIFEST))


def manifest() -> dict:
    _require_fixture()
    return json.loads(MANIFEST.read_bytes())


def _cargo_measure() -> str:
    """Run the Rust residue-separation measurement and return its output.

    This is the enforcing check.  Parsing its printed table rather than
    recomputing it here keeps one implementation of the measurement.
    """
    if shutil.which("cargo") is None:
        pytest.fail("NOT VERIFIED -- cargo is absent, so the margin was not measured.")
    proc = subprocess.run(
        ["cargo", "test", "--release", "-p", "sentinelwipe-carve",
         "--test", "residue_separation", "--", "--nocapture"],
        cwd=REPO / "core", capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        pytest.fail("the Rust residue-separation measurement FAILED:\n" + out[-4000:])
    return out


def _num(pattern: str, text: str) -> float:
    m = re.search(pattern, text)
    assert m, "could not find %r in the measurement output" % pattern
    return float(m.group(1))


# --------------------------------------------------------------------------
# The counted set: what the fixture claims is reachable at all
# --------------------------------------------------------------------------

def test_the_counted_set_excludes_what_has_no_signature():
    """40 planted, 33 reachable, 7 unreachable by construction.

    Five are plaintext, which carries no magic bytes; two are fragmented in
    shapes a bifragment search cannot solve.  A fixture containing only cases we
    pass would not be evidence.
    """
    m = manifest()
    cs = m["counted_set"]
    assert cs["total"] == 40
    assert cs["expected_recoverable"] == 33
    assert cs["unrecoverable_by_design"] == 7

    unrec = [f for f in m["files"]
             if f["expected_recoverable"] == "unrecoverable-by-design"]
    assert len(unrec) == 7
    txt = sorted(f["path"] for f in unrec if f["kind"].upper() == "TXT")
    assert len(txt) == 5, "expected 5 plaintext files unreachable by signature, got %r" % txt
    other = sorted(f["path"] for f in unrec if f["kind"].upper() != "TXT")
    assert other == sorted(BY_DESIGN), other


def test_no_txt_file_is_labelled_recoverable():
    """Plain text has no signature.  Labelling it recoverable would overstate the engine.

    Our corpus text opens with an ASCII banner and keying on it would lift recall
    to 38.  That is refused: a carver tuned to a marker we planted ourselves
    measures nothing.  See docs/ai-log/entries/2026-09-03.md.
    """
    for f in manifest()["files"]:
        if f["kind"].upper() == "TXT":
            assert f["expected_recoverable"] == "unrecoverable-by-design", f["path"]


def test_recall_thresholds_are_defined_over_the_reachable_set():
    """>=95% unfragmented and >=60% fragmented, measured over what is reachable.

    Measured over all 40 the thresholds are unreachable by construction: 33 of 40
    is 82.5%, below the 95% bar, without the carver being at fault.

    Both bars are now MEASURED, because the code that has to earn them has been
    run.  The unfragmented bar is met in ``test_recall_over_the_reachable_set``.
    The fragmented bar is not, and ``test_the_five_fragmented_files_one_at_a_time``
    reports the shortfall per file rather than averaging it away.
    """
    m = manifest()
    reach = [f for f in m["files"]
             if f["expected_recoverable"] != "unrecoverable-by-design"]
    unfrag = [f for f in reach if not f["fragmented"]]
    frag = [f for f in reach if f["fragmented"]]
    assert len(unfrag) == 28, len(unfrag)
    assert len(frag) == 5, len(frag)
    assert len(reach) == 33
    # the bars those sets imply
    assert -(-len(unfrag) * 95 // 100) == 27
    assert -(-len(frag) * 60 // 100) == 3

    # The per-file table in this module covers the fragmented reachable set exactly.
    assert sorted(BIFRAGMENT_OUTCOME) == sorted(f["path"] for f in frag)


# --------------------------------------------------------------------------
# The margin, measured through shipped Rust
# --------------------------------------------------------------------------

def test_the_rust_gate_matches_this_file():
    """The gate constant here must equal the one confidence.rs exports.

    If they drift, every margin number in this file is asserting a threshold the
    engine does not enforce -- a green run that has measured the wrong property.
    """
    src = (REPO / "core" / "carve" / "src" / "confidence.rs").read_text()
    m = re.search(r"pub const MIN_CONFIDENCE:\s*f64\s*=\s*([0-9.]+)", src)
    assert m, "confidence.rs no longer exports MIN_CONFIDENCE"
    assert float(m.group(1)) == MIN_CONFIDENCE


def test_the_structural_breach_point_is_where_the_arithmetic_puts_it():
    assert abs(STRUCTURAL_BREACH_POINT - 0.2857142857142857) < 1e-12
    assert abs(W_SIGNATURE + W_STRUCTURE + W_ENTROPY + W_SIZE - 1.0) < 1e-12


def test_residue_never_reaches_the_admission_gate():
    """The enforcing measurement, run through shipped structure.rs and confidence.rs.

    Asserts the margin that binds -- structural credit against the breach point --
    not the population gap, which describes a distance nothing enforces.
    """
    _require_fixture()
    out = _cargo_measure()

    highest_fp = _num(r"highest false positive\s+([0-9.]+)", out)
    lowest_tp = _num(r"lowest true positive\s+([0-9.]+)", out)
    worst_structure = _num(r"worst residue structure\s+([0-9.]+)", out)
    headroom = _num(r"MEASURED HEADROOM\s+([0-9.]+)", out)
    gate = _num(r"admission gate\s+MIN_CONFIDENCE\s+([0-9.]+)", out)
    assert gate == MIN_CONFIDENCE, (
        "the measurement enforces a %.4f gate; this file asserts %.4f" % (gate, MIN_CONFIDENCE))

    assert highest_fp < MIN_CONFIDENCE, (
        "a residue decoy reached the admission gate: %.4f >= %.4f" % (highest_fp, MIN_CONFIDENCE))
    assert lowest_tp >= MIN_CONFIDENCE, (
        "a planted file fell below the gate: %.4f < %.4f" % (lowest_tp, MIN_CONFIDENCE))
    assert worst_structure < STRUCTURAL_BREACH_POINT, (
        "residue structural credit %.4f has reached the breach point %.6f -- decoys are "
        "one step from being admitted as evidence" % (worst_structure, STRUCTURAL_BREACH_POINT))
    assert abs(headroom - (STRUCTURAL_BREACH_POINT - worst_structure)) < 5e-4


# --------------------------------------------------------------------------
# Recall -- measured, through the shipped carve binary
# --------------------------------------------------------------------------

def _require_carver():
    if CARVE_BIN.exists():
        return
    msg = ("the carve binary does not exist yet (%s); recall is NOT measured. "
           "Set SENTINELWIPE_REQUIRE_CARVER=1 to make this a failure." % CARVE_BIN)
    if os.environ.get("SENTINELWIPE_REQUIRE_CARVER") == "1":
        pytest.fail("NOT VERIFIED -- " + msg)
    pytest.skip(msg)


_CARVE_RUNS: dict = {}


def carve(*args: str):
    """Run the shipped binary once per distinct argument list and cache the report.

    Returns ``(report, exit_code, stderr)``.  Exit 0 means something was admitted
    and 1 means a clean run that admitted nothing; both are runs that happened and
    both carry a complete report.  2, 3 and 4 mean the run did not happen, and
    those are failures here rather than an empty result quietly read as zero recall.

    A reassembling run costs roughly 63 s, so the cache is what keeps this module
    to two of them rather than one per test.
    """
    _require_fixture()
    _require_carver()
    if args in _CARVE_RUNS:
        return _CARVE_RUNS[args]
    proc = subprocess.run(
        [str(CARVE_BIN), *args, str(IMAGE.relative_to(REPO))],
        cwd=REPO, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        pytest.fail("the carve run did not happen: exit %d\nargs: %r\nstderr:\n%s"
                    % (proc.returncode, args, proc.stderr[-4000:]))
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail("carve exited %d but stdout is not one JSON document: %s\n"
                    "first 400 bytes: %r" % (proc.returncode, exc, proc.stdout[:400]))
    _CARVE_RUNS[args] = (report, proc.returncode, proc.stderr)
    return _CARVE_RUNS[args]


def _manifest_arg() -> str:
    return str(MANIFEST.relative_to(REPO))


def reassembly_flags() -> tuple:
    """The reassembly geometry, taken from the fixture manifest rather than typed here.

    The medium's cluster size and the gap bound are OPERATOR parameters: the engine
    does not read the manifest for them and never sees ground truth before it
    carves.  Deriving them here from ``bytes_per_cluster`` and ``max_gap_clusters``
    keeps this file from hardcoding a geometry the fixture could change underneath.
    """
    m = manifest()
    return ("--reassemble",
            "--cluster-bytes", str(m["bytes_per_cluster"]),
            "--max-gap-clusters", str(m["max_gap_clusters"]))


def the_run():
    """THE measured run: the whole image, reassembly ON, scored by SHA-256."""
    return carve("--phase", "pre-wipe", "--manifest", _manifest_arg(), *reassembly_flags())


def the_default_run():
    """The shipped default: no reassembly flag at all, so reassembly is OFF."""
    return carve("--phase", "pre-wipe", "--manifest", _manifest_arg())


# --- the join, done here rather than trusted from the report ---------------

def planted_by_digest(m: dict) -> dict:
    """digest -> planted path.  A digest join needs no name, offset or size."""
    by = {f["sha256"]: f["path"] for f in m["files"]}
    assert len(by) == len(m["files"]), (
        "two planted files share a SHA-256; a digest join cannot be trusted on this fixture")
    return by


def recovered_paths(report: dict, m: dict) -> dict:
    """Planted path -> the ADMITTED record that recovered it, byte for byte.

    Computed here from digests alone.  The carver publishes its own
    ``ground_truth`` block and this deliberately does not read it: a recall
    figure the engine scores for itself is not a measurement of the engine.

    A reassembled record joins here on exactly the same terms as a contiguous
    one.  Nothing in this function knows how many extents a record has.
    """
    by = planted_by_digest(m)
    out = {}
    for rec in report["candidates"]:
        if not rec["admitted"]:
            continue
        path = by.get(rec["sha256"])
        if path is not None:
            assert path not in out, "two admitted records both recovered %s" % path
            out[path] = rec
    return out


def digest_of_extents(rec: dict) -> str:
    """Re-hash the image bytes the record's own extents name, in logical order.

    This is the check that the ``sha256`` field is a digest of real bytes at real
    offsets and not a value the report carries about itself.  For a reassembled
    record it is also the check that the two fragments concatenate to the file:
    the gap between them is skipped, and the digest is over the join.
    """
    h = hashlib.sha256()
    with IMAGE.open("rb") as fh:
        for ext in rec["extents"]:
            fh.seek(ext["offset"])
            block = fh.read(ext["length"])
            assert len(block) == ext["length"], (
                "%s names %d bytes at %d and the image ended first"
                % (rec["id"], ext["length"], ext["offset"]))
            h.update(block)
    return h.hexdigest()


def unjoined_records(report: dict) -> list:
    """Records the run could not join to any planted file.

    The engine annotates a record with ``ground_truth`` when its digest matches a
    planted file, and failing that when its offset is a planted file's FIRST extent
    offset and the kind agrees.  ``ground_truth is None`` therefore means neither
    join landed.

    That is deliberately WIDER than "free-space decoy": a header lying inside a
    planted file's second or third fragment is unjoined too, and ZIP@1228603 is
    exactly such a header -- it sits inside media_inventory.docx's third extent.
    Wider is the safe direction. This is the population whose structural ceiling
    the admission margin has to hold against, and over-counting it can only make
    that ceiling harder to clear, never easier.
    """
    return [r for r in report["candidates"] if r.get("ground_truth") is None]


# --- stderr, which is where the cost of a search is published --------------

def reassembly_stats(stderr: str) -> dict:
    """Parse the reassembly counters the binary prints.

    docs/output_schema.md is frozen and carries no field for a validation count,
    so the cost is on stderr and is read from there.  Absence of these lines in a
    reassembling run is a failure, not a zero.
    """
    m = re.search(
        r"reassembly attempted (\d+) search\(es\): solved (\d+), ambiguous (\d+), "
        r"exhausted (\d+), degenerate (\d+), refused-contiguous (\d+), budget (\d+)",
        stderr)
    assert m, ("the reassembling run did not report its search outcomes on stderr; "
               "a cost that is not printed is a cost that is not measured:\n" + stderr[-2000:])
    c = re.search(
        r"reassembly cost (\d+) structure validations, (\d+) splice\(s\) accepted by the "
        r"validator, (\d+) of them determined and returned", stderr)
    assert c, "the reassembling run did not report its validation cost:\n" + stderr[-2000:]
    g = re.search(
        r"reassembly ON\s+cluster (\d+) bytes\s+max gap (\d+) clusters \((\d+) bytes, inclusive\)",
        stderr)
    assert g, "the reassembling run did not report its geometry:\n" + stderr[-2000:]
    per = {mm.group(1): (int(mm.group(2)), mm.group(3))
           for mm in re.finditer(
               r"carve:\s+(\S+) reassembled in (\d+) validations\s+extents \[([^\]]+)\]", stderr)}
    return {
        "attempted": int(m.group(1)), "solved": int(m.group(2)),
        "ambiguous": int(m.group(3)), "exhausted": int(m.group(4)),
        "degenerate": int(m.group(5)), "refused_contiguous": int(m.group(6)),
        "budget": int(m.group(7)),
        "validations": int(c.group(1)), "accepted_splices": int(c.group(2)),
        "determined": int(c.group(3)),
        "cluster_bytes": int(g.group(1)), "max_gap_clusters": int(g.group(2)),
        "max_gap_bytes": int(g.group(3)),
        "per_object": per,
    }


# --- the demo artifact -----------------------------------------------------

_COLS = "  %-6s %11s %9s %-12s  %-8s%-8s%-8s%-8s %-8s %-3s %-12s  %s"
_HEAD = _COLS % ("KIND", "OFFSET", "BYTES", "ASSEMBLY", "SIG", "STRUCT", "ENTROPY", "SIZE",
                 "TOTAL", "ADM", "SHA256", "PLANTED FILE  (SHA-256 join)")
_RULE = "  " + "-" * 130


def _row(rec: dict, label: str) -> str:
    c = rec["confidence"]
    line = _COLS % (
        rec["kind"], rec["offset"], rec["length"], rec["assembly"],
        "%.4f" % c["signature_integrity"], "%.4f" % c["structural_validity"],
        "%.4f" % c["entropy_consistency"], "%.4f" % c["size_plausibility"],
        "%.4f" % c["total"],
        "yes" if rec["admitted"] else "no",
        rec["sha256"][:12], label)
    if len(rec["extents"]) > 1:
        line += ("\n" + " " * 10 + "extents  "
                 + "  ".join("%d+%d" % (e["offset"], e["length"]) for e in rec["extents"]))
    return line


def _emit(lines, capsys):
    text = "\n".join(lines)
    with capsys.disabled():
        print("\n" + text + "\n")


# --------------------------------------------------------------------------
# The default is OFF, and that is a state, not an accident
# --------------------------------------------------------------------------

def test_reassembly_is_off_by_default_and_the_default_run_still_recovers_28(capsys):
    """With no reassembly flag the engine is the contiguous engine, unchanged.

    This REPLACES the previous module's blanket assertion that no record is ever
    reassembled.  That assertion was correct when bifragment.rs was not called at
    all; it is now the assertion for ONE run -- the default one -- and it is made
    stronger here by also pinning what the default run recovers and by proving that
    the bare default and an explicit ``--no-reassemble`` produce the same records.

    28 of 40 is the number that was published for the contiguous engine.  If
    wiring reassembly in behind a flag had moved it, the flag would not be a flag.
    """
    m = manifest()
    report, exit_code, stderr = the_default_run()
    assert exit_code == 0

    assert report["counts"]["by_assembly"]["reassembled"] == 0, (
        "the DEFAULT run reassembled a record. Reassembly is opt-in; a default that "
        "reassembles silently changes every number published for the contiguous engine.")
    for rec in report["candidates"]:
        assert len(rec["extents"]) == 1, (
            "%s carries %d extents in the default run" % (rec["id"], len(rec["extents"])))

    assert "reassembly attempted" not in stderr, (
        "the default run reported search outcomes; zero attempts and zero results "
        "are different statements and the default made zero ATTEMPTS")
    assert "reassembly off" in stderr.lower(), (
        "the default run does not say on stderr that reassembly was off:\n" + stderr[-1500:])

    got = recovered_paths(report, m)
    contiguous = sorted(f["path"] for f in m["files"]
                        if f["expected_recoverable"] == "signature-only")
    assert sorted(got) == contiguous, sorted(got)
    assert len(got) == 28, len(got)
    assert report["counts"]["sha256_matches_planted"] == 28

    for path in BIFRAGMENT_OUTCOME:
        assert path not in got, (
            "%s was recovered by the DEFAULT run, which does not reassemble" % path)

    assert "demonstrated recall (contiguous engine)" in stderr.lower()
    assert "two-fragment reassembly" not in stderr.lower().split("demonstrated recall")[1][:200]

    # The bare default and the explicit spelling are the same run.
    explicit, _, _ = carve("--phase", "pre-wipe", "--manifest", _manifest_arg(),
                           "--no-reassemble")
    assert explicit["candidates"] == report["candidates"], (
        "--no-reassemble produced different records than the bare default; the "
        "default is then not spellable and the demo cannot state it")

    _emit(["=" * 112,
           "DEFAULT RUN (reassembly OFF)  %s" % report["provenance"]["command"],
           "  demonstrated recall (contiguous engine)   %d of %d, byte-exact, joined on SHA-256"
           % (len(got), m["counted_set"]["total"]),
           "  records reassembled                        %d   (zero ATTEMPTS, not zero results)"
           % report["counts"]["by_assembly"]["reassembled"],
           "=" * 112], capsys)


# --------------------------------------------------------------------------

def test_recall_over_the_reachable_set(capsys):
    """Demonstrated recall with two-fragment reassembly ON, joined by SHA-256.

    The set the engine can reach is now the 28 planted files the manifest marks
    ``signature-only`` PLUS whatever of the 5 marked ``bifragment`` a forward,
    two-fragment, cluster-quantised search can actually solve.  Both halves are
    asserted BY DIGEST, one path at a time; the 7 unreachable by construction are
    asserted absent.

    A row count is not a recall figure.  This run admits 33 records and three of
    them carry bytes that are not any planted file's bytes -- one is a genuine
    false positive and two sit at a planted file's offset.  Only the digest sees it.

    The reachability ceiling and this number are two fields, printed on two lines.
    """
    m = manifest()
    report, exit_code, stderr = the_run()

    assert report["schema"] == "sentinelwipe.carve.report/1", report["schema"]
    assert exit_code == 0, "the carve admitted nothing (exit %d)" % exit_code
    assert report["provenance"]["is_carve_run"] is True, (
        "this report is not a carve run, so nothing in it is recall")
    assert report["run"]["image_sha256"] == m["image_sha256"], (
        "the carver read a different image than the manifest describes")

    gate = report["policy"]["min_confidence"]
    assert gate == MIN_CONFIDENCE, (
        "the run scored against a %.4f gate; this file asserts %.4f" % (gate, MIN_CONFIDENCE))

    records = report["candidates"]

    # Every record's arithmetic and geometry, before any of it is counted as evidence.
    for rec in records:
        c = rec["confidence"]
        w = c["weighted"]
        assert abs(sum(w.values()) - c["total"]) < 1e-9, rec["id"]
        assert rec["admitted"] == (c["total"] >= gate), (
            "%s: admitted=%s but total %.6f against gate %.6f"
            % (rec["id"], rec["admitted"], c["total"], gate))
        assert digest_of_extents(rec) == rec["sha256"], (
            "%s: the sha256 field is not the digest of the bytes its extents name"
            % rec["id"])
        assert sum(e["length"] for e in rec["extents"]) == rec["length"], (
            "%s: length %d is not the sum of its extents" % (rec["id"], rec["length"]))
        assert rec["extents"][0]["offset"] == rec["offset"], rec["id"]
        assert (rec["assembly"] == "reassembled") == (len(rec["extents"]) > 1), (
            "%s: assembly %r against %d extents -- the label and the shape disagree"
            % (rec["id"], rec["assembly"], len(rec["extents"])))

    # The reassembled records, on the geometry the operator supplied.
    stats = reassembly_stats(stderr)
    assert stats["cluster_bytes"] == m["bytes_per_cluster"]
    assert stats["max_gap_clusters"] == m["max_gap_clusters"]
    assert m["max_gap_is_inclusive"] is True
    assert stats["max_gap_bytes"] == m["bytes_per_cluster"] * m["max_gap_clusters"]

    reassembled = [r for r in records if r["assembly"] == "reassembled"]
    assert len(reassembled) == report["counts"]["by_assembly"]["reassembled"]
    assert len(reassembled) == stats["solved"] == stats["determined"], (
        "%d records claim reassembly but the search reported %d solved"
        % (len(reassembled), stats["solved"]))
    cl = m["bytes_per_cluster"]
    for rec in reassembled:
        assert len(rec["extents"]) == 2, (
            "%s joins %d fragments; this search joins at most 2"
            % (rec["id"], len(rec["extents"])))
        a, b = rec["extents"]
        gap = b["offset"] - (a["offset"] + a["length"])
        assert gap > 0, "%s: the second extent does not lie after the first" % rec["id"]
        assert a["offset"] % cl == 0 and b["offset"] % cl == 0, (
            "%s: an extent does not start on the %d-byte cluster grid" % (rec["id"], cl))
        assert a["length"] % cl == 0, (
            "%s: the leading fragment is not a whole number of clusters" % rec["id"])
        assert gap % cl == 0, "%s: the gap is not a whole number of clusters" % rec["id"]
        assert gap // cl <= m["max_gap_clusters"], (
            "%s: gap %d clusters exceeds the bound of %d"
            % (rec["id"], gap // cl, m["max_gap_clusters"]))
        assert rec["id"] in stats["per_object"], (
            "%s was reassembled and the run did not publish what its search cost"
            % rec["id"])

    # The three ground-truth sets, read off the manifest, never hardcoded.
    contiguous = sorted(f["path"] for f in m["files"]
                        if f["expected_recoverable"] == "signature-only")
    needs_bifragment = sorted(f["path"] for f in m["files"]
                              if f["expected_recoverable"] == "bifragment")
    unreachable = sorted(f["path"] for f in m["files"]
                         if f["expected_recoverable"] == "unrecoverable-by-design")
    assert (len(contiguous), len(needs_bifragment), len(unreachable)) == (28, 5, 7)
    assert len(contiguous) + len(needs_bifragment) + len(unreachable) == m["counted_set"]["total"]

    got = recovered_paths(report, m)
    by_digest = planted_by_digest(m)

    # ---- the table ----
    matched, admitted_unmatched, rejected = [], [], []
    for rec in sorted(records, key=lambda r: r["offset"]):
        path = by_digest.get(rec["sha256"])
        if rec["admitted"] and path:
            matched.append(_row(rec, path))
        elif rec["admitted"]:
            gt = rec["ground_truth"]
            note = ("%s  <-- NOT this file's bytes" % gt["path"]) if gt else "(no planted match)"
            admitted_unmatched.append(_row(rec, note))
        else:
            gt = rec["ground_truth"]
            rejected.append(_row(rec, gt["path"] if gt else "(residue)"))

    lines = ["=" * 130,
             "CARVE RUN  %s" % report["provenance"]["command"],
             "  image %s  %d bytes  sha256 %s"
             % (report["run"]["image_path"], report["run"]["image_bytes"],
                report["run"]["image_sha256"][:16]),
             "  formula   %s" % report["policy"]["formula"],
             "  gate      MIN_CONFIDENCE %.4f   admitted = total >= gate, one comparison"
             % gate,
             "  geometry  cluster %d bytes   max gap %d clusters (%d bytes, inclusive)"
             % (stats["cluster_bytes"], stats["max_gap_clusters"], stats["max_gap_bytes"]),
             "=" * 130, "",
             "ADMITTED AND BYTE-EXACT -- %d records, joined to the manifest by SHA-256" % len(matched),
             _HEAD, _RULE] + matched
    if admitted_unmatched:
        lines += ["",
                  "ADMITTED, NOT A RECOVERY -- %d records. Scored over the gate; the bytes are"
                  % len(admitted_unmatched),
                  "  not a planted file's bytes. Counting rows instead of digests is how this hides.",
                  _HEAD, _RULE] + admitted_unmatched
    lines += ["",
              "REJECTED -- %d records, below the gate" % len(rejected),
              _HEAD, _RULE] + rejected

    reach = report["ground_truth"]["reachability"]
    lines += ["",
              "-" * 130,
              "DEMONSTRATED RECALL (contiguous engine + two-fragment reassembly)   %d of %d"
              % (len(got), m["counted_set"]["total"]),
              "                                          planted files, every one verified by",
              "                                          SHA-256 against the digest",
              "                                          fixtures/build_image.py recorded.",
              "                                          %d of them were joined from two extents."
              % len(reassembled),
              "",
              "REACHABILITY CEILING -- a different number, and never the same sentence as the above:",
              "  contiguous                    %2d   what a contiguous engine could reach at all"
              % reach["contiguous"],
              "  needs bifragment reassembly   %2d   searched this run; %d solved, %d refused"
              % (reach["needs_bifragment_reassembly"],
                 len([p for p in needs_bifragment if p in got]),
                 len([p for p in needs_bifragment if p not in got])),
              "  unreachable by construction   %2d   reachable by nothing this carver does"
              % reach["unreachable_by_construction"],
              "-" * 130,
              "",
              "WHAT THE SEARCH COST   %d search(es): solved %d, ambiguous %d, exhausted %d, "
              "degenerate %d, refused-contiguous %d, budget %d"
              % (stats["attempted"], stats["solved"], stats["ambiguous"], stats["exhausted"],
                 stats["degenerate"], stats["refused_contiguous"], stats["budget"]),
              "                       %d structure validations, %d splice(s) accepted by the "
              "validator, %d determined"
              % (stats["validations"], stats["accepted_splices"], stats["determined"])]
    for oid, (cost, ext) in sorted(stats["per_object"].items()):
        lines.append("                       %-16s %7d validations  extents [%s]" % (oid, cost, ext))
    lines += ["",
              "SCORE DISTRIBUTION   admitted n=%d  min %.4f  max %.4f  mean %.4f"
              % (report["score_distribution"]["admitted"]["n"],
                 report["score_distribution"]["admitted"]["min"],
                 report["score_distribution"]["admitted"]["max"],
                 report["score_distribution"]["admitted"]["mean"]),
              "                     rejected n=%d  min %.4f  max %.4f  mean %.4f"
              % (report["score_distribution"]["rejected"]["n"],
                 report["score_distribution"]["rejected"]["min"],
                 report["score_distribution"]["rejected"]["max"],
                 report["score_distribution"]["rejected"]["mean"]),
              "MARGIN THAT BINDS    structural_headroom %.6f = breach point %.6f - worst rejected %.6f"
              % (report["margin"]["structural_headroom"],
                 report["margin"]["structural_breach_point"],
                 report["margin"]["worst_rejected_structural_validity"]),
              "=" * 130]
    _emit(lines, capsys)

    # ---- the assertions ----
    missing = [p for p in contiguous if p not in got]
    assert not missing, (
        "%d of %d contiguous reachable files recovered. NOT RECOVERED: %s\n"
        "This is a finding about the engine. Do not lower the bar to meet it."
        % (len(contiguous) - len(missing), len(contiguous), missing))

    solved = sorted(p for p in needs_bifragment if p in got)
    expected_solved = sorted(p for p, (ok, _g, _r) in BIFRAGMENT_OUTCOME.items() if ok)
    assert solved == expected_solved, (
        "the fragmented set moved. recovered %s, this file records %s.\n"
        "Re-measure it per file in test_the_five_fragmented_files_one_at_a_time and "
        "republish the number; do not edit the expectation to match the run."
        % (solved, expected_solved))

    impossible = [p for p in unreachable if p in got]
    assert not impossible, (
        "%s is planted as unreachable by construction and was recovered anyway" % impossible)

    assert sorted(got) == sorted(contiguous + expected_solved), sorted(got)
    assert len(got) == 30, (
        "demonstrated recall is %d of %d; this file records 30 of 40" % (len(got), 40))

    # The engine's own arithmetic must agree with the join computed above.
    gt = report["ground_truth"]
    assert gt["recall_measured"] is True
    assert gt["demonstrated_recall"] is not None, gt["demonstrated_recall_note"]
    assert gt["demonstrated_recall"]["recovered"] == len(got), (
        "the report claims %d recovered; an independent digest join finds %d"
        % (gt["demonstrated_recall"]["recovered"], len(got)))
    assert gt["demonstrated_recall"]["of"] == m["counted_set"]["total"]
    assert report["counts"]["sha256_matches_planted"] == len(got)

    # Ceiling and result are two fields. A run must never publish the ceiling as
    # the result, and a reassembling engine must never exceed its own ceiling.
    ceiling = reach["contiguous"] + reach["needs_bifragment_reassembly"]
    assert ceiling == m["counted_set"]["expected_recoverable"] == 33
    assert gt["demonstrated_recall"]["recovered"] <= ceiling
    assert gt["demonstrated_recall"]["recovered"] != ceiling, (
        "the report publishes the 33-of-40 reachability ceiling as a recall figure")
    assert "demonstrated recall (contiguous engine + two-fragment reassembly)" in stderr.lower(), (
        "the operator-facing line does not label the number as demonstrated recall "
        "of the engine that produced it")

    # A record that recovered a planted file byte-exact and was then rejected is a
    # recall loss, so no such record may exist unnoticed.
    for rec in records:
        if not rec["admitted"] and rec["sha256"] in by_digest:
            pytest.fail("%s recovered %s byte-exact and was rejected at %.4f"
                        % (rec["id"], by_digest[rec["sha256"]], rec["confidence"]["total"]))


# --------------------------------------------------------------------------

def test_the_five_fragmented_files_one_at_a_time(capsys):
    """Each of the 5 files the manifest tags ``bifragment``: recovered, or why not.

    Two of five is 40% against a 60% bar.  The bar is NOT met and the shortfall is
    reported per file with its measured gap, rather than averaged into a
    percentage that hides which three failed.

    The gaps are re-derived from the manifest here, so the reason text next to each
    file carries a number the fixture backs.  The aggregate search outcomes --
    solved, ambiguous, exhausted, refused-contiguous -- are read off the run's own
    stderr and asserted; the per-file attribution of an ambiguous verdict comes from
    bifragment.rs's per-plant measurement and is labelled as its finding, not this
    file's.
    """
    m = manifest()
    report, _, stderr = the_run()
    stats = reassembly_stats(stderr)
    got = recovered_paths(report, m)
    by_path = {f["path"]: f for f in m["files"]}
    cl = m["bytes_per_cluster"]

    frag = sorted(f["path"] for f in m["files"]
                  if f["expected_recoverable"] == "bifragment")
    assert sorted(BIFRAGMENT_OUTCOME) == frag

    lines = ["=" * 130,
             "THE FIVE FILES THAT NEED TWO-FRAGMENT REASSEMBLY, ONE AT A TIME",
             "  cluster %d bytes   max gap %d clusters (%d bytes, INCLUSIVE)"
             % (cl, m["max_gap_clusters"], cl * m["max_gap_clusters"]), ""]

    rows = []
    for path in frag:
        f = by_path[path]
        ext = f["extents"]
        assert len(ext) == 2, "%s is tagged bifragment with %d extents" % (path, len(ext))
        gap_bytes = ext[1]["byte_offset"] - (ext[0]["byte_offset"] + ext[0]["byte_length"])
        assert gap_bytes % cl == 0, "%s: gap %d is not a whole number of clusters" % (path, gap_bytes)
        gap = gap_bytes // cl

        want_ok, want_gap, reason = BIFRAGMENT_OUTCOME[path]
        assert gap == want_gap, (
            "%s: the fixture's gap is %d clusters and this file records %d"
            % (path, gap, want_gap))
        assert reason.strip(), "%s has no stated reason" % path

        ok = path in got
        assert ok is want_ok, (
            "%s: recovered=%s and this file records %s. Re-measure and republish; "
            "do not edit the record to match the run." % (path, ok, want_ok))

        rec = got.get(path)
        rows.append((path, f, gap, ok, rec, reason))
        lines += ["  %-28s %-5s %7d bytes   gap %3d cluster(s) = %7d bytes   RECOVERED: %s"
                  % (path, f["kind"], f["size"], gap, gap_bytes, "YES" if ok else "no"),
                  "    planted extents   %s"
                  % "  ".join("%d+%d" % (e["byte_offset"], e["byte_length"]) for e in ext)]
        if ok:
            assert rec["assembly"] == "reassembled", (
                "%s was recovered but the record is not labelled reassembled" % path)
            assert [(e["offset"], e["length"]) for e in rec["extents"]] == \
                   [(e["byte_offset"], e["byte_length"]) for e in ext], (
                "%s: the record's extents are not the manifest's extents" % path)
            assert rec["length"] == f["size"]
            assert digest_of_extents(rec) == f["sha256"]
            cost, printed = stats["per_object"][rec["id"]]
            lines += ["    carved extents    %s"
                      % "  ".join("%d+%d" % (e["offset"], e["length"]) for e in rec["extents"]),
                      "    record            %s  confidence %.4f  struct %.4f  %d validations"
                      % (rec["id"], rec["confidence"]["total"],
                         rec["confidence"]["structural_validity"], cost),
                      "    REASON            %s" % reason]
        else:
            lines += ["    REASON NOT RECOVERED  %s" % reason]
        lines.append("")

    solved = [p for p, _f, _g, ok, _r, _rn in rows if ok]
    bar = -(-len(frag) * 60 // 100)
    lines += ["-" * 130,
              "  FRAGMENTED-SET RESULT   %d of %d recovered byte-exact = %.1f%%"
              % (len(solved), len(frag), 100.0 * len(solved) / len(frag)),
              "  BAR                     %d of %d = 60%%   --  NOT MET, short by %d file(s)"
              % (bar, len(frag), bar - len(solved)),
              "  The three that failed are named above with a reason each. The bar is not",
              "  lowered to meet the measurement and the measurement is not rounded to meet",
              "  the bar.",
              "-" * 130,
              "  SEARCH OUTCOMES  attempted %d: solved %d, ambiguous %d, exhausted %d, "
              "degenerate %d, refused-contiguous %d, budget %d"
              % (stats["attempted"], stats["solved"], stats["ambiguous"], stats["exhausted"],
                 stats["degenerate"], stats["refused_contiguous"], stats["budget"]),
              "  An AMBIGUOUS search is a REFUSAL: splices validated, none was pinned in both",
              "  dimensions, and the engine returned nothing rather than guessing between them.",
              "=" * 130]
    _emit(lines, capsys)

    assert len(solved) == 2, len(solved)
    assert len(solved) < bar, (
        "the fragmented set now meets its 60%% bar (%d of %d). That is a new result: "
        "re-measure it, update BIFRAGMENT_OUTCOME per file, and republish the recall "
        "figure. Do not leave this assertion inverted." % (len(solved), len(frag)))

    # The searches that failed, failed by refusing -- never by returning a wrong join.
    assert stats["solved"] == 2
    assert stats["degenerate"] == 0 and stats["budget"] == 0, stats
    assert stats["ambiguous"] + stats["exhausted"] + stats["solved"] == stats["attempted"], stats
    assert stats["accepted_splices"] > stats["determined"], (
        "no splice was accepted and then refused; an ambiguous verdict is the whole "
        "reason this engine can be trusted not to guess")

    # handover_briefing.mov: never searched, because its contiguous read validates.
    # That is measurable from the report: a contiguous record of exactly its planted
    # length, full structural credit, admitted, and the wrong digest.
    hb = by_path["/handover_briefing.mov"]
    lead = hb["extents"][0]["byte_offset"]
    at_lead = [r for r in report["candidates"] if r["offset"] == lead]
    assert len(at_lead) == 1, at_lead
    rec = at_lead[0]
    assert rec["assembly"] == "contiguous" and rec["admitted"] is True
    assert rec["length"] == hb["size"], (
        "the record at handover_briefing.mov's offset is not its planted length; the "
        "reason recorded for that file no longer holds")
    assert rec["confidence"]["structural_validity"] == 1.0
    assert rec["sha256"] != hb["sha256"], (
        "MP4@%d now hashes to handover_briefing.mov; re-measure the whole set" % lead)
    assert stats["refused_contiguous"] == 0, (
        "a search was entered and then refused as contiguous; the precondition is "
        "supposed to be applied before the search, so this costs probes for nothing")


# --------------------------------------------------------------------------
# The two planted to defeat this algorithm
# --------------------------------------------------------------------------

def records_carrying(records: list, digests: dict) -> list:
    """Every record whose bytes ARE one of these planted files, admitted or not.

    Factored out so that ``test_the_by_design_absence_check_can_fail`` can prove
    this detector fires.  An absence assertion nobody has seen fail is not
    evidence of absence.
    """
    return sorted((r["id"], digests[r["sha256"]], r["admitted"])
                  for r in records if r["sha256"] in digests)


def test_the_by_design_absence_check_can_fail():
    """The absence check above must be capable of failing. Prove it, do not assume it.

    A record carrying media_inventory.docx's digest is forged into a copy of the
    real record list.  The detector must find it.  Without this, every "not
    recovered" assertion in the next test is indistinguishable from a detector
    that returns the empty list unconditionally.
    """
    m = manifest()
    report, _, _ = the_run()
    by_path = {f["path"]: f for f in m["files"]}
    digests = {by_path[p]["sha256"]: p for p in BY_DESIGN}

    assert records_carrying(report["candidates"], digests) == [], (
        "precondition: the real run carries neither by-design file")

    forged = copy.deepcopy(report["candidates"][0])
    forged["id"] = "FORGED@0"
    forged["sha256"] = by_path["/media_inventory.docx"]["sha256"]
    forged["admitted"] = True
    hits = records_carrying(report["candidates"] + [forged], digests)
    assert hits == [("FORGED@0", "/media_inventory.docx", True)], hits

    # And the guard clause built on it must raise, not merely report.
    with pytest.raises(AssertionError):
        assert not records_carrying(report["candidates"] + [forged], digests)


def test_the_two_by_design_failures_are_not_recovered(capsys):
    """The fixture fragments two files to defeat this engine, and they still defeat it.

    ``media_inventory.docx`` is planted in three extents and ``evidence_bag_seal.jpg``
    in two stored out of physical order.  Reassembly is ON for this run and neither
    is recovered: a two-fragment search cannot solve a three-fragment object, and a
    forward-only search cannot reach a second fragment that lies at a LOWER offset
    than its first.  Absence is asserted by digest over EVERY record, admitted or
    rejected, and ``test_the_by_design_absence_check_can_fail`` proves that
    assertion can fail.

    The second half is the one that matters more, and it matters more now than it
    did before reassembly existed.  A carver that recognised any fragmented file by
    name would produce this same output, so the engine source is searched for the
    names, planted offsets, extent offsets and lengths, sizes and digests of ALL
    SEVEN fragmented files -- the two that were recovered included, because a
    recovery the engine was told the answer to is not a recovery.  The reassembling
    run is then repeated with no manifest at all, and must produce the same records
    field for field.
    """
    m = manifest()
    report, _, _ = the_run()

    by_path = {f["path"]: f for f in m["files"]}
    for p in BY_DESIGN:
        assert by_path[p]["expected_recoverable"] == "unrecoverable-by-design", p
        assert by_path[p]["fragmented"] is True, p
    assert len(by_path["/media_inventory.docx"]["extents"]) == 3
    seal = by_path["/evidence_bag_seal.jpg"]["extents"]
    assert seal[1]["byte_offset"] < seal[0]["byte_offset"], (
        "evidence_bag_seal.jpg is no longer stored out of physical order, so it no "
        "longer tests a forward-only search")

    got = recovered_paths(report, m)
    digests = {by_path[p]["sha256"]: p for p in BY_DESIGN}

    # 1. Absent from the recovery set, and absent from the report entirely by digest.
    for p in BY_DESIGN:
        assert p not in got, "%s was recovered, and it is planted to be unrecoverable" % p
    carried = records_carrying(report["candidates"], digests)
    assert not carried, (
        "a record carries the exact bytes of a by-design failure: %r -- the "
        "by-design failure did not fail" % carried)

    # 2. What the engine DID emit over those bytes, and why it is not a recovery.
    spans = {p: [(e["byte_offset"], e["byte_offset"] + e["byte_length"])
                 for e in by_path[p]["extents"]] for p in BY_DESIGN}
    touching = []
    for rec in sorted(report["candidates"], key=lambda r: r["offset"]):
        claimed = [(e["offset"], e["offset"] + e["length"]) for e in rec["extents"]]
        for p in BY_DESIGN:
            if any(lo < b and a < hi for a, b in spans[p] for lo, hi in claimed):
                assert rec["sha256"] != by_path[p]["sha256"]
                touching.append((p, rec))
                break

    lines = ["=" * 130,
             "BY-DESIGN FAILURES -- planted to defeat this engine, with reassembly ON", ""]
    for p in BY_DESIGN:
        f = by_path[p]
        lines += ["  %-24s %-5s %7d bytes  %d extents  sha256 %s"
                  % (p, f["kind"], f["size"], len(f["extents"]), f["sha256"][:12]),
                  "    extents  %s" % "  ".join("%d+%d" % (e["byte_offset"], e["byte_length"])
                                                for e in f["extents"]),
                  "    RECOVERED: no   (%s)"
                  % ("3 extents; this search joins at most 2"
                     if len(f["extents"]) > 2
                     else "extent[1] precedes extent[0]; this search is forward-only")]
    lines += ["", "  Records the engine emitted over those bytes -- none of them is the file:",
              _HEAD, _RULE]
    for p, rec in touching:
        lines.append(_row(rec, "%s  <-- NOT this file's bytes" % p))
    lines += ["", "  %d record(s) overlap; 0 hash to a by-design file." % len(touching),
              "=" * 130]
    _emit(lines, capsys)

    # 3. Nothing in the engine knows ANY fragmented file by name, offset, length
    #    or digest -- including the two it recovered.
    fragmented = [f["path"] for f in m["files"] if f["fragmented"]]
    assert len(fragmented) == 7, fragmented
    needles = _needles(m, fragmented)
    hits = _scan_engine(needles)
    assert not hits, (
        "the engine special-cases a fragmented file. These are executable, "
        "non-test, non-comment lines naming one of them:\n  " + "\n  ".join(hits))

    # 4. Ground truth never reaches the engine, search included: the same
    #    reassembling run with no manifest at all produces the same records, field
    #    for field, minus the annotation. This is the answer to "you wrote the
    #    fixture -- did you also tell it where the second fragment was?"
    blind, _, blind_err = carve("--phase", "pre-wipe", *reassembly_flags())
    assert blind["ground_truth"] is None
    strip = lambda cs: [{k: v for k, v in c.items() if k != "ground_truth"} for c in cs]
    assert strip(blind["candidates"]) == strip(report["candidates"]), (
        "the engine produced different records when handed the manifest; ground "
        "truth is reaching the scoring or the search path")
    blind_stats = reassembly_stats(blind_err)
    for k in ("attempted", "solved", "ambiguous", "exhausted", "validations",
              "accepted_splices", "determined"):
        assert blind_stats[k] == reassembly_stats(the_run()[2])[k], (
            "the search spent a different %s without the manifest: %d against %d"
            % (k, blind_stats[k], reassembly_stats(the_run()[2])[k]))


def _needles(m: dict, paths: list) -> dict:
    """needle -> the planted file it would betray."""
    by_path = {f["path"]: f for f in m["files"]}
    needles = {}
    for p in paths:
        f = by_path[p]
        needles[re.sub(r"\.[a-z0-9]+$", "", p.lstrip("/"))] = p
        needles[f["sha256"]] = p
        needles[f["sha256"][:16]] = p
        nums = {str(f["size"]), str(f["offset"])}
        for e in f["extents"]:
            nums.add(str(e["byte_offset"]))
            nums.add(str(e["byte_length"]))
        for n in nums:
            needles[n] = p
    return needles


def _scan_engine(needles: dict, roots=None) -> list:
    roots = roots or sorted((REPO / "core" / "carve" / "src").rglob("*.rs"))
    hits = []
    for src in roots:
        for lineno, code in _engine_lines(src):
            flat = code.replace("_", "")
            for needle, owner in needles.items():
                found = (needle in code if not needle.isdigit()
                         else re.search(r"(?<![0-9a-fA-F])%s(?![0-9a-fA-F])" % needle, flat))
                if found:
                    try:
                        name = src.relative_to(REPO)
                    except ValueError:
                        name = src
                    hits.append("%s:%d  %s  (%s)  %s"
                                % (name, lineno, needle, owner, code.strip()[:80]))
    return hits


def test_the_engine_source_scan_can_fail(tmp_path):
    """The special-casing scan must fire on a planted constant. Prove it.

    Three cases, because the scan has three ways to be vacuous: it must hit an
    offset written as a bare integer, hit one written with Rust digit separators,
    and NOT hit one that appears only in a comment or below ``#[cfg(test)]`` --
    a fixture path in a unit test is a test naming its own input, not the engine
    recognising a file.
    """
    m = manifest()
    seal = {f["path"]: f for f in m["files"]}["/evidence_bag_seal.jpg"]
    off = seal["extents"][1]["byte_offset"]
    needles = _needles(m, ["/evidence_bag_seal.jpg"])

    bare = tmp_path / "bare.rs"
    bare.write_text("fn f() -> u64 { %d }\n" % off)
    assert _scan_engine(needles, [bare]), "the scan missed a bare planted offset"

    sep = tmp_path / "sep.rs"
    sep.write_text("fn f() -> u64 { %s }\n" % "_".join(
        [str(off)[i:i + 3] for i in range(0, len(str(off)), 3)]))
    assert _scan_engine(needles, [sep]), (
        "the scan missed an offset written with Rust digit separators, which is how "
        "anyone would actually write it")

    quiet = tmp_path / "quiet.rs"
    quiet.write_text("// the second extent sits at %d\nfn f() {}\n#[cfg(test)]\n"
                     "mod t { const X: u64 = %d; }\n" % (off, off))
    assert not _scan_engine(needles, [quiet]), (
        "the scan fired on a comment or on test code; it would then be unfalsifiable "
        "in the other direction")


def _engine_lines(path: Path):
    """(lineno, code) for executable engine source only.

    Comments are stripped and everything from the file's ``#[cfg(test)]`` module to
    the end is dropped, because a fixture path in a unit test is a test naming its
    own input, not the engine recognising a file.
    """
    lines = path.read_text().splitlines()
    cut = len(lines)
    for i, line in enumerate(lines):
        if line.strip() == "#[cfg(test)]":
            cut = i
            break
    out, in_block = [], False
    for lineno, raw in enumerate(lines[:cut], 1):
        code = raw
        if in_block:
            if "*/" in code:
                code, in_block = code.split("*/", 1)[1], False
            else:
                continue
        while "/*" in code:
            head, rest = code.split("/*", 1)
            if "*/" in rest:
                code = head + rest.split("*/", 1)[1]
            else:
                code, in_block = head, True
                break
        code = re.sub(r"//.*$", "", code)
        if code.strip():
            out.append((lineno, code))
    return out


# --------------------------------------------------------------------------
# The risk reassembly introduces, measured rather than assumed
# --------------------------------------------------------------------------

def test_reassembly_did_not_enlarge_the_false_positive_surface(capsys):
    """A two-fragment search gives every decoy many more chances to validate.

    That is the risk this step had to answer, and it is answered by comparison
    rather than by argument: the two runs are diffed record by record.  If
    reassembly lifted any residue record's structural credit past
    STRUCTURAL_BREACH_POINT, decoys would start clearing the gate on structure
    alone and the whole confidence argument would go with them.

    core/carve/tests/residue_separation.rs is the CI guard for the population;
    this is the guard for the two runs of the shipped binary.
    """
    m = manifest()
    contig, _, _ = the_default_run()
    reasm, _, _ = the_run()

    ci = {r["offset"]: r for r in contig["candidates"]}
    ri = {r["offset"]: r for r in reasm["candidates"]}
    assert sorted(ci) == sorted(ri), (
        "reassembly changed which offsets produce a record; it is supposed to change "
        "how a record ends, never whether a header is found")
    assert contig["counts"]["records"] == reasm["counts"]["records"], (
        "reassembly added or removed a row. A solved search REPLACES the leading "
        "fragment's record; it never emits a second one beside it.")

    changed = sorted(o for o in ci if ci[o] != ri[o])
    reassembled = [r["id"] for r in reasm["candidates"] if r["assembly"] == "reassembled"]
    assert [ci[o]["id"] for o in changed] == sorted(reassembled, key=lambda i: ri_off(reasm, i)), (
        "records changed that were not reassembled: %s" % [ci[o]["id"] for o in changed])

    res_c = unjoined_records(contig)
    res_r = unjoined_records(reasm)
    assert len(res_c) == len(res_r), (len(res_c), len(res_r))
    ceil_c = max(r["confidence"]["structural_validity"] for r in res_c)
    ceil_r = max(r["confidence"]["structural_validity"] for r in res_r)
    adm_c = [r["id"] for r in res_c if r["admitted"]]
    adm_r = [r["id"] for r in res_r if r["admitted"]]

    lines = ["=" * 130,
             "DID REASSEMBLY ENLARGE THE FALSE-POSITIVE SURFACE?  Measured, not assumed.", "",
             "  records                          contiguous %3d   reassembled-run %3d"
             % (contig["counts"]["records"], reasm["counts"]["records"]),
             "  records that CHANGED at all      %d  -> %s"
             % (len(changed), [ci[o]["id"] for o in changed]),
             "  records joined to no planted file (the adversarial population)  %3d -> %3d"
             % (len(res_c), len(res_r)),
             "  their STRUCTURAL ceiling         %.6f -> %.6f    breach point %.6f"
             % (ceil_c, ceil_r, STRUCTURAL_BREACH_POINT),
             "  of them, ADMITTED                %s -> %s" % (adm_c, adm_r),
             ""]
    for key in ("lowest_admitted", "highest_rejected", "worst_rejected_structural_validity",
                "structural_breach_point", "structural_headroom"):
        lines.append("  margin.%-38s %.6f -> %.6f"
                     % (key, contig["margin"][key], reasm["margin"][key]))
    lines += ["", "=" * 130]
    _emit(lines, capsys)

    assert ceil_r == ceil_c, (
        "reassembly moved the unjoined population's structural ceiling from %.6f to "
        "%.6f. That is the number a decoy has to reach; it must not move because a "
        "search gave every header more chances to validate." % (ceil_c, ceil_r))
    assert contig["margin"] == reasm["margin"], (
        "the margin block moved:\n  contiguous %r\n  reassembled %r"
        % (contig["margin"], reasm["margin"]))
    assert adm_r == adm_c, (
        "reassembly admitted a different unjoined set: %s against %s" % (adm_r, adm_c))
    assert len(adm_r) == 1, (
        "%d records joined to no planted file are admitted; the run is supposed to "
        "carry exactly one false positive and name it" % len(adm_r))
    assert reasm["margin"]["worst_rejected_structural_validity"] < STRUCTURAL_BREACH_POINT, (
        "rejected residue structural credit %.6f has reached the breach point %.6f"
        % (reasm["margin"]["worst_rejected_structural_validity"], STRUCTURAL_BREACH_POINT))

    # Every record that did change, changed for the better and by reassembly.
    for o in changed:
        a, b = ci[o], ri[o]
        assert b["assembly"] == "reassembled" and a["assembly"] != "reassembled"
        assert b["confidence"]["total"] > a["confidence"]["total"]
        assert b["sha256"] in {f["sha256"] for f in m["files"]}, (
            "%s changed under reassembly and does not hash to a planted file" % b["id"])


def ri_off(report: dict, rec_id: str) -> int:
    return next(r["offset"] for r in report["candidates"] if r["id"] == rec_id)


def test_the_one_genuine_false_positive_is_still_reported_as_one(capsys):
    """ZIP@1228603 is a real false positive and reassembly neither fixed nor lifted it.

    It is the lowest admitted score in both runs.  Its bytes are not any planted
    file's bytes -- no digest match -- and it is not a leading fragment, so the
    engine joins it to nothing.  Stated precisely: it is a nested ZIP local-file
    header lying INSIDE media_inventory.docx's third extent, which is why the
    by-design table shows it overlapping that file while this test calls it a false
    positive.  Both are true, and the digest is what separates them.

    Its structural credit of 0.3000 sits ABOVE STRUCTURAL_BREACH_POINT, which is
    precisely why it clears the gate -- and it is the reason that breach point is
    the margin worth quoting.  It stays in the report.  A recovery engine that
    scores full marks on a fixture we wrote ourselves is the weakest claim in the
    deck.
    """
    m = manifest()
    by_digest = planted_by_digest(m)
    rows = {}
    for label, (report, _, _) in (("contiguous", the_default_run()),
                                  ("reassembled", the_run())):
        hit = [r for r in report["candidates"] if r["id"] == GENUINE_FALSE_POSITIVE]
        assert len(hit) == 1, (
            "%s is not in the %s run; if it has gone, that is a change to publish, "
            "not a silent improvement" % (GENUINE_FALSE_POSITIVE, label))
        rec = hit[0]
        rows[label] = rec

        assert rec["admitted"] is True, (
            "%s is no longer admitted in the %s run" % (GENUINE_FALSE_POSITIVE, label))
        assert rec["ground_truth"] is None, (
            "%s is now joined to a planted file; if the engine can name it, it is no "
            "longer an unattributed false positive and the wording has to change"
            % GENUINE_FALSE_POSITIVE)
        assert rec["sha256"] not in by_digest
        assert rec["assembly"] == "signature-span", rec["assembly"]
        assert len(rec["extents"]) == 1
        assert rec["confidence"]["total"] == report["margin"]["lowest_admitted"], (
            "%s is no longer the lowest admitted score in the %s run"
            % (GENUINE_FALSE_POSITIVE, label))

    a, b = rows["contiguous"], rows["reassembled"]
    _emit(["=" * 130,
           "THE ONE GENUINE FALSE POSITIVE -- reported, not removed", "",
           "  %-16s %-12s %-12s" % ("", "contiguous", "reassembled"),
           "  %-16s %-12.4f %-12.4f" % ("confidence", a["confidence"]["total"],
                                        b["confidence"]["total"]),
           "  %-16s %-12.6f %-12.6f" % ("structural", a["confidence"]["structural_validity"],
                                        b["confidence"]["structural_validity"]),
           "  %-16s %-12d %-12d" % ("length", a["length"], b["length"]),
           "  %-16s %-12s %-12s" % ("assembly", a["assembly"], b["assembly"]),
           "",
           "  Reassembly did NOT change its score: %.4f in both runs, structural %.6f in both."
           % (a["confidence"]["total"], a["confidence"]["structural_validity"]),
           "  It is the lowest admitted score in both runs and it stays in the report.",
           "  Its structural credit %.6f is above the breach point %.6f, which is what the"
           % (b["confidence"]["structural_validity"], STRUCTURAL_BREACH_POINT),
           "  %.6f headroom over the REJECTED population is protecting."
           % the_run()[0]["margin"]["structural_headroom"],
           "  It is a nested ZIP header inside media_inventory.docx's third extent: real",
           "  bytes, wrongly bounded, correctly scored, and honestly published.",
           "=" * 130], capsys)

    assert a["confidence"]["total"] == b["confidence"]["total"], (
        "reassembly moved the false positive's score from %.4f to %.4f"
        % (a["confidence"]["total"], b["confidence"]["total"]))
    assert a["confidence"] == b["confidence"], (a["confidence"], b["confidence"])
    assert a["length"] == b["length"] and a["sha256"] == b["sha256"]
    assert b["confidence"]["structural_validity"] > STRUCTURAL_BREACH_POINT, (
        "this record clears the gate on structural credit; if that is no longer true "
        "the explanation for why it is admitted has changed")


# --------------------------------------------------------------------------
# Claim discipline
# --------------------------------------------------------------------------

def _sentences(text: str) -> list:
    out = []
    for line in text.splitlines():
        for s in re.split(r"(?<=[.!?;])\s+", line.strip()):
            if s.strip():
                out.append(re.sub(r"\s+", " ", s.strip()))
    return out


def _recall_sentences(texts, recall: int, total: int):
    """(violations, how many sentences mentioned demonstrated recall at all)."""
    bad, seen = [], 0
    for label, text in texts:
        for s in _sentences(text):
            if "demonstrated recall" not in s.lower():
                continue
            seen += 1
            if "ceiling" in s.lower() or "reachab" in s.lower():
                bad.append((label, "names the ceiling in the same sentence", s))
            pairs = set(re.findall(r"(?<!\d)(\d+)\s+of\s+(\d+)(?!\d)", s))
            wrong = sorted(p for p in pairs if p != (str(recall), str(total)))
            if wrong:
                bad.append((label, "carries a second count %r" % (wrong,), s))
    return bad, seen


def test_the_two_numbers_are_never_in_one_sentence(capsys):
    """Demonstrated recall and the reachability ceiling are two sentences, always.

    Enforced over everything the run publishes in prose: stderr, the recall note,
    the recall method string and every provenance note.  A sentence that names
    demonstrated recall may carry exactly one "N of M", and it must be the recall
    figure -- not the ceiling, and not both.

    ``seen`` is asserted non-zero so this cannot pass by finding nothing to check.
    """
    lines = ["=" * 130, "CLAIM DISCIPLINE -- every sentence that names demonstrated recall", ""]
    total_seen = 0
    for label, (report, _, stderr), recall in (
            ("default", the_default_run(), 28),
            ("--reassemble", the_run(), 30)):
        gt = report["ground_truth"]
        texts = [("%s:stderr" % label, stderr),
                 ("%s:demonstrated_recall_note" % label, gt["demonstrated_recall_note"]),
                 ("%s:demonstrated_recall.method" % label, gt["demonstrated_recall"]["method"])]
        texts += [("%s:provenance.notes[%d]" % (label, i), n)
                  for i, n in enumerate(report["provenance"]["notes"])]
        bad, seen = _recall_sentences(texts, recall, 40)
        total_seen += seen
        assert seen >= 2, (
            "%s: only %d sentence(s) name demonstrated recall, so this check has "
            "almost nothing to enforce" % (label, seen))
        assert not bad, (
            "the two numbers appear in one sentence:\n  "
            + "\n  ".join("%s: %s\n    %s" % b for b in bad))
        for _lab, text in texts:
            for s in _sentences(text):
                if "demonstrated recall" in s.lower():
                    lines.append("  %-14s %s" % (label, s[:112]))
        # The ceiling is published, just not there.
        ceiling = (gt["reachability"]["contiguous"]
                   + gt["reachability"]["needs_bifragment_reassembly"])
        assert ceiling == 33
        assert gt["demonstrated_recall"]["recovered"] == recall
    lines += ["", "  %d sentence(s) checked across both runs; 0 carry both numbers." % total_seen,
              "=" * 130]
    _emit(lines, capsys)
