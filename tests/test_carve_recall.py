"""Recall and false-positive rate of the carver against the planted fixture manifest.

Two properties live here.  Both are now measured through shipped code.

THE MARGIN.  The carving engine admits a candidate at
``confidence::MIN_CONFIDENCE``.  What protects that gate is not the 0.2500 gap
between the planted and residue populations -- that is a distance nothing
enforces.  It is the structural credit a decoy would need in order to clear the
gate on its own, given that a decoy already scores full marks on signature,
entropy and size.  These tests assert the gate the Rust code actually enforces,
by running its CI measurement rather than restating its numbers.

RECALL (measured 2026-09-03, through the shipped ``carve`` binary).  The engine
carves CONTIGUOUS objects only; ``bifragment.rs`` is deferred and is never called.
So it is bounded above by the 28 planted files a contiguous engine can reach, and
that ceiling is not its result.  DEMONSTRATED RECALL (CONTIGUOUS ENGINE) is what a
run measurably recovered, joined to the manifest BY SHA-256 -- never by row count,
because this run admits five records at a planted file's offset whose bytes are not
that file's bytes, and only the digest sees the difference.

The reachability CEILING of 33 of 40 and the demonstrated recall are two numbers.
They live in two fields, they are printed on two lines, and they never appear in
one sentence.

When the binary is absent these tests SKIP, loudly, with the reason naming the
missing path -- never silently.  Set SENTINELWIPE_REQUIRE_CARVER=1 to turn the
absence into a failure, which is what CI should do.
"""

from __future__ import annotations

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
CARVE_BIN = REPO / "core" / "target" / "release" / "carve"

# The four weights and the gate, as published in docs/architecture.md D2 and
# exported from core/carve/src/confidence.rs.  Duplicated here deliberately: if
# these drift from the Rust constants, test_the_rust_gate_matches_this_file
# fails, which is the point.
W_SIGNATURE, W_STRUCTURE, W_ENTROPY, W_SIZE = 0.40, 0.35, 0.15, 0.10
MIN_CONFIDENCE = 0.75
NON_STRUCTURE_CEILING = W_SIGNATURE + W_ENTROPY + W_SIZE          # 0.65
STRUCTURAL_BREACH_POINT = (MIN_CONFIDENCE - NON_STRUCTURE_CEILING) / W_STRUCTURE


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
    assert other == ["/evidence_bag_seal.jpg", "/media_inventory.docx"], other


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


def the_run():
    """The measured run: the whole image, scored against the manifest by SHA-256."""
    return carve("--phase", "pre-wipe", "--manifest", str(MANIFEST.relative_to(REPO)))


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
    offsets and not a value the report carries about itself.
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


# --- the demo artifact -----------------------------------------------------

_COLS = "  %-6s %11s %9s   %-8s%-8s%-8s%-8s %-8s %-3s %-12s  %s"
_HEAD = _COLS % ("KIND", "OFFSET", "BYTES", "SIG", "STRUCT", "ENTROPY", "SIZE",
                 "TOTAL", "ADM", "SHA256", "PLANTED FILE  (SHA-256 join)")
_RULE = "  " + "-" * 114


def _row(rec: dict, label: str) -> str:
    c = rec["confidence"]
    return _COLS % (
        rec["kind"], rec["offset"], rec["length"],
        "%.4f" % c["signature_integrity"], "%.4f" % c["structural_validity"],
        "%.4f" % c["entropy_consistency"], "%.4f" % c["size_plausibility"],
        "%.4f" % c["total"],
        "yes" if rec["admitted"] else "no",
        rec["sha256"][:12], label)


def _emit(lines, capsys):
    text = "\n".join(lines)
    with capsys.disabled():
        print("\n" + text + "\n")


# --------------------------------------------------------------------------

def test_recall_over_the_reachable_set(capsys):
    """Demonstrated recall of the contiguous engine, joined to the manifest by SHA-256.

    The engine carves contiguous objects only -- ``bifragment.rs`` is deferred and
    is never called -- so the set it can reach at all is the 28 planted files the
    manifest marks ``signature-only``.  Those 28 are asserted BY DIGEST, one path
    at a time, and the 5 files needing reassembly and the 7 unreachable by
    construction are asserted absent.  A row count is not a recall figure: five
    records in this run are admitted at a planted file's offset carrying bytes
    that are not that file, and only the digest sees it.

    The ">=60% of fragmented" bar in
    ``test_recall_thresholds_are_defined_over_the_reachable_set`` is a bar for the
    bifragment engine.  It is not measured here and is not claimed here, because
    the code that would earn it has not been run.
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

    # Every record's arithmetic, before any of it is counted as evidence.
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

    assert report["counts"]["by_assembly"]["reassembled"] == 0, (
        "a record claims reassembly, but bifragment.rs is deferred and must not have run")

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

    lines = ["=" * 112,
             "CARVE RUN  %s" % report["provenance"]["command"],
             "  image %s  %d bytes  sha256 %s"
             % (report["run"]["image_path"], report["run"]["image_bytes"],
                report["run"]["image_sha256"][:16]),
             "  formula   %s" % report["policy"]["formula"],
             "  gate      MIN_CONFIDENCE %.4f   admitted = total >= gate, one comparison"
             % gate,
             "=" * 112, "",
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
              "-" * 112,
              "DEMONSTRATED RECALL (contiguous engine)   %d of %d planted files, every one"
              % (len(got), m["counted_set"]["total"]),
              "                                          verified by SHA-256 against the digest",
              "                                          fixtures/build_image.py recorded.",
              "",
              "REACHABILITY CEILING -- a different number, and never the same sentence as the above:",
              "  contiguous                    %2d   what a contiguous engine could reach at all"
              % reach["contiguous"],
              "  needs bifragment reassembly   %2d   bifragment.rs deferred, never called, recovered none"
              % reach["needs_bifragment_reassembly"],
              "  unreachable by construction   %2d   reachable by nothing this carver does"
              % reach["unreachable_by_construction"],
              "-" * 112,
              "",
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
              "=" * 112]
    _emit(lines, capsys)

    # ---- the assertions ----
    missing = [p for p in contiguous if p not in got]
    assert not missing, (
        "demonstrated recall is %d of %d contiguous reachable files. NOT RECOVERED: %s\n"
        "This is a finding about the engine. Do not lower the bar to meet it."
        % (len(contiguous) - len(missing), len(contiguous), missing))

    reassembled = [p for p in needs_bifragment if p in got]
    assert not reassembled, (
        "%s was recovered byte-exact, but it needs bifragment reassembly and "
        "bifragment.rs was never called. Either the manifest's fragment layout is "
        "wrong or the engine did something it does not claim to do." % reassembled)

    impossible = [p for p in unreachable if p in got]
    assert not impossible, (
        "%s is planted as unreachable by construction and was recovered anyway" % impossible)

    assert sorted(got) == contiguous, sorted(got)

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
    # the result, and the contiguous engine must never exceed its own ceiling.
    assert gt["demonstrated_recall"]["recovered"] <= reach["contiguous"]
    assert gt["demonstrated_recall"]["recovered"] != m["counted_set"]["expected_recoverable"], (
        "the report publishes the 33-of-40 reachability ceiling as a recall figure")
    assert "demonstrated recall (contiguous engine)" in stderr.lower(), (
        "the operator-facing line does not label the number as demonstrated recall")

    # A record that recovered a planted file byte-exact and was then rejected is a
    # recall loss, so no such record may exist unnoticed.
    for rec in records:
        if not rec["admitted"] and rec["sha256"] in by_digest:
            pytest.fail("%s recovered %s byte-exact and was rejected at %.4f"
                        % (rec["id"], by_digest[rec["sha256"]], rec["confidence"]["total"]))


def test_the_two_by_design_failures_are_not_recovered(capsys):
    """The fixture fragments two files to defeat this engine, and they defeat it.

    ``media_inventory.docx`` is planted in three extents and ``evidence_bag_seal.jpg``
    in two stored out of physical order.  Neither is recovered.  Absence is asserted
    by digest over EVERY record, admitted or rejected: a record does sit at each
    file's planted offset and one of them is admitted, so an assertion phrased on
    offsets or on record counts would pass while the bytes were wrong.

    The second half is the one that matters more.  A carver that recognised these
    two by name would produce this same output, so the engine source is searched
    for their names, their planted offsets, their extent offsets and lengths, their
    sizes and their digests, and the run is repeated with no manifest at all to
    confirm ground truth never reaches the engine.
    """
    m = manifest()
    report, _, _ = the_run()

    by_path = {f["path"]: f for f in m["files"]}
    by_design = ["/media_inventory.docx", "/evidence_bag_seal.jpg"]
    for p in by_design:
        assert by_path[p]["expected_recoverable"] == "unrecoverable-by-design", p
        assert by_path[p]["fragmented"] is True, p

    got = recovered_paths(report, m)
    digests = {by_path[p]["sha256"]: p for p in by_design}

    # 1. Absent from the recovery set, and absent from the report entirely by digest.
    for p in by_design:
        assert p not in got, "%s was recovered, and it is planted to be unrecoverable" % p
    for rec in report["candidates"]:
        assert rec["sha256"] not in digests, (
            "%s carries the exact bytes of %s (admitted=%s) -- the by-design failure "
            "did not fail" % (rec["id"], digests[rec["sha256"]], rec["admitted"]))

    # 2. What the engine DID emit over those bytes, and why it is not a recovery.
    spans = {p: [(e["byte_offset"], e["byte_offset"] + e["byte_length"])
                 for e in by_path[p]["extents"]] for p in by_design}
    touching = []
    for rec in sorted(report["candidates"], key=lambda r: r["offset"]):
        lo, hi = rec["offset"], rec["offset"] + rec["length"]
        for p in by_design:
            if any(lo < b and a < hi for a, b in spans[p]):
                assert rec["sha256"] != by_path[p]["sha256"]
                touching.append((p, rec))
                break

    lines = ["=" * 112,
             "BY-DESIGN FAILURES -- planted to defeat this engine, and they did", ""]
    for p in by_design:
        f = by_path[p]
        lines += ["  %-24s %-5s %7d bytes  %d extents  sha256 %s"
                  % (p, f["kind"], f["size"], len(f["extents"]), f["sha256"][:12]),
                  "    extents  %s" % "  ".join("%d+%d" % (e["byte_offset"], e["byte_length"])
                                                for e in f["extents"]),
                  "    RECOVERED: no"]
    lines += ["", "  Records the engine emitted over those bytes -- none of them is the file:",
              _HEAD, _RULE]
    for p, rec in touching:
        lines.append(_row(rec, "%s  <-- NOT this file's bytes" % p))
    lines += ["", "  %d record(s) overlap; 0 hash to a by-design file." % len(touching),
              "=" * 112]
    _emit(lines, capsys)

    # 3. Nothing in the engine knows these two by name, offset, length or digest.
    needles = {}
    for p in by_design:
        f = by_path[p]
        stem = re.sub(r"\.[a-z0-9]+$", "", p.lstrip("/"))
        needles[stem] = p
        needles[f["sha256"]] = p
        needles[f["sha256"][:16]] = p
        nums = {str(f["size"]), str(f["offset"])}
        for e in f["extents"]:
            nums.add(str(e["byte_offset"]))
            nums.add(str(e["byte_length"]))
        for n in nums:
            needles[n] = p

    hits = []
    for src in sorted((REPO / "core" / "carve" / "src").rglob("*.rs")):
        for lineno, code in _engine_lines(src):
            flat = code.replace("_", "")
            for needle, owner in needles.items():
                found = (needle in code if not needle.isdigit()
                         else re.search(r"(?<![0-9a-fA-F])%s(?![0-9a-fA-F])" % needle, flat))
                if found:
                    hits.append("%s:%d  %s  (%s)  %s"
                                % (src.relative_to(REPO), lineno, needle, owner, code.strip()[:80]))
    assert not hits, (
        "the engine special-cases a by-design failure. These are executable, "
        "non-test, non-comment lines naming one of them:\n  " + "\n  ".join(hits))

    # 4. Ground truth never reaches the engine: the same run with no manifest at
    #    all produces the same records, field for field, minus the annotation.
    blind, _, _ = carve("--phase", "pre-wipe")
    assert blind["ground_truth"] is None
    strip = lambda cs: [{k: v for k, v in c.items() if k != "ground_truth"} for c in cs]
    assert strip(blind["candidates"]) == strip(report["candidates"]), (
        "the engine produced different records when handed the manifest; ground "
        "truth is reaching the scoring path")


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
