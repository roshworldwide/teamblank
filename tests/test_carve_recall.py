"""Recall and false-positive rate of the carver against the planted fixture manifest.

Two properties live here, and only one of them can be measured today.

THE MARGIN (measurable now).  The carving engine admits a candidate at
``confidence::MIN_CONFIDENCE``.  What protects that gate is not the 0.2500 gap
between the planted and residue populations -- that is a distance nothing
enforces.  It is the structural credit a decoy would need in order to clear the
gate on its own, given that a decoy already scores full marks on signature,
entropy and size.  These tests assert the gate the Rust code actually enforces,
by running its CI measurement rather than restating its numbers.

RECALL (not measurable yet).  ``carve.rs`` and the ``carve`` binary do not exist.
Those tests are written and are SKIPPED, loudly, with the reason naming the
missing binary -- never silently.  Set SENTINELWIPE_REQUIRE_CARVER=1 to turn the
absence into a failure, which is what CI should do once the binary lands.
"""

from __future__ import annotations

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
# Recall -- written, and skipped LOUDLY until the carve binary exists
# --------------------------------------------------------------------------

def _require_carver():
    if CARVE_BIN.exists():
        return
    msg = ("the carve binary does not exist yet (%s); recall is NOT measured. "
           "Set SENTINELWIPE_REQUIRE_CARVER=1 to make this a failure." % CARVE_BIN)
    if os.environ.get("SENTINELWIPE_REQUIRE_CARVER") == "1":
        pytest.fail("NOT VERIFIED -- " + msg)
    pytest.skip(msg)


def test_recall_over_the_reachable_set():
    _require_carver()
    raise AssertionError(
        "carve binary exists but this test has not been written against it. "
        "It must assert >=27 of 28 unfragmented and >=3 of 5 fragmented, compare "
        "recovered sha256 against the manifest rather than counting rows, and "
        "print the per-file table with all four confidence terms.")


def test_the_two_by_design_failures_are_not_recovered():
    _require_carver()
    raise AssertionError(
        "carve binary exists but this test has not been written against it. "
        "It must assert media_inventory.docx and evidence_bag_seal.jpg are absent "
        "from the output, and that nothing special-cases them by name or offset.")
