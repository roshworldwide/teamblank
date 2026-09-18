from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinelwipe.canon import CanonError, canonicalize, parse_strict

_REPO = Path(__file__).resolve().parents[1]
_DOC_BYTES = (_REPO / "fixtures" / "jcs_vectors.json").read_bytes()
_DOC = json.loads(_DOC_BYTES)

VECTORS = _DOC["vectors"]
REFUSALS = _DOC["refusals"]


def test_the_committed_file_is_a_fixed_point_of_this_implementation():
    assert canonicalize(parse_strict(_DOC_BYTES)) == _DOC_BYTES


def test_the_table_is_present_and_not_vacuous():
    counts = _DOC["counts"]
    assert counts["vectors"] == len(VECTORS) >= 70, "vector table truncated"
    assert counts["refusals"] == len(REFUSALS) >= 12, "refusal table truncated"
    names = [v["name"] for v in VECTORS]
    assert "astral-key-sorts-before-u+e000" in names
    assert "rfc-8785-sample-string" in names


@pytest.mark.parametrize("vec", VECTORS, ids=lambda v: v["name"])
def test_messy_input_canonicalises_to_the_reference_bytes(vec):
    got = canonicalize(parse_strict(vec["input"].encode("utf-8")))
    assert got == vec["canonical"].encode("utf-8"), (
        f"{vec['name']}: python bytes differ from the Rust reference"
    )


@pytest.mark.parametrize("ref", REFUSALS, ids=lambda r: r["name"])
def test_refusals_carry_the_same_class_in_both_languages(ref):
    with pytest.raises(CanonError) as ei:
        parse_strict(ref["input"].encode("utf-8"))
    assert ei.value.kind == ref["error"], (
        f"{ref['name']}: python refused as {ei.value.kind!r}, "
        f"the reference says {ref['error']!r}"
    )


def test_sorting_agreement_is_not_an_accident_of_ascii():
    astral, e000, empty = chr(0x10000), chr(0xE000), ""
    got = canonicalize({e000: 1, astral: 2, empty: 3})
    expected = (
        "{" + '"' + empty + '":3,'
        + '"' + astral + '":2,'
        + '"' + e000 + '":1}'
    ).encode("utf-8")
    assert got == expected
    two = canonicalize({astral: 1, e000: 2})
    assert two.index(astral.encode("utf-8")) < two.index(e000.encode("utf-8"))