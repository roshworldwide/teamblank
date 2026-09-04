"""The canonicalisation contract, shared with the Rust implementation.

fixtures/canon_vectors.json is the single source of truth for both languages. A Rust
test reads the same file and asserts the same bytes; if the two implementations ever
drift, this is the file that catches it — and it catches it at build time rather than
on the day someone verifies a certificate on a laptop that is not ours.

Signatures are only as reproducible as the bytes underneath them, so these tests run
before any crypto exists and must keep passing after it lands.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from pathlib import Path

import pytest

from sentinelwipe.canon import (
    MAX_SAFE_INT, CanonError, Decimal6, Ratio, assert_no_float_literals,
    canonicalize, parse,
)

VECTORS = json.loads((Path(__file__).parent.parent / "fixtures" / "canon_vectors.json")
                     .read_text(encoding="utf-8"))


def _rebuild(o):
    """Restore Ratio/Fixed6 carriers from the plain JSON in the vector file."""
    if isinstance(o, dict):
        if set(o) == {"n", "d"}:
            return Ratio(o["n"], o["d"])
        return {k: _rebuild(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_rebuild(v) for v in o]
    return o


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_vector_bytes_and_digest(case):
    """Every vector's stored bytes must be the canonical form of its own parse."""
    canonical = case["canonical"].encode("utf-8")
    assert canonicalize(_rebuild(json.loads(case["canonical"]))) == canonical
    assert hashlib.sha256(canonical).hexdigest() == case["sha256"]
    assert len(canonical) == case["bytes"]
    assert_no_float_literals(canonical)


def test_utf16_ordering_is_not_code_point_ordering():
    """The vector that justifies RFC 8785 3.2.3.

    U+1F600 sorts BEFORE U+FFFD by UTF-16 code unit (D83D < FFFD) and AFTER it by code
    point (1F600 > FFFD). An implementation that sorts by code point passes every other
    test in this file.
    """
    out = canonicalize({"\U0001F600": 1, "�": 2}).decode()
    assert out.index("\U0001F600") < out.index("�")


def test_ratio_is_reduced_so_equal_values_are_equal_bytes():
    assert canonicalize({"a": Ratio.reduced(1024, 524288)}) == canonicalize({"a": Ratio(1, 512)})


def test_decimal6_is_verbatim_and_refuses_reformatting():
    """The carrier that removes the cross-language rounding hazard.

    A scaled integer would need round() at the boundary, and Python rounds half-even
    while Rust rounds half-away-from-zero. They differ only on an exact .5 at the sixth
    decimal — rarely, unreproducibly, and for the first time on someone else's laptop.
    A verbatim string has no rounding step to disagree about.
    """
    assert canonicalize({"e": Decimal6("7.061690")}) == b'{"e":"7.061690"}'
    for bad in ["7.06169", "7.0616900", "7", "7.061690e0", "  7.061690"]:
        with pytest.raises(CanonError):
            Decimal6(bad)


@pytest.mark.parametrize("payload", [
    pytest.param({"x": 1.5}, id="bare_float"),
    pytest.param({"x": [1, 2.0]}, id="float_in_array"),
    pytest.param({"a": {"b": 0.1}}, id="float_nested"),
    pytest.param({"x": float("nan")}, id="nan"),
    pytest.param({"x": float("inf")}, id="inf"),
    pytest.param({"x": MAX_SAFE_INT + 1}, id="int_past_2_53"),
    pytest.param({1: "a"}, id="non_string_key"),
    pytest.param({"x": {1, 2}}, id="unserialisable_type"),
])
def test_rejected(payload):
    with pytest.raises(CanonError):
        canonicalize(payload)


@pytest.mark.parametrize("args", [(1, 0), (1, -3)])
def test_ratio_denominator_must_be_positive(args):
    with pytest.raises(CanonError):
        Ratio(*args)


def test_error_names_the_path():
    """A rejection that does not say where is a rejection nobody can act on."""
    with pytest.raises(CanonError, match=r"\$\.audit\.overwrite\.ratio"):
        canonicalize({"audit": {"overwrite": {"ratio": 0.949731}}})


def test_max_safe_int_is_allowed():
    assert canonicalize({"a": MAX_SAFE_INT}) == b'{"a":9007199254740991}'


def _random_value(depth=0):
    r = random.random()
    if depth > 3 or r < 0.30:
        return random.choice([
            None, True, False,
            random.randint(-(2**40), 2**40),
            "".join(random.choice('ab"\\\t\n/é漢\U0001F600\x01') for _ in range(4)),
            Ratio.reduced(random.randint(1, 10**6), random.randint(1, 10**6)),
            Decimal6(f"{random.randint(-10**6, 10**6)}.{random.randint(0, 999999):06d}"),
        ])
    if r < 0.60:
        return [_random_value(depth + 1) for _ in range(random.randint(0, 4))]
    return {f"k{random.randint(0, 40)}": _random_value(depth + 1)
            for _ in range(random.randint(0, 5))}


def test_round_trip_is_a_fixed_point_over_ten_thousand_payloads():
    """canonicalize(parse(canonicalize(x))) == canonicalize(x), always.

    Ten thousand generated payloads including astral characters, control characters,
    both carriers, and every escape.
    """
    random.seed(20260904)
    for _ in range(10_000):
        once = canonicalize(_random_value())
        assert canonicalize(parse(once)) == once
        assert_no_float_literals(once)


def test_parse_refuses_a_float_literal():
    with pytest.raises(CanonError):
        parse(b'{"a":1.5}')


def test_vector_file_documents_what_it_does_not_cover():
    """Matches fixtures/guard_vectors.json: an untested path is named, not omitted."""
    assert VECTORS["not_exercised"], "the vector file must say what it does not reach"
    for reason in VECTORS["not_exercised"].values():
        assert len(reason) > 60


def test_float_guard_ignores_strings_but_catches_structural_floats():
    """The guard must not fire on Decimal6's string, and must fire on a real leak.

    A guard with false positives gets switched off, which is how a guard stops
    guarding. A guard that misses the real case was never one.
    """
    assert_no_float_literals(b'{"e":"7.061690","f":"-1.500000"}')      # legal
    assert_no_float_literals(b'{"s":"1e9 and 0.5 inside a string"}')   # legal
    for leaked in [b'{"a":1.5}', b'{"a":[1,2.0]}', b'{"a":1e9}', b'{"a":-0.001}']:
        with pytest.raises(CanonError, match="outside a string"):
            assert_no_float_literals(leaked)


def test_float_guard_survives_escaped_quotes():
    """A backslash-escaped quote must not be read as closing the string."""
    assert_no_float_literals(rb'{"s":"he said \"1.5\" out loud"}')
