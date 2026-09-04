"""RFC 8785 JSON Canonicalization Scheme, and the numeric policy that makes it safe.

A signature over JSON is worthless unless the bytes are reproducible. Two serialisers
that disagree about key order, whitespace or float formatting produce two different
signatures over the same logical certificate, and the verifier then fails on a document
nobody tampered with.

RFC 8785 settles order, whitespace and string escaping. It does not make floats safe:
its number rule defers to ECMAScript Number::toString, whose shortest-round-trip
formatting is the classic source of cross-language canonicalisation bugs, because Rust
and Python reach it by different routes.

So this module does not implement that rule. It forbids floats instead.

`canonicalize` raises on any float it meets. Every quantity that used to be one is
carried as the integers it was actually derived from:

    Ratio(n, d)   an exact rational — a rate is bytes over nanoseconds, a coverage is
                  sectors over sectors, a timing ratio is elapsed over floor. All four
                  are already integer pairs upstream; rendering them as a decimal was a
                  lossy display step that had no business happening before signing.

    Decimal6(s)   a fixed six-decimal string, copied verbatim from the engine's own
                  report, for the few figures with no exact rational behind them.
                  Entropy is the only one. A string has no rounding step, so Python's
                  half-even and Rust's half-away-from-zero cannot disagree about it.

The consequence is that the Rust side needs no float formatter at all. Integer
serialisation is unambiguous in every language, so the two implementations cannot drift
on the one thing that would be hardest to notice and most expensive to discover late.

Reference: RFC 8785, JSON Canonicalization Scheme (JCS), IETF, June 2020.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

SCHEMA = "sentinelwipe.canon/1"

# JSON's safe integer range. Beyond this a double cannot hold the value exactly, so a
# consumer that parses into a float would silently lose digits.
MAX_SAFE_INT = 2**53 - 1

# Exactly six decimal places, optional sign, no exponent.
_DEC6 = re.compile(r"-?(0|[1-9][0-9]*)\.[0-9]{6}")


class CanonError(ValueError):
    """The payload cannot be canonicalised. Always names the offending path.

    ``kind`` is one of: float | duplicate-key | unsafe-integer | parse | canon —
    the refusal classes shared with the Rust side through fixtures/jcs_vectors.json.
    """

    def __init__(self, msg: str, kind: str = "canon"):
        super().__init__(msg)
        self.kind = kind


# ── numeric carriers ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Ratio:
    """An exact rational, carried as the two integers it was measured from.

    `d` must be positive and non-zero. The pair is stored reduced, so that two runs
    that measure 1024/524288 and 1/512 produce identical bytes.
    """

    n: int
    d: int

    def __post_init__(self) -> None:
        if not isinstance(self.n, int) or isinstance(self.n, bool):
            raise CanonError(f"Ratio numerator must be int, got {type(self.n).__name__}")
        if not isinstance(self.d, int) or isinstance(self.d, bool):
            raise CanonError(f"Ratio denominator must be int, got {type(self.d).__name__}")
        if self.d <= 0:
            raise CanonError(f"Ratio denominator must be positive, got {self.d}")

    @staticmethod
    def reduced(n: int, d: int) -> "Ratio":
        f = Fraction(n, d)
        return Ratio(f.numerator, f.denominator)

    def to_json(self) -> dict:
        f = Fraction(self.n, self.d)
        return {"d": f.denominator, "n": f.numerator}

    def as_float(self) -> float:
        """For display only. Never for signing."""
        return self.n / self.d


@dataclass(frozen=True)
class Decimal6:
    """A measured continuous value, carried as a fixed six-decimal STRING.

    Matches core/ledger/src/jcs.rs, and the reason is a cross-language hazard rather
    than taste. The obvious alternative — an integer scaled by 1e6 — needs a rounding
    step at the boundary, and Python's round() is half-even while Rust's f64::round()
    is half-away-from-zero. The two agree on every value except an exact .5 at the
    sixth decimal, where they would produce different bytes, different signatures, and
    a verification failure on a document nobody touched. The failure would be rare,
    non-reproducible, and would appear for the first time on someone else's laptop.

    A string copied verbatim from the engine's own report has no rounding step to
    disagree about. The engine already decided the precision; nothing downstream
    re-decides it.
    """

    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise CanonError(f"Decimal6 needs a string, got {type(self.text).__name__}")
        if not _DEC6.fullmatch(self.text):
            raise CanonError(
                f"Decimal6({self.text!r}): expected exactly six decimal places, e.g. "
                f"'7.061690'. Copy the engine's own rendering; do not reformat it."
            )

    def to_json(self) -> str:
        return self.text

    def as_float(self) -> float:
        """For display only. Never for signing."""
        return float(self.text)


# ── UTF-16 ordering ─────────────────────────────────────────────────────────────────

def _utf16_key(s: str) -> tuple[int, ...]:
    """RFC 8785 §3.2.3 orders keys by UTF-16 code unit, not by code point.

    The two agree across the whole BMP and disagree above U+FFFF, where a code point
    sorts high but its surrogate pair sorts into the D800–DFFF range. Sorting by code
    point would be right almost always, which is the worst kind of wrong.
    """
    b = s.encode("utf-16-be")
    return tuple(int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2))


# ── string escaping ─────────────────────────────────────────────────────────────────

_ESCAPES = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}


def _string(s: str) -> str:
    """Minimal escaping per RFC 8785 §3.2.2.2: the two mandatory escapes, the five
    short forms, and \\u00xx for everything else below 0x20. Nothing else is escaped —
    in particular the solidus is left bare and non-ASCII is emitted as itself."""
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in _ESCAPES:
            out.append(_ESCAPES[cp])
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# ── the serialiser ──────────────────────────────────────────────────────────────────

def _ser(v: Any, path: str) -> str:
    if v is None:
        return "null"

    if v is True:
        return "true"
    if v is False:
        return "false"

    if isinstance(v, float):
        raise CanonError(
            f"{path}: float {v!r} in a signed payload. Carry it as Ratio(n, d) if it "
            f"came from two integers, or Fixed6 if it came from a transcendental "
            f"computation. See py/sentinelwipe/canon.py."
        )

    if isinstance(v, int):
        if abs(v) > MAX_SAFE_INT:
            raise CanonError(
                f"{path}: integer {v} exceeds 2^53-1 and cannot survive a JSON parser "
                f"that uses doubles. Carry it as a decimal string."
            )
        return str(v)

    if isinstance(v, str):
        return _string(v)

    if isinstance(v, (Ratio, Decimal6)):
        return _ser(v.to_json(), path)

    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_ser(x, f"{path}[{i}]") for i, x in enumerate(v)) + "]"

    if isinstance(v, dict):
        # Validate before sorting: _utf16_key would raise AttributeError on a
        # non-string key, which tells the caller nothing about where the fault is.
        for k in v:
            if not isinstance(k, str):
                raise CanonError(f"{path}: object key {k!r} is not a string")
        items = [
            _string(k) + ":" + _ser(v[k], f"{path}.{k}")
            for k in sorted(v.keys(), key=_utf16_key)
        ]
        return "{" + ",".join(items) + "}"

    raise CanonError(f"{path}: {type(v).__name__} is not serialisable in a signed payload")


def canonicalize(obj: Any) -> bytes:
    """Return the RFC 8785 canonical form as UTF-8 bytes. Raises on any float."""
    return _ser(obj, "$").encode("utf-8")


def parse(b: bytes) -> Any:
    """Parse canonical bytes back, restoring Ratio and Fixed6 carriers.

    Present so the round-trip property can be tested: canonicalize(parse(x)) == x.
    """
    def hook(d: dict) -> Any:
        if set(d) == {"n", "d"} and all(isinstance(x, int) for x in d.values()):
            return Ratio(d["n"], d["d"])
        return d

    return json.loads(b.decode("utf-8"), object_hook=hook, parse_float=_no_floats)


def _no_floats(s: str) -> Any:
    raise CanonError(f"parsed a float literal {s!r} — canonical bytes must not contain one")


_FLOAT_LITERAL = re.compile(rb"-?\d+(\.\d+|[eE][-+]?\d+)")


# ── the check a caller actually wants ───────────────────────────────────────────────

def assert_no_float_literals(b: bytes) -> None:
    """Belt and braces: no float syntax survives *outside* a string literal.

    The qualifier is the whole difficulty. Decimal6 carries a measured value as the
    JSON string "7.061690", so a naive scan for a digit-dot-digit run fires on legal
    output and the guard gets switched off — which is how a guard stops guarding.

    So this walks the bytes tracking string state, honouring backslash escapes, and
    scans only the spans between strings. Structural bytes are the only place a number
    can legally appear, and a fraction or exponent there means a float reached the
    serialiser through a path the type checks did not cover.
    """
    spans: list[bytes] = []
    start = 0
    i = 0
    in_str = False
    n = len(b)
    while i < n:
        c = b[i]
        if in_str:
            if c == 0x5C:          # backslash: skip the escaped byte
                i += 2
                continue
            if c == 0x22:          # closing quote
                in_str = False
                start = i + 1
            i += 1
            continue
        if c == 0x22:              # opening quote
            spans.append(b[start:i])
            in_str = True
        i += 1
    if in_str:
        raise CanonError("unterminated string literal in canonical output")
    spans.append(b[start:])

    for span in spans:
        m = _FLOAT_LITERAL.search(span)
        if m:
            raise CanonError(
                f"float literal {m.group(0)!r} outside a string in canonical output"
            )

# ── the strict boundary parser ──────────────────────────────────────────────────────
#
# ``parse`` above is deliberately lenient: it exists so the round-trip property can be
# tested, and it rides on the stdlib. The stdlib is the wrong tool at a TRUST BOUNDARY:
# json.loads keeps the last of duplicate keys silently, admits lone-surrogate escapes,
# and parses fractions (caught here only by the parse_float hook). ``parse_strict`` is
# the boundary parser: it accepts exactly what ``canonicalize`` emits plus insignificant
# whitespace, and refuses — never coerces — everything else. It returns PLAIN values;
# restoring Ratio/Decimal6 carriers stays ``parse``'s job, because a boundary should do
# one thing.
#
# It is pinned to the Rust reference (core/ledger/src/jcs.rs) through
# fixtures/jcs_vectors.json: 75 messy inputs that must canonicalise to identical bytes,
# and 13 inputs that must refuse with the same class. Direction of truth is the mirror
# of the write guard's: there Python was the measured original; here Rust is.


class _Strict:
    def __init__(self, b: bytes):
        self.b = b
        self.i = 0

    def err(self, what: str) -> CanonError:
        return CanonError(f"{what} (byte {self.i})", kind="parse")

    def ws(self) -> None:
        while self.i < len(self.b) and self.b[self.i] in b" \t\n\r":
            self.i += 1

    def eat(self, lit: bytes, what: str) -> None:
        if self.b[self.i : self.i + len(lit)] == lit:
            self.i += len(lit)
        else:
            raise self.err(what)

    def value(self):
        if self.i >= len(self.b):
            raise self.err("unexpected end of input")
        c = self.b[self.i]
        if c == 0x6E:  # n
            self.eat(b"null", "expected null"); return None
        if c == 0x74:  # t
            self.eat(b"true", "expected true"); return True
        if c == 0x66:  # f
            self.eat(b"false", "expected false"); return False
        if c == 0x22:
            return self.string()
        if c == 0x5B:
            return self.array()
        if c == 0x7B:
            return self.object()
        if c == 0x2D or 0x30 <= c <= 0x39:
            return self.integer()
        raise self.err("unexpected byte")

    def integer(self) -> int:
        start = self.i
        if self.b[self.i : self.i + 1] == b"-":
            self.i += 1
        d0 = self.i
        while self.i < len(self.b) and 0x30 <= self.b[self.i] <= 0x39:
            self.i += 1
        if self.i == d0:
            raise self.err("minus sign with no digits")
        if self.i - d0 > 1 and self.b[d0] == 0x30:
            raise self.err("leading zero")
        if self.b[self.i : self.i + 1] in (b".", b"e", b"E"):
            raise CanonError(
                f"float syntax at byte {self.i}: the signed payload carries no floating point",
                kind="float",
            )
        n = int(self.b[start : self.i])
        if abs(n) > MAX_SAFE_INT:
            raise CanonError(f"integer {n} is outside the safe range", kind="unsafe-integer")
        return n

    def hex4(self) -> int:
        h = self.b[self.i : self.i + 4]
        if len(h) != 4:
            raise self.err("truncated \\u escape")
        try:
            v = int(h, 16)
        except ValueError:
            raise self.err("bad hex in \\u escape") from None
        self.i += 4
        return v

    _SIMPLE = {0x22: '"', 0x5C: "\\", 0x2F: "/", 0x62: "\b",
               0x74: "\t", 0x6E: "\n", 0x66: "\f", 0x72: "\r"}

    def string(self) -> str:
        self.eat(b'"', "expected opening quote")
        parts: list = []
        while True:
            if self.i >= len(self.b):
                raise self.err("unterminated string")
            c = self.b[self.i]
            if c == 0x22:
                self.i += 1
                return "".join(parts)
            if c == 0x5C:
                self.i += 1
                if self.i >= len(self.b):
                    raise self.err("truncated escape")
                e = self.b[self.i]
                self.i += 1
                if e in self._SIMPLE:
                    parts.append(self._SIMPLE[e])
                elif e == 0x75:
                    hi = self.hex4()
                    if 0xD800 <= hi <= 0xDBFF:
                        self.eat(b"\\u", "high surrogate without its low half")
                        lo = self.hex4()
                        if not 0xDC00 <= lo <= 0xDFFF:
                            raise self.err("invalid low surrogate")
                        parts.append(chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)))
                    elif 0xDC00 <= hi <= 0xDFFF:
                        raise self.err("lone low surrogate")
                    else:
                        parts.append(chr(hi))
                else:
                    raise self.err("unknown escape")
            elif c < 0x20:
                raise self.err("raw control character in string")
            else:
                n = 1 if c < 0x80 else 2 if c < 0xE0 else 3 if c < 0xF0 else 4
                try:
                    parts.append(self.b[self.i : self.i + n].decode("utf-8"))
                except UnicodeDecodeError:
                    raise self.err("invalid UTF-8") from None
                self.i += n

    def array(self) -> list:
        self.eat(b"[", "expected [")
        items: list = []
        self.ws()
        if self.b[self.i : self.i + 1] == b"]":
            self.i += 1
            return items
        while True:
            self.ws()
            items.append(self.value())
            self.ws()
            nxt = self.b[self.i : self.i + 1]
            if nxt == b",":
                self.i += 1
            elif nxt == b"]":
                self.i += 1
                return items
            else:
                raise self.err("expected , or ] in array")

    def object(self) -> dict:
        self.eat(b"{", "expected {")
        pairs: dict = {}
        self.ws()
        if self.b[self.i : self.i + 1] == b"}":
            self.i += 1
            return pairs
        while True:
            self.ws()
            k = self.string()
            if k in pairs:
                raise CanonError(f"duplicate object key {k!r}", kind="duplicate-key")
            self.ws()
            self.eat(b":", "expected : after key")
            self.ws()
            pairs[k] = self.value()
            self.ws()
            nxt = self.b[self.i : self.i + 1]
            if nxt == b",":
                self.i += 1
            elif nxt == b"}":
                self.i += 1
                return pairs
            else:
                raise self.err("expected , or } in object")


def parse_strict(b: bytes):
    """Strict boundary parse: plain values out, refusal (never coercion) on the way in."""
    p = _Strict(b)
    p.ws()
    v = p.value()
    p.ws()
    if p.i != len(p.b):
        raise p.err("trailing input after the document")
    return v

