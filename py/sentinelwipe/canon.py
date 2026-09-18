from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

SCHEMA = "sentinelwipe.canon/1"

MAX_SAFE_INT = 2**53 - 1

_DEC6 = re.compile(r"-?(0|[1-9][0-9]*)\.[0-9]{6}")


class CanonError(ValueError):
    def __init__(self, msg: str, kind: str = "canon"):
        super().__init__(msg)
        self.kind = kind


@dataclass(frozen=True)
class Ratio:
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
        return self.n / self.d


@dataclass(frozen=True)
class Decimal6:
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
        return float(self.text)


def _utf16_key(s: str) -> tuple[int, ...]:
    b = s.encode("utf-16-be")
    return tuple(int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2))


_ESCAPES = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}


def _string(s: str) -> str:
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
    return _ser(obj, "$").encode("utf-8")


def parse(b: bytes) -> Any:
    def hook(d: dict) -> Any:
        if set(d) == {"n", "d"} and all(isinstance(x, int) for x in d.values()):
            return Ratio(d["n"], d["d"])
        return d

    return json.loads(b.decode("utf-8"), object_hook=hook, parse_float=_no_floats)


def _no_floats(s: str) -> Any:
    raise CanonError(f"parsed a float literal {s!r} — canonical bytes must not contain one")


_FLOAT_LITERAL = re.compile(rb"-?\d+(\.\d+|[eE][-+]?\d+)")


def assert_no_float_literals(b: bytes) -> None:
    spans: list[bytes] = []
    start = 0
    i = 0
    in_str = False
    n = len(b)
    while i < n:
        c = b[i]
        if in_str:
            if c == 0x5C:
                i += 2
                continue
            if c == 0x22:
                in_str = False
                start = i + 1
            i += 1
            continue
        if c == 0x22:
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
        if c == 0x6E:
            self.eat(b"null", "expected null"); return None
        if c == 0x74:
            self.eat(b"true", "expected true"); return True
        if c == 0x66:
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
    p = _Strict(b)
    p.ws()
    v = p.value()
    p.ws()
    if p.i != len(p.b):
        raise p.err("trailing input after the document")
    return v
