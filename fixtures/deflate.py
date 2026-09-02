"""A DEFLATE encoder this project owns, so compressed bytes stop being a
property of whichever libz the teammate's laptop happens to link.

MEASURED motivation, recorded in docs/architecture.md: Info-ZIP's encoder and
Python's `zlib` produced 13,937 and 14,066 bytes from identical input.  Both
decompress correctly; the bytes differ.  PNG, DOCX and GZIP all ride on
DEFLATE, so a corpus built through the linked libz would differ per machine and
CLAUDE.md rule 6 (reproducible from a fresh clone) would fail in a way no
single-machine test can detect.  uv's managed CPython bundles SQLite statically
but still links the *system* libz, so pinning the interpreter does not pin it.

Stored blocks (BTYPE=00) would also be reproducible, but they are not
compressed: entropy collapses to the plaintext's own, and the confidence
function's entropy_consistency term (weight 0.15) then has nothing to
discriminate.  So this is a real LZ77 matcher feeding RFC 1951 fixed-Huffman
codes (BTYPE=01): greedy matching, nearest-match tie-break, a fixed search
effort, no floats, no clock, no host state.

The output is ordinary DEFLATE.  `zlib.decompress` reads it, and every stream
this module produces is asserted against that round trip before it is returned.
`zlib` is used here for exactly two things -- inflate (verification) and
adler32 (a fixed algorithm defined by RFC 1950).  Never for compression.
"""

from __future__ import annotations

import struct
import zlib

__all__ = ["deflate_raw", "zlib_wrap", "WINDOW", "MIN_MATCH", "MAX_MATCH", "MAX_CHAIN"]

WINDOW = 32768
MIN_MATCH = 3
MAX_MATCH = 258

# Fixed search effort.  This is deliberately a module constant and NOT a
# parameter of deflate_raw: a caller who could tune it could change the bytes
# of the fixture without changing the seed, which is the reproducibility defect
# this whole module exists to remove.
MAX_CHAIN = 24

# RFC 1951 section 3.2.5, length codes 257..285.
_LEN_BASE = (3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43,
             51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258)
_LEN_EXTRA = (0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
              4, 4, 4, 4, 5, 5, 5, 5, 0)

# RFC 1951 section 3.2.5, distance codes 0..29.
_DIST_BASE = (1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257,
              385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
              16385, 24577)
_DIST_EXTRA = (0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
               9, 9, 10, 10, 11, 11, 12, 12, 13, 13)

# length -> (length symbol, extra bit count, extra bit value), for 3..258.
_LEN_MAP: list[tuple[int, int, int]] = [(0, 0, 0)] * (MAX_MATCH + 1)
for _i in range(len(_LEN_BASE)):
    _base = _LEN_BASE[_i]
    _eb = _LEN_EXTRA[_i]
    for _k in range(1 << _eb):
        if _base + _k <= MAX_MATCH:
            _LEN_MAP[_base + _k] = (257 + _i, _eb, _k)
_LEN_MAP[258] = (285, 0, 0)

# distance -> (distance symbol, extra bit count, extra bit value), for 1..32768.
# 32 KiB of tuples costs nothing and removes a linear scan from the inner loop.
_DIST_MAP: list[tuple[int, int, int]] = [(0, 0, 0)] * (WINDOW + 1)
for _i in range(len(_DIST_BASE)):
    _base = _DIST_BASE[_i]
    _eb = _DIST_EXTRA[_i]
    for _k in range(1 << _eb):
        if _base + _k <= WINDOW:
            _DIST_MAP[_base + _k] = (_i, _eb, _k)


def _fixed_litlen_code(sym: int) -> tuple[int, int]:
    """RFC 1951 section 3.2.6 fixed literal/length alphabet -> (code, bits)."""
    if sym <= 143:
        return 0x30 + sym, 8
    if sym <= 255:
        return 0x190 + (sym - 144), 9
    if sym <= 279:
        return sym - 256, 7
    return 0xC0 + (sym - 280), 8


def _bitrev(value: int, nbits: int) -> int:
    out = 0
    for i in range(nbits):
        out = (out << 1) | ((value >> i) & 1)
    return out


# Huffman codes are transmitted starting with their most significant bit while
# the bit stream itself is filled least significant bit first (RFC 1951 3.1.1).
# Pre-reversing lets the packer treat every field identically.
_REV_LITLEN: list[tuple[int, int]] = []
for _s in range(288):
    _c, _n = _fixed_litlen_code(_s)
    _REV_LITLEN.append((_bitrev(_c, _n), _n))

_REV_DIST: list[tuple[int, int]] = [(_bitrev(_s, 5), 5) for _s in range(30)]

_END_OF_BLOCK = _REV_LITLEN[256]


class _Bits:
    """DEFLATE bit packer. Bits enter each byte from the least significant end."""

    __slots__ = ("out", "acc", "n")

    def __init__(self) -> None:
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, val: int, nbits: int) -> None:
        self.acc |= (val & ((1 << nbits) - 1)) << self.n
        self.n += nbits
        while self.n >= 8:
            self.out.append(self.acc & 0xFF)
            self.acc >>= 8
            self.n -= 8

    def align(self) -> None:
        if self.n:
            self.out.append(self.acc & 0xFF)
            self.acc = 0
            self.n = 0


def deflate_raw(data: bytes) -> bytes:
    """Raw DEFLATE (RFC 1951): one fixed-Huffman block, deterministic bytes.

    A single block is legal at any length -- BFINAL is set on it and the
    decoder stops at the end-of-block symbol.  Emitting exactly one block also
    removes the "where do we split" decision, which would otherwise be a second
    place for two builds to disagree.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("deflate_raw takes bytes, got %r" % type(data).__name__)
    data = bytes(data)

    bw = _Bits()
    bw.put(1, 1)   # BFINAL = 1
    bw.put(1, 2)   # BTYPE  = 01, fixed Huffman

    n = len(data)
    put = bw.put
    rev_lit = _REV_LITLEN
    rev_dist = _REV_DIST
    len_map = _LEN_MAP
    dist_map = _DIST_MAP

    # Hash chains over 3-byte keys.  head[key] is the newest position holding
    # that key; prev[pos] is the next older one.  Walking newest-first means the
    # nearest match wins a tie, which is both the cheaper distance code and a
    # fixed, reproducible choice.
    head: dict[int, int] = {}
    prev = [-1] * n
    stop = n - 2  # last position at which a full 3-byte key exists is n-3

    i = 0
    while i < n:
        best_len = 0
        best_dist = 0
        if i < stop:
            key = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
            cand = head.get(key, -1)
            chain = 0
            limit = MAX_MATCH if n - i > MAX_MATCH else n - i
            while cand >= 0 and chain < MAX_CHAIN:
                d = i - cand
                if d > WINDOW:
                    break
                # C-level reject: the byte one past the current best must match
                # before an extension can beat it.
                if data[cand + best_len] == data[i + best_len]:
                    ln = 0
                    while ln < limit and data[cand + ln] == data[i + ln]:
                        ln += 1
                    if ln > best_len:
                        best_len = ln
                        best_dist = d
                        if ln >= limit:
                            break
                cand = prev[cand]
                chain += 1

        if best_len >= MIN_MATCH:
            sym, eb, ev = len_map[best_len]
            c, nb = rev_lit[sym]
            put(c, nb)
            if eb:
                put(ev, eb)
            ds, deb, dev = dist_map[best_dist]
            c, nb = rev_dist[ds]
            put(c, nb)
            if deb:
                put(dev, deb)
            step = best_len
        else:
            c, nb = rev_lit[data[i]]
            put(c, nb)
            step = 1

        # Index every position the token covered, so a later match can still
        # find text that this one skipped over.
        end = i + step
        if end > stop:
            end = stop
        k = i
        while k < end:
            key = (data[k] << 16) | (data[k + 1] << 8) | data[k + 2]
            prev[k] = head.get(key, -1)
            head[key] = k
            k += 1
        i += step

    put(_END_OF_BLOCK[0], _END_OF_BLOCK[1])
    bw.align()
    out = bytes(bw.out)

    # zlib's inflater is an independent implementation. If it disagrees with us
    # the fixture is wrong, and the build must stop here rather than ship a
    # corpus that only our own reader can open.
    if zlib.decompress(out, -15) != data:
        raise AssertionError("fixtures/deflate.py failed its zlib round trip")
    return out


def zlib_wrap(data: bytes) -> bytes:
    """RFC 1950 stream: 0x78 0x01 header, our raw DEFLATE, big-endian Adler-32.

    0x78 = CM 8 / CINFO 7 (32 KiB window); 0x01 = FCHECK making the 16-bit
    header a multiple of 31, FDICT 0, FLEVEL 0.  Adler-32 is a fixed algorithm,
    so zlib.adler32 carries no build dependence.
    """
    return (b"\x78\x01" + deflate_raw(data)
            + struct.pack(">I", zlib.adler32(data) & 0xFFFFFFFF))
