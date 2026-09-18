from __future__ import annotations

import struct
import zlib

__all__ = ["deflate_raw", "zlib_wrap", "WINDOW", "MIN_MATCH", "MAX_MATCH", "MAX_CHAIN"]

WINDOW = 32768
MIN_MATCH = 3
MAX_MATCH = 258

MAX_CHAIN = 24

_LEN_BASE = (3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43,
             51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258)
_LEN_EXTRA = (0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
              4, 4, 4, 4, 5, 5, 5, 5, 0)

_DIST_BASE = (1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257,
              385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
              16385, 24577)
_DIST_EXTRA = (0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
               9, 9, 10, 10, 11, 11, 12, 12, 13, 13)

_LEN_MAP: list[tuple[int, int, int]] = [(0, 0, 0)] * (MAX_MATCH + 1)
for _i in range(len(_LEN_BASE)):
    _base = _LEN_BASE[_i]
    _eb = _LEN_EXTRA[_i]
    for _k in range(1 << _eb):
        if _base + _k <= MAX_MATCH:
            _LEN_MAP[_base + _k] = (257 + _i, _eb, _k)
_LEN_MAP[258] = (285, 0, 0)

_DIST_MAP: list[tuple[int, int, int]] = [(0, 0, 0)] * (WINDOW + 1)
for _i in range(len(_DIST_BASE)):
    _base = _DIST_BASE[_i]
    _eb = _DIST_EXTRA[_i]
    for _k in range(1 << _eb):
        if _base + _k <= WINDOW:
            _DIST_MAP[_base + _k] = (_i, _eb, _k)


def _fixed_litlen_code(sym: int) -> tuple[int, int]:
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


_REV_LITLEN: list[tuple[int, int]] = []
for _s in range(288):
    _c, _n = _fixed_litlen_code(_s)
    _REV_LITLEN.append((_bitrev(_c, _n), _n))

_REV_DIST: list[tuple[int, int]] = [(_bitrev(_s, 5), 5) for _s in range(30)]

_END_OF_BLOCK = _REV_LITLEN[256]


class _Bits:
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
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("deflate_raw takes bytes, got %r" % type(data).__name__)
    data = bytes(data)

    bw = _Bits()
    bw.put(1, 1)
    bw.put(1, 2)

    n = len(data)
    put = bw.put
    rev_lit = _REV_LITLEN
    rev_dist = _REV_DIST
    len_map = _LEN_MAP
    dist_map = _DIST_MAP

    head: dict[int, int] = {}
    prev = [-1] * n
    stop = n - 2

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

    if zlib.decompress(out, -15) != data:
        raise AssertionError("fixtures/deflate.py failed its zlib round trip")
    return out


def zlib_wrap(data: bytes) -> bytes:
    return (b"\x78\x01" + deflate_raw(data)
            + struct.pack(">I", zlib.adler32(data) & 0xFFFFFFFF))
