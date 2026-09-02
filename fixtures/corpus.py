"""The 40-file forensic corpus: real encoders, one seed, no clock.

Phase 2 does structure-aware carving -- a JPEG segment walk to EOI, PNG chunk
CRCs, a PDF xref that points at a real byte offset, a ZIP central directory, a
SQLite page header, an MP4 `ftyp` box tree.  A magic header wrapped around
random bytes would make the carver's structural term untestable, so nothing
here is a stub: every generator below is a real encoder for its format, and
every file is checked by an INDEPENDENT decoder before it is believed
(`sips`, `afinfo`, Info-ZIP `unzip -t`, `gzip -t`, the `sqlite3` module,
zlib's inflater).

Determinism, per CLAUDE.md rule 6 and docs/architecture.md D1:

  * Every byte descends from the seed through `hashlib.shake_128` in counter
    mode.  Nothing reads the clock, the host filesystem, a uuid, the locale,
    or the stdlib pseudo-random module, and there is no PYTHONHASHSEED
    dependence: nothing iterates a set and no dict ordering reaches the output.
  * DEFLATE comes from `fixtures/deflate.py`, never from the linked libz --
    two encoders produced 13,937 and 14,066 bytes for identical input.  `zlib`
    appears here only as crc32 (a fixed algorithm) and as an inflater used to
    verify what we wrote.
  * SQLite databases are laid out page by page from the on-disk format spec
    rather than built through the `sqlite3` module, because the module's
    physical layout moves between library versions -- measured, 5 of 35 pages
    differed between SQLite 3.53.4 and 3.51.0 for identical statements.  The
    module is then used as the independent reader.
  * Every format field that normally carries a timestamp, a host name, a
    process id or a library version is pinned: gzip MTIME/OS, ZIP DOS
    date/time, PDF /CreationDate and /ID, PNG (tIME omitted entirely),
    QuickTime mvhd/tkhd/mdhd creation times, the SQLite header's
    version-valid-for and write-library fields.

Container note, MEASURED on this machine: CoreAudio dispatches on the file
extension.  The same bytes -- major brand `qt  `, a 16-bit PCM (`sowt`) track --
open under `afinfo` as `.mov` and are refused as `.mp4` or `.m4a`
("AudioFileOpenURL failed").  The five files in the MP4 family are therefore
named `.mov` so their structural validity is checkable by a decoder we did not
write.  The carver is unaffected: its signature is the `ftyp` atom at offset 4
and the box tree beneath it, which are the same in both containers.
"""

from __future__ import annotations

import hashlib
import math
import struct
import zlib  # crc32 / adler32 / inflate ONLY. Compression is fixtures/deflate.py.
from collections import Counter
from dataclasses import dataclass

try:  # imported as a package member (from fixtures import corpus)
    from .deflate import deflate_raw, zlib_wrap
except ImportError:  # imported as a top-level module (sys.path has fixtures/)
    from deflate import deflate_raw, zlib_wrap

__all__ = [
    "CorpusFile", "generate_corpus", "DetRandom", "shannon_bits_per_byte",
    "KINDS", "CORPUS_NAMES", "NAMES_BY_KIND", "FIRST_OF_KIND", "LAST_OF_KIND",
    "FRAGMENTATION_SLOTS", "DELETED_CONTIGUOUS_CANDIDATES",
]


# --------------------------------------------------------------------------
# 1 · determinism primitives
# --------------------------------------------------------------------------

class DetRandom:
    """SHAKE-128 in counter mode. Same seed and label -> same bytes, anywhere.

    The stdlib pseudo-random module is reproducible for its raw bit source but
    not for shuffle, sample and choices, whose algorithms have changed between
    CPython releases.  A sponge in counter mode is bit-exact on every platform
    that has hashlib, and it is auditable in fifteen lines.
    """

    __slots__ = ("_key", "_ctr", "_buf", "_pos")

    BLOCK = 64

    def __init__(self, seed: bytes | str, label: str = "") -> None:
        if isinstance(seed, str):
            seed = seed.encode("utf-8")
        self._key = hashlib.shake_128(
            seed + b"\x1f" + label.encode("utf-8")).digest(32)
        self._ctr = 0
        self._buf = b""
        self._pos = 0

    def _refill(self) -> None:
        self._buf = hashlib.shake_128(
            self._key + struct.pack(">Q", self._ctr)).digest(self.BLOCK)
        self._ctr += 1
        self._pos = 0

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            if self._pos >= len(self._buf):
                self._refill()
            take = min(n - len(out), len(self._buf) - self._pos)
            out += self._buf[self._pos:self._pos + take]
            self._pos += take
        return bytes(out)

    def below(self, n: int) -> int:
        """Uniform int in [0, n) by rejection sampling. No float arithmetic,
        so no rounding mode can differ between builds."""
        if n <= 0:
            raise ValueError("n must be positive")
        if n == 1:
            return 0
        bits = (n - 1).bit_length()
        nbytes = (bits + 7) // 8
        mask = (1 << bits) - 1
        while True:
            v = int.from_bytes(self.bytes(nbytes), "big") & mask
            if v < n:
                return v

    def between(self, lo: int, hi: int) -> int:
        """Uniform int in [lo, hi], both ends included."""
        return lo + self.below(hi - lo + 1)

    def pick(self, seq):
        return seq[self.below(len(seq))]


def shannon_bits_per_byte(data: bytes) -> float:
    """Shannon entropy of the byte histogram. The whole-image figure in the
    manifest is this function's output, so the demo's entropy line traces to a
    measurement rather than to an assertion.

    Two determinism details, both deliberate:

    * The histogram is exact integer counting, and it is written into a
      fixed 256-slot list, so nothing depends on iteration order. Counter is
      the C-level counter and is twice as fast as a Python loop over 268 MB.
    * math.fsum, not a running subtraction. fsum is exactly rounded and
      order-independent, so the only floating-point freedom left in the
      result is math.log2 itself. MEASURED on the shipped image: the value is
      7.061690499603866 and the nearest 6-decimal rounding boundary is
      3.96e-10 away, while a worst-case 1-ULP log2 disagreement across 256
      terms moves it by ~2e-13. The rounded value in the manifest therefore
      cannot flip on a different libm, which is what rule 5 requires of it.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for value, occurrences in Counter(data).items():
        counts[value] = occurrences
    n = len(data)
    return math.fsum(-(c / n) * math.log2(c / n) for c in counts if c)


# --------------------------------------------------------------------------
# 2 · prose
# --------------------------------------------------------------------------

_VOCAB = (
    "sector cluster extent residue platter spindle allocation journal inode "
    "signature entropy carve verify certificate ledger merkle anchor witness "
    "overwrite purge sanitize degauss firmware controller namespace partition "
    "checksum manifest fragment offset boundary heuristic threshold recovery "
    "chain integrity attest revoke quorum retention custody evidence exhibit "
    "acquisition imaging hashing baseline telemetry throughput latency device "
    "operator reviewed measured declared unverifiable degraded nominal remap "
    "overprovision leveling superblock bitmap digest timestamp examiner seal"
).split()

_HEADINGS = (
    "ACQUISITION LOG", "CHAIN OF CUSTODY", "SECTOR SURVEY", "RESIDUE ANALYSIS",
    "VERIFICATION PASS", "CONTROLLER RESPONSE", "MEDIA CLASSIFICATION",
    "HANDOVER RECORD", "DISPOSAL AUTHORITY", "BENCH OBSERVATION",
)


def _prose(rnd: DetRandom, target_bytes: int, title: str) -> str:
    """English-shaped ASCII. The letter distribution puts byte entropy near
    4.2 bits/byte, far from the 7.9+ of the compressed formats. That spread is
    the whole reason the confidence function's entropy term is testable."""
    parts = ["SENTINELWIPE FIXTURE RECORD -- %s\n" % title, "=" * 72 + "\n\n"]
    total = sum(len(p) for p in parts)
    section = 0
    while total < target_bytes:
        section += 1
        head = "%s %03d\n%s\n\n" % (rnd.pick(_HEADINGS), section, "-" * 40)
        parts.append(head)
        total += len(head)
        for _ in range(rnd.between(4, 9)):
            words = [rnd.pick(_VOCAB) for _ in range(rnd.between(9, 22))]
            words[0] = words[0].capitalize()
            sentence = " ".join(words) + rnd.pick((".", ".", ".", ";", "?"))
            wrapped = [sentence[i:i + 76] for i in range(0, len(sentence), 76)]
            block = "\n".join(wrapped) + "\n"
            parts.append(block)
            total += len(block)
        parts.append("\n")
        total += 1
    return "".join(parts)


def _build_txt(rnd: DetRandom, target_bytes: int, title: str) -> bytes:
    return _prose(rnd, target_bytes, title).encode("ascii")


# --------------------------------------------------------------------------
# 3 · synthetic imagery
# --------------------------------------------------------------------------

def _photo_rgb(rnd: DetRandom, width: int, height: int, noise: int) -> bytes:
    """Photograph-like RGB: a smooth bilinear field plus sensor-like grain.

    Integer arithmetic only -- no libm, because `cos` is not required to be
    correctly rounded and a last-ulp difference would move quantised JPEG
    coefficients.  A pure gradient compresses to almost nothing and would leave
    PNG entropy near 1 bit/byte; real photographs carry grain, and the grain is
    also what gives the JPEG encoder non-trivial AC coefficients to code.
    """
    gw, gh = 9, 9
    lattice = [[tuple(rnd.bytes(3)) for _ in range(gw)] for _ in range(gh)]
    grain = rnd.bytes(width * height * 3)

    out = bytearray(width * height * 3)
    for y in range(height):
        fy = (y * (gh - 1) * 256) // max(1, height - 1) if height > 1 else 0
        y0 = min(fy >> 8, gh - 2)
        wy = fy - (y0 << 8)
        row0 = lattice[y0]
        row1 = lattice[y0 + 1]
        for x in range(width):
            fx = (x * (gw - 1) * 256) // max(1, width - 1) if width > 1 else 0
            x0 = min(fx >> 8, gw - 2)
            wx = fx - (x0 << 8)
            base = (y * width + x) * 3
            p00 = row0[x0]
            p01 = row0[x0 + 1]
            p10 = row1[x0]
            p11 = row1[x0 + 1]
            for c in range(3):
                top = p00[c] * (256 - wx) + p01[c] * wx
                bot = p10[c] * (256 - wx) + p11[c] * wx
                v = (top * (256 - wy) + bot * wy) >> 16
                v += (grain[base + c] - 128) * noise // 128
                out[base + c] = 0 if v < 0 else (255 if v > 255 else v)
    return bytes(out)


# --------------------------------------------------------------------------
# 4 · PNG
# --------------------------------------------------------------------------

_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + kind + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF))


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _build_png(pixels: bytes, width: int, height: int, text: dict,
               idat_chunk_size: int | None) -> bytes:
    """Truecolour 8-bit PNG, filter type rotated per scanline.

    `idat_chunk_size` is the knob the extent planner needs.  None emits ONE
    opaque IDAT holding the whole zlib stream; an integer splits it into chunks
    of that many bytes.  The contrast matters and is invisible unless both
    shapes are on the disk: a single-IDAT PNG gives the carver one length field
    to trust, while a PNG cut into 8192-byte IDATs gives it a chunk boundary
    every two clusters, and the cost of validating a candidate extent order
    moves by roughly an order of magnitude between the two.  The old generator
    hardcoded 32768 and neither case was representable.

    No tIME chunk: it would be a clock reference. tEXt is ASCII and carries none.
    """
    bpp = 3
    stride = width * bpp
    raw = bytearray()
    prev = bytes(stride)
    for y in range(height):
        line = pixels[y * stride:(y + 1) * stride]
        ftype = (0, 1, 2, 3, 4)[y % 5]  # deterministic rotation, all 5 exercised
        enc = bytearray(stride)
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            x = line[i]
            if ftype == 0:
                enc[i] = x
            elif ftype == 1:
                enc[i] = (x - a) & 0xFF
            elif ftype == 2:
                enc[i] = (x - b) & 0xFF
            elif ftype == 3:
                enc[i] = (x - ((a + b) >> 1)) & 0xFF
            else:
                enc[i] = (x - _paeth(a, b, c)) & 0xFF
        raw.append(ftype)
        raw += enc
        prev = line

    out = bytearray(_PNG_SIG)
    out += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    for k in sorted(text):  # sorted: dict insertion order never reaches the bytes
        out += _png_chunk(b"tEXt",
                          k.encode("latin-1") + b"\x00" + text[k].encode("latin-1"))
    stream = zlib_wrap(bytes(raw))
    if idat_chunk_size is None:
        out += _png_chunk(b"IDAT", stream)
    else:
        for off in range(0, len(stream), idat_chunk_size):
            out += _png_chunk(b"IDAT", stream[off:off + idat_chunk_size])
    out += _png_chunk(b"IEND", b"")
    return bytes(out)


# --------------------------------------------------------------------------
# 5 · JPEG -- baseline sequential, integer only
# --------------------------------------------------------------------------
#
# The forward DCT is libjpeg's `jpeg_fdct_islow` (jfdctint.c) reimplemented in
# Python.  It is fixed-point integer, so no call reaches libm.  A float DCT
# built from math.cos would be a cross-platform hazard: cos is not required to
# be correctly rounded, and a last-ulp difference flips a quantised coefficient
# and changes every byte after it in the entropy-coded stream.

_CONST_BITS = 13
_PASS1_BITS = 2
_F_0_298631336 = 2446
_F_0_390180644 = 3196
_F_0_541196100 = 4433
_F_0_765366865 = 6270
_F_0_899976223 = 7373
_F_1_175875602 = 9633
_F_1_501321110 = 12299
_F_1_847759065 = 15137
_F_1_961570560 = 16069
_F_2_053119869 = 16819
_F_2_562915447 = 20995
_F_3_072711026 = 25172

_ZIGZAG = (
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
)

# ITU-T T.81 Annex K.1 sample quantisation tables (the quality-50 baseline).
_QUANT_LUMA_50 = (
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
)
_QUANT_CHROMA_50 = (
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
)

# ITU-T T.81 Annex K.3 sample Huffman tables.
_DC_LUMA_BITS = (0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0)
_DC_CHROMA_BITS = (0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0)
_DC_VALS = tuple(range(12))

_AC_LUMA_BITS = (0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D)
_AC_LUMA_VALS = (
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
    0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
    0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
    0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
    0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
    0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
    0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
    0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
    0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4,
    0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
)
_AC_CHROMA_BITS = (0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77)
_AC_CHROMA_VALS = (
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41,
    0x51, 0x07, 0x61, 0x71, 0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91,
    0xA1, 0xB1, 0xC1, 0x09, 0x23, 0x33, 0x52, 0xF0, 0x15, 0x62, 0x72, 0xD1,
    0x0A, 0x16, 0x24, 0x34, 0xE1, 0x25, 0xF1, 0x17, 0x18, 0x19, 0x1A, 0x26,
    0x27, 0x28, 0x29, 0x2A, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A,
    0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4,
    0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
    0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF2, 0xF3, 0xF4,
    0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
)


def _scale_quant(base, quality: int) -> list[int]:
    """IJG quality scaling, integer only."""
    q = max(1, min(100, quality))
    scale = 5000 // q if q < 50 else 200 - q * 2
    return [max(1, min(255, (v * scale + 50) // 100)) for v in base]


def _huff_table(bits, vals) -> dict:
    """BITS/HUFFVAL -> {symbol: (code, length)}, per T.81 Annex C."""
    codes = {}
    code = 0
    k = 0
    for length in range(1, 17):
        for _ in range(bits[length - 1]):
            codes[vals[k]] = (code, length)
            k += 1
            code += 1
        code <<= 1
    return codes


def _descale(x: int, n: int) -> int:
    return (x + (1 << (n - 1))) >> n


def _fdct_islow(d: list[int]) -> list[int]:
    """libjpeg jpeg_fdct_islow. Output is scaled up by 8 against a true DCT."""
    for ctr in range(8):
        o = ctr * 8
        t0 = d[o + 0] + d[o + 7]; t7 = d[o + 0] - d[o + 7]
        t1 = d[o + 1] + d[o + 6]; t6 = d[o + 1] - d[o + 6]
        t2 = d[o + 2] + d[o + 5]; t5 = d[o + 2] - d[o + 5]
        t3 = d[o + 3] + d[o + 4]; t4 = d[o + 3] - d[o + 4]

        t10 = t0 + t3; t13 = t0 - t3
        t11 = t1 + t2; t12 = t1 - t2

        d[o + 0] = (t10 + t11) << _PASS1_BITS
        d[o + 4] = (t10 - t11) << _PASS1_BITS

        z1 = (t12 + t13) * _F_0_541196100
        d[o + 2] = _descale(z1 + t13 * _F_0_765366865, _CONST_BITS - _PASS1_BITS)
        d[o + 6] = _descale(z1 - t12 * _F_1_847759065, _CONST_BITS - _PASS1_BITS)

        z1 = t4 + t7
        z2 = t5 + t6
        z3 = t4 + t6
        z4 = t5 + t7
        z5 = (z3 + z4) * _F_1_175875602

        t4 *= _F_0_298631336
        t5 *= _F_2_053119869
        t6 *= _F_3_072711026
        t7 *= _F_1_501321110
        z1 *= -_F_0_899976223
        z2 *= -_F_2_562915447
        z3 = z3 * -_F_1_961570560 + z5
        z4 = z4 * -_F_0_390180644 + z5

        d[o + 7] = _descale(t4 + z1 + z3, _CONST_BITS - _PASS1_BITS)
        d[o + 5] = _descale(t5 + z2 + z4, _CONST_BITS - _PASS1_BITS)
        d[o + 3] = _descale(t6 + z2 + z3, _CONST_BITS - _PASS1_BITS)
        d[o + 1] = _descale(t7 + z1 + z4, _CONST_BITS - _PASS1_BITS)

    for ctr in range(8):
        t0 = d[ctr + 0] + d[ctr + 56]; t7 = d[ctr + 0] - d[ctr + 56]
        t1 = d[ctr + 8] + d[ctr + 48]; t6 = d[ctr + 8] - d[ctr + 48]
        t2 = d[ctr + 16] + d[ctr + 40]; t5 = d[ctr + 16] - d[ctr + 40]
        t3 = d[ctr + 24] + d[ctr + 32]; t4 = d[ctr + 24] - d[ctr + 32]

        t10 = t0 + t3; t13 = t0 - t3
        t11 = t1 + t2; t12 = t1 - t2

        d[ctr + 0] = _descale(t10 + t11, _PASS1_BITS)
        d[ctr + 32] = _descale(t10 - t11, _PASS1_BITS)

        z1 = (t12 + t13) * _F_0_541196100
        d[ctr + 16] = _descale(z1 + t13 * _F_0_765366865, _CONST_BITS + _PASS1_BITS)
        d[ctr + 48] = _descale(z1 - t12 * _F_1_847759065, _CONST_BITS + _PASS1_BITS)

        z1 = t4 + t7
        z2 = t5 + t6
        z3 = t4 + t6
        z4 = t5 + t7
        z5 = (z3 + z4) * _F_1_175875602

        t4 *= _F_0_298631336
        t5 *= _F_2_053119869
        t6 *= _F_3_072711026
        t7 *= _F_1_501321110
        z1 *= -_F_0_899976223
        z2 *= -_F_2_562915447
        z3 = z3 * -_F_1_961570560 + z5
        z4 = z4 * -_F_0_390180644 + z5

        d[ctr + 56] = _descale(t4 + z1 + z3, _CONST_BITS + _PASS1_BITS)
        d[ctr + 40] = _descale(t5 + z2 + z4, _CONST_BITS + _PASS1_BITS)
        d[ctr + 24] = _descale(t6 + z2 + z3, _CONST_BITS + _PASS1_BITS)
        d[ctr + 8] = _descale(t7 + z1 + z4, _CONST_BITS + _PASS1_BITS)
    return d


class _JpegBits:
    """MSB-first bit packer with the mandatory 0xFF -> 0xFF 0x00 stuffing."""

    __slots__ = ("out", "acc", "nbits")

    def __init__(self) -> None:
        self.out = bytearray()
        self.acc = 0
        self.nbits = 0

    def write(self, code: int, length: int) -> None:
        if length == 0:
            return
        self.acc = (self.acc << length) | (code & ((1 << length) - 1))
        self.nbits += length
        while self.nbits >= 8:
            self.nbits -= 8
            byte = (self.acc >> self.nbits) & 0xFF
            self.out.append(byte)
            if byte == 0xFF:
                self.out.append(0x00)
        self.acc &= (1 << self.nbits) - 1

    def flush(self) -> None:
        if self.nbits:
            pad = 8 - self.nbits
            self.write((1 << pad) - 1, pad)  # pad with 1 bits, per T.81


def _magnitude(v: int) -> tuple[int, int]:
    if v == 0:
        return 0, 0
    cat = abs(v).bit_length()
    return cat, (v if v > 0 else v + (1 << cat) - 1)


def _encode_block(bw: _JpegBits, zz, prev_dc: int, dc_tab: dict, ac_tab: dict) -> int:
    cat, bits = _magnitude(zz[0] - prev_dc)
    code, ln = dc_tab[cat]
    bw.write(code, ln)
    bw.write(bits, cat)

    run = 0
    for k in range(1, 64):
        v = zz[k]
        if v == 0:
            run += 1
            continue
        while run > 15:
            c, l = ac_tab[0xF0]  # ZRL
            bw.write(c, l)
            run -= 16
        cat, bits = _magnitude(v)
        c, l = ac_tab[(run << 4) | cat]
        bw.write(c, l)
        bw.write(bits, cat)
        run = 0
    if run > 0:
        c, l = ac_tab[0x00]  # EOB
        bw.write(c, l)
    return zz[0]


def _seg(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def _build_jpeg(pixels: bytes, width: int, height: int, quality: int,
                comment: bytes) -> bytes:
    """Packed RGB8 -> baseline sequential JFIF, 4:4:4, Annex K tables.

    4:4:4 (no chroma subsampling) keeps the scan interleave one block per
    component per MCU, which keeps the entropy-coded stream a single ordered
    walk the carver's structure check can follow.
    """
    if len(pixels) != width * height * 3:
        raise ValueError("pixel buffer is %d bytes, expected %d"
                         % (len(pixels), width * height * 3))

    ql = _scale_quant(_QUANT_LUMA_50, quality)
    qc = _scale_quant(_QUANT_CHROMA_50, quality)

    npix = width * height
    Y = bytearray(npix)
    CB = bytearray(npix)
    CR = bytearray(npix)
    for i in range(npix):
        r = pixels[3 * i]
        g = pixels[3 * i + 1]
        b = pixels[3 * i + 2]
        y = (19595 * r + 38470 * g + 7471 * b + 32768) >> 16
        cb = (-11056 * r - 21712 * g + 32768 * b + 8421376) >> 16
        cr = (32768 * r - 27440 * g - 5328 * b + 8421376) >> 16
        Y[i] = 0 if y < 0 else (255 if y > 255 else y)
        CB[i] = 0 if cb < 0 else (255 if cb > 255 else cb)
        CR[i] = 0 if cr < 0 else (255 if cr > 255 else cr)

    dc_l = _huff_table(_DC_LUMA_BITS, _DC_VALS)
    ac_l = _huff_table(_AC_LUMA_BITS, _AC_LUMA_VALS)
    dc_c = _huff_table(_DC_CHROMA_BITS, _DC_VALS)
    ac_c = _huff_table(_AC_CHROMA_BITS, _AC_CHROMA_VALS)

    out = bytearray(b"\xFF\xD8")  # SOI
    out += _seg(0xE0, b"JFIF\x00" + bytes([1, 2, 1])
                + struct.pack(">HH", 72, 72) + b"\x00\x00")
    if comment:
        out += _seg(0xFE, comment)  # COM
    out += _seg(0xDB, bytes([0x00]) + bytes(ql[_ZIGZAG[i]] for i in range(64)))
    out += _seg(0xDB, bytes([0x01]) + bytes(qc[_ZIGZAG[i]] for i in range(64)))
    sof = bytes([8]) + struct.pack(">HH", height, width) + bytes([3])
    sof += bytes([1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1])
    out += _seg(0xC0, sof)  # SOF0, baseline
    out += _seg(0xC4, bytes([0x00]) + bytes(_DC_LUMA_BITS) + bytes(_DC_VALS))
    out += _seg(0xC4, bytes([0x10]) + bytes(_AC_LUMA_BITS) + bytes(_AC_LUMA_VALS))
    out += _seg(0xC4, bytes([0x01]) + bytes(_DC_CHROMA_BITS) + bytes(_DC_VALS))
    out += _seg(0xC4, bytes([0x11]) + bytes(_AC_CHROMA_BITS) + bytes(_AC_CHROMA_VALS))
    out += _seg(0xDA, bytes([3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]))  # SOS

    bw = _JpegBits()
    pdc = [0, 0, 0]
    planes = (Y, CB, CR)
    tabs = ((dc_l, ac_l, ql), (dc_c, ac_c, qc), (dc_c, ac_c, qc))
    mcux = (width + 7) // 8
    mcuy = (height + 7) // 8
    zigzag = _ZIGZAG
    for by in range(mcuy):
        for bx in range(mcux):
            for ci in range(3):
                plane = planes[ci]
                blk = [0] * 64
                for r in range(8):
                    sy = by * 8 + r
                    if sy >= height:
                        sy = height - 1
                    row = sy * width
                    for c in range(8):
                        sx = bx * 8 + c
                        if sx >= width:
                            sx = width - 1
                        blk[r * 8 + c] = plane[row + sx] - 128
                coefs = _fdct_islow(blk)
                dct, act, qt = tabs[ci]
                zz = [0] * 64
                for i in range(64):
                    j = zigzag[i]
                    qval = qt[j] * 8
                    t = coefs[j]
                    if t < 0:
                        zz[i] = -((-t + (qval >> 1)) // qval)
                    else:
                        zz[i] = (t + (qval >> 1)) // qval
                pdc[ci] = _encode_block(bw, zz, pdc[ci], dct, act)
    bw.flush()
    out += bw.out
    out += b"\xFF\xD9"  # EOI
    return bytes(out)


# --------------------------------------------------------------------------
# 6 · PDF
# --------------------------------------------------------------------------

def _pdf_esc(s: str) -> str:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _build_pdf(rnd: DetRandom, title: str, pages: int, blob_bytes: int) -> bytes:
    """PDF 1.7 with a cross-reference table computed from real object offsets.

    The carver's PDF check looks for `xref`, a trailer carrying /Root, and a
    `startxref` byte offset that actually lands on the xref keyword.  That only
    means anything if the offsets come from where the objects really are, which
    is what the assembly loop below does.  /CreationDate and /ID are normally a
    clock and a random nonce; both are pinned to the seed here.
    """
    objs: list[bytes] = []

    def add(body: bytes) -> int:
        objs.append(body)
        return len(objs)  # object numbers are 1-based

    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier "
               b"/Encoding /WinAnsiEncoding >>")
    # An embedded octet-stream: this is where a PDF gets its high-entropy region,
    # which is what pulls the format off the plain-text end of the entropy scale.
    blob = zlib_wrap(rnd.bytes(blob_bytes))
    attach = add(b"<< /Type /EmbeddedFile /Subtype /application#2Foctet-stream"
                 b" /Filter /FlateDecode /Length " + str(len(blob)).encode()
                 + b" >>\nstream\n" + blob + b"\nendstream")

    pages_obj = add(b"PLACEHOLDER")  # reserved so each /Page can point at it
    page_ids = []
    for p in range(pages):
        lines = ["SENTINELWIPE %s -- page %d of %d" % (title, p + 1, pages),
                 "-" * 68]
        for _ in range(44):
            lines.append(" ".join(rnd.pick(_VOCAB) for _ in range(9)))
        ops = [b"BT /F1 10 Tf 54 738 Td 12 TL"]
        for ln in lines:
            ops.append(b"(" + _pdf_esc(ln).encode("latin-1") + b") Tj T*")
        ops.append(b"ET")
        ops.append(b"0.5 w 54 726 m 558 726 l S")  # a real vector rule
        stream = zlib_wrap(b"\n".join(ops) + b"\n")
        cid = add(b"<< /Filter /FlateDecode /Length " + str(len(stream)).encode()
                  + b" >>\nstream\n" + stream + b"\nendstream")
        page_ids.append(add(
            b"<< /Type /Page /Parent " + str(pages_obj).encode()
            + b" 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 "
            + str(font).encode() + b" 0 R >> >> /Contents "
            + str(cid).encode() + b" 0 R >>"))

    kids = b" ".join(str(p).encode() + b" 0 R" for p in page_ids)
    objs[pages_obj - 1] = (b"<< /Type /Pages /Count " + str(pages).encode()
                           + b" /Kids [" + kids + b"] >>")
    names = add(b"<< /Names [(residue.bin) << /Type /Filespec /F (residue.bin)"
                b" /EF << /F " + str(attach).encode() + b" 0 R >> >>] >>")
    catalog = add(b"<< /Type /Catalog /Pages " + str(pages_obj).encode()
                  + b" 0 R /Names << /EmbeddedFiles " + str(names).encode()
                  + b" 0 R >> >>")
    info = add(b"<< /Title (" + _pdf_esc(title).encode("latin-1")
               + b") /Producer (SENTINELWIPE fixture generator) "
               b"/Creator (SENTINELWIPE) /CreationDate (D:20260101000000Z) "
               b"/ModDate (D:20260101000000Z) >>")

    out = bytearray(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")
    offsets = [0] * (len(objs) + 1)
    for i, body in enumerate(objs, start=1):
        offsets[i] = len(out)
        out += str(i).encode() + b" 0 obj\n" + body + b"\nendobj\n"

    xref_at = len(out)
    out += b"xref\n0 " + str(len(objs) + 1).encode() + b"\n"
    out += b"0000000000 65535 f \n"
    for i in range(1, len(objs) + 1):
        out += ("%010d 00000 n \n" % offsets[i]).encode("ascii")
    doc_id = rnd.bytes(16).hex().upper().encode("ascii")
    out += (b"trailer\n<< /Size " + str(len(objs) + 1).encode()
            + b" /Root " + str(catalog).encode() + b" 0 R /Info "
            + str(info).encode() + b" 0 R /ID [<" + doc_id + b"> <" + doc_id
            + b">] >>\nstartxref\n" + str(xref_at).encode() + b"\n%%EOF\n")
    return bytes(out)


# --------------------------------------------------------------------------
# 7 · ZIP / DOCX
# --------------------------------------------------------------------------

# 2026-01-01 00:00:00 as an MS-DOS date/time pair. Frozen: the zipfile module
# stamps the wall clock into every local header and every central directory
# entry, which is the most common reason two "identical" ZIPs differ.
_DOS_TIME = 0x0000
_DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1

# Version-made-by 0x031E = Unix (3), ZIP spec 3.0. Hardcoded rather than taken
# from the host: the zipfile module derives it from sys.platform, so a Windows
# teammate's archive would differ in the central directory.
_VERSION_MADE_BY = 0x031E
_VERSION_NEEDED = 20
_EXTERNAL_ATTR = 0o644 << 16


def _build_zip(entries: list[tuple[str, bytes]]) -> bytes:
    """A ZIP container written field by field.

    The zipfile module's deflated write path routes the payload through the
    linked libz and would reintroduce exactly the machine dependence
    fixtures/deflate.py exists to remove, so the container is assembled here
    instead, field by field, over our own encoder.
    """
    out = bytearray()
    central = bytearray()
    for name, data in entries:
        nb = name.encode("utf-8")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        comp = deflate_raw(data)
        method = 8
        if len(comp) >= len(data):  # never store an entry larger than its input
            comp, method = data, 0
        offset = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, _VERSION_NEEDED, 0, method,
                           _DOS_TIME, _DOS_DATE, crc, len(comp), len(data),
                           len(nb), 0) + nb + comp
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, _VERSION_MADE_BY,
                               _VERSION_NEEDED, 0, method, _DOS_TIME, _DOS_DATE,
                               crc, len(comp), len(data), len(nb), 0, 0, 0, 0,
                               _EXTERNAL_ATTR, offset) + nb
    cd_at = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
                       len(central), cd_at, 0)
    return bytes(out)


_CT = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
       '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
       '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
       '<Default Extension="xml" ContentType="application/xml"/>'
       '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
       '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
       '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
       '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
       '</Types>')

_ROOT_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
              '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
              '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
              '</Relationships>')

_DOC_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
             '</Relationships>')

_STYLES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Helvetica" w:hAnsi="Helvetica"/>'
           '<w:sz w:val="20"/></w:rPr></w:rPrDefault></w:docDefaults>'
           '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>'
           '<w:pPr><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/></w:rPr></w:style>'
           '<w:style w:type="paragraph" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
           '</w:styles>')


def _xesc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_docx(rnd: DetRandom, title: str, paragraphs: int) -> bytes:
    body = []
    words_total = 0
    for i in range(paragraphs):
        n = rnd.between(8, 26)
        words = " ".join(rnd.pick(_VOCAB) for _ in range(n))
        words_total += n
        style = "Heading1" if i % 25 == 0 else "Normal"
        body.append('<w:p><w:pPr><w:pStyle w:val="%s"/></w:pPr>'
                    '<w:r><w:t xml:space="preserve">[%04d] %s</w:t></w:r></w:p>'
                    % (style, i, _xesc(words)))
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:body>' + "".join(body)
           + '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/></w:sectPr>'
           '</w:body></w:document>')
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties '
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<dc:title>%s</dc:title><dc:creator>SENTINELWIPE</dc:creator>'
            '<cp:lastModifiedBy>SENTINELWIPE</cp:lastModifiedBy>'
            '<dcterms:created xsi:type="dcterms:W3CDTF">2026-01-01T00:00:00Z</dcterms:created>'
            '<dcterms:modified xsi:type="dcterms:W3CDTF">2026-01-01T00:00:00Z</dcterms:modified>'
            '</cp:coreProperties>' % _xesc(title))
    app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           '<Application>SENTINELWIPE fixture generator</Application>'
           '<Paragraphs>%d</Paragraphs><Words>%d</Words><Pages>%d</Pages>'
           '</Properties>' % (paragraphs, words_total, max(1, words_total // 400)))
    return _build_zip([
        ("[Content_Types].xml", _CT.encode("utf-8")),
        ("_rels/.rels", _ROOT_RELS.encode("utf-8")),
        ("word/document.xml", doc.encode("utf-8")),
        ("word/_rels/document.xml.rels", _DOC_RELS.encode("utf-8")),
        ("word/styles.xml", _STYLES.encode("utf-8")),
        ("docProps/core.xml", core.encode("utf-8")),
        ("docProps/app.xml", app.encode("utf-8")),
    ])


# --------------------------------------------------------------------------
# 8 · SQLite -- pages laid out from the on-disk format spec
# --------------------------------------------------------------------------
#
# The sqlite3 MODULE cannot give byte-identical output across laptops: measured,
# the same inserts under SQLite 3.53.4 (uv's CPython 3.11) and 3.51.0 (system
# CPython 3.9) produced databases differing in 5 of 35 pages -- interior b-tree
# pages, not metadata, so freezing header fields is necessary and nowhere near
# sufficient. So the pages are laid out here. Scope is deliberately small: table
# b-trees only, no indices, no overflow pages, no freelist, UTF-8, one interior
# level. The sqlite3 module is then the INDEPENDENT reader that proves it.
#
# Reference: https://sqlite.org/fileformat2.html

_LEAF_TABLE = 0x0D
_INTERIOR_TABLE = 0x05
_SQLITE_PINNED_VERSION = 3045000  # 3.45.0, the floor we normalise every build to


def _varint(n: int) -> bytes:
    """SQLite big-endian base-128 varint. Only non-negative values occur here."""
    if n == 0:
        return b"\x00"
    if n > 0x7FFFFFFFFFFFFFFF:
        raise ValueError(n)
    out = []
    while n:
        out.append(n & 0x7F)
        n >>= 7
    out.reverse()
    return bytes([b | 0x80 for b in out[:-1]] + [out[-1]])


def _int_serial(v: int) -> tuple[int, bytes]:
    if v == 0:
        return 8, b""
    if v == 1:
        return 9, b""
    for st, nbytes in ((1, 1), (2, 2), (3, 3), (4, 4), (5, 6), (6, 8)):
        lo, hi = -(1 << (8 * nbytes - 1)), (1 << (8 * nbytes - 1)) - 1
        if lo <= v <= hi:
            return st, v.to_bytes(nbytes, "big", signed=True)
    raise ValueError(v)


def _record(values) -> bytes:
    """One row as a SQLite record. Pass None for the INTEGER PRIMARY KEY column:
    that column is stored as NULL and the real value lives in the cell rowid."""
    types, body = [], bytearray()
    for v in values:
        if v is None:
            types.append(0)
        elif isinstance(v, int):
            st, raw = _int_serial(v)
            types.append(st)
            body += raw
        elif isinstance(v, str):
            raw = v.encode("utf-8")
            types.append(13 + 2 * len(raw))
            body += raw
        elif isinstance(v, (bytes, bytearray)):
            types.append(12 + 2 * len(v))
            body += bytes(v)
        else:
            raise TypeError(type(v))
    tbytes = b"".join(_varint(t) for t in types)
    hlen = len(tbytes) + 1
    while len(_varint(hlen)) + len(tbytes) != hlen:  # varint width fixpoint
        hlen = len(_varint(hlen)) + len(tbytes)
    return _varint(hlen) + tbytes + bytes(body)


class _SqliteDb:
    def __init__(self, page_size: int = 4096) -> None:
        self.ps = page_size
        # Page 1 is reserved up front: allocating it later would renumber every
        # table root already handed out.
        self.pages: list[bytearray] = [bytearray(page_size)]

    def _new_page(self) -> int:
        self.pages.append(bytearray(self.ps))
        return len(self.pages)  # page numbers are 1-based

    def _write_leaf(self, pageno: int, cells: list[bytes], header_at: int) -> None:
        p = self.pages[pageno - 1]
        content = self.ps
        ptrs = []
        for c in cells:
            content -= len(c)
            p[content:content + len(c)] = c
            ptrs.append(content)
        p[header_at] = _LEAF_TABLE
        struct.pack_into(">H", p, header_at + 1, 0)  # no freeblocks
        struct.pack_into(">H", p, header_at + 3, len(cells))
        struct.pack_into(">H", p, header_at + 5, content & 0xFFFF)  # 0 means 65536
        p[header_at + 7] = 0                                        # fragmented bytes
        for i, off in enumerate(ptrs):
            struct.pack_into(">H", p, header_at + 8 + 2 * i, off)

    def _write_interior(self, pageno: int, children, rightmost: int) -> None:
        p = self.pages[pageno - 1]
        content = self.ps
        ptrs = []
        for child, key in children:
            cell = struct.pack(">I", child) + _varint(key)
            content -= len(cell)
            p[content:content + len(cell)] = cell
            ptrs.append(content)
        p[0] = _INTERIOR_TABLE
        struct.pack_into(">H", p, 1, 0)
        struct.pack_into(">H", p, 3, len(children))
        struct.pack_into(">H", p, 5, content & 0xFFFF)
        p[7] = 0
        struct.pack_into(">I", p, 8, rightmost)
        for i, off in enumerate(ptrs):
            struct.pack_into(">H", p, 12 + 2 * i, off)

    def add_table(self, rows) -> int:
        """rows: (rowid, values) in ascending rowid order. Returns the root page."""
        root = self._new_page()
        cells = [_varint(len(r)) + _varint(rid) + r
                 for rid, r in ((rid, _record(vals)) for rid, vals in rows)]
        max_local = self.ps - 35
        for c in cells:
            if len(c) > max_local:
                raise ValueError("row needs an overflow page; not supported")
        groups: list[list[bytes]] = [[]]
        used = 8
        for c in cells:
            if used + 2 + len(c) > self.ps:
                groups.append([])
                used = 8
            groups[-1].append(c)
            used += 2 + len(c)
        leaf_pages = []
        idx = 0
        for group in groups:
            pn = self._new_page()
            self._write_leaf(pn, group, 0)
            leaf_pages.append((pn, rows[idx + len(group) - 1][0]))
            idx += len(group)
        if len(leaf_pages) == 1:
            # One leaf needs no interior level: the root becomes the leaf. The
            # leaf was the last page allocated, so popping renumbers nothing.
            only = leaf_pages[0][0]
            self.pages[root - 1] = self.pages[only - 1]
            self.pages.pop(only - 1)
            return root
        self._write_interior(root, leaf_pages[:-1], leaf_pages[-1][0])
        return root

    def finish(self, schema) -> bytes:
        """schema rows: (type, name, tbl_name, rootpage, sql), written into
        page 1's sqlite_master leaf, which begins after the 100-byte header."""
        cells = []
        for i, row in enumerate(schema, start=1):
            rec = _record(list(row))
            cells.append(_varint(len(rec)) + _varint(i) + rec)
        self._write_leaf(1, cells, 100)
        hdr = self.pages[0]
        hdr[0:16] = b"SQLite format 3\x00"
        struct.pack_into(">H", hdr, 16, 1 if self.ps == 65536 else self.ps)
        hdr[18] = 1   # write version: legacy rollback journal
        hdr[19] = 1   # read version
        hdr[20] = 0   # reserved bytes per page
        hdr[21], hdr[22], hdr[23] = 64, 32, 32  # payload fractions, spec defaults
        struct.pack_into(">I", hdr, 24, 1)                # change counter
        struct.pack_into(">I", hdr, 28, len(self.pages))  # database size in pages
        struct.pack_into(">I", hdr, 32, 0)                # freelist trunk page
        struct.pack_into(">I", hdr, 36, 0)                # freelist page count
        struct.pack_into(">I", hdr, 40, len(schema))      # schema cookie
        struct.pack_into(">I", hdr, 44, 4)                # schema format 4
        struct.pack_into(">I", hdr, 48, 0)                # default page cache size
        struct.pack_into(">I", hdr, 52, 0)                # largest root (no autovacuum)
        struct.pack_into(">I", hdr, 56, 1)                # text encoding: UTF-8
        struct.pack_into(">I", hdr, 60, 0)                # user version
        struct.pack_into(">I", hdr, 64, 0)                # incremental vacuum
        struct.pack_into(">I", hdr, 68, 0)                # application id
        struct.pack_into(">I", hdr, 92, 1)                # version-valid-for
        struct.pack_into(">I", hdr, 96, _SQLITE_PINNED_VERSION)
        return b"".join(bytes(p) for p in self.pages)


_SQL_CUSTODY = ("CREATE TABLE custody (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, "
                "actor TEXT NOT NULL, action TEXT NOT NULL, media TEXT NOT NULL, "
                "lba INTEGER NOT NULL, digest TEXT NOT NULL)")
_SQL_SECTOR = ("CREATE TABLE sector (id INTEGER PRIMARY KEY, lba INTEGER, "
               "pattern TEXT, passes INTEGER, verified INTEGER)")

_ACTORS = ("operator.a", "operator.b", "auditor", "ntro.reviewer", "bench.tech")
_ACTIONS = ("mount", "carve", "wipe", "verify", "sign", "anchor", "quarantine")
_MEDIA = ("sata-hdd", "nvme-ssd", "usb-flash", "sd-card", "emmc")
_PATTERNS = ("0x00", "0xFF", "random", "0x55", "0xAA")


def _build_sqlite(rnd: DetRandom, rows: int, page_size: int = 4096) -> bytes:
    custody = []
    for i in range(rows):
        custody.append((i + 1, [
            None,
            # Timestamps come from the row index, never from the clock.
            "2026-01-%02dT%02d:%02d:%02dZ" % (1 + i % 28, i % 24,
                                              (i * 7) % 60, (i * 13) % 60),
            rnd.pick(_ACTORS),
            rnd.pick(_ACTIONS),
            rnd.pick(_MEDIA),
            rnd.between(0, 500_000_000),
            rnd.bytes(32).hex(),
        ]))
    sector = []
    for i in range(rows // 2):
        sector.append((i + 1, [None, i * 8, rnd.pick(_PATTERNS),
                               rnd.between(1, 3), i % 2]))
    db = _SqliteDb(page_size=page_size)
    r1 = db.add_table(custody)
    r2 = db.add_table(sector)
    return db.finish([
        ("table", "custody", "custody", r1, _SQL_CUSTODY),
        ("table", "sector", "sector", r2, _SQL_SECTOR),
    ])


# --------------------------------------------------------------------------
# 9 · MP4 / QuickTime -- a real, decodable 16-bit PCM track
# --------------------------------------------------------------------------
#
# A carver's MP4 check is `ftyp` at offset 4 plus a walkable box tree. Writing a
# fake H.264 track would give a box tree no decoder accepts, so the payload is
# 16-bit little-endian PCM ('sowt'), a real codec macOS CoreAudio decodes. That
# makes "structurally valid" an externally checkable claim rather than a
# self-assessment. See the module docstring for the .mov extension measurement.

# 1904-01-01 to 1970-01-01 is 2082844800 s; 1970-01-01 to 2026-01-01 is
# 1767225600 s. Pinned, because left to the clock these three boxes would be the
# loudest nondeterminism in the corpus.
_QT_EPOCH_2026 = 2082844800 + 1767225600
_MATRIX_UNITY = struct.pack(">9i", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)


def _box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + kind + payload


def _pcm_samples(rnd: DetRandom, frames: int, rate: int) -> bytes:
    """Two-channel 16-bit LE: a stepped triangle carrier plus dither.

    Integer only. A sine would need libm; a triangle is exactly representable
    and still a real waveform a decoder renders as a tone. The dither is what
    lifts the byte entropy off the floor a pure tone would sit on.
    """
    out = bytearray(frames * 4)
    period = max(2, rate // 220)  # about 220 Hz
    half = max(1, period // 2)
    dither = rnd.bytes(frames * 2)
    pos = 0
    for i in range(frames):
        t = i % period
        if t < half:
            tri = (t * 2 * 20000) // period - 20000
        else:
            tri = 20000 - ((t - half) * 2 * 20000) // half
        env = 20000 + ((i * 8000) // max(1, frames))
        left = (tri * env) // 28000 + dither[2 * i] - 128
        right = -left // 2 + dither[2 * i + 1] - 128
        struct.pack_into("<hh", out, pos,
                         max(-32768, min(32767, left)),
                         max(-32768, min(32767, right)))
        pos += 4
    return bytes(out)


def _build_mp4(rnd: DetRandom, frames: int, rate: int = 44100) -> bytes:
    audio = _pcm_samples(rnd, frames, rate)
    movie_dur = 600 * frames // rate

    ftyp = _box(b"ftyp", b"qt  " + struct.pack(">I", 0x20050300) + b"qt  ")
    mvhd = _box(b"mvhd", struct.pack(">BBBB", 0, 0, 0, 0)
                + struct.pack(">IIII", _QT_EPOCH_2026, _QT_EPOCH_2026, 600, movie_dur)
                + struct.pack(">iHH", 0x00010000, 0x0100, 0)
                + b"\x00" * 8 + _MATRIX_UNITY + b"\x00" * 24
                + struct.pack(">I", 2))
    tkhd = _box(b"tkhd", struct.pack(">BBBB", 0, 0, 0, 0x0F)
                + struct.pack(">IIIII", _QT_EPOCH_2026, _QT_EPOCH_2026, 1, 0, movie_dur)
                + b"\x00" * 8 + struct.pack(">HHHH", 0, 0, 0x0100, 0)
                + _MATRIX_UNITY + struct.pack(">II", 0, 0))
    mdhd = _box(b"mdhd", struct.pack(">BBBB", 0, 0, 0, 0)
                + struct.pack(">IIII", _QT_EPOCH_2026, _QT_EPOCH_2026, rate, frames)
                + struct.pack(">HH", 0x55C4, 0))  # 'und'
    hdlr = _box(b"hdlr", struct.pack(">BBBB", 0, 0, 0, 0) + b"mhlr" + b"soun"
                + b"\x00" * 12 + bytes([12]) + b"SoundHandler")
    smhd = _box(b"smhd", struct.pack(">BBBBhH", 0, 0, 0, 0, 0, 0))
    dref = _box(b"dref", struct.pack(">BBBBI", 0, 0, 0, 0, 1)
                + _box(b"url ", struct.pack(">BBBB", 0, 0, 0, 1)))
    dinf = _box(b"dinf", dref)
    sowt = _box(b"sowt", b"\x00" * 6 + struct.pack(">H", 1)
                + struct.pack(">HHI", 0, 0, 0)       # version, revision, vendor
                + struct.pack(">HHHH", 2, 16, 0, 0)  # channels, bits, compid, packet
                + struct.pack(">I", rate << 16))
    stsd = _box(b"stsd", struct.pack(">BBBBI", 0, 0, 0, 0, 1) + sowt)
    stts = _box(b"stts", struct.pack(">BBBBI", 0, 0, 0, 0, 1)
                + struct.pack(">II", frames, 1))
    stsc = _box(b"stsc", struct.pack(">BBBBI", 0, 0, 0, 0, 1)
                + struct.pack(">III", 1, frames, 1))
    stsz = _box(b"stsz", struct.pack(">BBBBII", 0, 0, 0, 0, 4, frames))

    def assemble(chunk_off: int) -> bytes:
        stco = _box(b"stco", struct.pack(">BBBBI", 0, 0, 0, 0, 1)
                    + struct.pack(">I", chunk_off))
        stbl = _box(b"stbl", stsd + stts + stsc + stsz + stco)
        minf = _box(b"minf", smhd + dinf + stbl)
        mdia = _box(b"mdia", mdhd + hdlr + minf)
        return _box(b"moov", mvhd + _box(b"trak", tkhd + mdia))

    moov = assemble(0)                    # the size is offset-independent
    data_off = len(ftyp) + len(moov) + 8  # +8 for the mdat box header
    moov = assemble(data_off)
    return ftyp + moov + _box(b"mdat", audio)


# --------------------------------------------------------------------------
# 10 · GZIP
# --------------------------------------------------------------------------

def _build_gzip(payload: bytes, inner_name: str) -> bytes:
    """RFC 1952 member. MTIME is forced to 0 and OS to 255 (unknown).

    The gzip module stamps the wall clock into MTIME and the build platform
    into the OS byte by default; both are nondeterminism, and both are pinned
    to constants here. XFL is 0
    (unspecified) because our encoder is neither libz's "maximum" nor its
    "fastest" setting, and claiming either would be a false statement in a
    header field.
    """
    name = inner_name.encode("ascii")
    head = (bytes([0x1F, 0x8B, 0x08, 0x08])   # magic, CM=deflate, FLG=FNAME
            + struct.pack("<I", 0)            # MTIME = 0
            + bytes([0x00, 0xFF])             # XFL = 0, OS = 255 (unknown)
            + name + b"\x00")
    return (head + deflate_raw(payload)
            + struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF,
                          len(payload) & 0xFFFFFFFF))


# --------------------------------------------------------------------------
# 11 · the corpus
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class CorpusFile:
    """One planted file. `sha256` is of `data`, and is what recovery is scored against."""
    name: str
    kind: str
    data: bytes
    sha256: str


KINDS = ("TXT", "GZIP", "PNG", "JPEG", "PDF", "DOCX", "SQLITE", "MP4")

# name, kind, per-kind build arguments. Order is the corpus order and is stable.
# Sizes are chosen so the smallest file is comfortably multi-cluster at a 4 KiB
# cluster (the floor measured below is 12 clusters), which every fragmentation
# case needs: a 3-fragment plan cannot be expressed in fewer than 3 clusters.
_PLAN: tuple[tuple[str, str, dict], ...] = (
    # ---- TXT: the low-entropy anchor, near 4.3 bits/byte
    ("evidence_log_2026-01-14.txt", "TXT", {"target": 40960, "title": "EVIDENCE LOG"}),
    ("interview_transcript_raw.txt", "TXT", {"target": 61440, "title": "INTERVIEW TRANSCRIPT"}),
    ("sector_survey_notes.txt", "TXT", {"target": 81920, "title": "SECTOR SURVEY NOTES"}),
    ("operator_handover.txt", "TXT", {"target": 114688, "title": "OPERATOR HANDOVER"}),
    ("wipe_command_history.txt", "TXT", {"target": 163840, "title": "WIPE COMMAND HISTORY"}),

    # ---- GZIP: DEFLATE over prose, so entropy sits at the top of the scale
    ("audit_trail.log.gz", "GZIP", {"payload": 196608, "inner": "audit_trail.log"}),
    ("dmesg_capture.log.gz", "GZIP", {"payload": 262144, "inner": "dmesg_capture.log"}),
    ("controller_dump.bin.gz", "GZIP", {"payload": 327680, "inner": "controller_dump.bin"}),
    ("carve_session.log.gz", "GZIP", {"payload": 393216, "inner": "carve_session.log"}),
    ("imaging_transcript.txt.gz", "GZIP", {"payload": 458752, "inner": "imaging_transcript.txt"}),

    # ---- PNG: the IDAT chunk-size knob. None = one opaque IDAT.
    ("sector_map_01.png", "PNG", {"w": 224, "h": 224, "noise": 26, "idat": None}),
    ("sector_map_02.png", "PNG", {"w": 256, "h": 256, "noise": 30, "idat": 8192}),
    ("sector_map_03.png", "PNG", {"w": 256, "h": 256, "noise": 34, "idat": 8192}),
    ("seizure_photo_a.png", "PNG", {"w": 288, "h": 288, "noise": 22, "idat": None}),
    ("entropy_heatmap.png", "PNG", {"w": 240, "h": 240, "noise": 38, "idat": 8192}),

    # ---- JPEG
    ("seizure_photo_b.jpg", "JPEG", {"w": 320, "h": 320, "noise": 24, "q": 92}),
    ("drive_label_macro.jpg", "JPEG", {"w": 288, "h": 288, "noise": 30, "q": 94}),
    ("bench_setup_wide.jpg", "JPEG", {"w": 352, "h": 288, "noise": 26, "q": 90}),
    ("platter_surface_01.jpg", "JPEG", {"w": 256, "h": 256, "noise": 40, "q": 95}),
    ("evidence_bag_seal.jpg", "JPEG", {"w": 304, "h": 304, "noise": 28, "q": 93}),

    # ---- PDF
    ("chain_of_custody.pdf", "PDF", {"pages": 10, "blob": 24576, "title": "CHAIN OF CUSTODY"}),
    ("acquisition_worksheet.pdf", "PDF", {"pages": 8, "blob": 32768, "title": "ACQUISITION WORKSHEET"}),
    ("standards_checklist.pdf", "PDF", {"pages": 12, "blob": 16384, "title": "STANDARDS CHECKLIST"}),
    ("examiner_affidavit.pdf", "PDF", {"pages": 6, "blob": 40960, "title": "EXAMINER AFFIDAVIT"}),
    ("disposal_certificate.pdf", "PDF", {"pages": 14, "blob": 20480, "title": "DISPOSAL CERTIFICATE"}),

    # ---- DOCX
    ("sanitization_report.docx", "DOCX", {"paras": 900, "title": "SANITIZATION REPORT"}),
    ("incident_summary.docx", "DOCX", {"paras": 1400, "title": "INCIDENT SUMMARY"}),
    ("lab_procedure_v3.docx", "DOCX", {"paras": 700, "title": "LAB PROCEDURE V3"}),
    ("custody_addendum.docx", "DOCX", {"paras": 1100, "title": "CUSTODY ADDENDUM"}),
    ("media_inventory.docx", "DOCX", {"paras": 1800, "title": "MEDIA INVENTORY"}),

    # ---- SQLITE
    ("custody_ledger.db", "SQLITE", {"rows": 1100}),
    ("sector_index.db", "SQLITE", {"rows": 700}),
    ("device_registry.db", "SQLITE", {"rows": 900}),
    ("carve_results.db", "SQLITE", {"rows": 1500}),
    ("hash_baseline.db", "SQLITE", {"rows": 1300}),

    # ---- MP4 family. Named .mov: measured, CoreAudio dispatches on extension
    # and refuses these exact bytes as .mp4. See the module docstring.
    ("bodycam_intake.mov", "MP4", {"frames": 22050}),
    ("bench_capture_01.mov", "MP4", {"frames": 33075}),
    ("drive_teardown.mov", "MP4", {"frames": 44100}),
    ("sealing_procedure.mov", "MP4", {"frames": 55125}),
    ("handover_briefing.mov", "MP4", {"frames": 16537}),
)

CORPUS_NAMES = tuple(name for name, _kind, _spec in _PLAN)

# Names are the one thing this module is the authority on, so the two name
# lists the extent planner needs are published here rather than retyped there.
# The previous fragmentation table named five files that were not in the corpus
# and one that could not be built; that class of defect is removed by deriving
# both lists from _PLAN itself and asserting, in generate_corpus, that they are
# disjoint and that every name they mention is really generated.
#
# The rule is deliberately boring, so no choice reads as cherry-picking:
#   * the fragmentation ladder draws the LAST file of a kind,
#   * the deleted-contiguous set draws the FIRST file of a kind.
# Nothing can therefore land in both.

NAMES_BY_KIND = {}
for _name, _kind, _spec in _PLAN:
    NAMES_BY_KIND.setdefault(_kind, []).append(_name)
NAMES_BY_KIND = {k: tuple(v) for k, v in NAMES_BY_KIND.items()}
FIRST_OF_KIND = {k: v[0] for k, v in NAMES_BY_KIND.items()}
LAST_OF_KIND = {k: v[-1] for k, v in NAMES_BY_KIND.items()}

# The fragmentation ladder, bound to files this module really generates.
#
#   FRAG-01  2 frags, gap 1 cluster        floor case; contiguous carving fails
#   FRAG-02  2 frags, gap 16 clusters      the ordinary real gap
#   FRAG-03  2 frags, gap 128 clusters     sets and proves the max_gap budget
#   FRAG-04  2 frags, gap 50 clusters containing FRAG-05 fragment 0
#   FRAG-05  2 frags, gap 70 clusters containing FRAG-04 fragment 1
#   FRAG-06  3 frags                       unsolvable by bifragment carving
#   FRAG-07  2 frags, physically reversed  unsolvable by a forward-only search
#
# The KINDS here are fixed by the ladder's design and are not free choices.
# FRAG-04 and FRAG-05 must be the SAME kind: the point of the mutual interleave
# is that the decoy sitting in each file's gap carries the same signature as the
# file being carved. FRAG-06 is a DOCX and FRAG-07 a JPEG, matching the operator
# decision in docs/architecture.md -- a tri-fragment DOCX and an out-of-order
# JPEG, both unsolvable by construction, both named on screen at demo time.
FRAGMENTATION_SLOTS = {
    "FRAG-01": LAST_OF_KIND["PNG"],    # entropy_heatmap.png,        45 clusters
    "FRAG-02": LAST_OF_KIND["GZIP"],   # imaging_transcript.txt.gz,  32 clusters
    "FRAG-03": LAST_OF_KIND["PDF"],    # disposal_certificate.pdf,   12 clusters
    "FRAG-04": NAMES_BY_KIND["MP4"][-2],  # sealing_procedure.mov,   54 clusters
    "FRAG-05": NAMES_BY_KIND["MP4"][-1],  # handover_briefing.mov,   17 clusters
    "FRAG-06": LAST_OF_KIND["DOCX"],   # media_inventory.docx,       20 clusters
    "FRAG-07": LAST_OF_KIND["JPEG"],   # evidence_bag_seal.jpg,      27 clusters
}

# One contiguous file of each of the eight kinds, offered to the planner for the
# deleted set: every format is represented, so no carve result can be waved away
# with "they only deleted the formats that carve easily".
DELETED_CONTIGUOUS_CANDIDATES = tuple(FIRST_OF_KIND[k] for k in KINDS)


_MIN_FILE_BYTES = 4096  # every file must span more than one 4 KiB cluster


def _build_one(seed: str, name: str, kind: str, spec: dict) -> bytes:
    """One file. The PRNG is labelled with the file name, so adding, removing
    or reordering a file never shifts the bytes of any other file."""
    rnd = DetRandom(seed, label="%s|%s" % (kind, name))

    if kind == "TXT":
        return _build_txt(rnd, spec["target"], spec["title"])

    if kind == "GZIP":
        payload = _build_txt(rnd, spec["payload"], spec["inner"].upper())
        return _build_gzip(payload, spec["inner"])

    if kind == "PNG":
        px = _photo_rgb(rnd, spec["w"], spec["h"], spec["noise"])
        return _build_png(px, spec["w"], spec["h"],
                          {"Software": "SENTINELWIPE fixture generator",
                           "Source": "synthetic bilinear field plus grain",
                           "Title": name},
                          spec["idat"])

    if kind == "JPEG":
        px = _photo_rgb(rnd, spec["w"], spec["h"], spec["noise"])
        return _build_jpeg(px, spec["w"], spec["h"], spec["q"],
                           b"SENTINELWIPE fixture " + name.encode("ascii"))

    if kind == "PDF":
        return _build_pdf(rnd, spec["title"], spec["pages"], spec["blob"])

    if kind == "DOCX":
        return _build_docx(rnd, spec["title"], spec["paras"])

    if kind == "SQLITE":
        return _build_sqlite(rnd, spec["rows"])

    if kind == "MP4":
        return _build_mp4(rnd, spec["frames"])

    raise ValueError("unknown corpus kind %r" % kind)


def generate_corpus(seed: str) -> list[CorpusFile]:
    """The 40 planted files, in corpus order, derived entirely from `seed`.

    Deterministic: run it twice in two fresh processes and every sha256 matches.
    Nothing here reads the clock, the host, the locale or the environment.
    """
    if not isinstance(seed, str):
        raise TypeError("seed must be str, got %r" % type(seed).__name__)

    files: list[CorpusFile] = []
    for name, kind, spec in _PLAN:
        data = _build_one(seed, name, kind, spec)
        if len(data) < _MIN_FILE_BYTES:
            raise AssertionError(
                "%s is %d bytes; every planted file must be at least %d so it "
                "spans more than one cluster" % (name, len(data), _MIN_FILE_BYTES))
        files.append(CorpusFile(name=name, kind=kind, data=data,
                                sha256=hashlib.sha256(data).hexdigest()))

    if len(files) != 40:
        raise AssertionError("corpus is %d files, must be exactly 40" % len(files))
    names = [f.name for f in files]
    if len(set(names)) != 40:
        raise AssertionError("corpus file names are not unique")
    if len({f.sha256 for f in files}) != 40:
        raise AssertionError("two corpus files share a sha256")
    have = set(names)
    missing = sorted("%s->%s" % (slot, n)
                     for slot, n in FRAGMENTATION_SLOTS.items() if n not in have)
    if missing:
        raise AssertionError("fragmentation slots name absent files: %s" % missing)
    absent = [n for n in DELETED_CONTIGUOUS_CANDIDATES if n not in have]
    if absent:
        raise AssertionError("deleted-set candidates name absent files: %s" % absent)
    # A file in both lists would be counted twice by the planner's deleted set,
    # silently turning 12 deleted files into 11. Fail the build instead.
    both = sorted(set(FRAGMENTATION_SLOTS.values())
                  & set(DELETED_CONTIGUOUS_CANDIDATES))
    if both:
        raise AssertionError("file is both a ladder slot and a deleted-set "
                             "candidate: %s" % both)
    if len(set(DELETED_CONTIGUOUS_CANDIDATES)) != len(KINDS):
        raise AssertionError("deleted-set candidates must be one file per kind")
    return files


def _main(argv) -> int:
    """Write the corpus to a directory and print the measured table.

    fixtures/build_image.py is the real CLI; this exists so the corpus can be
    regenerated and handed to external decoders on its own.
    """
    import os

    outdir = argv[1] if len(argv) > 1 else "corpus_out"
    seed = argv[2] if len(argv) > 2 else "sentinelwipe/fixture/v1"
    os.makedirs(outdir, exist_ok=True)
    files = generate_corpus(seed)
    total = 0
    print("%-28s %-7s %10s %7s %8s  %s"
          % ("name", "kind", "bytes", "clu4k", "H b/B", "sha256[:16]"))
    for f in files:
        with open(os.path.join(outdir, f.name), "wb") as fh:
            fh.write(f.data)
        total += len(f.data)
        print("%-28s %-7s %10d %7d %8.4f  %s"
              % (f.name, f.kind, len(f.data), (len(f.data) + 4095) // 4096,
                 shannon_bits_per_byte(f.data), f.sha256[:16]))
    print("40 files, %d bytes (%.2f MiB)" % (total, total / 1048576))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv))
