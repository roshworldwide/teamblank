"""FAT32 on-disk structures for the SENTINELWIPE forensic fixture.

Pure Python standard library. The image is assembled byte by byte: boot sector /
BPB, FSInfo, the backup boot region at sector 6, two identical FAT copies, a root
directory carrying VFAT long filenames, and file data written at exactly the
cluster extents the planner chose.

Three properties this module exists to guarantee, each one a defect measured in a
previous round:

1. ``build_image`` NEVER allocates. It is handed a list of placements whose
   extents were fixed before a byte was written and it writes those extents. A
   cursor-incrementing allocator cannot express a 128-cluster gap, a mutual
   interleave, or a fragment that lies physically before its predecessor, and
   those cases are the whole point of the fixture. The only clusters this module
   picks for itself are the root directory's, taken from the lowest clusters no
   placement claims.

2. Residue fills clusters that are FAT-free AND claimed by no planted extent.
   Deletion frees the FAT chain, so a residue pass keyed on "FAT-free" alone
   overwrites every deleted file and the demo silently degrades from 40
   recoverable to 28 with no error raised anywhere. ``residue_clusters``
   subtracts the claimed set, and ``build_image`` re-hashes every placement out
   of the finished image before returning.

3. A zero-length file has ``first_cluster = 0`` and no FAT chain. An allocator
   that forces a minimum of one cluster produces a file a driver reads as
   0 bytes from a cluster it also thinks is allocated; ``fsck`` calls that a
   cross-link.

Determinism: no clock, no ``random``, no host ``stat``, no locale, no
``PYTHONHASHSEED`` dependence. Timestamps and the volume ID are pinned constants
that the caller may override with values derived from the fixture seed.

Deliberately not implemented: subdirectories, FAT12/16, in-place mutation of an
existing image.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

__all__ = [
    "Geometry",
    "compute_geometry",
    "largest_valid_cluster_size",
    "build_image",
    "read_image",
    "residue_clusters",
    "root_directory_clusters",
    "short_name_for",
    "lfn_checksum",
    "BYTES_PER_SECTOR",
    "FAT32_MIN_CLUSTERS",
    "FAT32_MAX_CLUSTERS",
    "DEFAULT_VOLUME_ID",
    "DEFAULT_VOLUME_LABEL",
    "DEFAULT_STAMP",
]

BYTES_PER_SECTOR = 512

# Below 65525 data clusters a conforming driver reads the volume as FAT16, whatever
# the boot sector says. Microsoft's FAT specification makes this the definition of
# the type, not a hint.
FAT32_MIN_CLUSTERS = 65525
FAT32_MAX_CLUSTERS = 0x0FFFFFF5 - 2

FREE = 0x00000000
EOC = 0x0FFFFFFF
FAT_ENTRY_MASK = 0x0FFFFFFF

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LONG_NAME = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID  # 0x0F

DELETED_MARK = 0xE5
LAST_LFN_MASK = 0x40
LFN_CHARS_PER_ENTRY = 13
DIR_ENTRY_SIZE = 32

# Pinned so the image hash is a function of the corpus alone. 2026-01-01 00:00:00.
DEFAULT_STAMP = (2026, 1, 1, 0, 0, 0)
DEFAULT_VOLUME_ID = 0x5E471E10
DEFAULT_VOLUME_LABEL = "SENTINELWP"

# 8.3 field: everything outside this is replaced by '_' by short_name_for().
_SFN_INVALID = set(b'"*+,./:;<=>?[\\]|') | set(range(0x00, 0x21)) | {0x7F}


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


# --------------------------------------------------------------------- geometry


@dataclass(frozen=True)
class Geometry:
    """Resolved FAT32 geometry. ``data_start_offset`` is a byte offset."""

    size_bytes: int
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved: int
    num_fats: int
    fat_sectors: int
    cluster_count: int
    data_start_offset: int

    @property
    def bytes_per_cluster(self) -> int:
        return self.sectors_per_cluster * self.bytes_per_sector

    @property
    def total_sectors(self) -> int:
        return self.size_bytes // self.bytes_per_sector

    @property
    def data_start_sector(self) -> int:
        return self.data_start_offset // self.bytes_per_sector

    @property
    def first_cluster(self) -> int:
        return 2

    @property
    def last_cluster(self) -> int:
        return self.cluster_count + 1

    @property
    def fat_entries(self) -> int:
        """Entries the on-disk FAT can physically hold, reserved pair included."""
        return self.fat_sectors * self.bytes_per_sector // 4

    def cluster_offset(self, cluster: int) -> int:
        if not self.first_cluster <= cluster <= self.last_cluster:
            raise ValueError(
                "cluster %d outside %d..%d"
                % (cluster, self.first_cluster, self.last_cluster)
            )
        return self.data_start_offset + (cluster - 2) * self.bytes_per_cluster

    def clusters_for(self, nbytes: int) -> int:
        return _ceil_div(nbytes, self.bytes_per_cluster)


def compute_geometry(
    size_bytes: int,
    bytes_per_cluster: int,
    *,
    reserved: int = 32,
    num_fats: int = 2,
    bytes_per_sector: int = BYTES_PER_SECTOR,
) -> Geometry:
    """Smallest FAT that covers every cluster the volume then has.

    Solved in the driver's direction: CountOfClusters = (TotSec32 - data_start) /
    SecPerClus with the remainder discarded, and the FAT sized to cover
    CountOfClusters + 2 entries. Sizing the FAT first and deriving clusters from
    it is the off-by-two that leaves the last clusters with no FAT entry -- it is
    how 64 MiB was published as 129024 clusters when the FAT at that size holds
    129024 entries in total and therefore addresses only 129022 data clusters.
    """
    if size_bytes <= 0 or size_bytes % bytes_per_sector:
        raise ValueError(
            "image size must be a positive multiple of %d bytes" % bytes_per_sector
        )
    if bytes_per_cluster % bytes_per_sector:
        raise ValueError("cluster size must be a multiple of the sector size")
    spc = bytes_per_cluster // bytes_per_sector
    if spc < 1 or spc > 128 or spc & (spc - 1):
        raise ValueError("sectors per cluster must be a power of two in 1..128")
    if bytes_per_cluster > 32768:
        raise ValueError("FAT32 cluster size may not exceed 32768 bytes")
    if num_fats < 1 or reserved < 1:
        raise ValueError("num_fats and reserved must be >= 1")

    total_sectors = size_bytes // bytes_per_sector

    def fits(fat_sectors: int) -> bool:
        data_start = reserved + num_fats * fat_sectors
        if data_start >= total_sectors:
            return False
        clusters = (total_sectors - data_start) // spc
        if clusters < 1:
            return False
        # Compared in bytes on purpose: a ceil-div on sectors here is where the
        # published 129024 came from.
        return fat_sectors * bytes_per_sector >= (clusters + 2) * 4

    # fits() is monotone in fat_sectors: the left side grows, the right side
    # shrinks, so the smallest satisfying value is a clean binary search.
    lo, hi, best = 1, max(1, total_sectors // num_fats), None
    while lo <= hi:
        mid = (lo + hi) // 2
        if fits(mid):
            best, hi = mid, mid - 1
        else:
            lo = mid + 1
    if best is None:
        raise ValueError(
            "no FAT32 geometry for %d bytes at %d-byte clusters" % (size_bytes, bytes_per_cluster)
        )

    # Start the data area on a cluster boundary. Not required by the spec; every
    # formatter does it and drivers on flash media are measurably happier.
    while (reserved + num_fats * best) % spc:
        best += 1
    if not fits(best):
        raise ValueError(
            "cluster-aligning the data area broke the FAT fit for %d bytes at %d-byte clusters"
            % (size_bytes, bytes_per_cluster)
        )

    data_start_sector = reserved + num_fats * best
    cluster_count = (total_sectors - data_start_sector) // spc
    if cluster_count < FAT32_MIN_CLUSTERS:
        raise ValueError(
            "%d bytes at %d-byte clusters yields %d clusters; FAT32 requires >= %d"
            % (size_bytes, bytes_per_cluster, cluster_count, FAT32_MIN_CLUSTERS)
        )
    if cluster_count > FAT32_MAX_CLUSTERS:
        raise ValueError("cluster count %d exceeds the FAT32 maximum" % cluster_count)
    if (cluster_count + 2) * 4 > best * bytes_per_sector:
        raise ValueError(
            "internal: FAT of %d sectors cannot address %d clusters" % (best, cluster_count)
        )

    return Geometry(
        size_bytes=size_bytes,
        bytes_per_sector=bytes_per_sector,
        sectors_per_cluster=spc,
        reserved=reserved,
        num_fats=num_fats,
        fat_sectors=best,
        cluster_count=cluster_count,
        data_start_offset=data_start_sector * bytes_per_sector,
    )


def largest_valid_cluster_size(size_bytes: int, **kw) -> int:
    """Largest cluster size for which this image still holds >= 65525 clusters."""
    for bpc in (32768, 16384, 8192, 4096, 2048, 1024, 512):
        try:
            compute_geometry(size_bytes, bpc, **kw)
        except ValueError:
            continue
        return bpc
    raise ValueError("no FAT32 cluster size yields >= %d clusters for %d bytes"
                     % (FAT32_MIN_CLUSTERS, size_bytes))


# ------------------------------------------------------------------- structures


def fat_datetime(year: int, month: int, day: int, hour: int = 0, minute: int = 0,
                 second: int = 0) -> tuple[int, int]:
    if not 1980 <= year <= 2107:
        raise ValueError("FAT dates cover 1980..2107")
    return (
        ((year - 1980) << 9) | (month << 5) | day,
        (hour << 11) | (minute << 5) | (second // 2),
    )


def boot_sector(geo: Geometry, volume_id: int, volume_label: str,
                root_cluster: int) -> bytes:
    b = bytearray(geo.bytes_per_sector)
    b[0:3] = b"\xEB\x58\x90"                                  # jmp short +0x58; nop
    b[3:11] = b"MSWIN4.1"                                     # OEM name drivers special-case
    struct.pack_into("<H", b, 0x0B, geo.bytes_per_sector)     # BPB_BytsPerSec
    b[0x0D] = geo.sectors_per_cluster                         # BPB_SecPerClus
    struct.pack_into("<H", b, 0x0E, geo.reserved)             # BPB_RsvdSecCnt
    b[0x10] = geo.num_fats                                    # BPB_NumFATs
    struct.pack_into("<H", b, 0x11, 0)                        # BPB_RootEntCnt = 0 on FAT32
    struct.pack_into("<H", b, 0x13, 0)                        # BPB_TotSec16 -> use TotSec32
    b[0x15] = 0xF8                                            # BPB_Media, fixed disk
    struct.pack_into("<H", b, 0x16, 0)                        # BPB_FATSz16 = 0 on FAT32
    struct.pack_into("<H", b, 0x18, 63)                       # BPB_SecPerTrk
    struct.pack_into("<H", b, 0x1A, 255)                      # BPB_NumHeads
    struct.pack_into("<I", b, 0x1C, 0)                        # BPB_HiddSec, no partition table
    struct.pack_into("<I", b, 0x20, geo.total_sectors)        # BPB_TotSec32
    struct.pack_into("<I", b, 0x24, geo.fat_sectors)          # BPB_FATSz32
    struct.pack_into("<H", b, 0x28, 0)                        # BPB_ExtFlags: FATs mirrored
    struct.pack_into("<H", b, 0x2A, 0)                        # BPB_FSVer
    struct.pack_into("<I", b, 0x2C, root_cluster)             # BPB_RootClus
    struct.pack_into("<H", b, 0x30, 1)                        # BPB_FSInfo
    struct.pack_into("<H", b, 0x32, 6)                        # BPB_BkBootSec
    b[0x40] = 0x80                                            # BS_DrvNum
    b[0x42] = 0x29                                            # BS_BootSig
    struct.pack_into("<I", b, 0x43, volume_id & 0xFFFFFFFF)   # BS_VolID
    b[0x47:0x52] = _label11(volume_label)                     # BS_VolLab
    b[0x52:0x5A] = b"FAT32   "                                # BS_FilSysType
    b[geo.bytes_per_sector - 2:geo.bytes_per_sector] = b"\x55\xAA"
    return bytes(b)


def fsinfo_sector(free_count: int, next_free: int, sector_size: int = BYTES_PER_SECTOR) -> bytes:
    b = bytearray(sector_size)
    b[0x000:0x004] = b"RRaA"                                  # FSI_LeadSig
    b[0x1E4:0x1E8] = b"rrAa"                                  # FSI_StrucSig
    struct.pack_into("<I", b, 0x1E8, free_count & 0xFFFFFFFF)  # FSI_Free_Count
    struct.pack_into("<I", b, 0x1EC, next_free & 0xFFFFFFFF)   # FSI_Nxt_Free
    b[sector_size - 4:sector_size] = b"\x00\x00\x55\xAA"      # FSI_TrailSig
    return bytes(b)


def _label11(label: str) -> bytes:
    packed = bytearray(label.upper().ljust(11)[:11].encode("ascii", "replace"))
    for i, c in enumerate(packed):
        if c in _SFN_INVALID and c != 0x20:
            packed[i] = ord("_")
    return bytes(packed)


def lfn_checksum(name11: bytes) -> int:
    """The one-byte checksum every LFN entry in a set carries over its 8.3 name."""
    if len(name11) != 11:
        raise ValueError("8.3 name field must be exactly 11 bytes")
    s = 0
    for c in name11:
        s = (((s & 1) << 7) | (s >> 1)) + c
        s &= 0xFF
    return s


def short_name_for(long_name: str, used: set[bytes] | None = None) -> tuple[bytes, bool]:
    """Pack a long name into the 11-byte 8.3 field, with a ``~n`` tail when lossy.

    Returns ``(name11, lossy)``. ``lossy`` is True when the 8.3 form is not a
    byte-for-byte match of the long name, which is when a VFAT long-name entry
    set is genuinely required rather than merely permitted.

    The prototype's short_name() raised ValueError on 30 of the 40 corpus names --
    ``036_sqlite.sqlite`` has a seven-character extension and no 8.3 form at all.
    Rejecting the corpus is not an option; producing ``036_SQ~1.SQL`` and carrying
    the real name in the LFN set is.
    """
    used = used if used is not None else set()

    stripped = long_name.strip().lstrip(".")
    if not stripped:
        raise ValueError("empty name: %r" % long_name)

    if "." in stripped:
        stem, _, ext = stripped.rpartition(".")
    else:
        stem, ext = stripped, ""
    if not stem:                     # e.g. ".config" -> stem ".config", no extension
        stem, ext = stripped, ""

    def clean(s: str) -> str:
        out = []
        for ch in s:
            if ch == " ":
                continue             # spaces are dropped, not translated
            u = ch.upper()
            b = u.encode("ascii", "replace")
            code = b[0] if len(b) == 1 else ord("_")
            if code in _SFN_INVALID or code > 0x7F:
                code = ord("_")
            out.append(chr(code))
        return "".join(out)

    base, extc = clean(stem), clean(ext)[:3]

    lossy = (
        base != stem
        or extc != ext
        or len(base) > 8
        or len(ext) > 3
        or stripped != long_name
    )

    if not lossy:
        name11 = (base.ljust(8) + extc.ljust(3)).encode("ascii")
        if name11 not in used:
            if name11[0] == DELETED_MARK:
                name11 = bytes([0x05]) + name11[1:]
            return name11, False
        lossy = True                 # collision forces a tail anyway

    if not base:
        base = "_"
    for n in range(1, 1000000):
        tail = "~%d" % n
        head = base[: max(1, 8 - len(tail))]
        candidate = (head + tail).ljust(8)[:8] + extc.ljust(3)
        name11 = candidate.encode("ascii")
        if name11 not in used:
            if name11[0] == DELETED_MARK:
                name11 = bytes([0x05]) + name11[1:]
            return name11, True
    raise ValueError("could not generate a unique 8.3 name for %r" % long_name)


def lfn_entries(long_name: str, name11: bytes) -> list[bytes]:
    """The VFAT long-name entry set for one file, in on-disk (reverse) order.

    13 UCS-2LE characters per 32-byte entry, attribute 0x0F, sequence numbers
    counting from 1 with 0x40 set on the entry that holds the tail of the name,
    stored last-first so a forward scan meets the tail before the 8.3 entry.
    """
    if not long_name:
        raise ValueError("empty long name")
    units = long_name.encode("utf-16-le")
    if len(units) // 2 > 255:
        raise ValueError("long name exceeds 255 UCS-2 characters: %r" % long_name)
    chars = [units[i:i + 2] for i in range(0, len(units), 2)]
    for c in chars:
        if c == b"\x00\x00":
            raise ValueError("NUL in long name: %r" % long_name)

    checksum = lfn_checksum(name11)
    n_entries = _ceil_div(len(chars), LFN_CHARS_PER_ENTRY)
    padded = list(chars)
    if len(padded) < n_entries * LFN_CHARS_PER_ENTRY:
        padded.append(b"\x00\x00")                              # terminator
        while len(padded) < n_entries * LFN_CHARS_PER_ENTRY:
            padded.append(b"\xFF\xFF")                          # pad

    out = []
    for seq in range(1, n_entries + 1):
        chunk = padded[(seq - 1) * LFN_CHARS_PER_ENTRY: seq * LFN_CHARS_PER_ENTRY]
        e = bytearray(DIR_ENTRY_SIZE)
        e[0x00] = seq | (LAST_LFN_MASK if seq == n_entries else 0)
        e[0x01:0x0B] = b"".join(chunk[0:5])
        e[0x0B] = ATTR_LONG_NAME
        e[0x0C] = 0x00                                          # LDIR_Type, 0 = name entry
        e[0x0D] = checksum
        e[0x0E:0x1A] = b"".join(chunk[5:11])
        struct.pack_into("<H", e, 0x1A, 0)                      # LDIR_FstClusLO must be 0
        e[0x1C:0x20] = b"".join(chunk[11:13])
        out.append(bytes(e))
    out.reverse()
    return out


def dir_entry(name11: bytes, attr: int, first_cluster: int, size: int,
              date: int, time: int, nt_res: int = 0) -> bytes:
    if len(name11) != 11:
        raise ValueError("8.3 name field must be exactly 11 bytes")
    e = bytearray(DIR_ENTRY_SIZE)
    e[0x00:0x0B] = name11
    e[0x0B] = attr
    e[0x0C] = nt_res
    e[0x0D] = 0                                                 # DIR_CrtTimeTenth
    struct.pack_into("<HH", e, 0x0E, time, date)                # creation
    struct.pack_into("<H", e, 0x12, date)                       # last access
    struct.pack_into("<H", e, 0x14, (first_cluster >> 16) & 0xFFFF)
    struct.pack_into("<HH", e, 0x16, time, date)                # last write
    struct.pack_into("<H", e, 0x1A, first_cluster & 0xFFFF)
    struct.pack_into("<I", e, 0x1C, size)
    return bytes(e)


# ------------------------------------------------------------------- placements


def _extent_fields(ext) -> tuple[int, int, int, int]:
    try:
        return (
            int(ext.cluster_start),
            int(ext.cluster_count),
            int(ext.byte_offset),
            int(ext.byte_length),
        )
    except AttributeError as exc:                                # pragma: no cover
        raise TypeError(
            "extent must expose cluster_start, cluster_count, byte_offset, byte_length: %r"
            % (ext,)
        ) from exc


def _placement_fields(p) -> tuple[str, bytes, bool, list]:
    try:
        return str(p.name), bytes(p.data), bool(p.deleted), list(p.extents)
    except AttributeError as exc:                                # pragma: no cover
        raise TypeError(
            "placement must expose name, data, deleted, extents: %r" % (p,)
        ) from exc


def _validate_placements(geo: Geometry, placements) -> dict[int, str]:
    """Return {cluster: owner name}. Raises on any layout a driver would misread."""
    bpc = geo.bytes_per_cluster
    claimed: dict[int, str] = {}
    seen_names: set[str] = set()

    for p in placements:
        name, data, _deleted, extents = _placement_fields(p)
        if name in seen_names:
            raise ValueError("duplicate placement name %r" % name)
        seen_names.add(name)

        total = 0
        for i, ext in enumerate(extents):
            start, count, offset, length = _extent_fields(ext)
            if count < 1:
                raise ValueError("%s extent %d: cluster_count must be >= 1" % (name, i))
            if start < geo.first_cluster or start + count - 1 > geo.last_cluster:
                raise ValueError(
                    "%s extent %d: clusters %d..%d outside %d..%d"
                    % (name, i, start, start + count - 1, geo.first_cluster, geo.last_cluster)
                )
            if offset != geo.cluster_offset(start):
                raise ValueError(
                    "%s extent %d: byte_offset %d does not match cluster %d at %d"
                    % (name, i, offset, start, geo.cluster_offset(start))
                )
            if length < 1 or length > count * bpc:
                raise ValueError(
                    "%s extent %d: byte_length %d does not fit %d cluster(s)"
                    % (name, i, length, count)
                )
            if count != _ceil_div(length, bpc):
                raise ValueError(
                    "%s extent %d: %d clusters reserved for %d bytes; expected %d"
                    % (name, i, count, length, _ceil_div(length, bpc))
                )
            if i < len(extents) - 1 and length != count * bpc:
                raise ValueError(
                    "%s extent %d: a non-final extent must be cluster-full "
                    "(%d bytes in %d clusters leaves a hole the FAT chain cannot express)"
                    % (name, i, length, count)
                )
            for c in range(start, start + count):
                if c in claimed:
                    raise ValueError(
                        "cluster %d claimed by both %r and %r" % (c, claimed[c], name)
                    )
                claimed[c] = name
            total += length

        if total != len(data):
            raise ValueError(
                "%s: extents cover %d bytes, data is %d bytes" % (name, total, len(data))
            )
        if not extents and len(data):
            raise ValueError("%s: %d bytes of data with no extents" % (name, len(data)))

    return claimed


def root_directory_clusters(geo: Geometry, names, volume_label: str = DEFAULT_VOLUME_LABEL) -> int:
    """Clusters the root directory needs for these names. Callable before planning."""
    total = DIR_ENTRY_SIZE if volume_label else 0
    used: set[bytes] = set()
    for name in names:
        name11, _lossy = short_name_for(name, used)
        used.add(name11)
        total += DIR_ENTRY_SIZE * (1 + len(lfn_entries(name, name11)))
    total += DIR_ENTRY_SIZE                                      # the 0x00 end marker
    return max(1, _ceil_div(total, geo.bytes_per_cluster))


def _choose_root_chain(geo: Geometry, claimed, count: int) -> list[int]:
    """The lowest clusters no placement claims. The only allocation this module does."""
    chain, c = [], geo.first_cluster
    while len(chain) < count:
        if c > geo.last_cluster:
            raise ValueError("no free clusters left for the root directory")
        if c not in claimed:
            chain.append(c)
        c += 1
    return chain


def residue_clusters(geo: Geometry, placements,
                     volume_label: str = DEFAULT_VOLUME_LABEL) -> list[int]:
    """Clusters a residue fill may write: FAT-free AND claimed by no planted extent.

    Equivalent statement, and the one the code enforces: every cluster minus the
    planted extents minus the root directory. The two agree because the only
    clusters the FAT marks in use are the root directory's and the live files',
    and every live file's clusters are claimed. A deleted file's clusters are
    FAT-free but still claimed, which is exactly the case the naive "FAT-free"
    rule got wrong: it overwrote all 12 deleted files and reported nothing.
    """
    placements = list(placements)
    claimed = _validate_placements(geo, placements)
    n_root = root_directory_clusters(geo, [str(p.name) for p in placements], volume_label)
    root_set = set(_choose_root_chain(geo, claimed, n_root))
    return [c for c in range(geo.first_cluster, geo.last_cluster + 1)
            if c not in claimed and c not in root_set]


# ------------------------------------------------------------------------ build


def build_image(geo: Geometry, placements, residue_fn, *,
                volume_label: str = DEFAULT_VOLUME_LABEL,
                volume_id: int = DEFAULT_VOLUME_ID,
                stamp: tuple = DEFAULT_STAMP,
                verify: bool = True) -> bytes:
    """Assemble the image. Writes exactly the extents given; allocates nothing.

    ``placements`` is a sequence of objects exposing ``name``, ``data``,
    ``deleted`` and ``extents`` (each extent exposing ``cluster_start``,
    ``cluster_count``, ``byte_offset``, ``byte_length``) -- i.e. ``plan.Placement``
    and ``plan.Extent``, taken structurally so this module never imports the
    planner.

    ``residue_fn`` is ``fn(cluster: int, nbytes: int) -> bytes`` and is called
    once per cluster that is FAT-free AND claimed by no placement AND not part of
    the root directory. Pass ``None`` to leave free space zeroed. It is never
    called for the boot sector, either FAT, the FSInfo sectors, the backup boot
    region or the root directory: those are not in the data area or are not free.

    Returns the image bytes. With ``verify=True`` every placement is re-read out
    of the finished image through its own extents and SHA-256 compared before the
    bytes are handed back.
    """
    placements = list(placements)
    bpc = geo.bytes_per_cluster
    date, time = fat_datetime(*stamp)

    claimed = _validate_placements(geo, placements)

    # --- directory entry stream -------------------------------------------------
    root = bytearray()
    entry_slots: list[tuple[int, int]] = []            # (byte index in stream, n entries)
    used_short: set[bytes] = set()
    if volume_label:
        root += dir_entry(_label11(volume_label), ATTR_VOLUME_ID, 0, 0, date, time)

    for p in placements:
        name, data, _deleted, extents = _placement_fields(p)
        name11, _lossy = short_name_for(name, used_short)
        used_short.add(name11)
        lfns = lfn_entries(name, name11)               # always emitted: fls must show real names
        start_index = len(root)
        for e in lfns:
            root += e
        first_cluster = _extent_fields(extents[0])[0] if extents else 0
        root += dir_entry(name11, ATTR_ARCHIVE, first_cluster, len(data), date, time)
        entry_slots.append((start_index, len(lfns) + 1))

    root += b"\x00" * DIR_ENTRY_SIZE                   # end-of-directory marker
    root_cluster_count = max(1, _ceil_div(len(root), bpc))

    # --- root directory placement: the lowest clusters nobody planted ----------
    root_chain = _choose_root_chain(geo, claimed, root_cluster_count)
    root_set = set(root_chain)

    # --- deletion, in the directory stream, before it reaches the image --------
    # Marking the first byte 0xE5 is only half of a delete. An entry that keeps
    # DIR_FstClusHI/LO and DIR_FileSize still POINTS AT THE DATA, and a metadata
    # reader needs no carving to follow it: measured on the previous build, The
    # Sleuth Kit's `icat` recovered 8 of the 12 deleted files byte-perfect from
    # the directory alone -- every contiguous one -- which contradicts the
    # Phase-1 criterion that the deleted subset exists only as unreferenced
    # data. So the allocation fields are zeroed here as well. Windows zeroes
    # the high word on delete; zeroing all three is the honest version of the
    # criterion, and it leaves the deleted files reachable only by carving.
    for p, (index, n_entries) in zip(placements, entry_slots):
        if not bool(p.deleted):
            continue
        for k in range(n_entries):
            root[index + k * DIR_ENTRY_SIZE] = DELETED_MARK
        # Only the SHORT entry carries allocation fields. The preceding LFN
        # entries hold name characters at those same offsets, so touching them
        # would destroy the long name a forensic reader must still be able to
        # reconstruct.
        short = index + (n_entries - 1) * DIR_ENTRY_SIZE
        struct.pack_into("<H", root, short + 0x14, 0)      # DIR_FstClusHI
        struct.pack_into("<H", root, short + 0x1A, 0)      # DIR_FstClusLO
        struct.pack_into("<I", root, short + 0x1C, 0)      # DIR_FileSize

    # --- FAT ------------------------------------------------------------------
    fat = [FREE] * (geo.cluster_count + 2)
    fat[0] = 0x0FFFFFF8                                # media byte, sign-extended
    fat[1] = 0x0FFFFFFF                                # clean shutdown, no hard error
    for i, cl in enumerate(root_chain):
        fat[cl] = root_chain[i + 1] if i + 1 < len(root_chain) else EOC

    for p in placements:
        name, data, deleted, extents = _placement_fields(p)
        if deleted:
            # Deletion is the absence of a chain. The data stays where it is; that
            # is what makes the file exist only as unreferenced bytes.
            continue
        chain = []
        for ext in extents:
            start, count, _offset, _length = _extent_fields(ext)
            chain.extend(range(start, start + count))
        for i, cl in enumerate(chain):
            fat[cl] = chain[i + 1] if i + 1 < len(chain) else EOC

    # --- image ----------------------------------------------------------------
    img = bytearray(geo.size_bytes)

    for i, cl in enumerate(root_chain):                # root directory contents
        off = geo.cluster_offset(cl)
        img[off:off + bpc] = root[i * bpc:(i + 1) * bpc].ljust(bpc, b"\x00")

    for p in placements:                               # planted data, deleted included
        name, data, _deleted, extents = _placement_fields(p)
        pos = 0
        for ext in extents:
            start, count, offset, length = _extent_fields(ext)
            img[offset:offset + length] = data[pos:pos + length]
            slack = count * bpc - length
            if slack:                                  # cluster slack, zeroed
                img[offset + length:offset + count * bpc] = b"\x00" * slack
            pos += length

    # --- residue: FAT-free AND unclaimed. Both halves of that are load-bearing --
    if residue_fn is not None:
        lo_guard = geo.data_start_offset
        for cl in range(geo.first_cluster, geo.last_cluster + 1):
            if fat[cl] != FREE or cl in claimed or cl in root_set:
                continue
            off = geo.cluster_offset(cl)
            if off < lo_guard or off + bpc > geo.size_bytes:     # unreachable by construction
                raise AssertionError("residue would leave the data area at cluster %d" % cl)
            blob = residue_fn(cl, bpc)
            if not isinstance(blob, (bytes, bytearray)) or len(blob) != bpc:
                raise ValueError(
                    "residue_fn(%d, %d) must return exactly %d bytes" % (cl, bpc, bpc)
                )
            img[off:off + bpc] = blob

    # --- FATs, both copies ----------------------------------------------------
    packed = struct.pack("<%dI" % len(fat), *fat).ljust(geo.fat_sectors * geo.bytes_per_sector,
                                                        b"\x00")
    if len(packed) != geo.fat_sectors * geo.bytes_per_sector:
        raise AssertionError("FAT does not fit its %d sectors" % geo.fat_sectors)
    for k in range(geo.num_fats):
        off = (geo.reserved + k * geo.fat_sectors) * geo.bytes_per_sector
        img[off:off + len(packed)] = packed

    # --- boot sector, FSInfo, backup boot region ------------------------------
    used_clusters = sum(1 for cl in range(geo.first_cluster, geo.last_cluster + 1)
                        if fat[cl] != FREE)
    next_free = geo.first_cluster
    while next_free <= geo.last_cluster and fat[next_free] != FREE:
        next_free += 1
    if next_free > geo.last_cluster:
        next_free = 0xFFFFFFFF

    boot = boot_sector(geo, volume_id, volume_label, root_chain[0])
    info = fsinfo_sector(geo.cluster_count - used_clusters, next_free, geo.bytes_per_sector)
    sec = geo.bytes_per_sector
    img[0:sec] = boot
    img[sec:2 * sec] = info
    img[6 * sec:7 * sec] = boot                        # BPB_BkBootSec
    img[7 * sec:8 * sec] = info

    if verify:
        _verify_round_trip(geo, placements, img)

    return bytes(img)


def _verify_round_trip(geo: Geometry, placements, img) -> None:
    """Re-read every placement out of the finished image through its own extents.

    This is the check that would have caught a residue pass eating the deleted
    files: it reads the bytes that are actually on the disk, not the plan.
    """
    for p in placements:
        name, data, _deleted, extents = _placement_fields(p)
        blob = bytearray()
        for ext in extents:
            _start, _count, offset, length = _extent_fields(ext)
            blob += img[offset:offset + length]
        got = hashlib.sha256(bytes(blob)).hexdigest()
        want = getattr(p, "sha256", None) or hashlib.sha256(data).hexdigest()
        if got != want:
            raise AssertionError(
                "%s does not read back from its extents: image %s != expected %s"
                % (name, got, want)
            )


# ----------------------------------------------------------------------- reader


def read_image(img) -> dict:
    """Independent re-parse of a finished image, LFN reassembly included.

    Walks the on-disk BPB and FAT with no reference to the build-time plan, so a
    disagreement between this and the manifest is real. Used by the tests and by
    the negative control.
    """
    img = memoryview(bytes(img))
    bps = struct.unpack_from("<H", img, 0x0B)[0]
    spc = img[0x0D]
    rsvd = struct.unpack_from("<H", img, 0x0E)[0]
    nfat = img[0x10]
    total = struct.unpack_from("<I", img, 0x20)[0]
    fatsz = struct.unpack_from("<I", img, 0x24)[0]
    root_cluster = struct.unpack_from("<I", img, 0x2C)[0]
    if bytes(img[0x1FE:0x200]) != b"\x55\xAA" or bytes(img[0x52:0x5A]) != b"FAT32   ":
        raise ValueError("not a FAT32 boot sector")

    data_start_sector = rsvd + nfat * fatsz
    nclus = (total - data_start_sector) // spc
    cluster_bytes = spc * bps
    fats = [
        list(struct.unpack_from("<%dI" % (nclus + 2), img, (rsvd + k * fatsz) * bps))
        for k in range(nfat)
    ]
    fat = [e & FAT_ENTRY_MASK for e in fats[0]]

    def off(c: int) -> int:
        return (data_start_sector + (c - 2) * spc) * bps

    def walk(c: int) -> list[int]:
        seen, order = set(), []
        while 2 <= c <= nclus + 1 and c not in seen:
            seen.add(c)
            order.append(c)
            c = fat[c]
        return order

    stream = bytearray()
    for c in walk(root_cluster):
        stream += img[off(c):off(c) + cluster_bytes]

    # LFN sets are ordered by their position on disk (stored last chunk first), not
    # by the sequence byte, because deletion overwrites the sequence byte of the
    # first entry with 0xE5. Reconstructing a deleted file's long name is exactly
    # what a forensic reader must do, so the parse keeps 0xE5 LFN entries.
    files, lfn_parts, lfn_sum = [], [], None
    for i in range(0, len(stream), DIR_ENTRY_SIZE):
        e = stream[i:i + DIR_ENTRY_SIZE]
        if len(e) < DIR_ENTRY_SIZE or e[0] == 0x00:
            break
        attr = e[0x0B]
        if attr & 0x3F == ATTR_LONG_NAME:
            raw = bytes(e[0x01:0x0B]) + bytes(e[0x0E:0x1A]) + bytes(e[0x1C:0x20])
            if lfn_sum is not None and e[0x0D] != lfn_sum:
                lfn_parts = []                              # a new set began
            lfn_parts.append(raw)
            lfn_sum = e[0x0D]
            continue
        if attr & ATTR_VOLUME_ID and not attr & ATTR_DIRECTORY:
            lfn_parts, lfn_sum = [], None
            continue

        name11 = bytes(e[0x00:0x0B])
        deleted = name11[0] == DELETED_MARK
        raw = name11.decode("ascii", "replace")
        short = raw[:8].rstrip() + ("." + raw[8:].rstrip() if raw[8:].strip() else "")

        # Deletion overwrote the first byte of the 8.3 name, so the checksum the LFN
        # set carries no longer matches. The checksum is a bijection in that byte:
        # solve for it, which recovers the lost first character as well.
        recovered_first = None
        probe = name11
        if deleted and lfn_sum is not None:
            for b in range(256):
                cand = bytes([b]) + name11[1:]
                if lfn_checksum(cand) == lfn_sum:
                    probe, recovered_first = cand, b
                    break

        long_name = None
        if lfn_parts and lfn_sum == lfn_checksum(probe):
            text = b"".join(reversed(lfn_parts)).decode("utf-16-le", "replace")
            long_name = text.split("\x00", 1)[0].rstrip("\uffff")
        if recovered_first is not None:
            raw = probe.decode("ascii", "replace")
            short = raw[:8].rstrip() + ("." + raw[8:].rstrip() if raw[8:].strip() else "")
        lfn_parts, lfn_sum = [], None

        first = (struct.unpack_from("<H", e, 0x14)[0] << 16) | struct.unpack_from("<H", e, 0x1A)[0]
        size = struct.unpack_from("<I", e, 0x1C)[0]
        chain = [] if deleted or first == 0 else walk(first)
        blob = b"".join(bytes(img[off(c):off(c) + cluster_bytes]) for c in chain)[:size]
        files.append({
            "short_name": short,
            "long_name": long_name,
            "deleted": deleted,
            "size": size,
            "first_cluster": first,
            "chain": chain,
            "data": blob,
            "sha256": hashlib.sha256(blob).hexdigest(),
        })

    free = sum(1 for c in range(2, nclus + 2) if fat[c] == FREE)
    return {
        "bytes_per_sector": bps,
        "sectors_per_cluster": spc,
        "reserved": rsvd,
        "num_fats": nfat,
        "fat_sectors": fatsz,
        "total_sectors": total,
        "cluster_count": nclus,
        "data_start_offset": data_start_sector * bps,
        "root_cluster": root_cluster,
        "fats_identical": all(f == fats[0] for f in fats),
        "fat_free_clusters": free,
        "fsinfo_free": struct.unpack_from("<I", img, bps + 0x1E8)[0],
        "fsinfo_next_free": struct.unpack_from("<I", img, bps + 0x1EC)[0],
        "backup_boot_matches": bytes(img[6 * bps:7 * bps]) == bytes(img[0:bps]),
        "files": files,
    }
