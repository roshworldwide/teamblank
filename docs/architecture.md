# Architecture

Component map, the telemetry path from Rust to the instrument, and the published
confidence function are written at Phase 2, against measured output only. This file
opens with the decisions that constrain everything downstream.

## D1 · Fixture substrate — hand-written FAT32, stdlib Python only

**Decided 2026-09-02. Status: adopted.**

The fixture is a FAT32 image this project writes byte by byte in pure Python. No
container runtime, no kernel formatter, no mounting, no new dependency.

### Why not the kernel toolchain

The build pack assumed Linux. This machine has no `losetup`, no `mke2fs`, no
`mkfs.vfat`, and a Docker daemon that is down. Two paths out were investigated and
both were rejected on measurement, not preference.

*Docker.* Docker Desktop 4.81.0 is installed but client-only: `docker info` exits 1,
`AutoStart` is false, and a 2.1 GB half-applied 4.86.0 update has been staged since
2026-08-12 that the next launch resumes. The tooling actually needed is 4.73 MiB; the
runtime around it is 17.2 GB, an 8 GB VM on a 16 GB machine, and root LaunchDaemons
wanting an admin password on a fresh laptop. No fallback runtime exists — colima,
podman, lima, nerdctl and qemu are all absent. `demo_script.md` already forbids this
shape in writing: a live filesystem operation never stands between the team and a
working demo.

*Native builds.* `mke2fs`, `debugfs`, `dumpe2fs` and `e2fsck` do build on macOS arm64,
and dosfstools 4.2 builds with a two-line shim. This was the strongest form of the
ext4 argument and it still fails, for one reason: the resulting image was validated
only by `dumpe2fs` — the same tool family inspecting its own output. No Linux kernel
has ever mounted it. The realism credential does not exist in any form available to
this team, while the cost of a second substrate is fully real.

Measured against determinism, the comparison is not close. `mke2fs -d` imports host
uid, gid and umask with no suppressing flag (umask 022 and 077 produce different
image hashes), one changed line in `mke2fs.conf` moves the hash, and three plausible
base tags carry three different e2fsprogs versions. `SOURCE_DATE_EPOCH` is not
honoured by released dosfstools 4.2. Meanwhile the pure-Python image reproduced
byte-identically across three independent runs under varied `TZ`, `LANG`, `umask`,
working directory and `PYTHONHASHSEED`, and across three CPython builds with three
different SQLite versions.

### Why a hand-written filesystem is not a shortcut

The carver does signature and structure carving and never parses filesystem metadata.
The substrate therefore has exactly three jobs: place bytes at known offsets, fragment
them across non-contiguous extents, and support deletion as unreferenced data. A
chosen cluster chain does all three better than a requested one — it is the only
approach where the fragment layout is an input the writer obeys rather than an
allocator outcome discovered afterwards. That is what makes the tri-fragment and
out-of-order cases buildable at all. `mke2fs` cannot be asked for them.

Evidence the image is a real filesystem and not a plausible-looking one: Apple's
`msdos` driver mounts it read-write, `fsck_msdos` exits 0 with no orphan clusters, and
a negative control confirms the driver is genuinely walking our chains — rewriting one
mid-chain FAT entry makes the fragmented file vanish from the mount. Five single-field
boot-sector corruptions each produced `no mountable file systems`, so the test can fail.

### The reproducibility defect this uncovered

`zlib.compress` output is a property of the linked libz, not of the input. Info-ZIP and
zlib produced 13,937 and 14,066 bytes from identical input, both decompressing
correctly. PNG, DOCX and GZIP all ride on DEFLATE, so the corpus would have differed
per laptop and the reproducibility rule would have failed in a way no single-machine
test could detect. uv's managed CPython bundles SQLite statically but still links the
system libz, so pinning the interpreter does not pin zlib.

The fixture therefore carries its own fixed-Huffman DEFLATE encoder. `zlib` is used
only for CRC32, Adler32 and round-trip verification, which are fixed algorithms.

### Nothing is mounted, by decision

`losetup` is inherited Linux shape from the build pack, and `hdiutil attach` is worse
than unnecessary on macOS: it assigns a runtime `/dev/diskN` that no allowlist written
in advance can name, and mounting into `/Volumes` lets Spotlight and `fseventsd` write
into the fixture. The carve/wipe/carve loop was run end to end on a raw image file with
zero subprocesses and zero mounts. `Loopback images only` in CLAUDE.md is read as scope
— image files rather than block devices — not as an instruction to attach anything.

The consequence, stated plainly: no kernel validates the image at build time, so this
is described as a raw image carrying FAT32-structured metadata, which is all the carver
requires, and never as a certified FAT32 volume.

### What this costs, and where it is written down

The fixture is FAT32 and nothing else. ext4, NTFS and APFS are out until nationals and
go on the slide rather than into the build. Byte-identity across six laptops remains an
inference until one teammate clones, builds and diffs a hash; no slide claims it before
then. The full limitations list is maintained in `standards_map.md`, and every one of
them is reproduced in the certificate rather than summarised.

### Operator decisions taken

- The demo reports the **measured** recovery count with both deliberately unsolvable
  cases named on screen, not a round 40 of 40. The fixture plants a tri-fragment DOCX
  and an out-of-order JPEG that bifragment gap carving cannot solve by construction; a
  fixture containing only cases we pass is not evidence.
- The writer implements **VFAT long filenames**, so `fls` output shows real names during
  the independent cross-check rather than 8.3 stubs.
- **The Sleuth Kit is installed** as the independent carving cross-check named in the
  locked stack. It is development tooling only: never imported at runtime, never added
  to `pyproject.toml`, and the cross-check test skips when it is absent.
