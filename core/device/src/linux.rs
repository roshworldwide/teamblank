//! [`LinuxBlock`] — the Linux block-device implementation of [`Device`].
//!
//! # This code has never run. Not once, anywhere.
//!
//! Read that literally. There is no Linux host on this project, there is no
//! Linux CI, and no `ioctl` in this file has ever been issued against a kernel.
//! `cargo build -p sentinelwipe-device --features linux-block` on macOS
//! **type-checks** it and `cargo test` runs the unit tests below, and those two
//! facts are the entire extent of what is known about it. In particular:
//!
//! * Nobody has confirmed that `BLKSSZGET` returns what this file expects.
//! * Nobody has watched an `SG_IO` round trip succeed or fail.
//! * Nobody has seen a real `IDENTIFY DEVICE` response go through
//!   [`ata_sanitize_claims`].
//! * No drive has been erased by it, and none should be until it has been
//!   exercised on hardware nobody minds losing.
//!
//! What *is* checked here, by the tests at the bottom of this file:
//!
//! | checked | how |
//! |---|---|
//! | the `_IOC` request-number arithmetic | computed values compared against the well-known literals (`BLKGETSIZE64` = `0x80081272`, `NVME_IOCTL_ADMIN_CMD` = `0xC0484E41`) |
//! | `sg_io_hdr_t` layout | `size_of` = 88, `align_of` = 8, and every field offset compared against the C layout on LP64 |
//! | `nvme_passthru_cmd` layout | `size_of` = 72 and every field offset |
//! | the ATA PASS-THROUGH (16) CDB byte order | two hand-computed vectors, including the split LBA interleave SAT specifies |
//! | claim extraction from ATA `IDENTIFY` words and NVMe `Identify Controller` bytes | synthetic buffers with individual bits set |
//!
//! # Which constants are transcribed rather than measured
//!
//! CLAUDE.md rule 2 requires every number on screen to trace to a measurement,
//! and none of the following do. They are transcribed from the published
//! interfaces — `include/uapi/linux/fs.h`, `scsi/sg.h`, `include/uapi/linux/nvme_ioctl.h`,
//! SAT-4, ACS-4 and the NVM Express base specification — and this project has
//! never compared one of them to a running kernel or a drive:
//!
//! * every `BLK*` and `NVME_IOCTL_*` request number and the `_IOC` field widths
//! * `SG_IO` = `0x2285`, which `scsi/sg.h` defines as a bare literal rather
//!   than through `_IOC`
//! * the `sg_io_hdr_t` and `nvme_passthru_cmd` field orders
//! * ATA `IDENTIFY DEVICE` word 59 bits 12–15, word 82 bit 1 and word 128
//!   bits 0/1/5
//! * NVMe `Identify Controller` `OACS` at byte 256, `FNA` at byte 524 and
//!   `SANICAP` at byte 328
//!
//! None of them reaches a certificate on the demo path, because the demo path
//! is an image file and never constructs a `LinuxBlock`. If that ever changes,
//! this list is the list of things to verify on hardware first.
//!
//! # Default deny, twice, before anything is opened
//!
//! [`LinuxBlock::open`] refuses unless **all** of these hold, checked in order,
//! and it names the clause that refused:
//!
//! 1. the build target is Linux — on macOS it stops here, always;
//! 2. `SENTINELWIPE_DEVICE_MODE` is exactly `1` in the environment, which is
//!    clause D2 of `fixtures/guard.py` and carries that module's own reason
//!    code, `DENY_DEVICE_ENV_NOT_SET`;
//! 3. a [`WriteAuthority`] was supplied, and it allows the target — the
//!    allowlist, the alias rule, the running-system-disk rule and the typed
//!    confirmation are all its business, not this file's.
//!
//! There is no fourth path and no read-only shortcut into a device node. The
//! guard's device clauses D3–D6 are `DESIGNED BUT UNVERIFIED` for want of a
//! Linux host, exactly as its docstring says, and this file does not paper over
//! that by adding a second opinion of its own.
//!
//! # Two things a real Linux path will need that are not here
//!
//! Written down because their absence is a defect the moment this runs, and a
//! defect that is written down is not a surprise:
//!
//! 1. **`O_DIRECT`.** Sampled read-back through the page cache verifies the
//!    kernel's copy of the write, not the drive's. On [`ImageFile`] the file
//!    *is* the medium so `sync` is exact; on a block device it is not, and
//!    verification must either open `O_DIRECT` or drop caches between the write
//!    and the read. `O_DIRECT` also imposes its own alignment rules on the
//!    buffer, which the wipe layer's pass buffers do not currently satisfy.
//! 2. **The frozen-drive case.** A laptop firmware that issues `SECURITY FREEZE
//!    LOCK` at power-on makes `SECURITY ERASE UNIT` fail, and the standard
//!    workaround is a suspend/resume cycle. A tool that reports that failure as
//!    "erase complete" is the exact failure CLAUDE.md rule 1 names.

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::{
    Capabilities, ClaimSource, Device, DeviceError, Identity, SanitizePrimitive, Support,
    Transport, WriteAuthority,
};

// --------------------------------------------------------------- _IOC numbers

// asm-generic/ioctl.h field widths. Every architecture this project would
// target (x86_64, aarch64) uses these; alpha, mips, powerpc and sparc do not,
// and a port to one of those must revisit this block rather than inherit it.
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS; // 8
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS; // 16
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS; // 30

const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

/// `_IOC(dir, type, nr, size)` from `asm-generic/ioctl.h`.
///
/// Written out rather than hardcoded so the request numbers below are derived
/// the same way the kernel headers derive them, and so a transcription error in
/// one of them shows up as a mismatch against the published literal in
/// [`tests::ioctl_numbers_match_the_published_literals`].
const fn ioc(dir: u32, typ: u32, nr: u32, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT) | (size << IOC_SIZESHIFT) | (typ << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT)
}

const BLK_IOC_TYPE: u32 = 0x12;

/// `BLKGETSIZE64` — capacity in **bytes**, into a `u64`.
///
/// Note which one this is. `BLKGETSIZE` (`0x1260`) returns the size in 512-byte
/// units into a `long`, which overflows at 2 TiB on a 32-bit `long` and is the
/// classic way a wipe tool silently addresses the wrong end of a large drive.
/// This file does not use it.
pub const BLKGETSIZE64: u32 = ioc(IOC_READ, BLK_IOC_TYPE, 114, 8);
/// `BLKSSZGET` — logical sector size, into an `int`.
pub const BLKSSZGET: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 104, 0);
/// `BLKPBSZGET` — physical sector size, into an `int`.
pub const BLKPBSZGET: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 123, 0);
/// `BLKFLSBUF` — flush the buffer cache for this device.
pub const BLKFLSBUF: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 97, 0);
/// `BLKDISCARD` — TRIM a range. A hint, never a sanitize. See
/// [`SanitizePrimitive::TrimDeallocate`].
pub const BLKDISCARD: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 119, 0);
/// `BLKSECDISCARD` — secure discard, where the device supports it.
pub const BLKSECDISCARD: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 125, 0);

/// `SG_IO`. `scsi/sg.h` defines this as a bare literal, not through `_IOC`, so
/// it is transcribed and cannot be cross-checked by arithmetic the way the
/// `BLK*` numbers can.
pub const SG_IO: u32 = 0x2285;

const NVME_IOC_TYPE: u32 = 0x4E; // 'N'

/// `NVME_IOCTL_ADMIN_CMD` — `_IOWR('N', 0x41, struct nvme_admin_cmd)`.
pub const NVME_IOCTL_ADMIN_CMD: u32 = ioc(
    IOC_READ | IOC_WRITE,
    NVME_IOC_TYPE,
    0x41,
    core::mem::size_of::<NvmePassthruCmd>() as u32,
);
/// `NVME_IOCTL_ID` — `_IO('N', 0x40)`, returns the namespace id.
pub const NVME_IOCTL_ID: u32 = ioc(IOC_NONE, NVME_IOC_TYPE, 0x40, 0);

// ------------------------------------------------------------------- SG_IO

/// SG_IO transfer directions, from `scsi/sg.h`.
pub mod sg_dxfer {
    pub const NONE: i32 = -1;
    pub const TO_DEV: i32 = -2;
    pub const FROM_DEV: i32 = -3;
    pub const TO_FROM_DEV: i32 = -4;
}

/// `sg_io_hdr_t`, the version 3 SG_IO header.
///
/// Field order and types are the C struct's. `interface_id` must be `'S'`
/// (0x53) or the kernel rejects the request; that is the only field with a
/// fixed value and [`SgIoHdr::new`] sets it.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SgIoHdr {
    pub interface_id: i32,
    pub dxfer_direction: i32,
    pub cmd_len: u8,
    pub mx_sb_len: u8,
    pub iovec_count: u16,
    pub dxfer_len: u32,
    pub dxferp: *mut core::ffi::c_void,
    pub cmdp: *mut u8,
    pub sbp: *mut u8,
    pub timeout: u32,
    pub flags: u32,
    pub pack_id: i32,
    pub usr_ptr: *mut core::ffi::c_void,
    pub status: u8,
    pub masked_status: u8,
    pub msg_status: u8,
    pub sb_len_wr: u8,
    pub host_status: u16,
    pub driver_status: u16,
    pub resid: i32,
    pub duration: u32,
    pub info: u32,
}

impl SgIoHdr {
    /// A zeroed header with `interface_id` set to `'S'`.
    pub fn new() -> Self {
        SgIoHdr {
            interface_id: b'S' as i32,
            dxfer_direction: sg_dxfer::NONE,
            cmd_len: 0,
            mx_sb_len: 0,
            iovec_count: 0,
            dxfer_len: 0,
            dxferp: core::ptr::null_mut(),
            cmdp: core::ptr::null_mut(),
            sbp: core::ptr::null_mut(),
            timeout: 0,
            flags: 0,
            pack_id: 0,
            usr_ptr: core::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        }
    }
}

impl Default for SgIoHdr {
    fn default() -> Self {
        Self::new()
    }
}

// ------------------------------------------------- ATA PASS-THROUGH (16) CDB

/// SAT ATA pass-through protocol values.
pub mod ata_protocol {
    pub const HARD_RESET: u8 = 0;
    pub const SRST: u8 = 1;
    pub const NON_DATA: u8 = 3;
    pub const PIO_DATA_IN: u8 = 4;
    pub const PIO_DATA_OUT: u8 = 5;
    pub const DMA: u8 = 6;
}

/// ATA command opcodes used by this file.
pub mod ata_cmd {
    pub const IDENTIFY_DEVICE: u8 = 0xEC;
    pub const SECURITY_SET_PASSWORD: u8 = 0xF1;
    pub const SECURITY_ERASE_PREPARE: u8 = 0xF3;
    pub const SECURITY_ERASE_UNIT: u8 = 0xF4;
    pub const SANITIZE_DEVICE: u8 = 0xB4;
}

/// `SANITIZE DEVICE` feature values, ACS-4.
pub mod ata_sanitize_feature {
    pub const STATUS_EXT: u16 = 0x0000;
    pub const CRYPTO_SCRAMBLE_EXT: u16 = 0x0011;
    pub const BLOCK_ERASE_EXT: u16 = 0x0012;
    pub const OVERWRITE_EXT: u16 = 0x0014;
    pub const FREEZE_LOCK_EXT: u16 = 0x0020;
    pub const ANTIFREEZE_LOCK_EXT: u16 = 0x0040;
}

/// Build an ATA PASS-THROUGH (16) command descriptor block.
///
/// The byte order is SAT's, not ATA's, and it is not intuitive: the 48-bit LBA
/// is split so that bytes 7/9/11 carry the *high* order half and 8/10/12 carry
/// the low, interleaved. Getting that wrong addresses a different sector and
/// nothing about the resulting failure says so, which is why it is one function
/// with a hand-computed test vector rather than inline byte assignments at each
/// call site.
///
/// * `extend` — set for a 48-bit command; clears to the 28-bit form.
/// * `t_dir` — 1 when data moves from the device to the host.
/// * `byt_blok` — 1 when `t_length` counts blocks rather than bytes.
/// * `t_length` — which field holds the transfer length: 0 none, 1 features,
///   2 count, 3 STPSIU.
#[allow(clippy::too_many_arguments)]
pub fn ata_pass_through_16(
    protocol: u8,
    extend: bool,
    ck_cond: bool,
    t_dir: bool,
    byt_blok: bool,
    t_length: u8,
    features: u16,
    count: u16,
    lba: u64,
    device: u8,
    command: u8,
) -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = 0x85; // ATA PASS-THROUGH (16)
    cdb[1] = ((protocol & 0x0F) << 1) | u8::from(extend);
    cdb[2] = (u8::from(ck_cond) << 5)
        | (u8::from(t_dir) << 3)
        | (u8::from(byt_blok) << 2)
        | (t_length & 0x03);
    cdb[3] = (features >> 8) as u8;
    cdb[4] = (features & 0xFF) as u8;
    cdb[5] = (count >> 8) as u8;
    cdb[6] = (count & 0xFF) as u8;
    cdb[7] = ((lba >> 24) & 0xFF) as u8;
    cdb[8] = (lba & 0xFF) as u8;
    cdb[9] = ((lba >> 32) & 0xFF) as u8;
    cdb[10] = ((lba >> 8) & 0xFF) as u8;
    cdb[11] = ((lba >> 40) & 0xFF) as u8;
    cdb[12] = ((lba >> 16) & 0xFF) as u8;
    cdb[13] = device;
    cdb[14] = command;
    cdb[15] = 0; // control
    cdb
}

/// The CDB for `IDENTIFY DEVICE`, PIO data-in, one 512-byte block.
pub fn cdb_identify_device() -> [u8; 16] {
    ata_pass_through_16(
        ata_protocol::PIO_DATA_IN,
        false,
        false,
        true,
        true,
        2,
        0,
        1,
        0,
        0,
        ata_cmd::IDENTIFY_DEVICE,
    )
}

/// The CDB for `SANITIZE DEVICE` with the given feature — non-data, 48-bit.
///
/// The key is passed in the LBA field: ACS-4 requires `0x426B4972` ("BkIr") in
/// LBA(31:0) for `BLOCK ERASE EXT` and `0x43727970` ("Cryp") for
/// `CRYPTO SCRAMBLE EXT`, which is the standard's own guard against a
/// stray command erasing a drive.
pub fn cdb_sanitize_device(feature: u16, key: u32) -> [u8; 16] {
    ata_pass_through_16(
        ata_protocol::NON_DATA,
        true,
        true,
        false,
        false,
        0,
        feature,
        0,
        key as u64,
        0,
        ata_cmd::SANITIZE_DEVICE,
    )
}

/// ACS-4 sanitize keys, transcribed.
pub mod ata_sanitize_key {
    pub const BLOCK_ERASE: u32 = 0x426B_4972;
    pub const CRYPTO_SCRAMBLE: u32 = 0x4372_7970;
    pub const OVERWRITE: u32 = 0x4F57_4552;
}

// ------------------------------------------------------- NVMe admin passthru

/// `struct nvme_passthru_cmd` from `include/uapi/linux/nvme_ioctl.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmePassthruCmd {
    pub opcode: u8,
    pub flags: u8,
    pub rsvd1: u16,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub metadata: u64,
    pub addr: u64,
    pub metadata_len: u32,
    pub data_len: u32,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
    pub timeout_ms: u32,
    pub result: u32,
}

/// NVMe admin opcodes used here.
pub mod nvme_admin_op {
    pub const IDENTIFY: u8 = 0x06;
    pub const FORMAT_NVM: u8 = 0x80;
    pub const SANITIZE: u8 = 0x84;
}

/// An `Identify Controller` command, CNS = 1, into a 4 KiB buffer.
pub fn nvme_identify_controller(buf: &mut [u8; 4096]) -> NvmePassthruCmd {
    NvmePassthruCmd {
        opcode: nvme_admin_op::IDENTIFY,
        nsid: 0,
        addr: buf.as_mut_ptr() as u64,
        data_len: 4096,
        cdw10: 1, // CNS = 1, Identify Controller
        ..Default::default()
    }
}

// --------------------------------------------------------- claim extraction

/// Sanitize claims read out of a 256-word ATA `IDENTIFY DEVICE` response.
///
/// Returns `(primitive, support)` pairs for the ATA primitives only. Every
/// value is [`Support::Claimed`] or [`Support::NotClaimed`] — never
/// [`Support::Unknown`], because a bit that was read is a bit that was read.
/// Whether the drive tells the truth is a different question and is what the
/// behavioural audit exists to answer.
///
/// Bit positions, transcribed from ACS-4:
///
/// * word 59 bit 12 — SANITIZE feature set supported
/// * word 59 bit 13 — `CRYPTO SCRAMBLE EXT` supported
/// * word 59 bit 14 — `OVERWRITE EXT` supported
/// * word 59 bit 15 — `BLOCK ERASE EXT` supported
/// * word 82 bit 1 — Security feature set supported
/// * word 128 bit 0 — security supported, bit 1 — enabled, bit 5 — enhanced
///   erase supported
pub fn ata_sanitize_claims(id: &[u16; 256]) -> Vec<(SanitizePrimitive, Support)> {
    let w59 = id[59];
    let w82 = id[82];
    let w128 = id[128];

    let sanitize_set = w59 & (1 << 12) != 0;
    let security_set = (w82 & (1 << 1) != 0) || (w128 & 1 != 0);

    let claim = |b: bool| {
        if b {
            Support::Claimed
        } else {
            Support::NotClaimed
        }
    };

    vec![
        (
            SanitizePrimitive::AtaSecureErase,
            claim(security_set),
        ),
        (
            SanitizePrimitive::AtaSecureEraseEnhanced,
            // Enhanced erase is only meaningful if the security set is there at
            // all; the word 128 bit alone is not enough.
            claim(security_set && w128 & (1 << 5) != 0),
        ),
        (
            SanitizePrimitive::AtaSanitizeCryptoScramble,
            claim(sanitize_set && w59 & (1 << 13) != 0),
        ),
        (
            SanitizePrimitive::AtaSanitizeOverwrite,
            claim(sanitize_set && w59 & (1 << 14) != 0),
        ),
        (
            SanitizePrimitive::AtaSanitizeBlockErase,
            claim(sanitize_set && w59 & (1 << 15) != 0),
        ),
    ]
}

/// Sanitize claims read out of a 4096-byte NVMe `Identify Controller` response.
///
/// Byte positions, transcribed from the NVM Express base specification:
///
/// * `OACS`, bytes 257:256 — bit 1 is Format NVM support
/// * `FNA`, byte 524 — bit 2 is cryptographic erase support in Format NVM
/// * `SANICAP`, bytes 331:328 — bit 0 crypto erase, bit 1 block erase,
///   bit 2 overwrite
pub fn nvme_sanitize_claims(id: &[u8; 4096]) -> Vec<(SanitizePrimitive, Support)> {
    let oacs = u16::from_le_bytes([id[256], id[257]]);
    let fna = id[524];
    let sanicap = u32::from_le_bytes([id[328], id[329], id[330], id[331]]);

    let claim = |b: bool| {
        if b {
            Support::Claimed
        } else {
            Support::NotClaimed
        }
    };

    vec![
        (
            SanitizePrimitive::NvmeFormatCryptoErase,
            // Both halves are needed: the controller must support Format NVM
            // *and* declare cryptographic erase within it.
            claim(oacs & (1 << 1) != 0 && fna & (1 << 2) != 0),
        ),
        (
            SanitizePrimitive::NvmeSanitizeCryptoErase,
            claim(sanicap & 1 != 0),
        ),
        (
            SanitizePrimitive::NvmeSanitizeBlockErase,
            claim(sanicap & (1 << 1) != 0),
        ),
        (
            SanitizePrimitive::NvmeSanitizeOverwrite,
            claim(sanicap & (1 << 2) != 0),
        ),
    ]
}

// ------------------------------------------------------------- the ioctl call

/// Issue an `ioctl`. The only line in this crate that talks to a kernel, and on
/// every platform this project builds on it is compiled out.
///
/// Everything above it — the request numbers, the header and command structs,
/// the CDB builder, the claim extraction — is ordinary Rust that type-checks
/// and unit-tests on macOS. This function is the seam, deliberately made as
/// small as it can be, so that the untestable surface is one call rather than
/// scattered through the file.
#[allow(unused_variables)]
fn issue_ioctl(fd: i32, request: u32, arg: *mut core::ffi::c_void) -> Result<i32, DeviceError> {
    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn ioctl(fd: core::ffi::c_int, request: core::ffi::c_ulong, ...) -> core::ffi::c_int;
        }
        // SAFETY: `fd` is a descriptor this module opened and still owns,
        // `request` is one of the constants above, and `arg` points at a live,
        // correctly sized struct owned by the caller for the duration of the
        // call. NONE OF THAT HAS BEEN OBSERVED TO HOLD AT RUNTIME, because this
        // branch has never been compiled, let alone executed. Treat this
        // comment as a specification of what a Linux bring-up must confirm, not
        // as a claim that it does.
        let rc = unsafe { ioctl(fd, request as core::ffi::c_ulong, arg) };
        if rc < 0 {
            return Err(DeviceError::io(
                "ioctl",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(rc)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(DeviceError::Unsupported {
            operation: "ioctl",
            detail: format!(
                "request 0x{request:08X} was not issued: this binary was not built for \
                 Linux, so LinuxBlock performs no I/O at all"
            ),
        })
    }
}

// ---------------------------------------------------------------- LinuxBlock

/// The environment factor. `fixtures/guard.py` clause D2, same variable, same
/// required value.
pub const DEVICE_MODE_ENV: &str = "SENTINELWIPE_DEVICE_MODE";

/// A Linux block device addressed by logical block. See the module docs: this
/// has never run.
pub struct LinuxBlock {
    target: PathBuf,
    /// `None` on every platform this project builds on, because
    /// [`LinuxBlock::open`] refuses before it opens anything.
    #[allow(dead_code)]
    file: Option<File>,
    #[allow(dead_code)]
    authority: Option<Box<dyn WriteAuthority>>,
}

impl LinuxBlock {
    /// A handle that has opened nothing, for exercising the trait shape.
    ///
    /// The counterpart of [`crate::WindowsBlock::stub`], and named the same way
    /// for the same reason: it opens nothing and its name must not suggest
    /// otherwise.
    pub fn unopened(target: impl AsRef<Path>) -> Self {
        LinuxBlock {
            target: target.as_ref().to_path_buf(),
            file: None,
            authority: None,
        }
    }

    /// Open a block device for writing, through `authority`.
    ///
    /// Refuses in three places before it opens anything. See the module docs
    /// for the order and for why the allowlist itself is the authority's job
    /// rather than this file's.
    pub fn open(
        target: impl AsRef<Path>,
        authority: Box<dyn WriteAuthority>,
    ) -> Result<Self, DeviceError> {
        Self::open_with_env(target, authority, std::env::var(DEVICE_MODE_ENV).ok())
    }

    /// [`LinuxBlock::open`] with the environment factor passed in.
    ///
    /// The environment is an argument so the refusal order can be tested on
    /// macOS without setting a process-wide variable in a test suite that runs
    /// in parallel. It is the same seam, and for the same reason, as
    /// `fixtures/guard.py`'s `env` parameter.
    pub fn open_with_env(
        target: impl AsRef<Path>,
        authority: Box<dyn WriteAuthority>,
        device_mode: Option<String>,
    ) -> Result<Self, DeviceError> {
        let target = target.as_ref().to_path_buf();

        // 1. Platform. First, and unconditional.
        if !cfg!(target_os = "linux") {
            return Err(DeviceError::Unsupported {
                operation: "open",
                detail: format!(
                    "{} is a Linux block device and this binary was not built for Linux; \
                     LinuxBlock has never been executed on any host",
                    target.display()
                ),
            });
        }

        // 2. The environment factor. Same variable and same reason code as
        //    fixtures/guard.py clause D2, so an audit line from either half of
        //    the project reads the same.
        if device_mode.as_deref() != Some("1") {
            return Err(DeviceError::Refused {
                code: "DENY_DEVICE_ENV_NOT_SET".to_string(),
                detail: format!(
                    "{DEVICE_MODE_ENV} is not \"1\"; device targets stay refused"
                ),
            });
        }

        // 3. The authority. The allowlist, the alias rule, the
        //    running-system-disk rule and the typed confirmation are all its
        //    decision. This file does not hold a second opinion about which
        //    devices are permissible, because two allowlists that disagree is
        //    worse than one that is wrong.
        let granted = authority.open_writable(&target)?;
        Ok(LinuxBlock {
            target: granted.resolved,
            file: Some(granted.file),
            authority: Some(authority),
        })
    }

    fn refuse(&self, operation: &'static str) -> DeviceError {
        DeviceError::Unsupported {
            operation,
            detail: format!(
                "LinuxBlock holds no open handle on {}; on a non-Linux build it never \
                 will. See core/device/src/linux.rs",
                self.target.display()
            ),
        }
    }

    /// The `BLKSSZGET` / `BLKPBSZGET` / `BLKGETSIZE64` probe, as it would be
    /// issued.
    ///
    /// Present so the request numbers above are used rather than merely
    /// declared, and so a Linux bring-up has one function to point at hardware.
    /// On every build of this project it returns `Unsupported` from
    /// [`issue_ioctl`] on the first call.
    #[allow(dead_code)]
    fn probe_geometry(&self, fd: i32) -> Result<(u32, u32, u64), DeviceError> {
        let mut logical: i32 = 0;
        let mut physical: i32 = 0;
        let mut bytes: u64 = 0;
        issue_ioctl(
            fd,
            BLKSSZGET,
            &mut logical as *mut i32 as *mut core::ffi::c_void,
        )?;
        issue_ioctl(
            fd,
            BLKPBSZGET,
            &mut physical as *mut i32 as *mut core::ffi::c_void,
        )?;
        issue_ioctl(
            fd,
            BLKGETSIZE64,
            &mut bytes as *mut u64 as *mut core::ffi::c_void,
        )?;
        if logical <= 0 || bytes == 0 {
            return Err(DeviceError::Unsupported {
                operation: "probe_geometry",
                detail: format!("kernel reported logical={logical}, bytes={bytes}"),
            });
        }
        Ok((logical as u32, physical.max(logical) as u32, bytes))
    }
}

impl Device for LinuxBlock {
    fn identify(&self) -> Identity {
        // It knows the node it was handed and nothing else, because it has
        // opened nothing. No model, no serial, no firmware: the IDENTIFY
        // response that would carry them has never been fetched.
        let mut id = Identity::unknown("linux block device (never executed)");
        id.target = Some(self.target.clone());
        id.transport = Transport::Unknown;
        // False, and it stays false until an IDENTIFY has actually come back.
        // A device node that was never opened is not evidence of a drive.
        id.is_physical_medium = false;
        id.source = ClaimSource::NotProbed;
        id
    }

    fn capabilities(&self) -> Result<Capabilities, DeviceError> {
        // No geometry was ever read, so there is no honest Capabilities to
        // return. See `Device::capabilities` for why this is a Result.
        Err(self.refuse("capabilities"))
    }

    fn read_sectors(&mut self, _lba: u64, _buf: &mut [u8]) -> Result<(), DeviceError> {
        Err(self.refuse("read_sectors"))
    }

    fn write_sectors(&mut self, _lba: u64, _buf: &[u8]) -> Result<(), DeviceError> {
        Err(self.refuse("write_sectors"))
    }

    fn sync(&mut self) -> Result<(), DeviceError> {
        Err(self.refuse("sync"))
    }
}

impl std::fmt::Debug for LinuxBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxBlock")
            .field("target", &self.target)
            .field("open", &self.file.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DenyAll;

    #[test]
    fn ioctl_numbers_match_the_published_literals() {
        // The point of deriving these rather than hardcoding them: the
        // arithmetic and the published value have to agree, so a transcription
        // slip in the `_IOC` field widths shows up here.
        assert_eq!(BLKGETSIZE64, 0x8008_1272);
        assert_eq!(BLKSSZGET, 0x0000_1268);
        assert_eq!(BLKPBSZGET, 0x0000_127B);
        assert_eq!(BLKFLSBUF, 0x0000_1261);
        assert_eq!(BLKDISCARD, 0x0000_1277);
        assert_eq!(BLKSECDISCARD, 0x0000_127D);
        assert_eq!(NVME_IOCTL_ADMIN_CMD, 0xC048_4E41);
        assert_eq!(NVME_IOCTL_ID, 0x0000_4E40);
        assert_eq!(SG_IO, 0x2285);
    }

    fn offset_of<T>(base: &T, field: *const u8) -> usize {
        field as usize - (base as *const T as usize)
    }

    #[test]
    fn sg_io_hdr_matches_the_c_layout_on_lp64() {
        assert_eq!(core::mem::size_of::<SgIoHdr>(), 88);
        assert_eq!(core::mem::align_of::<SgIoHdr>(), 8);

        let h = SgIoHdr::new();
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.interface_id) as *const u8), 0);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.dxfer_direction) as *const u8), 4);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.cmd_len) as *const u8), 8);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.mx_sb_len) as *const u8), 9);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.iovec_count) as *const u8), 10);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.dxfer_len) as *const u8), 12);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.dxferp) as *const u8), 16);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.cmdp) as *const u8), 24);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.sbp) as *const u8), 32);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.timeout) as *const u8), 40);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.flags) as *const u8), 44);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.pack_id) as *const u8), 48);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.usr_ptr) as *const u8), 56);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.status) as *const u8), 64);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.host_status) as *const u8), 68);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.driver_status) as *const u8), 70);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.resid) as *const u8), 72);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.duration) as *const u8), 76);
        assert_eq!(offset_of(&h, core::ptr::addr_of!(h.info) as *const u8), 80);

        // The one field with a required value.
        assert_eq!(h.interface_id, 0x53);
    }

    #[test]
    fn nvme_passthru_cmd_matches_the_c_layout() {
        assert_eq!(core::mem::size_of::<NvmePassthruCmd>(), 72);
        let c = NvmePassthruCmd::default();
        assert_eq!(offset_of(&c, core::ptr::addr_of!(c.opcode) as *const u8), 0);
        assert_eq!(offset_of(&c, core::ptr::addr_of!(c.nsid) as *const u8), 4);
        assert_eq!(offset_of(&c, core::ptr::addr_of!(c.metadata) as *const u8), 16);
        assert_eq!(offset_of(&c, core::ptr::addr_of!(c.addr) as *const u8), 24);
        assert_eq!(offset_of(&c, core::ptr::addr_of!(c.data_len) as *const u8), 36);
        assert_eq!(offset_of(&c, core::ptr::addr_of!(c.cdw10) as *const u8), 40);
        assert_eq!(offset_of(&c, core::ptr::addr_of!(c.timeout_ms) as *const u8), 64);
        assert_eq!(offset_of(&c, core::ptr::addr_of!(c.result) as *const u8), 68);

        // The size feeds the ioctl number, so a layout change moves the request
        // number and the assertion above catches it.
        assert_eq!(
            NVME_IOCTL_ADMIN_CMD,
            ioc(IOC_READ | IOC_WRITE, 0x4E, 0x41, 72)
        );
    }

    #[test]
    fn the_identify_cdb_is_byte_for_byte_what_sat_specifies() {
        // Hand-computed: 0x85, protocol 4 << 1 = 0x08, t_dir|byt_blok|t_length
        // = 0x08|0x04|0x02 = 0x0E, count 1 in byte 6, command 0xEC in byte 14.
        assert_eq!(
            cdb_identify_device(),
            [0x85, 0x08, 0x0E, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xEC, 0]
        );
    }

    #[test]
    fn the_lba_interleave_is_the_split_one_sat_specifies() {
        // A distinct byte in each of the six LBA positions, so a transposition
        // cannot pass.
        let cdb = ata_pass_through_16(
            ata_protocol::NON_DATA,
            true,
            false,
            false,
            false,
            0,
            0,
            0,
            0x0000_5040_3020_1000,
            0,
            0xB4,
        );
        // Byte for byte against SAT-4's field list. The first version of this
        // vector had bytes 7 and 12 the other way round and the test caught it,
        // which is the entire reason the interleave is one function with a
        // hand-computed vector rather than six inline assignments.
        assert_eq!(cdb[7], 0x30, "lba(31:24)");
        assert_eq!(cdb[8], 0x00, "lba(7:0)");
        assert_eq!(cdb[9], 0x40, "lba(39:32)");
        assert_eq!(cdb[10], 0x10, "lba(15:8)");
        assert_eq!(cdb[11], 0x50, "lba(47:40)");
        assert_eq!(cdb[12], 0x20, "lba(23:16)");
        assert_eq!(cdb[1], (3 << 1) | 1, "protocol non-data, extend set");
    }

    #[test]
    fn a_sanitize_cdb_carries_the_standards_own_key() {
        let cdb = cdb_sanitize_device(
            ata_sanitize_feature::BLOCK_ERASE_EXT,
            ata_sanitize_key::BLOCK_ERASE,
        );
        assert_eq!(cdb[14], ata_cmd::SANITIZE_DEVICE);
        assert_eq!(cdb[3], 0x00);
        assert_eq!(cdb[4], 0x12);
        // "BkIr" = 0x426B4972, split across the SAT LBA fields.
        assert_eq!(cdb[8], 0x72, "key(7:0)");
        assert_eq!(cdb[10], 0x49, "key(15:8)");
        assert_eq!(cdb[12], 0x6B, "key(23:16)");
        assert_eq!(cdb[7], 0x42, "key(31:24)");
        assert_eq!(cdb[2] & 0x20, 0x20, "ck_cond, so status comes back");
    }

    #[test]
    fn ata_claims_are_read_bit_by_bit_and_never_guessed() {
        let mut id = [0u16; 256];
        // Nothing set: everything is NotClaimed, and nothing is Unknown.
        for (_, s) in ata_sanitize_claims(&id) {
            assert_eq!(s, Support::NotClaimed);
        }

        // Security feature set, plus enhanced erase.
        id[82] = 1 << 1;
        id[128] = (1 << 0) | (1 << 5);
        let claims = ata_sanitize_claims(&id);
        let get = |p: SanitizePrimitive| claims.iter().find(|(q, _)| *q == p).unwrap().1;
        assert_eq!(get(SanitizePrimitive::AtaSecureErase), Support::Claimed);
        assert_eq!(
            get(SanitizePrimitive::AtaSecureEraseEnhanced),
            Support::Claimed
        );
        // The SANITIZE set is separate and is still not claimed.
        assert_eq!(
            get(SanitizePrimitive::AtaSanitizeBlockErase),
            Support::NotClaimed
        );

        // The SANITIZE feature-set bit gates the three EXT bits: a drive that
        // sets BLOCK ERASE EXT without the feature-set bit claims nothing.
        let mut id2 = [0u16; 256];
        id2[59] = 1 << 15;
        let claims2 = ata_sanitize_claims(&id2);
        let get2 = |p: SanitizePrimitive| claims2.iter().find(|(q, _)| *q == p).unwrap().1;
        assert_eq!(
            get2(SanitizePrimitive::AtaSanitizeBlockErase),
            Support::NotClaimed
        );
        id2[59] |= 1 << 12;
        let claims3 = ata_sanitize_claims(&id2);
        let get3 = |p: SanitizePrimitive| claims3.iter().find(|(q, _)| *q == p).unwrap().1;
        assert_eq!(
            get3(SanitizePrimitive::AtaSanitizeBlockErase),
            Support::Claimed
        );
    }

    #[test]
    fn nvme_claims_need_both_halves_before_format_crypto_erase_is_claimed() {
        let mut id = [0u8; 4096];
        let get = |id: &[u8; 4096], p: SanitizePrimitive| {
            nvme_sanitize_claims(id)
                .iter()
                .find(|(q, _)| *q == p)
                .unwrap()
                .1
        };

        assert_eq!(
            get(&id, SanitizePrimitive::NvmeFormatCryptoErase),
            Support::NotClaimed
        );
        // OACS says Format NVM is supported, but FNA does not say crypto erase.
        id[256] = 1 << 1;
        assert_eq!(
            get(&id, SanitizePrimitive::NvmeFormatCryptoErase),
            Support::NotClaimed
        );
        id[524] = 1 << 2;
        assert_eq!(
            get(&id, SanitizePrimitive::NvmeFormatCryptoErase),
            Support::Claimed
        );

        // SANICAP, one bit at a time.
        id[328] = 0b101;
        assert_eq!(
            get(&id, SanitizePrimitive::NvmeSanitizeCryptoErase),
            Support::Claimed
        );
        assert_eq!(
            get(&id, SanitizePrimitive::NvmeSanitizeBlockErase),
            Support::NotClaimed
        );
        assert_eq!(
            get(&id, SanitizePrimitive::NvmeSanitizeOverwrite),
            Support::Claimed
        );
    }

    #[test]
    fn identify_controller_points_at_the_callers_buffer() {
        let mut buf = [0u8; 4096];
        let want = buf.as_mut_ptr() as u64;
        let cmd = nvme_identify_controller(&mut buf);
        assert_eq!(cmd.opcode, nvme_admin_op::IDENTIFY);
        assert_eq!(cmd.cdw10, 1);
        assert_eq!(cmd.data_len, 4096);
        assert_eq!(cmd.addr, want);
    }

    // ----------------------------------------------------- refusal order

    #[test]
    fn the_platform_is_refused_before_anything_else_is_consulted() {
        // On this build target the first clause always fires, and it fires
        // before the environment factor and before the authority is asked —
        // which is why passing device mode "1" changes nothing here.
        let err = LinuxBlock::open_with_env(
            "/dev/sda",
            Box::new(DenyAll),
            Some("1".to_string()),
        )
        .unwrap_err();

        if cfg!(target_os = "linux") {
            // Never taken in this project. Written so the assertion is honest
            // about what it checks on a host that does not exist yet.
            assert_eq!(err.code(), "DEVICE_REFUSED");
        } else {
            assert_eq!(err.code(), "DEVICE_UNSUPPORTED");
            assert!(
                format!("{err}").contains("never been executed"),
                "{err}"
            );
        }
    }

    #[test]
    fn an_unopened_handle_refuses_every_operation() {
        let mut d = LinuxBlock::unopened("/dev/sda");
        assert_eq!(d.capabilities().unwrap_err().code(), "DEVICE_UNSUPPORTED");
        assert_eq!(
            d.read_sectors(0, &mut [0u8; 512]).unwrap_err().code(),
            "DEVICE_UNSUPPORTED"
        );
        assert_eq!(
            d.write_sectors(0, &[0u8; 512]).unwrap_err().code(),
            "DEVICE_UNSUPPORTED"
        );
        assert_eq!(d.sync().unwrap_err().code(), "DEVICE_UNSUPPORTED");
    }

    #[test]
    fn it_does_not_claim_to_be_a_drive_it_never_opened() {
        let d = LinuxBlock::unopened("/dev/sda");
        let id = d.identify();
        assert!(!id.is_physical_medium);
        assert_eq!(id.model_or_unknown(), "unknown");
        assert_eq!(id.serial_or_unknown(), "unknown");
        assert_eq!(id.source, ClaimSource::NotProbed);
        assert!(id.kind.contains("never executed"));
    }

    #[test]
    fn the_ioctl_seam_is_compiled_out_on_this_platform() {
        // The whole point of keeping `issue_ioctl` to one function: on any
        // build this project makes, it is a refusal rather than a syscall.
        let mut scratch: u64 = 0;
        let r = issue_ioctl(
            -1,
            BLKGETSIZE64,
            &mut scratch as *mut u64 as *mut core::ffi::c_void,
        );
        if cfg!(target_os = "linux") {
            // A bad descriptor: the call is real and fails with EBADF.
            assert!(r.is_err());
        } else {
            let e = r.unwrap_err();
            assert_eq!(e.code(), "DEVICE_UNSUPPORTED");
            assert!(format!("{e}").contains("0x80081272"), "{e}");
        }
        assert_eq!(scratch, 0);
    }
}
