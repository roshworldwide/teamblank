use std::fs::File;
use std::path::{Path, PathBuf};

use crate::{
    Capabilities, ClaimSource, Device, DeviceError, Identity, SanitizePrimitive, Support,
    Transport, WriteAuthority,
};

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioc(dir: u32, typ: u32, nr: u32, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT) | (size << IOC_SIZESHIFT) | (typ << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT)
}

const BLK_IOC_TYPE: u32 = 0x12;

pub const BLKGETSIZE64: u32 = ioc(IOC_READ, BLK_IOC_TYPE, 114, 8);
pub const BLKSSZGET: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 104, 0);
pub const BLKPBSZGET: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 123, 0);
pub const BLKFLSBUF: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 97, 0);
pub const BLKDISCARD: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 119, 0);
pub const BLKSECDISCARD: u32 = ioc(IOC_NONE, BLK_IOC_TYPE, 125, 0);

pub const SG_IO: u32 = 0x2285;

const NVME_IOC_TYPE: u32 = 0x4E;

pub const NVME_IOCTL_ADMIN_CMD: u32 = ioc(
    IOC_READ | IOC_WRITE,
    NVME_IOC_TYPE,
    0x41,
    core::mem::size_of::<NvmePassthruCmd>() as u32,
);
pub const NVME_IOCTL_ID: u32 = ioc(IOC_NONE, NVME_IOC_TYPE, 0x40, 0);

pub mod sg_dxfer {
    pub const NONE: i32 = -1;
    pub const TO_DEV: i32 = -2;
    pub const FROM_DEV: i32 = -3;
    pub const TO_FROM_DEV: i32 = -4;
}

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

pub mod ata_protocol {
    pub const HARD_RESET: u8 = 0;
    pub const SRST: u8 = 1;
    pub const NON_DATA: u8 = 3;
    pub const PIO_DATA_IN: u8 = 4;
    pub const PIO_DATA_OUT: u8 = 5;
    pub const DMA: u8 = 6;
}

pub mod ata_cmd {
    pub const IDENTIFY_DEVICE: u8 = 0xEC;
    pub const SECURITY_SET_PASSWORD: u8 = 0xF1;
    pub const SECURITY_ERASE_PREPARE: u8 = 0xF3;
    pub const SECURITY_ERASE_UNIT: u8 = 0xF4;
    pub const SANITIZE_DEVICE: u8 = 0xB4;
}

pub mod ata_sanitize_feature {
    pub const STATUS_EXT: u16 = 0x0000;
    pub const CRYPTO_SCRAMBLE_EXT: u16 = 0x0011;
    pub const BLOCK_ERASE_EXT: u16 = 0x0012;
    pub const OVERWRITE_EXT: u16 = 0x0014;
    pub const FREEZE_LOCK_EXT: u16 = 0x0020;
    pub const ANTIFREEZE_LOCK_EXT: u16 = 0x0040;
}

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
    cdb[0] = 0x85;
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
    cdb[15] = 0;
    cdb
}

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

pub mod ata_sanitize_key {
    pub const BLOCK_ERASE: u32 = 0x426B_4972;
    pub const CRYPTO_SCRAMBLE: u32 = 0x4372_7970;
    pub const OVERWRITE: u32 = 0x4F57_4552;
}

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

pub mod nvme_admin_op {
    pub const IDENTIFY: u8 = 0x06;
    pub const FORMAT_NVM: u8 = 0x80;
    pub const SANITIZE: u8 = 0x84;
}

pub fn nvme_identify_controller(buf: &mut [u8; 4096]) -> NvmePassthruCmd {
    NvmePassthruCmd {
        opcode: nvme_admin_op::IDENTIFY,
        nsid: 0,
        addr: buf.as_mut_ptr() as u64,
        data_len: 4096,
        cdw10: 1,
        ..Default::default()
    }
}

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

pub const DEVICE_MODE_ENV: &str = "SENTINELWIPE_DEVICE_MODE";

pub struct LinuxBlock {
    target: PathBuf,
    #[allow(dead_code)]
    file: Option<File>,
    #[allow(dead_code)]
    authority: Option<Box<dyn WriteAuthority>>,
}

impl LinuxBlock {
    pub fn unopened(target: impl AsRef<Path>) -> Self {
        LinuxBlock {
            target: target.as_ref().to_path_buf(),
            file: None,
            authority: None,
        }
    }

    pub fn open(
        target: impl AsRef<Path>,
        authority: Box<dyn WriteAuthority>,
    ) -> Result<Self, DeviceError> {
        Self::open_with_env(target, authority, std::env::var(DEVICE_MODE_ENV).ok())
    }

    pub fn open_with_env(
        target: impl AsRef<Path>,
        authority: Box<dyn WriteAuthority>,
        device_mode: Option<String>,
    ) -> Result<Self, DeviceError> {
        let target = target.as_ref().to_path_buf();

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

        if device_mode.as_deref() != Some("1") {
            return Err(DeviceError::Refused {
                code: "DENY_DEVICE_ENV_NOT_SET".to_string(),
                detail: format!(
                    "{DEVICE_MODE_ENV} is not \"1\"; device targets stay refused"
                ),
            });
        }

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
        let mut id = Identity::unknown("linux block device (never executed)");
        id.target = Some(self.target.clone());
        id.transport = Transport::Unknown;
        id.is_physical_medium = false;
        id.source = ClaimSource::NotProbed;
        id
    }

    fn capabilities(&self) -> Result<Capabilities, DeviceError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DenyAll;

    #[test]
    fn ioctl_numbers_match_the_published_literals() {
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

        assert_eq!(
            NVME_IOCTL_ADMIN_CMD,
            ioc(IOC_READ | IOC_WRITE, 0x4E, 0x41, 72)
        );
    }

    #[test]
    fn the_identify_cdb_is_byte_for_byte_what_sat_specifies() {
        assert_eq!(
            cdb_identify_device(),
            [0x85, 0x08, 0x0E, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xEC, 0]
        );
    }

    #[test]
    fn the_lba_interleave_is_the_split_one_sat_specifies() {
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
        assert_eq!(cdb[8], 0x72, "key(7:0)");
        assert_eq!(cdb[10], 0x49, "key(15:8)");
        assert_eq!(cdb[12], 0x6B, "key(23:16)");
        assert_eq!(cdb[7], 0x42, "key(31:24)");
        assert_eq!(cdb[2] & 0x20, 0x20, "ck_cond, so status comes back");
    }

    #[test]
    fn ata_claims_are_read_bit_by_bit_and_never_guessed() {
        let mut id = [0u16; 256];
        for (_, s) in ata_sanitize_claims(&id) {
            assert_eq!(s, Support::NotClaimed);
        }

        id[82] = 1 << 1;
        id[128] = (1 << 0) | (1 << 5);
        let claims = ata_sanitize_claims(&id);
        let get = |p: SanitizePrimitive| claims.iter().find(|(q, _)| *q == p).unwrap().1;
        assert_eq!(get(SanitizePrimitive::AtaSecureErase), Support::Claimed);
        assert_eq!(
            get(SanitizePrimitive::AtaSecureEraseEnhanced),
            Support::Claimed
        );
        assert_eq!(
            get(SanitizePrimitive::AtaSanitizeBlockErase),
            Support::NotClaimed
        );

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

    #[test]
    fn the_platform_is_refused_before_anything_else_is_consulted() {
        let err = LinuxBlock::open_with_env(
            "/dev/sda",
            Box::new(DenyAll),
            Some("1".to_string()),
        )
        .unwrap_err();

        if cfg!(target_os = "linux") {
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
        let mut scratch: u64 = 0;
        let r = issue_ioctl(
            -1,
            BLKGETSIZE64,
            &mut scratch as *mut u64 as *mut core::ffi::c_void,
        );
        if cfg!(target_os = "linux") {
            assert!(r.is_err());
        } else {
            let e = r.unwrap_err();
            assert_eq!(e.code(), "DEVICE_UNSUPPORTED");
            assert!(format!("{e}").contains("0x80081272"), "{e}");
        }
        assert_eq!(scratch, 0);
    }
}
