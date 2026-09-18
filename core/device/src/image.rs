use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{
    byte_offset, checked_range, sanitize_table, Capabilities, ClaimSource, Device, DeviceError,
    Identity, MediumKind, SanitizePrimitive, Support, Transport, WriteAuthority,
};

pub const DEFAULT_LOGICAL_SECTOR_BYTES: u32 = 512;

pub struct ImageFile {
    resolved: PathBuf,
    file: File,
    logical_sector_bytes: u32,
    total_sectors: u64,
    byte_len: u64,

    authority: Option<Box<dyn WriteAuthority>>,
    decision_code: Option<String>,
    policy_digest: Option<String>,

    bytes_read: u64,
    bytes_written: u64,
    read_calls: u64,
    write_calls: u64,
}

impl ImageFile {
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, DeviceError> {
        Self::open_read_only_with_sector_size(path, DEFAULT_LOGICAL_SECTOR_BYTES)
    }

    pub fn open_read_only_with_sector_size(
        path: impl AsRef<Path>,
        logical_sector_bytes: u32,
    ) -> Result<Self, DeviceError> {
        let path = path.as_ref();
        check_sector_size(logical_sector_bytes)?;
        match std::fs::metadata(path) {
            Ok(md) if !md.is_file() => {
                return Err(DeviceError::Unsupported {
                    operation: "open",
                    detail: format!(
                        "{} is not a regular file; ImageFile addresses files, and a \
                         device node belongs to LinuxBlock behind its own two-factor \
                         arming",
                        path.display()
                    ),
                })
            }
            Ok(_) => {}
            Err(e) => return Err(DeviceError::io("stat", e)),
        }
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| DeviceError::io("open read-only", e))?;
        let resolved = std::fs::canonicalize(path)
            .map_err(|e| DeviceError::io("canonicalize", e))?;
        Self::from_parts(resolved, file, logical_sector_bytes, None, None, None)
    }

    pub fn open_writable(
        path: impl AsRef<Path>,
        authority: Box<dyn WriteAuthority>,
    ) -> Result<Self, DeviceError> {
        Self::open_writable_with_sector_size(path, authority, DEFAULT_LOGICAL_SECTOR_BYTES)
    }

    pub fn open_writable_with_sector_size(
        path: impl AsRef<Path>,
        authority: Box<dyn WriteAuthority>,
        logical_sector_bytes: u32,
    ) -> Result<Self, DeviceError> {
        check_sector_size(logical_sector_bytes)?;
        let granted = authority.open_writable(path.as_ref())?;
        let digest = authority.policy_digest();
        Self::from_parts(
            granted.resolved,
            granted.file,
            logical_sector_bytes,
            Some(authority),
            Some(granted.decision_code),
            Some(digest),
        )
    }

    fn from_parts(
        resolved: PathBuf,
        file: File,
        logical_sector_bytes: u32,
        authority: Option<Box<dyn WriteAuthority>>,
        decision_code: Option<String>,
        policy_digest: Option<String>,
    ) -> Result<Self, DeviceError> {
        let md = file
            .metadata()
            .map_err(|e| DeviceError::io("stat", e))?;
        if !md.is_file() {
            return Err(DeviceError::Unsupported {
                operation: "open",
                detail: format!(
                    "{} is not a regular file; ImageFile addresses files, and a device \
                     node belongs to LinuxBlock behind its own two-factor arming",
                    resolved.display()
                ),
            });
        }
        let byte_len = md.len();
        if byte_len == 0 {
            return Err(DeviceError::Io {
                operation: "open",
                kind: "InvalidData".to_string(),
                detail: format!(
                    "{} is empty; a zero-length file is not a medium, and a wipe of it \
                     would complete in no time at all and defeat the timing audit",
                    resolved.display()
                ),
            });
        }
        if byte_len % logical_sector_bytes as u64 != 0 {
            return Err(DeviceError::Misaligned {
                len: byte_len as usize,
                logical_sector_bytes,
            });
        }
        Ok(ImageFile {
            resolved,
            file,
            logical_sector_bytes,
            total_sectors: byte_len / logical_sector_bytes as u64,
            byte_len,
            authority,
            decision_code,
            policy_digest,
            bytes_read: 0,
            bytes_written: 0,
            read_calls: 0,
            write_calls: 0,
        })
    }

    pub fn resolved_path(&self) -> &Path {
        &self.resolved
    }

    pub fn decision_code(&self) -> Option<&str> {
        self.decision_code.as_deref()
    }

    pub fn policy_digest(&self) -> Option<&str> {
        self.policy_digest.as_deref()
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn read_calls(&self) -> u64 {
        self.read_calls
    }

    pub fn write_calls(&self) -> u64 {
        self.write_calls
    }

    fn seek_to(&mut self, lba: u64, operation: &'static str) -> Result<u64, DeviceError> {
        let off = byte_offset(lba, self.logical_sector_bytes).ok_or(DeviceError::OutOfRange {
            lba,
            sectors: 0,
            total_sectors: self.total_sectors,
        })?;
        self.file
            .seek(SeekFrom::Start(off))
            .map_err(|e| DeviceError::io(operation, e))?;
        Ok(off)
    }
}

fn check_sector_size(logical_sector_bytes: u32) -> Result<(), DeviceError> {
    if logical_sector_bytes == 0 || !logical_sector_bytes.is_power_of_two() {
        return Err(DeviceError::Unsupported {
            operation: "open",
            detail: format!(
                "logical sector size {logical_sector_bytes} is not a power of two"
            ),
        });
    }
    Ok(())
}

impl Device for ImageFile {
    fn identify(&self) -> Identity {
        let mut id = Identity::unknown("image file");
        id.target = Some(self.resolved.clone());
        id.transport = Transport::File;
        id.is_physical_medium = false;
        id.source = ClaimSource::FileMetadata;
        id
    }

    fn capabilities(&self) -> Result<Capabilities, DeviceError> {
        Ok(Capabilities {
            medium: MediumKind::Image,
            logical_sector_bytes: self.logical_sector_bytes,
            physical_sector_bytes: None,
            total_sectors: self.total_sectors,
            writable: self.authority.is_some(),
            sanitize: sanitize_table(
                (Support::Simulated, ClaimSource::NotProbed),
                &[
                    (
                        SanitizePrimitive::Overwrite,
                        if self.authority.is_some() {
                            Support::Claimed
                        } else {
                            Support::NotClaimed
                        },
                        ClaimSource::FileMetadata,
                    ),
                    (
                        SanitizePrimitive::TrimDeallocate,
                        Support::NotClaimed,
                        ClaimSource::FileMetadata,
                    ),
                ],
            ),
        })
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), DeviceError> {
        checked_range(lba, buf.len(), self.logical_sector_bytes, self.total_sectors)?;
        self.seek_to(lba, "seek for read")?;
        match self.file.read_exact(buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(DeviceError::ShortTransfer {
                    wanted: buf.len(),
                    moved: 0,
                })
            }
            Err(e) => return Err(DeviceError::io("read", e)),
        }
        self.bytes_read += buf.len() as u64;
        self.read_calls += 1;
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), DeviceError> {
        let authority = self.authority.as_ref().ok_or_else(|| DeviceError::NotWritable {
            detail: format!(
                "{} was opened read-only; a writable handle requires a WriteAuthority",
                self.resolved.display()
            ),
        })?;

        checked_range(lba, buf.len(), self.logical_sector_bytes, self.total_sectors)?;
        let offset = byte_offset(lba, self.logical_sector_bytes).ok_or(DeviceError::OutOfRange {
            lba,
            sectors: 0,
            total_sectors: self.total_sectors,
        })?;

        authority.authorize_write(&self.resolved, offset, buf.len() as u64)?;

        self.seek_to(lba, "seek for write")?;
        self.file
            .write_all(buf)
            .map_err(|e| DeviceError::io("write", e))?;
        self.bytes_written += buf.len() as u64;
        self.write_calls += 1;
        Ok(())
    }

    fn sync(&mut self) -> Result<(), DeviceError> {
        if self.authority.is_none() {
            return Ok(());
        }
        self.file
            .sync_all()
            .map_err(|e| DeviceError::io("sync_all", e))
    }
}

impl std::fmt::Debug for ImageFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageFile")
            .field("resolved", &self.resolved)
            .field("logical_sector_bytes", &self.logical_sector_bytes)
            .field("total_sectors", &self.total_sectors)
            .field("writable", &self.authority.is_some())
            .field("policy_digest", &self.policy_digest)
            .field("bytes_written", &self.bytes_written)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizedFile, DenyAll};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    fn scratch_root() -> PathBuf {
        match std::env::var_os("SENTINELWIPE_SCRATCH") {
            Some(v) => PathBuf::from(v),
            None => std::env::temp_dir().join("sentinelwipe-device-tests"),
        }
    }

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn scratch_image(name: &str, sectors: u64) -> (PathBuf, PathBuf) {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = scratch_root().join(format!("device-{}-{}-{}", std::process::id(), n, name));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        let path = dir.join("image.img");
        let len = (sectors * 512) as usize;
        let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes).expect("write scratch image");
        (dir, path)
    }

    struct ScratchAuthority {
        root: PathBuf,
        seen: Mutex<Vec<(u64, u64)>>,
        refuse_after_calls: Option<usize>,
    }

    impl ScratchAuthority {
        fn new(root: &Path) -> Self {
            ScratchAuthority {
                root: std::fs::canonicalize(root).expect("canonicalize root"),
                seen: Mutex::new(Vec::new()),
                refuse_after_calls: None,
            }
        }
        fn refusing_after(root: &Path, n: usize) -> Self {
            let mut a = Self::new(root);
            a.refuse_after_calls = Some(n);
            a
        }
        fn contained(&self, p: &Path) -> bool {
            let mut cur: Option<&Path> = Some(p);
            while let Some(c) = cur {
                if c == self.root {
                    return true;
                }
                cur = c.parent();
            }
            false
        }
        fn calls(&self) -> Vec<(u64, u64)> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl WriteAuthority for ScratchAuthority {
        fn open_writable(&self, target: &Path) -> Result<AuthorizedFile, DeviceError> {
            let resolved = std::fs::canonicalize(target)
                .map_err(|e| DeviceError::io("canonicalize", e))?;
            if !self.contained(&resolved) {
                return Err(DeviceError::Refused {
                    code: "DENY_NOT_ALLOWLISTED".to_string(),
                    detail: format!("{} is not under the test scratch root", resolved.display()),
                });
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&resolved)
                .map_err(|e| DeviceError::io("open r+", e))?;
            Ok(AuthorizedFile {
                file,
                resolved,
                decision_code: "ALLOW_FILE".to_string(),
                policy_digest: self.policy_digest(),
            })
        }

        fn authorize_write(
            &self,
            resolved: &Path,
            offset: u64,
            len: u64,
        ) -> Result<(), DeviceError> {
            let mut seen = self.seen.lock().unwrap();
            seen.push((offset, len));
            if let Some(n) = self.refuse_after_calls {
                if seen.len() > n {
                    return Err(DeviceError::Refused {
                        code: "DENY_TEST_BUDGET".to_string(),
                        detail: format!("refused write {} of {}", seen.len(), resolved.display()),
                    });
                }
            }
            if !self.contained(resolved) {
                return Err(DeviceError::Refused {
                    code: "DENY_NOT_ALLOWLISTED".to_string(),
                    detail: format!("{} escaped the scratch root", resolved.display()),
                });
            }
            Ok(())
        }

        fn policy_digest(&self) -> String {
            format!("test-scratch:{}", self.root.display())
        }
    }

    #[test]
    fn reads_are_sector_addressed_and_land_on_the_right_bytes() {
        let (dir, path) = scratch_image("read", 8);
        let mut dev = ImageFile::open_read_only(&path).unwrap();
        let caps = dev.capabilities().unwrap();
        assert_eq!(caps.check_invariants(), Ok(()));
        assert_eq!(caps.total_sectors, 8);
        assert_eq!(caps.total_bytes(), 4096);
        assert_eq!(caps.medium, MediumKind::Image);

        let mut buf = [0u8; 512];
        dev.read_sectors(3, &mut buf).unwrap();
        for (i, b) in buf.iter().enumerate() {
            assert_eq!(*b, ((3 * 512 + i) % 251) as u8, "byte {i} of sector 3");
        }
        assert_eq!(dev.bytes_read(), 512);
        assert_eq!(dev.read_calls(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_read_past_the_end_is_refused_rather_than_short() {
        let (dir, path) = scratch_image("eof", 4);
        let mut dev = ImageFile::open_read_only(&path).unwrap();
        let mut buf = [0u8; 1024];
        let err = dev.read_sectors(3, &mut buf).unwrap_err();
        assert_eq!(
            err,
            DeviceError::OutOfRange {
                lba: 3,
                sectors: 2,
                total_sectors: 4
            }
        );
        assert_eq!(dev.bytes_read(), 0);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_buffer_that_is_not_a_whole_number_of_sectors_is_refused() {
        let (dir, path) = scratch_image("align", 4);
        let mut dev = ImageFile::open_read_only(&path).unwrap();
        let mut buf = [0u8; 500];
        assert_eq!(
            dev.read_sectors(0, &mut buf).unwrap_err(),
            DeviceError::Misaligned {
                len: 500,
                logical_sector_bytes: 512
            }
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_read_only_handle_cannot_write_and_says_which_control_stopped_it() {
        let (dir, path) = scratch_image("ro", 4);
        let mut dev = ImageFile::open_read_only(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = dev.write_sectors(0, &[0xFFu8; 512]).unwrap_err();
        assert_eq!(err.code(), "DEVICE_NOT_WRITABLE");
        assert_eq!(std::fs::read(&path).unwrap(), before, "the file changed");
        assert!(!dev.capabilities().unwrap().writable);
        assert_eq!(
            dev.capabilities().unwrap().support(SanitizePrimitive::Overwrite),
            Support::NotClaimed
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn deny_all_is_what_a_caller_who_forgets_the_guard_gets() {
        let (dir, path) = scratch_image("denyall", 4);
        let err = ImageFile::open_writable(&path, Box::new(DenyAll)).unwrap_err();
        assert_eq!(err.code(), "DEVICE_REFUSED");
        assert!(format!("{err}").starts_with("DENY_NO_WRITE_AUTHORITY"), "{err}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn every_write_is_authorized_separately() {
        let (dir, path) = scratch_image("perwrite", 8);
        let auth = std::sync::Arc::new(ScratchAuthority::new(&dir));
        let mut dev = ImageFile::open_writable(&path, Box::new(ArcAuthority(auth.clone()))).unwrap();

        for lba in 0..4u64 {
            dev.write_sectors(lba, &[0xA5u8; 512]).unwrap();
        }
        dev.sync().unwrap();

        assert_eq!(
            auth.calls(),
            vec![(0, 512), (512, 512), (1024, 512), (1536, 512)]
        );
        assert_eq!(dev.bytes_written(), 2048);
        assert_eq!(dev.write_calls(), 4);

        let on_disk = std::fs::read(&path).unwrap();
        assert!(on_disk[..2048].iter().all(|b| *b == 0xA5));
        assert_eq!(on_disk[2048], (2048 % 251) as u8);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_refusal_mid_pass_stops_the_write_and_leaves_the_bytes_alone() {
        let (dir, path) = scratch_image("midrefuse", 8);
        let auth = std::sync::Arc::new(ScratchAuthority::refusing_after(&dir, 2));
        let mut dev = ImageFile::open_writable(&path, Box::new(ArcAuthority(auth.clone()))).unwrap();

        dev.write_sectors(0, &[0x11u8; 512]).unwrap();
        dev.write_sectors(1, &[0x11u8; 512]).unwrap();
        let err = dev.write_sectors(2, &[0x11u8; 512]).unwrap_err();
        assert_eq!(err.code(), "DEVICE_REFUSED");
        assert!(format!("{err}").starts_with("DENY_TEST_BUDGET"), "{err}");

        let on_disk = std::fs::read(&path).unwrap();
        assert!(on_disk[..1024].iter().all(|b| *b == 0x11));
        assert_eq!(on_disk[1024], (1024 % 251) as u8);
        assert_eq!(dev.bytes_written(), 1024);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_write_past_the_end_cannot_grow_the_medium() {
        let (dir, path) = scratch_image("nogrow", 4);
        let auth = std::sync::Arc::new(ScratchAuthority::new(&dir));
        let mut dev = ImageFile::open_writable(&path, Box::new(ArcAuthority(auth.clone()))).unwrap();
        let err = dev.write_sectors(4, &[0u8; 512]).unwrap_err();
        assert_eq!(
            err,
            DeviceError::OutOfRange {
                lba: 4,
                sectors: 1,
                total_sectors: 4
            }
        );
        assert!(auth.calls().is_empty());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 2048);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn write_then_read_back_returns_what_was_written() {
        let (dir, path) = scratch_image("readback", 16);
        let auth = std::sync::Arc::new(ScratchAuthority::new(&dir));
        let mut dev = ImageFile::open_writable(&path, Box::new(ArcAuthority(auth))).unwrap();

        let pattern: Vec<u8> = (0..2048).map(|i| (i * 7 % 256) as u8).collect();
        dev.write_sectors(8, &pattern).unwrap();
        dev.sync().unwrap();

        let mut back = vec![0u8; 2048];
        dev.read_sectors(8, &mut back).unwrap();
        assert_eq!(back, pattern);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_image_file_does_not_claim_to_be_a_disk() {
        let (dir, path) = scratch_image("identity", 4);
        let dev = ImageFile::open_read_only(&path).unwrap();
        let id = dev.identify();

        assert_eq!(id.kind, "image file");
        assert!(!id.is_physical_medium);
        assert_eq!(id.transport, Transport::File);
        assert_eq!(id.model, None);
        assert_eq!(id.serial, None);
        assert_eq!(id.firmware, None);
        assert_eq!(id.wwn, None);
        assert_eq!(id.model_or_unknown(), "unknown");
        assert_eq!(id.serial_or_unknown(), "unknown");
        assert_eq!(id.source, ClaimSource::FileMetadata);
        assert_eq!(id.target.as_deref(), Some(dev.resolved_path()));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn every_ata_and_nvme_primitive_reads_simulated_on_an_image() {
        let (dir, path) = scratch_image("simulated", 4);
        let auth = std::sync::Arc::new(ScratchAuthority::new(&dir));
        let dev = ImageFile::open_writable(&path, Box::new(ArcAuthority(auth))).unwrap();
        let caps = dev.capabilities().unwrap();
        assert_eq!(caps.check_invariants(), Ok(()));

        assert_eq!(caps.support(SanitizePrimitive::Overwrite), Support::Claimed);
        assert_eq!(caps.claimed(), vec![SanitizePrimitive::Overwrite]);

        for p in [
            SanitizePrimitive::AtaSecureErase,
            SanitizePrimitive::AtaSecureEraseEnhanced,
            SanitizePrimitive::AtaSanitizeBlockErase,
            SanitizePrimitive::AtaSanitizeCryptoScramble,
            SanitizePrimitive::AtaSanitizeOverwrite,
            SanitizePrimitive::NvmeFormatCryptoErase,
            SanitizePrimitive::NvmeSanitizeBlockErase,
            SanitizePrimitive::NvmeSanitizeCryptoErase,
            SanitizePrimitive::NvmeSanitizeOverwrite,
        ] {
            assert_eq!(caps.support(p), Support::Simulated, "{p}");
            assert_eq!(caps.support(p).as_str(), "simulated");
            assert!(!caps.support(p).is_real(), "{p} must not dispatch for real");
        }
        assert_eq!(
            caps.support(SanitizePrimitive::TrimDeallocate),
            Support::NotClaimed
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_file_reports_no_physical_sector_size_rather_than_guessing_one() {
        let (dir, path) = scratch_image("phys", 4);
        let dev = ImageFile::open_read_only(&path).unwrap();
        assert_eq!(dev.capabilities().unwrap().physical_sector_bytes, None);
        assert_eq!(dev.capabilities().unwrap().physical_or_logical(), 512);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_trailing_partial_sector_is_refused_rather_than_rounded_away() {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = scratch_root().join(format!("device-{}-{}-partial", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image.img");
        std::fs::write(&path, vec![0u8; 1025]).unwrap();
        let err = ImageFile::open_read_only(&path).unwrap_err();
        assert_eq!(
            err,
            DeviceError::Misaligned {
                len: 1025,
                logical_sector_bytes: 512
            }
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_empty_file_is_not_a_medium() {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = scratch_root().join(format!("device-{}-{}-empty", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("image.img");
        std::fs::write(&path, b"").unwrap();
        let err = ImageFile::open_read_only(&path).unwrap_err();
        assert_eq!(err.code(), "DEVICE_IO");
        assert!(format!("{err}").contains("not a medium"), "{err}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_directory_is_not_a_medium() {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = scratch_root().join(format!("device-{}-{}-dir", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        let err = ImageFile::open_read_only(&dir).unwrap_err();
        assert_eq!(err.code(), "DEVICE_UNSUPPORTED");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_non_power_of_two_sector_size_is_refused() {
        let (dir, path) = scratch_image("sectorsize", 4);
        let err = ImageFile::open_read_only_with_sector_size(&path, 520).unwrap_err();
        assert_eq!(err.code(), "DEVICE_UNSUPPORTED");
        let err2 = ImageFile::open_read_only_with_sector_size(&path, 4096).unwrap_err();
        assert_eq!(
            err2,
            DeviceError::Misaligned {
                len: 2048,
                logical_sector_bytes: 4096
            }
        );
        let dev = ImageFile::open_read_only_with_sector_size(&path, 1024).unwrap();
        assert_eq!(dev.capabilities().unwrap().total_sectors, 2);
        std::fs::remove_dir_all(dir).ok();
    }

    struct ArcAuthority(std::sync::Arc<ScratchAuthority>);

    impl WriteAuthority for ArcAuthority {
        fn open_writable(&self, target: &Path) -> Result<AuthorizedFile, DeviceError> {
            self.0.open_writable(target)
        }
        fn authorize_write(
            &self,
            resolved: &Path,
            offset: u64,
            len: u64,
        ) -> Result<(), DeviceError> {
            self.0.authorize_write(resolved, offset, len)
        }
        fn policy_digest(&self) -> String {
            self.0.policy_digest()
        }
    }
}
