//! [`ImageFile`] — a regular file addressed as a medium. The only
//! implementation in this crate that runs.
//!
//! # What it is, and the sentence it must never let anyone say
//!
//! A 256 MB file is not a disk. It has no model, no serial, no firmware
//! revision, no world-wide name, no over-provisioned region, no ATA security
//! feature set and no NVMe controller. [`ImageFile::identify`] therefore
//! returns `None` for every one of those fields and
//! [`Identity::is_physical_medium`] is `false`, so any consumer that prints
//! "the drive" for an image is making that up on its own rather than being
//! handed it. `docs/architecture.md` D1 already commits the project to the same
//! discipline about the fixture — *a raw image carrying FAT32-structured
//! metadata, never a certified FAT32 volume* — and this is that rule at the
//! device boundary.
//!
//! Its capabilities say the same thing in the other direction:
//! [`MediumKind::Image`], and the only sanitize primitive with
//! [`Support::Claimed`] is [`SanitizePrimitive::Overwrite`] — the one whose
//! effect can be read back and checked. Every ATA and NVMe primitive is
//! [`Support::Simulated`], which is operator decision 3 carried in the type:
//! *simulated is never verified*, and the word is in the field rather than in a
//! footnote.
//!
//! # Every write goes through an authority
//!
//! `ImageFile` has no code path that opens a writable descriptor.
//! [`ImageFile::open_writable`] takes a [`WriteAuthority`], the authority
//! performs the policy decision and hands back the descriptor it decided about,
//! and [`ImageFile::write_sectors`] calls
//! [`WriteAuthority::authorize_write`] on the byte range *before every single
//! write*. There is no cached "already allowed" flag and no fast path around
//! it: `git grep -n 'File::create\|OpenOptions' core/device/src/image.rs`
//! returns only the read-only open.
//!
//! The consequence is the one CLAUDE.md rule 4 asks for. A caller that forgets
//! the guard does not get an unguarded write — [`ImageFile::open_read_only`]
//! produces a handle whose `write_sectors` returns `DEVICE_NOT_WRITABLE`, and
//! the only authority this crate itself ships is [`DenyAll`].
//!
//! # Read-back verification and the page cache
//!
//! Sampled read-back is the wipe layer's verification step, and it is only
//! evidence if the read reaches the medium rather than the kernel's copy of it.
//! For a file, `sync` (`fsync`) makes the written bytes the file's contents,
//! and the file *is* the medium — so on this implementation the guarantee is
//! exact. It is not exact on a block device, and `linux.rs` says so where it
//! matters. This is stated here because the same verification code will run
//! against both.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{
    byte_offset, checked_range, sanitize_table, Capabilities, ClaimSource, Device, DeviceError,
    Identity, MediumKind, SanitizePrimitive, Support, Transport, WriteAuthority,
};

/// The default logical sector size.
///
/// 512 because that is what `out/fixture.img` is built with: 268,435,456 bytes
/// is exactly 524,288 sectors of 512, and `fixtures/fat32.py` writes a boot
/// sector declaring 512-byte sectors. It is a default, not an assumption —
/// [`ImageFile::open_read_only_with_sector_size`] takes any power of two.
pub const DEFAULT_LOGICAL_SECTOR_BYTES: u32 = 512;

/// A regular file addressed by logical block.
pub struct ImageFile {
    /// The target as the authority resolved it, or as this module canonicalized
    /// it for a read-only open. Never the string the operator typed.
    resolved: PathBuf,
    file: File,
    logical_sector_bytes: u32,
    total_sectors: u64,
    byte_len: u64,

    /// `None` means read-only, and `write_sectors` refuses. There is no other
    /// way to be writable.
    authority: Option<Box<dyn WriteAuthority>>,
    decision_code: Option<String>,
    policy_digest: Option<String>,

    // ---- counters, for the behavioural audit -----------------------------
    //
    // The audit computes an expected minimum duration from capacity and
    // measured throughput. These are the device's own independent account of
    // how many bytes actually crossed the boundary, so a pass that claims to
    // have written 256 MB can be checked against the medium's count rather than
    // against the loop's own bookkeeping.
    bytes_read: u64,
    bytes_written: u64,
    read_calls: u64,
    write_calls: u64,
}

impl ImageFile {
    /// Open for reading only. No authority, because reading is not a
    /// destructive operation — this is the path the carver takes.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, DeviceError> {
        Self::open_read_only_with_sector_size(path, DEFAULT_LOGICAL_SECTOR_BYTES)
    }

    /// Open for reading only with an explicit logical sector size.
    pub fn open_read_only_with_sector_size(
        path: impl AsRef<Path>,
        logical_sector_bytes: u32,
    ) -> Result<Self, DeviceError> {
        let path = path.as_ref();
        check_sector_size(logical_sector_bytes)?;
        // Classify before opening, not after. `from_parts` also refuses a
        // non-regular file, but it can only do so once a handle exists, and
        // Windows refuses to hand out a handle on a directory at all — there the
        // open fails first and the caller is told DEVICE_IO "access denied",
        // which describes a permission problem that did not happen. Deciding
        // here means both platforms name the same cause.
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

    /// Open for reading and writing, through `authority`.
    ///
    /// This crate does not open the file. `authority.open_writable(path)` does,
    /// having made the full policy decision — containment, symlink and race
    /// defence, typed confirmation — and it returns the descriptor it decided
    /// about rather than the path, so nothing can be swapped underneath between
    /// the decision and the open. That is the rule `fixtures/guard.py` states
    /// in its own module docstring, and it is honoured here rather than
    /// re-derived.
    pub fn open_writable(
        path: impl AsRef<Path>,
        authority: Box<dyn WriteAuthority>,
    ) -> Result<Self, DeviceError> {
        Self::open_writable_with_sector_size(path, authority, DEFAULT_LOGICAL_SECTOR_BYTES)
    }

    /// [`ImageFile::open_writable`] with an explicit logical sector size.
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
        // A trailing partial sector cannot be addressed as a sector. Rounding
        // down would silently leave those bytes outside every wipe pass and
        // outside every read-back sweep, and they would still be there after a
        // certificate said otherwise. Refuse instead.
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

    /// The path this handle addresses, as resolved.
    pub fn resolved_path(&self) -> &Path {
        &self.resolved
    }

    /// The authority's allow code, for the certificate. `None` on a read-only
    /// handle, where no authority was consulted because none was needed.
    pub fn decision_code(&self) -> Option<&str> {
        self.decision_code.as_deref()
    }

    /// The digest of the policy in force, for the certificate.
    pub fn policy_digest(&self) -> Option<&str> {
        self.policy_digest.as_deref()
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Bytes this handle has actually moved off the medium.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Bytes this handle has actually written to the medium — the independent
    /// witness the behavioural audit checks a pass's own bookkeeping against.
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
        // Every descriptive field stays None. See the module docs: a file has
        // no model, serial, firmware or WWN, and inventing one for a
        // certificate would be forging a certificate.
        let mut id = Identity::unknown("image file");
        id.target = Some(self.resolved.clone());
        id.transport = Transport::File;
        id.is_physical_medium = false;
        // The two things actually established, by stat and by reading the file:
        // it is a regular file, and it is this long.
        id.source = ClaimSource::FileMetadata;
        id
    }

    fn capabilities(&self) -> Result<Capabilities, DeviceError> {
        Ok(Capabilities {
            medium: MediumKind::Image,
            logical_sector_bytes: self.logical_sector_bytes,
            // Unknown, and left unknown. A file has no physical sector size;
            // the underlying volume has one, this handle did not ask it, and
            // repeating the logical size here would be a fabricated
            // measurement. Callers needing a number call
            // `Capabilities::physical_or_logical` and are visibly accepting a
            // substitute.
            physical_sector_bytes: None,
            total_sectors: self.total_sectors,
            writable: self.authority.is_some(),
            sanitize: sanitize_table(
                // No ATA or NVMe primitive exists on a file. Every one of them
                // is Simulated, so anything the wipe layer emits about them
                // carries the word `simulated` from the capability report
                // onward.
                (Support::Simulated, ClaimSource::NotProbed),
                &[
                    // The one real capability, and the only one whose effect
                    // this project can verify by reading the medium back.
                    (
                        SanitizePrimitive::Overwrite,
                        if self.authority.is_some() {
                            Support::Claimed
                        } else {
                            // A read-only handle cannot overwrite anything, and
                            // saying otherwise would let a capability report
                            // promise something the handle cannot do.
                            Support::NotClaimed
                        },
                        ClaimSource::FileMetadata,
                    ),
                    // TRIM is not a sanitize operation and a file has no
                    // controller to hint to.
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
        // read_exact is all-or-nothing by contract: on error the buffer's
        // contents are unspecified, which is why the caller is told the read
        // failed rather than given a count.
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

        // Before every write. Not once at open, not once per pass. The refusal
        // is passed through with the authority's own reason code and is not
        // reworded, because the code is what a reader of the audit line will
        // match against `fixtures/guard.py`'s table.
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
            // Nothing of ours is outstanding on a read-only handle.
            return Ok(());
        }
        self.file
            .sync_all()
            .map_err(|e| DeviceError::io("sync_all", e))
    }
}

impl std::fmt::Debug for ImageFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn WriteAuthority` is not Debug, and should not be: an authority's
        // internals are policy, and policy belongs in `policy_digest`.
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

// ---------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizedFile, DenyAll};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    // ------------------------------------------------------------------
    // Where these tests are allowed to write.
    //
    // Every byte written below goes to a file this test created inside a
    // directory it created. `SENTINELWIPE_SCRATCH` names that directory when
    // the caller has one (the build session sets it to its own scratchpad);
    // otherwise a per-process subdirectory of the platform temp directory is
    // used. Nothing here ever names `out/fixture.img`, and nothing here opens
    // a path it did not create.
    // ------------------------------------------------------------------
    fn scratch_root() -> PathBuf {
        match std::env::var_os("SENTINELWIPE_SCRATCH") {
            Some(v) => PathBuf::from(v),
            None => std::env::temp_dir().join("sentinelwipe-device-tests"),
        }
    }

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// A fresh directory, and a file of `sectors` * 512 bytes inside it whose
    /// byte at offset `i` is `(i % 251) as u8`.
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

    /// **A TEST DOUBLE, NOT A GUARD.**
    ///
    /// It is `#[cfg(test)]`, so it exists only inside this crate's unit tests
    /// and cannot be reached from any build of the binary. It allows writes
    /// under one directory it was handed and refuses everything else, using
    /// canonical-path ancestry.
    ///
    /// It is deliberately *not* a second implementation of the allowlist. The
    /// real containment argument — inode ancestry rather than string prefix,
    /// hardlink and mount-crossing defence, the macOS `/.vol` refusal, the
    /// typed confirmation — lives in `fixtures/guard.py` and in `guard.rs`, and
    /// is exercised by the shared conformance vectors. What this double is for
    /// is proving one thing about `ImageFile`: that `write_sectors` consults an
    /// authority on every call and honours its answer.
    struct ScratchAuthority {
        root: PathBuf,
        /// Every (offset, len) it was asked about, in order. The evidence that
        /// the consultation happens per write rather than once at open.
        seen: Mutex<Vec<(u64, u64)>>,
        /// When set, refuse this many bytes into the run.
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

    // ---------------------------------------------------------------- reads

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

    // --------------------------------------------------------------- writes

    #[test]
    fn a_read_only_handle_cannot_write_and_says_which_control_stopped_it() {
        let (dir, path) = scratch_image("ro", 4);
        let mut dev = ImageFile::open_read_only(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = dev.write_sectors(0, &[0xFFu8; 512]).unwrap_err();
        assert_eq!(err.code(), "DEVICE_NOT_WRITABLE");
        assert_eq!(std::fs::read(&path).unwrap(), before, "the file changed");
        assert!(!dev.capabilities().unwrap().writable);
        // And it does not claim an overwrite capability it cannot exercise.
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

        // Four writes, four consultations, each carrying its own byte range.
        assert_eq!(
            auth.calls(),
            vec![(0, 512), (512, 512), (1024, 512), (1536, 512)]
        );
        assert_eq!(dev.bytes_written(), 2048);
        assert_eq!(dev.write_calls(), 4);

        let on_disk = std::fs::read(&path).unwrap();
        assert!(on_disk[..2048].iter().all(|b| *b == 0xA5));
        // And nothing outside the written range moved.
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
        // Sector 2 is untouched: the refusal happened before the seek.
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
        // The range check runs before the authority is consulted, so a refusal
        // here is the device's, and the file is still 2048 bytes.
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

    // ------------------------------------------------------------- identity

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

        // The one thing it can really do, and can prove by reading back.
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
            // Operator decision 3, checked at its source: the word is in the
            // field itself.
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

    // ------------------------------------------------------------ open rules

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
        // 4096 divides 2048? No — 2048 bytes is not a whole 4 KiB sector.
        let err2 = ImageFile::open_read_only_with_sector_size(&path, 4096).unwrap_err();
        assert_eq!(
            err2,
            DeviceError::Misaligned {
                len: 2048,
                logical_sector_bytes: 4096
            }
        );
        // 1024 does.
        let dev = ImageFile::open_read_only_with_sector_size(&path, 1024).unwrap();
        assert_eq!(dev.capabilities().unwrap().total_sectors, 2);
        std::fs::remove_dir_all(dir).ok();
    }

    /// `Box<dyn WriteAuthority>` takes ownership, and these tests need to read
    /// the authority's log afterwards. One newtype, so the test double itself
    /// stays a plain struct.
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
