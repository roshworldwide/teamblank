//! [`WindowsBlock`] — the Windows implementation of [`Device`], as a stub.
//!
//! # What this file is, stated before anything else
//!
//! **No line in this file has ever run on Windows, because no line in it does
//! anything.** Every method returns [`DeviceError::Unsupported`] naming the
//! operation. There is no `CreateFileW` here, no `DeviceIoControl`, no handle,
//! no `unsafe`, and no conditional compilation — it compiles identically on
//! macOS, Linux and Windows, and behaves identically on all three, which is to
//! say it refuses.
//!
//! # Then why does it exist
//!
//! Because the architecture slide claims *"Windows behind the same trait,
//! stubbed, compiling, untested"*, and CLAUDE.md's scope discipline says that
//! in exactly those words. A claim of platform parity is worth something only
//! if the abstraction it rests on is real, and the cheapest honest proof that
//! it is real is a second implementation that satisfies the trait without the
//! trait bending to accommodate it.
//!
//! That proof is mechanical and it is in `lib.rs`:
//! `tests::the_wipe_layer_shape_compiles_against_the_trait_alone` runs a
//! generic `fn wipe_layer_shape<D: Device + ?Sized>` against a `WindowsBlock`
//! and then against `&mut dyn Device`. If a future change to [`Device`] leaks
//! a POSIX assumption — a raw file descriptor in a signature, a Unix-only
//! type, a method that only a file could answer — this file stops compiling
//! and that test goes red. The stub is a tripwire, not a placeholder.
//!
//! # What it does not claim
//!
//! [`WindowsBlock::capabilities`] returns `Unsupported` rather than a
//! plausible-looking `Capabilities`. It would have to invent a logical sector
//! size to return one at all, and a 512 invented here is a 512 that ends up on
//! a certificate — CLAUDE.md rule 2 forbids exactly that, "not even in a mock".
//! [`WindowsBlock::identify`] does answer, because *unknown* is an available
//! true answer for every field of an [`Identity`] and
//! [`Identity::unknown`] is it.
//!
//! # What the real implementation would be
//!
//! Recorded here so the work is scoped rather than hand-waved, and so nobody
//! reads the absence of code as an absence of a plan. None of it is written.
//!
//! | need | Win32 route |
//! |---|---|
//! | open the medium | `CreateFileW(r"\\.\PhysicalDrive0", GENERIC_READ \| GENERIC_WRITE, FILE_SHARE_READ \| FILE_SHARE_WRITE, .., OPEN_EXISTING, FILE_FLAG_NO_BUFFERING \| FILE_FLAG_WRITE_THROUGH, ..)` |
//! | logical sector size, capacity | `DeviceIoControl(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX)` → `DISK_GEOMETRY_EX` |
//! | physical sector size | `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageAccessAlignmentProperty` → `STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR::BytesPerPhysicalSector` |
//! | rotational vs solid-state | `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceSeekPenaltyProperty` → `DEVICE_SEEK_PENALTY_DESCRIPTOR::IncursSeekPenalty` |
//! | model, serial, firmware | `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceProperty` → `STORAGE_DEVICE_DESCRIPTOR` offsets |
//! | ATA / NVMe sanitize claims | `IOCTL_ATA_PASS_THROUGH_DIRECT` (`IDENTIFY DEVICE` words 82/83/128) and `IOCTL_STORAGE_PROTOCOL_COMMAND` (NVMe `Identify Controller`, `OACS` / `SANICAP`) |
//! | exclusive access before writing | `FSCTL_LOCK_VOLUME` then `FSCTL_DISMOUNT_VOLUME` on every volume the disk carries — without this, Windows will not let a sector write through, and with it, this becomes a tool that can destroy the machine it runs on |
//!
//! That last row is the reason this stays a stub until the guard's device path
//! is real on Windows as well. `fixtures/guard.py` clause D0 refuses device
//! targets on macOS today and clause D5 — refuse the disk backing the running
//! system — is marked DESIGNED BUT UNVERIFIED for want of a host to measure on.
//! A Windows device path shipped ahead of a Windows-aware D5 is precisely the
//! disqualifying defect CLAUDE.md rule 4 names.
//!
//! # Reads are refused too, and that is deliberate
//!
//! A read-only Windows path would be harmless and moderately useful. It is
//! still not here, because a half-implemented platform is worse to reason about
//! than an absent one: it invites a demo that half works and a slide that says
//! *Windows support* without a qualifier. One refusal, one meaning.

use std::path::{Path, PathBuf};

use crate::{Capabilities, ClaimSource, Device, DeviceError, Identity, Transport};

/// The Windows block-device implementation. A stub. See the module docs.
#[derive(Debug, Clone)]
pub struct WindowsBlock {
    /// The device path this handle would address, e.g.
    /// `\\.\PhysicalDrive0`. Recorded so an error message can name it. Never
    /// opened.
    target: PathBuf,
}

impl WindowsBlock {
    /// Construct a stub for `target`.
    ///
    /// Named `stub`, not `open`, because it opens nothing. A constructor called
    /// `open` that never opens anything is the kind of name that ends up quoted
    /// in a status report as evidence of a Windows implementation.
    pub fn stub(target: impl AsRef<Path>) -> Self {
        WindowsBlock {
            target: target.as_ref().to_path_buf(),
        }
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    fn refuse(&self, operation: &'static str) -> DeviceError {
        DeviceError::Unsupported {
            operation,
            detail: format!(
                "WindowsBlock is a compiling stub and performs no I/O; {} was not \
                 touched. The Win32 route this would take is documented in \
                 core/device/src/windows.rs",
                self.target.display()
            ),
        }
    }
}

impl Device for WindowsBlock {
    fn identify(&self) -> Identity {
        // Answers, and answers honestly: it knows the string it was handed and
        // nothing else. Every descriptive field stays None and renders
        // `unknown`; `is_physical_medium` stays false because this handle has
        // not established that anything is there at all.
        let mut id = Identity::unknown("windows block device (stub)");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_is_unsupported_and_names_itself() {
        let mut d = WindowsBlock::stub(r"\\.\PhysicalDrive0");

        for e in [
            d.capabilities().unwrap_err(),
            d.read_sectors(0, &mut [0u8; 512]).unwrap_err(),
            d.write_sectors(0, &[0u8; 512]).unwrap_err(),
            d.sync().unwrap_err(),
        ] {
            assert_eq!(e.code(), "DEVICE_UNSUPPORTED");
            match e {
                DeviceError::Unsupported { operation, detail } => {
                    assert!(
                        ["capabilities", "read_sectors", "write_sectors", "sync"]
                            .contains(&operation),
                        "unnamed operation {operation}"
                    );
                    assert!(detail.contains("PhysicalDrive0"), "{detail}");
                }
                other => panic!("expected Unsupported, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_read_is_refused_and_the_buffer_is_untouched() {
        let mut d = WindowsBlock::stub(r"\\.\PhysicalDrive1");
        let mut buf = [0xEEu8; 512];
        assert!(d.read_sectors(0, &mut buf).is_err());
        assert!(buf.iter().all(|b| *b == 0xEE));
    }

    #[test]
    fn it_reports_no_geometry_rather_than_a_plausible_one() {
        // The point of the Result on `capabilities`. A stub that returned
        // `logical_sector_bytes: 512` would be inventing a measurement.
        let d = WindowsBlock::stub(r"\\.\PhysicalDrive0");
        assert!(d.capabilities().is_err());
    }

    #[test]
    fn identify_answers_unknown_without_inventing_a_drive() {
        let d = WindowsBlock::stub(r"\\.\PhysicalDrive0");
        let id = d.identify();
        assert_eq!(id.kind, "windows block device (stub)");
        assert!(!id.is_physical_medium);
        assert_eq!(id.transport, Transport::Unknown);
        assert_eq!(id.source, ClaimSource::NotProbed);
        assert_eq!(id.model_or_unknown(), "unknown");
        assert_eq!(id.serial_or_unknown(), "unknown");
        assert_eq!(id.firmware_or_unknown(), "unknown");
        assert_eq!(id.wwn_or_unknown(), "unknown");
        assert_eq!(id.target.as_deref(), Some(d.target()));
    }
}
