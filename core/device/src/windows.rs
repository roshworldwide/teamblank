use std::path::{Path, PathBuf};

use crate::{Capabilities, ClaimSource, Device, DeviceError, Identity, Transport};

#[derive(Debug, Clone)]
pub struct WindowsBlock {
    target: PathBuf,
}

impl WindowsBlock {
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
