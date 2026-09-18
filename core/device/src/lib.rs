pub mod guard;

pub mod image;

#[cfg(feature = "linux-block")]
pub mod linux;

pub mod windows;

pub use image::ImageFile;
pub use windows::WindowsBlock;

#[cfg(feature = "linux-block")]
pub use linux::LinuxBlock;

use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};

pub trait Device {
    fn identify(&self) -> Identity;

    fn capabilities(&self) -> Result<Capabilities, DeviceError>;

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), DeviceError>;

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), DeviceError>;

    fn sync(&mut self) -> Result<(), DeviceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediumKind {
    Rotational,
    SolidState,
    Image,
    Unknown,
}

impl MediumKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MediumKind::Rotational => "rotational",
            MediumKind::SolidState => "solid-state",
            MediumKind::Image => "image",
            MediumKind::Unknown => "unknown",
        }
    }

    pub fn has_hidden_regions(&self) -> bool {
        matches!(self, MediumKind::SolidState | MediumKind::Unknown)
    }
}

impl fmt::Display for MediumKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SanitizePrimitive {
    Overwrite,
    AtaSecureErase,
    AtaSecureEraseEnhanced,
    AtaSanitizeBlockErase,
    AtaSanitizeCryptoScramble,
    AtaSanitizeOverwrite,
    NvmeFormatCryptoErase,
    NvmeSanitizeBlockErase,
    NvmeSanitizeCryptoErase,
    NvmeSanitizeOverwrite,
    TrimDeallocate,
}

impl SanitizePrimitive {
    pub fn as_str(&self) -> &'static str {
        match self {
            SanitizePrimitive::Overwrite => "overwrite",
            SanitizePrimitive::AtaSecureErase => "ata-secure-erase",
            SanitizePrimitive::AtaSecureEraseEnhanced => "ata-secure-erase-enhanced",
            SanitizePrimitive::AtaSanitizeBlockErase => "ata-sanitize-block-erase",
            SanitizePrimitive::AtaSanitizeCryptoScramble => "ata-sanitize-crypto-scramble",
            SanitizePrimitive::AtaSanitizeOverwrite => "ata-sanitize-overwrite",
            SanitizePrimitive::NvmeFormatCryptoErase => "nvme-format-crypto-erase",
            SanitizePrimitive::NvmeSanitizeBlockErase => "nvme-sanitize-block-erase",
            SanitizePrimitive::NvmeSanitizeCryptoErase => "nvme-sanitize-crypto-erase",
            SanitizePrimitive::NvmeSanitizeOverwrite => "nvme-sanitize-overwrite",
            SanitizePrimitive::TrimDeallocate => "trim-deallocate",
        }
    }

    pub const ALL: [SanitizePrimitive; 11] = [
        SanitizePrimitive::Overwrite,
        SanitizePrimitive::AtaSecureErase,
        SanitizePrimitive::AtaSecureEraseEnhanced,
        SanitizePrimitive::AtaSanitizeBlockErase,
        SanitizePrimitive::AtaSanitizeCryptoScramble,
        SanitizePrimitive::AtaSanitizeOverwrite,
        SanitizePrimitive::NvmeFormatCryptoErase,
        SanitizePrimitive::NvmeSanitizeBlockErase,
        SanitizePrimitive::NvmeSanitizeCryptoErase,
        SanitizePrimitive::NvmeSanitizeOverwrite,
        SanitizePrimitive::TrimDeallocate,
    ];
}

impl fmt::Display for SanitizePrimitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Support {
    Claimed,
    NotClaimed,
    Unknown,
    Simulated,
}

impl Support {
    pub fn as_str(&self) -> &'static str {
        match self {
            Support::Claimed => "claimed",
            Support::NotClaimed => "not-claimed",
            Support::Unknown => "unknown",
            Support::Simulated => "simulated",
        }
    }

    pub fn is_real(&self) -> bool {
        matches!(self, Support::Claimed)
    }
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimSource {
    AtaIdentify,
    NvmeIdentifyController,
    Sysfs,
    FileMetadata,
    NotProbed,
}

impl ClaimSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClaimSource::AtaIdentify => "ata-identify",
            ClaimSource::NvmeIdentifyController => "nvme-identify-controller",
            ClaimSource::Sysfs => "sysfs",
            ClaimSource::FileMetadata => "file-metadata",
            ClaimSource::NotProbed => "not-probed",
        }
    }
}

impl fmt::Display for ClaimSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanitizeClaim {
    pub primitive: SanitizePrimitive,
    pub support: Support,
    pub source: ClaimSource,
}

impl SanitizeClaim {
    pub const fn new(
        primitive: SanitizePrimitive,
        support: Support,
        source: ClaimSource,
    ) -> Self {
        SanitizeClaim {
            primitive,
            support,
            source,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Capabilities {
    pub medium: MediumKind,

    pub logical_sector_bytes: u32,

    pub physical_sector_bytes: Option<u32>,

    pub total_sectors: u64,

    pub writable: bool,

    pub sanitize: Vec<SanitizeClaim>,
}

impl Capabilities {
    pub fn total_bytes(&self) -> u64 {
        self.total_sectors
            .saturating_mul(self.logical_sector_bytes as u64)
    }

    pub fn physical_or_logical(&self) -> u32 {
        self.physical_sector_bytes
            .unwrap_or(self.logical_sector_bytes)
    }

    pub fn support(&self, p: SanitizePrimitive) -> Support {
        self.sanitize
            .iter()
            .find(|c| c.primitive == p)
            .map(|c| c.support)
            .unwrap_or(Support::Unknown)
    }

    pub fn claim_source(&self, p: SanitizePrimitive) -> ClaimSource {
        self.sanitize
            .iter()
            .find(|c| c.primitive == p)
            .map(|c| c.source)
            .unwrap_or(ClaimSource::NotProbed)
    }

    pub fn claimed(&self) -> Vec<SanitizePrimitive> {
        self.sanitize
            .iter()
            .filter(|c| c.support.is_real())
            .map(|c| c.primitive)
            .collect()
    }

    pub fn sectors_in(&self, len: usize) -> Option<u64> {
        let s = self.logical_sector_bytes as usize;
        if s == 0 || len % s != 0 {
            return None;
        }
        Some((len / s) as u64)
    }

    pub fn check_invariants(&self) -> Result<(), String> {
        if self.logical_sector_bytes == 0 {
            return Err("logical_sector_bytes is 0".to_string());
        }
        if !self.logical_sector_bytes.is_power_of_two() {
            return Err(format!(
                "logical_sector_bytes {} is not a power of two",
                self.logical_sector_bytes
            ));
        }
        if let Some(p) = self.physical_sector_bytes {
            if p == 0 || !p.is_power_of_two() {
                return Err(format!("physical_sector_bytes {p} is not a power of two"));
            }
            if p < self.logical_sector_bytes {
                return Err(format!(
                    "physical_sector_bytes {p} is smaller than logical {}",
                    self.logical_sector_bytes
                ));
            }
        }
        if self.sanitize.len() != SanitizePrimitive::ALL.len() {
            return Err(format!(
                "sanitize has {} rows, expected one per primitive ({})",
                self.sanitize.len(),
                SanitizePrimitive::ALL.len()
            ));
        }
        for (i, want) in SanitizePrimitive::ALL.iter().enumerate() {
            if self.sanitize[i].primitive != *want {
                return Err(format!(
                    "sanitize row {i} is {} but SanitizePrimitive::ALL order requires {want}",
                    self.sanitize[i].primitive
                ));
            }
        }
        for c in &self.sanitize {
            if c.support == Support::Claimed && c.source == ClaimSource::NotProbed {
                return Err(format!(
                    "{} is Claimed with source not-probed: a claim with no source is an assertion",
                    c.primitive
                ));
            }
        }
        Ok(())
    }
}

pub fn sanitize_table(
    default: (Support, ClaimSource),
    overrides: &[(SanitizePrimitive, Support, ClaimSource)],
) -> Vec<SanitizeClaim> {
    SanitizePrimitive::ALL
        .iter()
        .map(|p| {
            match overrides.iter().find(|(op, _, _)| op == p) {
                Some((_, s, src)) => SanitizeClaim::new(*p, *s, *src),
                None => SanitizeClaim::new(*p, default.0, default.1),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Ata,
    Nvme,
    Usb,
    Scsi,
    File,
    Unknown,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Ata => "ata",
            Transport::Nvme => "nvme",
            Transport::Usb => "usb",
            Transport::Scsi => "scsi",
            Transport::File => "file",
            Transport::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub kind: String,

    pub target: Option<PathBuf>,

    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
    pub wwn: Option<String>,

    pub transport: Transport,

    pub is_physical_medium: bool,

    pub source: ClaimSource,
}

impl Identity {
    pub fn unknown(kind: &str) -> Self {
        Identity {
            kind: kind.to_string(),
            target: None,
            model: None,
            serial: None,
            firmware: None,
            wwn: None,
            transport: Transport::Unknown,
            is_physical_medium: false,
            source: ClaimSource::NotProbed,
        }
    }

    pub fn model_or_unknown(&self) -> &str {
        or_unknown(&self.model)
    }
    pub fn serial_or_unknown(&self) -> &str {
        or_unknown(&self.serial)
    }
    pub fn firmware_or_unknown(&self) -> &str {
        or_unknown(&self.firmware)
    }
    pub fn wwn_or_unknown(&self) -> &str {
        or_unknown(&self.wwn)
    }
}

pub fn or_unknown(v: &Option<String>) -> &str {
    match v {
        Some(s) if !s.is_empty() => s.as_str(),
        _ => "unknown",
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} via {} · model {} · serial {} · firmware {}",
            self.kind,
            self.transport,
            self.model_or_unknown(),
            self.serial_or_unknown(),
            self.firmware_or_unknown()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorRange {
    pub first_lba: u64,
    pub count: u64,
}

impl SectorRange {
    pub const fn new(first_lba: u64, count: u64) -> Self {
        SectorRange { first_lba, count }
    }

    pub fn end_lba(&self) -> u64 {
        self.first_lba.saturating_add(self.count)
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn byte_len(&self, logical_sector_bytes: u32) -> u64 {
        self.count.saturating_mul(logical_sector_bytes as u64)
    }
}

impl fmt::Display for SectorRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.first_lba, self.end_lba())
    }
}

#[derive(Debug)]
pub struct AuthorizedFile {
    pub file: File,
    pub resolved: PathBuf,
    pub decision_code: String,
    pub policy_digest: String,
}

pub trait WriteAuthority: Send + Sync {
    fn open_writable(&self, target: &Path) -> Result<AuthorizedFile, DeviceError>;

    fn authorize_write(
        &self,
        resolved: &Path,
        offset: u64,
        len: u64,
    ) -> Result<(), DeviceError>;

    fn policy_digest(&self) -> String;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl WriteAuthority for DenyAll {
    fn open_writable(&self, target: &Path) -> Result<AuthorizedFile, DeviceError> {
        Err(DeviceError::Refused {
            code: "DENY_NO_WRITE_AUTHORITY".to_string(),
            detail: format!(
                "{} was not offered to any write authority; the device layer cannot \
                 open a writable handle on its own",
                target.display()
            ),
        })
    }

    fn authorize_write(&self, resolved: &Path, offset: u64, len: u64) -> Result<(), DeviceError> {
        Err(DeviceError::Refused {
            code: "DENY_NO_WRITE_AUTHORITY".to_string(),
            detail: format!(
                "refused {len} bytes at offset {offset} of {}: no write authority",
                resolved.display()
            ),
        })
    }

    fn policy_digest(&self) -> String {
        "deny-all".to_string()
    }
}

pub struct GuardAuthority {
    policy: guard::Policy,
    confirmation: Option<String>,
    mode: &'static str,
}

impl GuardAuthority {
    pub fn new(policy: guard::Policy, confirmation: Option<String>) -> Self {
        GuardAuthority {
            policy,
            confirmation,
            mode: "r+",
        }
    }

    pub fn creating(policy: guard::Policy, confirmation: Option<String>) -> Self {
        GuardAuthority {
            policy,
            confirmation,
            mode: "w",
        }
    }

    pub fn policy(&self) -> &guard::Policy {
        &self.policy
    }

    fn path_str(target: &Path) -> Result<&str, DeviceError> {
        target.to_str().ok_or_else(|| DeviceError::Refused {
            code: "DENY_NON_UTF8_PATH".to_string(),
            detail: format!(
                "{} is not valid UTF-8; the guard's predicate is defined over str and \
                 will not be handed bytes it cannot resolve",
                target.display()
            ),
        })
    }

    fn decide(&self, path: &str) -> Result<guard::Decision, DeviceError> {
        let d = guard::authorize(
            &self.policy,
            path,
            self.confirmation.as_deref(),
            self.mode,
            &guard::Env::Process,
            None,
        );
        if !d.allowed {
            return Err(DeviceError::Refused {
                code: d.code.to_string(),
                detail: d.detail,
            });
        }
        Ok(d)
    }
}

impl WriteAuthority for GuardAuthority {
    fn open_writable(&self, target: &Path) -> Result<AuthorizedFile, DeviceError> {
        let path = Self::path_str(target)?;
        let decision = self.decide(path)?;
        let file = guard::open_authorized(
            &self.policy,
            path,
            self.mode,
            self.confirmation.as_deref(),
            &guard::Env::Process,
        )
        .map_err(|e| match e {
            guard::GuardError::Refused(d) => DeviceError::Refused {
                code: d.code.to_string(),
                detail: d.detail,
            },
            guard::GuardError::Io(io) => DeviceError::io("guard open", io),
        })?;
        Ok(AuthorizedFile {
            file,
            resolved: PathBuf::from(decision.resolved),
            decision_code: decision.code.to_string(),
            policy_digest: self.policy_digest(),
        })
    }

    fn authorize_write(&self, resolved: &Path, offset: u64, len: u64) -> Result<(), DeviceError> {
        let path = Self::path_str(resolved)?;
        let d = guard::authorize(
            &self.policy,
            path,
            self.confirmation.as_deref(),
            "r+",
            &guard::Env::Process,
            None,
        );
        if !d.allowed {
            return Err(DeviceError::Refused {
                code: d.code.to_string(),
                detail: format!(
                    "{} (refused {len} bytes at offset {offset})",
                    d.detail
                ),
            });
        }
        Ok(())
    }

    fn policy_digest(&self) -> String {
        format!("policy-payload:{}", self.policy.digest_payload())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    Unsupported {
        operation: &'static str,
        detail: String,
    },
    Refused { code: String, detail: String },
    OutOfRange {
        lba: u64,
        sectors: u64,
        total_sectors: u64,
    },
    Misaligned {
        len: usize,
        logical_sector_bytes: u32,
    },
    NotWritable { detail: String },
    ShortTransfer { wanted: usize, moved: usize },
    Io {
        operation: &'static str,
        kind: String,
        detail: String,
    },
}

impl DeviceError {
    pub fn io(operation: &'static str, e: std::io::Error) -> Self {
        DeviceError::Io {
            operation,
            kind: format!("{:?}", e.kind()),
            detail: e.to_string(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            DeviceError::Unsupported { .. } => "DEVICE_UNSUPPORTED",
            DeviceError::Refused { .. } => "DEVICE_REFUSED",
            DeviceError::OutOfRange { .. } => "DEVICE_OUT_OF_RANGE",
            DeviceError::Misaligned { .. } => "DEVICE_MISALIGNED",
            DeviceError::NotWritable { .. } => "DEVICE_NOT_WRITABLE",
            DeviceError::ShortTransfer { .. } => "DEVICE_SHORT_TRANSFER",
            DeviceError::Io { .. } => "DEVICE_IO",
        }
    }
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceError::Unsupported { operation, detail } => {
                write!(f, "DEVICE_UNSUPPORTED: {operation}: {detail}")
            }
            DeviceError::Refused { code, detail } => write!(f, "{code}: {detail}"),
            DeviceError::OutOfRange {
                lba,
                sectors,
                total_sectors,
            } => write!(
                f,
                "DEVICE_OUT_OF_RANGE: {sectors} sector(s) at lba {lba} exceed the \
                 medium's {total_sectors} sectors"
            ),
            DeviceError::Misaligned {
                len,
                logical_sector_bytes,
            } => write!(
                f,
                "DEVICE_MISALIGNED: {len} bytes is not a whole number of \
                 {logical_sector_bytes}-byte sectors"
            ),
            DeviceError::NotWritable { detail } => write!(f, "DEVICE_NOT_WRITABLE: {detail}"),
            DeviceError::ShortTransfer { wanted, moved } => write!(
                f,
                "DEVICE_SHORT_TRANSFER: moved {moved} of {wanted} bytes"
            ),
            DeviceError::Io {
                operation,
                kind,
                detail,
            } => write!(f, "DEVICE_IO: {operation}: {kind}: {detail}"),
        }
    }
}

impl std::error::Error for DeviceError {}

pub fn checked_range(
    lba: u64,
    len: usize,
    logical_sector_bytes: u32,
    total_sectors: u64,
) -> Result<u64, DeviceError> {
    if logical_sector_bytes == 0 {
        return Err(DeviceError::Misaligned {
            len,
            logical_sector_bytes,
        });
    }
    let s = logical_sector_bytes as usize;
    if len == 0 || len % s != 0 {
        return Err(DeviceError::Misaligned {
            len,
            logical_sector_bytes,
        });
    }
    let sectors = (len / s) as u64;
    let end = match lba.checked_add(sectors) {
        Some(e) => e,
        None => {
            return Err(DeviceError::OutOfRange {
                lba,
                sectors,
                total_sectors,
            })
        }
    };
    if end > total_sectors {
        return Err(DeviceError::OutOfRange {
            lba,
            sectors,
            total_sectors,
        });
    }
    Ok(sectors)
}

pub fn byte_offset(lba: u64, logical_sector_bytes: u32) -> Option<u64> {
    lba.checked_mul(logical_sector_bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wipe_layer_shape<D: Device + ?Sized>(dev: &mut D) -> (String, u64, bool) {
        let id = dev.identify();
        match dev.capabilities() {
            Ok(caps) => {
                assert!(
                    caps.check_invariants().is_ok(),
                    "{:?}",
                    caps.check_invariants()
                );
                (
                    format!("{} / {}", id.kind, caps.medium),
                    caps.total_bytes(),
                    caps.support(SanitizePrimitive::AtaSecureErase).is_real(),
                )
            }
            Err(e) => (format!("{} / {}", id.kind, e.code()), 0, false),
        }
    }

    #[test]
    fn the_wipe_layer_shape_compiles_against_the_trait_alone() {
        let mut w = WindowsBlock::stub("\\\\.\\PhysicalDrive0");
        let (line, bytes, real_ata) = wipe_layer_shape(&mut w);
        assert_eq!(line, "windows block device (stub) / DEVICE_UNSUPPORTED");
        assert_eq!(bytes, 0);
        assert!(!real_ata);

        let boxed: &mut dyn Device = &mut w;
        let _ = wipe_layer_shape(boxed);
    }

    #[test]
    fn checked_range_refuses_the_ways_a_wipe_runs_off_the_end() {
        assert_eq!(checked_range(0, 4096, 512, 8), Ok(8));
        assert_eq!(checked_range(7, 512, 512, 8), Ok(1));

        assert_eq!(
            checked_range(8, 512, 512, 8),
            Err(DeviceError::OutOfRange {
                lba: 8,
                sectors: 1,
                total_sectors: 8
            })
        );
        assert_eq!(
            checked_range(0, 513, 512, 8),
            Err(DeviceError::Misaligned {
                len: 513,
                logical_sector_bytes: 512
            })
        );
        assert_eq!(
            checked_range(0, 0, 512, 8),
            Err(DeviceError::Misaligned {
                len: 0,
                logical_sector_bytes: 512
            })
        );
        assert_eq!(
            checked_range(u64::MAX, 512, 512, 8),
            Err(DeviceError::OutOfRange {
                lba: u64::MAX,
                sectors: 1,
                total_sectors: 8
            })
        );
    }

    #[test]
    fn deny_all_refuses_both_halves_with_the_same_code() {
        let d = DenyAll;
        let e = d.open_writable(Path::new("/anywhere")).unwrap_err();
        assert_eq!(e.code(), "DEVICE_REFUSED");
        assert!(format!("{e}").starts_with("DENY_NO_WRITE_AUTHORITY"));
        let e2 = d
            .authorize_write(Path::new("/anywhere"), 0, 512)
            .unwrap_err();
        assert!(format!("{e2}").starts_with("DENY_NO_WRITE_AUTHORITY"));
        assert_eq!(d.policy_digest(), "deny-all");
    }

    #[test]
    fn a_claim_with_no_source_is_refused_as_an_assertion() {
        let caps = Capabilities {
            medium: MediumKind::Unknown,
            logical_sector_bytes: 512,
            physical_sector_bytes: None,
            total_sectors: 1,
            writable: false,
            sanitize: sanitize_table(
                (Support::Unknown, ClaimSource::NotProbed),
                &[(
                    SanitizePrimitive::AtaSecureErase,
                    Support::Claimed,
                    ClaimSource::NotProbed,
                )],
            ),
        };
        let err = caps.check_invariants().unwrap_err();
        assert!(err.contains("ata-secure-erase"), "{err}");
        assert!(err.contains("not-probed"), "{err}");
    }

    #[test]
    fn sanitize_table_is_complete_and_ordered() {
        let t = sanitize_table((Support::Unknown, ClaimSource::NotProbed), &[]);
        assert_eq!(t.len(), SanitizePrimitive::ALL.len());
        for (row, want) in t.iter().zip(SanitizePrimitive::ALL.iter()) {
            assert_eq!(row.primitive, *want);
        }
    }

    #[test]
    fn unknown_is_the_only_spelling_of_not_known() {
        let id = Identity::unknown("nothing");
        assert_eq!(id.model_or_unknown(), "unknown");
        assert_eq!(id.serial_or_unknown(), "unknown");
        assert_eq!(id.firmware_or_unknown(), "unknown");
        assert_eq!(id.wwn_or_unknown(), "unknown");
        assert!(!id.is_physical_medium);
        let mut id2 = id.clone();
        id2.model = Some(String::new());
        assert_eq!(id2.model_or_unknown(), "unknown");
    }

    #[test]
    fn support_separates_a_claim_from_a_verification() {
        assert!(Support::Claimed.is_real());
        assert!(!Support::Simulated.is_real());
        assert!(!Support::Unknown.is_real());
        assert!(!Support::NotClaimed.is_real());
        assert_eq!(Support::Simulated.as_str(), "simulated");
    }

    #[test]
    fn medium_kind_names_where_overwrite_is_not_enough() {
        assert!(MediumKind::SolidState.has_hidden_regions());
        assert!(MediumKind::Unknown.has_hidden_regions());
        assert!(!MediumKind::Rotational.has_hidden_regions());
        assert!(!MediumKind::Image.has_hidden_regions());
    }

    #[test]
    fn sector_range_saturates_rather_than_wrapping() {
        let r = SectorRange::new(u64::MAX - 1, 8);
        assert_eq!(r.end_lba(), u64::MAX);
        assert_eq!(SectorRange::new(0, 4).byte_len(512), 2048);
        assert!(SectorRange::new(9, 0).is_empty());
        assert_eq!(format!("{}", SectorRange::new(3, 5)), "[3, 8)");
    }

    #[test]
    fn the_guard_adapter_gates_a_real_image_file() {
        use crate::image::ImageFile;

        let root = match std::env::var_os("SENTINELWIPE_SCRATCH") {
            Some(v) => PathBuf::from(v),
            None => std::env::temp_dir().join("sentinelwipe-device-tests"),
        };
        let dir = root.join(format!("guard-adapter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        let inside = dir.join("image.img");
        std::fs::write(&inside, vec![0u8; 4096]).expect("write scratch image");
        let outside_dir = root.join(format!("guard-adapter-outside-{}", std::process::id()));
        std::fs::create_dir_all(&outside_dir).expect("create outside dir");
        let outside = outside_dir.join("image.img");
        std::fs::write(&outside, vec![0u8; 4096]).expect("write outside image");

        let policy = guard::Policy::build(guard::PolicySpec::with_roots([dir
            .to_str()
            .expect("scratch path is utf-8")]))
        .expect("policy over an existing scratch directory");

        let mut dev = ImageFile::open_writable(
            &inside,
            Box::new(GuardAuthority::new(policy.clone(), None)),
        )
        .expect("the guard allows a file inside its own root");
        assert_eq!(dev.decision_code(), Some(guard::ALLOW_FILE));
        assert!(dev
            .policy_digest()
            .expect("a guarded handle carries a policy")
            .starts_with("policy-payload:"));
        dev.write_sectors(0, &[0x5Au8; 512]).unwrap();
        dev.sync().unwrap();
        let mut back = [0u8; 512];
        dev.read_sectors(0, &mut back).unwrap();
        assert!(back.iter().all(|b| *b == 0x5A));

        let err = ImageFile::open_writable(
            &outside,
            Box::new(GuardAuthority::new(policy.clone(), None)),
        )
        .unwrap_err();
        assert_eq!(err.code(), "DEVICE_REFUSED");
        assert!(
            format!("{err}").starts_with(guard::DENY_NOT_ALLOWLISTED),
            "{err}"
        );
        assert!(std::fs::read(&outside).unwrap().iter().all(|b| *b == 0));

        let confirming = guard::Policy::build(guard::PolicySpec {
            roots: vec![dir.to_str().unwrap().to_string()],
            require_confirmation: true,
            ..guard::PolicySpec::default()
        })
        .expect("confirming policy");
        let err2 = ImageFile::open_writable(
            &inside,
            Box::new(GuardAuthority::new(
                confirming.clone(),
                Some("not the resolved path".to_string()),
            )),
        )
        .unwrap_err();
        assert_eq!(err2.code(), "DEVICE_REFUSED");
        assert!(format!("{err2}").starts_with("DENY_CONFIRMATION"), "{err2}");

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside_dir).ok();
    }

    #[test]
    fn physical_sector_size_falls_back_only_where_it_is_written_down() {
        let caps = Capabilities {
            medium: MediumKind::Image,
            logical_sector_bytes: 512,
            physical_sector_bytes: None,
            total_sectors: 4,
            writable: false,
            sanitize: sanitize_table((Support::Simulated, ClaimSource::NotProbed), &[]),
        };
        assert_eq!(caps.physical_sector_bytes, None);
        assert_eq!(caps.physical_or_logical(), 512);
        assert_eq!(caps.total_bytes(), 2048);
        assert_eq!(caps.sectors_in(1024), Some(2));
        assert_eq!(caps.sectors_in(1000), None);
    }
}
