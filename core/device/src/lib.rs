//! Medium-agnostic `Device` trait; image files today, Linux block devices gated, Windows stubbed.
//!
//! # What this crate is for
//!
//! Everything above this boundary — the overwrite passes, the sanitize
//! dispatch, the behavioural timing audit, the telemetry stream — is written
//! against [`Device`] and against nothing else. That is the whole point. The
//! architecture slide claims Windows parity behind one trait, and a claim like
//! that is either enforced by the compiler or it is a drawing. It is enforced
//! here: the trait is object-safe, three implementations exist, and the wipe
//! layer's bound is `D: Device` / `&mut dyn Device`, never a concrete type.
//!
//! ```text
//!   wipe / verify / telemetry        <- platform-free, names only `Device`
//!  ---------------------------------  the trait boundary
//!   ImageFile   LinuxBlock  WindowsBlock
//!   (runs)      (gated,     (stub,
//!                never run)  Unsupported)
//! ```
//!
//! `tests::the_wipe_layer_shape_compiles_against_the_trait_alone` instantiates
//! a generic function with two of those three and calls it through
//! `&mut dyn Device`, so the parity claim fails a test if it stops being true.
//!
//! # Module map
//!
//! ```text
//!   lib.rs     the trait, the capability and identity vocabulary, the errors,
//!              and the WriteAuthority interface every writable medium needs
//!   guard.rs   the Rust write guard  (OWNED BY THE GUARD AGENT — see below)
//!   image.rs   ImageFile: a file, sector-addressed, writes gated on an authority
//!   linux.rs   LinuxBlock: SG_IO / ioctl shapes, cargo-feature gated, NEVER RUN
//!   windows.rs WindowsBlock: a stub that returns Unsupported for everything
//! ```
//!
//! # How the guard reaches the write path, and why it is inverted
//!
//! [`image::ImageFile`] does not call `guard.rs`. It holds a
//! `Box<dyn WriteAuthority>` — a trait declared here, with three methods — and
//! consults it before every write. [`GuardAuthority`] at the bottom of this
//! file is the one adapter that binds `guard::Policy` to that trait, and it is
//! the only place in the device layer that names anything from `guard`.
//!
//! The inversion buys two things:
//!
//! 1. **Default deny.** [`ImageFile`](image::ImageFile) cannot be constructed
//!    writable without an authority, and the fallback authority is
//!    [`DenyAll`]. A caller who forgets the guard does not get an unguarded
//!    write; it gets `DENY_NO_WRITE_AUTHORITY`. There is no `File::create` and
//!    no `OpenOptions::write` anywhere below the trait — the authority hands
//!    back the descriptor, so the device layer has no way to open one itself.
//! 2. **A test seam that is not a policy seam.** `image.rs`'s unit tests drive
//!    a `#[cfg(test)]` double to prove that `write_sectors` consults an
//!    authority on every call. The double cannot reach a build, and it is not a
//!    second allowlist: the allowlist argument lives in `guard.rs` and
//!    `fixtures/guard.py`, checked against each other by the shared conformance
//!    vectors.
//!
//! # What this crate deliberately does not publish
//!
//! There is no `nominal_throughput` in [`Capabilities`], and there will not be
//! one. CLAUDE.md rule 2 admits no number that was not measured, and the
//! behavioural audit in the wipe layer exists precisely because a device's own
//! account of how fast it is cannot be trusted. Throughput is measured by the
//! caller, per run, or it does not exist.

// `guard.rs` is the Rust write guard, owned by the guard half of this phase and
// held to `fixtures/guard.py` by the shared conformance vectors. Declared here
// because the crate root is the only place a module may be declared, and
// because `tests/test_module_declarations.py` refuses an undeclared module
// file. `GuardAuthority`, at the bottom of this file, is the only thing in the
// device layer that names an item from it.
pub mod guard;

pub mod image;

// Gated. `cargo build -p sentinelwipe-device --features linux-block` type-checks
// it on macOS; the default build does not compile it at all. See `linux.rs` for
// what that means and what it does not mean.
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

// ---------------------------------------------------------------- the trait

/// A sector-addressed medium.
///
/// # All-or-nothing transfers
///
/// [`read_sectors`](Device::read_sectors) and
/// [`write_sectors`](Device::write_sectors) either move every byte of `buf` or
/// return an error. There is no short-transfer return value, on purpose: a
/// wipe that writes 900 of 1,000 sectors and reports how many it managed is a
/// wipe that leaves 100 sectors of recoverable data behind a success code. An
/// implementation that can only transfer part of the buffer must retry
/// internally until it has moved all of it or fail with
/// [`DeviceError::ShortTransfer`].
///
/// # Buffer length carries the count
///
/// Neither method takes a sector count. `buf.len()` divided by
/// [`Capabilities::logical_sector_bytes`] is the count, and a buffer that is
/// not a whole number of sectors is [`DeviceError::Misaligned`]. A separate
/// `count` argument that has to agree with `buf.len()` is a class of bug — the
/// wrong-number-of-sectors bug — and this signature deletes it rather than
/// checking for it.
///
/// # Object safety
///
/// No method is generic and none mentions `Self` in a return position, so
/// `&mut dyn Device` is legal and the wipe layer may hold a boxed device
/// chosen at runtime. That is asserted by a test in this file.
pub trait Device {
    /// What the medium actually is, as far as this implementation can tell.
    ///
    /// Every field it does not know is `None` and renders as `unknown`. An
    /// implementation may not fill a field with a plausible value; see
    /// [`Identity`].
    fn identify(&self) -> Identity;

    /// Geometry, medium kind, and which sanitize primitives the medium
    /// *claims*. See [`Capabilities`] and [`Support`] — a claim is not a
    /// verification and the type says so.
    ///
    /// # Why this returns a `Result` when [`identify`](Device::identify) does
    /// not
    ///
    /// *Unknown* is always an available true answer for an identity string, and
    /// [`Identity::unknown`] is it. There is no such answer for a sector size:
    /// [`Capabilities::logical_sector_bytes`] is a non-zero `u32` because every
    /// address in this trait is denominated in it, so an implementation that
    /// does not know it has nothing true to put there. [`WindowsBlock`] and an
    /// unarmed [`LinuxBlock`] would have to invent 512, and a 512 invented here
    /// is a 512 printed on a certificate. They return
    /// [`DeviceError::Unsupported`] instead.
    fn capabilities(&self) -> Result<Capabilities, DeviceError>;

    /// Read `buf.len()` bytes starting at logical block `lba`.
    ///
    /// All-or-nothing. `buf` is untouched on error.
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), DeviceError>;

    /// Write `buf.len()` bytes starting at logical block `lba`.
    ///
    /// All-or-nothing. Implementations backed by anything a human owns must
    /// route this through a [`WriteAuthority`] and must return
    /// [`DeviceError::Refused`] when there is none.
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), DeviceError>;

    /// Push accepted writes down to the medium.
    ///
    /// A fifth method beyond the four the phase brief names, and it is here for
    /// one reason: **sampled read-back verification is worthless if the read is
    /// served out of the page cache.** Verification that reads back what the
    /// kernel is still holding in memory verifies the kernel, not the wipe.
    /// The wipe layer calls this between the last write of a pass and the first
    /// read of the verification sweep.
    ///
    /// The limit of what this buys, stated rather than implied: on a real
    /// block device `fsync` returns once the writes reach the drive, and on
    /// macOS it does not force the drive's own write cache — `F_FULLFSYNC`
    /// does, and reaching it needs a `libc` dependency this workspace does not
    /// have. On [`ImageFile`], where the file *is* the medium, `sync_all` is
    /// exactly the right guarantee.
    fn sync(&mut self) -> Result<(), DeviceError>;
}

// ------------------------------------------------------------ medium & claims

/// What kind of medium this is, to the resolution the wipe layer dispatches on.
///
/// Four variants and no more. `Rotational` and `SolidState` change which
/// sanitize primitive is correct; `Image` says the question does not apply, and
/// `Unknown` is what an honest implementation returns when it could not find
/// out. There is no `Nvme` variant because NVMe is a transport, not a medium —
/// see [`Identity::transport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediumKind {
    /// Spinning magnetic media. Overwrite reaches every addressable sector.
    Rotational,
    /// Flash. Overwrite does **not** reach over-provisioned or remapped blocks,
    /// which is the whole reason the sanitize primitives exist and the reason
    /// CLAUDE.md rule 1 makes the certificate say so.
    SolidState,
    /// A regular file standing in for a medium. Not a disk. See [`Identity`].
    Image,
    /// Not determined. Never a default dressed up as a finding.
    Unknown,
}

impl MediumKind {
    /// The wire spelling. Same convention as `carve`'s `Kind::as_str`: the
    /// string a report carries is defined next to the variant, so no consumer
    /// needs a translation table.
    pub fn as_str(&self) -> &'static str {
        match self {
            MediumKind::Rotational => "rotational",
            MediumKind::SolidState => "solid-state",
            MediumKind::Image => "image",
            MediumKind::Unknown => "unknown",
        }
    }

    /// True where an overwrite of every addressable sector is not, by itself,
    /// evidence that every copy of the data is gone.
    ///
    /// This is the flag that forces the limitations line onto the certificate.
    pub fn has_hidden_regions(&self) -> bool {
        matches!(self, MediumKind::SolidState | MediumKind::Unknown)
    }
}

impl fmt::Display for MediumKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A sanitize operation a medium may or may not offer.
///
/// The list is what the wipe layer dispatches on and stops there. The standards
/// mapping — which of these is NIST SP 800-88 *Clear* and which is *Purge* —
/// lives in `docs/standards_map.md`, which belongs to the operator. Putting a
/// clause number in this enum would be this crate asserting a standards claim
/// in a file no officer will read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SanitizePrimitive {
    /// Writing a pattern over every addressable sector through
    /// [`Device::write_sectors`]. The only primitive whose effect this project
    /// can verify by reading the medium back.
    Overwrite,
    /// ATA `SECURITY ERASE UNIT`, normal mode.
    AtaSecureErase,
    /// ATA `SECURITY ERASE UNIT`, enhanced mode — reaches reallocated sectors.
    AtaSecureEraseEnhanced,
    /// ATA `SANITIZE DEVICE` / `BLOCK ERASE EXT`.
    AtaSanitizeBlockErase,
    /// ATA `SANITIZE DEVICE` / `CRYPTO SCRAMBLE EXT`.
    AtaSanitizeCryptoScramble,
    /// ATA `SANITIZE DEVICE` / `OVERWRITE EXT`, executed by the drive itself.
    AtaSanitizeOverwrite,
    /// NVMe `Format NVM` with Secure Erase Settings = 2 (cryptographic erase).
    NvmeFormatCryptoErase,
    /// NVMe `Sanitize`, Block Erase.
    NvmeSanitizeBlockErase,
    /// NVMe `Sanitize`, Crypto Erase.
    NvmeSanitizeCryptoErase,
    /// NVMe `Sanitize`, Overwrite.
    NvmeSanitizeOverwrite,
    /// `TRIM` / `DEALLOCATE`. Present for completeness of the capability
    /// report; it is a hint to the controller, not a sanitize operation, and
    /// the wipe layer must never dispatch a sanitize to it.
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

    /// Every primitive, in a fixed order, so a capability report is stable
    /// across runs. CLAUDE.md rule 6: the certificate is byte-identical given
    /// the same inputs, and a map iteration order would break that.
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

/// How strongly a medium is known to offer a primitive.
///
/// This type exists so that the difference between *the drive says it can* and
/// *we watched it work* cannot be flattened by accident. CLAUDE.md rule 1 is
/// the reason: claiming a clean wipe we did not verify is the one failure that
/// ends this project's credibility.
///
/// Note what is **not** in this enum: `Verified`. No value of `capabilities()`
/// may ever assert that a sanitize worked. Verification is an observation made
/// after the fact by the wipe layer and the adversarial carve, and it is
/// carried in their output, not in a capability report taken beforehand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Support {
    /// The medium reported support through a real identify path, and the
    /// report was read rather than assumed. Still only a claim.
    Claimed,
    /// The medium reported that it does not support this.
    NotClaimed,
    /// Not probed, or probed and inconclusive.
    Unknown,
    /// No such primitive exists on this medium and never will. The wipe layer
    /// may model the operation, and everything it emits about that run must
    /// carry the word `simulated` in the field itself — never in a footnote.
    /// This is operator decision 3 expressed as a type.
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

    /// True only for [`Support::Claimed`]. The wipe layer dispatches a real
    /// sanitize on this and on nothing else; `Simulated` and `Unknown` both
    /// take the simulated path, labelled.
    pub fn is_real(&self) -> bool {
        matches!(self, Support::Claimed)
    }
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a capability claim came from.
///
/// A claim with no stated source is an assertion, and this project does not
/// ship assertions. The certificate prints this next to the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimSource {
    /// ATA `IDENTIFY DEVICE`, words 82/83/128/creation-of-the-security-set.
    AtaIdentify,
    /// NVMe `Identify Controller`, `OACS` / `FNA` / `SANICAP`.
    NvmeIdentifyController,
    /// A Linux sysfs attribute, e.g. `queue/rotational`.
    Sysfs,
    /// A property of a regular file, established by `stat` and by reading it.
    FileMetadata,
    /// Nothing was consulted. The paired [`Support`] must be `Unknown` or
    /// `Simulated`; a `Claimed` with this source is a bug and
    /// [`Capabilities::check_invariants`] refuses it.
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

/// One row of the sanitize capability table: the primitive, how strongly it is
/// supported, and where that came from.
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

// ------------------------------------------------------------- capabilities

/// Everything the wipe layer needs to choose a method, and nothing it needs to
/// take on faith.
#[derive(Debug, Clone, PartialEq)]
pub struct Capabilities {
    pub medium: MediumKind,

    /// The addressing unit. Every `lba` in this trait is in these units and
    /// every buffer length must be a multiple of it.
    pub logical_sector_bytes: u32,

    /// The medium's real write granularity, where the medium said so.
    ///
    /// `None` means *unknown*, and it is `None` far more often than a caller
    /// expects — a regular file has no physical sector size, and reporting the
    /// logical size in this field would be a fabricated measurement. Callers
    /// that need a number for alignment call
    /// [`physical_or_logical`](Capabilities::physical_or_logical), which is
    /// explicit about the fallback at the call site.
    pub physical_sector_bytes: Option<u32>,

    /// Addressable sectors. `total_sectors * logical_sector_bytes` is the
    /// number the behavioural audit divides by measured throughput.
    pub total_sectors: u64,

    /// True if this handle can write. False is not a property of the medium —
    /// it usually means no [`WriteAuthority`] was supplied.
    pub writable: bool,

    /// Sanitize claims, in [`SanitizePrimitive::ALL`] order, one row per
    /// primitive. Fixed length and fixed order so the report is reproducible.
    pub sanitize: Vec<SanitizeClaim>,
}

impl Capabilities {
    /// Total addressable bytes. Saturating, because a `u64` overflow here would
    /// otherwise wrap into a plausible small number and mislead the audit.
    pub fn total_bytes(&self) -> u64 {
        self.total_sectors
            .saturating_mul(self.logical_sector_bytes as u64)
    }

    /// The physical sector size, falling back to the logical one.
    ///
    /// Named to make the fallback visible where it is used. Reading
    /// `caps.physical_or_logical()` says *I accepted a substitute*; reading
    /// `caps.physical_sector_bytes` cannot silently do so, because it is an
    /// `Option`.
    pub fn physical_or_logical(&self) -> u32 {
        self.physical_sector_bytes
            .unwrap_or(self.logical_sector_bytes)
    }

    /// How strongly `p` is supported. `Unknown` for a primitive with no row,
    /// which cannot happen for a well-formed `Capabilities` but is the safe
    /// answer if it does.
    pub fn support(&self, p: SanitizePrimitive) -> Support {
        self.sanitize
            .iter()
            .find(|c| c.primitive == p)
            .map(|c| c.support)
            .unwrap_or(Support::Unknown)
    }

    /// The source of the claim about `p`.
    pub fn claim_source(&self, p: SanitizePrimitive) -> ClaimSource {
        self.sanitize
            .iter()
            .find(|c| c.primitive == p)
            .map(|c| c.source)
            .unwrap_or(ClaimSource::NotProbed)
    }

    /// Primitives the medium actually claims. Empty is a normal answer and the
    /// wipe layer must handle it — an image file claims exactly one thing.
    pub fn claimed(&self) -> Vec<SanitizePrimitive> {
        self.sanitize
            .iter()
            .filter(|c| c.support.is_real())
            .map(|c| c.primitive)
            .collect()
    }

    /// Whole sectors in `len` bytes, or `None` if `len` is not a whole number
    /// of them.
    pub fn sectors_in(&self, len: usize) -> Option<u64> {
        let s = self.logical_sector_bytes as usize;
        if s == 0 || len % s != 0 {
            return None;
        }
        Some((len / s) as u64)
    }

    /// Structural invariants an implementation must not violate.
    ///
    /// Returns the first violation as a message. Every implementation in this
    /// crate is checked against it by a unit test, so a future medium that
    /// reports a `Claimed` it never probed fails a test rather than reaching a
    /// certificate.
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

/// Build a full, ordered sanitize table where every primitive takes the same
/// `(support, source)` except those listed in `overrides`.
///
/// Used by every implementation so that the fixed row order of
/// [`SanitizePrimitive::ALL`] is produced in one place and cannot drift.
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

// ----------------------------------------------------------------- identity

/// What the medium is carried on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Ata,
    Nvme,
    Usb,
    Scsi,
    /// Not a transport. A file reached through the filesystem.
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

/// What the implementation actually knows about the thing it is addressing.
///
/// # The rule this type exists to enforce
///
/// Every descriptive field is an `Option<String>` and **an implementation that
/// does not know a value leaves it `None`.** It does not substitute a filename
/// for a model number, a device node for a serial, or the string `"N/A"` for a
/// measurement it did not take. [`or_unknown`] renders `None` as `unknown`, and
/// that is the only spelling of *we do not know* this project uses.
///
/// # An image file is not a disk
///
/// [`is_physical_medium`](Identity::is_physical_medium) is `false` for
/// [`ImageFile`], and every string field it fills is `None`. A 256 MB file has
/// no model, no serial, no firmware revision and no world-wide name, and a
/// certificate that prints one for it is a forged certificate. The one thing
/// `ImageFile` does report is what it is: a path, a byte length, and
/// [`Transport::File`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// One line naming what this is, always present, never fabricated. For an
    /// image: `"image file"`. It is a category, not a marketing string.
    pub kind: String,

    /// The path or device node this handle addresses, as the implementation
    /// resolved it — not as the operator typed it.
    pub target: Option<PathBuf>,

    pub model: Option<String>,
    pub serial: Option<String>,
    pub firmware: Option<String>,
    /// World-wide name / EUI-64, where the medium reports one.
    pub wwn: Option<String>,

    pub transport: Transport,

    /// `true` only for something that is physically a storage device. `false`
    /// for a file. The certificate branches on this to decide whether the
    /// phrase "the drive" is even permissible.
    pub is_physical_medium: bool,

    /// Where the strings above came from, so a reader can weigh them.
    pub source: ClaimSource,
}

impl Identity {
    /// An identity that admits it knows nothing. The starting point for every
    /// implementation, so the default is ignorance rather than invention.
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

/// The project's only spelling of *we do not know*.
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

// ------------------------------------------------------------- sector ranges

/// A half-open run of logical blocks, `[first_lba, first_lba + count)`.
///
/// Lives here rather than in the wipe crate because it is the unit the
/// telemetry event's `sector_range` field carries and the unit a device is
/// addressed in, and two crates agreeing on a pair of integers by convention is
/// how an off-by-one ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorRange {
    pub first_lba: u64,
    pub count: u64,
}

impl SectorRange {
    pub const fn new(first_lba: u64, count: u64) -> Self {
        SectorRange { first_lba, count }
    }

    /// One past the last block. Saturating: an overflowing range is clamped
    /// rather than wrapped, because a wrapped end reads as a valid small range.
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

// ------------------------------------------------------------- write authority

/// A writable file this crate was *permitted* to open, plus the evidence of
/// permission.
///
/// The guard hands back the descriptor, not the path, for the reason
/// `fixtures/guard.py` states in its module docstring: a path can be swapped
/// between the decision and the open, and a descriptor cannot.
#[derive(Debug)]
pub struct AuthorizedFile {
    /// The open, writable descriptor. Already re-checked by the authority
    /// against its own decision.
    pub file: File,
    /// The authority's own resolution of the target — the value it compared
    /// the typed confirmation against, not the string the operator passed.
    pub resolved: PathBuf,
    /// The authority's allow code, e.g. `ALLOW_FILE`. Copied into the
    /// certificate so a reader can see which clause let the write happen.
    pub decision_code: String,
    /// Digest of the policy that was in force. Also for the certificate.
    pub policy_digest: String,
}

/// The interface every write in this crate passes through.
///
/// # Why this is a trait and not a direct call into `guard.rs`
///
/// See the crate docs. In one line: the device layer must not be able to open a
/// writable handle by itself, and inverting the dependency makes that a
/// property of the type system rather than of everyone remembering.
///
/// # Contract
///
/// * [`open_writable`](WriteAuthority::open_writable) is the **only** way this
///   crate obtains a writable descriptor. It performs the full policy decision
///   — allowlist containment, symlink and race defence, typed confirmation —
///   and returns the descriptor it decided about.
/// * [`authorize_write`](WriteAuthority::authorize_write) is called before
///   **every** [`Device::write_sectors`], with the byte offset and length about
///   to be written. It is the cheap re-check: an implementation is expected to
///   verify the range and the still-open handle, not to re-walk the filesystem.
/// * Both return [`DeviceError::Refused`] carrying the authority's own reason
///   code. The device layer never invents a reason code and never softens one.
///
/// An authority must be safe to call from the telemetry thread's timing loop:
/// `authorize_write` runs once per pass chunk, at over 20 Hz.
pub trait WriteAuthority: Send + Sync {
    /// Decide about `target` and, if allowed, return an open writable
    /// descriptor for it.
    fn open_writable(&self, target: &Path) -> Result<AuthorizedFile, DeviceError>;

    /// Re-check immediately before a write of `len` bytes at absolute byte
    /// `offset` within the already-authorized `resolved` target.
    fn authorize_write(
        &self,
        resolved: &Path,
        offset: u64,
        len: u64,
    ) -> Result<(), DeviceError>;

    /// A stable digest of the policy in force, for the certificate.
    fn policy_digest(&self) -> String;
}

/// The authority this crate ships, and the only one it ships: it refuses
/// everything.
///
/// It exists so that *no authority supplied* and *an authority that says no*
/// are the same code path, and so that a caller who forgets to wire the guard
/// gets a refusal rather than an unguarded descriptor. `guard.rs` supplies the
/// one that can say yes.
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
        // Not a hash of anything. A digest field that looked like a real digest
        // would let a deny-all run be mistaken for a policied one in a report.
        "deny-all".to_string()
    }
}

// ------------------------------------------------------------ guard adapter

/// The [`WriteAuthority`] backed by [`guard::Policy`]. The one place the device
/// layer names the guard.
///
/// # What it delegates, and what it decides
///
/// It decides nothing. Containment by inode ancestry, the `/.vol` refusal,
/// the hardlink and mount-crossing clauses, the device two-factor, the typed
/// confirmation and the TOCTOU-defended descent are all `guard.rs`'s, and this
/// adapter passes the guard's own reason code through to
/// [`DeviceError::Refused`] without rewording it. A refusal that reaches an
/// audit line therefore carries the same string as the corresponding row of
/// `fixtures/guard.py`'s red-team table.
///
/// # Why `authorize_write` re-runs the whole decision
///
/// [`WriteAuthority::authorize_write`] is described as the cheap re-check, and
/// on this adapter it is not cheap: the guard exposes one predicate, and it
/// resolves the path and walks its ancestry every time. That is a deliberate
/// choice over caching an "already allowed" flag, which is precisely the
/// mechanism by which a guard stops guarding. The cost is a filesystem walk per
/// `write_sectors` call, which the wipe layer should keep in mind when it picks
/// a chunk size — it is per call, not per byte.
///
/// # `policy_digest` is a payload, and says so
///
/// `guard.rs` carries no hash primitive, because Phase 3 adds no dependency, so
/// [`guard::Policy::digest_payload`] returns the exact bytes
/// `fixtures/guard.py` feeds to SHA-256 rather than the digest of them. This
/// adapter returns those bytes behind a `policy-payload:` prefix so that no
/// reader and no certificate field can mistake them for a hex digest. The
/// certificate writer, which has `sha2`, hashes the part after the prefix and
/// gets the same value the Python guard publishes.
pub struct GuardAuthority {
    policy: guard::Policy,
    confirmation: Option<String>,
    mode: &'static str,
}

impl GuardAuthority {
    /// An authority over `policy`, opening existing files read/write.
    ///
    /// `confirmation` is the operator's typed string. It is passed to the guard
    /// and checked there, last, after the allowlist has already said yes — it
    /// carries no authority of its own, and a policy with
    /// `require_confirmation` set refuses without it.
    pub fn new(policy: guard::Policy, confirmation: Option<String>) -> Self {
        GuardAuthority {
            policy,
            confirmation,
            mode: "r+",
        }
    }

    /// The same, for a target that does not exist yet (guard mode `"w"`).
    ///
    /// A wipe never creates its target, so the wipe path uses
    /// [`GuardAuthority::new`]; this exists for the fixture and scratch-image
    /// paths that do.
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
        // The decision is taken first for its record fields — `resolved` and
        // the allow code both go on the certificate. `open_authorized` takes
        // its own decision immediately afterwards and is the one that matters:
        // it is the call that produces the descriptor, and it re-establishes
        // every fact against that descriptor rather than against the path.
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
        // A write is always against a target that exists by now, whatever mode
        // the open used, so the re-check asks the existing-file predicate.
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

// -------------------------------------------------------------------- errors

/// Everything that can go wrong at the device boundary.
///
/// `std::io::Error` is deliberately not carried: it is neither `Clone` nor
/// `PartialEq`, and the certificate needs an error that can be compared and
/// reproduced. The `kind` and the message are captured instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    /// This implementation does not do this, on this platform, in this build.
    /// Carries what was asked for and why not — never a bare "unsupported".
    Unsupported {
        operation: &'static str,
        detail: String,
    },
    /// A [`WriteAuthority`] said no. `code` is the authority's own reason code,
    /// passed through unaltered.
    Refused { code: String, detail: String },
    /// The requested range does not lie inside the medium.
    OutOfRange {
        lba: u64,
        sectors: u64,
        total_sectors: u64,
    },
    /// A buffer length that is not a whole number of logical sectors.
    Misaligned {
        len: usize,
        logical_sector_bytes: u32,
    },
    /// A write was attempted on a handle that has no write authority.
    NotWritable { detail: String },
    /// The medium moved less than all of the buffer and could not be made to
    /// move the rest.
    ShortTransfer { wanted: usize, moved: usize },
    /// Anything the operating system refused, with the operation named.
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

    /// A short, stable code for the certificate and for tests. Same discipline
    /// as the guard's reason codes: the string is defined next to the variant.
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

// --------------------------------------------------------------- range check

/// The bounds and alignment check every implementation runs before touching a
/// medium. Returns the sector count on success.
///
/// Shared so that `ImageFile`, `LinuxBlock` and `WindowsBlock` cannot disagree
/// about what an in-range request is, and so that the arithmetic that decides
/// whether a wipe runs off the end of a medium exists once and is tested once.
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

/// Byte offset of `lba`, or `None` on overflow.
pub fn byte_offset(lba: u64, logical_sector_bytes: u32) -> Option<u64> {
    lba.checked_mul(logical_sector_bytes as u64)
}

// ---------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    /// **This is the Windows-parity claim, as a test.**
    ///
    /// `wipe_layer_shape` is generic over `D: Device` and names no concrete
    /// type. It is instantiated below with `WindowsBlock` and, through
    /// `&mut dyn Device`, with a trait object. If someone later adds a method
    /// to `Device` that mentions `Self` in a return position, or a generic
    /// method, `as_dyn` stops compiling and this test goes red — which is the
    /// only way "one trait, three platforms" stays true rather than becoming a
    /// slide.
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

        // Object safety, exercised rather than asserted in a comment.
        let boxed: &mut dyn Device = &mut w;
        let _ = wipe_layer_shape(boxed);
    }

    #[test]
    fn checked_range_refuses_the_ways_a_wipe_runs_off_the_end() {
        // 8 sectors of 512 bytes.
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
        // u64 overflow must be an OutOfRange, never a wrap into a small range.
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
        // An empty string is not a value either.
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
        // The word the certificate must carry, from the type itself.
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

    // ---------------------------------------------------- the guard adapter

    /// End to end, with the real `guard::Policy` and a real file: the wipe path
    /// as it will actually be wired, minus the wipe.
    ///
    /// Everything it writes to is a file it created inside a directory it
    /// created under `SENTINELWIPE_SCRATCH` (or the platform temp directory).
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
        // A second file, in a directory the policy does not allow.
        let outside_dir = root.join(format!("guard-adapter-outside-{}", std::process::id()));
        std::fs::create_dir_all(&outside_dir).expect("create outside dir");
        let outside = outside_dir.join("image.img");
        std::fs::write(&outside, vec![0u8; 4096]).expect("write outside image");

        let policy = guard::Policy::build(guard::PolicySpec::with_roots([dir
            .to_str()
            .expect("scratch path is utf-8")]))
        .expect("policy over an existing scratch directory");

        // Allowed: the file inside the root opens, writes, and reads back.
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

        // Refused: a file outside the root never yields a writable handle, and
        // the guard's own reason code is what comes back.
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
        // And it is untouched.
        assert!(std::fs::read(&outside).unwrap().iter().all(|b| *b == 0));

        // The typed confirmation is a conjunct with no authority of its own: a
        // policy that requires one refuses a wrong string even for a target the
        // allowlist already accepted.
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
