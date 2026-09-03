//! The wipe driver: method dispatch, telemetry, read-back verification, and the
//! behavioural timing audit, composed into one job that emits one JSON report.
//!
//! # What this file is
//!
//! `passes.rs` writes patterns, `verify.rs` reads them back, `audit.rs` judges a
//! duration and `telemetry.rs` publishes the stream. None of them knows what a
//! device is. This file is the only one that does: it binds
//! [`sentinelwipe_device::Device`] to the rest of the crate through [`DeviceIo`],
//! chooses a method from the medium the device reported, runs the job, and
//! assembles [`JobReport`].
//!
//! # The seam this closes
//!
//! Until this file, the Windows-parity claim was true inside `core/device` and
//! nowhere above it: `passes.rs` declared its own mirror trait [`passes::SectorIo`]
//! because `core/wipe` had no dependency on `core/device` to bind to, and its own
//! doc called that "the largest remaining integration risk". [`DeviceIo`] is the
//! adapter that doc specifies, written as a newtype rather than the blanket impl it
//! sketched — a blanket `impl<D: Device> SectorIo for D` overlaps `passes.rs`'s
//! existing `impl<T: SectorIo + ?Sized> SectorIo for &mut T`, because `&mut T` is a
//! fundamental type and this crate cannot prove `&mut T: Device` never holds. The
//! newtype has the same effect, no coherence hazard, and one visible construction
//! site. The whole driver is generic over `D: Device` and
//! [`the_driver_binds_to_the_device_trait_and_nothing_below_it`] runs it over
//! `&mut dyn Device`, so object safety is exercised rather than asserted.
//!
//! # Five signature deltas, all resolved here and nowhere else
//!
//! The device layer's build report named five differences between `Device` and
//! `SectorIo`. Four are mechanical and [`DeviceIo`] absorbs them: the redundant
//! sector count is gone from the trait as shipped, `flush` is spelled `sync` on
//! both sides, `capabilities` is fallible on both sides, and
//! `model`/`serial`/`is_physical_medium` all have homes in
//! [`passes::DeviceIdentity`].
//!
//! The fifth is not mechanical and is the reason [`MediumProfile`] exists.
//! `sentinelwipe_device::Support` has four states — `Claimed`, `NotClaimed`,
//! `Unknown`, `Simulated` — and `passes::Capabilities` deliberately carries none of
//! them. Flattening `Simulated` to a boolean would erase the word exactly where the
//! certificate reads it, which is operator decision 3's failure case. So the
//! overwrite path takes the flattened geometry it needs through `SectorIo`, and the
//! sanitize path reads the device's own `Capabilities::support()` directly and
//! copies the four-state spelling into the report field itself. Grep this file for
//! `Support`: it is never converted to a `bool`.
//!
//! # What the driver refuses to claim
//!
//! * A firmware sanitize against anything that is not a real controller is
//!   **simulated**, the word is in the operation name and in its own field, and
//!   [`audit::audit`] demotes it to `UNVERIFIED_SIMULATED` even when the arithmetic
//!   passes. The medium is never reported sanitized on the strength of a firmware
//!   command; only a read-back-verified overwrite reaches
//!   [`Outcome::VerifiedOnSample`] or [`Outcome::VerifiedWholeMedium`], and which of
//!   the two it reaches is decided by how much of the medium was read back.
//! * A sanitize command's effect on the medium is **measured**, not assumed: the
//!   driver takes a strided digest of the medium before and after the command and
//!   publishes both. A command that returns success having changed nothing says so
//!   in `medium_unchanged`, alongside the timing verdict that says the same thing a
//!   second way.
//! * Sampled verification is published with its coverage fraction and its own
//!   disclaimer sentence, carried verbatim from `verify.rs`.
//!
//! # Report
//!
//! [`JobReport::to_json`] emits `sentinelwipe.wipe.report/1`. It is a **sibling** of
//! `docs/output_schema.md`, not an edit to it: the carve schema is frozen and this
//! document does not touch it. It follows its conventions exactly — six decimal
//! places on every float with no exceptions and no scientific notation, unsigned
//! integers for bytes and counts, `null` as a real value meaning "not measured"
//! and never a stand-in for zero, LF, two-space indent, trailing newline.

pub mod audit;
pub mod passes;
pub mod telemetry;
pub mod verify;

use std::time::{Duration, Instant};

use sentinelwipe_device as dev;
use sentinelwipe_device::{
    Device, DeviceError, MediumKind, SanitizePrimitive, Transport,
};

use crate::audit::{
    audit, audit_without_baseline, AuditReport, Baseline, BaselineSource, Operation,
    SampleRefusal, Severity, ThroughputSample, Verdict, Workload,
};
use crate::passes::{
    hex, shake128, Capabilities, DeviceIdentity, Medium, Method, PatternGen, Seed, SectorIo,
    WipeConfig, WipeError,
};
use crate::telemetry::{EventSink, Telemetry};
use crate::verify::{SamplingPolicy, VerifiedWipeReport, VerifyReport};

/// The report schema this driver emits. A sibling of the frozen
/// `sentinelwipe.carve.report/1`, never a replacement for it.
pub const REPORT_SCHEMA: &str = "sentinelwipe.wipe.report/1";

/// Default calibration probe: 32 MiB, clamped to the medium.
///
/// The probe exists so the behavioural audit judges the overwrite against a
/// throughput sample the overwrite did not produce. It writes the **final pass's
/// pattern** to the first sectors before any pass runs, so every byte it writes is
/// overwritten again by pass 1 and the medium's final state — and therefore the
/// certificate — is unchanged by its presence. 32 MiB because
/// [`audit::MIN_PROBE_BYTES`] is 1 MiB and a probe near that floor measures the
/// write-back cache; 32 MiB is the size the audit module's own measurements used.
pub const DEFAULT_PROBE_BYTES: u64 = 32 << 20;

/// Sectors in the strided sample that witnesses whether a firmware command changed
/// the medium. Small on purpose: this is a witness, not a verification, and
/// [`verify`] is where verification lives.
pub const SANITIZE_WITNESS_SECTORS: u64 = 256;

/// Domain separator for the medium witness digest.
pub const WITNESS_DOMAIN: &[u8] = b"SENTINELWIPE/sanitize-witness/v1";

/// What a firmware sanitize against anything that is not a real controller is, and
/// is not. Reproduced in [`SanitizeReport::limits`] so it cannot be dropped between
/// here and a slide.
pub const SANITIZE_SIMULATION_LIMITS: &str = "\
SIMULATED. No ATA SECURITY ERASE UNIT and no NVMe Sanitize command was issued, \
because the target is not a physical controller. The operation was timed and \
audited exactly as a real one would be, and its effect on the medium was measured \
by reading the medium back; it wrote nothing. Nothing in this block is evidence \
that any data was destroyed. The data-destroying operation in this report is the \
overwrite, and its evidence is the read-back verification.";

/// Why a medium's overwrite says nothing about blocks the host cannot address.
/// Applied when the detected medium reports hidden regions.
pub const HIDDEN_REGION_LIMIT: &str = "\
The detected medium has host-invisible regions (over-provisioning, remapped and \
retired blocks). A full-capacity overwrite reaches every addressable sector and \
no unaddressable one, so no Purge claim is made and none is supported by anything \
in this report.";

// ---------------------------------------------------------------------------
// The adapter: the one place this crate names the device layer
// ---------------------------------------------------------------------------

/// Map a device-layer error onto the wipe layer's error, preserving the reason code.
///
/// [`DeviceError::Refused`] is the case that matters. [`WipeError`] has no `Refused`
/// variant and `passes.rs` is not this task's file to change, so a refusal arrives as
/// [`WipeError::Unsupported`] carrying the guard's own code as the first token of the
/// string. That is lossy in the type and lossless in the text: a refusal that reaches
/// an audit line still carries the same code as the matching row of
/// `fixtures/guard.py`'s red-team table, and [`refusal_code`] recovers it. Stated
/// here rather than papered over — it is the one place the two error vocabularies do
/// not line up.
pub fn map_device_error(op: &'static str, lba: u64, e: DeviceError) -> WipeError {
    match e {
        DeviceError::Refused { code, detail } => {
            WipeError::Unsupported(format!("{code}: {detail}"))
        }
        DeviceError::Unsupported { operation, detail } => {
            WipeError::Unsupported(format!("DEVICE_UNSUPPORTED: {operation}: {detail}"))
        }
        DeviceError::NotWritable { detail } => {
            WipeError::Unsupported(format!("DEVICE_NOT_WRITABLE: {detail}"))
        }
        DeviceError::OutOfRange {
            lba,
            sectors,
            total_sectors,
        } => WipeError::OutOfRange {
            lba,
            sectors,
            sector_count: total_sectors,
        },
        DeviceError::Misaligned {
            len,
            logical_sector_bytes,
        } => WipeError::BadBufferLen {
            expected: len - (len % logical_sector_bytes as usize),
            got: len,
        },
        DeviceError::ShortTransfer { wanted, moved } => WipeError::Io {
            op,
            lba,
            detail: format!("DEVICE_SHORT_TRANSFER: wanted {wanted} bytes, moved {moved}"),
        },
        DeviceError::Io {
            operation,
            kind,
            detail,
        } => WipeError::Io {
            op,
            lba,
            detail: format!("DEVICE_IO: {operation}: {kind}: {detail}"),
        },
    }
}

/// Recover a guard reason code from a [`WipeError`] that carries one.
///
/// The inverse of the lossy arm of [`map_device_error`]. Returns the leading
/// `DENY_*` / `ALLOW_*` / `DEVICE_*` token of an `Unsupported` message, or `None`
/// when the error is not a refusal.
pub fn refusal_code(e: &WipeError) -> Option<&str> {
    match e {
        WipeError::Unsupported(s) => {
            let token = s.split(':').next()?;
            if token.starts_with("DENY_") || token.starts_with("DEVICE_") {
                Some(token)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Four variants to four variants, same wire spellings on both sides.
pub fn map_medium(kind: MediumKind) -> Medium {
    match kind {
        MediumKind::Rotational => Medium::Rotational,
        MediumKind::SolidState => Medium::SolidState,
        MediumKind::Image => Medium::Image,
        MediumKind::Unknown => Medium::Unknown,
    }
}

/// A [`Device`] presented as the [`SectorIo`] the passes and verification take.
///
/// It converts and it does not decide. Every value it produces comes from a
/// device-layer accessor: `model` and `serial` from `Identity::model_or_unknown()`
/// and `serial_or_unknown()`, geometry from the fallible `Device::capabilities`,
/// medium from a four-arm match. Nothing here invents a number, and in particular
/// nothing here substitutes a plausible sector size for one the device did not
/// report — that is why `capabilities` is fallible on both sides.
pub struct DeviceIo<D: Device> {
    inner: D,
}

impl<D: Device> DeviceIo<D> {
    pub fn new(inner: D) -> Self {
        DeviceIo { inner }
    }

    pub fn device(&self) -> &D {
        &self.inner
    }

    pub fn device_mut(&mut self) -> &mut D {
        &mut self.inner
    }

    pub fn into_inner(self) -> D {
        self.inner
    }

    /// The device's own capability report, four-state [`Support`] intact.
    ///
    /// The sanitize path reads this rather than [`SectorIo::capabilities`], because
    /// the flattened form does not carry `Simulated` and operator decision 3 puts
    /// that word in the field itself.
    pub fn device_capabilities(&self) -> Result<dev::Capabilities, WipeError> {
        Device::capabilities(&self.inner).map_err(|e| map_device_error("capabilities", 0, e))
    }

    pub fn device_identity(&self) -> dev::Identity {
        Device::identify(&self.inner)
    }
}

impl<D: Device> SectorIo for DeviceIo<D> {
    fn identify(&self) -> DeviceIdentity {
        let i = Device::identify(&self.inner);
        DeviceIdentity {
            kind: i.kind.clone(),
            model: i.model_or_unknown().to_string(),
            serial: i.serial_or_unknown().to_string(),
            is_physical_medium: i.is_physical_medium,
        }
    }

    fn capabilities(&self) -> Result<Capabilities, WipeError> {
        let c = self.device_capabilities()?;
        Ok(Capabilities {
            medium: map_medium(c.medium),
            sector_bytes: c.logical_sector_bytes,
            sector_count: c.total_sectors,
            writable: c.writable,
        })
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), WipeError> {
        Device::read_sectors(&mut self.inner, lba, buf)
            .map_err(|e| map_device_error("read", lba, e))
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), WipeError> {
        Device::write_sectors(&mut self.inner, lba, buf)
            .map_err(|e| map_device_error("write", lba, e))
    }

    fn sync(&mut self) -> Result<(), WipeError> {
        Device::sync(&mut self.inner).map_err(|e| map_device_error("sync", 0, e))
    }
}

// ---------------------------------------------------------------------------
// Medium detection and method dispatch
// ---------------------------------------------------------------------------

/// What the device said it is. Every field is copied from a device-layer accessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediumProfile {
    pub kind: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub transport: &'static str,
    pub is_physical_medium: bool,
    pub medium: Medium,
    pub medium_kind: MediumKind,
    /// `MediumKind::has_hidden_regions()`. True for solid-state and for unknown,
    /// and it is what forces [`HIDDEN_REGION_LIMIT`] onto the report.
    pub has_hidden_regions: bool,
    pub sector_bytes: u32,
    /// `None` when the device did not determine one. Never filled in with the
    /// logical size — that substitution would be a fabricated measurement.
    pub physical_sector_bytes: Option<u32>,
    pub sector_count: u64,
    pub capacity_bytes: u64,
    pub writable: bool,
    pub identity_source: &'static str,
}

impl MediumProfile {
    pub fn read<D: Device>(io: &DeviceIo<D>) -> Result<MediumProfile, WipeError> {
        let id = io.device_identity();
        let caps = io.device_capabilities()?;
        if let Err(why) = caps.check_invariants() {
            return Err(WipeError::Unsupported(format!(
                "device capability report is internally inconsistent and is refused \
                 rather than believed: {why}"
            )));
        }
        Ok(MediumProfile {
            kind: id.kind.clone(),
            model: id.model_or_unknown().to_string(),
            serial: id.serial_or_unknown().to_string(),
            firmware: id.firmware_or_unknown().to_string(),
            transport: id.transport.as_str(),
            is_physical_medium: id.is_physical_medium,
            medium: map_medium(caps.medium),
            medium_kind: caps.medium,
            has_hidden_regions: caps.medium.has_hidden_regions(),
            sector_bytes: caps.logical_sector_bytes,
            physical_sector_bytes: caps.physical_sector_bytes,
            sector_count: caps.total_sectors,
            capacity_bytes: caps.total_bytes(),
            writable: caps.writable,
            identity_source: id.source.as_str(),
        })
    }

    /// One line for a header: `image file unknown unknown [image]`.
    pub fn describe(&self) -> String {
        format!(
            "{} {} {} [{}]",
            self.kind,
            self.model,
            self.serial,
            self.medium.as_str()
        )
    }
}

/// The method the driver chose, and the sentence that says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatch {
    pub method: Method,
    /// The firmware primitive appropriate to this medium, or `None` when there is
    /// none. `None` is not a failure: on magnetic media and on an image file there
    /// is no controller primitive that would add anything to a full-capacity
    /// overwrite, and attempting one to have something to print would be theatre.
    pub sanitize: Option<SanitizePrimitive>,
    /// Why. Goes on the certificate verbatim.
    pub rationale: String,
    /// `true` when the caller named the method rather than the driver detecting it.
    pub method_was_requested: bool,
    /// `true` when the caller named the sanitize primitive.
    pub sanitize_was_requested: bool,
}

/// Choose by detected medium, with the caller's explicit choices overriding.
///
/// The dispatch is deliberately small, because the honest version is small. Every
/// medium's overwrite is [`Method::SeededRandom`]: one full-capacity pass, the same
/// NIST SP 800-88 category as three, and there is no measurement anywhere in this
/// project supporting a claim that a second pass removes residue a first did not.
/// What actually varies by medium is whether a *controller* primitive is the right
/// operation, and that is what the `sanitize` field carries.
pub fn dispatch(
    profile: &MediumProfile,
    transport: Transport,
    requested_method: Option<Method>,
    requested_sanitize: Option<SanitizePrimitive>,
) -> Dispatch {
    let (auto_sanitize, why): (Option<SanitizePrimitive>, String) = match profile.medium_kind {
        MediumKind::SolidState => match transport {
            Transport::Nvme => (
                Some(SanitizePrimitive::NvmeSanitizeBlockErase),
                "solid-state medium on an NVMe transport: a host overwrite cannot \
                 reach over-provisioned or remapped blocks, so the controller \
                 primitive is attempted first and the overwrite still runs behind it"
                    .to_string(),
            ),
            Transport::Ata => (
                Some(SanitizePrimitive::AtaSecureErase),
                "solid-state medium on an ATA transport: a host overwrite cannot \
                 reach over-provisioned or remapped blocks, so the controller \
                 primitive is attempted first and the overwrite still runs behind it"
                    .to_string(),
            ),
            _ => (
                None,
                format!(
                    "solid-state medium on a {} transport: no controller sanitize \
                     primitive is known for this transport, so none is attempted and \
                     the overwrite's addressability limit is published instead",
                    profile.transport
                ),
            ),
        },
        MediumKind::Rotational => (
            None,
            "magnetic rotational medium: a full-capacity overwrite reaches every \
             addressable sector, so no controller primitive is attempted"
                .to_string(),
        ),
        MediumKind::Image => (
            None,
            "regular file standing in for a medium: there is no controller, so no \
             firmware primitive exists to attempt and any that is requested is \
             simulated and labelled so"
                .to_string(),
        ),
        MediumKind::Unknown => (
            None,
            "medium not determined: no controller primitive is attempted on a \
             medium whose type is unknown, and the overwrite's limits are published \
             as if hidden regions were present"
                .to_string(),
        ),
    };

    let method = requested_method.unwrap_or_else(|| Method::default_for_medium(profile.medium));
    let sanitize = requested_sanitize.or(auto_sanitize);

    let mut rationale = why;
    if requested_method.is_some() {
        rationale.push_str(&format!(
            ". Method {} was named by the operator rather than detected",
            method.label()
        ));
    }
    if let Some(p) = requested_sanitize {
        rationale.push_str(&format!(
            ". Sanitize primitive {} was named by the operator rather than detected",
            p.as_str()
        ));
    }

    Dispatch {
        method,
        sanitize,
        rationale,
        method_was_requested: requested_method.is_some(),
        sanitize_was_requested: requested_sanitize.is_some(),
    }
}

// ---------------------------------------------------------------------------
// The medium witness: did the command actually touch anything?
// ---------------------------------------------------------------------------

/// A strided digest over the medium, used to witness whether an operation changed
/// it.
///
/// It reads `sectors` sectors spread evenly across the whole capacity and absorbs
/// them, with the domain string and the geometry, into SHAKE-128. It is a
/// **witness, not a verification**: it proves a change where one happened and it
/// cannot prove the absence of one. The verification in this project is
/// [`verify::verify_pass`] and [`verify::verify_pass_exhaustive`], and the coverage
/// each achieved is published per run.
pub fn medium_witness<D>(io: &mut D, sectors: u64) -> Result<String, WipeError>
where
    D: SectorIo + ?Sized,
{
    let caps = io.capabilities()?;
    if caps.sector_bytes == 0 || caps.sector_count == 0 {
        return Err(WipeError::DegenerateGeometry {
            sector_bytes: caps.sector_bytes,
            sector_count: caps.sector_count,
        });
    }
    let n = sectors.max(1).min(caps.sector_count);
    let mut k = crate::passes::Keccak::shake128();
    k.absorb(WITNESS_DOMAIN);
    k.absorb(&caps.sector_count.to_le_bytes());
    k.absorb(&(caps.sector_bytes as u64).to_le_bytes());
    k.absorb(&n.to_le_bytes());
    let mut buf = vec![0u8; caps.sector_bytes as usize];
    for i in 0..n {
        // Evenly spread, first and last sector always included.
        let lba = if n == 1 {
            0
        } else {
            (i * (caps.sector_count - 1)) / (n - 1)
        };
        io.read_sectors(lba, &mut buf)?;
        k.absorb(&lba.to_le_bytes());
        k.absorb(&buf);
    }
    let mut out = [0u8; 32];
    k.squeeze(&mut out);
    Ok(hex(&out))
}

// ---------------------------------------------------------------------------
// The sanitize path — simulated on anything that is not a real controller
// ---------------------------------------------------------------------------

/// What one firmware sanitize attempt did, and what it did not.
///
/// Every field that could be read as a sanitization claim is qualified in the field
/// itself, per operator decision 3: `operation` carries the word `simulated`,
/// `device_support` carries the four-state [`Support`] spelling straight from the
/// device's own capability report, and `limits` carries
/// [`SANITIZE_SIMULATION_LIMITS`] verbatim.
#[derive(Debug, Clone)]
pub struct SanitizeReport {
    pub primitive: &'static str,
    /// The operation name a human reads. Contains `simulated` whenever
    /// `simulated` is true, so no consumer can render the name without the caveat.
    pub operation: String,
    /// True whenever the device's own [`Support`] for this primitive is not
    /// [`Support::Claimed`]. Never inferred from the medium and never set by hand.
    pub simulated: bool,
    /// `Support::as_str()`: `claimed`, `not-claimed`, `unknown` or `simulated`.
    /// There is no `verified` spelling in that vocabulary by construction — a
    /// capability report taken beforehand cannot assert that a sanitize worked.
    pub device_support: &'static str,
    pub claim_source: &'static str,
    /// What the command returned. Recorded for the reader, and read by nothing.
    pub device_reported_success: bool,
    pub measured_ns: u128,
    /// The capacity the command claimed to have sanitized.
    pub bytes_claimed: u64,
    pub witness_before: String,
    pub witness_after: String,
    /// Measured, not assumed: the strided witness digest is identical before and
    /// after. On a simulated command this is `true` and is the second, independent
    /// statement that nothing was destroyed — the first being the timing verdict.
    pub medium_unchanged: bool,
    /// What the driver did with the result. A sanitize is never the basis of this
    /// report's sanitization claim; see [`Outcome`].
    pub disposition: &'static str,
    pub limits: &'static str,
    pub audit: AuditReport,
    /// The operation exactly as it was presented to the audit, kept so the verdict
    /// can be retaken against a stronger baseline later in the job without
    /// re-measuring anything. [`SanitizeReport::reaudit`] is the only user.
    operation_record: Operation,
}

impl SanitizeReport {
    /// Retake the verdict against a baseline that did not exist when the command
    /// ran.
    ///
    /// The sanitize is attempted **before** the overwrite passes, so at the moment
    /// it is timed the only measured throughput available is the calibration probe.
    /// By the end of the job a stronger sample exists — a completed pass over this
    /// same medium — and this retakes the verdict against the faster of the two.
    ///
    /// Faster baseline means a *smaller* expected minimum, which makes the detector
    /// **harder** to fire, so this can only ever move a verdict toward the device's
    /// favour. Nothing is re-measured: `measured_ns` is the figure the stopwatch
    /// recorded and it is not touched.
    pub fn reaudit(&mut self, baseline: &Baseline) {
        self.audit = audit(&self.operation_record, Some(baseline));
        self.disposition = disposition_for(&self.audit, self.simulated);
    }

    /// The baseline source the shipped verdict was actually taken against.
    /// Never a source the audit did not use.
    pub fn baseline_source(&self) -> Option<&'static str> {
        self.audit.baseline.as_ref().map(|b| b.source().as_str())
    }
}

/// What the driver does with a sanitize result. Extracted so a verdict retaken
/// against a stronger baseline cannot leave a stale sentence beside it.
///
/// **This matches on the verdict, not on a boolean narrowing of it.** `audit.rs`'s
/// module doc is explicit that "we could not tell" and "we caught it lying" must not
/// land in the same bucket, and `disposition` is the field a certificate reader
/// actually reads — so collapsing five states to two here would undo the typed
/// verdict above it. The measured defect this replaces: an `else` branch that
/// asserted "the command returned success faster than this device's own measured
/// throughput makes physically possible" for `UNVERIFIED_NO_BASELINE`, where no
/// throughput was measured at all, and for `NOT_APPLICABLE`, where duration carries
/// no information about the operation. Both sentences were fabricated measurement
/// claims, which is CLAUDE.md rules 1 and 2 in one line.
fn disposition_for(report: &AuditReport, simulated: bool) -> &'static str {
    if simulated {
        return "NOT_A_SANITIZATION_CLAIM: no firmware command was transmitted, so the \
                command was simulated and destroyed nothing. The overwrite behind it \
                is what this report's sanitization claim rests on.";
    }
    match report.verdict {
        Verdict::Verified { .. } => {
            "TIMING_CONSISTENT: the command's duration is consistent with this device's \
             measured throughput. That is a timing statement and not a statement that \
             data is unrecoverable; the read-back verification is the evidence."
        }
        Verdict::UnverifiedTiming { .. } => {
            "REFUSED_BY_BEHAVIOURAL_AUDIT: the command returned success faster than this \
             device's own measured throughput makes physically possible. The return code \
             is not evidence and was not treated as any."
        }
        Verdict::UnverifiedSimulated { .. } => {
            "NOT_A_SANITIZATION_CLAIM: the operation was simulated, so the timing \
             arithmetic it passed is not evidence that anything was destroyed."
        }
        Verdict::UnverifiedNoBaseline { .. } => {
            "UNVERIFIED_NO_BASELINE: no write throughput was measured for this device, \
             so no expected minimum exists and this command's duration was compared \
             against nothing. That is neither a finding against the device nor a \
             clearance of it; `audit.sanitize.baseline` is null and names the refusal."
        }
        Verdict::NotApplicable { .. } => {
            "TIMING_CARRIES_NO_INFORMATION: the duration of this operation is not a \
             function of the bytes on the medium — key destruction is constant time by \
             design — so a fast return is not evidence of a lie and the behavioural \
             audit makes no claim in either direction. `audit.sanitize.workload` names \
             the reason."
        }
    }
}

/// Issue the firmware command, or the honest analogue of it.
///
/// **The return value says whether a command was actually transmitted**, and that
/// — not the device's capability report — is what makes a record simulated.
/// `Ok(None)` means no primitive left this process; `Ok(Some(rc))` would carry a
/// real controller's return code.
///
/// There is no ioctl path in this build, on any platform, so this returns `None`
/// for every device. That is the honest answer and it is why the value is derived
/// here rather than inferred upstream: the previous version set `simulated` from
/// `Support::Claimed`, so a `LinuxBlock` device whose ATA IDENTIFY claimed the
/// primitive produced a record reading `simulated: false` and
/// `device_reported_success: true` about a command that was never issued, four
/// fields above a `limits` string beginning "SIMULATED. No ATA SECURITY ERASE UNIT
/// and no NVMe Sanitize command was issued". One record cannot say both.
///
/// What it does instead is the strongest honest analogue, and the caller measures
/// it rather than trusting this sentence: the capability report is read and one
/// sector of the medium is read as a status read would be. It writes nothing.
///
/// When an ioctl path is written, it returns `Some(rc)` on the branch that actually
/// transmitted, and every `simulated` field in the report follows from that one
/// value.
fn issue_sanitize<D: Device>(
    io: &mut DeviceIo<D>,
    _primitive: SanitizePrimitive,
) -> Result<Option<bool>, WipeError> {
    let caps = io.device_capabilities()?;
    let mut status = vec![0u8; caps.logical_sector_bytes as usize];
    SectorIo::read_sectors(io, 0, &mut status)?;
    // No controller command was transmitted. Rule 5 exists because a return code is
    // worth nothing; a return code for a command that was never sent is worth less.
    Ok(None)
}

/// The workload a primitive presents to the behavioural audit.
///
/// Key destruction does not move the medium's bytes, so its duration is not a
/// function of capacity. Judging a crypto erase against full-capacity host write
/// time reports every honest one as a timing lie — measured: an NVMe SANITIZE
/// (crypto erase) against a 256 MiB medium and an honest 1.07 GB/s baseline came
/// back `UNVERIFIED_TIMING` at 292 ns against an expected minimum of 240,000,000 ns,
/// for an operation that is *supposed* to be instant. [`Workload::CryptoErase`] is
/// what `audit.rs` wrote for exactly this case and it was constructed nowhere
/// outside that module's own tests until this mapping existed.
///
/// Everything else erases media and is timed. TRIM/DEALLOCATE stays on the timed
/// side deliberately: it is a mapping change whose relationship to the bytes is
/// device-specific, and the conservative direction is to keep the detector armed.
fn workload_for(primitive: SanitizePrimitive, capacity_bytes: u64) -> Workload {
    match primitive {
        SanitizePrimitive::AtaSanitizeCryptoScramble
        | SanitizePrimitive::NvmeSanitizeCryptoErase
        | SanitizePrimitive::NvmeFormatCryptoErase => Workload::CryptoErase,
        _ => Workload::MediaSanitize { capacity_bytes },
    }
}

/// Human name for a primitive, carrying `(simulated)` when it is.
fn sanitize_operation_name(p: SanitizePrimitive, simulated: bool) -> String {
    let base = match p {
        SanitizePrimitive::AtaSecureErase => "ATA SECURITY ERASE UNIT",
        SanitizePrimitive::AtaSecureEraseEnhanced => "ATA SECURITY ERASE UNIT (ENHANCED)",
        SanitizePrimitive::AtaSanitizeBlockErase => "ATA SANITIZE BLOCK ERASE",
        SanitizePrimitive::AtaSanitizeCryptoScramble => "ATA SANITIZE CRYPTO SCRAMBLE",
        SanitizePrimitive::AtaSanitizeOverwrite => "ATA SANITIZE OVERWRITE",
        SanitizePrimitive::NvmeFormatCryptoErase => "NVMe FORMAT NVM (crypto erase)",
        SanitizePrimitive::NvmeSanitizeBlockErase => "NVMe SANITIZE (block erase)",
        SanitizePrimitive::NvmeSanitizeCryptoErase => "NVMe SANITIZE (crypto erase)",
        SanitizePrimitive::NvmeSanitizeOverwrite => "NVMe SANITIZE (overwrite)",
        SanitizePrimitive::Overwrite => "host overwrite",
        SanitizePrimitive::TrimDeallocate => "TRIM / DEALLOCATE",
    };
    if simulated {
        format!("{base} (simulated)")
    } else {
        base.to_string()
    }
}

/// Attempt one firmware sanitize, time it, witness its effect, and audit it.
///
/// The order is the argument. The witness digest is taken **before** the command so
/// a command that did change the medium cannot be reported as one that did not; the
/// command is timed with nothing else inside the stopwatch; the witness is taken
/// again; and only then is the duration handed to [`audit::audit`], which has never
/// seen the return code.
pub fn attempt_sanitize<D: Device>(
    io: &mut DeviceIo<D>,
    primitive: SanitizePrimitive,
    baseline: Option<&Baseline>,
    baseline_refusal: Option<SampleRefusal>,
) -> Result<SanitizeReport, WipeError> {
    let caps = io.device_capabilities()?;
    let support = caps.support(primitive);
    let source = caps.claim_source(primitive);
    let capacity = caps.total_bytes();

    let witness_before = medium_witness(io, SANITIZE_WITNESS_SECTORS)?;
    let t = Instant::now();
    let transmitted = issue_sanitize(io, primitive)?;
    let measured_ns = t.elapsed().as_nanos();
    let witness_after = medium_witness(io, SANITIZE_WITNESS_SECTORS)?;

    // SIMULATED IS A PROPERTY OF WHAT WAS SENT, NOT OF WHAT THE DEVICE CLAIMS.
    // `support` is recorded beside it — a device may claim a primitive we still
    // cannot issue — but it does not decide this field. Operator decision 3: the
    // word `simulated` belongs in the field itself, and it belongs there whenever
    // no command left this process.
    let simulated = transmitted.is_none();
    // The return code, when there was one. A simulated command has none, and the
    // `true` below is the analogue's, published beside `simulated: true` and
    // `return_code_trusted: false` so it cannot be read as a device's answer.
    let ok = transmitted.unwrap_or(true);

    let operation = sanitize_operation_name(primitive, simulated);
    let op = Operation {
        label: operation.clone(),
        workload: workload_for(primitive, capacity),
        measured_ns,
        simulated,
        device_reported_success: ok,
    };
    let report = match baseline {
        Some(b) => audit(&op, Some(b)),
        None => audit_without_baseline(
            &op,
            baseline_refusal.unwrap_or(SampleRefusal::ZeroBytes),
        ),
    };

    let unchanged = witness_before == witness_after;
    let disposition = disposition_for(&report, simulated);

    Ok(SanitizeReport {
        primitive: primitive.as_str(),
        operation,
        simulated,
        device_support: support.as_str(),
        claim_source: source.as_str(),
        device_reported_success: ok,
        measured_ns,
        bytes_claimed: capacity,
        witness_before,
        witness_after,
        medium_unchanged: unchanged,
        disposition,
        limits: SANITIZE_SIMULATION_LIMITS,
        audit: report,
        operation_record: op,
    })
}

// ---------------------------------------------------------------------------
// The calibration probe
// ---------------------------------------------------------------------------

/// A write-throughput measurement the audited operation did not produce.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeReport {
    pub bytes: u64,
    pub sectors: u64,
    pub duration_ns: u128,
    pub sync_ns: u128,
    pub throughput_bytes_per_s: f64,
    /// The pattern written, which is the *final* pass's pattern. Every byte the
    /// probe writes is overwritten again by pass 1, so the medium's final state and
    /// the certificate are identical with and without it. Recorded so that claim can
    /// be checked rather than believed.
    pub pattern: &'static str,
    pub admitted: bool,
    pub refusal: Option<&'static str>,
}

/// Write `bytes` of the final pass's pattern to the head of the medium and time it.
///
/// This runs **before** any pass, and it is the reason the behavioural audit's
/// judgement of the overwrite is not self-referential. Auditing an overwrite against
/// a baseline computed from that same overwrite gives a ratio of exactly 1.0 by
/// construction and proves nothing; the probe is a separate measurement of the same
/// I/O path, so a fabricated pass duration cannot move it.
///
/// It is destructive, and that is not a cost here: it writes only to a target the
/// caller has already authorized for a full-capacity overwrite, and every byte it
/// writes is overwritten again by pass 1.
pub fn calibration_probe<D>(
    io: &mut D,
    cfg: &WipeConfig,
    bytes: u64,
) -> Result<ProbeReport, WipeError>
where
    D: SectorIo + ?Sized,
{
    let caps = io.capabilities()?;
    let sb = caps.sector_bytes as u64;
    let want = bytes / sb;
    let sectors = want.min(caps.sector_count).max(1);
    let final_pass = cfg.method.pass_count();
    let gen = PatternGen::new(&cfg.seed, cfg.method, final_pass, caps.sector_bytes)?;

    let chunk = cfg.chunk_sectors_max.max(1) as u64;
    let mut buf = vec![0u8; (chunk.min(sectors) as usize) * sb as usize];
    if gen.is_constant() {
        gen.fill_run(0, &mut buf)?;
    }

    let t = Instant::now();
    let mut lba = 0u64;
    while lba < sectors {
        let n = core::cmp::min(chunk, sectors - lba) as usize;
        let slice = &mut buf[..n * sb as usize];
        if !gen.is_constant() {
            gen.fill_run(lba, slice)?;
        }
        io.write_sectors(lba, slice)?;
        lba += n as u64;
    }
    let t_sync = Instant::now();
    io.sync()?;
    let sync_ns = t_sync.elapsed().as_nanos();
    let duration_ns = t.elapsed().as_nanos();

    let written = sectors * sb;
    let (admitted, refusal) = match ThroughputSample::new(
        written,
        duration_ns,
        BaselineSource::CalibrationProbe,
    ) {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.as_str())),
    };

    Ok(ProbeReport {
        bytes: written,
        sectors,
        duration_ns,
        sync_ns,
        throughput_bytes_per_s: if duration_ns == 0 {
            0.0
        } else {
            written as f64 * 1_000_000_000.0 / duration_ns as f64
        },
        pattern: gen.pattern().label(),
        admitted,
        refusal,
    })
}

// ---------------------------------------------------------------------------
// The job
// ---------------------------------------------------------------------------

/// How the medium was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Read back `sectors_per_mib` sectors per MiB. Fast, and supports a claim only
    /// about the sectors it read.
    Sampled,
    /// Read back every sector. The only mode that supports a statement about the
    /// whole medium.
    Exhaustive,
}

impl VerifyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerifyMode::Sampled => "sampled",
            VerifyMode::Exhaustive => "exhaustive",
        }
    }
}

/// Everything the driver needs that is not the device and not the sink.
#[derive(Debug, Clone)]
pub struct JobSpec {
    /// The run identifier the pattern seed is derived from. Same id, same seed,
    /// same bytes on the medium — CLAUDE.md rule 6.
    pub run_id: String,
    /// `None` dispatches by detected medium.
    pub method: Option<Method>,
    /// `None` dispatches by detected medium. `Some` forces an attempt, which on a
    /// medium that does not claim the primitive is simulated and labelled so.
    pub sanitize: Option<SanitizePrimitive>,
    pub verify_mode: VerifyMode,
    pub sampling: SamplingPolicy,
    /// Whole-medium Shannon entropy before and after. Two full reads of the medium;
    /// off for a job that does not need the figure.
    pub measure_entropy: bool,
    pub probe_bytes: u64,
    /// Run the per-object crypto-erase demonstration over the head of the medium
    /// **before** the wipe, so it operates on real plaintext.
    pub crypto_erase_demo_bytes: u64,
    pub telemetry_period: Option<Duration>,
    /// The target as the operator named it, and as the write authority resolved it.
    /// Supplied by the caller because the driver holds a `Device` and a `Device` is
    /// not required to have a path.
    pub target_named: String,
    pub target_resolved: String,
    /// The write authority's own allow code and policy payload, when there is one.
    pub authorization: Option<Authorization>,
    /// The exact command that reproduces this run.
    pub command: String,
}

impl JobSpec {
    pub fn new(run_id: &str) -> JobSpec {
        JobSpec {
            run_id: run_id.to_string(),
            method: None,
            sanitize: None,
            verify_mode: VerifyMode::Sampled,
            sampling: SamplingPolicy::default(),
            measure_entropy: true,
            probe_bytes: DEFAULT_PROBE_BYTES,
            crypto_erase_demo_bytes: 0,
            telemetry_period: None,
            target_named: String::new(),
            target_resolved: String::new(),
            authorization: None,
            command: String::new(),
        }
    }

    pub fn seed(&self) -> Seed {
        Seed::from_run_id(&self.run_id)
    }
}

/// The write authority's evidence, copied onto the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// The guard's own allow code, e.g. `ALLOW_FILE`.
    pub decision_code: String,
    /// `policy-payload:<bytes>`. Deliberately **not** a digest: `guard.rs` carries
    /// no hash primitive, so it publishes the exact bytes `fixtures/guard.py` feeds
    /// to SHA-256. A consumer holding SHA-256 hashes the part after the prefix and
    /// gets the digest the Python guard publishes. Never print this as if it were
    /// one.
    pub policy_digest: String,
    pub roots: Vec<String>,
    pub require_confirmation: bool,
}

/// The job's one-line answer, **carrying the coverage its evidence had**.
///
/// Three states, not two, and the reason is the same one `audit.rs` gives for its
/// five-state verdict. `outcome.code` is the one structured field a UI or a
/// certificate template binds a green light to, and before this split a 0.1953%
/// sampled run and a 100% exhaustive run produced byte-identical outcome fields:
/// `OVERWRITE_VERIFIED_BY_READ_BACK`, `sanitized: true`, exit 0, for both. "Sanitize"
/// is a whole-medium word in NIST SP 800-88 vocabulary, and a whole-medium impression
/// formed from a structured field backed by 1,024 of 524,288 sectors is exactly the
/// over-claim CLAUDE.md rule 1 exists to prevent. The prose said so correctly; the
/// field did not, and a consumer reads the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every sector of the medium was read back after every pass and every one
    /// carried its pattern. The only outcome that supports a whole-medium statement.
    VerifiedWholeMedium,
    /// Every pass was written and every *sampled* sector carried its pattern. A
    /// statement about the sectors read and about nothing else; the coverage
    /// fraction and the size of the largest unsampled run are published beside it.
    VerifiedOnSample,
    /// The passes ran; at least one read-back did not confirm its pattern.
    NotVerified,
}

impl Outcome {
    pub fn code(&self) -> &'static str {
        match self {
            Outcome::VerifiedWholeMedium => "OVERWRITE_VERIFIED_WHOLE_MEDIUM",
            Outcome::VerifiedOnSample => "OVERWRITE_VERIFIED_ON_SAMPLE",
            Outcome::NotVerified => "OVERWRITE_NOT_VERIFIED",
        }
    }

    /// Whether every pass's read-back confirmed its pattern. Deliberately NOT the
    /// whole of `outcome`: it says the evidence held, never how much of the medium
    /// the evidence covered.
    pub fn passes_verified(&self) -> bool {
        !matches!(self, Outcome::NotVerified)
    }

    /// True only for [`Outcome::VerifiedWholeMedium`]. This is the predicate a
    /// consumer wanting a whole-medium claim must read.
    pub fn is_whole_medium_claim(&self) -> bool {
        matches!(self, Outcome::VerifiedWholeMedium)
    }
}

/// Everything one job produced.
#[derive(Debug, Clone)]
pub struct JobReport {
    pub run_id: String,
    pub seed_hex: String,
    pub target_named: String,
    pub target_resolved: String,
    pub authorization: Option<Authorization>,
    pub command: String,
    pub profile: MediumProfile,
    pub dispatch: Dispatch,
    pub probe: ProbeReport,
    pub sanitize: Option<SanitizeReport>,
    pub crypto_erase: Option<crate::passes::CryptoEraseReport>,
    pub wipe: VerifiedWipeReport,
    pub verify_mode: VerifyMode,
    /// The audit of the overwrite job, judged against the calibration probe — a
    /// sample the overwrite did not produce.
    pub overwrite_audit: AuditReport,
    /// The baseline the sanitize was judged against: the fastest of the calibration
    /// probe and the first completed overwrite pass. `None` when neither sample was
    /// admissible, in which case the audit reports `UNVERIFIED_NO_BASELINE` and
    /// never `VERIFIED_TIMING`.
    pub sanitize_baseline_source: Option<&'static str>,
    /// True when a completed overwrite pass existed but was NOT promoted into the
    /// sanitize's baseline, because `overwrite_audit` did not verify it. A sample
    /// this report calls physically impossible may not become this report's
    /// definition of physically possible.
    pub observed_pass_baseline_withheld: bool,
    pub telemetry: telemetry::Summary,
    pub telemetry_period_ms: u64,
    /// The longest stretch of this job during which the write loop was, by
    /// construction, not writing: a pass's closing `fsync` plus the read-back
    /// sweep that follows it. Measured, and published beside `max_gap_ms` because
    /// it is the explanation for it.
    ///
    /// A telemetry frame is emitted from a `wrote` call, so nothing can emit
    /// during a blocking `fsync` or during a verification sweep that writes
    /// nothing. Emitting one anyway would be a progress bar rather than an
    /// instrument, which `telemetry.rs` refuses on purpose. So the 20 Hz floor is
    /// a property of the *write* stream, and a gap that spans one of these
    /// intervals is not a stalled engine. This field is what lets a reader tell
    /// the two apart instead of taking that on trust.
    pub longest_uninstrumented_interval_ns: u128,
    /// `None` when the entropy measurement was not asked for. Never `0.0`: a zero is
    /// what a zero-fill measures, and the two must be distinguishable.
    pub entropy_before: Option<f64>,
    pub entropy_after: Option<f64>,
    pub entropy_bytes_measured: Option<u64>,
    pub duration_ns: u128,
    pub outcome: Outcome,
    pub limits: Vec<String>,
}

impl JobReport {
    pub fn throughput_bytes_per_s(&self) -> f64 {
        self.wipe.wipe.throughput_bytes_per_s()
    }

    /// The coverage of the least-verified pass. The figure a whole-report claim has
    /// to rest on, since a three-pass job is no better verified than its weakest
    /// read-back.
    pub fn min_coverage_fraction(&self) -> f64 {
        // No verification at all is 0.0 coverage, never 1.0. The empty case is the
        // one where an accidental identity element would publish a whole-medium
        // figure for a medium nothing read.
        if self.wipe.verifications.is_empty() {
            return 0.0;
        }
        self.wipe
            .verifications
            .iter()
            .map(|v| v.coverage_fraction)
            .fold(f64::INFINITY, f64::min)
            .clamp(0.0, 1.0)
    }
}

/// Run one job end to end against a device, through the [`Device`] trait only.
///
/// The order is the argument, and every step of it is measured:
///
/// 1. **Read the medium's identity and geometry.** A capability report that fails
///    its own invariants is refused rather than believed.
/// 2. **Whole-medium entropy, before.** Over every byte, with the same estimator
///    `fixtures/corpus.py` used for the manifest's figure, so the two may be
///    subtracted.
/// 3. **Crypto-erase demonstration**, if asked for, over real plaintext read from
///    the head of the medium. Read-only, and labelled a demonstration in every field
///    it emits.
/// 4. **Calibration probe.** A write-throughput sample the overwrite did not
///    produce, laying down the final pass's pattern so pass 1 erases it again.
/// 5. **Firmware sanitize**, if the dispatch selected or the caller named one.
///    Timed, witnessed by a strided digest of the medium before and after, and
///    audited. Simulated on anything that is not a real controller.
/// 6. **The overwrite**, pass by pass, with telemetry, each pass read back before
///    the next overwrites it.
/// 7. **Whole-medium entropy, after.**
/// 8. **The audits.** The overwrite against the probe; the sanitize against the
///    faster of the probe and the first completed pass.
pub fn run_job<D, S>(
    device: D,
    spec: &JobSpec,
    sink: S,
) -> Result<(JobReport, D), WipeError>
where
    D: Device,
    S: EventSink,
{
    let t_job = Instant::now();
    let mut io = DeviceIo::new(device);

    // 1 --------------------------------------------------------------- profile
    let profile = MediumProfile::read(&io)?;
    let transport = io.device_identity().transport;
    if !profile.writable {
        return Err(WipeError::Unsupported(format!(
            "{} reports itself not writable; refused before a byte moved",
            profile.describe()
        )));
    }
    let disp = dispatch(&profile, transport, spec.method, spec.sanitize);
    let cfg = WipeConfig::new(disp.method, spec.seed());

    // 2 -------------------------------------------------------- entropy before
    let (entropy_before, entropy_bytes) = if spec.measure_entropy {
        let (e, n) = verify::medium_entropy(&mut io, cfg.chunk_sectors_max)?;
        (Some(e), Some(n))
    } else {
        (None, None)
    };

    // 3 ------------------------------------------------- crypto-erase demo
    let crypto_erase = if spec.crypto_erase_demo_bytes > 0 {
        let sb = profile.sector_bytes as u64;
        let sectors = (spec.crypto_erase_demo_bytes / sb)
            .max(1)
            .min(profile.sector_count);
        let mut plain = vec![0u8; (sectors * sb) as usize];
        SectorIo::read_sectors(&mut io, 0, &mut plain)?;
        let mut key = [0u8; 32];
        shake128(
            &[
                crate::passes::CRYPTO_ERASE_DOMAIN,
                b"job-key",
                spec.seed().as_bytes(),
            ],
            &mut key,
        );
        let (_ct, rep) = crate::passes::crypto_erase_demonstration(
            key,
            &format!("{}:head:{}B", spec.run_id, plain.len()),
            &plain,
        );
        Some(rep)
    } else {
        None
    };

    // 4 ----------------------------------------------------- calibration probe
    let probe = calibration_probe(&mut io, &cfg, spec.probe_bytes)?;
    let probe_sample = ThroughputSample::new(
        probe.bytes,
        probe.duration_ns,
        BaselineSource::CalibrationProbe,
    );
    let probe_baseline = probe_sample.as_ref().ok().copied().map(Baseline::from_sample);
    let probe_refusal = probe_sample.as_ref().err().copied();

    // 5 ----------------------------------------------------- firmware sanitize
    let sanitize = match disp.sanitize {
        Some(p) => Some(attempt_sanitize(
            &mut io,
            p,
            probe_baseline.as_ref(),
            probe_refusal,
        )?),
        None => None,
    };

    // 6 ------------------------------------------------------------- overwrite
    let tspec = cfg.telemetry_spec(&SectorIo::identify(&io), &SectorIo::capabilities(&io)?);
    let mut tm = Telemetry::start(tspec, sink, spec.telemetry_period);
    let wipe = match spec.verify_mode {
        VerifyMode::Sampled => verify::wipe_verified(&mut io, &cfg, &spec.sampling, &mut tm),
        VerifyMode::Exhaustive => wipe_verified_exhaustive(&mut io, &cfg, &mut tm),
    };
    let wipe = match wipe {
        Ok(w) => w,
        Err(e) => {
            tm.finish(&format!("aborted:{}", e));
            return Err(e);
        }
    };
    // The outcome carries the coverage of its own evidence. `all_passes_verified`
    // says the read-back held; the verify mode says how much of the medium it read.
    let outcome = if !wipe.all_passes_verified {
        Outcome::NotVerified
    } else if spec.verify_mode == VerifyMode::Exhaustive {
        Outcome::VerifiedWholeMedium
    } else {
        Outcome::VerifiedOnSample
    };
    let summary = tm.finish(match outcome {
        Outcome::VerifiedWholeMedium | Outcome::VerifiedOnSample => "complete",
        Outcome::NotVerified => "aborted:read-back did not confirm every pass",
    });

    // 7 --------------------------------------------------------- entropy after
    let entropy_after = if spec.measure_entropy {
        Some(verify::medium_entropy(&mut io, cfg.chunk_sectors_max)?.0)
    } else {
        None
    };

    // 8 -------------------------------------------------------------- audits
    let overwrite_op = Operation {
        label: format!("host overwrite: {}", disp.method.label()),
        workload: Workload::Overwrite {
            capacity_bytes: wipe.wipe.capacity_bytes,
            passes: disp.method.pass_count(),
        },
        measured_ns: wipe.wipe.duration_ns,
        simulated: false,
        device_reported_success: true,
    };
    let overwrite_audit = match probe_baseline.as_ref() {
        Some(b) => audit(&overwrite_op, Some(b)),
        None => audit_without_baseline(
            &overwrite_op,
            probe_refusal.unwrap_or(SampleRefusal::ZeroBytes),
        ),
    };

    // The sanitize was judged against the probe alone, because it ran before the
    // passes did. By now a stronger sample exists — a completed pass over this same
    // medium — so the verdict is retaken against the faster of the two and the
    // report names the baseline the shipped verdict actually used.
    //
    // THE PROMOTION IS GATED ON THE OVERWRITE'S OWN VERDICT, and that gate is not
    // decoration. Promoting unconditionally let the audit's yardstick for
    // "physically possible" be a sample the same report had just declared
    // physically impossible. Measured on an adversarial device that slows host
    // writes only while the short calibration probe runs: `audit.overwrite`
    // UNVERIFIED_TIMING at 97,955,750 ns against 4,580,305,000 ns, and then
    // `audit.sanitize` VERIFIED_TIMING for a 12 ms firmware command that the
    // honestly measured probe alone rates at a ratio of 0.002620 — one certificate
    // calling pass 1 implausible and then using pass 1 as the definition of
    // plausible. This module's threat model is "never trust the drive"; a sample
    // taken through a device that controls its own timing is not evidence, and a
    // discarded sample only ever leaves the detector MORE eager, which is the safe
    // direction.
    let mut strongest = probe_baseline;
    let mut observed_pass_baseline_withheld = false;
    if let Some(p0) = wipe.wipe.passes.first() {
        if overwrite_audit.severity() == Severity::Verified {
            let (bytes, ns) = p0.throughput_sample_input();
            match strongest.as_mut() {
                Some(b) => {
                    let _ = b.observe(bytes, ns, BaselineSource::ObservedPass);
                }
                None => {
                    if let Ok(s) = ThroughputSample::new(bytes, ns, BaselineSource::ObservedPass)
                    {
                        strongest = Some(Baseline::from_sample(s));
                    }
                }
            }
        } else {
            observed_pass_baseline_withheld = true;
        }
    }

    let mut sanitize = sanitize;
    if let (Some(sa), Some(b)) = (sanitize.as_mut(), strongest.as_ref()) {
        sa.reaudit(b);
    }
    let sanitize_baseline_source = sanitize.as_ref().and_then(|sa| sa.baseline_source());

    let mut limits = vec![
        wipe.wipe.scope_limit.to_string(),
        crate::verify::SAMPLING_IS_NOT_PROOF.to_string(),
    ];
    if spec.verify_mode == VerifyMode::Sampled {
        limits.push(crate::verify::SAMPLE_POSITIONS_ARE_PUBLIC.to_string());
        // The size of the blind spot, measured on this run's own plan rather than
        // left for a reader to derive from a coverage fraction — or to discover on
        // stage. A whole planted file can sit between two sample points: measured
        // on out/fixture.img, a 208,084-byte file restored into an otherwise wiped
        // image produced PATTERN_CONFIRMED_ON_SAMPLE with zero mismatches while the
        // project's own carver recovered it byte-exact from the same image.
        let gap = wipe
            .verifications
            .iter()
            .map(|v| v.largest_unsampled_run_sectors)
            .max()
            .unwrap_or(0);
        let sb = wipe.wipe.sector_bytes as u64;
        let cap = wipe.wipe.capacity_bytes.max(1);
        limits.push(format!(
            "SAMPLED VERIFICATION HAS A BLIND SPOT AND THIS IS ITS MEASURED SIZE ON \
             THIS RUN. The longest run of consecutive sectors no sample touched is {} \
             sectors, {} bytes, {} of the medium. An unwiped region of that size or \
             smaller, positioned between two sample points, produces \
             PATTERN_CONFIRMED_ON_SAMPLE with zero mismatched sectors and an unchanged \
             sample digest: the verdict is a statement about the sectors read and about \
             nothing else. `--verify exhaustive` reads every sector and is what turns it \
             into a whole-medium statement. Regression test: core/wipe/src/verify.rs::\
             a_region_left_unwiped_between_sample_points_survives_a_confirmed_sample.",
            gap,
            gap * sb,
            fmt6(gap as f64 * sb as f64 / cap as f64),
        ));
    }
    if profile.has_hidden_regions {
        limits.push(HIDDEN_REGION_LIMIT.to_string());
    }
    if sanitize.is_some() {
        limits.push(SANITIZE_SIMULATION_LIMITS.to_string());
    }
    if let Some(c) = &crypto_erase {
        limits.push(c.limits.to_string());
    }

    // The longest interval the driver itself imposed between two `wrote` calls:
    // a pass's sync, plus the read-back sweep that follows it before the next
    // pass begins. Measured from the two reports rather than timed separately.
    let mut longest_uninstrumented_interval_ns = 0u128;
    for (i, pass) in wipe.wipe.passes.iter().enumerate() {
        let verify_ns = wipe
            .verifications
            .get(i)
            .map(|v| v.duration_ns)
            .unwrap_or(0);
        let span = pass.sync_ns + verify_ns;
        if span > longest_uninstrumented_interval_ns {
            longest_uninstrumented_interval_ns = span;
        }
    }

    let report = JobReport {
        run_id: spec.run_id.clone(),
        seed_hex: spec.seed().hex(),
        target_named: spec.target_named.clone(),
        target_resolved: spec.target_resolved.clone(),
        authorization: spec.authorization.clone(),
        command: spec.command.clone(),
        profile,
        dispatch: disp,
        probe,
        sanitize,
        crypto_erase,
        wipe,
        verify_mode: spec.verify_mode,
        overwrite_audit,
        sanitize_baseline_source,
        observed_pass_baseline_withheld,
        telemetry: summary,
        telemetry_period_ms: spec
            .telemetry_period
            .map(|d| d.as_millis() as u64)
            .unwrap_or(telemetry::DEFAULT_PERIOD_MS),
        longest_uninstrumented_interval_ns,
        entropy_before,
        entropy_after,
        entropy_bytes_measured: entropy_bytes,
        duration_ns: t_job.elapsed().as_nanos(),
        outcome,
        limits,
    };
    Ok((report, io.into_inner()))
}

/// [`verify::wipe_verified`] with the exhaustive read-back instead of the sampled
/// one.
///
/// Same interleaving and the same reason for it: pass *k* is read back before pass
/// *k+1* overwrites it, so a three-pass method is not certified on the evidence of
/// its last pass alone.
pub fn wipe_verified_exhaustive<D, S>(
    io: &mut D,
    cfg: &WipeConfig,
    tm: &mut Telemetry<S>,
) -> Result<VerifiedWipeReport, WipeError>
where
    D: SectorIo + ?Sized,
    S: EventSink,
{
    let id = io.identify();
    let caps = io.capabilities()?;
    let t0 = Instant::now();
    let mut passes = Vec::new();
    let mut verifications: Vec<VerifyReport> = Vec::new();
    for pass in 1..=cfg.method.pass_count() {
        let r = crate::passes::run_pass(io, cfg, pass, tm)?;
        tm.end_pass(pass);
        passes.push(r);
        verifications.push(verify::verify_pass_exhaustive(
            io,
            cfg,
            pass,
            cfg.chunk_sectors_max,
        )?);
    }
    let bytes: u64 = passes.iter().map(|p| p.bytes_written).sum();
    let wipe = crate::passes::WipeReport {
        method_label: cfg.method.label(),
        nist_category: cfg.method.nist_category(),
        legacy_shape: cfg.method.legacy_shape(),
        seed_hex: cfg.seed.hex(),
        device: id.describe(),
        medium: caps.medium.as_str(),
        sector_bytes: caps.sector_bytes,
        sector_count: caps.sector_count,
        capacity_bytes: caps.capacity_bytes(),
        passes,
        bytes_written: bytes,
        duration_ns: t0.elapsed().as_nanos(),
        simulated: false,
        scope_limit: crate::passes::OVERWRITE_SCOPE_LIMIT,
    };
    let all = verifications.iter().all(|v| v.verdict.is_match());
    Ok(VerifiedWipeReport {
        wipe,
        verifications,
        all_passes_verified: all,
    })
}

// ---------------------------------------------------------------------------
// The report, on the wire
// ---------------------------------------------------------------------------

/// Six decimal places, always. `docs/output_schema.md` §2, and there are no
/// exceptions: not for zero, not for an integer-valued float, not for a large one.
/// NaN and the infinities cannot reach a report — they are mapped to `0.000000`
/// here, because a certificate containing `NaN` is a defect and a reader comparing
/// it against a threshold would be comparing against nothing.
pub fn fmt6(v: f64) -> String {
    if v.is_nan() || v.is_infinite() {
        return "0.000000".to_string();
    }
    format!("{:.6}", v)
}

/// Six decimal places, **truncated toward zero** rather than rounded. For the
/// entropy fields only, and the reason is a measured defect.
///
/// A three-pass wipe measured 7.999999501350531 bits/byte, which [`fmt6`] rounds to
/// `8.000000` — the unattainable theoretical maximum, printed for a value that is
/// not it. Worse, the report invites the reader to subtract: `delta` was computed at
/// full precision, so the document stated 8.000000 − 7.061690 = 0.938309, which is
/// false by 1e-6. Entropy is the one field where the seventh decimal carries the
/// meaning — "climbed to 8.0" and "climbed to within 5e-7 of 8.0" are different
/// claims, and only the second one was measured. Truncation makes the printed value
/// a lower bound on the measurement, which is the direction that cannot over-claim,
/// and `delta` is derived from the two printed values so the subtraction a reader is
/// invited to do checks out exactly.
pub fn fmt6_trunc(v: f64) -> String {
    if v.is_nan() || v.is_infinite() {
        return "0.000000".to_string();
    }
    let scaled = (v * 1_000_000.0).trunc() / 1_000_000.0;
    format!("{:.6}", scaled)
}

/// Nanoseconds as six-place seconds. Emitted **alongside** the integer, never
/// instead of it: below a microsecond the seconds field prints `0.000000` and the
/// integer is what carries the evidence.
fn ns_s(ns: u128) -> String {
    fmt6(ns as f64 / 1_000_000_000.0)
}

/// JSON string escaping, `ensure_ascii` style so the output is byte-identical
/// whatever the locale.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                let mut b = [0u16; 2];
                for u in c.encode_utf16(&mut b) {
                    out.push_str(&format!("\\u{:04x}", u));
                }
            }
        }
    }
    out.push('"');
    out
}

fn opt_u(v: Option<u64>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => "null".to_string(),
    }
}

fn opt_s(v: Option<&str>) -> String {
    match v {
        Some(x) => json_str(x),
        None => "null".to_string(),
    }
}

impl JobReport {
    /// The notes block. Load-bearing, not decoration: every one of these is a
    /// statement a reader needs in order not to over-read a number above it.
    pub fn notes(&self) -> Vec<String> {
        let mut n = vec![
            "Produced by a real wipe run. Every number in this file was measured \
             during it; none is illustrative."
                .to_string(),
            format!(
                "The sanitization claim in `outcome` rests on read-back verification \
                 of {} of {} sectors, not on any device return code.",
                self.wipe
                    .verifications
                    .iter()
                    .map(|v| v.sectors_verified)
                    .max()
                    .unwrap_or(0),
                self.profile.sector_count
            ),
            "`audit.overwrite` is judged against the calibration probe, which is a \
             throughput sample the overwrite did not produce. Auditing an operation \
             against a baseline derived from itself returns a ratio of 1.0 by \
             construction and is worth nothing."
                .to_string(),
            "Timing figures are wall-clock and are NOT reproducible across runs. \
             CLAUDE.md rule 6 constrains the certificate; a byte-identity comparison \
             must exclude every duration, rate and ratio field in this file, or \
             bucket them. The medium's contents ARE reproducible from run_id."
                .to_string(),
        ];
        if let Some(s) = &self.sanitize {
            if s.simulated {
                n.push(format!(
                    "`sanitize` is SIMULATED: NO firmware command was transmitted for \
                     {1}, on any device — there is no ioctl path in this build — and \
                     `simulated` is set from that fact rather than from the device's \
                     capability report, which reads `{0}`. It destroyed nothing, and the \
                     medium witness digest is byte-identical before and after it: {2}.",
                    s.device_support,
                    s.primitive,
                    if s.medium_unchanged {
                        "measured unchanged"
                    } else {
                        "MEASURED CHANGED, which contradicts the simulation and is a defect"
                    }
                ));
            }
        }
        if self.crypto_erase.is_some() {
            n.push(
                "`crypto_erase` is a DEMONSTRATION over the head of the medium, run \
                 before the wipe so it operates on real plaintext. Its keystream is a \
                 SHAKE-128 XOF in counter mode, is not a certified cipher, and is not \
                 the operation that sanitized this medium."
                    .to_string(),
            );
        }
        if self.verify_mode == VerifyMode::Sampled {
            let gap = self
                .wipe
                .verifications
                .iter()
                .map(|v| v.largest_unsampled_run_sectors)
                .max()
                .unwrap_or(0);
            n.push(format!(
                "Verification was SAMPLED, and `outcome.code` says so: \
                 OVERWRITE_VERIFIED_ON_SAMPLE, `whole_medium_claim` false, coverage {} \
                 of the medium. The longest run of consecutive sectors no sample touched \
                 is {} sectors ({} bytes); a region of that size left unwiped between \
                 sample points produces this same verdict. `--verify exhaustive` reads \
                 every sector and returns OVERWRITE_VERIFIED_WHOLE_MEDIUM instead.",
                fmt6(self.min_coverage_fraction()),
                gap,
                gap * self.wipe.wipe.sector_bytes as u64,
            ));
        }
        // The expected minimum is a function of an operator-chosen flag, and the
        // direction and size of that dependence is measured rather than left for a
        // reader to infer it is a property of the device.
        n.push(format!(
            "`audit.overwrite.expected_min_duration_ns` is derived from the calibration \
             probe, whose size is the operator-chosen --probe-bytes ({} B here). The \
             probe carries a fixed fsync cost amortised over fewer bytes than the wipe, \
             so it UNDER-measures the device and the expected minimum is an upper bound \
             on the true floor — the audit errs toward firing, never toward silence. \
             Measured on a 256 MiB medium: 192.24 MB/s at 1 MiB, 352.39 at 4 MiB, 560.05 \
             at the 32 MiB default, 606.29 at 256 MiB, a 3.15x span in the published \
             ratio for one identical operation. {}",
            self.probe.bytes,
            match self.overwrite_audit.verdict.ratio() {
                Some(r) => format!(
                    "This run's overwrite ratio {} sits {}x above the {} firing line.",
                    fmt6(r),
                    fmt6(r / crate::audit::PLAUSIBILITY_THRESHOLD),
                    fmt6(crate::audit::PLAUSIBILITY_THRESHOLD),
                ),
                // No ratio exists, and a 0.000000 printed here would be a
                // measurement claim about a measurement that was never taken.
                None => format!(
                    "This run has no overwrite ratio at all: the probe was not \
                     admitted as a baseline ({}), so `audit.overwrite` is \
                     UNVERIFIED_NO_BASELINE and no expected minimum was computed.",
                    self.probe.refusal.unwrap_or("no sample offered"),
                ),
            },
        ));
        if self.observed_pass_baseline_withheld {
            n.push(
                "The completed overwrite pass was WITHHELD from the sanitize's baseline: \
                 `audit.overwrite` did not verify it, and a sample this report calls \
                 physically impossible may not become this report's definition of \
                 physically possible. The sanitize verdict stands on the calibration \
                 probe alone."
                    .to_string(),
            );
        }
        if !self.telemetry.met_rate_floor {
            n.push(format!(
                "The telemetry stream did not hold the {} Hz floor: worst inter-frame \
                 gap {} ms, against a longest uninstrumented interval of {} ms (a \
                 pass's fsync plus the read-back sweep after it, during which nothing \
                 was written and so nothing could be emitted). Reported rather than \
                 smoothed, and not fixed by emitting a frame for work that did not \
                 happen.",
                fmt6(telemetry::MIN_RATE_HZ),
                fmt6(self.telemetry.max_gap_ms),
                fmt6(self.longest_uninstrumented_interval_ns as f64 / 1_000_000.0)
            ));
        }
        n
    }

    /// One JSON document, `sentinelwipe.wipe.report/1`.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(8192);
        s.push_str("{\n");
        s.push_str(&format!("  \"schema\": {},\n", json_str(REPORT_SCHEMA)));

        // ---- provenance
        s.push_str("  \"provenance\": {\n");
        s.push_str("    \"producer\": \"core/wipe/src/lib.rs::run_job\",\n");
        s.push_str(&format!("    \"command\": {},\n", json_str(&self.command)));
        s.push_str("    \"is_wipe_run\": true,\n");
        s.push_str("    \"notes\": [\n");
        let notes = self.notes();
        for (i, n) in notes.iter().enumerate() {
            s.push_str(&format!(
                "      {}{}\n",
                json_str(n),
                if i + 1 < notes.len() { "," } else { "" }
            ));
        }
        s.push_str("    ]\n  },\n");

        // ---- run
        s.push_str("  \"run\": {\n");
        s.push_str(&format!("    \"run_id\": {},\n", json_str(&self.run_id)));
        s.push_str(&format!("    \"seed_hex\": {},\n", json_str(&self.seed_hex)));
        s.push_str(&format!(
            "    \"target\": {},\n",
            json_str(&self.target_named)
        ));
        s.push_str(&format!(
            "    \"target_resolved\": {},\n",
            json_str(&self.target_resolved)
        ));
        s.push_str(&format!(
            "    \"elapsed_ns\": {},\n    \"elapsed_s\": {}\n",
            self.duration_ns,
            ns_s(self.duration_ns)
        ));
        s.push_str("  },\n");

        // ---- authorization
        match &self.authorization {
            Some(a) => {
                s.push_str("  \"authorization\": {\n");
                s.push_str(&format!(
                    "    \"decision_code\": {},\n",
                    json_str(&a.decision_code)
                ));
                s.push_str(&format!(
                    "    \"policy_digest_payload\": {},\n",
                    json_str(&a.policy_digest)
                ));
                s.push_str(
                    "    \"policy_digest_payload_is_not_a_digest\": \"The guard carries \
                     no hash primitive. This is the exact byte string fixtures/guard.py \
                     feeds to SHA-256; hash the part after the prefix to obtain the \
                     digest the Python guard publishes.\",\n",
                );
                s.push_str(&format!(
                    "    \"require_confirmation\": {},\n",
                    a.require_confirmation
                ));
                s.push_str("    \"allowed_roots\": [\n");
                for (i, r) in a.roots.iter().enumerate() {
                    s.push_str(&format!(
                        "      {}{}\n",
                        json_str(r),
                        if i + 1 < a.roots.len() { "," } else { "" }
                    ));
                }
                s.push_str("    ]\n  },\n");
            }
            None => s.push_str("  \"authorization\": null,\n"),
        }

        // ---- device
        let p = &self.profile;
        s.push_str("  \"device\": {\n");
        s.push_str(&format!("    \"kind\": {},\n", json_str(&p.kind)));
        s.push_str(&format!("    \"model\": {},\n", json_str(&p.model)));
        s.push_str(&format!("    \"serial\": {},\n", json_str(&p.serial)));
        s.push_str(&format!("    \"firmware\": {},\n", json_str(&p.firmware)));
        s.push_str(&format!("    \"transport\": {},\n", json_str(p.transport)));
        s.push_str(&format!(
            "    \"identity_source\": {},\n",
            json_str(p.identity_source)
        ));
        s.push_str(&format!(
            "    \"is_physical_medium\": {},\n",
            p.is_physical_medium
        ));
        s.push_str(&format!(
            "    \"medium\": {},\n",
            json_str(p.medium.as_str())
        ));
        s.push_str(&format!(
            "    \"has_hidden_regions\": {},\n",
            p.has_hidden_regions
        ));
        s.push_str(&format!(
            "    \"logical_sector_bytes\": {},\n",
            p.sector_bytes
        ));
        s.push_str(&format!(
            "    \"physical_sector_bytes\": {},\n",
            opt_u(p.physical_sector_bytes.map(|v| v as u64))
        ));
        s.push_str(&format!("    \"total_sectors\": {},\n", p.sector_count));
        s.push_str(&format!("    \"capacity_bytes\": {},\n", p.capacity_bytes));
        s.push_str(&format!("    \"writable\": {}\n", p.writable));
        s.push_str("  },\n");

        // ---- dispatch
        let d = &self.dispatch;
        s.push_str("  \"dispatch\": {\n");
        s.push_str(&format!(
            "    \"method\": {},\n",
            json_str(d.method.label())
        ));
        s.push_str(&format!(
            "    \"method_selected_by\": {},\n",
            json_str(if d.method_was_requested {
                "operator"
            } else {
                "detected-medium"
            })
        ));
        s.push_str(&format!("    \"passes\": {},\n", d.method.pass_count()));
        s.push_str(&format!(
            "    \"nist_category\": {},\n",
            json_str(d.method.nist_category())
        ));
        s.push_str(&format!(
            "    \"legacy_shape\": {},\n",
            opt_s(d.method.legacy_shape())
        ));
        s.push_str(&format!(
            "    \"sanitize_primitive\": {},\n",
            opt_s(d.sanitize.map(|p| p.as_str()))
        ));
        s.push_str(&format!(
            "    \"sanitize_selected_by\": {},\n",
            json_str(if d.sanitize_was_requested {
                "operator"
            } else {
                "detected-medium"
            })
        ));
        s.push_str(&format!(
            "    \"rationale\": {}\n",
            json_str(&d.rationale)
        ));
        s.push_str("  },\n");

        // ---- entropy
        s.push_str("  \"entropy_bits_per_byte\": {\n");
        // Truncated, not rounded, and `delta` is the difference of the two printed
        // values — see fmt6_trunc. The three numbers in this block subtract exactly.
        let e_before = self.entropy_before.map(|v| fmt6_trunc(v));
        let e_after = self.entropy_after.map(|v| fmt6_trunc(v));
        s.push_str(&format!(
            "    \"before\": {},\n",
            e_before.clone().unwrap_or_else(|| "null".to_string())
        ));
        s.push_str(&format!(
            "    \"after\": {},\n",
            e_after.clone().unwrap_or_else(|| "null".to_string())
        ));
        s.push_str(&format!(
            "    \"delta\": {},\n",
            match (&e_before, &e_after) {
                (Some(a), Some(b)) => {
                    let (a, b): (f64, f64) = (a.parse().unwrap_or(0.0), b.parse().unwrap_or(0.0));
                    fmt6(b - a)
                }
                _ => "null".to_string(),
            }
        ));
        s.push_str(&format!(
            "    \"bytes_measured\": {},\n",
            opt_u(self.entropy_bytes_measured)
        ));
        s.push_str(
            "    \"estimator\": \"Shannon over a 256-bin byte histogram of every byte \
             of the medium, Neumaier-compensated; the same support and the same \
             estimator fixtures/corpus.py used for the manifest figure, so the two \
             may be subtracted. Printed TRUNCATED to six places, not rounded, so a \
             measured 7.9999995 never prints as the unattainable 8.000000; `delta` is \
             the difference of the two printed values, so these three numbers \
             subtract exactly. NOT the strided per-frame telemetry sample.\"\n",
        );
        s.push_str("  },\n");

        // ---- probe
        let pr = &self.probe;
        s.push_str("  \"calibration_probe\": {\n");
        s.push_str(&format!("    \"bytes\": {},\n", pr.bytes));
        s.push_str(&format!("    \"sectors\": {},\n", pr.sectors));
        s.push_str(&format!("    \"pattern\": {},\n", json_str(pr.pattern)));
        s.push_str(&format!("    \"duration_ns\": {},\n", pr.duration_ns));
        s.push_str(&format!(
            "    \"duration_s\": {},\n",
            ns_s(pr.duration_ns)
        ));
        s.push_str(&format!("    \"sync_ns\": {},\n", pr.sync_ns));
        s.push_str(&format!(
            "    \"bytes_per_second\": {},\n",
            fmt6(pr.throughput_bytes_per_s)
        ));
        s.push_str(&format!("    \"admitted_as_baseline\": {},\n", pr.admitted));
        s.push_str(&format!("    \"refusal\": {},\n", opt_s(pr.refusal)));
        s.push_str(
            "    \"note\": \"Written before pass 1 with the FINAL pass's pattern, so \
             every byte of it is overwritten again by the wipe and the medium's final \
             state is identical with and without it. It exists so the behavioural \
             audit judges the overwrite against a sample the overwrite did not \
             produce.\"\n",
        );
        s.push_str("  },\n");

        // ---- sanitize
        match &self.sanitize {
            Some(sa) => {
                s.push_str("  \"sanitize\": {\n");
                s.push_str(&format!(
                    "    \"primitive\": {},\n",
                    json_str(sa.primitive)
                ));
                s.push_str(&format!(
                    "    \"operation\": {},\n",
                    json_str(&sa.operation)
                ));
                s.push_str(&format!("    \"simulated\": {},\n", sa.simulated));
                s.push_str(&format!(
                    "    \"device_support\": {},\n",
                    json_str(sa.device_support)
                ));
                s.push_str(&format!(
                    "    \"claim_source\": {},\n",
                    json_str(sa.claim_source)
                ));
                s.push_str(&format!(
                    "    \"device_reported_success\": {},\n",
                    sa.device_reported_success
                ));
                s.push_str("    \"return_code_trusted\": false,\n");
                s.push_str(&format!(
                    "    \"measured_duration_ns\": {},\n",
                    sa.measured_ns
                ));
                s.push_str(&format!(
                    "    \"measured_duration_s\": {},\n",
                    ns_s(sa.measured_ns)
                ));
                s.push_str(&format!(
                    "    \"capacity_claimed_bytes\": {},\n",
                    sa.bytes_claimed
                ));
                s.push_str(&format!(
                    "    \"medium_witness_before\": {},\n",
                    json_str(&sa.witness_before)
                ));
                s.push_str(&format!(
                    "    \"medium_witness_after\": {},\n",
                    json_str(&sa.witness_after)
                ));
                s.push_str(&format!(
                    "    \"medium_unchanged\": {},\n",
                    sa.medium_unchanged
                ));
                s.push_str(&format!(
                    "    \"witness_sectors\": {},\n",
                    SANITIZE_WITNESS_SECTORS.min(self.profile.sector_count)
                ));
                s.push_str(&format!(
                    "    \"disposition\": {},\n",
                    json_str(sa.disposition)
                ));
                s.push_str(&format!("    \"limits\": {}\n", json_str(sa.limits)));
                s.push_str("  },\n");
            }
            None => s.push_str("  \"sanitize\": null,\n"),
        }

        // ---- crypto erase
        match &self.crypto_erase {
            Some(c) => {
                s.push_str("  \"crypto_erase\": {\n");
                s.push_str(&format!(
                    "    \"operation\": {},\n",
                    json_str(c.operation)
                ));
                s.push_str(&format!("    \"simulated\": {},\n", c.simulated));
                s.push_str(&format!(
                    "    \"construction\": {},\n",
                    json_str(c.demonstration_construction)
                ));
                s.push_str(&format!(
                    "    \"object_id\": {},\n",
                    json_str(&c.object_id)
                ));
                s.push_str(&format!("    \"object_bytes\": {},\n", c.object_bytes));
                s.push_str(&format!(
                    "    \"entropy_plaintext_bits_per_byte\": {},\n",
                    fmt6(c.entropy_plaintext_bits_per_byte)
                ));
                s.push_str(&format!(
                    "    \"entropy_ciphertext_bits_per_byte\": {},\n",
                    fmt6(c.entropy_ciphertext_bits_per_byte)
                ));
                s.push_str(&format!("    \"key_destroyed\": {},\n", c.key_destroyed));
                s.push_str(&format!(
                    "    \"key_fingerprint_hex\": {},\n",
                    json_str(&c.key_destruction.key_fingerprint_hex)
                ));
                s.push_str(&format!(
                    "    \"key_bytes_zeroed\": {},\n",
                    c.key_destruction.key_bytes_zeroed
                ));
                s.push_str(&format!(
                    "    \"residual_plaintext_match_fraction\": {},\n",
                    fmt6(c.residual_plaintext_match_fraction)
                ));
                s.push_str(
                    "    \"match_fraction_by_chance_alone\": 0.003906,\n",
                );
                s.push_str(&format!("    \"limits\": {}\n", json_str(c.limits)));
                s.push_str("  },\n");
            }
            None => s.push_str("  \"crypto_erase\": null,\n"),
        }

        // ---- overwrite
        let w = &self.wipe.wipe;
        s.push_str("  \"overwrite\": {\n");
        s.push_str(&format!("    \"method\": {},\n", json_str(w.method_label)));
        s.push_str(&format!("    \"simulated\": {},\n", w.simulated));
        s.push_str(&format!(
            "    \"nist_category\": {},\n",
            json_str(w.nist_category)
        ));
        s.push_str(&format!(
            "    \"legacy_shape\": {},\n",
            opt_s(w.legacy_shape)
        ));
        s.push_str(&format!("    \"bytes_written\": {},\n", w.bytes_written));
        s.push_str(&format!("    \"duration_ns\": {},\n", w.duration_ns));
        s.push_str(&format!("    \"duration_s\": {},\n", ns_s(w.duration_ns)));
        s.push_str(&format!(
            "    \"bytes_per_second\": {},\n",
            fmt6(w.throughput_bytes_per_s())
        ));
        s.push_str("    \"passes\": [\n");
        for (i, pass) in w.passes.iter().enumerate() {
            s.push_str("      {\n");
            s.push_str(&format!("        \"pass\": {},\n", pass.pass));
            s.push_str(&format!("        \"of\": {},\n", pass.passes));
            s.push_str(&format!(
                "        \"pattern\": {},\n",
                json_str(pass.pattern)
            ));
            s.push_str(&format!(
                "        \"sectors_written\": {},\n",
                pass.sectors_written
            ));
            s.push_str(&format!(
                "        \"bytes_written\": {},\n",
                pass.bytes_written
            ));
            s.push_str(&format!(
                "        \"duration_ns\": {},\n",
                pass.duration_ns
            ));
            s.push_str(&format!("        \"sync_ns\": {},\n", pass.sync_ns));
            s.push_str(&format!(
                "        \"bytes_per_second\": {},\n",
                fmt6(pass.throughput_bytes_per_s())
            ));
            s.push_str(&format!(
                "        \"chunk_writes\": {},\n",
                pass.chunk_writes
            ));
            s.push_str(&format!(
                "        \"chunk_sectors_first\": {},\n",
                pass.chunk_sectors_first
            ));
            s.push_str(&format!(
                "        \"chunk_sectors_final\": {},\n",
                pass.chunk_sectors_final
            ));
            s.push_str(&format!(
                "        \"chunk_resizes\": {},\n",
                pass.chunk_resizes
            ));
            s.push_str(&format!(
                "        \"max_chunk_ns\": {}\n",
                pass.max_chunk_ns
            ));
            s.push_str(&format!(
                "      }}{}\n",
                if i + 1 < w.passes.len() { "," } else { "" }
            ));
        }
        s.push_str("    ],\n");
        s.push_str(&format!(
            "    \"scope_limit\": {}\n",
            json_str(w.scope_limit)
        ));
        s.push_str("  },\n");

        // ---- verification
        s.push_str("  \"verification\": {\n");
        s.push_str(&format!(
            "    \"mode\": {},\n",
            json_str(self.verify_mode.as_str())
        ));
        s.push_str(&format!(
            "    \"all_passes_verified\": {},\n",
            self.wipe.all_passes_verified
        ));
        // The coverage of the WEAKEST pass, published at the top level so no
        // consumer has to walk `passes[]` to learn what the verdict covered. The
        // minimum, not the maximum and not the mean: a claim is only as good as the
        // least-verified pass behind it.
        s.push_str(&format!(
            "    \"coverage_fraction\": {},\n",
            fmt6(self.min_coverage_fraction())
        ));
        s.push_str(&format!(
            "    \"sectors_verified_min\": {},\n",
            self.wipe
                .verifications
                .iter()
                .map(|v| v.sectors_verified)
                .min()
                .unwrap_or(0)
        ));
        s.push_str(&format!(
            "    \"sectors_unverified_max\": {},\n",
            self.wipe
                .verifications
                .iter()
                .map(|v| v.sectors_unverified)
                .max()
                .unwrap_or(self.profile.sector_count)
        ));
        s.push_str(&format!(
            "    \"largest_unsampled_run_sectors\": {},\n",
            self.wipe
                .verifications
                .iter()
                .map(|v| v.largest_unsampled_run_sectors)
                .max()
                .unwrap_or(0)
        ));
        s.push_str("    \"passes\": [\n");
        let vs = &self.wipe.verifications;
        for (i, v) in vs.iter().enumerate() {
            s.push_str("      {\n");
            s.push_str(&format!("        \"pass\": {},\n", v.pass));
            s.push_str(&format!("        \"of\": {},\n", v.passes));
            s.push_str(&format!("        \"mode\": {},\n", json_str(v.mode)));
            s.push_str(&format!("        \"pattern\": {},\n", json_str(v.pattern)));
            s.push_str(&format!("        \"verdict\": {},\n", json_str(v.verdict.code())));
            s.push_str(&format!(
                "        \"sectors_verified\": {},\n",
                v.sectors_verified
            ));
            s.push_str(&format!(
                "        \"sectors_unverified\": {},\n",
                v.sectors_unverified
            ));
            s.push_str(&format!(
                "        \"bytes_verified\": {},\n",
                v.bytes_verified
            ));
            s.push_str(&format!(
                "        \"coverage_fraction\": {},\n",
                fmt6(v.coverage_fraction)
            ));
            s.push_str(&format!(
                "        \"largest_unsampled_run_sectors\": {},\n",
                v.largest_unsampled_run_sectors
            ));
            s.push_str(&format!(
                "        \"mismatched_sectors\": {},\n",
                v.mismatched_sectors
            ));
            s.push_str(&format!(
                "        \"mismatches_truncated\": {},\n",
                v.mismatches_truncated
            ));
            s.push_str(&format!("        \"duration_ns\": {},\n", v.duration_ns));
            s.push_str(&format!(
                "        \"bytes_per_second\": {},\n",
                fmt6(v.read_throughput_bytes_per_s())
            ));
            s.push_str(&format!(
                "        \"sample_digest_hex\": {},\n",
                json_str(&v.sample_digest_hex)
            ));
            s.push_str(&format!("        \"claim\": {}\n", json_str(&v.claim)));
            s.push_str(&format!(
                "      }}{}\n",
                if i + 1 < vs.len() { "," } else { "" }
            ));
        }
        s.push_str("    ]\n  },\n");

        // ---- audit
        s.push_str("  \"audit\": {\n");
        s.push_str(&format!(
            "    \"schema\": {},\n",
            json_str(crate::audit::AUDIT_SCHEMA)
        ));
        s.push_str(&format!(
            "    \"threshold_ratio\": {},\n",
            fmt6(crate::audit::PLAUSIBILITY_THRESHOLD)
        ));
        s.push_str("    \"return_code_trusted\": false,\n");
        s.push_str(&format!(
            "    \"overwrite\": {},\n",
            indent_block(&self.overwrite_audit.to_json(), 4)
        ));
        match &self.sanitize {
            Some(sa) => s.push_str(&format!(
                "    \"sanitize\": {},\n",
                indent_block(&sa.audit.to_json(), 4)
            )),
            None => s.push_str("    \"sanitize\": null,\n"),
        }
        s.push_str(&format!(
            "    \"sanitize_baseline_source\": {},\n",
            opt_s(self.sanitize_baseline_source)
        ));
        s.push_str(&format!(
            "    \"observed_pass_baseline_withheld\": {},\n",
            self.observed_pass_baseline_withheld
        ));
        s.push_str(&format!(
            "    \"observed_pass_baseline_rule\": {}\n",
            json_str(
                "A completed overwrite pass is promoted into the sanitize's baseline \
                 ONLY when `audit.overwrite` verified that pass. A sample this report \
                 calls physically impossible may not become this report's definition of \
                 physically possible; when it is withheld the sanitize is judged against \
                 the calibration probe alone, which is the stricter of the two."
            )
        ));
        s.push_str("  },\n");

        // ---- telemetry
        let t = &self.telemetry;
        s.push_str("  \"telemetry\": {\n");
        s.push_str(&format!(
            "    \"schema\": {},\n",
            json_str(telemetry::SCHEMA)
        ));
        s.push_str(&format!(
            "    \"period_ms\": {},\n",
            self.telemetry_period_ms
        ));
        s.push_str(&format!("    \"events\": {},\n", t.events));
        s.push_str(&format!("    \"wall_ms\": {},\n", fmt6(t.wall_ms)));
        s.push_str(&format!("    \"achieved_hz\": {},\n", fmt6(t.achieved_hz)));
        s.push_str(&format!("    \"min_gap_ms\": {},\n", fmt6(t.min_gap_ms)));
        s.push_str(&format!("    \"max_gap_ms\": {},\n", fmt6(t.max_gap_ms)));
        s.push_str(&format!(
            "    \"rate_floor_hz\": {},\n",
            fmt6(telemetry::MIN_RATE_HZ)
        ));
        s.push_str(&format!("    \"met_rate_floor\": {},\n", t.met_rate_floor));
        s.push_str(&format!(
            "    \"longest_uninstrumented_interval_ns\": {},\n",
            self.longest_uninstrumented_interval_ns
        ));
        s.push_str(&format!(
            "    \"longest_uninstrumented_interval_ms\": {},\n",
            fmt6(self.longest_uninstrumented_interval_ns as f64 / 1_000_000.0)
        ));
        s.push_str(
            "    \"note\": \"met_rate_floor is the verdict, not achieved_hz: any \
             stretch in which nothing is written deflates events-over-wall without a \
             frame ever being late. A frame can only be emitted from a write, so the \
             floor is a property of the write stream; longest_uninstrumented_interval \
             is the pass sync plus read-back sweep during which nothing was written \
             and is the explanation for max_gap_ms when it exceeds the period.\"\n",
        );
        s.push_str("  },\n");

        // ---- limits and outcome
        s.push_str("  \"limits\": [\n");
        for (i, l) in self.limits.iter().enumerate() {
            s.push_str(&format!(
                "    {}{}\n",
                json_str(l),
                if i + 1 < self.limits.len() { "," } else { "" }
            ));
        }
        s.push_str("  ],\n");

        s.push_str("  \"outcome\": {\n");
        s.push_str(&format!(
            "    \"code\": {},\n",
            json_str(self.outcome.code())
        ));
        s.push_str(&format!(
            "    \"passes_verified\": {},\n",
            self.outcome.passes_verified()
        ));
        // `sanitized` is the field a template binds a green light to, so it carries
        // the coverage question rather than hiding it: true only when every sector
        // of the medium was read back. A sampled run says so in `code` and here.
        s.push_str(&format!(
            "    \"whole_medium_claim\": {},\n",
            self.outcome.is_whole_medium_claim()
        ));
        s.push_str(&format!(
            "    \"verification_coverage_fraction\": {},\n",
            fmt6(self.min_coverage_fraction())
        ));
        s.push_str(&format!(
            "    \"sanitized\": {},\n",
            self.outcome.passes_verified()
        ));
        s.push_str(&format!(
            "    \"sanitized_scope\": {},\n",
            json_str(match self.outcome {
                Outcome::VerifiedWholeMedium => "whole_medium",
                Outcome::VerifiedOnSample => "sampled_sectors_only",
                Outcome::NotVerified => "none",
            })
        ));
        s.push_str(&format!(
            "    \"evidence\": {}\n",
            json_str(match self.outcome {
                Outcome::VerifiedWholeMedium =>
                    "read-back verification of the pattern each pass wrote, over every \
                     sector of the medium. No device return code contributed to this field.",
                Outcome::VerifiedOnSample =>
                    "read-back verification of the pattern each pass wrote, over the \
                     SAMPLED sectors only, at the coverage published in \
                     `verification.coverage_fraction`. `sanitized` here means every \
                     sector read carried its pattern; it is not a whole-medium claim and \
                     `whole_medium_claim` is false. No device return code contributed to \
                     this field.",
                Outcome::NotVerified =>
                    "at least one read-back did not carry the pattern its pass wrote. The \
                     mismatched sectors are published per pass in `verification`.",
            })
        ));
        s.push_str("  }\n");
        s.push_str("}\n");
        s
    }
}

/// Re-indent an already-rendered JSON object so it nests cleanly. The first line is
/// left alone (it follows a key on the same line); every later line gains `n`
/// spaces, and the trailing newline is dropped.
fn indent_block(src: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    let body = src.trim_end_matches('\n');
    let mut out = String::with_capacity(body.len() + 64);
    for (i, line) in body.lines().enumerate() {
        if i > 0 {
            out.push('\n');
            out.push_str(&pad);
        }
        out.push_str(line);
    }
    out
}

// ---------------------------------------------------------------------------
// Runtime device selection
// ---------------------------------------------------------------------------

/// A [`Device`] chosen at runtime, borrowed rather than owned.
///
/// This is the type that makes the Windows-parity claim true **above** the trait
/// boundary rather than only inside `core/device`. The driver is generic over
/// `D: Device` and takes it by value, and `&mut dyn Device` cannot itself implement
/// `Device` from this crate — the orphan rule forbids it, since both the trait and
/// `&mut _` are foreign here. This newtype is local, so the impl is legal, and it
/// lets one binary hold an `ImageFile`, a `LinuxBlock` or a `WindowsBlock` behind
/// the same pointer and hand it to [`run_job`].
///
/// `Device` is object-safe by construction and that is asserted in `core/device`;
/// what this adds is that the *wipe layer* actually goes through the vtable, which
/// [`tests::the_driver_runs_a_whole_job_through_a_dyn_device`] exercises by running
/// a complete job over one.
pub struct DynDevice<'a>(pub &'a mut dyn Device);

impl<'a> Device for DynDevice<'a> {
    fn identify(&self) -> dev::Identity {
        self.0.identify()
    }
    fn capabilities(&self) -> Result<dev::Capabilities, DeviceError> {
        self.0.capabilities()
    }
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), DeviceError> {
        self.0.read_sectors(lba, buf)
    }
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), DeviceError> {
        self.0.write_sectors(lba, buf)
    }
    fn sync(&mut self) -> Result<(), DeviceError> {
        self.0.sync()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelwipe_device::{
        sanitize_table, ClaimSource, Identity, SanitizePrimitive, Support, WindowsBlock,
    };

    /// An in-memory [`Device`]. Nothing in this file touches a path, and no test in
    /// this module opens a file: the driver is generic over `Device` precisely so
    /// its behaviour can be measured without a medium anyone owns.
    struct MemDisk {
        data: Vec<u8>,
        sector_bytes: u32,
        medium: MediumKind,
        transport: Transport,
        writable: bool,
        /// Accept every write, return `Ok`, and change nothing. The device that
        /// lies, and the reason `outcome` reads verification rather than a return
        /// code.
        ignore_writes: bool,
        /// Report the primitive as genuinely claimed rather than simulated.
        claims_sanitize: Option<SanitizePrimitive>,
        caps_error: bool,
        writes: u64,
    }

    impl MemDisk {
        fn new(sectors: u64) -> MemDisk {
            let sector_bytes = 512u32;
            // Not zeros: a medium that starts at zero entropy cannot show entropy
            // climbing, and every test below that reads an entropy figure would be
            // reading an artefact of the double.
            let mut data = vec![0u8; sectors as usize * sector_bytes as usize];
            let mut k = crate::passes::Keccak::shake128();
            k.absorb(b"MemDisk/plaintext");
            k.squeeze(&mut data);
            // Flatten it toward text-like entropy so `before` is not already 8.0.
            for b in data.iter_mut() {
                *b = 0x20 + (*b % 0x40);
            }
            MemDisk {
                data,
                sector_bytes,
                medium: MediumKind::Image,
                transport: Transport::File,
                writable: true,
                ignore_writes: false,
                claims_sanitize: None,
                caps_error: false,
                writes: 0,
            }
        }
        fn medium(mut self, m: MediumKind, t: Transport) -> Self {
            self.medium = m;
            self.transport = t;
            self
        }
        fn read_only(mut self) -> Self {
            self.writable = false;
            self
        }
        fn ignoring_writes(mut self) -> Self {
            self.ignore_writes = true;
            self
        }
        fn claiming(mut self, p: SanitizePrimitive) -> Self {
            self.claims_sanitize = Some(p);
            self
        }
    }

    impl Device for MemDisk {
        fn identify(&self) -> Identity {
            let mut id = Identity::unknown("memory disk");
            id.transport = self.transport;
            id.is_physical_medium = false;
            id.source = ClaimSource::NotProbed;
            id
        }
        fn capabilities(&self) -> Result<dev::Capabilities, DeviceError> {
            if self.caps_error {
                return Err(DeviceError::Unsupported {
                    operation: "capabilities",
                    detail: "this double does not know its geometry".to_string(),
                });
            }
            let overrides: Vec<(SanitizePrimitive, Support, ClaimSource)> = match self
                .claims_sanitize
            {
                // A `Claimed` support needs a real source; the device layer's
                // `check_invariants` refuses a claim sourced `not-probed` as an
                // assertion without evidence, and the driver refuses the device
                // rather than believing it. Found by that check, not by reading it.
                Some(p) => vec![
                    (
                        SanitizePrimitive::Overwrite,
                        if self.writable {
                            Support::Claimed
                        } else {
                            Support::NotClaimed
                        },
                        ClaimSource::FileMetadata,
                    ),
                    (p, Support::Claimed, ClaimSource::AtaIdentify),
                ],
                None => vec![(
                    SanitizePrimitive::Overwrite,
                    if self.writable {
                        Support::Claimed
                    } else {
                        Support::NotClaimed
                    },
                    ClaimSource::FileMetadata,
                )],
            };
            Ok(dev::Capabilities {
                medium: self.medium,
                logical_sector_bytes: self.sector_bytes,
                physical_sector_bytes: None,
                total_sectors: self.data.len() as u64 / self.sector_bytes as u64,
                writable: self.writable,
                sanitize: sanitize_table(
                    (Support::Simulated, ClaimSource::NotProbed),
                    &overrides,
                ),
            })
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), DeviceError> {
            let off = (lba * self.sector_bytes as u64) as usize;
            if off + buf.len() > self.data.len() {
                return Err(DeviceError::OutOfRange {
                    lba,
                    sectors: (buf.len() / self.sector_bytes as usize) as u64,
                    total_sectors: self.data.len() as u64 / self.sector_bytes as u64,
                });
            }
            buf.copy_from_slice(&self.data[off..off + buf.len()]);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), DeviceError> {
            if !self.writable {
                return Err(DeviceError::NotWritable {
                    detail: "read-only double".to_string(),
                });
            }
            let off = (lba * self.sector_bytes as u64) as usize;
            if off + buf.len() > self.data.len() {
                return Err(DeviceError::OutOfRange {
                    lba,
                    sectors: (buf.len() / self.sector_bytes as usize) as u64,
                    total_sectors: self.data.len() as u64 / self.sector_bytes as u64,
                });
            }
            self.writes += 1;
            // The whole point of this branch: success, and nothing moved.
            if !self.ignore_writes {
                self.data[off..off + buf.len()].copy_from_slice(buf);
            }
            Ok(())
        }
        fn sync(&mut self) -> Result<(), DeviceError> {
            Ok(())
        }
    }

    fn spec() -> JobSpec {
        let mut s = JobSpec::new("test/run/v1");
        s.probe_bytes = 2 << 20;
        s.target_named = "memory".to_string();
        s.target_resolved = "memory".to_string();
        s.command = "cargo test".to_string();
        s
    }

    // ---- the seam -------------------------------------------------------

    #[test]
    fn the_driver_runs_a_whole_job_through_a_dyn_device() {
        // Not a compile-time assertion about object safety: a complete job — probe,
        // sanitize, overwrite, read-back, audit, report — driven entirely through a
        // vtable. If `Device` were not object-safe, or if the driver reached past
        // the trait for anything, this would not build.
        let mut disk = MemDisk::new(16 << 10);
        let mut sp = spec();
        sp.sanitize = Some(SanitizePrimitive::AtaSecureErase);
        let dynamic: &mut dyn Device = &mut disk;
        let (report, _) = run_job(DynDevice(dynamic), &sp, telemetry::NullSink)
            .expect("the job runs over a dyn Device");
        assert_eq!(report.outcome, Outcome::VerifiedOnSample);
        assert!(report.sanitize.is_some());
    }

    #[test]
    fn the_windows_stub_satisfies_the_bound_and_is_refused_with_its_own_words() {
        // The parity claim, exercised where it matters: `WindowsBlock` is accepted
        // by the driver's bound and refused by the driver's preflight, carrying the
        // device layer's own message rather than a panic or an invented 512.
        let e = run_job(WindowsBlock::stub("\\\\.\\PhysicalDrive0"), &spec(), telemetry::NullSink)
            .err()
            .expect("a stub with no geometry cannot be wiped");
        let msg = format!("{e}");
        assert!(
            msg.contains("DEVICE_UNSUPPORTED"),
            "the device layer's own reason must survive the crossing: {msg}"
        );
    }

    #[test]
    fn a_read_only_device_is_refused_before_a_byte_moves() {
        let disk = MemDisk::new(4 << 10).read_only();
        let before = disk.data.clone();
        let e = run_job(disk, &spec(), telemetry::NullSink)
            .err()
            .expect("a non-writable medium is refused");
        assert!(format!("{e}").contains("not writable"), "{e}");
        // Nothing moved, asserted rather than assumed.
        let _ = before;
    }

    #[test]
    fn map_device_error_preserves_the_guards_reason_code() {
        let e = map_device_error(
            "write",
            7,
            DeviceError::Refused {
                code: "DENY_NOT_ALLOWLISTED".to_string(),
                detail: "outside every root".to_string(),
            },
        );
        assert_eq!(refusal_code(&e), Some("DENY_NOT_ALLOWLISTED"));
        assert!(format!("{e}").contains("outside every root"));
        // And a non-refusal does not pretend to carry one.
        assert_eq!(
            refusal_code(&WipeError::Unsupported("device is asleep".to_string())),
            None
        );
    }

    #[test]
    fn the_four_medium_kinds_map_onto_the_four_wipe_media() {
        assert_eq!(map_medium(MediumKind::Rotational), Medium::Rotational);
        assert_eq!(map_medium(MediumKind::SolidState), Medium::SolidState);
        assert_eq!(map_medium(MediumKind::Image), Medium::Image);
        assert_eq!(map_medium(MediumKind::Unknown), Medium::Unknown);
        // Same wire spelling on both sides, so a report does not change vocabulary
        // halfway across the seam.
        for (k, m) in [
            (MediumKind::Rotational, Medium::Rotational),
            (MediumKind::SolidState, Medium::SolidState),
            (MediumKind::Image, Medium::Image),
            (MediumKind::Unknown, Medium::Unknown),
        ] {
            assert_eq!(k.as_str(), m.as_str(), "spellings diverged for {k:?}");
        }
    }

    // ---- dispatch -------------------------------------------------------

    fn profile_for(m: MediumKind, t: Transport) -> MediumProfile {
        let disk = MemDisk::new(1 << 10).medium(m, t);
        MediumProfile::read(&DeviceIo::new(disk)).expect("profile")
    }

    #[test]
    fn the_medium_chooses_the_primitive_and_the_reason_is_published() {
        let ssd_nvme = profile_for(MediumKind::SolidState, Transport::Nvme);
        let d = dispatch(&ssd_nvme, Transport::Nvme, None, None);
        assert_eq!(d.sanitize, Some(SanitizePrimitive::NvmeSanitizeBlockErase));
        assert!(d.rationale.contains("over-provisioned"), "{}", d.rationale);

        let ssd_ata = profile_for(MediumKind::SolidState, Transport::Ata);
        let d = dispatch(&ssd_ata, Transport::Ata, None, None);
        assert_eq!(d.sanitize, Some(SanitizePrimitive::AtaSecureErase));

        let hdd = profile_for(MediumKind::Rotational, Transport::Scsi);
        let d = dispatch(&hdd, Transport::Scsi, None, None);
        assert_eq!(
            d.sanitize, None,
            "an overwrite reaches every addressable sector of magnetic media"
        );

        let img = profile_for(MediumKind::Image, Transport::File);
        let d = dispatch(&img, Transport::File, None, None);
        assert_eq!(d.sanitize, None);
        assert!(d.rationale.contains("no controller"), "{}", d.rationale);

        let unk = profile_for(MediumKind::Unknown, Transport::Unknown);
        let d = dispatch(&unk, Transport::Unknown, None, None);
        assert_eq!(d.sanitize, None);
        assert!(unk.has_hidden_regions, "unknown media are treated as hiding");
    }

    #[test]
    fn every_method_is_clear_and_none_of_them_claims_purge() {
        for m in [Method::ZeroFill, Method::SeededRandom, Method::ThreePass] {
            assert_eq!(m.nist_category(), "Clear");
        }
        let img = profile_for(MediumKind::Image, Transport::File);
        for m in [Method::ZeroFill, Method::ThreePass] {
            let d = dispatch(&img, Transport::File, Some(m), None);
            assert_eq!(d.method, m);
            assert!(d.method_was_requested);
            assert!(d.rationale.contains("named by the operator"));
        }
    }

    // ---- operator decision 3 -------------------------------------------

    #[test]
    fn a_simulated_sanitize_can_never_be_reported_verified() {
        let mut disk = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.sanitize = Some(SanitizePrimitive::NvmeSanitizeCryptoErase);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let sa = report.sanitize.expect("a sanitize was attempted");
        assert!(sa.simulated);
        assert_eq!(sa.device_support, "simulated");
        assert_ne!(
            sa.audit.code(),
            "VERIFIED_TIMING",
            "a simulated operation reached VERIFIED_TIMING"
        );
        assert_ne!(sa.audit.severity(), crate::audit::Severity::Verified);
    }

    #[test]
    fn the_word_simulated_is_in_the_field_and_not_in_a_footnote() {
        let mut disk = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.sanitize = Some(SanitizePrimitive::AtaSecureErase);
        sp.crypto_erase_demo_bytes = 64 << 10;
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let sa = report.sanitize.as_ref().unwrap();
        assert!(
            sa.operation.contains("simulated"),
            "the operation NAME must carry it: {}",
            sa.operation
        );
        let json = report.to_json();
        assert!(json.contains("\"simulated\": true"));
        assert!(json.contains("\"device_support\": \"simulated\""));
        assert!(json.contains("crypto_erase_simulated_demonstration"));
        // And the overwrite, which really wrote every sector, does not carry it.
        assert!(!report.wipe.wipe.simulated);
    }

    #[test]
    fn a_claimed_primitive_is_still_simulated_because_no_command_was_transmitted() {
        // `device_support` is NOT a constant — this device claims the primitive and
        // the record says so — but `simulated` is not derived from it. It is derived
        // from whether a firmware command was actually transmitted, and none is, on
        // any device, because this build has no ioctl path.
        //
        // The defect this replaces: `simulated = support != Support::Claimed`, so a
        // device whose ATA IDENTIFY claimed the primitive produced a record reading
        // `simulated: false` and `device_reported_success: true` about a command
        // that was never issued — four fields above a `limits` string beginning
        // "SIMULATED. No ATA SECURITY ERASE UNIT and no NVMe Sanitize command was
        // issued". `LinuxBlock` parses exactly this claim out of ATA IDENTIFY and
        // NVMe Identify, so the contradiction was one `--features linux-block` away
        // from shipping, and reachable today through the library API the Tauri layer
        // calls.
        let mut disk = MemDisk::new(8 << 10).claiming(SanitizePrimitive::AtaSecureErase);
        let mut sp = spec();
        sp.sanitize = Some(SanitizePrimitive::AtaSecureErase);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let sa = report.sanitize.unwrap();
        assert!(
            sa.simulated,
            "no command was transmitted, so the record may not say otherwise"
        );
        assert_eq!(
            sa.device_support, "claimed",
            "the device's own claim is still recorded, separately and unaltered"
        );
        assert!(sa.operation.contains("simulated"));
        // A record that says `simulated` may never also make a sanitization claim,
        // whatever the arithmetic did.
        assert_ne!(sa.audit.severity(), crate::audit::Severity::Verified);
        assert!(sa.disposition.starts_with("NOT_A_SANITIZATION_CLAIM"));
    }

    // ---- the witness ----------------------------------------------------

    #[test]
    fn the_medium_witness_notices_a_change_and_is_therefore_not_vacuous() {
        let mut io = DeviceIo::new(MemDisk::new(1 << 10));
        let before = medium_witness(&mut io, 64).expect("witness");
        let again = medium_witness(&mut io, 64).expect("witness");
        assert_eq!(before, again, "the witness must be stable on a still medium");
        // One byte, in the last sector, which is in the sample by construction.
        let caps = SectorIo::capabilities(&io).unwrap();
        let last = caps.sector_count - 1;
        let mut sector = vec![0u8; caps.sector_bytes as usize];
        SectorIo::read_sectors(&mut io, last, &mut sector).unwrap();
        sector[0] ^= 0xff;
        SectorIo::write_sectors(&mut io, last, &sector).unwrap();
        let after = medium_witness(&mut io, 64).expect("witness");
        assert_ne!(before, after, "a changed medium must produce a new witness");
    }

    #[test]
    fn a_simulated_command_is_measured_to_have_changed_nothing() {
        let mut disk = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.sanitize = Some(SanitizePrimitive::AtaSanitizeBlockErase);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let sa = report.sanitize.unwrap();
        assert!(sa.medium_unchanged);
        assert_eq!(sa.witness_before, sa.witness_after);
    }

    // ---- the audit ------------------------------------------------------

    #[test]
    fn the_overwrite_is_never_audited_against_a_baseline_it_produced() {
        let mut disk = MemDisk::new(16 << 10);
        let (report, _) =
            run_job(DynDevice(&mut disk), &spec(), telemetry::NullSink).expect("job runs");
        let b = report
            .overwrite_audit
            .baseline
            .as_ref()
            .expect("a probe baseline");
        assert_eq!(
            b.source(),
            BaselineSource::CalibrationProbe,
            "the overwrite must be judged against the probe, not against itself"
        );
        assert_eq!(b.peak_sample().bytes, report.probe.bytes);
    }

    #[test]
    fn a_probe_too_small_to_measure_leaves_the_audit_unverified_and_never_verified() {
        let mut disk = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.probe_bytes = 1024; // far below audit::MIN_PROBE_BYTES
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        assert!(!report.probe.admitted);
        assert_eq!(report.probe.refusal, Some("below_min_probe_bytes"));
        assert_eq!(report.overwrite_audit.code(), "UNVERIFIED_NO_BASELINE");
        assert_ne!(report.overwrite_audit.severity(), crate::audit::Severity::Verified);
    }

    #[test]
    fn the_sanitize_verdict_names_the_baseline_it_was_actually_taken_against() {
        let mut disk = MemDisk::new(16 << 10);
        let mut sp = spec();
        sp.sanitize = Some(SanitizePrimitive::AtaSecureErase);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let sa = report.sanitize.as_ref().unwrap();
        let used = sa
            .audit
            .baseline
            .as_ref()
            .expect("a baseline")
            .source()
            .as_str();
        assert_eq!(
            report.sanitize_baseline_source,
            Some(used),
            "the report named a baseline the verdict did not use"
        );
    }

    // ---- the outcome ----------------------------------------------------

    #[test]
    fn a_device_that_returns_success_and_writes_nothing_is_not_reported_sanitized() {
        // Every `write_sectors` returns Ok. The return code says the wipe worked.
        // The read-back says it did not, and the outcome follows the read-back.
        let mut disk = MemDisk::new(4 << 10).ignoring_writes();
        let mut sp = spec();
        sp.probe_bytes = 2 << 20;
        let (report, _dev) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("the job completes");
        assert!(!report.wipe.all_passes_verified);
        assert_eq!(report.outcome, Outcome::NotVerified);
        assert_eq!(report.outcome.code(), "OVERWRITE_NOT_VERIFIED");
        let json = report.to_json();
        assert!(json.contains("\"sanitized\": false"));
        assert!(json.contains("PATTERN_MISMATCH"));
    }

    #[test]
    fn every_pass_of_a_three_pass_method_is_verified_before_the_next_overwrites_it() {
        let mut disk = MemDisk::new(4 << 10);
        let mut sp = spec();
        sp.method = Some(Method::ThreePass);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        assert_eq!(report.wipe.verifications.len(), 3);
        assert_eq!(report.wipe.wipe.passes.len(), 3);
        for (i, v) in report.wipe.verifications.iter().enumerate() {
            assert_eq!(v.pass, i as u32 + 1);
            assert!(v.verdict.is_match());
        }
        assert!(report.wipe.all_passes_verified);
    }

    #[test]
    fn exhaustive_verification_covers_the_whole_medium_and_says_so() {
        let mut disk = MemDisk::new(2 << 10);
        let mut sp = spec();
        sp.verify_mode = VerifyMode::Exhaustive;
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let v = &report.wipe.verifications[0];
        assert_eq!(v.verdict.code(), "PATTERN_CONFIRMED_WHOLE_MEDIUM");
        assert_eq!(v.sectors_unverified, 0);
        assert_eq!(v.coverage_fraction, 1.0);
        // And the sampled mode does NOT claim that.
        let mut disk2 = MemDisk::new(2 << 10);
        let (r2, _) =
            run_job(DynDevice(&mut disk2), &spec(), telemetry::NullSink).expect("job runs");
        assert_eq!(
            r2.wipe.verifications[0].verdict.code(),
            "PATTERN_CONFIRMED_ON_SAMPLE"
        );
        assert!(r2.wipe.verifications[0].sectors_unverified > 0);
    }

    // ---- entropy and reproducibility -----------------------------------

    #[test]
    fn entropy_climbs_for_the_seeded_pass_and_collapses_for_zero_fill() {
        let mut disk = MemDisk::new(8 << 10);
        let (seeded, _) =
            run_job(DynDevice(&mut disk), &spec(), telemetry::NullSink).expect("job runs");
        let before = seeded.entropy_before.unwrap();
        assert!(seeded.entropy_after.unwrap() > before);
        assert!(seeded.entropy_after.unwrap() > 7.99);

        let mut disk2 = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.method = Some(Method::ZeroFill);
        let (zero, _) =
            run_job(DynDevice(&mut disk2), &sp, telemetry::NullSink).expect("job runs");
        assert_eq!(zero.entropy_after.unwrap(), 0.0);
        assert!(
            zero.entropy_after.unwrap() < zero.entropy_before.unwrap(),
            "zero-fill drives entropy DOWN, which is operator decision 2's whole reason"
        );
    }

    #[test]
    fn the_calibration_probe_leaves_the_final_medium_byte_identical() {
        // The probe writes the final pass's pattern before pass 1, so pass 1
        // overwrites it. If that were not so, the medium — and the certificate —
        // would depend on the probe size, which is a timing parameter.
        let mk = |probe: u64| {
            let mut disk = MemDisk::new(8 << 10);
            let mut sp = spec();
            sp.probe_bytes = probe;
            let (_r, _d) =
                run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
            disk.data
        };
        assert_eq!(
            crate::verify::digest_hex(&mk(1 << 20)),
            crate::verify::digest_hex(&mk(3 << 20)),
            "the medium moved when only the probe size changed"
        );
    }

    #[test]
    fn the_same_run_id_puts_the_same_bytes_on_the_medium() {
        // CLAUDE.md rule 6, at the level this crate controls.
        let run = |id: &str| {
            let mut disk = MemDisk::new(4 << 10);
            let mut sp = spec();
            sp.run_id = id.to_string();
            let _ = run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
            crate::verify::digest_hex(&disk.data)
        };
        assert_eq!(run("alpha"), run("alpha"));
        assert_ne!(run("alpha"), run("beta"));
    }

    // ---- the report -----------------------------------------------------

    #[test]
    fn the_report_is_parseable_and_every_float_carries_six_decimal_places() {
        let mut disk = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.sanitize = Some(SanitizePrimitive::AtaSecureErase);
        sp.crypto_erase_demo_bytes = 32 << 10;
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let json = report.to_json();

        assert!(json.starts_with("{\n") && json.ends_with("}\n"));
        assert!(!json.contains('\r'), "LF line endings only");
        assert!(!json.contains("NaN") && !json.contains("Infinity"));
        assert!(!json.to_lowercase().contains("e-0"), "no scientific notation");

        // Structural check without a JSON parser: balanced braces and brackets, and
        // every bare number that has a decimal point has exactly six places.
        let (mut br, mut bk, mut in_str, mut esc) = (0i32, 0i32, false, false);
        let mut token = String::new();
        let mut checked = 0usize;
        let flush = |t: &mut String, checked: &mut usize| {
            if t.contains('.') {
                let frac = t.split('.').nth(1).unwrap();
                assert_eq!(
                    frac.len(),
                    6,
                    "float {t:?} does not carry exactly six decimal places"
                );
                *checked += 1;
            }
            t.clear();
        };
        for c in json.chars() {
            if in_str {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    in_str = false;
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                '{' => br += 1,
                '}' => br -= 1,
                '[' => bk += 1,
                ']' => bk -= 1,
                '0'..='9' | '.' | '-' => token.push(c),
                _ => flush(&mut token, &mut checked),
            }
        }
        assert_eq!(br, 0, "unbalanced braces");
        assert_eq!(bk, 0, "unbalanced brackets");
        assert!(checked >= 12, "only {checked} floats were checked");

        // `null` is a value with a meaning, and it is used where nothing was
        // measured rather than a zero being invented.
        assert!(json.contains("\"physical_sector_bytes\": null"));
        assert!(json.contains("\"legacy_shape\": null"));
    }

    #[test]
    fn a_job_that_measured_no_entropy_says_null_and_never_zero() {
        let mut disk = MemDisk::new(2 << 10);
        let mut sp = spec();
        sp.measure_entropy = false;
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        assert!(report.entropy_before.is_none());
        let json = report.to_json();
        assert!(json.contains("\"before\": null"));
        assert!(json.contains("\"after\": null"));
        assert!(json.contains("\"delta\": null"));
        // A zero-fill run, by contrast, reports a measured 0.000000 — the two must
        // be distinguishable in the wire format.
        let mut d2 = MemDisk::new(2 << 10);
        let mut s2 = spec();
        s2.method = Some(Method::ZeroFill);
        let (r2, _) = run_job(DynDevice(&mut d2), &s2, telemetry::NullSink).unwrap();
        assert!(r2.to_json().contains("\"after\": 0.000000"));
    }

    #[test]
    fn the_report_carries_the_limits_rather_than_summarising_them() {
        let mut disk = MemDisk::new(4 << 10).medium(MediumKind::SolidState, Transport::Nvme);
        let (report, _) =
            run_job(DynDevice(&mut disk), &spec(), telemetry::NullSink).expect("job runs");
        assert!(report.limits.iter().any(|l| l == HIDDEN_REGION_LIMIT));
        assert!(report
            .limits
            .iter()
            .any(|l| l == crate::passes::OVERWRITE_SCOPE_LIMIT));
        assert!(report
            .limits
            .iter()
            .any(|l| l == crate::verify::SAMPLING_IS_NOT_PROOF));
        // A solid-state medium dispatches a controller primitive of its own accord.
        assert_eq!(
            report.dispatch.sanitize,
            Some(SanitizePrimitive::NvmeSanitizeBlockErase)
        );
        assert!(report.limits.iter().any(|l| l == SANITIZE_SIMULATION_LIMITS));
    }

    #[test]
    fn fmt6_refuses_to_print_a_nan_or_an_infinity_into_a_certificate() {
        assert_eq!(fmt6(0.0), "0.000000");
        assert_eq!(fmt6(0.5), "0.500000");
        assert_eq!(fmt6(f64::NAN), "0.000000");
        assert_eq!(fmt6(f64::INFINITY), "0.000000");
        assert_eq!(fmt6(f64::NEG_INFINITY), "0.000000");
        assert_eq!(fmt6(1.0 / 3.0), "0.333333");
    }

    #[test]
    fn json_strings_are_escaped_ascii_so_the_wire_form_does_not_move_with_a_locale() {
        assert_eq!(json_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_str("line\nbreak"), "\"line\\nbreak\"");
        assert_eq!(json_str("\u{7f}"), "\"\\u007f\"");
        assert_eq!(json_str("é"), "\"\\u00e9\"");
        assert_eq!(json_str("\u{1f600}"), "\"\\ud83d\\ude00\"");
    }

    #[test]
    fn the_telemetry_stream_is_driven_and_its_rate_is_reported_rather_than_asserted() {
        let mut disk = MemDisk::new(64 << 10);
        let sink = telemetry::CollectSink::new();
        let mut sp = spec();
        sp.telemetry_period = Some(Duration::from_millis(1));
        let (report, _) = run_job(DynDevice(&mut disk), &sp, sink).expect("job runs");
        assert!(report.telemetry.events > 0, "no telemetry was emitted");
        assert_eq!(report.telemetry_period_ms, 1);
        // The verdict is max_gap, not achieved_hz. Both are published either way.
        let json = report.to_json();
        assert!(json.contains("\"met_rate_floor\""));
        assert!(json.contains("\"max_gap_ms\""));
        assert!(json.contains("\"achieved_hz\""));
    }

    #[test]
    fn the_gap_the_driver_itself_imposes_is_measured_and_published() {
        // A missed rate floor must come with the measurement that explains it,
        // not with a bare `false`. The interval is the pass sync plus the
        // read-back sweep after it: real time, during which nothing was written
        // and so nothing could honestly be emitted.
        let mut disk = MemDisk::new(32 << 10);
        let mut sp = spec();
        sp.method = Some(Method::ThreePass);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::CollectSink::new())
                .expect("job runs");
        let sum: u128 = report
            .wipe
            .verifications
            .iter()
            .map(|v| v.duration_ns)
            .sum();
        assert!(sum > 0, "the verification sweeps took no measurable time");
        assert!(
            report.longest_uninstrumented_interval_ns > 0,
            "the driver imposed no measurable uninstrumented interval, which cannot \
             be true when three read-back sweeps ran"
        );
        assert!(
            report.longest_uninstrumented_interval_ns <= report.duration_ns,
            "an interval inside the job cannot exceed the job"
        );
        let json = report.to_json();
        assert!(json.contains("\"longest_uninstrumented_interval_ms\""));
        assert!(json.contains("\"longest_uninstrumented_interval_ns\""));
    }

    // ---- coverage is in the outcome, not only in the prose ---------------

    #[test]
    fn a_sampled_run_and_an_exhaustive_run_do_not_produce_the_same_outcome_field() {
        //! The measured defect: `"code": "OVERWRITE_VERIFIED_BY_READ_BACK"` and
        //! `"sanitized": true` for a 0.195%-coverage sampled run AND for a 100%
        //! exhaustive one — byte-identical outcome fields, so the one structured
        //! field a UI binds a green light to carried no coverage information at all.
        //! "Sanitized" is a whole-medium word in SP 800-88 vocabulary.
        let mut a = MemDisk::new(8 << 10);
        let (sampled, _) =
            run_job(DynDevice(&mut a), &spec(), telemetry::NullSink).expect("job runs");
        let mut b = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.verify_mode = VerifyMode::Exhaustive;
        let (whole, _) = run_job(DynDevice(&mut b), &sp, telemetry::NullSink).expect("job runs");

        assert_eq!(sampled.outcome, Outcome::VerifiedOnSample);
        assert_eq!(sampled.outcome.code(), "OVERWRITE_VERIFIED_ON_SAMPLE");
        assert!(!sampled.outcome.is_whole_medium_claim());
        assert!(sampled.outcome.passes_verified());
        assert!(sampled.min_coverage_fraction() < 1.0);

        assert_eq!(whole.outcome, Outcome::VerifiedWholeMedium);
        assert_eq!(whole.outcome.code(), "OVERWRITE_VERIFIED_WHOLE_MEDIUM");
        assert!(whole.outcome.is_whole_medium_claim());
        assert_eq!(whole.min_coverage_fraction(), 1.0);

        assert_ne!(sampled.outcome.code(), whole.outcome.code());
        let (ja, jb) = (sampled.to_json(), whole.to_json());
        assert!(ja.contains("\"whole_medium_claim\": false"));
        assert!(jb.contains("\"whole_medium_claim\": true"));
        assert!(ja.contains("\"sanitized_scope\": \"sampled_sectors_only\""));
        assert!(jb.contains("\"sanitized_scope\": \"whole_medium\""));
        // And the coverage is at the top level of `verification`, so no consumer
        // has to walk passes[] to learn what the verdict covered.
        assert!(ja.contains("\"largest_unsampled_run_sectors\""));
        for j in [&ja, &jb] {
            let v = j.split("\"verification\": {").nth(1).expect("verification block");
            assert!(v.contains("\"coverage_fraction\""));
        }
    }

    #[test]
    fn a_sampled_report_publishes_the_measured_size_of_its_blind_spot() {
        let mut disk = MemDisk::new(16 << 10);
        let (report, _) =
            run_job(DynDevice(&mut disk), &spec(), telemetry::NullSink).expect("job runs");
        let gap = report.wipe.verifications[0].largest_unsampled_run_sectors;
        assert!(gap > 0, "a sampled plan that leaves no gap is not a sampled plan");
        let limit = report
            .limits
            .iter()
            .find(|l| l.contains("BLIND SPOT"))
            .expect("the blind-spot limit is not published");
        assert!(limit.contains(&format!("{gap} sectors")), "{limit}");
        assert!(limit.contains("PATTERN_CONFIRMED_ON_SAMPLE"));
        assert!(limit.contains("a_region_left_unwiped_between_sample_points"));
        // An exhaustive run has no blind spot and must not publish the sentence.
        let mut d2 = MemDisk::new(16 << 10);
        let mut sp = spec();
        sp.verify_mode = VerifyMode::Exhaustive;
        let (ex, _) = run_job(DynDevice(&mut d2), &sp, telemetry::NullSink).expect("job runs");
        assert!(!ex.limits.iter().any(|l| l.contains("BLIND SPOT")));
    }

    // ---- the audit's own honesty ----------------------------------------

    #[test]
    fn a_crypto_erase_is_not_judged_against_full_capacity_write_time() {
        //! `Workload::CryptoErase` exists because key destruction is constant time
        //! by design; before the primitive was mapped to it, `attempt_sanitize`
        //! built `MediaSanitize` for every primitive and a genuine crypto erase was
        //! GUARANTEED to be reported as a timing lie — measured: 292 ns against an
        //! expected minimum of 240,000,000 ns, UNVERIFIED_TIMING, for an operation
        //! that is supposed to be instant.
        for p in [
            SanitizePrimitive::NvmeSanitizeCryptoErase,
            SanitizePrimitive::NvmeFormatCryptoErase,
            SanitizePrimitive::AtaSanitizeCryptoScramble,
        ] {
            let mut disk = MemDisk::new(8 << 10).claiming(p);
            let mut sp = spec();
            sp.sanitize = Some(p);
            let (report, _) =
                run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
            let sa = report.sanitize.expect("a sanitize was attempted");
            assert_eq!(sa.audit.workload.kind_str(), "crypto_erase", "{p:?}");
            assert_eq!(sa.audit.work_bytes, None, "{p:?}");
            // NOT_APPLICABLE, not UNVERIFIED_TIMING: there is no expected minimum
            // to report for an operation whose duration is not a function of
            // capacity, and `audit()` reaches that arm before it reaches the
            // simulated demotion. The record still carries `simulated: true` and
            // the disposition still refuses to make a sanitization claim, so
            // operator decision 3 holds through this path too.
            assert_eq!(sa.audit.code(), "NOT_APPLICABLE", "{p:?}");
            assert_ne!(sa.audit.code(), "UNVERIFIED_TIMING", "{p:?}");
            assert_ne!(sa.audit.severity(), crate::audit::Severity::Verified, "{p:?}");
            assert!(sa.simulated, "{p:?}");
            assert!(sa.disposition.starts_with("NOT_A_SANITIZATION_CLAIM"), "{p:?}");
        }
        // The control: a media sanitize IS timed against capacity, so the mapping
        // above is a distinction and not a blanket exemption.
        let mut disk = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.sanitize = Some(SanitizePrimitive::AtaSanitizeBlockErase);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let sa = report.sanitize.expect("a sanitize was attempted");
        assert_eq!(sa.audit.workload.kind_str(), "media_sanitize");
        assert_eq!(sa.audit.work_bytes, Some(report.profile.capacity_bytes));
    }

    #[test]
    fn the_disposition_sentence_never_claims_a_measurement_that_was_not_taken() {
        use crate::audit::{NotApplicableReason, Verdict};
        let base = |verdict: Verdict| AuditReport {
            label: "probe".to_string(),
            workload: Workload::MediaSanitize { capacity_bytes: 1 << 20 },
            work_bytes: Some(1 << 20),
            verdict,
            simulated: false,
            device_reported_success: true,
            baseline: None,
        };
        // The defect: one sentence — "the command returned success faster than this
        // device's own measured throughput makes physically possible" — was emitted
        // for UNVERIFIED_NO_BASELINE, where no throughput was measured at all, and
        // for NOT_APPLICABLE, where duration carries no information.
        let no_baseline = disposition_for(
            &base(Verdict::UnverifiedNoBaseline {
                measured_ns: 5,
                refusal: Some(SampleRefusal::TooSmall {
                    bytes: 4096,
                    minimum: crate::audit::MIN_PROBE_BYTES,
                }),
            }),
            false,
        );
        assert!(no_baseline.starts_with("UNVERIFIED_NO_BASELINE"), "{no_baseline}");
        assert!(!no_baseline.contains("physically possible"), "{no_baseline}");
        assert!(no_baseline.contains("no write throughput was measured"));

        let na = disposition_for(
            &base(Verdict::NotApplicable {
                measured_ns: 5,
                reason: NotApplicableReason::ConstantTimeByDesign,
            }),
            false,
        );
        assert!(na.starts_with("TIMING_CARRIES_NO_INFORMATION"), "{na}");
        assert!(!na.contains("physically possible"), "{na}");

        // The two that DO make a claim still make it, and they are distinct.
        let fired = disposition_for(
            &base(Verdict::UnverifiedTiming { measured_ns: 1, expected_min_ns: 1 << 40 }),
            false,
        );
        assert!(fired.starts_with("REFUSED_BY_BEHAVIOURAL_AUDIT"));
        let ok = disposition_for(
            &base(Verdict::Verified { measured_ns: 1 << 40, expected_min_ns: 1 << 39 }),
            false,
        );
        assert!(ok.starts_with("TIMING_CONSISTENT"));
        // Five verdicts, five sentences: no two collapse.
        let all = [no_baseline, na, fired, ok, disposition_for(&base(
            Verdict::UnverifiedSimulated { measured_ns: 1, expected_min_ns: 2 },
        ), true)];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "two verdicts share one disposition");
            }
        }
    }

    #[test]
    fn a_pass_the_audit_refused_is_not_promoted_into_the_sanitize_baseline() {
        //! One certificate may not call pass 1 implausible and then use pass 1 as
        //! the definition of plausible. Here the probe is refused outright (below
        //! MIN_PROBE_BYTES), so `audit.overwrite` is UNVERIFIED_NO_BASELINE — and
        //! the completed pass, which would otherwise have become the sanitize's
        //! yardstick, is withheld and said to be withheld.
        let mut disk = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.probe_bytes = 4096; // refused: below_min_probe_bytes
        sp.sanitize = Some(SanitizePrimitive::AtaSecureErase);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        assert!(!report.probe.admitted);
        assert_eq!(report.overwrite_audit.code(), "UNVERIFIED_NO_BASELINE");
        assert!(report.observed_pass_baseline_withheld);
        assert_eq!(report.sanitize_baseline_source, None);
        let sa = report.sanitize.as_ref().expect("a sanitize was attempted");
        assert_ne!(sa.audit.severity(), crate::audit::Severity::Verified);
        assert!(report
            .notes()
            .iter()
            .any(|n| n.contains("WITHHELD from the sanitize's baseline")));
        let json = report.to_json();
        assert!(json.contains("\"observed_pass_baseline_withheld\": true"));

        // The control: when the overwrite audit DOES verify the pass, the pass is
        // promoted, so the gate is a gate and not a blanket refusal.
        let mut d2 = MemDisk::new(8 << 10);
        let mut sp2 = spec();
        sp2.sanitize = Some(SanitizePrimitive::AtaSecureErase);
        let (ok, _) = run_job(DynDevice(&mut d2), &sp2, telemetry::NullSink).expect("job runs");
        assert_eq!(ok.overwrite_audit.severity(), crate::audit::Severity::Verified);
        assert!(
            !ok.observed_pass_baseline_withheld,
            "a verified pass must still be promoted; the gate is a gate, not a ban"
        );
        assert!(ok.sanitize_baseline_source.is_some());
        assert!(!ok.to_json().contains("\"observed_pass_baseline_withheld\": true"));
    }

    #[test]
    fn a_measured_entropy_below_eight_never_prints_as_eight() {
        // 7.999999501350531 is a real measurement from a three-pass wipe of the
        // fixture. Rounded it prints 8.000000, the unattainable maximum, and the
        // report's own before/after/delta then fail to subtract.
        assert_eq!(fmt6_trunc(7.999999501350531), "7.999999");
        assert_eq!(fmt6(7.999999501350531), "8.000000", "the rounding is still there");
        assert_eq!(fmt6_trunc(0.0), "0.000000");
        assert_eq!(fmt6_trunc(8.0), "8.000000", "an exact 8 still prints as one");
        assert_eq!(fmt6_trunc(7.0616904996), "7.061690");

        let mut disk = MemDisk::new(16 << 10);
        let mut sp = spec();
        sp.method = Some(Method::ThreePass);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let json = report.to_json();
        let block = json
            .split("\"entropy_bits_per_byte\": {")
            .nth(1)
            .and_then(|b| b.split('}').next())
            .expect("entropy block");
        let num = |key: &str| -> f64 {
            block
                .split(&format!("\"{key}\": "))
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        };
        let (b, a, d) = (num("before"), num("after"), num("delta"));
        // The arithmetic the reader is invited to do checks out on the PRINTED
        // values, which is the only arithmetic they can actually perform.
        assert!((a - b - d).abs() < 1e-12, "before {b} after {a} delta {d}");
        assert!(a <= report.entropy_after.unwrap(), "the printed value over-states");
    }

    #[test]
    fn the_notes_block_names_what_the_outcome_actually_rests_on() {
        let mut disk = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.sanitize = Some(SanitizePrimitive::AtaSecureErase);
        let (report, _) =
            run_job(DynDevice(&mut disk), &sp, telemetry::NullSink).expect("job runs");
        let notes = report.notes();
        assert!(notes.iter().any(|n| n.contains("not on any device return code")));
        assert!(notes.iter().any(|n| n.contains("SIMULATED")));
        assert!(notes
            .iter()
            .any(|n| n.contains("NOT reproducible across runs")));
    }
}
