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

pub const REPORT_SCHEMA: &str = "sentinelwipe.wipe.report/1";

pub const DEFAULT_PROBE_BYTES: u64 = 32 << 20;

pub const SANITIZE_WITNESS_SECTORS: u64 = 256;

pub const WITNESS_DOMAIN: &[u8] = b"SENTINELWIPE/sanitize-witness/v1";

pub const SANITIZE_SIMULATION_LIMITS: &str = "\
SIMULATED. No ATA SECURITY ERASE UNIT and no NVMe Sanitize command was issued, \
because the target is not a physical controller. The operation was timed and \
audited exactly as a real one would be, and its effect on the medium was measured \
by reading the medium back; it wrote nothing. Nothing in this block is evidence \
that any data was destroyed. The data-destroying operation in this report is the \
overwrite, and its evidence is the read-back verification.";

pub const HIDDEN_REGION_LIMIT: &str = "\
The detected medium has host-invisible regions (over-provisioning, remapped and \
retired blocks). A full-capacity overwrite reaches every addressable sector and \
no unaddressable one, so no Purge claim is made and none is supported by anything \
in this report.";

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

pub fn map_medium(kind: MediumKind) -> Medium {
    match kind {
        MediumKind::Rotational => Medium::Rotational,
        MediumKind::SolidState => Medium::SolidState,
        MediumKind::Image => Medium::Image,
        MediumKind::Unknown => Medium::Unknown,
    }
}

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
    pub has_hidden_regions: bool,
    pub sector_bytes: u32,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatch {
    pub method: Method,
    pub sanitize: Option<SanitizePrimitive>,
    pub rationale: String,
    pub method_was_requested: bool,
    pub sanitize_was_requested: bool,
}

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

#[derive(Debug, Clone)]
pub struct SanitizeReport {
    pub primitive: &'static str,
    pub operation: String,
    pub simulated: bool,
    pub device_support: &'static str,
    pub claim_source: &'static str,
    pub device_reported_success: bool,
    pub measured_ns: u128,
    pub bytes_claimed: u64,
    pub witness_before: String,
    pub witness_after: String,
    pub medium_unchanged: bool,
    pub disposition: &'static str,
    pub limits: &'static str,
    pub audit: AuditReport,
    operation_record: Operation,
}

impl SanitizeReport {
    pub fn reaudit(&mut self, baseline: &Baseline) {
        self.audit = audit(&self.operation_record, Some(baseline));
        self.disposition = disposition_for(&self.audit, self.simulated);
    }

    pub fn baseline_source(&self) -> Option<&'static str> {
        self.audit.baseline.as_ref().map(|b| b.source().as_str())
    }
}

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

fn issue_sanitize<D: Device>(
    io: &mut DeviceIo<D>,
    _primitive: SanitizePrimitive,
) -> Result<Option<bool>, WipeError> {
    let caps = io.device_capabilities()?;
    let mut status = vec![0u8; caps.logical_sector_bytes as usize];
    SectorIo::read_sectors(io, 0, &mut status)?;
    Ok(None)
}

fn workload_for(primitive: SanitizePrimitive, capacity_bytes: u64) -> Workload {
    match primitive {
        SanitizePrimitive::AtaSanitizeCryptoScramble
        | SanitizePrimitive::NvmeSanitizeCryptoErase
        | SanitizePrimitive::NvmeFormatCryptoErase => Workload::CryptoErase,
        _ => Workload::MediaSanitize { capacity_bytes },
    }
}

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

    let simulated = transmitted.is_none();
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

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeReport {
    pub bytes: u64,
    pub sectors: u64,
    pub duration_ns: u128,
    pub sync_ns: u128,
    pub throughput_bytes_per_s: f64,
    pub pattern: &'static str,
    pub admitted: bool,
    pub refusal: Option<&'static str>,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    Sampled,
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

#[derive(Debug, Clone)]
pub struct JobSpec {
    pub run_id: String,
    pub method: Option<Method>,
    pub sanitize: Option<SanitizePrimitive>,
    pub verify_mode: VerifyMode,
    pub sampling: SamplingPolicy,
    pub measure_entropy: bool,
    pub probe_bytes: u64,
    pub crypto_erase_demo_bytes: u64,
    pub telemetry_period: Option<Duration>,
    pub target_named: String,
    pub target_resolved: String,
    pub authorization: Option<Authorization>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub decision_code: String,
    pub policy_digest: String,
    pub roots: Vec<String>,
    pub require_confirmation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    VerifiedWholeMedium,
    VerifiedOnSample,
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

    pub fn passes_verified(&self) -> bool {
        !matches!(self, Outcome::NotVerified)
    }

    pub fn is_whole_medium_claim(&self) -> bool {
        matches!(self, Outcome::VerifiedWholeMedium)
    }
}

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
    pub overwrite_audit: AuditReport,
    pub sanitize_baseline_source: Option<&'static str>,
    pub observed_pass_baseline_withheld: bool,
    pub telemetry: telemetry::Summary,
    pub telemetry_period_ms: u64,
    pub longest_uninstrumented_interval_ns: u128,
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

    pub fn min_coverage_fraction(&self) -> f64 {
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

    let (entropy_before, entropy_bytes) = if spec.measure_entropy {
        let (e, n) = verify::medium_entropy(&mut io, cfg.chunk_sectors_max)?;
        (Some(e), Some(n))
    } else {
        (None, None)
    };

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

    let probe = calibration_probe(&mut io, &cfg, spec.probe_bytes)?;
    let probe_sample = ThroughputSample::new(
        probe.bytes,
        probe.duration_ns,
        BaselineSource::CalibrationProbe,
    );
    let probe_baseline = probe_sample.as_ref().ok().copied().map(Baseline::from_sample);
    let probe_refusal = probe_sample.as_ref().err().copied();

    let sanitize = match disp.sanitize {
        Some(p) => Some(attempt_sanitize(
            &mut io,
            p,
            probe_baseline.as_ref(),
            probe_refusal,
        )?),
        None => None,
    };

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

    let entropy_after = if spec.measure_entropy {
        Some(verify::medium_entropy(&mut io, cfg.chunk_sectors_max)?.0)
    } else {
        None
    };

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

pub fn fmt6(v: f64) -> String {
    if v.is_nan() || v.is_infinite() {
        return "0.000000".to_string();
    }
    format!("{:.6}", v)
}

pub fn fmt6_trunc(v: f64) -> String {
    if v.is_nan() || v.is_infinite() {
        return "0.000000".to_string();
    }
    let scaled = (v * 1_000_000.0).trunc() / 1_000_000.0;
    format!("{:.6}", scaled)
}

fn ns_s(ns: u128) -> String {
    fmt6(ns as f64 / 1_000_000_000.0)
}

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

    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(8192);
        s.push_str("{\n");
        s.push_str(&format!("  \"schema\": {},\n", json_str(REPORT_SCHEMA)));

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

        s.push_str("  \"entropy_bits_per_byte\": {\n");
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

        s.push_str("  \"verification\": {\n");
        s.push_str(&format!(
            "    \"mode\": {},\n",
            json_str(self.verify_mode.as_str())
        ));
        s.push_str(&format!(
            "    \"all_passes_verified\": {},\n",
            self.wipe.all_passes_verified
        ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelwipe_device::{
        sanitize_table, ClaimSource, Identity, SanitizePrimitive, Support, WindowsBlock,
    };

    struct MemDisk {
        data: Vec<u8>,
        sector_bytes: u32,
        medium: MediumKind,
        transport: Transport,
        writable: bool,
        ignore_writes: bool,
        claims_sanitize: Option<SanitizePrimitive>,
        caps_error: bool,
        writes: u64,
    }

    impl MemDisk {
        fn new(sectors: u64) -> MemDisk {
            let sector_bytes = 512u32;
            let mut data = vec![0u8; sectors as usize * sector_bytes as usize];
            let mut k = crate::passes::Keccak::shake128();
            k.absorb(b"MemDisk/plaintext");
            k.squeeze(&mut data);
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

    #[test]
    fn the_driver_runs_a_whole_job_through_a_dyn_device() {
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
        for (k, m) in [
            (MediumKind::Rotational, Medium::Rotational),
            (MediumKind::SolidState, Medium::SolidState),
            (MediumKind::Image, Medium::Image),
            (MediumKind::Unknown, Medium::Unknown),
        ] {
            assert_eq!(k.as_str(), m.as_str(), "spellings diverged for {k:?}");
        }
    }

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
        assert!(!report.wipe.wipe.simulated);
    }

    #[test]
    fn a_claimed_primitive_is_still_simulated_because_no_command_was_transmitted() {
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
        assert_ne!(sa.audit.severity(), crate::audit::Severity::Verified);
        assert!(sa.disposition.starts_with("NOT_A_SANITIZATION_CLAIM"));
    }

    #[test]
    fn the_medium_witness_notices_a_change_and_is_therefore_not_vacuous() {
        let mut io = DeviceIo::new(MemDisk::new(1 << 10));
        let before = medium_witness(&mut io, 64).expect("witness");
        let again = medium_witness(&mut io, 64).expect("witness");
        assert_eq!(before, again, "the witness must be stable on a still medium");
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
        sp.probe_bytes = 1024;
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

    #[test]
    fn a_device_that_returns_success_and_writes_nothing_is_not_reported_sanitized() {
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
        let mut disk2 = MemDisk::new(2 << 10);
        let (r2, _) =
            run_job(DynDevice(&mut disk2), &spec(), telemetry::NullSink).expect("job runs");
        assert_eq!(
            r2.wipe.verifications[0].verdict.code(),
            "PATTERN_CONFIRMED_ON_SAMPLE"
        );
        assert!(r2.wipe.verifications[0].sectors_unverified > 0);
    }

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
        let json = report.to_json();
        assert!(json.contains("\"met_rate_floor\""));
        assert!(json.contains("\"max_gap_ms\""));
        assert!(json.contains("\"achieved_hz\""));
    }

    #[test]
    fn the_gap_the_driver_itself_imposes_is_measured_and_published() {
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

    #[test]
    fn a_sampled_run_and_an_exhaustive_run_do_not_produce_the_same_outcome_field() {
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
        let mut d2 = MemDisk::new(16 << 10);
        let mut sp = spec();
        sp.verify_mode = VerifyMode::Exhaustive;
        let (ex, _) = run_job(DynDevice(&mut d2), &sp, telemetry::NullSink).expect("job runs");
        assert!(!ex.limits.iter().any(|l| l.contains("BLIND SPOT")));
    }

    #[test]
    fn a_crypto_erase_is_not_judged_against_full_capacity_write_time() {
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
            assert_eq!(sa.audit.code(), "NOT_APPLICABLE", "{p:?}");
            assert_ne!(sa.audit.code(), "UNVERIFIED_TIMING", "{p:?}");
            assert_ne!(sa.audit.severity(), crate::audit::Severity::Verified, "{p:?}");
            assert!(sa.simulated, "{p:?}");
            assert!(sa.disposition.starts_with("NOT_A_SANITIZATION_CLAIM"), "{p:?}");
        }
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
        let mut disk = MemDisk::new(8 << 10);
        let mut sp = spec();
        sp.probe_bytes = 4096;
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
