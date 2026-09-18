use std::time::Instant;

pub const PLAUSIBILITY_THRESHOLD_NUMER: u128 = 1;
pub const PLAUSIBILITY_THRESHOLD_DENOM: u128 = 20;

pub const PLAUSIBILITY_THRESHOLD: f64 =
    PLAUSIBILITY_THRESHOLD_NUMER as f64 / PLAUSIBILITY_THRESHOLD_DENOM as f64;

pub const MIN_PROBE_BYTES: u64 = 1 << 20;

pub const AUDIT_SCHEMA: &str = "sentinelwipe.wipe.audit/1";

#[derive(Debug)]
pub struct Stopwatch {
    started: Instant,
}

impl Stopwatch {
    pub fn start() -> Self {
        Stopwatch { started: Instant::now() }
    }

    pub fn elapsed_ns(&self) -> u128 {
        self.started.elapsed().as_nanos()
    }

    pub fn stop(self) -> u128 {
        self.started.elapsed().as_nanos()
    }
}

pub fn timed<T, F: FnOnce() -> T>(f: F) -> (T, u128) {
    let sw = Stopwatch::start();
    let out = f();
    (out, sw.stop())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineSource {
    ObservedPass,
    CalibrationProbe,
}

impl BaselineSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            BaselineSource::ObservedPass => "observed_pass",
            BaselineSource::CalibrationProbe => "calibration_probe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleRefusal {
    ZeroBytes,
    ZeroElapsed,
    TooSmall { bytes: u64, minimum: u64 },
}

impl SampleRefusal {
    pub fn as_str(&self) -> &'static str {
        match self {
            SampleRefusal::ZeroBytes => "zero_bytes",
            SampleRefusal::ZeroElapsed => "zero_elapsed",
            SampleRefusal::TooSmall { .. } => "below_min_probe_bytes",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThroughputSample {
    pub bytes: u64,
    pub elapsed_ns: u128,
    pub source: BaselineSource,
}

impl ThroughputSample {
    pub fn new(
        bytes: u64,
        elapsed_ns: u128,
        source: BaselineSource,
    ) -> Result<Self, SampleRefusal> {
        if bytes == 0 {
            return Err(SampleRefusal::ZeroBytes);
        }
        if bytes < MIN_PROBE_BYTES {
            return Err(SampleRefusal::TooSmall { bytes, minimum: MIN_PROBE_BYTES });
        }
        if elapsed_ns == 0 {
            return Err(SampleRefusal::ZeroElapsed);
        }
        Ok(ThroughputSample { bytes, elapsed_ns, source })
    }

    pub fn bytes_per_second(&self) -> f64 {
        self.bytes as f64 * 1_000_000_000.0 / self.elapsed_ns as f64
    }

    fn faster_than(&self, other: &ThroughputSample) -> bool {
        self.bytes as u128 * other.elapsed_ns > other.bytes as u128 * self.elapsed_ns
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Baseline {
    peak: ThroughputSample,
    admitted: u32,
    refused: u32,
}

impl Baseline {
    pub fn from_sample(sample: ThroughputSample) -> Self {
        Baseline { peak: sample, admitted: 1, refused: 0 }
    }

    pub fn observe(
        &mut self,
        bytes: u64,
        elapsed_ns: u128,
        source: BaselineSource,
    ) -> Result<(), SampleRefusal> {
        match ThroughputSample::new(bytes, elapsed_ns, source) {
            Ok(s) => {
                self.admitted += 1;
                if s.faster_than(&self.peak) {
                    self.peak = s;
                }
                Ok(())
            }
            Err(e) => {
                self.refused += 1;
                Err(e)
            }
        }
    }

    pub fn peak_sample(&self) -> ThroughputSample {
        self.peak
    }

    pub fn source(&self) -> BaselineSource {
        self.peak.source
    }

    pub fn samples_admitted(&self) -> u32 {
        self.admitted
    }

    pub fn samples_refused(&self) -> u32 {
        self.refused
    }

    pub fn bytes_per_second(&self) -> f64 {
        self.peak.bytes_per_second()
    }

    pub fn expected_min_ns(&self, work_bytes: u64) -> u128 {
        work_bytes as u128 * self.peak.elapsed_ns / self.peak.bytes as u128
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workload {
    Overwrite { capacity_bytes: u64, passes: u32 },
    MediaSanitize { capacity_bytes: u64 },
    CryptoErase,
}

impl Workload {
    pub fn work_bytes(&self) -> Option<u64> {
        match *self {
            Workload::Overwrite { capacity_bytes, passes } => {
                Some(capacity_bytes.saturating_mul(passes as u64))
            }
            Workload::MediaSanitize { capacity_bytes } => Some(capacity_bytes),
            Workload::CryptoErase => None,
        }
    }

    pub fn capacity_bytes(&self) -> u64 {
        match *self {
            Workload::Overwrite { capacity_bytes, .. } => capacity_bytes,
            Workload::MediaSanitize { capacity_bytes } => capacity_bytes,
            Workload::CryptoErase => 0,
        }
    }

    pub fn passes(&self) -> u32 {
        match *self {
            Workload::Overwrite { passes, .. } => passes,
            Workload::MediaSanitize { .. } => 1,
            Workload::CryptoErase => 0,
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match *self {
            Workload::Overwrite { .. } => "overwrite",
            Workload::MediaSanitize { .. } => "media_sanitize",
            Workload::CryptoErase => "crypto_erase",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Operation {
    pub label: String,
    pub workload: Workload,
    pub measured_ns: u128,
    pub simulated: bool,
    pub device_reported_success: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotApplicableReason {
    ConstantTimeByDesign,
    NoWorkClaimed,
    BelowTimingResolution,
}

impl NotApplicableReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotApplicableReason::ConstantTimeByDesign => "constant_time_by_design",
            NotApplicableReason::NoWorkClaimed => "no_work_claimed",
            NotApplicableReason::BelowTimingResolution => "below_timing_resolution",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Verified,
    Unverified,
    NotApplicable,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Verified => "verified",
            Severity::Unverified => "unverified",
            Severity::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Verified { measured_ns: u128, expected_min_ns: u128 },
    UnverifiedTiming { measured_ns: u128, expected_min_ns: u128 },
    UnverifiedSimulated { measured_ns: u128, expected_min_ns: u128 },
    UnverifiedNoBaseline { measured_ns: u128, refusal: Option<SampleRefusal> },
    NotApplicable { measured_ns: u128, reason: NotApplicableReason },
}

impl Verdict {
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::Verified { .. } => "VERIFIED_TIMING",
            Verdict::UnverifiedTiming { .. } => "UNVERIFIED_TIMING",
            Verdict::UnverifiedSimulated { .. } => "UNVERIFIED_SIMULATED",
            Verdict::UnverifiedNoBaseline { .. } => "UNVERIFIED_NO_BASELINE",
            Verdict::NotApplicable { .. } => "NOT_APPLICABLE",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Verdict::Verified { .. } => Severity::Verified,
            Verdict::UnverifiedTiming { .. }
            | Verdict::UnverifiedSimulated { .. }
            | Verdict::UnverifiedNoBaseline { .. } => Severity::Unverified,
            Verdict::NotApplicable { .. } => Severity::NotApplicable,
        }
    }

    pub fn measured_ns(&self) -> u128 {
        match *self {
            Verdict::Verified { measured_ns, .. }
            | Verdict::UnverifiedTiming { measured_ns, .. }
            | Verdict::UnverifiedSimulated { measured_ns, .. }
            | Verdict::UnverifiedNoBaseline { measured_ns, .. }
            | Verdict::NotApplicable { measured_ns, .. } => measured_ns,
        }
    }

    pub fn expected_min_ns(&self) -> Option<u128> {
        match *self {
            Verdict::Verified { expected_min_ns, .. }
            | Verdict::UnverifiedTiming { expected_min_ns, .. }
            | Verdict::UnverifiedSimulated { expected_min_ns, .. } => Some(expected_min_ns),
            Verdict::UnverifiedNoBaseline { .. } | Verdict::NotApplicable { .. } => None,
        }
    }

    pub fn ratio(&self) -> Option<f64> {
        match self.expected_min_ns() {
            Some(e) if e > 0 => Some(self.measured_ns() as f64 / e as f64),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub label: String,
    pub workload: Workload,
    pub work_bytes: Option<u64>,
    pub verdict: Verdict,
    pub simulated: bool,
    pub device_reported_success: bool,
    pub baseline: Option<Baseline>,
}

impl AuditReport {
    pub fn code(&self) -> &'static str {
        self.verdict.code()
    }

    pub fn severity(&self) -> Severity {
        self.verdict.severity()
    }

    pub fn summary(&self) -> String {
        let m = ns_to_s(self.verdict.measured_ns());
        match self.verdict {
            Verdict::UnverifiedTiming { expected_min_ns, .. } => format!(
                "UNVERIFIED_TIMING · {} · measured {} s against an expected minimum of {} s \
                 ({} of it) at a measured {} B/s. Device reported {}; the return code was not \
                 trusted.",
                self.label,
                m,
                ns_to_s(expected_min_ns),
                fmt6(self.verdict.ratio().unwrap_or(0.0)),
                self.baseline.map(|b| fmt6(b.bytes_per_second())).unwrap_or_else(|| "0".into()),
                if self.device_reported_success { "success" } else { "failure" },
            ),
            Verdict::Verified { expected_min_ns, .. } => format!(
                "VERIFIED_TIMING · {} · measured {} s against an expected minimum of {} s ({} of it).",
                self.label,
                m,
                ns_to_s(expected_min_ns),
                fmt6(self.verdict.ratio().unwrap_or(0.0)),
            ),
            Verdict::UnverifiedSimulated { expected_min_ns, .. } => format!(
                "UNVERIFIED_SIMULATED · {} · measured {} s against an expected minimum of {} s. \
                 Simulated operations are not verified.",
                self.label,
                m,
                ns_to_s(expected_min_ns),
            ),
            Verdict::UnverifiedNoBaseline { refusal, .. } => format!(
                "UNVERIFIED_NO_BASELINE · {} · measured {} s. No measured throughput for this \
                 device ({}), so no expected minimum exists.",
                self.label,
                m,
                refusal.map(|r| r.as_str()).unwrap_or("no sample offered"),
            ),
            Verdict::NotApplicable { reason, .. } => format!(
                "NOT_APPLICABLE · {} · measured {} s. Timing carries no information here ({}).",
                self.label,
                m,
                reason.as_str(),
            ),
        }
    }

    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str(&format!("  \"schema\": \"{}\",\n", AUDIT_SCHEMA));
        s.push_str(&format!("  \"operation\": \"{}\",\n", escape(&self.label)));
        s.push_str(&format!("  \"code\": \"{}\",\n", self.code()));
        s.push_str(&format!("  \"severity\": \"{}\",\n", self.severity().as_str()));
        s.push_str(&format!("  \"simulated\": {},\n", self.simulated));
        s.push_str(&format!(
            "  \"device_reported_success\": {},\n",
            self.device_reported_success
        ));
        s.push_str("  \"return_code_trusted\": false,\n");
        s.push_str("  \"workload\": {\n");
        s.push_str(&format!("    \"kind\": \"{}\",\n", self.workload.kind_str()));
        s.push_str(&format!(
            "    \"capacity_bytes\": {},\n",
            self.workload.capacity_bytes()
        ));
        s.push_str(&format!("    \"passes\": {},\n", self.workload.passes()));
        match self.work_bytes {
            Some(w) => s.push_str(&format!("    \"work_bytes\": {}\n", w)),
            None => s.push_str("    \"work_bytes\": null\n"),
        }
        s.push_str("  },\n");
        s.push_str(&format!(
            "  \"measured_duration_ns\": {},\n",
            self.verdict.measured_ns()
        ));
        s.push_str(&format!(
            "  \"measured_duration_s\": {},\n",
            ns_to_s(self.verdict.measured_ns())
        ));
        match self.verdict.expected_min_ns() {
            Some(e) => {
                s.push_str(&format!("  \"expected_min_duration_ns\": {},\n", e));
                s.push_str(&format!(
                    "  \"expected_min_duration_s\": {},\n",
                    ns_to_s(e)
                ));
            }
            None => {
                s.push_str("  \"expected_min_duration_ns\": null,\n");
                s.push_str("  \"expected_min_duration_s\": null,\n");
            }
        }
        match self.verdict.ratio() {
            Some(r) => s.push_str(&format!(
                "  \"ratio_measured_over_expected_min\": {},\n",
                fmt6(r)
            )),
            None => s.push_str("  \"ratio_measured_over_expected_min\": null,\n"),
        }
        s.push_str(&format!(
            "  \"threshold_ratio\": {},\n",
            fmt6(PLAUSIBILITY_THRESHOLD)
        ));
        match self.baseline {
            Some(b) => {
                let p = b.peak_sample();
                s.push_str("  \"baseline\": {\n");
                s.push_str(&format!("    \"source\": \"{}\",\n", b.source().as_str()));
                s.push_str("    \"measured\": true,\n");
                s.push_str(&format!("    \"probe_bytes\": {},\n", p.bytes));
                s.push_str(&format!("    \"probe_elapsed_ns\": {},\n", p.elapsed_ns));
                s.push_str(&format!(
                    "    \"bytes_per_second\": {},\n",
                    fmt6(b.bytes_per_second())
                ));
                s.push_str(&format!("    \"samples_admitted\": {},\n", b.samples_admitted()));
                s.push_str(&format!("    \"samples_refused\": {}\n", b.samples_refused()));
                s.push_str("  },\n");
            }
            None => s.push_str("  \"baseline\": null,\n"),
        }
        s.push_str(&format!("  \"note\": \"{}\"\n", escape(&self.summary())));
        s.push_str("}\n");
        s
    }
}

pub fn audit(op: &Operation, baseline: Option<&Baseline>) -> AuditReport {
    let work_bytes = op.workload.work_bytes();
    let measured_ns = op.measured_ns;

    let verdict = match work_bytes {
        None => Verdict::NotApplicable {
            measured_ns,
            reason: NotApplicableReason::ConstantTimeByDesign,
        },
        Some(0) => Verdict::NotApplicable {
            measured_ns,
            reason: NotApplicableReason::NoWorkClaimed,
        },
        Some(w) => match baseline {
            None => Verdict::UnverifiedNoBaseline { measured_ns, refusal: None },
            Some(b) => {
                let expected_min_ns = b.expected_min_ns(w);
                if expected_min_ns == 0 {
                    Verdict::NotApplicable {
                        measured_ns,
                        reason: NotApplicableReason::BelowTimingResolution,
                    }
                } else if measured_ns * PLAUSIBILITY_THRESHOLD_DENOM
                    < expected_min_ns * PLAUSIBILITY_THRESHOLD_NUMER
                {
                    Verdict::UnverifiedTiming { measured_ns, expected_min_ns }
                } else if op.simulated {
                    Verdict::UnverifiedSimulated { measured_ns, expected_min_ns }
                } else {
                    Verdict::Verified { measured_ns, expected_min_ns }
                }
            }
        },
    };

    AuditReport {
        label: op.label.clone(),
        workload: op.workload,
        work_bytes,
        verdict,
        simulated: op.simulated,
        device_reported_success: op.device_reported_success,
        baseline: baseline.copied(),
    }
}

pub fn audit_without_baseline(op: &Operation, refusal: SampleRefusal) -> AuditReport {
    let mut r = audit(op, None);
    if let Verdict::UnverifiedNoBaseline { measured_ns, .. } = r.verdict {
        r.verdict = Verdict::UnverifiedNoBaseline { measured_ns, refusal: Some(refusal) };
    }
    r
}

fn fmt6(v: f64) -> String {
    if v.is_nan() || v.is_infinite() {
        return "0.000000".to_string();
    }
    format!("{:.6}", v)
}

fn ns_to_s(ns: u128) -> String {
    fmt6(ns as f64 / 1_000_000_000.0)
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::path::PathBuf;

    fn synthetic_baseline() -> Baseline {
        Baseline::from_sample(
            ThroughputSample::new(1 << 20, 1_000_000, BaselineSource::ObservedPass).unwrap(),
        )
    }

    const FIXTURE_BYTES: u64 = 268_435_456;

    fn op(label: &str, workload: Workload, measured_ns: u128, simulated: bool) -> Operation {
        Operation {
            label: label.to_string(),
            workload,
            measured_ns,
            simulated,
            device_reported_success: true,
        }
    }

    #[test]
    fn expected_minimum_for_the_fixture_is_exact_integer_arithmetic() {
        let b = synthetic_baseline();
        assert_eq!(b.expected_min_ns(FIXTURE_BYTES), 256_000_000);
        assert_eq!(b.expected_min_ns(FIXTURE_BYTES * 3), 768_000_000);
    }

    #[test]
    fn threshold_rational_and_float_agree() {
        assert_eq!(PLAUSIBILITY_THRESHOLD, 0.05);
        assert_eq!(
            PLAUSIBILITY_THRESHOLD_NUMER as f64 / PLAUSIBILITY_THRESHOLD_DENOM as f64,
            PLAUSIBILITY_THRESHOLD
        );
    }

    #[test]
    fn the_boundary_is_where_the_rule_says_it_is() {
        let b = synthetic_baseline();
        let w = Workload::MediaSanitize { capacity_bytes: FIXTURE_BYTES };
        let at = audit(&op("at 5%", w, 12_800_000, false), Some(&b));
        assert_eq!(at.code(), "VERIFIED_TIMING", "exactly 5% is not under 5%");
        let under = audit(&op("just under", w, 12_799_999, false), Some(&b));
        assert_eq!(under.code(), "UNVERIFIED_TIMING");
    }

    #[test]
    fn return_code_has_no_influence_on_the_verdict() {
        let b = synthetic_baseline();
        let w = Workload::MediaSanitize { capacity_bytes: FIXTURE_BYTES };
        for &(ns, expect) in &[
            (1_000u128, "UNVERIFIED_TIMING"),
            (300_000_000u128, "VERIFIED_TIMING"),
        ] {
            let mut yes = op("device says success", w, ns, false);
            yes.device_reported_success = true;
            let mut no = op("device says success", w, ns, false);
            no.device_reported_success = false;
            let a = audit(&yes, Some(&b));
            let c = audit(&no, Some(&b));
            assert_eq!(a.code(), expect);
            assert_eq!(
                a.verdict, c.verdict,
                "the status byte changed the verdict; it must not"
            );
        }
    }

    #[test]
    fn the_verdict_never_collapses_to_a_boolean() {
        let b = synthetic_baseline();
        let w = Workload::MediaSanitize { capacity_bytes: FIXTURE_BYTES };
        let fired = audit(&op("fast", w, 1_000, false), Some(&b));
        let no_base = audit(&op("no baseline", w, 1_000, false), None);
        let na = audit(&op("crypto", Workload::CryptoErase, 1_000, false), Some(&b));

        for r in [&fired, &no_base, &na] {
            assert_ne!(r.severity(), Severity::Verified);
        }
        let codes = [fired.code(), no_base.code(), na.code()];
        assert_eq!(
            codes.len(),
            codes.iter().collect::<std::collections::BTreeSet<_>>().len(),
            "three distinct situations must not share a code"
        );
        assert_ne!(no_base.severity(), na.severity());
        assert_eq!(fired.severity(), Severity::Unverified);
        assert_eq!(na.severity(), Severity::NotApplicable);
    }

    #[test]
    fn crypto_erase_is_not_applicable_however_fast_it_returns() {
        let b = synthetic_baseline();
        let r = audit(&op("crypto-erase", Workload::CryptoErase, 12, false), Some(&b));
        assert_eq!(r.code(), "NOT_APPLICABLE");
        assert_eq!(r.verdict.expected_min_ns(), None);
        assert_eq!(r.verdict.ratio(), None);
        assert!(matches!(
            r.verdict,
            Verdict::NotApplicable { reason: NotApplicableReason::ConstantTimeByDesign, .. }
        ));
    }

    #[test]
    fn zero_work_and_sub_resolution_work_are_named_separately() {
        let b = synthetic_baseline();
        let zero = audit(
            &op("nothing", Workload::MediaSanitize { capacity_bytes: 0 }, 5, false),
            Some(&b),
        );
        assert!(matches!(
            zero.verdict,
            Verdict::NotApplicable { reason: NotApplicableReason::NoWorkClaimed, .. }
        ));
        let fast = Baseline::from_sample(
            ThroughputSample::new(1 << 30, 1_000_000, BaselineSource::ObservedPass).unwrap(),
        );
        assert_eq!(fast.expected_min_ns(512), 0);
        let tiny = audit(
            &op("one sector", Workload::MediaSanitize { capacity_bytes: 512 }, 5, false),
            Some(&fast),
        );
        assert!(matches!(
            tiny.verdict,
            Verdict::NotApplicable { reason: NotApplicableReason::BelowTimingResolution, .. }
        ));
    }

    #[test]
    fn a_baseline_cannot_be_assumed_only_measured() {
        let s = ThroughputSample::new(1 << 20, 1_000_000, BaselineSource::CalibrationProbe).unwrap();
        assert_eq!(s.bytes, 1 << 20);
        assert_eq!(s.elapsed_ns, 1_000_000);
    }

    #[test]
    fn degenerate_samples_are_refused_with_a_reason() {
        assert_eq!(
            ThroughputSample::new(0, 10, BaselineSource::ObservedPass).unwrap_err(),
            SampleRefusal::ZeroBytes
        );
        assert_eq!(
            ThroughputSample::new(1 << 20, 0, BaselineSource::ObservedPass).unwrap_err(),
            SampleRefusal::ZeroElapsed
        );
        assert_eq!(
            ThroughputSample::new(4096, 10, BaselineSource::ObservedPass).unwrap_err(),
            SampleRefusal::TooSmall { bytes: 4096, minimum: MIN_PROBE_BYTES }
        );
    }

    #[test]
    fn a_zero_nanosecond_sample_cannot_disarm_the_detector() {
        let mut b = synthetic_baseline();
        assert_eq!(b.observe(1 << 30, 0, BaselineSource::ObservedPass), Err(SampleRefusal::ZeroElapsed));
        assert_eq!(b.samples_refused(), 1);
        assert_eq!(b.expected_min_ns(FIXTURE_BYTES), 256_000_000, "the peak moved");
    }

    #[test]
    fn the_baseline_keeps_the_fastest_sample() {
        let mut b = synthetic_baseline();
        b.observe(4 << 20, 1_000_000, BaselineSource::ObservedPass).unwrap();
        b.observe(1 << 20, 8_000_000, BaselineSource::ObservedPass).unwrap();
        assert_eq!(b.samples_admitted(), 3);
        assert_eq!(b.expected_min_ns(FIXTURE_BYTES), 64_000_000);
    }

    #[test]
    fn no_baseline_is_unverified_and_never_verified() {
        let w = Workload::Overwrite { capacity_bytes: FIXTURE_BYTES, passes: 1 };
        let r = audit(&op("overwrite, unmeasured host", w, 900_000_000, false), None);
        assert_eq!(r.code(), "UNVERIFIED_NO_BASELINE");
        assert_eq!(r.severity(), Severity::Unverified);
        assert_eq!(r.verdict.expected_min_ns(), None);
        let with_reason = audit_without_baseline(
            &op("overwrite, probe refused", w, 900_000_000, false),
            SampleRefusal::TooSmall { bytes: 4096, minimum: MIN_PROBE_BYTES },
        );
        assert!(matches!(
            with_reason.verdict,
            Verdict::UnverifiedNoBaseline { refusal: Some(SampleRefusal::TooSmall { .. }), .. }
        ));
        assert!(with_reason.to_json().contains("\"expected_min_duration_ns\": null"));
    }

    #[test]
    fn a_simulated_operation_that_passes_the_arithmetic_is_still_not_verified() {
        let b = synthetic_baseline();
        let w = Workload::MediaSanitize { capacity_bytes: FIXTURE_BYTES };
        let r = audit(&op("NVMe Sanitize (simulated)", w, 300_000_000, true), Some(&b));
        assert_eq!(r.code(), "UNVERIFIED_SIMULATED");
        assert_eq!(r.severity(), Severity::Unverified);
        assert!(r.to_json().contains("\"simulated\": true"));
        let fast = audit(&op("NVMe Sanitize (simulated)", w, 4_000, true), Some(&b));
        assert_eq!(fast.code(), "UNVERIFIED_TIMING");
    }

    #[test]
    fn the_two_durations_are_emitted_side_by_side() {
        let b = synthetic_baseline();
        let w = Workload::MediaSanitize { capacity_bytes: FIXTURE_BYTES };
        let r = audit(&op("ATA SECURITY ERASE UNIT (simulated)", w, 4_000, true), Some(&b));
        let j = r.to_json();
        assert!(j.contains("\"code\": \"UNVERIFIED_TIMING\""));
        assert!(j.contains("\"measured_duration_ns\": 4000"));
        assert!(j.contains("\"expected_min_duration_ns\": 256000000"));
        assert!(j.contains("\"threshold_ratio\": 0.050000"));
        assert!(j.contains("\"return_code_trusted\": false"));
        assert!(j.contains("\"source\": \"observed_pass\""));
        let m = j.find("\"measured_duration_ns\"").unwrap();
        let e = j.find("\"expected_min_duration_ns\"").unwrap();
        assert!(m < e);
        let mut floats = 0;
        for line in j.lines() {
            let value = match line.rsplit_once(": ") {
                Some((_, v)) => v.trim_end_matches(','),
                None => continue,
            };
            if value.parse::<f64>().is_err() {
                continue;
            }
            if let Some(dot) = value.find('.') {
                assert_eq!(
                    value.len() - dot - 1,
                    6,
                    "float {} is not six places, in line {}",
                    value,
                    line
                );
                floats += 1;
            }
        }
        assert!(floats >= 4, "only {} floats scanned; the scan is broken", floats);
    }

    #[test]
    fn the_summary_carries_both_figures() {
        let b = synthetic_baseline();
        let w = Workload::MediaSanitize { capacity_bytes: FIXTURE_BYTES };
        let s = audit(&op("NVMe Sanitize (simulated)", w, 4_000, true), Some(&b)).summary();
        assert!(s.starts_with("UNVERIFIED_TIMING"));
        assert!(s.contains("0.000004"), "{}", s);
        assert!(s.contains("0.256000"), "{}", s);
    }

    struct Xorshift(u64);
    impl Xorshift {
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                let b = x.to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
        }
    }

    fn make_private_scratch() -> Option<PathBuf> {
        let root = std::env::var("SENTINELWIPE_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let unique = format!(
            "sentinelwipe-audit-{}-{}",
            std::process::id(),
            Stopwatch::start().elapsed_ns()
        );
        let dir = root.join(unique);
        fs::create_dir(&dir).ok()?;
        Some(dir)
    }

    const CHUNK: usize = 4 << 20;

    fn timed_overwrite(path: &PathBuf, bytes: u64, seed: u64) -> std::io::Result<u128> {
        let mut rng = Xorshift(seed);
        let mut buf = vec![0u8; CHUNK];
        let mut f = OpenOptions::new().write(true).open(path)?;
        f.seek(SeekFrom::Start(0))?;
        let sw = Stopwatch::start();
        let mut done = 0u64;
        while done < bytes {
            let n = std::cmp::min(CHUNK as u64, bytes - done) as usize;
            rng.fill(&mut buf[..n]);
            f.write_all(&buf[..n])?;
            done += n as u64;
        }
        f.sync_all()?;
        Ok(sw.stop())
    }

    fn create_of_size(path: &PathBuf, bytes: u64, seed: u64) -> std::io::Result<()> {
        let mut rng = Xorshift(seed);
        let mut buf = vec![0u8; CHUNK];
        let mut f = File::create(path)?;
        let mut done = 0u64;
        while done < bytes {
            let n = std::cmp::min(CHUNK as u64, bytes - done) as usize;
            rng.fill(&mut buf[..n]);
            f.write_all(&buf[..n])?;
            done += n as u64;
        }
        f.sync_all()
    }

    #[test]
    fn behavioural_audit_fires_in_one_direction_and_not_the_other() {
        const CALIBRATION_BYTES: u64 = 32 << 20;

        let dir = match make_private_scratch() {
            Some(d) => d,
            None => {
                eprintln!("no writable scratch directory; real-I/O audit not measured");
                return;
            }
        };
        let probe = dir.join("calibration_probe.bin");
        let target = dir.join("overwrite_target.bin");

        create_of_size(&probe, CALIBRATION_BYTES, 0x5EED_0001).expect("create probe");
        create_of_size(&target, FIXTURE_BYTES, 0x5EED_0002).expect("create target");

        let p1 = timed_overwrite(&probe, CALIBRATION_BYTES, 0xA1).expect("probe 1");
        let p2 = timed_overwrite(&probe, CALIBRATION_BYTES, 0xA2).expect("probe 2");
        let mut baseline = Baseline::from_sample(
            ThroughputSample::new(CALIBRATION_BYTES, p1, BaselineSource::CalibrationProbe)
                .expect("probe 1 admissible"),
        );
        baseline
            .observe(CALIBRATION_BYTES, p2, BaselineSource::CalibrationProbe)
            .expect("probe 2 admissible");

        let real_ns = timed_overwrite(&target, FIXTURE_BYTES, 0xB1).expect("overwrite");

        let (status, sim_ns) = timed(|| {
            let h = OpenOptions::new().write(true).open(&target);
            match h {
                Ok(f) => f.metadata().map(|m| m.len() == FIXTURE_BYTES).unwrap_or(false),
                Err(_) => false,
            }
        });

        fs::remove_file(&probe).ok();
        fs::remove_file(&target).ok();
        fs::remove_dir(&dir).ok();

        let expected_min = baseline.expected_min_ns(FIXTURE_BYTES);

        let real = audit(
            &op(
                "single-pass overwrite, 256 MiB image",
                Workload::Overwrite { capacity_bytes: FIXTURE_BYTES, passes: 1 },
                real_ns,
                false,
            ),
            Some(&baseline),
        );
        let mut sim_op = op(
            "ATA SECURITY ERASE UNIT (simulated)",
            Workload::MediaSanitize { capacity_bytes: FIXTURE_BYTES },
            sim_ns,
            true,
        );
        sim_op.device_reported_success = status;
        let fake = audit(&sim_op, Some(&baseline));

        println!("\n--- behavioural audit, measured ---");
        println!(
            "baseline           {} B over {} ns = {} B/s  ({}, {} admitted)",
            baseline.peak_sample().bytes,
            baseline.peak_sample().elapsed_ns,
            fmt6(baseline.bytes_per_second()),
            baseline.source().as_str(),
            baseline.samples_admitted()
        );
        println!("probe 1 / probe 2  {} ns / {} ns", p1, p2);
        println!(
            "expected minimum   {} ns ({} s) for {} bytes",
            expected_min,
            ns_to_s(expected_min),
            FIXTURE_BYTES
        );
        println!("genuine overwrite  {}", real.summary());
        println!("fast sanitize      {}", fake.summary());
        println!("{}", fake.to_json());

        assert_eq!(
            real.code(),
            "VERIFIED_TIMING",
            "a genuine 256 MiB overwrite fired the detector: measured {} ns against an \
             expected minimum of {} ns",
            real_ns,
            expected_min
        );
        assert!(real.verdict.ratio().unwrap() >= PLAUSIBILITY_THRESHOLD);

        assert_eq!(fake.code(), "UNVERIFIED_TIMING");
        assert_eq!(fake.verdict.measured_ns(), sim_ns);
        assert_eq!(fake.verdict.expected_min_ns(), Some(expected_min));
        assert!(fake.verdict.ratio().unwrap() < PLAUSIBILITY_THRESHOLD);
        assert!(status, "the simulated command reported success, and was flagged anyway");
    }
}
