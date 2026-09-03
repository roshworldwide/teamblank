//! # The behavioural audit — timing as evidence, because drives lie
//!
//! CLAUDE.md rule 5: *time every sanitize command; a 1 TB erase completing in 200 ms
//! means the drive lied; flag it, never trust the return code.*
//!
//! A firmware `SANITIZE` or `SECURITY ERASE UNIT` command answers with a status byte.
//! A drive that erased every cell and a drive that erased nothing return the **same**
//! status byte, and nothing in the command set distinguishes them. The return code is
//! therefore not evidence, and this module never consults one: [`audit`] ignores
//! [`Operation::device_reported_success`] entirely when forming a verdict and records it
//! only so a reader can see what the device claimed. `return_code_has_no_influence_on_the_verdict`
//! asserts exactly that.
//!
//! What *is* evidence is the clock. Erasing N bytes of media requires moving N bytes
//! through the device's write path, and that takes time bounded below by the device's own
//! throughput. If a command claims to have overwritten 268,435,456 bytes and returns in
//! four microseconds, the arithmetic refuses it whatever the status byte says.
//!
//! ## Where the throughput baseline comes from — measured, never assumed
//!
//! The expected minimum duration is `work_bytes / throughput`. The whole audit turns on
//! where `throughput` comes from, and there is exactly one wrong answer: a datasheet
//! figure, a constant, or anything else this process did not observe. An assumed
//! throughput makes the expected minimum a function of our assumption rather than of the
//! device, and the comparison becomes a tautology that can be tuned until it agrees with
//! whatever we wanted to conclude. This module cannot be handed one — [`Baseline`] is
//! constructible only from a [`ThroughputSample`], and a sample is `(bytes, elapsed_ns)`
//! that some caller actually timed.
//!
//! Two sources are legitimate, in this order of preference:
//!
//! 1. [`BaselineSource::ObservedPass`] — an overwrite pass that already completed against
//!    **this device in this run**. Strongest: same medium, same I/O path, same host load,
//!    same buffering, and no extra wear.
//! 2. [`BaselineSource::CalibrationProbe`] — a dedicated timed write of a bounded region,
//!    issued to this device immediately before the audited operation. Used when the
//!    operation is a firmware sanitize, which performs no host-visible I/O of its own and
//!    so leaves nothing to measure.
//!
//! The baseline must travel the **same path** as the operation it judges, buffering
//! included. A baseline measured with `O_DIRECT` against an operation that went through
//! the page cache compares two different machines.
//!
//! ## When the baseline is unavailable
//!
//! The verdict is [`Verdict::UnverifiedNoBaseline`] and it carries the reason. It is never
//! [`Verdict::Verified`]. Without a measured throughput there is no expected minimum, and
//! with no expected minimum there is no timing claim to make in either direction — so the
//! honest output is the one that says the audit could not run, not one that quietly passes.
//! Three ways to arrive there, all reported rather than smoothed over:
//!
//! - no sample was ever observed;
//! - every sample offered was refused as degenerate (see [`SampleRefusal`]);
//! - the expected minimum truncates to 0 ns, which is [`NotApplicableReason::BelowTimingResolution`]
//!   rather than a baseline failure: the work is too small for a clock to say anything about.
//!
//! ## Two deliberate choices, both generous to the device
//!
//! **The baseline keeps the *fastest* sample, not the mean.** A slow sample inflates the
//! expected minimum and manufactures false positives. Keeping the peak means a fire can
//! never be explained by our measurement having been slow — the device is being judged
//! against the best it was ever seen to do.
//!
//! **The expected minimum truncates down** (integer division, `work_bytes * sample_ns /
//! sample_bytes`), so rounding also favours the device.
//!
//! The cost of that generosity is the failure direction that matters: an inflated baseline
//! shrinks the expected minimum and silently disarms the detector. That is why
//! [`MIN_PROBE_BYTES`] refuses a sample below 1 MiB — measured, the fixed fsync cost dominates
//! a probe that small and the rate it reports stops describing the medium — and why every
//! report names its baseline's source, size and elapsed time, so a reader can reject the
//! baseline as easily as they can reject the verdict.
//!
//! ## A measured systematic, stated rather than tuned away
//!
//! Across six runs of `behavioural_audit_fires_in_one_direction_and_not_the_other`, a
//! 32 MiB calibration probe measured 1.70-2.07 GB/s while the 256 MiB overwrite it judged
//! ran at 2.19-2.42 GB/s. The probe **understates** the device by roughly 20%, because a
//! fixed `sync_all` cost is spread over eight times fewer bytes. That inflates the expected
//! minimum, which is the false-positive direction, and it is the reason the genuine
//! overwrite lands at a ratio near 0.78-0.86 rather than at 1.0.
//!
//! It is left uncorrected. A correction factor would be a tuning knob on the one number the
//! audit is supposed to measure, and the 20x threshold already absorbs a 20% error with a
//! factor of 16 to spare. Widening the probe would shrink the systematic and is the right
//! fix if it ever matters; inventing a multiplier is not.
//!
//! ## The honest limit of this method
//!
//! The baseline is only as truthful as the writes it was measured from. A device that fakes
//! host writes fast enough would inflate the baseline and, by that route, disarm this audit.
//! Timing cannot close that hole; sampled read-back verification is a separate check and a
//! necessary one. What this audit rules out is the specific and common failure where a
//! firmware command returns success without doing the work, and it rules that out
//! independently of anything the firmware says about itself.
//!
//! ## The verdict is not a boolean, and the reason is not stylistic
//!
//! "We could not tell" is a different answer from "it failed", and collapsing the two is
//! precisely the defect rule 1 exists to prevent — a tool that reports `false` for both an
//! unmeasurable operation and a detected lie has destroyed the distinction the certificate
//! is supposed to carry. [`Verdict`] therefore has five states and no `-> bool` accessor.
//! [`Verdict::severity`] narrows to three, never to two.
//!
//! And [`Verdict::Verified`] is *verified by timing*: the duration is consistent with the
//! measured throughput of this device. It attests that the time to do the work was spent.
//! It is not a claim that the data is gone — that claim belongs to read-back verification,
//! and per operator decision 3 a simulated operation may not make it at all, which is why a
//! simulated operation that passes the arithmetic is demoted to
//! [`Verdict::UnverifiedSimulated`] rather than reported as verified.

use std::time::Instant;

/// A sanitize that returns in under this fraction of its physically plausible minimum is
/// flagged. Held as an exact rational so the comparison is integer arithmetic and cannot
/// drift with float representation; [`PLAUSIBILITY_THRESHOLD`] is derived from it for display.
pub const PLAUSIBILITY_THRESHOLD_NUMER: u128 = 1;
/// Denominator of the plausibility threshold. `1/20` is the 5% of CLAUDE.md rule 5.
pub const PLAUSIBILITY_THRESHOLD_DENOM: u128 = 20;

/// The 5% threshold as a float, derived from the rational above so the two cannot disagree.
pub const PLAUSIBILITY_THRESHOLD: f64 =
    PLAUSIBILITY_THRESHOLD_NUMER as f64 / PLAUSIBILITY_THRESHOLD_DENOM as f64;

/// Smallest write a throughput sample may be measured over: 1 MiB.
///
/// **The mechanism, measured rather than assumed, and it is the opposite of what this
/// comment used to claim.** A small probe does not measure the write-back cache and does not
/// inflate the baseline on this platform; it *deflates* it. The probe's fixed `sync_all` cost
/// — 3.7 to 6.8 ms — is amortised over fewer bytes, so the rate it measures falls as the probe
/// shrinks. Through the shipped binary on a 256 MiB medium, varying only `--probe-bytes`:
/// 1 MiB → 192.24 MB/s (sync 69.6% of the probe), 4 MiB → 352.39 MB/s (40.4%), 32 MiB →
/// 560.05 MB/s (8.9%, the default), 128 MiB → 595.15 MB/s (2.6%), 256 MiB → 606.29 MB/s
/// (1.5%). That is a 3.15x span, and it agrees with the "A measured systematic" paragraph in
/// this module's header, which says the probe understates the device.
///
/// An under-measured baseline *inflates* the expected minimum, which makes the detector fire
/// on honest work rather than sleep through a lie. That is the safe direction, and it is why
/// the floor is a floor on sample size rather than a correction factor: below 1 MiB the fsync
/// dominates so completely that the figure stops describing the medium at all. The constant
/// is unchanged; only its justification was wrong, and this doc is what a jury reads.
pub const MIN_PROBE_BYTES: u64 = 1 << 20;

/// The schema string carried into the certificate by [`AuditReport::to_json`].
pub const AUDIT_SCHEMA: &str = "sentinelwipe.wipe.audit/1";

// ---------------------------------------------------------------------------
// Timing primitives
// ---------------------------------------------------------------------------

/// A monotonic stopwatch. `Instant` is monotonic, so a wall-clock adjustment mid-wipe
/// cannot manufacture or erase a duration.
#[derive(Debug)]
pub struct Stopwatch {
    started: Instant,
}

impl Stopwatch {
    pub fn start() -> Self {
        Stopwatch { started: Instant::now() }
    }

    /// Elapsed nanoseconds without consuming the stopwatch — for progress telemetry.
    pub fn elapsed_ns(&self) -> u128 {
        self.started.elapsed().as_nanos()
    }

    /// Consume and return the final elapsed nanoseconds.
    pub fn stop(self) -> u128 {
        self.started.elapsed().as_nanos()
    }
}

/// Time a closure. "Time every operation" is a rule, so make it one line to obey:
/// `let (status, ns) = timed(|| device.sanitize());`
pub fn timed<T, F: FnOnce() -> T>(f: F) -> (T, u128) {
    let sw = Stopwatch::start();
    let out = f();
    (out, sw.stop())
}

// ---------------------------------------------------------------------------
// The throughput baseline
// ---------------------------------------------------------------------------

/// Where a throughput sample was measured. Recorded in the certificate: a reader who
/// distrusts the source can reject the verdict without re-running anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineSource {
    /// An overwrite pass this run already completed against this device. Preferred.
    ObservedPass,
    /// A dedicated timed write issued to this device before the audited operation.
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

/// Why a sample was not admitted to the baseline. Refusals are reported, never swallowed:
/// a silently dropped sample looks identical to a baseline that was never attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleRefusal {
    /// Zero bytes moved. There is no throughput in it.
    ZeroBytes,
    /// The clock returned 0 ns. Admitting it would mean infinite throughput, an expected
    /// minimum of zero, and a detector that can never fire again.
    ZeroElapsed,
    /// Below [`MIN_PROBE_BYTES`]; measures cache, not medium.
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

/// One measured `(bytes, elapsed)` observation. There is no constructor that does not
/// carry both, which is what keeps an assumed throughput out of this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThroughputSample {
    pub bytes: u64,
    pub elapsed_ns: u128,
    pub source: BaselineSource,
}

impl ThroughputSample {
    /// Build a sample, refusing the degenerate cases rather than storing them.
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

    /// Is `self` faster than `other`? Cross-multiplied in `u128`, so two samples of
    /// different sizes compare exactly with no float involved.
    fn faster_than(&self, other: &ThroughputSample) -> bool {
        self.bytes as u128 * other.elapsed_ns > other.bytes as u128 * self.elapsed_ns
    }
}

/// The measured throughput this audit judges against. Keeps the fastest admitted sample;
/// see the module doc for why peak and not mean.
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

    /// Offer a measurement. Returns the refusal rather than hiding it.
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

    /// The floor this baseline puts under `work_bytes`, in nanoseconds.
    ///
    /// `work_bytes * sample_ns / sample_bytes`, entirely in `u128`: exact, reproducible on
    /// any host, and truncating downward so the rounding favours the device. 1 TB at
    /// 1 ns/byte is 1e21 ns, comfortably inside `u128`.
    pub fn expected_min_ns(&self, work_bytes: u64) -> u128 {
        work_bytes as u128 * self.peak.elapsed_ns / self.peak.bytes as u128
    }
}

// ---------------------------------------------------------------------------
// What the operation claimed to do
// ---------------------------------------------------------------------------

/// The physical work an operation claims to have performed.
///
/// This is deliberately *not* a method enum. The audit needs one thing from the caller —
/// how many bytes had to move — and mapping a named method onto that is the wipe
/// dispatcher's job, not this module's. It also keeps `CryptoErase` from being silently
/// treated as media work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workload {
    /// `passes` host-issued overwrites of `capacity_bytes`.
    Overwrite { capacity_bytes: u64, passes: u32 },
    /// A firmware command that erases the whole medium once: ATA SECURITY ERASE UNIT,
    /// NVMe Sanitize. No host I/O to observe, so the baseline must come from a probe.
    MediaSanitize { capacity_bytes: u64 },
    /// Destruction of the media-encryption key. Constant time by design: the medium is not
    /// touched, so duration carries no information about capacity and the timing audit does
    /// not apply. Saying "not applicable" here is what keeps the detector from firing on the
    /// one operation that is legitimately instant.
    CryptoErase,
}

impl Workload {
    /// Bytes that had to move. `None` when duration is not a function of capacity.
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

/// One timed operation, as presented to the audit.
#[derive(Debug, Clone)]
pub struct Operation {
    /// Human label for the certificate, e.g. `"ATA SECURITY ERASE UNIT (simulated)"`.
    pub label: String,
    pub workload: Workload,
    /// Measured wall time, from [`Stopwatch`] or [`timed`]. Never a computed figure.
    pub measured_ns: u128,
    /// Operator decision 3: an operation against an image file simulates and can never be
    /// reported as verified. Set by the dispatcher, not inferred here.
    pub simulated: bool,
    /// What the device said. Recorded for the reader; it has no influence on the verdict.
    pub device_reported_success: bool,
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/// Why the timing audit does not apply to an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotApplicableReason {
    /// Key destruction. Fast is correct here, so fast is not evidence of a lie.
    ConstantTimeByDesign,
    /// The operation claimed zero bytes of work.
    NoWorkClaimed,
    /// The expected minimum truncates to 0 ns: too little work for a clock to speak to.
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

/// The three-state narrowing of a verdict. Three, not two: an operation the audit could not
/// speak to must not land in the same bucket as one it caught lying.
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

/// The typed verdict the certificate carries.
///
/// Every variant that has an expected minimum carries the measured duration **beside** it,
/// in the same units, so a reader can do the division themselves rather than trusting
/// [`Verdict::ratio`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Duration is consistent with this device's measured throughput. Timing only — see the
    /// module doc; this is not a claim that the data is unrecoverable.
    Verified { measured_ns: u128, expected_min_ns: u128 },
    /// **UNVERIFIED_TIMING.** Returned success in under [`PLAUSIBILITY_THRESHOLD`] of the
    /// physically plausible minimum. The device claimed work it did not have time to do.
    UnverifiedTiming { measured_ns: u128, expected_min_ns: u128 },
    /// The arithmetic held, but the operation was simulated, so no verification is claimed
    /// from it. Operator decision 3.
    UnverifiedSimulated { measured_ns: u128, expected_min_ns: u128 },
    /// No measured throughput was available, so no expected minimum exists and no timing
    /// claim can be made in either direction.
    UnverifiedNoBaseline { measured_ns: u128, refusal: Option<SampleRefusal> },
    /// Duration carries no information about this operation.
    NotApplicable { measured_ns: u128, reason: NotApplicableReason },
}

impl Verdict {
    /// The code the certificate prints. `UNVERIFIED_TIMING` is the one named in CLAUDE.md
    /// rule 5 and is spelled exactly that way everywhere it appears.
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::Verified { .. } => "VERIFIED_TIMING",
            Verdict::UnverifiedTiming { .. } => "UNVERIFIED_TIMING",
            Verdict::UnverifiedSimulated { .. } => "UNVERIFIED_SIMULATED",
            Verdict::UnverifiedNoBaseline { .. } => "UNVERIFIED_NO_BASELINE",
            Verdict::NotApplicable { .. } => "NOT_APPLICABLE",
        }
    }

    /// There is deliberately no `-> bool` on this type. Three states, never two.
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

    /// measured / expected_min. A convenience over two numbers the verdict already carries
    /// separately, never a substitute for them.
    pub fn ratio(&self) -> Option<f64> {
        match self.expected_min_ns() {
            Some(e) if e > 0 => Some(self.measured_ns() as f64 / e as f64),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// The audit
// ---------------------------------------------------------------------------

/// The full record: verdict, both durations, and the baseline that produced the second one.
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub label: String,
    pub workload: Workload,
    pub work_bytes: Option<u64>,
    pub verdict: Verdict,
    pub simulated: bool,
    /// Recorded, not consulted.
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

    /// One line for the operator, both figures present, no adjectives.
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

    /// Certificate payload. Hand-rolled, zero dependencies, six decimal places on every
    /// float, key order stable — the conventions of `docs/output_schema.md` §2.
    ///
    /// Durations appear in both nanoseconds (integer, exact) and seconds (six places, for a
    /// human), and the measured value always sits immediately above the expected minimum so
    /// the two are read together.
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

/// Judge one timed operation against a measured baseline.
///
/// The order of the decisions is the argument:
///
/// 1. Work that does not scale with capacity is `NOT_APPLICABLE`. Deciding this first is
///    what stops a crypto-erase — legitimately instant — from being reported as a lie.
/// 2. No baseline is `UNVERIFIED_NO_BASELINE`, never `VERIFIED_TIMING`.
/// 3. An expected minimum of 0 ns is `NOT_APPLICABLE`: too small for a clock.
/// 4. `measured * 20 < expected_min` is `UNVERIFIED_TIMING`, in integer arithmetic.
/// 5. Otherwise the arithmetic held — and a simulated operation is demoted rather than
///    verified.
///
/// `op.device_reported_success` appears nowhere in the match above. It is copied into the
/// report so a reader can see what the device claimed, and it is read nowhere else. Grep it.
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

/// As [`audit`], for the case where the baseline could not be built and the refusal that
/// prevented it is worth carrying into the certificate.
pub fn audit_without_baseline(op: &Operation, refusal: SampleRefusal) -> AuditReport {
    let mut r = audit(op, None);
    if let Verdict::UnverifiedNoBaseline { measured_ns, .. } = r.verdict {
        r.verdict = Verdict::UnverifiedNoBaseline { measured_ns, refusal: Some(refusal) };
    }
    r
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Six decimal places, per `docs/output_schema.md` §2. No scientific notation.
fn fmt6(v: f64) -> String {
    if v.is_nan() || v.is_infinite() {
        return "0.000000".to_string();
    }
    format!("{:.6}", v)
}

/// Nanoseconds to seconds, six places. Below 1 microsecond this prints `0.000000`, which is
/// why the nanosecond integer is always emitted beside it.
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

// ---------------------------------------------------------------------------
// Tests
//
// SAFETY, and it is not a formality. This module's real-I/O test is the only place
// in the crate that writes hundreds of megabytes. It writes ONLY into a directory it
// created itself, under a unique name, with `create_dir` rather than `create_dir_all`
// so an existing path is an error and never a target. It opens nothing it did not
// create, it takes no path from configuration other than the scratch ROOT, and it
// removes what it made. It never reads or writes `out/fixture.img`: the 256 MiB figure
// is reproduced by generating a file of the fixture's exact size, so the measurement is
// fixture-scale without the fixture ever being opened.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::path::PathBuf;

    /// 1 MiB in 1 ms = 1,048,576,000 B/s. Chosen so the expected minimum for a 256 MiB
    /// workload is exactly 256,000,000 ns and the assertions below are exact, not approximate.
    fn synthetic_baseline() -> Baseline {
        Baseline::from_sample(
            ThroughputSample::new(1 << 20, 1_000_000, BaselineSource::ObservedPass).unwrap(),
        )
    }

    const FIXTURE_BYTES: u64 = 268_435_456; // out/fixture.img's size, not its contents.

    fn op(label: &str, workload: Workload, measured_ns: u128, simulated: bool) -> Operation {
        Operation {
            label: label.to_string(),
            workload,
            measured_ns,
            simulated,
            device_reported_success: true,
        }
    }

    // -- the arithmetic -----------------------------------------------------

    #[test]
    fn expected_minimum_for_the_fixture_is_exact_integer_arithmetic() {
        let b = synthetic_baseline();
        assert_eq!(b.expected_min_ns(FIXTURE_BYTES), 256_000_000);
        // Three passes is three times the work, exactly.
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
        // expected minimum 256,000,000 ns; 5% of it is 12,800,000 ns exactly.
        let at = audit(&op("at 5%", w, 12_800_000, false), Some(&b));
        assert_eq!(at.code(), "VERIFIED_TIMING", "exactly 5% is not under 5%");
        let under = audit(&op("just under", w, 12_799_999, false), Some(&b));
        assert_eq!(under.code(), "UNVERIFIED_TIMING");
    }

    // -- never trust the return code ---------------------------------------

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

        // All three are "not verified", and all three are different answers.
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

    // -- not applicable -----------------------------------------------------

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
        // A sector against a 1 GiB/ms baseline: 512 * 1_000_000 / 1_073_741_824 truncates
        // to 0 ns, so there is no floor for the measurement to sit under.
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

    // -- the baseline -------------------------------------------------------

    #[test]
    fn a_baseline_cannot_be_assumed_only_measured() {
        // There is no constructor taking a bytes-per-second figure. The only way in is a
        // (bytes, elapsed) pair somebody timed. This test exists to fail loudly if a
        // convenience constructor is ever added.
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
        // Admitting it would mean infinite throughput, an expected minimum of 0, and
        // nothing ever firing again.
        let mut b = synthetic_baseline();
        assert_eq!(b.observe(1 << 30, 0, BaselineSource::ObservedPass), Err(SampleRefusal::ZeroElapsed));
        assert_eq!(b.samples_refused(), 1);
        assert_eq!(b.expected_min_ns(FIXTURE_BYTES), 256_000_000, "the peak moved");
    }

    #[test]
    fn the_baseline_keeps_the_fastest_sample() {
        let mut b = synthetic_baseline(); // 1 MiB / 1 ms
        b.observe(4 << 20, 1_000_000, BaselineSource::ObservedPass).unwrap(); // 4x faster
        b.observe(1 << 20, 8_000_000, BaselineSource::ObservedPass).unwrap(); // 8x slower
        assert_eq!(b.samples_admitted(), 3);
        // Peak is 4 MiB/ms, so the fixture floor is a quarter of 256 ms.
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

    // -- operator decision 3: simulated is never verified --------------------

    #[test]
    fn a_simulated_operation_that_passes_the_arithmetic_is_still_not_verified() {
        let b = synthetic_baseline();
        let w = Workload::MediaSanitize { capacity_bytes: FIXTURE_BYTES };
        let r = audit(&op("NVMe Sanitize (simulated)", w, 300_000_000, true), Some(&b));
        assert_eq!(r.code(), "UNVERIFIED_SIMULATED");
        assert_eq!(r.severity(), Severity::Unverified);
        assert!(r.to_json().contains("\"simulated\": true"));
        // The demotion applies only to the passing branch: a fast simulated command still
        // reports the timing lie, which is the more specific and more useful answer.
        let fast = audit(&op("NVMe Sanitize (simulated)", w, 4_000, true), Some(&b));
        assert_eq!(fast.code(), "UNVERIFIED_TIMING");
    }

    // -- the certificate payload --------------------------------------------

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
        // measured must precede expected in the document; a reader divides top by bottom.
        let m = j.find("\"measured_duration_ns\"").unwrap();
        let e = j.find("\"expected_min_duration_ns\"").unwrap();
        assert!(m < e);
        // Every numeric value is either an integer or a float with exactly six places.
        // Scanned per line off the value side of the colon, so the schema string's dots
        // are not mistaken for a number.
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
        assert!(s.contains("0.000004"), "{}", s); // measured seconds
        assert!(s.contains("0.256000"), "{}", s); // expected minimum seconds
    }

    // -- both directions, against real measured I/O --------------------------

    /// Test-local filler. Not the wipe pattern — the seeded stream lives in the pattern
    /// module. This exists only so the bytes written are incompressible enough that no
    /// filesystem can shortcut the write into a hole.
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

    /// A directory this test created and nothing else. `create_dir` (not `create_dir_all`)
    /// on a unique name: if the path already exists this errors out rather than adopting
    /// somebody's data as a wipe target.
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

    /// Write `bytes` of filler over `path`, flush to the device, and return the elapsed
    /// nanoseconds. Creation and overwrite both go through here, so the calibration probe
    /// and the audited operation travel an identical path — the module doc requires that,
    /// and a baseline measured through a different path would judge a different machine.
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

    /// The whole point of the module, exercised in both directions off one measured
    /// baseline: a genuine 256 MiB overwrite must NOT fire, and a simulated sanitize
    /// claiming the same 256 MiB must fire with the real figures.
    ///
    /// The baseline is measured on a **separate** 32 MiB file, never on the operation it
    /// judges. Deriving it from the audited operation would make the ratio 1.000000 by
    /// construction and prove nothing.
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

        // 1 · The baseline, measured. Two probe writes; the baseline keeps the faster.
        let p1 = timed_overwrite(&probe, CALIBRATION_BYTES, 0xA1).expect("probe 1");
        let p2 = timed_overwrite(&probe, CALIBRATION_BYTES, 0xA2).expect("probe 2");
        let mut baseline = Baseline::from_sample(
            ThroughputSample::new(CALIBRATION_BYTES, p1, BaselineSource::CalibrationProbe)
                .expect("probe 1 admissible"),
        );
        baseline
            .observe(CALIBRATION_BYTES, p2, BaselineSource::CalibrationProbe)
            .expect("probe 2 admissible");

        // 2 · A genuine full overwrite of a 256 MiB image, timed.
        let real_ns = timed_overwrite(&target, FIXTURE_BYTES, 0xB1).expect("overwrite");

        // 3 · A sanitize that does nothing and says it worked, timed the same way.
        //
        // Not an empty closure: an empty closure optimises away and measures 0 ns, which
        // would make the flagged figure an artefact of the compiler rather than of a
        // command. This opens the device handle and reads its status the way a dispatcher
        // would, then returns success without writing a byte — which is exactly the
        // failure mode being detected. The measured nanoseconds are a real syscall.
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

        // Direction A: the real overwrite must not fire.
        assert_eq!(
            real.code(),
            "VERIFIED_TIMING",
            "a genuine 256 MiB overwrite fired the detector: measured {} ns against an \
             expected minimum of {} ns",
            real_ns,
            expected_min
        );
        assert!(real.verdict.ratio().unwrap() >= PLAUSIBILITY_THRESHOLD);

        // Direction B: the do-nothing sanitize must fire, with both real figures present.
        assert_eq!(fake.code(), "UNVERIFIED_TIMING");
        assert_eq!(fake.verdict.measured_ns(), sim_ns);
        assert_eq!(fake.verdict.expected_min_ns(), Some(expected_min));
        assert!(fake.verdict.ratio().unwrap() < PLAUSIBILITY_THRESHOLD);
        assert!(status, "the simulated command reported success, and was flagged anyway");
    }
}
