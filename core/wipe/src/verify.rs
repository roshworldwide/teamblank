//! # Sampled read-back verification — what turns a write into a claim
//!
//! A write that returned zero is not evidence that the medium changed. The device
//! reported success; CLAUDE.md rule 5 is that a device's report is not evidence and
//! rule 1 is that the tool never claims more than it verified. So after each pass
//! the engine reads sectors back and compares them against the pattern that pass was
//! supposed to lay down. The pattern is regenerable at any sector from the run seed
//! alone ([`crate::passes::PatternGen`]), which is what makes this possible without
//! keeping 256 MiB of expected bytes anywhere.
//!
//! ## Sampling is not proof, and the report says so in its own words
//!
//! The default reads [`DEFAULT_SECTORS_PER_MIB`] sectors out of every mebibyte, which
//! at a 512-byte sector is 4 of 2048 — **0.1953% of the medium.** Every artifact this
//! module emits carries that number, the count of sectors actually read, and
//! [`SAMPLING_IS_NOT_PROOF`] verbatim. There is no summarising it away: a verdict
//! field alone would let a reader believe the whole medium was checked.
//!
//! What the sample does and does not catch, arithmetically rather than rhetorically
//! — see [`detection_probability`]:
//!
//! | failure | sectors bad, per MiB region | P(detected) at 4/MiB |
//! |---|---|---|
//! | a whole region never written | 2048 | 1.000000 |
//! | a 64 KiB run never written | 128 | 0.2277 |
//! | one sector never written | 1 | 0.001953 |
//!
//! Sampling finds the failure that a wipe actually produces — a range skipped, a
//! device that ignored writes, a pass that never ran — and is nearly blind to a
//! single bad sector. That is the honest description of it, and it is why
//! [`verify_pass_exhaustive`] exists: at fixture scale the whole medium can be read
//! back for half a second, and a claim about all 524,288 sectors is worth more than
//! that.
//!
//! ## Measured, 2026-09-03, 256 MiB (524,288 sectors) on macOS arm64
//!
//! | rate | sectors read | coverage | wall |
//! |---|---|---|---|
//! | 1/MiB | 256 | 0.048828% | 0.001 s |
//! | 4/MiB (default) | 1,024 | 0.195312% | 0.002 s |
//! | 16/MiB | 4,096 | 0.781250% | 0.007 s |
//! | 64/MiB | 16,384 | 3.125000% | 0.027 s |
//! | **exhaustive** | **524,288** | **100%** | **0.480 s** |
//!
//! At this size the exhaustive read-back costs half a second against a 0.42 s wipe.
//! The sampled path saves 0.478 s and buys a materially weaker claim; at a terabyte
//! the trade reverses and the sampled path is the only one that finishes. Which one a
//! run uses is the operator's call -- `demo_script.md` is their file -- and this
//! module's job is to make both figures available and label each verdict with what it
//! actually covered.
//!
//! ## The sample positions are public, and that is a real limit
//!
//! Positions are derived from the published run seed, so a third party can reproduce
//! exactly which sectors we checked and re-check them — which is the point. The cost
//! is that a *malicious controller* that knows the seed knows which sectors it must
//! actually write. This module detects incidental failure, not adversarial firmware.
//! [`SAMPLE_POSITIONS_ARE_PUBLIC`] states it and the report carries it.
//!
//! Deriving positions from an unpublished random source would defeat the attack and
//! break CLAUDE.md rule 6 — the certificate would name different sectors every run
//! and no two runs would be byte-identical. The trade was taken in favour of
//! reproducibility, deliberately, and it is written down rather than hidden.

use std::time::Instant;

use crate::passes::{
    hex, sha3_256, shake128, ByteHistogram, Capabilities, Keccak, Method, PatternGen, SectorIo,
    Seed, WipeConfig, WipeError, WipeReport,
};
use crate::telemetry::{EventSink, Telemetry};

/// Domain separation for sample-position derivation. Distinct from the pattern
/// domain, so no sector's position can ever equal a slice of its own contents.
pub const SAMPLING_DOMAIN: &[u8] = b"SENTINELWIPE/verify-sample/v1";

/// Sectors read back per mebibyte of medium by default: 4 of 2048 at a 512-byte
/// sector, 0.1953% coverage.
pub const DEFAULT_SECTORS_PER_MIB: u32 = 4;

/// The region a sampling rate is quoted against.
pub const MIB: u64 = 1 << 20;

/// Cap on individually recorded mismatches. The count is exact and unbounded; the
/// list is not, because a certificate that inlines 500,000 mismatch records is a
/// denial of service against its own reader.
pub const MAX_RECORDED_MISMATCHES: usize = 64;

/// Carried verbatim in every sampled report. CLAUDE.md rule 1.
pub const SAMPLING_IS_NOT_PROOF: &str = "\
SAMPLING IS NOT PROOF OF THE WHOLE MEDIUM. This verdict covers only the sectors the \
sampling plan named and this run actually read back. Sectors outside the sample were \
not read after the pass and carry no verification claim from this run. A pass that \
skipped an unsampled sector would produce this same verdict.";

/// The limit that follows from publishing the seed.
pub const SAMPLE_POSITIONS_ARE_PUBLIC: &str = "\
Sample positions are derived from the run seed, which is published in the certificate \
so a third party can reproduce them. A device whose firmware knew the seed could write \
only the sampled sectors and pass. This procedure detects incidental failure -- a \
skipped range, an ignored write, a pass that did not run -- and does not detect \
adversarial firmware.";

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// How much to read back and where the rate is quoted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingPolicy {
    pub sectors_per_mib: u32,
    pub region_bytes: u64,
}

impl Default for SamplingPolicy {
    fn default() -> Self {
        SamplingPolicy {
            sectors_per_mib: DEFAULT_SECTORS_PER_MIB,
            region_bytes: MIB,
        }
    }
}

impl SamplingPolicy {
    pub fn per_mib(n: u32) -> Self {
        SamplingPolicy {
            sectors_per_mib: n,
            region_bytes: MIB,
        }
    }
}

/// The arithmetic of one sampling policy against one geometry, computed before a
/// sector is read so the coverage figure can be shown in advance.
#[derive(Debug, Clone, PartialEq)]
pub struct SamplingPlan {
    pub sectors_per_mib: u32,
    pub region_bytes: u64,
    pub sector_bytes: u32,
    pub sector_count: u64,
    /// Sectors in a full region. The final region may be shorter.
    pub region_sectors: u64,
    pub regions: u64,
    pub sectors_to_sample: u64,
    pub coverage_fraction: f64,
}

impl SamplingPlan {
    pub fn new(policy: &SamplingPolicy, caps: &Capabilities) -> Result<SamplingPlan, WipeError> {
        if caps.sector_bytes == 0 || caps.sector_count == 0 {
            return Err(WipeError::DegenerateGeometry {
                sector_bytes: caps.sector_bytes,
                sector_count: caps.sector_count,
            });
        }
        let region_sectors = (policy.region_bytes / caps.sector_bytes as u64).max(1);
        let regions = caps.sector_count.div_ceil(region_sectors);
        let k = policy.sectors_per_mib.max(1) as u64;
        let mut total = 0u64;
        for r in 0..regions {
            let first = r * region_sectors;
            let len = core::cmp::min(region_sectors, caps.sector_count - first);
            total += core::cmp::min(k, len);
        }
        Ok(SamplingPlan {
            sectors_per_mib: policy.sectors_per_mib,
            region_bytes: policy.region_bytes,
            sector_bytes: caps.sector_bytes,
            sector_count: caps.sector_count,
            region_sectors,
            regions,
            sectors_to_sample: total,
            coverage_fraction: total as f64 / caps.sector_count as f64,
        })
    }
}

/// The sectors to read back in one region, derived from the seed alone.
///
/// Deterministic, duplicate-free, sorted ascending — sorted so the read walks the
/// medium forward rather than seeking randomly, which on a rotational medium is the
/// difference between a verification and a punishment.
///
/// Uniformity is by rejection, not by `% region_sectors` on a raw draw: the modulo
/// of a uniform 64-bit value is biased toward low indices whenever the bound does
/// not divide 2^64, and a sampler biased toward the start of every region is a
/// sampler that under-reads the end of every region.
pub fn sample_region(
    seed: &Seed,
    method: Method,
    pass: u32,
    region_index: u64,
    region_first_lba: u64,
    region_sectors: u64,
    k: u64,
) -> Vec<u64> {
    if region_sectors == 0 || k == 0 {
        return Vec::new();
    }
    if k >= region_sectors {
        return (0..region_sectors).map(|i| region_first_lba + i).collect();
    }
    let mut xof = Keccak::shake128();
    xof.absorb(SAMPLING_DOMAIN);
    xof.absorb(seed.as_bytes());
    xof.absorb(&[method.id()]);
    xof.absorb(&pass.to_le_bytes());
    xof.absorb(&region_index.to_le_bytes());
    xof.absorb(&region_sectors.to_le_bytes());

    let zone = (u64::MAX / region_sectors) * region_sectors;
    let mut chosen: Vec<u64> = Vec::with_capacity(k as usize);
    let mut word = [0u8; 8];
    while (chosen.len() as u64) < k {
        xof.squeeze(&mut word);
        let x = u64::from_le_bytes(word);
        if x >= zone {
            continue; // rejected, so the modulo below is unbiased
        }
        let lba = region_first_lba + (x % region_sectors);
        if !chosen.contains(&lba) {
            chosen.push(lba);
        }
    }
    chosen.sort_unstable();
    chosen
}

/// Probability that a sample of `k` sectors drawn without replacement from a region
/// of `region_sectors` contains at least one of `bad` bad sectors.
///
/// The hypergeometric complement: `1 - prod_{i<k} (S-b-i)/(S-i)`. This is the
/// function behind the table in the module header, and it is computed rather than
/// asserted so a reviewer can put their own numbers in.
pub fn detection_probability(region_sectors: u64, k: u64, bad: u64) -> f64 {
    if region_sectors == 0 || k == 0 || bad == 0 {
        return 0.0;
    }
    let s = region_sectors;
    let b = bad.min(s);
    let k = k.min(s);
    if b + k > s {
        return 1.0;
    }
    let mut miss = 1.0f64;
    for i in 0..k {
        miss *= (s - b - i) as f64 / (s - i) as f64;
    }
    1.0 - miss
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// One sector that did not carry the pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub lba: u64,
    /// Offset within the sector of the first differing byte.
    pub first_diff_offset: u32,
    pub expected: u8,
    pub found: u8,
    /// How many bytes of the sector differ. A sector that differs in every byte is a
    /// sector that was never written; a sector differing in three bytes is something
    /// else, and the certificate should be able to tell them apart.
    pub differing_bytes: u32,
}

/// The three outcomes. There is no "probably" and no "partial": a mismatch anywhere
/// in the sample is [`Verdict::PatternMismatch`] for the whole pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every sampled sector carried the pattern. Says nothing about the rest.
    SampledPatternMatch,
    /// Every sector of the medium was read back and carried the pattern.
    ExhaustivePatternMatch,
    PatternMismatch,
}

impl Verdict {
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::SampledPatternMatch => "PATTERN_CONFIRMED_ON_SAMPLE",
            Verdict::ExhaustivePatternMatch => "PATTERN_CONFIRMED_WHOLE_MEDIUM",
            Verdict::PatternMismatch => "PATTERN_MISMATCH",
        }
    }

    pub fn is_match(&self) -> bool {
        !matches!(self, Verdict::PatternMismatch)
    }
}

/// What one verification did, in numbers a certificate can carry unaltered.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyReport {
    pub mode: &'static str,
    pub method_label: &'static str,
    pub pass: u32,
    pub passes: u32,
    pub pattern: &'static str,
    pub seed_hex: String,
    pub sector_bytes: u32,
    pub sector_count: u64,
    /// 0 for an exhaustive read-back.
    pub sectors_per_mib: u32,
    pub regions: u64,
    pub sectors_verified: u64,
    pub sectors_unverified: u64,
    pub bytes_verified: u64,
    pub coverage_fraction: f64,
    /// The longest run of consecutive sectors this plan did NOT sample, measured
    /// over the sample the run actually read rather than derived from the coverage
    /// fraction.
    ///
    /// This is the size of the blind spot, published so it does not have to be
    /// discovered. A region of this many sectors left unwiped, positioned between
    /// two sample points, produces [`Verdict::SampledPatternMatch`] with zero
    /// mismatches -- measured, in
    /// `a_region_left_unwiped_between_sample_points_survives_a_confirmed_sample`.
    /// 0 for an exhaustive read-back, where there is no such run by construction.
    pub largest_unsampled_run_sectors: u64,
    pub mismatched_sectors: u64,
    pub mismatches: Vec<Mismatch>,
    pub mismatches_truncated: bool,
    pub duration_ns: u128,
    pub verdict: Verdict,
    /// The sentence a human reads. Carries the measured numbers and, for a sampled
    /// run, [`SAMPLING_IS_NOT_PROOF`] and [`SAMPLE_POSITIONS_ARE_PUBLIC`].
    pub claim: String,
    /// A digest that pins *which* sectors this run read: SHAKE-128 over the domain
    /// string followed by every sampled LBA in the order they were read. A third
    /// party who re-derives the plan from the published seed gets the same 64 hex
    /// characters, without either side shipping 4,096 integers. For an exhaustive
    /// read-back it is instead a digest over the marker and the sector count, since
    /// the sector list is `0..sector_count` and enumerating it proves nothing.
    pub sample_digest_hex: String,
}

impl VerifyReport {
    pub fn read_throughput_bytes_per_s(&self) -> f64 {
        if self.duration_ns == 0 {
            0.0
        } else {
            self.bytes_verified as f64 * 1_000_000_000.0 / self.duration_ns as f64
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn claim_text(
    verdict: Verdict,
    verified: u64,
    total: u64,
    coverage: f64,
    mismatched: u64,
    pass: u32,
    passes: u32,
    exhaustive: bool,
    // Sectors in the longest unsampled run, and the sector size, so the claim
    // states the size of its own blind spot in bytes rather than leaving a reader
    // to derive it from the coverage fraction.
    largest_unsampled_run: u64,
    sector_bytes: u32,
) -> String {
    let head = match verdict {
        Verdict::PatternMismatch => format!(
            "PATTERN MISMATCH on pass {} of {}: {} of the {} sectors read back did not \
             carry the expected pattern. {} of {} sectors were read back, {:.4}% of the \
             medium.",
            pass, passes, mismatched, verified, verified, total, coverage * 100.0
        ),
        Verdict::ExhaustivePatternMatch => format!(
            "Pass {} of {}: all {} sectors of the medium were read back and every one \
             carried the expected pattern. Coverage 100.0000%.",
            pass, passes, verified
        ),
        Verdict::SampledPatternMatch => format!(
            "Pass {} of {}: {} of {} sectors were read back and every one carried the \
             expected pattern. Coverage {:.4}% of the medium.",
            pass,
            passes,
            verified,
            total,
            coverage * 100.0
        ),
    };
    if exhaustive {
        head
    } else {
        format!(
            "{} The longest run of consecutive sectors this sample did not touch is \
             {} sectors ({} bytes): an unwiped region of that size, positioned between \
             two sample points, would produce this same verdict with zero mismatches. \
             {} {}",
            head,
            largest_unsampled_run,
            largest_unsampled_run * sector_bytes as u64,
            SAMPLING_IS_NOT_PROOF,
            SAMPLE_POSITIONS_ARE_PUBLIC
        )
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

fn compare_sector(gen: &PatternGen, lba: u64, got: &[u8], expect: &mut [u8]) -> Option<Mismatch> {
    gen.fill_sector(lba, expect);
    let mut first: Option<(u32, u8, u8)> = None;
    let mut differing = 0u32;
    for (i, (g, e)) in got.iter().zip(expect.iter()).enumerate() {
        if g != e {
            differing += 1;
            if first.is_none() {
                first = Some((i as u32, *e, *g));
            }
        }
    }
    first.map(|(off, e, g)| Mismatch {
        lba,
        first_diff_offset: off,
        expected: e,
        found: g,
        differing_bytes: differing,
    })
}

/// Read back the sampling plan's sectors for one 1-based pass and compare each
/// against the pattern that pass wrote.
///
/// Sectors are read one at a time, on purpose: a sampled sector is a point
/// measurement and reading its neighbours to fill a chunk would mean a device could
/// satisfy the check by writing only the ranges around the sample points. One sector
/// per read is slower and is what the claim says happened.
pub fn verify_pass<D>(
    dev: &mut D,
    cfg: &WipeConfig,
    pass: u32,
    policy: &SamplingPolicy,
) -> Result<VerifyReport, WipeError>
where
    D: SectorIo + ?Sized,
{
    let caps = dev.capabilities()?;
    let plan = SamplingPlan::new(policy, &caps)?;
    let gen = PatternGen::new(&cfg.seed, cfg.method, pass, caps.sector_bytes)?;
    let sb = caps.sector_bytes as usize;

    let mut got = vec![0u8; sb];
    let mut expect = vec![0u8; sb];
    let mut mismatches: Vec<Mismatch> = Vec::new();
    let mut mismatched_sectors = 0u64;
    let mut verified = 0u64;
    let mut digest = Keccak::shake128();
    digest.absorb(SAMPLING_DOMAIN);

    let t0 = Instant::now();
    let k = policy.sectors_per_mib.max(1) as u64;
    // The blind spot, measured as the sample is taken: the longest run of
    // consecutive sectors between two sampled LBAs. `prev` starts as None so the
    // head of the medium counts, and the tail after the last sample is added below.
    let mut prev: Option<u64> = None;
    let mut largest_unsampled_run_sectors = 0u64;
    for region in 0..plan.regions {
        let first = region * plan.region_sectors;
        let len = core::cmp::min(plan.region_sectors, caps.sector_count - first);
        for lba in sample_region(
            &cfg.seed,
            cfg.method,
            pass,
            region,
            first,
            len,
            core::cmp::min(k, len),
        ) {
            dev.read_sectors(lba, &mut got)?;
            digest.absorb(&lba.to_le_bytes());
            let run = match prev {
                Some(p) => lba.saturating_sub(p).saturating_sub(1),
                None => lba,
            };
            if run > largest_unsampled_run_sectors {
                largest_unsampled_run_sectors = run;
            }
            prev = Some(lba);
            verified += 1;
            if let Some(m) = compare_sector(&gen, lba, &got, &mut expect) {
                mismatched_sectors += 1;
                if mismatches.len() < MAX_RECORDED_MISMATCHES {
                    mismatches.push(m);
                }
            }
        }
    }
    let duration_ns = t0.elapsed().as_nanos();
    // The tail: every sector after the last sampled one is unsampled too.
    let tail = match prev {
        Some(p) => caps.sector_count.saturating_sub(p).saturating_sub(1),
        None => caps.sector_count,
    };
    if tail > largest_unsampled_run_sectors {
        largest_unsampled_run_sectors = tail;
    }

    let mut dbytes = [0u8; 32];
    digest.squeeze(&mut dbytes);
    let verdict = if mismatched_sectors == 0 {
        Verdict::SampledPatternMatch
    } else {
        Verdict::PatternMismatch
    };
    let coverage = verified as f64 / caps.sector_count as f64;

    Ok(VerifyReport {
        mode: "sampled_read_back",
        method_label: cfg.method.label(),
        pass,
        passes: cfg.method.pass_count(),
        pattern: gen.pattern().label(),
        seed_hex: cfg.seed.hex(),
        sector_bytes: caps.sector_bytes,
        sector_count: caps.sector_count,
        sectors_per_mib: policy.sectors_per_mib,
        regions: plan.regions,
        sectors_verified: verified,
        sectors_unverified: caps.sector_count - verified,
        bytes_verified: verified * sb as u64,
        coverage_fraction: coverage,
        largest_unsampled_run_sectors,
        mismatched_sectors,
        mismatches_truncated: mismatched_sectors > mismatches.len() as u64,
        mismatches,
        duration_ns,
        verdict,
        claim: claim_text(
            verdict,
            verified,
            caps.sector_count,
            coverage,
            mismatched_sectors,
            pass,
            cfg.method.pass_count(),
            false,
            largest_unsampled_run_sectors,
            caps.sector_bytes,
        ),
        sample_digest_hex: hex(&dbytes),
    })
}

/// Read back **every** sector and compare it. The only verification in this module
/// that supports a statement about the whole medium.
///
/// Measured at 0.480 s over 524,288 sectors, one sequential read of the image. At
/// that price the sampled path's 0.478 s saving buys a materially weaker claim; on a
/// 1 TB drive the trade reverses and the sampled path is the only one that finishes.
pub fn verify_pass_exhaustive<D>(
    dev: &mut D,
    cfg: &WipeConfig,
    pass: u32,
    chunk_sectors: u32,
) -> Result<VerifyReport, WipeError>
where
    D: SectorIo + ?Sized,
{
    let caps = dev.capabilities()?;
    if caps.sector_bytes == 0 || caps.sector_count == 0 {
        return Err(WipeError::DegenerateGeometry {
            sector_bytes: caps.sector_bytes,
            sector_count: caps.sector_count,
        });
    }
    let gen = PatternGen::new(&cfg.seed, cfg.method, pass, caps.sector_bytes)?;
    let sb = caps.sector_bytes as usize;
    let chunk = chunk_sectors.max(1);

    let mut got = vec![0u8; chunk as usize * sb];
    let mut expect = vec![0u8; sb];
    let mut mismatches: Vec<Mismatch> = Vec::new();
    let mut mismatched_sectors = 0u64;

    let t0 = Instant::now();
    let mut lba = 0u64;
    while lba < caps.sector_count {
        let n = core::cmp::min(chunk as u64, caps.sector_count - lba) as u32;
        let slice = &mut got[..n as usize * sb];
        dev.read_sectors(lba, slice)?;
        for (i, sector) in slice.chunks(sb).enumerate() {
            if let Some(m) = compare_sector(&gen, lba + i as u64, sector, &mut expect) {
                mismatched_sectors += 1;
                if mismatches.len() < MAX_RECORDED_MISMATCHES {
                    mismatches.push(m);
                }
            }
        }
        lba += n as u64;
    }
    let duration_ns = t0.elapsed().as_nanos();

    let verdict = if mismatched_sectors == 0 {
        Verdict::ExhaustivePatternMatch
    } else {
        Verdict::PatternMismatch
    };

    Ok(VerifyReport {
        mode: "exhaustive_read_back",
        method_label: cfg.method.label(),
        pass,
        passes: cfg.method.pass_count(),
        pattern: gen.pattern().label(),
        seed_hex: cfg.seed.hex(),
        sector_bytes: caps.sector_bytes,
        sector_count: caps.sector_count,
        sectors_per_mib: 0,
        regions: 1,
        sectors_verified: caps.sector_count,
        sectors_unverified: 0,
        bytes_verified: caps.sector_count * sb as u64,
        coverage_fraction: 1.0,
        largest_unsampled_run_sectors: 0,
        mismatched_sectors,
        mismatches_truncated: mismatched_sectors > mismatches.len() as u64,
        mismatches,
        duration_ns,
        verdict,
        claim: claim_text(
            verdict,
            caps.sector_count,
            caps.sector_count,
            1.0,
            mismatched_sectors,
            pass,
            cfg.method.pass_count(),
            true,
            0,
            caps.sector_bytes,
        ),
        sample_digest_hex: hex(&sha3_256(&[
            b"SENTINELWIPE/verify-exhaustive/v1",
            &caps.sector_count.to_le_bytes(),
        ])),
    })
}

/// Exact whole-medium Shannon entropy, read back in chunks.
///
/// This is the figure `demo_script.md` narrates at 0:30 and it is measured over
/// every byte, exactly as `fixtures/corpus.py` measures the manifest's 7.0617. It is
/// **not** the strided per-frame sample in [`crate::telemetry::entropy_sampled`], and
/// the two must never be subtracted from one another.
pub fn medium_entropy<D>(dev: &mut D, chunk_sectors: u32) -> Result<(f64, u64), WipeError>
where
    D: SectorIo + ?Sized,
{
    let caps = dev.capabilities()?;
    if caps.sector_bytes == 0 || caps.sector_count == 0 {
        return Err(WipeError::DegenerateGeometry {
            sector_bytes: caps.sector_bytes,
            sector_count: caps.sector_count,
        });
    }
    let sb = caps.sector_bytes as usize;
    let chunk = chunk_sectors.max(1);
    let mut buf = vec![0u8; chunk as usize * sb];
    let mut hist = ByteHistogram::new();
    let mut lba = 0u64;
    while lba < caps.sector_count {
        let n = core::cmp::min(chunk as u64, caps.sector_count - lba) as u32;
        let slice = &mut buf[..n as usize * sb];
        dev.read_sectors(lba, slice)?;
        hist.add(slice);
        lba += n as u64;
    }
    Ok((hist.shannon_bits_per_byte(), hist.total()))
}

/// Everything a wipe job produces: what was written, and what was read back to
/// support it.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedWipeReport {
    pub wipe: WipeReport,
    pub verifications: Vec<VerifyReport>,
    /// True only when every pass's verification returned a match. A certificate that
    /// says a wipe succeeded reads this field, never the write path's return value.
    pub all_passes_verified: bool,
}

/// Write each pass, then read it back before the next pass overwrites it.
///
/// The ordering is the whole point. Verifying only the last pass of a three-pass
/// method would leave passes 1 and 2 as unverified assertions, and the certificate
/// would be claiming three passes on the evidence of one.
pub fn wipe_verified<D, S>(
    dev: &mut D,
    cfg: &WipeConfig,
    policy: &SamplingPolicy,
    tm: &mut Telemetry<S>,
) -> Result<VerifiedWipeReport, WipeError>
where
    D: SectorIo + ?Sized,
    S: EventSink,
{
    let id = dev.identify();
    let caps = dev.capabilities()?;
    let t0 = Instant::now();
    let mut passes = Vec::new();
    let mut verifications = Vec::new();
    for pass in 1..=cfg.method.pass_count() {
        let r = crate::passes::run_pass(dev, cfg, pass, tm)?;
        tm.end_pass(pass);
        passes.push(r);
        verifications.push(verify_pass(dev, cfg, pass, policy)?);
    }
    let bytes: u64 = passes.iter().map(|p| p.bytes_written).sum();
    let wipe = WipeReport {
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

/// Convenience for a caller that has bytes rather than a device: SHAKE-128 of a
/// buffer, used by the measurement runs to prove two wipes produced identical media.
pub fn digest_hex(data: &[u8]) -> String {
    let mut out = [0u8; 32];
    shake128(&[data], &mut out);
    hex(&out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passes::stub::MemDevice;
    use crate::passes::{overwrite, shannon_bits_per_byte};
    use crate::telemetry::{NullSink, Telemetry};

    const SB: u32 = 512;
    const SECTORS_PER_MIB: u64 = 2048;

    fn wiped(method: Method, run_id: &str, sectors: u64) -> (MemDevice, WipeConfig) {
        let cfg = WipeConfig::new(method, Seed::from_run_id(run_id));
        let mut dev = MemDevice::new(SB, sectors);
        let caps = dev.capabilities().unwrap();
        let mut tm = Telemetry::start(cfg.telemetry_spec(&dev.identify(), &caps), NullSink, None);
        overwrite(&mut dev, &cfg, &mut tm).unwrap();
        (dev, cfg)
    }

    // -- the plan ---------------------------------------------------------

    #[test]
    fn the_plan_arithmetic_is_exact() {
        let caps = Capabilities {
            medium: crate::passes::Medium::Image,
            sector_bytes: SB,
            sector_count: 4 * SECTORS_PER_MIB,
            writable: true,
        };
        let plan = SamplingPlan::new(&SamplingPolicy::default(), &caps).unwrap();
        assert_eq!(plan.region_sectors, SECTORS_PER_MIB);
        assert_eq!(plan.regions, 4);
        assert_eq!(plan.sectors_to_sample, 16);
        // 16 of 8192 sectors: 0.1953125% of the medium, and the report says so.
        assert_eq!(plan.coverage_fraction, 16.0 / 8192.0);
        assert!((plan.coverage_fraction - 0.001953125).abs() < 1e-15);
    }

    #[test]
    fn a_short_final_region_is_counted_not_rounded() {
        let caps = Capabilities {
            medium: crate::passes::Medium::Image,
            sector_bytes: SB,
            sector_count: SECTORS_PER_MIB + 3, // one full region plus three sectors
            writable: true,
        };
        let plan = SamplingPlan::new(&SamplingPolicy::default(), &caps).unwrap();
        assert_eq!(plan.regions, 2);
        // The short region holds 3 sectors and 4 were asked for: it contributes 3.
        assert_eq!(plan.sectors_to_sample, 7);
    }

    #[test]
    fn sample_positions_are_deterministic_distinct_sorted_and_in_range() {
        let seed = Seed::from_run_id("plan");
        let a = sample_region(&seed, Method::SeededRandom, 1, 0, 0, SECTORS_PER_MIB, 4);
        let b = sample_region(&seed, Method::SeededRandom, 1, 0, 0, SECTORS_PER_MIB, 4);
        assert_eq!(a, b, "the same seed must name the same sectors");
        assert_eq!(a.len(), 4);
        let mut sorted = a.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, a, "positions must be sorted and duplicate-free");
        assert!(a.iter().all(|&l| l < SECTORS_PER_MIB));
    }

    #[test]
    fn sample_positions_move_with_seed_pass_method_and_region() {
        let s1 = Seed::from_run_id("x");
        let s2 = Seed::from_run_id("y");
        let base = sample_region(&s1, Method::ThreePass, 1, 0, 0, SECTORS_PER_MIB, 8);
        assert_ne!(base, sample_region(&s2, Method::ThreePass, 1, 0, 0, SECTORS_PER_MIB, 8));
        assert_ne!(base, sample_region(&s1, Method::ThreePass, 2, 0, 0, SECTORS_PER_MIB, 8));
        assert_ne!(base, sample_region(&s1, Method::SeededRandom, 1, 0, 0, SECTORS_PER_MIB, 8));
        let other_region =
            sample_region(&s1, Method::ThreePass, 1, 1, SECTORS_PER_MIB, SECTORS_PER_MIB, 8);
        let shifted: Vec<u64> = other_region.iter().map(|l| l - SECTORS_PER_MIB).collect();
        assert_ne!(base, shifted, "every region must draw its own positions");
    }

    #[test]
    fn asking_for_more_sectors_than_a_region_holds_returns_all_of_them() {
        let seed = Seed::from_run_id("all");
        let got = sample_region(&seed, Method::ZeroFill, 1, 0, 100, 4, 9);
        assert_eq!(got, vec![100, 101, 102, 103]);
    }

    #[test]
    fn the_sampler_covers_a_region_evenly_enough_to_be_called_uniform() {
        // Rejection sampling, not a raw modulo. Over 512 regions x 8 draws the two
        // halves of a region should be close to even; a modulo bias on a 2048 bound
        // would not show here, but a construction error that anchored draws to low
        // indices would.
        let seed = Seed::from_run_id("uniformity");
        let mut low = 0u32;
        let mut high = 0u32;
        for region in 0..512u64 {
            for lba in sample_region(
                &seed,
                Method::SeededRandom,
                1,
                region,
                0,
                SECTORS_PER_MIB,
                8,
            ) {
                if lba < SECTORS_PER_MIB / 2 {
                    low += 1;
                } else {
                    high += 1;
                }
            }
        }
        assert_eq!(low + high, 4096);
        let skew = (low as f64 - high as f64).abs() / 4096.0;
        assert!(skew < 0.06, "half-region skew {:.4} over 4096 draws", skew);
    }

    // -- detection arithmetic ---------------------------------------------

    #[test]
    fn detection_probability_is_the_hypergeometric_complement() {
        assert_eq!(detection_probability(2048, 4, 0), 0.0);
        assert_eq!(detection_probability(2048, 4, 2048), 1.0);
        // One bad sector in a region, four drawn: 4/2048.
        let one = detection_probability(2048, 4, 1);
        assert!((one - 4.0 / 2048.0).abs() < 1e-12, "{}", one);
        // A 64 KiB unwritten run is 128 sectors: the module header quotes 0.2277.
        let run = detection_probability(2048, 4, 128);
        assert!((run - 0.227675).abs() < 1e-6, "{:.6}", run);
        // Monotone in the size of the failure.
        assert!(detection_probability(2048, 4, 10) > detection_probability(2048, 4, 5));
        // Monotone in the sampling rate.
        assert!(detection_probability(2048, 64, 8) > detection_probability(2048, 4, 8));
    }

    // -- verification against a real pass ---------------------------------

    #[test]
    fn a_correct_seeded_pass_verifies_and_reports_its_coverage() {
        let (mut dev, cfg) = wiped(Method::SeededRandom, "verify-ok", 4 * SECTORS_PER_MIB);
        let rep = verify_pass(&mut dev, &cfg, 1, &SamplingPolicy::default()).unwrap();
        assert_eq!(rep.verdict, Verdict::SampledPatternMatch);
        assert_eq!(rep.verdict.code(), "PATTERN_CONFIRMED_ON_SAMPLE");
        assert_eq!(rep.sectors_verified, 16);
        assert_eq!(rep.sectors_unverified, 8192 - 16);
        assert_eq!(rep.bytes_verified, 16 * 512);
        assert_eq!(rep.mismatched_sectors, 0);
        assert!((rep.coverage_fraction - 0.001953125).abs() < 1e-15);
        assert!(rep.claim.contains("SAMPLING IS NOT PROOF"));
        assert!(rep.claim.contains("0.1953%"));
        assert!(rep.claim.contains("adversarial firmware"));
        assert_eq!(rep.sample_digest_hex.len(), 64);
        assert_eq!(rep.mode, "sampled_read_back");
    }

    #[test]
    fn a_zero_fill_pass_verifies_against_zeros() {
        let (mut dev, cfg) = wiped(Method::ZeroFill, "verify-zero", SECTORS_PER_MIB);
        let rep = verify_pass(&mut dev, &cfg, 1, &SamplingPolicy::default()).unwrap();
        assert!(rep.verdict.is_match());
        assert_eq!(rep.pattern, "zeros_0x00");
    }

    #[test]
    fn verification_fails_when_a_sampled_sector_was_not_written() {
        let (mut dev, cfg) = wiped(Method::SeededRandom, "verify-bad", 2 * SECTORS_PER_MIB);
        let policy = SamplingPolicy::default();
        // Corrupt a sector the plan will actually read.
        let target = sample_region(&cfg.seed, cfg.method, 1, 0, 0, SECTORS_PER_MIB, 4)[2];
        let off = target as usize * 512;
        dev.data[off..off + 512].fill(0x00);

        let rep = verify_pass(&mut dev, &cfg, 1, &policy).unwrap();
        assert_eq!(rep.verdict, Verdict::PatternMismatch);
        assert_eq!(rep.mismatched_sectors, 1);
        assert_eq!(rep.mismatches[0].lba, target);
        assert!(rep.mismatches[0].differing_bytes > 500);
        assert!(rep.claim.starts_with("PATTERN MISMATCH"));
        assert!(!rep.mismatches_truncated);
    }

    #[test]
    fn verifying_the_wrong_pass_of_a_three_pass_method_fails() {
        // The medium carries pass 3. Checking it against pass 2's pattern must not
        // pass: this is what makes per-pass verification meaningful.
        let (mut dev, cfg) = wiped(Method::ThreePass, "wrong-pass", SECTORS_PER_MIB);
        let ok = verify_pass(&mut dev, &cfg, 3, &SamplingPolicy::default()).unwrap();
        assert!(ok.verdict.is_match());
        let bad = verify_pass(&mut dev, &cfg, 2, &SamplingPolicy::default()).unwrap();
        assert_eq!(bad.verdict, Verdict::PatternMismatch);
    }

    /// The test that proves the caveat rather than asserting it.
    ///
    /// One sector of an 8 MiB medium is left unwritten. The sampled plan does not
    /// name it, so the sampled verification returns a clean match — a true statement
    /// about the sectors it read, and a false impression of the medium if the caveat
    /// were dropped. The exhaustive read-back finds it.
    #[test]
    fn sampling_misses_a_single_bad_sector_that_exhaustive_read_back_catches() {
        let (mut dev, cfg) = wiped(Method::SeededRandom, "miss", 8 * SECTORS_PER_MIB);
        let policy = SamplingPolicy::default();

        let mut sampled: Vec<u64> = Vec::new();
        for region in 0..8u64 {
            sampled.extend(sample_region(
                &cfg.seed,
                cfg.method,
                1,
                region,
                region * SECTORS_PER_MIB,
                SECTORS_PER_MIB,
                4,
            ));
        }
        assert_eq!(sampled.len(), 32);
        let victim = (0..8 * SECTORS_PER_MIB)
            .find(|l| !sampled.contains(l))
            .expect("32 of 16384 sectors are sampled; the rest are not");
        let off = victim as usize * 512;
        dev.data[off..off + 512].fill(0xa5);

        let sampled_rep = verify_pass(&mut dev, &cfg, 1, &policy).unwrap();
        assert_eq!(
            sampled_rep.verdict,
            Verdict::SampledPatternMatch,
            "the sample happened to include the victim; the test needs a different seed"
        );
        assert_eq!(sampled_rep.sectors_unverified, 16384 - 32);

        let full = verify_pass_exhaustive(&mut dev, &cfg, 1, 256).unwrap();
        assert_eq!(full.verdict, Verdict::PatternMismatch);
        assert_eq!(full.mismatched_sectors, 1);
        assert_eq!(full.mismatches[0].lba, victim);
        assert_eq!(full.coverage_fraction, 1.0);
        assert_eq!(full.sectors_unverified, 0);
        assert!(!full.claim.contains("SAMPLING IS NOT PROOF"));
        assert!(full.claim.starts_with("PATTERN MISMATCH"));
        assert!(full.claim.contains("16384 of 16384 sectors were read back, 100.0000%"));
    }

    #[test]
    fn the_recorded_mismatch_list_is_capped_and_says_so() {
        let (mut dev, cfg) = wiped(Method::SeededRandom, "cap", 2 * SECTORS_PER_MIB);
        for b in dev.data.iter_mut() {
            *b = 0;
        }
        let full = verify_pass_exhaustive(&mut dev, &cfg, 1, 256).unwrap();
        assert_eq!(full.mismatched_sectors, 4096);
        assert_eq!(full.mismatches.len(), MAX_RECORDED_MISMATCHES);
        assert!(full.mismatches_truncated);
    }

    #[test]
    fn every_pass_of_a_three_pass_wipe_is_verified_before_the_next_overwrites_it() {
        let cfg = WipeConfig::new(Method::ThreePass, Seed::from_run_id("interleaved"));
        let mut dev = MemDevice::new(SB, 2 * SECTORS_PER_MIB);
        let caps = dev.capabilities().unwrap();
        let mut tm = Telemetry::start(cfg.telemetry_spec(&dev.identify(), &caps), NullSink, None);
        let rep = wipe_verified(&mut dev, &cfg, &SamplingPolicy::default(), &mut tm).unwrap();
        assert_eq!(rep.verifications.len(), 3);
        assert!(rep.all_passes_verified);
        assert_eq!(rep.verifications[0].pattern, "zeros_0x00");
        assert_eq!(rep.verifications[1].pattern, "ones_0xff");
        assert_eq!(rep.verifications[2].pattern, "shake128_seeded_stream");
        assert_eq!(rep.wipe.bytes_written, 3 * 2 * 1024 * 1024);
        for v in &rep.verifications {
            assert_eq!(v.sectors_verified, 8);
            assert_eq!(v.mismatched_sectors, 0);
        }
    }

    #[test]
    fn a_device_that_ignores_writes_is_caught_rather_than_believed() {
        // The failure CLAUDE.md rule 5 is about, in its host-visible form: the write
        // path returned success and the medium did not change.
        let cfg = WipeConfig::new(Method::SeededRandom, Seed::from_run_id("liar"));
        let mut dev = MemDevice::new(SB, SECTORS_PER_MIB);
        let before = dev.data.clone();
        // No wipe is run at all; the caller is pretending one succeeded.
        let rep = verify_pass(&mut dev, &cfg, 1, &SamplingPolicy::default()).unwrap();
        assert_eq!(rep.verdict, Verdict::PatternMismatch);
        assert_eq!(rep.mismatched_sectors, 4);
        assert_eq!(dev.data, before);
    }

    // -- entropy ----------------------------------------------------------

    #[test]
    fn medium_entropy_reads_the_whole_medium() {
        let (mut dev, _) = wiped(Method::ZeroFill, "e-zero", SECTORS_PER_MIB);
        let (h, n) = medium_entropy(&mut dev, 256).unwrap();
        assert_eq!(n, 1 << 20);
        assert_eq!(h, 0.0, "a zero-filled medium has no entropy at all");

        let (mut dev, _) = wiped(Method::SeededRandom, "e-rand", 2 * SECTORS_PER_MIB);
        let (h, n) = medium_entropy(&mut dev, 256).unwrap();
        assert_eq!(n, 2 << 20);
        assert!(h > 7.9999, "seeded pass entropy {:.6}", h);
        assert_eq!(h, shannon_bits_per_byte(&dev.data), "chunked histogram must equal a single pass");
    }

    #[test]
    fn degenerate_geometry_is_refused_by_every_entry_point() {
        let cfg = WipeConfig::new(Method::ZeroFill, Seed::from_run_id("d"));
        let mut dev = MemDevice::new(512, 0);
        assert!(matches!(
            verify_pass(&mut dev, &cfg, 1, &SamplingPolicy::default()).unwrap_err(),
            WipeError::DegenerateGeometry { .. }
        ));
        assert!(matches!(
            verify_pass_exhaustive(&mut dev, &cfg, 1, 8).unwrap_err(),
            WipeError::DegenerateGeometry { .. }
        ));
        assert!(matches!(
            medium_entropy(&mut dev, 8).unwrap_err(),
            WipeError::DegenerateGeometry { .. }
        ));
    }

    #[test]
    fn a_higher_sampling_rate_reads_more_and_says_so() {
        let (mut dev, cfg) = wiped(Method::SeededRandom, "rates", 4 * SECTORS_PER_MIB);
        let mut last = 0u64;
        for &k in &[1u32, 4, 16, 64] {
            let rep = verify_pass(&mut dev, &cfg, 1, &SamplingPolicy::per_mib(k)).unwrap();
            assert_eq!(rep.sectors_verified, 4 * k as u64);
            assert!(rep.sectors_verified > last);
            assert_eq!(rep.sectors_per_mib, k);
            assert!((rep.coverage_fraction - (4.0 * k as f64) / 8192.0).abs() < 1e-15);
            last = rep.sectors_verified;
        }
    }

    // -- the blind spot, measured rather than described ------------------

    /// Every LBA the shipped sampled plan reads, in the order it reads them.
    /// Re-derived here from the seed alone, the way a third party would.
    fn planned_lbas(cfg: &WipeConfig, policy: &SamplingPolicy, caps: &Capabilities) -> Vec<u64> {
        let plan = SamplingPlan::new(policy, caps).unwrap();
        let k = policy.sectors_per_mib.max(1) as u64;
        let mut out = Vec::new();
        for region in 0..plan.regions {
            let first = region * plan.region_sectors;
            let len = core::cmp::min(plan.region_sectors, caps.sector_count - first);
            out.extend(sample_region(
                &cfg.seed,
                cfg.method,
                1,
                region,
                first,
                len,
                core::cmp::min(k, len),
            ));
        }
        out
    }

    #[test]
    fn a_region_left_unwiped_between_sample_points_survives_a_confirmed_sample() {
        //! THE LIMITATION, AS A TEST RATHER THAN A PARAGRAPH.
        //!
        //! An adversarial verifier built this against the real fixture: the
        //! single-pass-random wiped image with one planted file (208,084 bytes,
        //! 0.0776% of the medium) restored between sample points. The shipped
        //! sampled verification returned PATTERN_CONFIRMED_ON_SAMPLE, zero
        //! mismatches, and a sample digest identical to the clean run — while the
        //! project's own carver recovered that file byte-exact from the same image.
        //!
        //! It is arithmetic, not a bug: 4 sampled sectors per MiB is 0.195% coverage
        //! and the hypergeometric table in this module's header says exactly what
        //! that detects. But an arithmetic consequence discovered on stage is worth
        //! nothing, so it is asserted here in both directions — the sampled verdict
        //! that misses it, AND the exhaustive verdict that catches it — and the
        //! measured size of the blind spot is published in the report's `limits`.
        let sectors = 8 * SECTORS_PER_MIB;
        let (mut dev, cfg) = wiped(Method::SeededRandom, "blind-spot/v1", sectors);
        let policy = SamplingPolicy::default();
        let caps = dev.capabilities().unwrap();

        // The control: the medium really is wiped, and the sample says so.
        let clean = verify_pass(&mut dev, &cfg, 1, &policy).unwrap();
        assert_eq!(clean.verdict, Verdict::SampledPatternMatch);
        assert_eq!(clean.mismatched_sectors, 0);
        assert_eq!(
            verify_pass_exhaustive(&mut dev, &cfg, 1, 256).unwrap().verdict,
            Verdict::ExhaustivePatternMatch,
            "the exhaustive control must pass before its failure below means anything"
        );

        // The largest run of sectors the plan never touches, re-derived from the
        // seed and cross-checked against the figure the report publishes.
        let lbas = planned_lbas(&cfg, &policy, &caps);
        let mut best = (0u64, 0u64); // (start, len)
        let mut prev: Option<u64> = None;
        for &lba in &lbas {
            let (start, len) = match prev {
                Some(p) => (p + 1, lba.saturating_sub(p).saturating_sub(1)),
                None => (0, lba),
            };
            if len > best.1 {
                best = (start, len);
            }
            prev = Some(lba);
        }
        if let Some(p) = prev {
            let tail = caps.sector_count.saturating_sub(p).saturating_sub(1);
            if tail > best.1 {
                best = (p + 1, tail);
            }
        }
        assert_eq!(
            clean.largest_unsampled_run_sectors, best.1,
            "the published blind-spot figure disagrees with the plan it came from"
        );
        assert!(
            best.1 >= 64,
            "only {} unsampled sectors in a row; this fixture cannot host the attack",
            best.1
        );

        // Restore "planted" bytes into that gap. Nothing else on the medium moves.
        let restored = core::cmp::min(best.1, 64);
        let plant = vec![0x5Au8; (restored * caps.sector_bytes as u64) as usize];
        dev.write_sectors(best.0, &plant).unwrap();

        // THE SAMPLED VERDICT DOES NOT NOTICE, and it does not notice silently:
        // same verdict, zero mismatches, and byte-identical sample digest.
        let after = verify_pass(&mut dev, &cfg, 1, &policy).unwrap();
        assert_eq!(after.verdict, Verdict::SampledPatternMatch);
        assert_eq!(after.mismatched_sectors, 0);
        assert_eq!(after.sectors_verified, clean.sectors_verified);
        assert_eq!(after.sample_digest_hex, clean.sample_digest_hex);
        assert_eq!(after.verdict.code(), "PATTERN_CONFIRMED_ON_SAMPLE");

        // THE EXHAUSTIVE VERDICT DOES. This is the upgrade `--verify exhaustive`
        // buys, stated as a measurement rather than as advice.
        let ex = verify_pass_exhaustive(&mut dev, &cfg, 1, 256).unwrap();
        assert_eq!(ex.verdict, Verdict::PatternMismatch);
        assert_eq!(ex.verdict.code(), "PATTERN_MISMATCH");
        assert_eq!(
            ex.mismatched_sectors, restored,
            "every restored sector must be caught, and no other"
        );

        // And the claim a certificate carries names the blind spot in bytes.
        assert!(
            after
                .claim
                .contains(&format!("{} sectors", after.largest_unsampled_run_sectors)),
            "the per-pass claim does not state the size of its own blind spot: {}",
            after.claim
        );
    }

    #[test]
    fn an_exhaustive_read_back_has_no_blind_spot_to_publish() {
        let (mut dev, cfg) = wiped(Method::SeededRandom, "blind-spot/exhaustive", 4 * SECTORS_PER_MIB);
        let ex = verify_pass_exhaustive(&mut dev, &cfg, 1, 256).unwrap();
        assert_eq!(ex.largest_unsampled_run_sectors, 0);
        assert_eq!(ex.coverage_fraction, 1.0);
        assert_eq!(ex.sectors_unverified, 0);
    }

}

// ---------------------------------------------------------------------------
// The measurement run
// ---------------------------------------------------------------------------

/// Everything `docs/` will quote about this module, measured against a copy of the
/// fixture rather than against a stub.
///
/// **Ignored by default and it must stay ignored.** It is the only test in this
/// crate that opens a writable descriptor on a file, and it opens it only through
/// [`crate::passes::stub::guard::authorize_write`], which refuses anything not
/// inode-contained in the directory named by `SENTINELWIPE_WIPE_SCRATCH` and
/// refuses the source workspace outright. `out/fixture.img` is read, never opened
/// for writing, and every wipe runs against a byte copy in the scratch root.
///
/// ```text
/// SENTINELWIPE_WIPE_SCRATCH=/path/to/scratch \
///   cargo test --release -p sentinelwipe-wipe --lib -- --ignored --nocapture measure_
/// ```
#[cfg(all(test, unix))]
mod measure {
    use super::*;
    use crate::passes::stub::{guard, ScratchImage};
    use crate::passes::{
        crypto_erase_demonstration, sha3_256, Method, Seed, WipeConfig,
    };
    use crate::telemetry::{NullSink, Telemetry};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    const SECTOR: u32 = 512;
    /// `fixtures/build_image.py` measured this over all 268,435,456 bytes with
    /// `math.fsum`. The Rust estimator must land on it.
    const FIXTURE_ENTROPY: f64 = 7.061690499603866;

    fn fixture_path() -> PathBuf {
        guard::workspace_root().join("out").join("fixture.img")
    }

    /// Byte copy, guarded. Explicitly a read/write loop rather than `std::io::copy`,
    /// which on macOS delegates to `fcopyfile` and can produce an APFS clone --
    /// a clone would make the first write to every block pay a copy-on-write break
    /// that has nothing to do with the wipe being measured.
    fn copy_into_scratch(src: &Path, dst: &Path) -> PathBuf {
        let resolved = guard::authorize_write(dst).expect("scratch guard refused the target");
        let mut r = std::fs::File::open(src)
            .unwrap_or_else(|e| panic!("fixture {}: {}", src.display(), e));
        let mut w = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&resolved)
            .unwrap_or_else(|e| panic!("{}: {}", resolved.display(), e));
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = r.read(&mut buf).expect("read fixture");
            if n == 0 {
                break;
            }
            w.write_all(&buf[..n]).expect("write scratch copy");
        }
        w.sync_all().expect("fsync scratch copy");
        resolved
    }

    fn mib_s(bytes: u64, ns: u128) -> f64 {
        if ns == 0 {
            0.0
        } else {
            bytes as f64 / 1_048_576.0 / (ns as f64 / 1e9)
        }
    }

    #[test]
    #[ignore = "writes ~1 GiB into SENTINELWIPE_WIPE_SCRATCH; run with --ignored --nocapture"]
    fn measure_methods_against_a_scratchpad_copy_of_the_fixture() {
        let root = guard::scratch_root().expect("set SENTINELWIPE_WIPE_SCRATCH");
        println!("\nscratch root      {}", root.display());
        println!("fixture           {}", fixture_path().display());

        // --- the before figure, and the cross-implementation check on it -----
        let base = copy_into_scratch(&fixture_path(), &root.join("phase3-baseline.img"));
        let mut dev = ScratchImage::open(&base, SECTOR).unwrap();
        let t = Instant::now();
        let (h_before, n) = medium_entropy(&mut dev, 2048).unwrap();
        println!(
            "\nBEFORE  {} bytes  entropy {:.15} bits/byte  ({:.2} s to scan)",
            n,
            h_before,
            t.elapsed().as_secs_f64()
        );
        println!("        manifest  {:.15}   delta {:.3e}", FIXTURE_ENTROPY, h_before - FIXTURE_ENTROPY);
        assert!(
            (h_before - FIXTURE_ENTROPY).abs() < 1e-9,
            "the Rust estimator disagrees with fixtures/corpus.py"
        );
        drop(dev);

        let seed = Seed::from_run_id("phase3-measurement");
        println!("\nseed              {}", seed.hex());

        for method in [Method::ZeroFill, Method::SeededRandom, Method::ThreePass] {
            let name = method.label();
            let img = copy_into_scratch(
                &fixture_path(),
                &root.join(format!("phase3-{}.img", method.id())),
            );
            let mut dev = ScratchImage::open(&img, SECTOR).unwrap();
            println!("\ntarget            {}", dev.path().display());
            let cfg = WipeConfig::new(method, seed);
            let caps = dev.capabilities().unwrap();
        let mut tm = Telemetry::start(cfg.telemetry_spec(&dev.identify(), &caps), NullSink, None);

            let rep = crate::passes::overwrite(&mut dev, &cfg, &mut tm).unwrap();
            let summary = tm.finish("complete");

            println!("\n=== {} ===", name);
            for p in &rep.passes {
                println!(
                    "  pass {}/{}  {:22}  {:>12} B  {:8.3} s  {:8.2} MiB/s  chunks {:>6} \
                     ({}->{} sectors, {} resizes)  max chunk {:.2} ms  sync {:.3} s",
                    p.pass,
                    p.passes,
                    p.pattern,
                    p.bytes_written,
                    p.duration_ns as f64 / 1e9,
                    mib_s(p.bytes_written, p.duration_ns),
                    p.chunk_writes,
                    p.chunk_sectors_first,
                    p.chunk_sectors_final,
                    p.chunk_resizes,
                    p.max_chunk_ns as f64 / 1e6,
                    p.sync_ns as f64 / 1e9,
                );
            }
            println!(
                "  TOTAL      {:>12} B  {:8.3} s  {:8.2} MiB/s",
                rep.bytes_written,
                rep.duration_ns as f64 / 1e9,
                mib_s(rep.bytes_written, rep.duration_ns)
            );
            println!(
                "  telemetry  {} events  {:.1} Hz achieved  max gap {:.1} ms  floor({} Hz) met: {}",
                summary.events,
                summary.achieved_hz,
                summary.max_gap_ms,
                crate::telemetry::MIN_RATE_HZ,
                summary.met_rate_floor
            );

            let (h_after, _) = medium_entropy(&mut dev, 2048).unwrap();
            println!(
                "  entropy    {:.9} -> {:.9} bits/byte  ({:+.9})",
                h_before,
                h_after,
                h_after - h_before
            );

            let last = method.pass_count();
            for k in [1u32, 4, 16, 64] {
                let v = verify_pass(&mut dev, &cfg, last, &SamplingPolicy::per_mib(k)).unwrap();
                println!(
                    "  verify {:>2}/MiB  {:>7} of {} sectors  coverage {:.6}%  {:>6.3} s  {}  digest {}",
                    k,
                    v.sectors_verified,
                    v.sector_count,
                    v.coverage_fraction * 100.0,
                    v.duration_ns as f64 / 1e9,
                    v.verdict.code(),
                    &v.sample_digest_hex[..16],
                );
                assert!(v.verdict.is_match(), "{}", v.claim);
            }
            let full = verify_pass_exhaustive(&mut dev, &cfg, last, 2048).unwrap();
            println!(
                "  verify all    {:>7} of {} sectors  coverage {:.6}%  {:>6.3} s  {}",
                full.sectors_verified,
                full.sector_count,
                full.coverage_fraction * 100.0,
                full.duration_ns as f64 / 1e9,
                full.verdict.code()
            );
            assert_eq!(full.verdict, Verdict::ExhaustivePatternMatch, "{}", full.claim);

            // Every earlier pass of a multi-pass method has already been overwritten
            // by the time the job ends, so it can only be verified in flight; that is
            // what wipe_verified does and what the interleaving test asserts.
            let mut whole = Vec::new();
            std::fs::File::open(&img)
                .unwrap()
                .read_to_end(&mut whole)
                .unwrap();
            println!("  sha3-256 of the wiped image  {}", crate::passes::hex(&sha3_256(&[&whole])));
        }

        // --- rule 6: the same seed must produce the same medium --------------
        let a = copy_into_scratch(&fixture_path(), &root.join("phase3-repro-a.img"));
        let b = copy_into_scratch(&fixture_path(), &root.join("phase3-repro-b.img"));
        let cfg = WipeConfig::new(Method::SeededRandom, seed);
        let mut digests = Vec::new();
        for p in [&a, &b] {
            let mut d = ScratchImage::open(p, SECTOR).unwrap();
            let dcaps = d.capabilities().unwrap();
            let mut tm =
                Telemetry::start(cfg.telemetry_spec(&d.identify(), &dcaps), NullSink, None);
            crate::passes::overwrite(&mut d, &cfg, &mut tm).unwrap();
            tm.finish("complete");
            let mut bytes = Vec::new();
            std::fs::File::open(p).unwrap().read_to_end(&mut bytes).unwrap();
            digests.push(crate::passes::hex(&sha3_256(&[&bytes])));
        }
        println!("\nreproducibility   run A {}", digests[0]);
        println!("                  run B {}", digests[1]);
        assert_eq!(digests[0], digests[1], "same seed produced different media");

        // --- crypto-erase, measured on real planted bytes --------------------
        let mut plain = vec![0u8; 1 << 20];
        {
            let mut f = std::fs::File::open(fixture_path()).unwrap();
            f.read_exact(&mut plain).unwrap();
        }
        let (cipher, rep) = crypto_erase_demonstration([0x5au8; 32], "fixture-first-mib", &plain);
        println!("\n=== {} ===", rep.operation);
        println!("  construction    {}", rep.demonstration_construction);
        println!("  object          {} bytes", rep.object_bytes);
        println!(
            "  entropy         plaintext {:.6} -> ciphertext {:.6} bits/byte",
            rep.entropy_plaintext_bits_per_byte, rep.entropy_ciphertext_bits_per_byte
        );
        println!(
            "  key             {} destroyed, {} bytes zeroed, fingerprint {}",
            rep.key_destroyed, rep.key_destruction.key_bytes_zeroed, rep.key_destruction.key_fingerprint_hex
        );
        println!(
            "  residual match  {:.8} of bytes recovered with a wrong key (chance alone: {:.8})",
            rep.residual_plaintext_match_fraction,
            1.0 / 256.0
        );
        assert!(rep.key_destroyed);
        assert_ne!(cipher, plain);
    }

    #[test]
    #[ignore = "reads out/fixture.img only; run with --ignored --nocapture"]
    fn measure_pattern_generation_throughput() {
        // Generation cost alone, with no device in the path: the ceiling the seeded
        // method can ever reach on this machine.
        let seed = Seed::from_run_id("gen-bench");
        for (label, method, pass) in [
            ("constant", Method::ZeroFill, 1u32),
            ("shake128", Method::SeededRandom, 1u32),
        ] {
            let gen = crate::passes::PatternGen::new(&seed, method, pass, SECTOR).unwrap();
            let mut buf = vec![0u8; 1 << 20];
            let t = Instant::now();
            let mut bytes = 0u64;
            for i in 0..64u64 {
                gen.fill_run(i * 2048, &mut buf).unwrap();
                bytes += buf.len() as u64;
            }
            let ns = t.elapsed().as_nanos();
            println!(
                "pattern {:9} {:>12} B  {:8.3} s  {:8.2} MiB/s",
                label,
                bytes,
                ns as f64 / 1e9,
                mib_s(bytes, ns)
            );
        }
    }
}
