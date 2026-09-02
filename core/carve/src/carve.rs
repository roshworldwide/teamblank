//! The carve driver: candidates in, recoveries out.
//!
//! This is the file the other four exist for. `signature::scan` says where an
//! object might begin, `structure::validate` says whether one really does and
//! where it stops, `confidence::confidence` scores what was found, and this
//! module runs them in that order, resolves the overlaps, and hands back a set
//! of [`Recovered`] records that map one-to-one onto the record shape frozen in
//! `docs/output_schema.md` §5.
//!
//! # CONTIGUOUS OBJECTS ONLY
//!
//! `bifragment.rs` exists and is partial. It is **deliberately deferred and is
//! not called from here** — not as a primary path and not as a fallback. Every
//! extent list this module produces has exactly one entry, so
//! `counts.by_assembly.reassembled` is 0 in every report it writes, and that
//! zero is the honest signal that reassembly was not attempted rather than
//! attempted and failed.
//!
//! The consequence is stated rather than hidden: a planted file split across a
//! gap is simply not recovered. On the frozen fixture that bounds this engine at
//! `ground_truth.reachability.contiguous` of the 40 planted files, and a run's
//! measured result is labelled *demonstrated recall (contiguous engine)*. The
//! reachability ceiling and the demonstrated recall are two different numbers
//! and this code never computes one from the other.
//!
//! # The one gate
//!
//! Admission is a single comparison: `confidence.total >= opts.min_confidence`,
//! and `min_confidence` defaults to [`MIN_CONFIDENCE`] read from `confidence.rs`
//! rather than to a literal. `Validation::valid` is reported on every record and
//! is **not** a second gate. Structural evidence reaches the decision only
//! through term 2 and its 0.35 weight, which is what keeps
//! [`STRUCTURAL_BREACH_POINT`] a meaningful and testable number: a hard `valid`
//! gate stacked on top would make the published score decorative.
//!
//! [`STRUCTURAL_BREACH_POINT`]: crate::confidence::STRUCTURAL_BREACH_POINT
//!
//! # Where the span comes from
//!
//! Three sources, in this order, and the record says which one was used:
//!
//! 1. **`Validation::end`** — the format walker parsed the object and reached
//!    its last byte. `assembly: "contiguous"`. This is the only span the carver
//!    treats as a recovery, and it is a claim the validator made, not a guess.
//!    Note that `end` can be `Some` on a rejection too (a JPEG that reached EOI
//!    but references an undefined Huffman table), which is why the assembly
//!    label follows `end` and not `valid`.
//! 2. **the scanner's footer** — no `end`, but the format publishes a
//!    terminator and `scan` resolved one in sequence. The span runs from the
//!    header to one past that terminator. `assembly: "signature-span"`.
//! 3. **the fallback window** — no `end` and no terminator (GZIP, MP4 and
//!    SQLITE publish none at all). See [`CarveOpts::residue_window`] for the
//!    policy and why the default is the adversarial one.
//!    `assembly: "signature-span"`.
//!
//! # Cost bound
//!
//! Each candidate's validator sees at most `signature::Signature::max_len`
//! bytes from the header — the same window `resolve_footer` already searches
//! for a terminator, published per row in the signature table. Without it a
//! spurious `PK\x03\x04` inside a compressed payload can send the ZIP walker
//! across the rest of the image, once per false header.

use crate::confidence::{
    confidence, kind_defines_footer, shannon_entropy, size_bounds, Confidence, MIN_CONFIDENCE,
    MIN_ENTROPY_SAMPLE, SIG_HEADER_AND_FOOTER, SIG_HEADER_MISMATCH, SIG_HEADER_ONLY,
    SIG_NO_FOOTER_DEFINED,
};
use crate::signature::{next_footer, scan, signature_for, Candidate, SIGNATURES};
use crate::structure::{validate, Validation};
use crate::Kind;

// ===========================================================================
// Options — every one of them is expressible on the `carve` command line,
// because the product claim is that the post-wipe carve runs with parameters
// byte-identical to the pre-wipe carve. A parameter that only exists in Rust
// cannot be shown to have been held constant.
// ===========================================================================

/// Everything that changes what the engine does. Nothing here is read from an
/// environment variable and nothing is a compile-time switch.
#[derive(Debug, Clone, PartialEq)]
pub struct CarveOpts {
    /// The admission gate. Defaults to [`MIN_CONFIDENCE`], read from
    /// `confidence.rs`. Exposed as `--min-confidence` so a run can be re-scored
    /// at a different gate and the report carries the gate it used.
    pub min_confidence: f64,

    /// Apply overlap suppression. Default `true`; `--no-dedup` turns it off, and
    /// the un-deduplicated record set is what the suppression rule is audited
    /// against. See [`carve`] for the rule.
    pub dedup: bool,

    /// Emit records that scored under the gate. Default `true`: the rejected
    /// population is the evidence the false-positive panel is built from, and
    /// dropping it would leave a report that cannot be challenged.
    pub report_rejected: bool,

    /// Span used for a candidate that has neither a validator `end` nor a
    /// terminator. `None` selects the per-kind default described below.
    ///
    /// **The default is deliberately adversarial.** It is
    /// `confidence::size_bounds(kind).full_lo` — the *shortest* span that earns
    /// full marks on term 4 for that kind, read from a shipped const rather than
    /// invented here. Handing an unbounded candidate the maximum size credit
    /// available makes every reported rejection a rejection the carver earned
    /// against the strongest form of that candidate, so the separation a run
    /// reports is a lower bound. Choosing the shortest such span is what keeps
    /// it cheap: a residue-heavy image costs kilobytes per false header, not
    /// megabytes.
    ///
    /// It is still a policy choice and `architecture.md` D2 says so. Only the
    /// adversarial ceiling — terms 3 and 4 pinned to 1.0 — is safe to quote
    /// against a challenge to it. `--residue-window <bytes>` overrides it for
    /// every kind at once so the sensitivity can be measured rather than argued.
    pub residue_window: Option<u64>,
}

impl Default for CarveOpts {
    fn default() -> CarveOpts {
        CarveOpts {
            min_confidence: MIN_CONFIDENCE,
            dedup: true,
            report_rejected: true,
            residue_window: None,
        }
    }
}

// ===========================================================================
// The record
// ===========================================================================

/// One physical byte range. A contiguous engine emits exactly one per record;
/// the field is a list because the schema is shared with a reassembling engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub offset: u64,
    pub length: u64,
}

/// How the byte range was established. The strings are the schema's own enum
/// values (`docs/output_schema.md` §5.3) and are written straight to the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assembly {
    /// One extent, ended by the structure validator.
    Contiguous,
    /// More than one extent, joined across a gap. **Never produced here** — the
    /// variant exists so the schema and the type agree, and so that a report
    /// showing `reassembled: 0` is showing a count and not a missing field.
    Reassembled,
    /// The structure validator established no end; the span is the signature
    /// layer's.
    SignatureSpan,
}

impl Assembly {
    pub fn as_str(&self) -> &'static str {
        match self {
            Assembly::Contiguous => "contiguous",
            Assembly::Reassembled => "reassembled",
            Assembly::SignatureSpan => "signature-span",
        }
    }
}

/// The signature layer's two observations, plus the named ladder rung term 1
/// landed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureObs {
    pub header_matched: bool,
    pub footer_defined: bool,
    pub footer_found: bool,
    pub ladder_rung: &'static str,
}

/// Machine-groupable rejection cause. The schema publishes exactly these two,
/// and both mean "scored under the gate" — which is why a candidate dropped by
/// overlap suppression is not emitted as a record at all: neither code would be
/// true of it, and inventing a third is a schema change.
pub const REASON_BELOW_GATE: &str = "below-min-confidence";
pub const REASON_BELOW_GATE_STRUCTURE_INVALID: &str = "below-min-confidence-structure-invalid";

/// One entry in the report's `candidates` array. Field for field, this is
/// `docs/output_schema.md` §5, so the JSON writer is mechanical.
#[derive(Debug, Clone, PartialEq)]
pub struct Recovered {
    pub kind: Kind,
    pub offset: u64,
    pub length: u64,
    pub extents: Vec<Extent>,
    pub assembly: Assembly,
    /// SHA-256 over exactly `length` bytes starting at `offset`, in logical
    /// order — the same bytes every term was scored on.
    pub sha256: String,
    pub signature: SignatureObs,
    pub structure: Validation,
    pub entropy_bits_per_byte: f64,
    pub entropy_sampled: bool,
    pub confidence: Confidence,
    pub admitted: bool,
    pub reason_code: Option<&'static str>,
    pub reason: Option<String>,
}

impl Recovered {
    /// `"<KIND>@<offset>"`. Stable within a run and the join key for the
    /// pre-wipe/post-wipe diff.
    pub fn id(&self) -> String {
        format!("{}@{}", self.kind.as_str(), self.offset)
    }

    /// One past the last byte of this record's span.
    pub fn end(&self) -> u64 {
        self.offset + self.length
    }
}

/// What one carve produced, including the numbers that describe the work rather
/// than the result. `scanned`, `suppressed` and `records.len()` are three
/// different counts and a report that prints only the last one cannot be
/// audited.
#[derive(Debug, Clone, PartialEq)]
pub struct CarveReport {
    /// Header matches returned by `signature::scan`, before any judgement.
    pub scanned: usize,
    /// Candidates dropped by overlap suppression. `0` when `dedup` is off.
    pub suppressed: usize,
    /// Candidates that scored under the gate and were dropped because
    /// `report_rejected` was off. Counted so the omission is visible.
    pub withheld_rejected: usize,
    /// The records, sorted by `offset` ascending, then kind name.
    pub records: Vec<Recovered>,
    /// The options this run used, carried so the report can publish them.
    pub opts: CarveOpts,
}

impl CarveReport {
    pub fn admitted(&self) -> usize {
        self.records.iter().filter(|r| r.admitted).count()
    }
    pub fn rejected(&self) -> usize {
        self.records.len() - self.admitted()
    }
}

// ===========================================================================
// Scoring one candidate
// ===========================================================================

/// The published rung name for a term-1 value, resolved by comparing against the
/// four published consts rather than by re-deriving the ladder. A renamed rung
/// therefore cannot drift from its value, and an unpublished value is a panic
/// rather than a string nobody notices.
fn rung_name(v: f64) -> &'static str {
    if v == SIG_HEADER_AND_FOOTER {
        "header-and-footer"
    } else if v == SIG_NO_FOOTER_DEFINED {
        "no-footer-defined"
    } else if v == SIG_HEADER_ONLY {
        "header-only"
    } else if v == SIG_HEADER_MISMATCH {
        "header-mismatch"
    } else {
        panic!("signature_integrity returned {v}, which is not a published ladder rung")
    }
}

/// Does the kind's header pattern match exactly at the start of `buf`? Asked of
/// the shipped table so this module keeps no second copy of any magic bytes.
/// Always true for a candidate `scan` produced; computed anyway, because term 1
/// takes it as an input and an input nobody computes is an assumption.
fn header_matches(kind: Kind, buf: &[u8]) -> bool {
    SIGNATURES.iter().any(|s| {
        s.kind == kind && buf.len() >= s.header.len() && &buf[..s.header.len()] == s.header
    })
}

/// Was the format's terminator found **in sequence** — after the header and
/// inside `span` bytes of the object? `false` for a kind that publishes none.
fn footer_in_sequence(buf: &[u8], kind: Kind, span: u64) -> bool {
    let Some(sig) = signature_for(kind) else {
        return false;
    };
    next_footer(buf, kind, sig.header.len() as u64, span).is_some()
}

/// The fallback span for a candidate with no validator end and no terminator.
fn fallback_window(kind: Kind, opts: &CarveOpts) -> u64 {
    opts.residue_window
        .unwrap_or_else(|| size_bounds(kind).full_lo)
}

/// Score one candidate. Pipeline order, once, with no branch on kind outside
/// the shipped tables.
fn score(image: &[u8], cand: &Candidate, opts: &CarveOpts) -> Recovered {
    let at = cand.header_at as usize;
    let sig = signature_for(cand.kind).expect("every scanned kind has a signature table row");

    // The validator's view is bounded by the table's own published search cap.
    let view_end = (cand.header_at.saturating_add(sig.max_len)).min(image.len() as u64) as usize;
    let view = &image[at..view_end];

    let v = validate(cand.kind, view);

    let (length, assembly) = match v.end {
        Some(end) if end > 0 => (end.min(view.len() as u64), Assembly::Contiguous),
        _ => {
            let span = match (sig.footer, cand.footer_at) {
                (Some(f), Some(footer_at)) => footer_at + f.len() as u64 - cand.header_at,
                _ => fallback_window(cand.kind, opts),
            };
            (
                span.min(image.len() as u64 - cand.header_at).max(1),
                Assembly::SignatureSpan,
            )
        }
    };

    let data = &image[at..at + length as usize];
    let header_matched = header_matches(cand.kind, view);
    let footer_found = footer_in_sequence(view, cand.kind, length);
    let c = confidence(cand.kind, header_matched, footer_found, &v, data);
    let admitted = c.total >= opts.min_confidence;

    let (reason_code, reason) = if admitted {
        (None, None)
    } else {
        let code = if v.valid {
            REASON_BELOW_GATE
        } else {
            REASON_BELOW_GATE_STRUCTURE_INVALID
        };
        // The structural half is `structure::validate`'s own detail string,
        // quoted verbatim. Paraphrasing it loses the offset it names.
        let line = format!(
            "confidence {:.4} below MIN_CONFIDENCE {:.4}; structure: {}",
            c.total, opts.min_confidence, v.detail
        );
        (Some(code), Some(line))
    };

    Recovered {
        kind: cand.kind,
        offset: cand.header_at,
        length,
        extents: vec![Extent {
            offset: cand.header_at,
            length,
        }],
        assembly,
        sha256: sha256_hex(data),
        signature: SignatureObs {
            header_matched,
            footer_defined: kind_defines_footer(cand.kind),
            footer_found,
            ladder_rung: rung_name(c.signature_integrity),
        },
        structure: v,
        entropy_bits_per_byte: shannon_entropy(data),
        entropy_sampled: data.len() >= MIN_ENTROPY_SAMPLE,
        confidence: c,
        admitted,
        reason_code,
        reason,
    }
}

// ===========================================================================
// The driver
// ===========================================================================

/// Carve `image`. Contiguous objects only.
///
/// # The deduplication rule — *claimed bytes*
///
/// `scan` is complete and non-suppressing by design: it reports headers nested
/// inside other objects and headers overlapping each other, because at scan time
/// nothing knows where anything ends. Something downstream therefore has to
/// decide which of two overlapping claims on the same bytes is the recovery.
/// This is that decision, and it is made **after** scoring, never before:
///
/// 1. Every candidate is scored independently.
/// 2. Admitted candidates are ranked by `confidence.total` descending, then
///    `length` descending, then `offset` ascending, then kind name — a total
///    order, so the outcome does not depend on scan order or on sort stability.
/// 3. Walking that ranking: a candidate whose span is disjoint from every span
///    already claimed becomes a **recovery** and claims its span. One that
///    intersects a claimed span is **suppressed**.
/// 4. Then the rejected candidates: one whose *header offset* falls inside a
///    claimed span is **suppressed**, because those bytes already belong to a
///    recovered object and the header is that object's payload, not an
///    independent candidate. One outside every claimed span is **kept** — that
///    is the residue population, and it is the evidence the false-positive
///    panel is built from.
/// 5. Suppressed candidates do not appear in `records`. The schema publishes
///    exactly two rejection codes and both mean "scored under the gate"; a
///    suppressed duplicate is neither, and inventing a third code is a schema
///    change. The count is reported as [`CarveReport::suppressed`] instead.
///
/// **Why highest confidence first.** The score is the published decision
/// function. Ranking by anything else — longest span, earliest offset — would
/// mean the report's own tie-break disagreed with its own gate, and the first
/// question an examiner asks about two overlapping claims is which one scored
/// better. Length breaks a score tie because the longer object is the one whose
/// validator walked further; offset and kind break the remainder only to make
/// the order total.
///
/// A rejected candidate that starts *before* a claimed span and overlaps into it
/// is kept. Its span is a signature-layer guess, so treating its guess as a
/// reason to delete evidence would be letting the weaker claim win.
///
/// `--no-dedup` skips steps 2 through 5 entirely and every scored candidate is
/// reported, which is how the rule above is audited rather than trusted.
pub fn carve(image: &[u8], opts: &CarveOpts) -> CarveReport {
    let cands = scan(image);
    let scanned = cands.len();

    let mut scored: Vec<Recovered> = cands.iter().map(|c| score(image, c, opts)).collect();

    let mut suppressed = 0usize;
    if opts.dedup {
        // Rank: admitted first, then the documented total order.
        let mut order: Vec<usize> = (0..scored.len()).collect();
        order.sort_by(|&a, &b| {
            let (x, y) = (&scored[a], &scored[b]);
            y.admitted
                .cmp(&x.admitted)
                .then(
                    y.confidence
                        .total
                        .partial_cmp(&x.confidence.total)
                        .unwrap_or(core::cmp::Ordering::Equal),
                )
                .then(y.length.cmp(&x.length))
                .then(x.offset.cmp(&y.offset))
                .then(x.kind.as_str().cmp(y.kind.as_str()))
        });

        // Claimed spans, kept sorted and disjoint so the membership test is a
        // binary search rather than a scan of every recovery so far.
        let mut claimed: Vec<(u64, u64)> = Vec::new();
        let mut keep = vec![false; scored.len()];

        for &i in &order {
            let r = &scored[i];
            if r.admitted {
                if intersects(&claimed, r.offset, r.end()) {
                    suppressed += 1;
                } else {
                    insert_span(&mut claimed, r.offset, r.end());
                    keep[i] = true;
                }
            } else if contains(&claimed, r.offset) {
                suppressed += 1;
            } else {
                keep[i] = true;
            }
        }

        let mut kept = Vec::with_capacity(scored.len() - suppressed);
        for (i, r) in scored.into_iter().enumerate() {
            if keep[i] {
                kept.push(r);
            }
        }
        scored = kept;
    }

    let mut withheld_rejected = 0usize;
    if !opts.report_rejected {
        let before = scored.len();
        scored.retain(|r| r.admitted);
        withheld_rejected = before - scored.len();
    }

    scored.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then(a.kind.as_str().cmp(b.kind.as_str()))
    });

    CarveReport {
        scanned,
        suppressed,
        withheld_rejected,
        records: scored,
        opts: opts.clone(),
    }
}

/// Does `[lo, hi)` intersect any span in the sorted, disjoint list?
fn intersects(spans: &[(u64, u64)], lo: u64, hi: u64) -> bool {
    // First span whose end is strictly greater than `lo`; anything earlier ends
    // at or before `lo` and cannot overlap.
    let i = spans.partition_point(|s| s.1 <= lo);
    matches!(spans.get(i), Some(&(s_lo, _)) if s_lo < hi)
}

/// Is `at` inside any span in the sorted, disjoint list?
fn contains(spans: &[(u64, u64)], at: u64) -> bool {
    let i = spans.partition_point(|s| s.1 <= at);
    matches!(spans.get(i), Some(&(lo, hi)) if at >= lo && at < hi)
}

/// Insert `[lo, hi)`, which the caller has already shown to be disjoint from
/// everything present, keeping the list sorted.
fn insert_span(spans: &mut Vec<(u64, u64)>, lo: u64, hi: u64) {
    let i = spans.partition_point(|s| s.1 <= lo);
    spans.insert(i, (lo, hi));
}

// ===========================================================================
// SHA-256, hand-rolled. FIPS 180-4.
// ===========================================================================
//
// CLAUDE.md forbids a new dependency without asking, and `crc32` in
// `structure/mod.rs` sets the precedent for hand-rolling a published digest
// here. This implementation is checked three ways: the NIST one-block and
// two-block vectors and the empty-string vector in the unit tests below; a
// streaming-vs-one-shot equivalence test; and, at every real run, against the
// SHA-256 digests `fixtures/build_image.py` computed independently in Python for
// each planted file. That last check is the strong one, and it is why the carve
// binary reports its recoveries by digest and not by count.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn sha256_block(h: &mut [u32; 8], b: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b2, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b2) ^ (a & c) ^ (b2 & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b2;
        b2 = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, add) in h.iter_mut().zip([a, b2, c, d, e, f, g, hh]) {
        *slot = slot.wrapping_add(add);
    }
}

/// Incremental SHA-256, so an image can be digested without a second copy of it
/// in memory.
#[derive(Debug, Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buffered: usize,
    len: u64,
}

impl Default for Sha256 {
    fn default() -> Sha256 {
        Sha256::new()
    }
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            h: H0,
            buf: [0u8; 64],
            buffered: 0,
            len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                // Still a partial block. Returning here is load-bearing: falling
                // through would reach `self.buffered = rest.len()` below with an
                // empty `rest` and silently discard the bytes just buffered.
                return;
            }
            let block = self.buf;
            sha256_block(&mut self.h, &block);
            self.buffered = 0;
        }
        let full = data.len() - data.len() % 64;
        let mut i = 0;
        while i < full {
            sha256_block(&mut self.h, &data[i..i + 64]);
            i += 64;
        }
        let rest = &data[full..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bitlen = self.len.wrapping_mul(8);
        let mut tail = Vec::with_capacity(128);
        tail.extend_from_slice(&self.buf[..self.buffered]);
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(&bitlen.to_be_bytes());
        let mut i = 0;
        while i < tail.len() {
            sha256_block(&mut self.h, &tail[i..i + 64]);
            i += 64;
        }
        let mut out = [0u8; 32];
        for (i, v) in self.h.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut s = Sha256::new();
    s.update(data);
    hex(&s.finish())
}

/// 32 bytes to 64 lowercase hex characters, without a formatting round trip per
/// byte.
pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0x0F) as usize] as char);
    }
    s
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SHA-256 against published vectors --------------------------------
    //
    // FIPS 180-4 / NIST CSRC example vectors. These are the standard's own
    // one-block and two-block messages, plus the empty string, plus the
    // million-'a' vector which exercises the length field past one block count.

    #[test]
    fn sha256_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_million_a_vector() {
        let mut s = Sha256::new();
        let chunk = vec![b'a'; 1000];
        for _ in 0..1000 {
            s.update(&chunk);
        }
        assert_eq!(
            hex(&s.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha256_streaming_matches_one_shot() {
        let data: Vec<u8> = (0u32..5000).map(|i| (i * 31 % 253) as u8).collect();
        let one = sha256_hex(&data);
        for chunk in [1usize, 7, 63, 64, 65, 4096] {
            let mut s = Sha256::new();
            for part in data.chunks(chunk) {
                s.update(part);
            }
            assert_eq!(hex(&s.finish()), one, "chunk size {chunk}");
        }
    }

    #[test]
    fn sha256_length_field_crosses_a_block_boundary() {
        // 55, 56 and 64 bytes are the three padding cases: fits, forces an extra
        // block, and exactly fills one.
        for n in [55usize, 56, 57, 63, 64, 65] {
            let d = vec![0x5Au8; n];
            let mut s = Sha256::new();
            s.update(&d);
            let a = hex(&s.finish());
            let mut s2 = Sha256::new();
            for b in &d {
                s2.update(&[*b]);
            }
            assert_eq!(a, hex(&s2.finish()), "n = {n}");
        }
    }

    // ---- the interval machinery the dedup rule stands on ------------------

    #[test]
    fn interval_membership_and_intersection() {
        let mut spans: Vec<(u64, u64)> = Vec::new();
        insert_span(&mut spans, 100, 200);
        insert_span(&mut spans, 300, 400);
        assert_eq!(spans, vec![(100, 200), (300, 400)]);

        assert!(contains(&spans, 100));
        assert!(contains(&spans, 199));
        assert!(!contains(&spans, 200), "the end is exclusive");
        assert!(!contains(&spans, 250));
        assert!(contains(&spans, 399));

        assert!(intersects(&spans, 150, 160));
        assert!(intersects(&spans, 50, 101), "one byte of overlap is overlap");
        assert!(intersects(&spans, 199, 300));
        assert!(!intersects(&spans, 200, 300), "abutting is not overlapping");
        assert!(!intersects(&spans, 0, 100));
        assert!(!intersects(&spans, 400, 500));
    }

    #[test]
    fn insert_keeps_the_list_sorted_whatever_the_arrival_order() {
        let mut spans: Vec<(u64, u64)> = Vec::new();
        for (lo, hi) in [(500u64, 600u64), (100, 200), (900, 1000), (300, 400)] {
            assert!(!intersects(&spans, lo, hi));
            insert_span(&mut spans, lo, hi);
        }
        assert_eq!(spans, vec![(100, 200), (300, 400), (500, 600), (900, 1000)]);
    }

    // ---- defaults ---------------------------------------------------------

    #[test]
    fn the_default_gate_is_the_exported_const_and_not_a_literal() {
        assert_eq!(CarveOpts::default().min_confidence, MIN_CONFIDENCE);
    }

    #[test]
    fn the_default_fallback_window_is_the_full_size_credit_floor() {
        let opts = CarveOpts::default();
        for k in [
            Kind::Jpeg,
            Kind::Png,
            Kind::Pdf,
            Kind::Zip,
            Kind::Sqlite,
            Kind::Mp4,
            Kind::Gzip,
        ] {
            assert_eq!(fallback_window(k, &opts), size_bounds(k).full_lo);
        }
        let forced = CarveOpts {
            residue_window: Some(4096),
            ..CarveOpts::default()
        };
        assert_eq!(fallback_window(Kind::Gzip, &forced), 4096);
    }

    #[test]
    fn the_ladder_rung_names_come_from_the_published_consts() {
        assert_eq!(rung_name(SIG_HEADER_AND_FOOTER), "header-and-footer");
        assert_eq!(rung_name(SIG_NO_FOOTER_DEFINED), "no-footer-defined");
        assert_eq!(rung_name(SIG_HEADER_ONLY), "header-only");
        assert_eq!(rung_name(SIG_HEADER_MISMATCH), "header-mismatch");
    }

    #[test]
    #[should_panic(expected = "not a published ladder rung")]
    fn an_unpublished_term_1_value_is_a_panic_not_a_silent_string() {
        rung_name(0.61);
    }

    // ---- the engine, on bytes built here ----------------------------------

    /// The smallest GZIP this project can build by hand: header, one stored
    /// DEFLATE block, CRC-32 and ISIZE. Enough for the driver to have a real
    /// object to find; the format walkers are tested exhaustively in their own
    /// modules.
    fn tiny_gzip(payload: &[u8]) -> Vec<u8> {
        let mut g = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        let n = payload.len() as u16;
        g.push(0x01);
        g.extend_from_slice(&n.to_le_bytes());
        g.extend_from_slice(&(!n).to_le_bytes());
        g.extend_from_slice(payload);
        g.extend_from_slice(&crate::structure::crc32(payload).to_le_bytes());
        g.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        g
    }

    #[test]
    fn an_empty_image_produces_an_empty_report() {
        let r = carve(&[], &CarveOpts::default());
        assert_eq!(r.scanned, 0);
        assert_eq!(r.records.len(), 0);
        assert_eq!(r.admitted(), 0);
        assert_eq!(r.rejected(), 0);
        assert_eq!(r.suppressed, 0);
    }

    #[test]
    fn a_zeroed_image_recovers_nothing() {
        // The post-wipe shape. Zeros do match the MP4 ftyp rows' first bytes, so
        // this is a real exercise of the scanner rather than a trivial one.
        let img = vec![0u8; 1 << 16];
        let r = carve(&img, &CarveOpts::default());
        assert_eq!(r.admitted(), 0, "a wiped image admitted something");
    }

    #[test]
    fn a_planted_object_is_found_and_its_sha256_is_the_bytes_that_were_planted() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);
        let want = sha256_hex(&obj);

        let mut img = vec![0u8; 4096];
        let at = img.len();
        img.extend_from_slice(&obj);
        img.extend_from_slice(&vec![0u8; 4096]);

        let r = carve(&img, &CarveOpts::default());
        let hits: Vec<&Recovered> = r.records.iter().filter(|x| x.admitted).collect();
        assert_eq!(hits.len(), 1, "expected exactly one recovery");
        let hit = hits[0];
        assert_eq!(hit.kind, Kind::Gzip);
        assert_eq!(hit.offset, at as u64);
        assert_eq!(hit.length, obj.len() as u64);
        assert_eq!(hit.assembly, Assembly::Contiguous);
        assert_eq!(hit.extents.len(), 1, "the contiguous engine emits one extent");
        assert_eq!(
            hit.sha256, want,
            "the recovered digest is not the planted object's digest"
        );
        assert_eq!(hit.id(), format!("GZIP@{at}"));
        assert!(hit.reason_code.is_none() && hit.reason.is_none());
    }

    #[test]
    fn admission_is_one_comparison_against_the_gate_and_nothing_else() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let img = tiny_gzip(&payload);

        let r = carve(&img, &CarveOpts::default());
        let rec = &r.records[0];
        assert_eq!(rec.admitted, rec.confidence.total >= MIN_CONFIDENCE);

        // Raise the gate above what this object can score and the same object,
        // byte for byte, is rejected. Nothing else about the record changes.
        let strict = CarveOpts {
            min_confidence: rec.confidence.total + 0.01,
            ..CarveOpts::default()
        };
        let r2 = carve(&img, &strict);
        let rec2 = &r2.records[0];
        assert!(!rec2.admitted);
        assert_eq!(rec2.sha256, rec.sha256);
        assert_eq!(rec2.confidence, rec.confidence);
        assert!(rec2.reason.as_ref().unwrap().contains(&rec2.structure.detail));
    }

    #[test]
    fn structure_valid_is_reported_but_is_not_a_second_gate() {
        // Every admitted record must satisfy the ONE published comparison, and
        // no record may be rejected while satisfying it.
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 11 % 249) as u8).collect();
        let img = tiny_gzip(&payload);
        let r = carve(&img, &CarveOpts::default());
        for rec in &r.records {
            assert_eq!(rec.admitted, rec.confidence.total >= MIN_CONFIDENCE);
        }
    }

    #[test]
    fn the_four_weighted_terms_sum_to_the_composite_on_every_record() {
        use crate::confidence::{W_ENTROPY, W_SIGNATURE, W_SIZE, W_STRUCTURE};
        let payload: Vec<u8> = (0u32..5000).map(|i| (i * 13 % 247) as u8).collect();
        let mut img = tiny_gzip(&payload);
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
        img.extend_from_slice(&vec![0x41u8; 2048]);
        let r = carve(&img, &CarveOpts::default());
        assert!(!r.records.is_empty());
        for rec in &r.records {
            let c = &rec.confidence;
            let sum = W_SIGNATURE * c.signature_integrity
                + W_STRUCTURE * c.structural_validity
                + W_ENTROPY * c.entropy_consistency
                + W_SIZE * c.size_plausibility;
            assert!(
                (sum - c.total).abs() < 1e-12,
                "{}: weighted terms sum to {sum}, total is {}",
                rec.id(),
                c.total
            );
        }
    }

    #[test]
    fn dedup_suppresses_a_header_buried_inside_a_recovered_object() {
        // A JPEG SOI sequence inside the GZIP payload. Un-deduplicated the
        // scanner reports both; deduplicated the buried one is payload of the
        // recovery that claimed those bytes.
        let mut payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        payload[1500] = 0xFF;
        payload[1501] = 0xD8;
        payload[1502] = 0xFF;
        let img = tiny_gzip(&payload);

        let loose = carve(
            &img,
            &CarveOpts {
                dedup: false,
                ..CarveOpts::default()
            },
        );
        let tight = carve(&img, &CarveOpts::default());

        assert!(
            loose.records.iter().any(|r| r.kind == Kind::Jpeg),
            "the un-deduplicated run should see the buried JPEG header"
        );
        assert!(
            !tight.records.iter().any(|r| r.kind == Kind::Jpeg),
            "the buried header was not suppressed by the claimed-bytes rule"
        );
        assert_eq!(loose.suppressed, 0, "--no-dedup suppresses nothing");
        assert!(tight.suppressed >= 1);
        assert_eq!(tight.records.len() + tight.suppressed, loose.records.len());
        assert_eq!(tight.scanned, loose.scanned, "dedup is not a scan change");
    }

    #[test]
    fn dedup_keeps_residue_that_lies_outside_every_recovery() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = tiny_gzip(&payload);
        let decoy_at = img.len() as u64;
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x00u8; 4096]);

        let r = carve(&img, &CarveOpts::default());
        let decoy = r
            .records
            .iter()
            .find(|x| x.kind == Kind::Jpeg && x.offset == decoy_at)
            .expect("free-space residue must survive deduplication: it is the evidence");
        assert!(!decoy.admitted);
        assert_eq!(decoy.assembly, Assembly::SignatureSpan);
        assert!(decoy.reason_code.is_some());
    }

    #[test]
    fn withholding_rejections_is_counted_rather_than_silent() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = tiny_gzip(&payload);
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x00u8; 4096]);

        let full = carve(&img, &CarveOpts::default());
        let quiet = carve(
            &img,
            &CarveOpts {
                report_rejected: false,
                ..CarveOpts::default()
            },
        );
        assert_eq!(quiet.records.len(), full.admitted());
        assert_eq!(quiet.withheld_rejected, full.rejected());
        assert!(quiet.withheld_rejected > 0);
    }

    #[test]
    fn records_come_back_in_offset_order() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = vec![0u8; 512];
        img.extend_from_slice(&tiny_gzip(&payload));
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x11u8; 8192]);
        img.extend_from_slice(&tiny_gzip(&payload));
        img.extend_from_slice(&vec![0u8; 512]);

        let r = carve(&img, &CarveOpts::default());
        let offsets: Vec<u64> = r.records.iter().map(|x| x.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn a_run_is_deterministic() {
        let payload: Vec<u8> = (0u32..4000).map(|i| (i * 17 % 241) as u8).collect();
        let mut img = tiny_gzip(&payload);
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x7Eu8; 6000]);
        img.extend_from_slice(&tiny_gzip(&payload));
        let a = carve(&img, &CarveOpts::default());
        let b = carve(&img, &CarveOpts::default());
        assert_eq!(a, b);
    }

    #[test]
    fn no_record_is_ever_reassembled_because_bifragment_is_not_called() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = tiny_gzip(&payload);
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x00u8; 2048]);
        let r = carve(&img, &CarveOpts::default());
        for rec in &r.records {
            assert_ne!(rec.assembly, Assembly::Reassembled);
            assert_eq!(rec.extents.len(), 1);
            assert_eq!(rec.extents[0].offset, rec.offset);
            assert_eq!(rec.extents[0].length, rec.length);
        }
    }

    #[test]
    fn every_record_span_lies_inside_the_image() {
        let payload: Vec<u8> = (0u32..2000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = tiny_gzip(&payload);
        // A header in the last few bytes: the fallback window must clamp.
        img.extend_from_slice(&[0x1F, 0x8B, 0x08]);
        let r = carve(&img, &CarveOpts::default());
        for rec in &r.records {
            assert!(rec.length >= 1);
            assert!(
                rec.end() <= img.len() as u64,
                "{} runs past the end of the image",
                rec.id()
            );
        }
    }
}
