//! # The published confidence function
//!
//! CLAUDE.md rule 3: *confidence scores are computed, not asserted, and the function is
//! published.* This module is that function. Every constant below was derived from a
//! measurement against `out/fixture.img`
//! (sha256 `d85612b255ff8e72e1ab8d7a34c227b67c3cb3acda75e2a92e5042758ac2df41`,
//! manifest sha256 `36036e5db70d270540c2839f150d2037a06a20873c368bed992c957b3dbeda04`),
//! and the measurement that produced it is written next to it. Nothing here is illustrative.
//!
//! ## The formula
//!
//! ```text
//! confidence = 0.40 * signature_integrity      how much signature evidence was observed
//!            + 0.35 * structural_validity      what the format walker concluded
//!            + 0.15 * entropy_consistency      does the payload look like this format
//!            + 0.10 * size_plausibility        is this length possible for this format
//! ```
//!
//! The four weights sum to exactly 1.00. Each term is independently computed, independently
//! unit tested, independently reportable through its own public function, and lies in [0,1].
//! No term is allowed to reach outside its own layer of evidence — in particular
//! `signature_integrity` never consults the structure walker and never inspects payload
//! bytes, because the whole point of the score is that the layers can disagree.
//!
//! ## Term 1 — signature_integrity, weight 0.40. The published ladder.
//!
//! Signature-layer evidence is two observations and no more: the header matched exactly at
//! the candidate offset, and the format's defined terminator was found in sequence after it.
//!
//! ```text
//!   0.00   header did not match exactly                                    (gate)
//!   0.50   header exact; the format defines a terminator; none in sequence
//!   0.75   header exact; the format defines no terminator                  (ceiling)
//!   1.00   header exact; the format defines a terminator; found in sequence
//! ```
//!
//! Whether a format defines a terminator is asked of [`crate::signature::signature_for`], so
//! [`crate::signature::SIGNATURES`] stays the single source of truth and is not duplicated
//! here. In the shipped table JPEG, PNG, PDF and ZIP carry a terminator; GZIP, MP4 and SQLITE
//! do not.
//!
//! The 0.75 rung is the one that gets asked about. It sits above 0.50 because for a footerless
//! format nothing is *missing* — there is no terminator to fail to find, so its absence is not
//! evidence of damage. It sits below 1.00 because only one independent signature observation
//! exists, and a score of 1.00 would claim corroboration that was never obtained. The
//! consequence is stated rather than hidden: **a GZIP, MP4 or SQLITE object can never exceed
//! 0.75 on this term and therefore can never exceed 0.90 overall.** Measured on the fixture,
//! a byte-perfect GZIP whose CRC32 and ISIZE both verify scores 0.900, not 1.000.
//!
//! The ladder deliberately awards 1.00 to a run of decoy bytes that happens to open with
//! `FF D8 FF` and contain an `FF D9` somewhere downstream. All 8 JPEG false positives planted
//! in the fixture residue do exactly that — their first `FF D9` lands between 23,206 and
//! 652,632 bytes after the header. That is not a defect in this term, it is the finding: **at
//! the signature layer a noise blob and a photograph are indistinguishable.** It is why this
//! term carries only 0.40 of the score and cannot on its own clear an admission threshold, and
//! it is the entire argument for spending 0.35 on structure.
//!
//! ## Term 2 — structural_validity, weight 0.35
//!
//! [`Validation::score`] is taken directly, clamped into [0,1], and is not re-derived here.
//! `Validation::valid` is deliberately *not* consulted: admission is `carve.rs`'s gate, scoring
//! is this module's, and collapsing the two would let one layer overrule the other silently.
//!
//! ## Term 3 — entropy_consistency, weight 0.15
//!
//! Shannon entropy in bits/byte over the object as recovered, scored against a per-format
//! trapezoid: zero below `lo_zero`, rising linearly to 1.0 at `lo_full`, flat to `hi_full`,
//! falling linearly to zero at `hi_zero`.
//!
//! Measured over the 40 planted files, reading each file's bytes from its manifest extents
//! (all 40 SHA-256 values re-verified against the manifest before measuring):
//!
//! ```text
//!   kind     n    min       max      mean      band used  (lo_zero lo_full hi_full hi_zero)
//!   PDF      5   7.9079    7.9491   7.9308     1.00  3.00  7.99  8.00
//!   DOCX→Zip 5   7.8835    7.8878   7.8862     1.00  3.00  7.99  8.00
//!   JPEG     5   7.8716    7.8995   7.8826     5.50  7.00  7.99  8.00
//!   GZIP     5   7.8669    7.8713   7.8692     5.50  7.00  7.99  8.00
//!   PNG      5   7.7986    7.8414   7.8219     5.50  7.00  7.99  8.00
//!   MP4      5   7.7600    7.7646   7.7617     3.00  6.00  7.99  8.00
//!   SQLITE   5   5.3189    5.5076   5.4263     0.50  1.50  7.90  8.00
//!   (TXT     5   4.5574    4.5682   4.5628     no Kind variant; not carved)
//! ```
//!
//! The corpus spans 4.5574 to 7.9491 bits/byte. Two measured facts changed the design:
//!
//! * **PDF is the highest-entropy kind in the corpus, not the lowest.** These PDFs carry
//!   FlateDecode streams. A PDF with uncompressed streams measures near 5. PDF is therefore
//!   genuinely bimodal and its band is deliberately almost the full range: **entropy carries
//!   close to zero discriminating power for PDF and the band says so rather than pretending
//!   otherwise.** ZIP is the same case — a STORED archive of text is low, a DEFLATE archive
//!   is high.
//! * **The bands are far wider than the measurement.** JPEG measures 7.8716–7.8995 and gets a
//!   plateau starting at 7.00. Fitting the plateau to the measured range would score better on
//!   this fixture and would be overfitting: a real low-detail JPEG or a PNG of a flat image
//!   sits lower. The bands are format-principled — an entropy-coded payload is
//!   near-incompressible by construction — and the fixture measurement is used to confirm the
//!   band contains it with margin, not to define the band.
//!
//! Objects shorter than [`MIN_ENTROPY_SAMPLE`] (1024 bytes) return the explicit
//! no-information value 0.5 rather than a fabricated score. Derived, not assumed: the
//! downward bias of sample entropy on uniform bytes was measured over 200 blocks per size —
//! 0.0449 bits at n=4096, 0.1914 at n=1024, 0.4121 at n=512, 0.8302 at n=256 (Miller–Madow
//! predicts 0.0449 / 0.1796 / 0.3593 / 0.7185). The tightest plateau floor here is 7.00 and
//! the lowest planted entropy for a kind using it is PNG at 7.7986, a margin of 0.80 bits. At
//! 1024 bytes the bias is 0.19 bits and safely inside that margin; at 256 bytes it is 0.83
//! bits and would swallow it.
//!
//! ## Term 4 — size_plausibility, weight 0.10
//!
//! The recovered length scored against a per-format trapezoid interpolated on log2(bytes),
//! because format size ranges are multiplicative, not additive.
//!
//! ```text
//!   kind    zero_lo  full_lo   full_hi   zero_hi   fixture measured range (n=5)
//!   Jpeg      107      1 KiB    16 MiB    64 MiB      92,851 ..   108,462
//!   Png        67    512 B      16 MiB    64 MiB     158,522 ..   260,595
//!   Pdf       300      1 KiB    32 MiB   128 MiB      38,408 ..    54,214
//!   Zip        22    256 B      64 MiB   256 MiB      32,453 ..    79,397   (DOCX)
//!   Sqlite    512      4 KiB   128 MiB   512 MiB     110,592 ..   221,184
//!   Mp4        16      4 KiB   128 MiB   512 MiB      66,689 ..   221,041
//!   Gzip       20    128 B      32 MiB   128 MiB      54,871 ..   127,302
//! ```
//!
//! `zero_lo` is the format's own structural floor, not a fixture number: 107 bytes is the
//! smallest baseline JPEG that can carry SOI+DQT+SOF0+DHT+SOS+EOI; 67 is PNG signature +
//! IHDR + a minimal IDAT + IEND; 22 is a ZIP end-of-central-directory record; 20 is a GZIP
//! 10-byte header + minimal DEFLATE + 8-byte trailer; 512 is the SQLite minimum page size and
//! so its minimum file size; 16 is a bare `ftyp` box; 300 is a minimal one-page PDF.
//!
//! `full_hi` and `zero_hi` are stated as fixture-derived judgement and nothing stronger. The
//! whole fixture is 256 MiB and its largest planted object is 260,595 bytes, so the fixture
//! contains no evidence about where a real object stops being plausible. They are set to make
//! one specific signal work: a candidate that ran to the carver's `max_len` clamp without a
//! structural end has, by construction, an undetermined length, and the term should say so.
//! That requires each `Signature::max_len` to sit at or below this table's `zero_hi` for its
//! kind. The shipped table satisfies it — JPEG 32 MiB, PNG 64 MiB, PDF 64 MiB, ZIP 128 MiB,
//! SQLITE 256 MiB, MP4 256 MiB, GZIP 128 MiB — and
//! `term4_the_shipped_max_len_clamp_is_penalised_by_this_table` asserts it against
//! [`crate::signature::SIGNATURES`] directly, so raising a `max_len` past a ceiling fails a
//! test here rather than silently inflating a score. Measured
//! consequence on the fixture, with GZIP `max_len` at 128 MiB: the 13 GZIP residue false
//! positives, having no terminator and no structural end, run to between 24,812,302 and
//! 134,217,728 bytes and score 1.000 down to 0.000 here.
//!
//! This term is the weakest of the four on this corpus, and carries the least weight for that
//! reason. It is worth being blunt about how weak: the 8 JPEG residue false positives span
//! 23,206 to 652,632 bytes, which is squarely inside the plausible range for a real JPEG, so
//! **the term awards all 8 of them 1.000 and contributes nothing to separating them.**
//!
//! ## The measured separation — the property that decides whether any of this is believable
//!
//! Every number below was computed by this module's own code over `out/fixture.img`. The
//! structural term came from a reference walker standing in for `structure.rs` — a JPEG
//! marker walk to EOI, a PNG chunk walk with per-chunk CRC32, a GZIP header + DEFLATE +
//! CRC32/ISIZE trailer check, a ZIP central-directory walk with per-entry CRC32, a PDF
//! startxref/trailer/%%EOF check, a SQLite page-geometry check and an MP4 box walk. It scored
//! 1.000 on all 35 planted carvable files and 0.000 on all 21 residue decoys.
//!
//! ```text
//!                                     n      min      max     mean
//!   planted files, carvable kinds    35   0.9000   1.0000   0.9571
//!   residue false positives          21   0.4500   0.6500   0.5424
//!     residue JPEG                    8   0.5680   0.6500   0.6339
//!     residue GZIP                   13   0.4500   0.5500   0.4862
//! ```
//!
//! Re-measured through the SHIPPED `structure::validate` by
//! `tests/residue_separation.rs`, which is the authority: the two edges and the gap are
//! unchanged — 35 planted files 0.9000..1.0000 mean 0.9571, 21 residue decoys 0.5186..0.6500
//! mean 0.5805 — but the shipped walker is not a hard 0.000 on residue. One residue GZIP earns
//! 0.2500 of partial structural credit because its 10-byte header parses cleanly and only the
//! DEFLATE stream fails. That 0.2500 is the number the headroom below is measured from.
//!
//! Lowest true positive 0.9000, highest false positive 0.6500, **separation 0.2500 with no
//! overlap.**
//!
//! ## The admission gate, and the headroom that actually protects it
//!
//! [`MIN_CONFIDENCE`] is **0.75**, and it is the gate every claim here is stated against. It
//! sits in the gap with 0.1500 of margin below the lowest true positive and 0.1000 above the
//! highest false positive. It is deliberately not 0.90: the 15 planted GZIP, MP4 and SQLITE
//! files score *exactly* 0.9000 because of the footerless ceiling, so a gate at 0.90 discards
//! all 15 real files. Only 20 of 35 true positives are strictly above 0.90.
//!
//! Because the gate is 0.75 and not 0.90, the margin that protects it is **not** the 0.2500
//! separation. A decoy scores at most `W_SIGNATURE + W_ENTROPY + W_SIZE` = 0.6500 on the three
//! terms that do not separate — which is exactly what all 8 residue JPEGs already score, full
//! marks on signature, entropy and size. The only thing between them and admission is the
//! structure term, and the structural credit at which such a decoy breaches the gate is
//!
//! ```text
//!   STRUCTURAL_BREACH_POINT
//!       = (MIN_CONFIDENCE - (W_SIGNATURE + W_ENTROPY + W_SIZE)) / W_STRUCTURE
//!       = (0.75 - 0.65) / 0.35
//!       = 0.285714
//! ```
//!
//! That is [`STRUCTURAL_BREACH_POINT`], derived from the weights and the gate rather than
//! transcribed, so changing a weight or the gate moves the guard with it. The worst structural
//! credit any residue decoy earns today is 0.2500, so **the real headroom is 0.0357.** Earlier
//! revisions of this module quoted 0.4700 of headroom against a structural breach at 0.72;
//! both numbers were computed against the 0.90 target and neither describes the gate this
//! carver enforces. `tests/residue_separation.rs` asserts strictly below
//! [`STRUCTURAL_BREACH_POINT`] and prints the measured headroom on every run.
//!
//! Where the separation comes from is worth saying out loud, because it is not evenly spread
//! across the four terms:
//!
//! * **Structure supplies 0.35 of the 0.25 gap** — all 21 decoys score 0.000 and all 35
//!   planted files 1.000, on its own more than the whole separation.
//! * **Entropy supplies a little.** Residue spans measure 6.1800–7.4172 bits/byte against
//!   7.7600–7.9491 for every planted compressed kind, but the bands are deliberately wide
//!   enough that 5 of 8 residue JPEGs still score 1.000 on it.
//! * **Signature and size supply nothing.** Both award the residue JPEGs full marks.
//!
//! **Structure validation is the only reason this number means anything.** If `structure/`
//! ever awards these decoys [`STRUCTURAL_BREACH_POINT`] — 0.285714, only 0.0357 above the
//! 0.2500 one of them already earns — the highest false positive reaches 0.7500, the gate
//! admits it, and residue is reported as recovered evidence. The residue distribution is
//! therefore the regression test that matters most in this crate, and it belongs in CI rather
//! than in a one-off measurement.
//!
//! ## What this module does not do
//!
//! It does not decide what is recoverable. The fixture plants two objects that bifragment gap
//! carving cannot solve by construction — a tri-fragment `media_inventory.docx` and a
//! reversed-extent `evidence_bag_seal.jpg` — and **nothing here special-cases them.** Handed
//! their correct bytes they score 1.0000 like any other intact object, which is right: they
//! are not malformed files, they are files this carver's reassembly cannot put back together.
//! They are excluded by `bifragment.rs` failing to reassemble them, upstream of any score.
//! A confidence function that knew their names would be asserting a result rather than
//! computing one.

use crate::signature::signature_for;
use crate::structure::Validation;
use crate::Kind;

/// Weight on signature-layer evidence. Published in the formula above.
pub const W_SIGNATURE: f64 = 0.40;
/// Weight on the structure walker's own score.
pub const W_STRUCTURE: f64 = 0.35;
/// Weight on payload entropy agreeing with the format.
pub const W_ENTROPY: f64 = 0.15;
/// Weight on the recovered length being possible for the format.
pub const W_SIZE: f64 = 0.10;

/// **The admission gate. `carve.rs` MUST set `CarveOpts::min_confidence` to this const rather
/// than to a literal, and every test that asserts a gate MUST read it from here.**
///
/// Why 0.75 and not 0.90. GZIP, MP4 and SQLITE define no terminator, so term 1 is capped at
/// [`SIG_NO_FOOTER_DEFINED`] for them and a byte-perfect object of those kinds tops out at
/// `0.40*0.75 + 0.35 + 0.15 + 0.10 = 0.9000` exactly. The fixture plants 15 such files and all
/// 15 measure exactly 0.9000, so a gate at 0.90 — whether compared with `>` or `>=` on a value
/// that is only equal to it up to float rounding — discards 15 true positives to buy nothing:
/// the highest false positive measured is 0.6500, and 0.75 already clears it by 0.1000 while
/// leaving 0.1500 below the lowest true positive.
///
/// 0.75 is a threshold on a *published* score, not a tuned magic number: it is the midpoint of
/// nothing and the consequence of the ladder. Raising it to 0.90 costs 15 files; the cost of
/// it being 0.75 is stated by [`STRUCTURAL_BREACH_POINT`] and is thin, which is why that
/// constant exists and is asserted against in CI.
pub const MIN_CONFIDENCE: f64 = 0.75;

/// The most a candidate can score without any structural evidence at all: full marks on
/// signature, entropy and size. All 8 residue JPEGs in the fixture already sit exactly here.
pub const NON_STRUCTURE_CEILING: f64 = W_SIGNATURE + W_ENTROPY + W_SIZE;

/// The structural credit at which a decoy holding [`NON_STRUCTURE_CEILING`] breaches
/// [`MIN_CONFIDENCE`]. **Derived from the weights and the gate, never transcribed** — change a
/// weight or the gate and this moves with it, and so does every guard written against it.
///
/// With the shipped weights and gate this is `(0.75 - 0.65) / 0.35 = 0.285714`. The worst
/// structural credit any residue decoy earns on the fixture today is 0.2500, so the headroom
/// is 0.0357. `tests/residue_separation.rs` asserts strictly below this value and prints the
/// measured headroom, because a tripwire set anywhere above it would pass in a state that
/// admits residue as evidence.
pub const STRUCTURAL_BREACH_POINT: f64 = (MIN_CONFIDENCE - NON_STRUCTURE_CEILING) / W_STRUCTURE;

/// Signature ladder rung: the header did not match exactly. Gate — nothing else is scored.
pub const SIG_HEADER_MISMATCH: f64 = 0.00;
/// Signature ladder rung: header exact, the format defines a terminator, none found in sequence.
pub const SIG_HEADER_ONLY: f64 = 0.50;
/// Signature ladder rung: header exact, the format defines no terminator. Ceiling for that kind.
pub const SIG_NO_FOOTER_DEFINED: f64 = 0.75;
/// Signature ladder rung: header exact and the format's terminator found in sequence.
pub const SIG_HEADER_AND_FOOTER: f64 = 1.00;

/// Shortest object over which Shannon entropy is reported rather than declared unknown.
///
/// Measured downward bias of sample entropy on uniform bytes, 200 blocks per size:
/// n=256 → 0.8302 bits, n=512 → 0.4121, n=1024 → 0.1914, n=4096 → 0.0449.
pub const MIN_ENTROPY_SAMPLE: usize = 1024;

/// Value returned by [`entropy_consistency`] when the object is too short to measure.
/// An explicit "no information" marker, not a score.
pub const ENTROPY_UNKNOWN: f64 = 0.5;

/// The four terms and their weighted sum. Every field is in [0,1] and separately reportable.
#[derive(Debug, Clone, PartialEq)]
pub struct Confidence {
    /// Term 1, weight 0.40. Signature ladder rung.
    pub signature_integrity: f64,
    /// Term 2, weight 0.35. `Validation::score`, clamped, never re-derived.
    pub structural_validity: f64,
    /// Term 3, weight 0.15. Shannon entropy against the per-kind band.
    pub entropy_consistency: f64,
    /// Term 4, weight 0.10. Recovered length against the per-kind bounds.
    pub size_plausibility: f64,
    /// The weighted sum. Weights total exactly 1.00, so this is in [0,1].
    pub total: f64,
}

/// A published entropy band, in bits per byte. Trapezoid: 0 at `lo_zero`, 1.0 across
/// `lo_full..=hi_full`, 0 again at `hi_zero`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyBand {
    pub lo_zero: f64,
    pub lo_full: f64,
    pub hi_full: f64,
    pub hi_zero: f64,
}

/// Published size bounds in bytes. Trapezoid interpolated on log2(bytes).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SizeBounds {
    /// The format's own structural floor. Below this the object cannot exist.
    pub zero_lo: u64,
    pub full_lo: u64,
    pub full_hi: u64,
    pub zero_hi: u64,
}

/// The entropy band this module scores `kind` against. Published so a report can print the
/// band beside the measurement that produced the score.
pub fn entropy_band(kind: Kind) -> EntropyBand {
    // Bands are format-principled and confirmed to contain the fixture measurement with
    // margin; see the module doc for the per-kind measured ranges.
    match kind {
        // Entropy-coded end to end. Incompressible payload by construction.
        Kind::Jpeg | Kind::Png | Kind::Gzip => EntropyBand {
            lo_zero: 5.50,
            lo_full: 7.00,
            hi_full: 7.99,
            hi_zero: 8.00,
        },
        // Compressed A/V, but a large `free`/`skip` atom of zeros drags the mean down.
        Kind::Mp4 => EntropyBand {
            lo_zero: 3.00,
            lo_full: 6.00,
            hi_full: 7.99,
            hi_zero: 8.00,
        },
        // Genuinely bimodal: DEFLATE streams are near 8, STORED/uncompressed near 4.5.
        // The band is wide because the format is, not because the measurement was.
        Kind::Zip | Kind::Pdf => EntropyBand {
            lo_zero: 1.00,
            lo_full: 3.00,
            hi_full: 7.99,
            hi_zero: 8.00,
        },
        // Page-structured with zero padding and plaintext records; BLOB-heavy databases climb.
        Kind::Sqlite => EntropyBand {
            lo_zero: 0.50,
            lo_full: 1.50,
            hi_full: 7.90,
            hi_zero: 8.00,
        },
    }
}

/// The size bounds this module scores `kind` against. `zero_lo` is a format floor; the upper
/// pair is fixture-derived judgement, documented as such in the module doc.
pub fn size_bounds(kind: Kind) -> SizeBounds {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    match kind {
        // 107 B: SOI+DQT+SOF0+DHT+SOS+EOI, the smallest baseline JPEG that can decode.
        Kind::Jpeg => SizeBounds { zero_lo: 107, full_lo: KIB, full_hi: 16 * MIB, zero_hi: 64 * MIB },
        // 67 B: 8 signature + 25 IHDR + 22 minimal IDAT + 12 IEND.
        Kind::Png => SizeBounds { zero_lo: 67, full_lo: 512, full_hi: 16 * MIB, zero_hi: 64 * MIB },
        // 300 B: a minimal one-page PDF with catalog, pages, page, xref, trailer, %%EOF.
        Kind::Pdf => SizeBounds { zero_lo: 300, full_lo: KIB, full_hi: 32 * MIB, zero_hi: 128 * MIB },
        // 22 B: a bare end-of-central-directory record, i.e. an empty archive.
        Kind::Zip => SizeBounds { zero_lo: 22, full_lo: 256, full_hi: 64 * MIB, zero_hi: 256 * MIB },
        // 512 B: the SQLite minimum page size, and so its minimum database file size.
        Kind::Sqlite => SizeBounds { zero_lo: 512, full_lo: 4 * KIB, full_hi: 128 * MIB, zero_hi: 512 * MIB },
        // 16 B: a bare `ftyp` box.
        Kind::Mp4 => SizeBounds { zero_lo: 16, full_lo: 4 * KIB, full_hi: 128 * MIB, zero_hi: 512 * MIB },
        // 20 B: 10-byte header + minimal DEFLATE block + 8-byte CRC32/ISIZE trailer.
        Kind::Gzip => SizeBounds { zero_lo: 20, full_lo: 128, full_hi: 32 * MIB, zero_hi: 128 * MIB },
    }
}

/// Whether this format publishes a terminating signature. Asked of
/// [`signature_for`] so [`crate::signature::SIGNATURES`] stays the single source of truth and
/// this module never keeps a second copy of it. A kind absent from the table is treated as
/// having no terminator — the conservative direction, since it caps the ladder at 0.75.
///
/// `signature.rs` documents that MP4's nine rows carry identical `footer` and `max_len`, so
/// taking the first row for a kind is well defined.
pub fn kind_defines_footer(kind: Kind) -> bool {
    signature_for(kind).map(|s| s.footer.is_some()).unwrap_or(false)
}

/// Term 1, weight 0.40. The published ladder, and nothing outside the signature layer:
/// this function never sees the payload and never sees the structure walker's verdict.
///
/// * `sig_ok` — the header matched exactly at the candidate offset.
/// * `footer_found` — the format's terminator was found in sequence after the header.
pub fn signature_integrity(kind: Kind, sig_ok: bool, footer_found: bool) -> f64 {
    if !sig_ok {
        return SIG_HEADER_MISMATCH;
    }
    if !kind_defines_footer(kind) {
        return SIG_NO_FOOTER_DEFINED;
    }
    if footer_found {
        SIG_HEADER_AND_FOOTER
    } else {
        SIG_HEADER_ONLY
    }
}

/// Term 2, weight 0.35. [`Validation::score`] taken directly and clamped into [0,1].
///
/// Clamping is the only transformation applied; the score is never re-derived here.
/// `Validation::valid` is not consulted — admission is `carve.rs`'s gate, not this module's.
pub fn structural_validity(v: &Validation) -> f64 {
    clamp01(v.score)
}

/// Shannon entropy of `data` in bits per byte, over the 256-symbol byte histogram.
/// Range [0.0, 8.0]. Empty input is 0.0.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c != 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    // Rounding in the sum can leave a hair below zero for a single-symbol input.
    if h < 0.0 {
        0.0
    } else {
        h
    }
}

/// Term 3, weight 0.15. Shannon entropy over the object as recovered, scored against the
/// published band for `kind`. Objects shorter than [`MIN_ENTROPY_SAMPLE`] return
/// [`ENTROPY_UNKNOWN`] because the sample bias exceeds the band margin at that length.
pub fn entropy_consistency(kind: Kind, data: &[u8]) -> f64 {
    if data.len() < MIN_ENTROPY_SAMPLE {
        return ENTROPY_UNKNOWN;
    }
    let e = shannon_entropy(data);
    let b = entropy_band(kind);
    trapezoid(e, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero)
}

/// Term 4, weight 0.10. Recovered length against the published bounds for `kind`,
/// interpolated on log2(bytes) because format size ranges are multiplicative.
pub fn size_plausibility(kind: Kind, len: u64) -> f64 {
    if len == 0 {
        return 0.0;
    }
    let b = size_bounds(kind);
    let l2 = |v: u64| (v.max(1) as f64).log2();
    trapezoid(
        l2(len),
        l2(b.zero_lo),
        l2(b.full_lo),
        l2(b.full_hi),
        l2(b.zero_hi),
    )
}

/// The published confidence function. Computes all four terms and their weighted sum.
///
/// `data` must be the object exactly as recovered, starting at the header — the same bytes
/// whose SHA-256 goes into [`crate::carve::Recovered`]. When validation failed and no end was
/// determined, `carve.rs` passes the span it fell back to; the entropy and size terms then
/// score that fallback span, which is the honest thing for them to report on.
pub fn confidence(
    kind: Kind,
    sig_ok: bool,
    footer_found: bool,
    v: &Validation,
    data: &[u8],
) -> Confidence {
    let signature_integrity = signature_integrity(kind, sig_ok, footer_found);
    let structural_validity = structural_validity(v);
    let entropy_consistency = entropy_consistency(kind, data);
    let size_plausibility = size_plausibility(kind, data.len() as u64);

    let total = clamp01(
        W_SIGNATURE * signature_integrity
            + W_STRUCTURE * structural_validity
            + W_ENTROPY * entropy_consistency
            + W_SIZE * size_plausibility,
    );

    Confidence {
        signature_integrity,
        structural_validity,
        entropy_consistency,
        size_plausibility,
        total,
    }
}

/// Clamp into [0,1], mapping NaN to 0.0.
///
/// Not `f64::clamp`: that propagates NaN, and a NaN reaching `Confidence::total` would put a
/// score on screen that compares false against every threshold. A malformed
/// `Validation::score` must degrade to "no structural evidence", not to an unorderable value.
fn clamp01(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

/// Trapezoidal membership: 0 at or below `lo_zero`, rising linearly to 1.0 at `lo_full`,
/// flat to `hi_full`, falling linearly to 0 at or above `hi_zero`.
fn trapezoid(x: f64, lo_zero: f64, lo_full: f64, hi_full: f64, hi_zero: f64) -> f64 {
    if x <= lo_zero || x >= hi_zero {
        0.0
    } else if x < lo_full {
        clamp01((x - lo_zero) / (lo_full - lo_zero))
    } else if x <= hi_full {
        1.0
    } else {
        clamp01((hi_zero - x) / (hi_zero - hi_full))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- stubs -------------------------------------------------------------------------
    // structure.rs is another agent's file. These tests construct Validation directly from
    // its published field contract so this module is tested without depending on the walker.

    fn v(valid: bool, score: f64, end: Option<u64>) -> Validation {
        Validation {
            valid,
            end,
            score,
            detail: String::from("stub"),
        }
    }

    /// A corpus of exactly known entropy: `k` distinct symbols, each equally frequent, so
    /// Shannon entropy is exactly log2(k) bits/byte. Deterministic, so no test result varies
    /// by machine. `k=181` gives 7.4997 bits, inside every compressed-kind plateau; `k=256`
    /// gives exactly 8.0; `k=2` gives exactly 1.0.
    fn uniform_over(k: usize, reps: usize) -> Vec<u8> {
        assert!((1..=256).contains(&k));
        (0..k * reps).map(|i| (i % k) as u8).collect()
    }

    /// Entropy sitting on the compressed-kind plateau (7.00..=7.99), long enough and large
    /// enough to score 1.0 on size for every kind. log2(181) = 7.4997 bits/byte.
    fn plateau_corpus() -> Vec<u8> {
        uniform_over(181, 1200) // 217,200 bytes
    }

    /// Deterministic pseudo-random bytes, for range-fuzzing the terms.
    fn high_entropy(n: usize) -> Vec<u8> {
        let mut s: u64 = 0x2545_F491_4F6C_DD1D;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    fn all_kinds() -> Vec<Kind> {
        vec![
            Kind::Jpeg,
            Kind::Png,
            Kind::Pdf,
            Kind::Zip,
            Kind::Sqlite,
            Kind::Mp4,
            Kind::Gzip,
        ]
    }

    // ---- the formula itself ------------------------------------------------------------

    #[test]
    fn weights_sum_to_one() {
        assert!((W_SIGNATURE + W_STRUCTURE + W_ENTROPY + W_SIZE - 1.0).abs() < 1e-12);
    }

    #[test]
    fn published_weights_are_the_published_numbers() {
        assert_eq!(W_SIGNATURE, 0.40);
        assert_eq!(W_STRUCTURE, 0.35);
        assert_eq!(W_ENTROPY, 0.15);
        assert_eq!(W_SIZE, 0.10);
    }

    #[test]
    fn total_is_the_weighted_sum_of_the_four_reported_terms() {
        // The reported terms must reconstruct the reported total. If they ever stop doing
        // that, a score is on screen whose derivation is not.
        let data = high_entropy(200_000);
        for k in all_kinds() {
            for (ok, ff, sc) in [
                (true, true, 1.0),
                (true, false, 0.5),
                (false, false, 0.0),
                (true, true, 0.25),
            ] {
                let c = confidence(k, ok, ff, &v(sc > 0.0, sc, None), &data);
                let expect = W_SIGNATURE * c.signature_integrity
                    + W_STRUCTURE * c.structural_validity
                    + W_ENTROPY * c.entropy_consistency
                    + W_SIZE * c.size_plausibility;
                assert!(
                    (c.total - expect).abs() < 1e-12,
                    "{:?} total {} != weighted sum {}",
                    k.as_str(),
                    c.total,
                    expect
                );
            }
        }
    }

    #[test]
    fn every_term_is_within_zero_and_one() {
        let corpora: Vec<Vec<u8>> = vec![
            vec![],
            vec![0u8; 1],
            vec![0u8; 4096],
            vec![0xFFu8; 100_000],
            high_entropy(2048),
            high_entropy(500_000),
        ];
        for k in all_kinds() {
            for d in &corpora {
                for sc in [-5.0, 0.0, 0.5, 1.0, 7.0, f64::NAN] {
                    let c = confidence(k, true, true, &v(true, sc, None), d);
                    for (name, t) in [
                        ("signature_integrity", c.signature_integrity),
                        ("structural_validity", c.structural_validity),
                        ("entropy_consistency", c.entropy_consistency),
                        ("size_plausibility", c.size_plausibility),
                        ("total", c.total),
                    ] {
                        assert!(
                            (0.0..=1.0).contains(&t),
                            "{} out of range: {} for {} len {}",
                            name,
                            t,
                            k.as_str(),
                            d.len()
                        );
                    }
                }
            }
        }
    }

    // ---- TERM 1: signature_integrity ---------------------------------------------------

    #[test]
    fn term1_header_mismatch_is_zero_for_every_kind_regardless_of_footer() {
        for k in all_kinds() {
            assert_eq!(signature_integrity(k, false, false), 0.00);
            assert_eq!(signature_integrity(k, false, true), 0.00);
        }
    }

    #[test]
    fn term1_ladder_for_kinds_that_define_a_terminator() {
        for k in all_kinds() {
            if !kind_defines_footer(k) {
                continue;
            }
            assert_eq!(
                signature_integrity(k, true, true),
                1.00,
                "{} header+footer",
                k.as_str()
            );
            assert_eq!(
                signature_integrity(k, true, false),
                0.50,
                "{} header only",
                k.as_str()
            );
        }
    }

    #[test]
    fn term1_footerless_kinds_are_capped_at_the_published_ceiling() {
        for k in all_kinds() {
            if kind_defines_footer(k) {
                continue;
            }
            // footer_found is meaningless for these; both inputs must land on the same rung.
            assert_eq!(signature_integrity(k, true, false), 0.75, "{}", k.as_str());
            assert_eq!(signature_integrity(k, true, true), 0.75, "{}", k.as_str());
        }
    }

    #[test]
    fn term1_rungs_are_strictly_ordered() {
        assert!(SIG_HEADER_MISMATCH < SIG_HEADER_ONLY);
        assert!(SIG_HEADER_ONLY < SIG_NO_FOOTER_DEFINED);
        assert!(SIG_NO_FOOTER_DEFINED < SIG_HEADER_AND_FOOTER);
    }

    #[test]
    fn term1_footerless_ceiling_caps_the_whole_score_at_0_90() {
        // Published consequence: a byte-perfect GZIP/MP4/SQLITE cannot reach 1.00.
        let data = plateau_corpus();
        for k in all_kinds() {
            if kind_defines_footer(k) {
                continue;
            }
            let c = confidence(k, true, true, &v(true, 1.0, Some(217_200)), &data);
            assert!(
                (c.total - 0.90).abs() < 1e-12,
                "{} best case is {}, expected 0.90",
                k.as_str(),
                c.total
            );
        }
    }

    #[test]
    fn term1_never_consults_structure_or_payload() {
        // Same inputs at the signature layer must produce the same rung no matter what the
        // walker said or what the bytes look like. This is what keeps the terms independent.
        let a = signature_integrity(Kind::Jpeg, true, true);
        let b = signature_integrity(Kind::Jpeg, true, true);
        assert_eq!(a, b);
        let c1 = confidence(Kind::Jpeg, true, true, &v(false, 0.0, None), &high_entropy(2048));
        let c2 = confidence(Kind::Jpeg, true, true, &v(true, 1.0, Some(9)), &vec![0u8; 200_000]);
        assert_eq!(c1.signature_integrity, c2.signature_integrity);
    }

    // ---- TERM 2: structural_validity ---------------------------------------------------

    #[test]
    fn term2_is_the_validation_score_verbatim() {
        for s in [0.0, 0.125, 0.25, 0.5, 0.75, 0.9999, 1.0] {
            assert_eq!(structural_validity(&v(true, s, None)), s);
        }
    }

    #[test]
    fn term2_clamps_out_of_range_scores_but_does_not_otherwise_transform_them() {
        assert_eq!(structural_validity(&v(true, 1.5, None)), 1.0);
        assert_eq!(structural_validity(&v(true, -0.5, None)), 0.0);
        assert_eq!(structural_validity(&v(true, f64::NAN, None)), 0.0);
        assert_eq!(structural_validity(&v(true, f64::INFINITY, None)), 1.0);
    }

    #[test]
    fn term2_ignores_the_valid_flag_by_design() {
        // Admission is carve.rs's gate. Documented seam; asserted so it cannot drift silently.
        assert_eq!(structural_validity(&v(false, 0.8, None)), 0.8);
        assert_eq!(structural_validity(&v(true, 0.8, None)), 0.8);
    }

    #[test]
    fn term2_rejected_structure_costs_exactly_the_structure_weight() {
        let data = high_entropy(100_000);
        let good = confidence(Kind::Jpeg, true, true, &v(true, 1.0, Some(100_000)), &data);
        let bad = confidence(Kind::Jpeg, true, true, &v(false, 0.0, None), &data);
        assert!((good.total - bad.total - W_STRUCTURE).abs() < 1e-12);
    }

    // ---- TERM 3: shannon_entropy -------------------------------------------------------

    #[test]
    fn entropy_of_empty_input_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_of_one_repeated_symbol_is_zero() {
        assert_eq!(shannon_entropy(&[0x41u8; 4096]), 0.0);
        assert_eq!(shannon_entropy(&[0x00u8; 1]), 0.0);
    }

    #[test]
    fn entropy_of_two_equiprobable_symbols_is_one_bit() {
        let d: Vec<u8> = (0..4096).map(|i| if i % 2 == 0 { 0u8 } else { 1u8 }).collect();
        assert!((shannon_entropy(&d) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn entropy_of_all_256_bytes_equally_is_exactly_eight_bits() {
        let d: Vec<u8> = (0..=255u8).cycle().take(256 * 64).collect();
        assert!((shannon_entropy(&d) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn entropy_of_sixteen_equiprobable_symbols_is_four_bits() {
        let d: Vec<u8> = (0..16u8).cycle().take(16 * 256).collect();
        assert!((shannon_entropy(&d) - 4.0).abs() < 1e-12);
    }

    #[test]
    fn entropy_never_leaves_zero_to_eight() {
        for d in [
            vec![],
            vec![7u8; 10_000],
            high_entropy(50_000),
            (0..=255u8).collect::<Vec<u8>>(),
        ] {
            let e = shannon_entropy(&d);
            assert!((0.0..=8.0).contains(&e), "entropy {} out of range", e);
        }
    }

    // ---- TERM 3: entropy_consistency ---------------------------------------------------

    #[test]
    fn term3_short_objects_report_no_information_not_a_score() {
        for n in [0usize, 1, 100, MIN_ENTROPY_SAMPLE - 1] {
            let d = high_entropy(n);
            assert_eq!(
                entropy_consistency(Kind::Jpeg, &d),
                ENTROPY_UNKNOWN,
                "len {}",
                n
            );
        }
        // One byte over the floor, the measurement is used.
        let d = high_entropy(MIN_ENTROPY_SAMPLE);
        assert_ne!(entropy_consistency(Kind::Jpeg, &d), ENTROPY_UNKNOWN);
    }

    #[test]
    fn term3_zero_entropy_payload_scores_zero_for_every_kind() {
        let d = vec![0u8; 100_000];
        for k in all_kinds() {
            assert_eq!(
                entropy_consistency(k, &d),
                0.0,
                "{} scored a run of zeros",
                k.as_str()
            );
        }
    }

    #[test]
    fn term3_every_kind_scores_full_on_a_payload_inside_its_plateau() {
        let d = plateau_corpus();
        let e = shannon_entropy(&d);
        assert!(
            (e - 181f64.log2()).abs() < 1e-12,
            "corpus entropy {} is not log2(181)",
            e
        );
        assert!((7.00..=7.90).contains(&e), "corpus entropy {} left the plateau", e);
        for k in all_kinds() {
            assert_eq!(entropy_consistency(k, &d), 1.0, "{}", k.as_str());
        }
    }

    #[test]
    fn term3_an_exactly_uniform_payload_is_penalised_not_rewarded() {
        // A payload at exactly 8.0 bits/byte is an encrypted or random block, not a
        // compressed file: measured planted maximum on the fixture was PDF at 7.9491, and
        // every band's hi_full sits at or above that but below 8.00.
        let d = uniform_over(256, 800);
        assert!((shannon_entropy(&d) - 8.0).abs() < 1e-12);
        for k in all_kinds() {
            assert_eq!(entropy_consistency(k, &d), 0.0, "{} rewarded a uniform block", k.as_str());
        }
    }

    #[test]
    fn term3_band_edges_are_the_published_edges() {
        // The trapezoid must actually turn where the published table says it turns.
        for k in all_kinds() {
            let b = entropy_band(k);
            assert!(b.lo_zero < b.lo_full && b.lo_full <= b.hi_full && b.hi_full < b.hi_zero);
            assert_eq!(trapezoid(b.lo_zero, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero), 0.0);
            assert_eq!(trapezoid(b.lo_full, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero), 1.0);
            assert_eq!(trapezoid(b.hi_full, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero), 1.0);
            assert_eq!(trapezoid(b.hi_zero, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero), 0.0);
            let mid = (b.lo_zero + b.lo_full) / 2.0;
            let s = trapezoid(mid, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero);
            assert!((s - 0.5).abs() < 1e-12, "{} midpoint {}", k.as_str(), s);
        }
    }

    #[test]
    fn term3_published_bands_contain_the_measured_fixture_ranges() {
        // Every number below is the measured min/max over the 5 planted files of that kind,
        // read from the manifest extents of out/fixture.img. If a band ever stops containing
        // its own corpus, this fails.
        let measured: &[(Kind, f64, f64)] = &[
            (Kind::Jpeg, 7.8716, 7.8995),
            (Kind::Png, 7.7986, 7.8414),
            (Kind::Gzip, 7.8669, 7.8713),
            (Kind::Zip, 7.8835, 7.8878), // DOCX
            (Kind::Mp4, 7.7600, 7.7646),
            (Kind::Pdf, 7.9079, 7.9491),
            (Kind::Sqlite, 5.3189, 5.5076),
        ];
        for (k, lo, hi) in measured {
            let b = entropy_band(*k);
            assert!(
                *lo >= b.lo_full && *hi <= b.hi_full,
                "{}: measured {}..{} outside plateau {}..{}",
                k.as_str(),
                lo,
                hi,
                b.lo_full,
                b.hi_full
            );
        }
    }

    #[test]
    fn term3_residue_entropy_scores_below_planted_entropy_for_jpeg() {
        // Measured residue span entropies for the 8 planted JPEG false positives, and the
        // measured planted JPEG range. The band must rank them in that order.
        let residue = [6.1800, 6.6964, 6.8861, 6.9463, 7.0426, 7.1645, 7.3280, 7.4172];
        let b = entropy_band(Kind::Jpeg);
        let planted_lo = trapezoid(7.8716, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero);
        assert_eq!(planted_lo, 1.0);
        for e in residue {
            let s = trapezoid(e, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero);
            assert!(s <= planted_lo, "residue {} scored {} >= planted", e, s);
        }
        // The two lowest are strictly separated.
        assert!(trapezoid(6.1800, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero) < 0.5);
    }

    // ---- TERM 4: size_plausibility -----------------------------------------------------

    #[test]
    fn term4_zero_length_scores_zero() {
        for k in all_kinds() {
            assert_eq!(size_plausibility(k, 0), 0.0, "{}", k.as_str());
        }
    }

    #[test]
    fn term4_below_the_format_floor_scores_zero() {
        for k in all_kinds() {
            let b = size_bounds(k);
            assert_eq!(size_plausibility(k, b.zero_lo), 0.0, "{}", k.as_str());
            assert_eq!(size_plausibility(k, b.zero_lo / 2), 0.0, "{}", k.as_str());
            assert_eq!(size_plausibility(k, 1), 0.0, "{}", k.as_str());
        }
    }

    #[test]
    fn term4_plateau_scores_full_and_bounds_are_ordered() {
        for k in all_kinds() {
            let b = size_bounds(k);
            assert!(b.zero_lo < b.full_lo && b.full_lo < b.full_hi && b.full_hi < b.zero_hi);
            assert_eq!(size_plausibility(k, b.full_lo), 1.0, "{}", k.as_str());
            assert_eq!(size_plausibility(k, b.full_hi), 1.0, "{}", k.as_str());
            let geo = ((b.full_lo as f64) * (b.full_hi as f64)).sqrt() as u64;
            assert_eq!(size_plausibility(k, geo), 1.0, "{}", k.as_str());
        }
    }

    #[test]
    fn term4_above_the_ceiling_decays_to_zero() {
        for k in all_kinds() {
            let b = size_bounds(k);
            assert_eq!(size_plausibility(k, b.zero_hi), 0.0, "{}", k.as_str());
            assert_eq!(size_plausibility(k, b.zero_hi * 4), 0.0, "{}", k.as_str());
            let mid = ((b.full_hi as f64) * (b.zero_hi as f64)).sqrt() as u64;
            let s = size_plausibility(k, mid);
            assert!(
                s > 0.0 && s < 1.0,
                "{} geometric midpoint above ceiling scored {}",
                k.as_str(),
                s
            );
        }
    }

    #[test]
    fn term4_is_monotone_across_the_low_ramp_and_the_high_ramp() {
        for k in all_kinds() {
            let b = size_bounds(k);
            let mut last = -1.0;
            let mut n = b.zero_lo;
            while n < b.full_lo {
                let s = size_plausibility(k, n);
                assert!(s >= last, "{} not monotone rising at {}", k.as_str(), n);
                last = s;
                n = (n as f64 * 1.1) as u64 + 1;
            }
            let mut last = 2.0;
            let mut n = b.full_hi;
            while n < b.zero_hi {
                let s = size_plausibility(k, n);
                assert!(s <= last, "{} not monotone falling at {}", k.as_str(), n);
                last = s;
                n = (n as f64 * 1.1) as u64 + 1;
            }
        }
    }

    #[test]
    fn term4_the_shipped_max_len_clamp_is_penalised_by_this_table() {
        // A candidate that ran to `Signature::max_len` never found an end, and this term has
        // to be able to say so. That only works while max_len sits at or below zero_hi.
        // Asserted against the shipped signature table, not against a copy of it.
        for k in all_kinds() {
            let b = size_bounds(k);
            let sig = crate::signature::signature_for(k)
                .unwrap_or_else(|| panic!("{} missing from SIGNATURES", k.as_str()));
            assert!(
                sig.max_len <= b.zero_hi,
                "{}: max_len {} exceeds this table's ceiling {}",
                k.as_str(),
                sig.max_len,
                b.zero_hi
            );
            let at_clamp = size_plausibility(k, sig.max_len);
            assert!(
                at_clamp <= 0.5,
                "{}: an object at the {}-byte clamp still scores {} on size",
                k.as_str(),
                sig.max_len,
                at_clamp
            );
        }
    }

    #[test]
    fn term4_published_bounds_contain_the_measured_fixture_sizes() {
        // Measured min/max size over the 5 planted files of each kind, from the manifest.
        let measured: &[(Kind, u64, u64)] = &[
            (Kind::Jpeg, 92_851, 108_462),
            (Kind::Png, 158_522, 260_595),
            (Kind::Gzip, 54_871, 127_302),
            (Kind::Zip, 32_453, 79_397), // DOCX
            (Kind::Mp4, 66_689, 221_041),
            (Kind::Pdf, 38_408, 54_214),
            (Kind::Sqlite, 110_592, 221_184),
        ];
        for (k, lo, hi) in measured {
            assert_eq!(size_plausibility(*k, *lo), 1.0, "{} min {}", k.as_str(), lo);
            assert_eq!(size_plausibility(*k, *hi), 1.0, "{} max {}", k.as_str(), hi);
        }
    }

    // ---- the separation property -------------------------------------------------------

    #[test]
    fn a_perfect_recovery_of_a_footer_bearing_kind_scores_one() {
        let d = plateau_corpus();
        for k in all_kinds() {
            if !kind_defines_footer(k) {
                continue;
            }
            let c = confidence(k, true, true, &v(true, 1.0, Some(217_200)), &d);
            assert!(
                (c.total - 1.0).abs() < 1e-12,
                "{} perfect recovery scored {}",
                k.as_str(),
                c.total
            );
        }
    }

    #[test]
    fn a_structurally_rejected_candidate_cannot_reach_the_admission_gate() {
        // A decoy scores 0 on structure by definition, so its ceiling is
        // NON_STRUCTURE_CEILING = 0.40 + 0 + 0.15 + 0.10 = 0.65. Asserted against the gate the
        // carver actually enforces, not against the 0.90 target this module once quoted.
        let d = plateau_corpus();
        for k in all_kinds() {
            let c = confidence(k, true, true, &v(false, 0.0, None), &d);
            assert!(
                c.total <= NON_STRUCTURE_CEILING + 1e-12,
                "{} rejected candidate reached {}",
                k.as_str(),
                c.total
            );
            assert!(
                c.total < MIN_CONFIDENCE,
                "{} rejected candidate reached {} against the {} gate",
                k.as_str(),
                c.total,
                MIN_CONFIDENCE
            );
        }
    }

    // ---- the admission gate and the breach point ---------------------------------------

    #[test]
    fn the_breach_point_is_derived_from_the_weights_and_the_gate() {
        // Not a transcription check: recompute it from the published constants and require
        // the exported const to agree. If a weight or the gate moves, both sides move.
        let expect = (MIN_CONFIDENCE - (W_SIGNATURE + W_ENTROPY + W_SIZE)) / W_STRUCTURE;
        assert!((STRUCTURAL_BREACH_POINT - expect).abs() < 1e-15);
        assert!((NON_STRUCTURE_CEILING - 0.65).abs() < 1e-12);
        // With the shipped weights and gate it lands on 0.285714. Stated so a reader can
        // check the arithmetic, asserted loosely so the derivation stays the source of truth.
        assert!(
            (STRUCTURAL_BREACH_POINT - 0.285_714_285_714_285_7).abs() < 1e-9,
            "breach point is {STRUCTURAL_BREACH_POINT}"
        );
        // A gate below the no-structure ceiling would admit every decoy outright; a breach
        // point above 1.0 would mean structure alone can never carry a candidate in.
        assert!(
            STRUCTURAL_BREACH_POINT > 0.0 && STRUCTURAL_BREACH_POINT <= 1.0,
            "the gate {MIN_CONFIDENCE} is unusable against a ceiling of {NON_STRUCTURE_CEILING}"
        );
    }

    #[test]
    fn a_decoy_at_the_breach_point_reaches_the_gate_and_below_it_does_not() {
        // The claim STRUCTURAL_BREACH_POINT makes, exercised through the real function:
        // full marks on signature, entropy and size — which is what all 8 residue JPEGs
        // already score — plus exactly this much structure is admission.
        let d = plateau_corpus();
        let at = confidence(
            Kind::Jpeg,
            true,
            true,
            &v(false, STRUCTURAL_BREACH_POINT, None),
            &d,
        );
        assert!(
            at.total >= MIN_CONFIDENCE - 1e-12,
            "a decoy at the breach point scored {} against the {} gate",
            at.total,
            MIN_CONFIDENCE
        );
        let below = confidence(
            Kind::Jpeg,
            true,
            true,
            &v(false, STRUCTURAL_BREACH_POINT - 0.001, None),
            &d,
        );
        assert!(
            below.total < MIN_CONFIDENCE,
            "a decoy just below the breach point scored {}",
            below.total
        );
    }

    #[test]
    fn the_gate_sits_strictly_inside_the_measured_separation() {
        // 0.6500 is the highest false positive measured on the fixture, 0.9000 the lowest
        // true positive. A gate outside that band is not a gate.
        assert!(MIN_CONFIDENCE > 0.65, "the gate admits the highest measured false positive");
        assert!(MIN_CONFIDENCE <= 0.90, "the gate rejects the lowest measured true positive");
        // And the reason it is not 0.90 itself: the footerless ceiling.
        let d = plateau_corpus();
        let footerless_best = confidence(Kind::Gzip, true, true, &v(true, 1.0, Some(217_200)), &d);
        assert!((footerless_best.total - 0.90).abs() < 1e-12);
        assert!(
            footerless_best.total >= MIN_CONFIDENCE,
            "the gate discards a byte-perfect footerless recovery"
        );
    }

    #[test]
    fn the_published_separation_holds_at_its_two_edges() {
        // Lowest true positive measured on the fixture: 0.9000 (a byte-perfect footerless
        // kind). Highest false positive measured: 0.6500 (a residue JPEG at full signature,
        // full entropy, full size, zero structure). Separation 0.2500.
        let d = plateau_corpus();
        let worst_tp = confidence(Kind::Gzip, true, false, &v(true, 1.0, Some(217_200)), &d);
        let best_fp = confidence(Kind::Jpeg, true, true, &v(false, 0.0, None), &d);
        assert!((worst_tp.total - 0.90).abs() < 1e-12, "{}", worst_tp.total);
        assert!((best_fp.total - 0.65).abs() < 1e-12, "{}", best_fp.total);
        assert!((worst_tp.total - best_fp.total - 0.25).abs() < 1e-12);
    }
}
