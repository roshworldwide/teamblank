//! Bifragment gap carving: recover an object whose bytes are split across two
//! non-adjacent extents, by searching a bounded two-dimensional lattice of
//! (first-fragment length, gap length) and asking the structure validator which
//! splice makes the object whole.
//!
//! # The problem
//!
//! Sequential carving reads from a header until the format says "done". That
//! fails the moment the filesystem allocator had to jump: everything after the
//! jump is another file's data or residue, and the object either never
//! terminates or terminates on foreign bytes. Bifragment gap carving is the
//! standard answer (Garfinkel, *Carving contiguous and fragmented files with
//! fast object validation*, DFRWS 2007): keep the header, cut the tail at a
//! candidate point, resume at a candidate point further on, and let the
//! validator decide.
//!
//! # The search space, and the bound on it
//!
//! Two free variables, both quantised to the **cluster grid**:
//!
//! * `hl` — the first fragment's length in bytes. Split points are the cluster
//!   boundaries strictly after `header_at`, so `hl` runs
//!   `first_boundary - header_at`, `+cluster`, `+2*cluster`, …
//! * `g` — the gap, in whole clusters, `1..=gaps`.
//!
//! The bounds, all of them published rather than implied:
//!
//! | dimension | bound | source |
//! |---|---|---|
//! | gap | `g * cluster <= max_gap_bytes`, **inclusive** | `CarveOpts::max_gap_bytes`, never hardcoded |
//! | gap floor | `g >= 1` | a gap of zero clusters is a contiguous object; sequential carving owns it |
//! | first fragment | `hl <= MAX_FIRST_FRAGMENT_CLUSTERS * cluster` | this module, [`MAX_FIRST_FRAGMENT_CLUSTERS`] |
//! | object total | `end <= min(max_len(kind), MAX_OBJECT_BYTES, data.len() - header_at)` | `signature::SIGNATURES` and [`MAX_OBJECT_BYTES`] |
//! | lattice | split and resume points are multiples of `cluster` | filesystem allocation granularity |
//!
//! **Inclusivity is observable, not academic.** The fixture publishes
//! `max_gap_clusters = 128`, `max_gap_is_inclusive = true`, and plants
//! `disposal_certificate.pdf` at a gap of exactly 128 clusters. The test is
//! `gap_bytes <= max_gap_bytes`, so `gaps = max_gap_bytes / cluster` and
//! `g = gaps` is searched. An exclusive bound loses that file, and
//! [`tests::gap_bound_is_inclusive_at_the_boundary`] pins the difference.
//!
//! **Why the cluster grid.** A byte-granular search over the same byte-space
//! costs `cluster^2` times as many validations — 4 194 304x at 2048 B/cluster —
//! and buys nothing, because a fragment that begins mid-cluster cannot be
//! produced by a cluster allocator. The ratio is measured, not asserted, by
//! [`tests::cluster_grid_versus_byte_grid_is_measured`] (both searches run to
//! completion on a miniature) and by
//! [`tests::fixture_byte_grid_control_does_not_finish`] (the byte grid runs on
//! the real fixture under a validation budget and does not reach the solution).
//!
//! # Search order and cost
//!
//! Outer loop: `hl` ascending. Inner loop: `g` ascending. The first splice that
//! validates *and is determined* (below) wins.
//!
//! That order makes cost interpretable. Ignoring the sequential probe and the
//! determinacy neighbours:
//!
//! ```text
//! validations(success) = (hl_true / cluster - 1) * gaps + g_true      (aligned header)
//! validations(failure) = MAX_FIRST_FRAGMENT_CLUSTERS * gaps
//! ```
//!
//! Cost is the honest counterweight to the capability, so [`Reassembly`]
//! carries the count and the caller is expected to print it.
//!
//! # Determinacy — why a validating splice is not yet a recovery
//!
//! A splice that validates is not necessarily the right splice. `validate` sees
//! only the assembled bytes, and a format whose validator does not cover every
//! byte of the object will accept an assembly in which residue has been
//! substituted for real content: same length, same structure, different file,
//! different SHA-256.
//!
//! MEASURED on `out/fixture.img` (sha256 d85612b2…) against `structure/` **as
//! shipped in this crate**, by walking every one of the 32 768 lattice cells for
//! all seven fragmented plants with no early exit, and comparing each accepted
//! assembly byte for byte against the planted file read out of the image at the
//! manifest's own extents. Reproduce with:
//!
//! ```text
//! cargo test --release -p sentinelwipe-carve --lib \
//!     bifragment::tests::fixture_lattice_enumeration -- --ignored --nocapture
//! ```
//!
//! ```text
//! plant                       cells  accepting  content-correct  determined
//! imaging_transcript.txt.gz   32768          1                1           1
//! entropy_heatmap.png         32768          1                1           1
//! disposal_certificate.pdf    32768         10                1           0
//! sealing_procedure.mov       32768       6660                1           0
//! handover_briefing.mov       32768       4096                1           0
//! media_inventory.docx        32768          0                0           0   (planted)
//! evidence_bag_seal.jpg       32768          0                0           0   (planted)
//! ```
//!
//! Read the middle two columns together and the problem is stated exactly:
//! `sealing_procedure.mov` has 6 660 assemblies the validator calls perfect and
//! 6 659 of them are a different file. Returning the first would be the silent
//! wrong-but-validating answer this module exists to prevent, and the fixture is
//! built so that it is the answer a naive search reaches first.
//!
//! So an accepted splice must also be **determined**: with everything else held
//! fixed, moving the split point one cluster either way, and moving the resume
//! point one cluster either way, must all fail to validate. Four extra
//! validations. A candidate that survives is pinned in both dimensions; one that
//! does not is skipped, and if the lattice ends with acceptances but no
//! determined one the search returns `None` and reports [`Stop::Ambiguous`].
//!
//! The rightmost column is what licenses the early exit. `search` stops at the
//! first determined hit, which is only sound if a determined hit is never wrong.
//! That is not argued here, it is asserted on the real image: across all seven
//! plants, **every determined splice is content-correct, and no plant has more
//! than one**. `fixture_lattice_enumeration_measures_ambiguity` fails if that
//! ever stops being true, which is the standing check behind the early exit.
//! The rule costs 4 validations on each recovery and changes nothing else.
//!
//! # Why the three refusals, and what each one costs the demo
//!
//! Neither the search nor its bounds are the reason three of the five solvable
//! plants are refused. In all three cases the true splice is inside the lattice
//! and IS accepted; the validator simply cannot tell it from the others.
//!
//! * **disposal_certificate.pdf — 10 accepting, 1 correct.** All ten sit at gap
//!   = 128 clusters, the true gap, and differ only in the split point:
//!   `hl` = 1..10 clusters. That interval is object 2's ~21 kB FlateDecode
//!   stream body, and `structure::pdf` resolves `startxref` and verifies 34 of
//!   34 xref offsets without ever decoding a stream, so every byte in the
//!   interval is unread. Since exactly one of the ten assemblies carries the
//!   planted bytes, and adding a check can only remove acceptances, a validator
//!   that inflated each `/FlateDecode` stream and checked its zlib Adler-32
//!   would leave exactly one — and the file would be recovered. **This is a gap
//!   in `structure/pdf.rs`, not in the search.**
//! * **sealing_procedure.mov / handover_briefing.mov — 6 660 and 4 096
//!   accepting, 1 correct each.** `mdat` declares its own length inside
//!   fragment 1, so the object's total length is fixed by the head alone and any
//!   tail of the right length tiles perfectly. QuickTime carries no checksum
//!   over sample data, so there is no byte in the format that separates the
//!   6 660. This is a limit of the container, not of `structure/mp4.rs`, and it
//!   is not repairable by any structure validator.
//! * `handover_briefing.mov` is worse than ambiguous: `structure::mp4` accepts
//!   the **contiguous** read at its header, so `search` refuses after one
//!   validation with [`Stop::Contiguous`] and never enters the lattice. The
//!   contiguous read is 66 689 bytes with the wrong SHA-256. Bifragment is right
//!   to stand down — sequential carving owns that case — but whoever owns
//!   `carve.rs` must know that sequential carving will emit a wrong object here
//!   unless it applies its own content test.
//!
//! Recovered on the fixture, therefore: **2 of the 5 solvable fragmented plants,
//! 0 of the 2 planted unsolvable, and 0 wrong.** That is a finding about
//! `structure/`, reported rather than hidden, and it is printed by name on every
//! run of `fixture_solvable_fragments_are_recovered_or_refused_never_wrong`.
//!
//! # What the fixture measurements cost to run
//!
//! MEASURED on this machine, Darwin arm64, whole-image `out/fixture.img` read
//! into memory once per test:
//!
//! ```text
//!   filter                                        threads  debug     release
//!   bifragment::tests::fixture                          1  246.5 s    28.1 s
//!   (whole crate, `cargo test -p sentinelwipe-carve`)   *  137.2 s    16.6 s
//!   fixture_lattice_enumeration  -- --ignored           1       —     75.8 s
//!   span_ceiling_cost            -- --ignored           1       —    198.7 s
//! ```
//!
//! The four refusals each walk the whole 32 768-cell lattice, which is the cost
//! the module is supposed to have; a debug build multiplies it by roughly ten.
//! **Run this crate's fixture tests with `--release`.** The two enumeration
//! measurements are `#[ignore]`d because they refuse to stop early by design;
//! everything load-bearing — the two planted failures, the two recoveries, the
//! never-wrong assertion — runs by default.
//!
//! # Buffer construction — why this is not `cluster^2` memcpy
//!
//! A naive implementation rebuilds `head ++ tail` per candidate and copies the
//! whole object every validation. Instead one working buffer `x` holds
//! `data[header_at .. header_at + window]`, and for candidate `(hl, g)` the head
//! is written *into* `x` at offset `g * cluster`; the bytes after it are already
//! `data[header_at + g*cluster + hl ..]`, which is exactly the wanted
//! continuation. The validator is handed `&x[g*cluster ..]`. Because `g`
//! ascends, each write lands strictly after the region any later `g` reads, and
//! the buffer is restored from `data` once per `hl`. Cost per validation is
//! `hl` bytes, independent of object size.
//! [`tests::sliding_head_buffer_equals_a_naive_splice`] checks the fast buffer
//! byte-for-byte against a naive splice across the whole lattice.
//!
//! # What this deliberately does not do
//!
//! * **It does not search backwards.** A physically reversed object
//!   (`evidence_bag_seal.jpg`, gap −77 clusters) is not solvable by a forward
//!   search and is reported as a failure.
//! * **It does not search three fragments.** A tri-fragment object
//!   (`media_inventory.docx`, gaps 11 then 29) is not solvable by a two-fragment
//!   search and is reported as a failure.
//!
//! Both are planted in the fixture to defeat this algorithm. Extending the
//! search to solve them would make the recovery figure a statement about the
//! fixture rather than about the carver.
//!
//! # Precondition, enforced here
//!
//! Bifragment carving applies only when the object does *not* validate
//! contiguously. The first thing [`bifragment`] does is one sequential probe;
//! if the object is whole in place it returns `None` rather than manufacturing
//! a two-extent answer. This is what stops a length-declaring format — MP4
//! declares `mdat`'s size in the first fragment — from being "reassembled" out
//! of the first candidate the lattice offers.

use crate::structure::{validate, Validation};
use crate::Kind;

/// A two-extent reassembly: `(byte_offset, byte_length)` per extent, in object
/// order, plus the number of structure validations the search spent.
#[derive(Clone, Debug, PartialEq)]
pub struct Reassembly {
    pub extents: Vec<(u64, u64)>,
    pub validations: u64,
}

/// Ceiling on the first fragment, in clusters.
///
/// Derivation, measured against `out/fixture.img`: the longest true first
/// fragment among the seven fragmented plants is 44 clusters
/// (`sealing_procedure.mov`), so 256 carries 5.8x headroom. At 2048 B/cluster
/// that is a 512 KiB first fragment.
///
/// The bound is what makes a *failed* search terminate in bounded time: an
/// exhausted search costs `MAX_FIRST_FRAGMENT_CLUSTERS * gaps` validations,
/// 32 768 at the fixture's 128-cluster gap bound. Without it the ceiling would
/// be the format's `max_len` and a failure would cost thousands of times more —
/// which matters, because every residue signature hit that survives to this
/// point pays the failure cost.
///
/// Consequence, stated rather than hidden: an object whose first fragment
/// exceeds 512 KiB is not recovered. That is a bound, not a success.
pub const MAX_FIRST_FRAGMENT_CLUSTERS: u64 = 256;

/// Object-size ceiling for the two-fragment search, in bytes.
///
/// This is the length of the slice handed to `validate` on every candidate, so
/// it sets the cost of a validation as directly as the lattice sets their
/// number. `SIGNATURES` carries `max_len` values of 32 to 256 MiB, which are
/// the right bounds for a *sequential* scan and ruinous here, because a
/// footer-scanning validator reads the whole slice on every candidate.
///
/// MEASURED, one exhausted `disposal_certificate.pdf` search against the
/// shipped `structure/` module, release build, Darwin arm64. 32 779 validations
/// in every row — the lattice is identical and only the slice changes.
/// Reproduce with `bifragment::tests::span_ceiling_cost_is_measured`
/// (`-- --ignored --nocapture`):
///
/// ```text
///   span ceiling                    elapsed
///   64 MiB (SIGNATURES max_len)     169.96 s
///    4 MiB                           18.57 s
///    1 MiB                           10.10 s
/// ```
///
/// So this constant is the one knob trading recoverable object size against
/// search time. The trade is not linear below a few MiB — the shipped PDF
/// validator does work proportional to the xref table as well as to the slice —
/// which is why the three rows above are measurements and not a formula.
/// 1 MiB is 4x the largest planted file (260 595 bytes, `seizure_photo_a.png`).
///
/// The consequence, stated rather than hidden: **an object longer than 1 MiB is
/// not reassembled by this module.** Sequential carving is unaffected — it uses
/// `SIGNATURES::max_len`; this bound applies only to the two-fragment search.
/// The working buffer is at most `MAX_OBJECT_BYTES + max_gap_bytes`.
///
/// The way to lift it without paying for it is to bound the slice by the
/// object's own footer instead of by a constant: `SIGNATURES` already carries
/// `footer` for JPEG, PNG, PDF and ZIP, so one linear scan for footer
/// occurrences would size each candidate's slice to the object rather than to
/// the ceiling. Not built here; named so it is not rediscovered.
pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024;

/// Object-size ceiling used when `signature::SIGNATURES` carries no `max_len`
/// for the kind (or carries zero).
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 16 * 1024 * 1024;

/// Why a search stopped. Diagnostics; the public entry point collapses this to
/// `Option<Reassembly>`.
///
/// INTEGRATOR NOTE: making this and [`search`] `pub` is a one-word change, and
/// worth making if the demo wants to print *why* an object was refused —
/// `Ambiguous` and `Contiguous` are different sentences on the slide. It is
/// `pub(crate)` only because the Phase 2 interface contract does not name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Stop {
    /// A splice validated.
    Solved,
    /// The object validates contiguously — sequential carving owns it.
    Contiguous,
    /// The whole bounded lattice was searched and nothing validated.
    Exhausted,
    /// Splices validated, but none had a determined split and resume point, so
    /// the object cannot be stated. A refusal, never a guess.
    Ambiguous,
    /// The validation budget ran out before the lattice did (measurement only).
    Budget,
    /// The inputs do not describe a searchable lattice.
    Degenerate,
}

/// The bounded lattice, resolved from the caller's options before any work.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct Plan {
    /// Absolute offset of the header in `data`.
    pub header_at: u64,
    /// Lattice step in bytes. `cluster` in production; 1 for the byte-grid control.
    pub grid: u64,
    /// Number of gap steps searched: `g` runs `1..=gaps`.
    pub gaps: u64,
    /// Length of the shortest candidate first fragment.
    pub first_head: u64,
    /// Largest candidate first fragment, in bytes.
    pub max_head: u64,
    /// Ceiling on the total object length, in bytes.
    pub span: u64,
    /// Working-buffer length, relative to `header_at`.
    pub window: u64,
    /// Validation ceiling. `u64::MAX` in production.
    pub budget: u64,
}

#[allow(dead_code)]
impl Plan {
    /// Resolve the lattice, or `None` if the inputs cannot describe one.
    pub(crate) fn new(
        data_len: u64,
        span: u64,
        header_at: u64,
        max_gap_bytes: u64,
        grid: u64,
        max_head_bytes: u64,
    ) -> Option<Plan> {
        if grid == 0 || header_at >= data_len {
            return None;
        }
        let avail = data_len - header_at;
        let span = span.min(avail);
        // A two-extent object needs at least one byte in each extent.
        if span < 2 {
            return None;
        }
        // Gap bound is INCLUSIVE: g * grid <= max_gap_bytes.
        let gaps = max_gap_bytes / grid;
        if gaps == 0 {
            return None;
        }
        // First split point: the first lattice boundary strictly after the header.
        let first_head = ((header_at / grid) + 1) * grid - header_at;
        let max_head = max_head_bytes.min(span - 1);
        if first_head > max_head {
            return None;
        }
        let window = avail.min(gaps.saturating_mul(grid).saturating_add(span));
        Some(Plan {
            header_at,
            grid,
            gaps,
            first_head,
            max_head,
            span,
            window,
            budget: u64::MAX,
        })
    }

    /// Number of candidate first-fragment lengths.
    pub(crate) fn splits(&self) -> u64 {
        (self.max_head - self.first_head) / self.grid + 1
    }

    /// Size of the lattice: the worst-case validation count of a failed search.
    pub(crate) fn lattice(&self) -> u64 {
        self.splits().saturating_mul(self.gaps)
    }
}

/// The result of one bounded search, including the cost of a failure.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct Outcome {
    pub found: Option<Reassembly>,
    pub validations: u64,
    pub stop: Stop,
    /// How many splices the validator accepted. `Ambiguous` with `accepted`
    /// large is a different sentence on the slide from `Exhausted` with
    /// `accepted` zero: the first says the validator cannot separate thousands
    /// of structurally perfect assemblies, the second says the object is not
    /// there in two forward fragments at all.
    pub accepted: u64,
}

/// Object-size ceiling for a kind, taken from the published signature table so
/// the number lives in exactly one file.
fn span_ceiling(kind: Kind, avail: u64) -> u64 {
    let want = kind.as_str();
    let mut max_len = DEFAULT_MAX_OBJECT_BYTES;
    for sig in crate::signature::SIGNATURES {
        if sig.kind.as_str() == want {
            if sig.max_len > 0 {
                max_len = sig.max_len;
            }
            break;
        }
    }
    max_len.min(MAX_OBJECT_BYTES).min(avail)
}

/// Search forward from a header for a second fragment that completes the object.
///
/// `data` is the whole image; `header_at` is an absolute offset into it.
/// `max_gap_bytes` comes from `CarveOpts` and is applied inclusively:
/// a gap of exactly `max_gap_bytes` is searched. `cluster` is the allocation
/// granularity, and both the split point and the resume point are constrained
/// to it.
///
/// Returns `None` — never a guess — when the object validates contiguously,
/// when the lattice is exhausted, or when the inputs are degenerate. The
/// returned [`Reassembly::validations`] is the measured cost of the recovery,
/// including the one sequential probe.
pub fn bifragment(
    data: &[u8],
    kind: Kind,
    header_at: u64,
    max_gap_bytes: u64,
    cluster: u64,
) -> Option<Reassembly> {
    let data_len = data.len() as u64;
    if header_at >= data_len || cluster == 0 {
        return None;
    }
    let span = span_ceiling(kind, data_len - header_at);
    let plan = Plan::new(
        data_len,
        span,
        header_at,
        max_gap_bytes,
        cluster,
        MAX_FIRST_FRAGMENT_CLUSTERS.saturating_mul(cluster),
    )?;
    search(data, &plan, |buf| validate(kind, buf)).found
}

/// The counted search. Separated from [`bifragment`] so tests can inject a stub
/// validator, drive the byte-grid control, and read the cost of a *failure* —
/// which the public `Option` return necessarily discards.
pub(crate) fn search<F>(data: &[u8], plan: &Plan, mut check: F) -> Outcome
where
    F: FnMut(&[u8]) -> Validation,
{
    let h = plan.header_at as usize;
    let window = plan.window as usize;
    let grid = plan.grid as usize;
    if window == 0 || h + window > data.len() {
        return Outcome { found: None, validations: 0, stop: Stop::Degenerate, accepted: 0 };
    }

    let mut validations: u64 = 0;

    // Precondition probe. Bifragment carving applies only where sequential
    // carving has already failed; if the object is whole in place, say so and
    // return nothing rather than inventing a second extent.
    {
        let seq_len = (plan.span as usize).min(window);
        let v = check(&data[h..h + seq_len]);
        validations += 1;
        if v.valid {
            return Outcome { found: None, validations, stop: Stop::Contiguous, accepted: 1 };
        }
        if validations >= plan.budget {
            return Outcome { found: None, validations, stop: Stop::Budget, accepted: 0 };
        }
    }

    // Working buffer. `x[i]` mirrors `data[h + i]` except where a candidate head
    // has been written over it.
    let mut x = data[h..h + window].to_vec();
    let head_src = &data[h..];

    let mut hl = plan.first_head as usize;
    let max_head = plan.max_head as usize;
    let mut accepted: u64 = 0;
    let mut indeterminate: u64 = 0;
    let mut scratch: Vec<u8> = Vec::new();

    while hl <= max_head {
        let mut dirty_to = 0usize;

        for g in 1..=plan.gaps {
            let goff = (g as usize).saturating_mul(grid);
            // Slice handed to the validator: head ++ continuation.
            if goff + hl >= window {
                break; // no room for the head, let alone a second fragment
            }
            let len = (plan.span as usize).min(window - goff);
            if len <= hl {
                break; // second extent would be empty; larger g only shrinks it
            }

            x[goff..goff + hl].copy_from_slice(&head_src[..hl]);
            dirty_to = dirty_to.max(goff + hl);

            let v = check(&x[goff..goff + len]);
            validations += 1;

            if v.valid {
                if let Some(end) = v.end {
                    let end = end as usize;
                    if end <= hl {
                        // The head alone contains a whole object: contiguous
                        // after all, and independent of g. Do not manufacture a
                        // second extent.
                        return Outcome {
                            found: None,
                            validations,
                            stop: Stop::Contiguous,
                            accepted: accepted + 1,
                        };
                    }
                    if end <= len {
                        let second_len = (end - hl) as u64;
                        let resume = plan.header_at + hl as u64 + goff as u64;
                        if resume + second_len <= data.len() as u64 {
                            accepted += 1;
                            // A validating splice is a candidate, not an answer.
                            // Both the split point and the resume point must be
                            // pinned, or the validator is not covering the bytes
                            // that distinguish this assembly from a wrong one.
                            let (determined, spent) =
                                is_determined(data, plan, hl, g, &mut scratch, &mut check);
                            validations += spent;
                            if determined {
                                return Outcome {
                                    found: Some(Reassembly {
                                        extents: vec![
                                            (plan.header_at, hl as u64),
                                            (resume, second_len),
                                        ],
                                        validations,
                                    }),
                                    validations,
                                    stop: Stop::Solved,
                                    accepted,
                                };
                            }
                            indeterminate += 1;
                            // The neighbour probes wrote into their own scratch
                            // buffer, but `x` still holds this candidate's head.
                        }
                    }
                }
                // valid with no usable end: no extents can be stated, so this is
                // not a recovery. Keep searching rather than guessing a length.
            }

            if validations >= plan.budget {
                return Outcome { found: None, validations, stop: Stop::Budget, accepted };
            }
        }

        // Restore everything a head was written over, so the next hl sees clean
        // image bytes. x[0..grid] is never written.
        let lo = grid.min(window);
        let hi = dirty_to.min(window);
        if hi > lo {
            x[lo..hi].copy_from_slice(&data[h + lo..h + hi]);
        }

        hl += grid;
    }

    let stop = if indeterminate > 0 { Stop::Ambiguous } else { Stop::Exhausted };
    Outcome { found: None, validations, stop, accepted }
}

/// Assemble `head ++ continuation` for one candidate into `scratch`, the plain
/// way. Used only by the determinacy probe, which runs at most four times per
/// accepted candidate, so it does not need the sliding-head buffer.
///
/// `gap_clusters` may sit one step outside the searched lattice: the claim being
/// tested is about the image, not about where the search chose to stop.
fn splice(
    data: &[u8],
    plan: &Plan,
    hl: usize,
    gap_clusters: u64,
    scratch: &mut Vec<u8>,
) -> bool {
    if hl == 0 || gap_clusters == 0 {
        return false;
    }
    let h = plan.header_at as usize;
    let avail = data.len() - h;
    let goff = match (gap_clusters as usize).checked_mul(plan.grid as usize) {
        Some(v) => v,
        None => return false,
    };
    if goff >= avail {
        return false;
    }
    let len = (plan.span as usize).min(avail - goff);
    if len <= hl {
        return false;
    }
    let resume = h + hl + goff;
    if resume + (len - hl) > data.len() {
        return false;
    }
    scratch.clear();
    scratch.reserve(len);
    scratch.extend_from_slice(&data[h..h + hl]);
    scratch.extend_from_slice(&data[resume..resume + (len - hl)]);
    true
}

/// The four one-cluster neighbours of `(hl, gap)`. If any of them also
/// validates, the validator is blind to the bytes that separate this assembly
/// from that one, and neither can be stated as the object.
///
/// A neighbour that falls outside the image is skipped rather than counted as a
/// contradiction: it cannot disagree, so it cannot disqualify. The one such case
/// that is not an edge is `gap - 1` when `gap == 1`, which is the *contiguous*
/// read — and that has already been validated and rejected by the precondition
/// probe before the lattice was entered, so skipping it discards nothing.
/// `entropy_heatmap.png` is the plant this applies to: its true gap is one
/// cluster, so it is pinned by three neighbours rather than four.
///
/// Returns `(determined, validations spent)`.
fn is_determined<F>(
    data: &[u8],
    plan: &Plan,
    hl: usize,
    gap: u64,
    scratch: &mut Vec<u8>,
    check: &mut F,
) -> (bool, u64)
where
    F: FnMut(&[u8]) -> Validation,
{
    let grid = plan.grid as usize;
    let neighbours: [(usize, u64); 4] = [
        (hl.saturating_sub(grid), gap),
        (hl + grid, gap),
        (hl, gap.wrapping_sub(1)),
        (hl, gap + 1),
    ];
    let mut spent = 0u64;
    for (nhl, ngap) in neighbours {
        if nhl == hl && ngap == gap {
            continue;
        }
        if !splice(data, plan, nhl, ngap, scratch) {
            continue; // outside the image: cannot contradict, so it does not
        }
        let v = check(scratch);
        spent += 1;
        if v.valid {
            return (false, spent);
        }
    }
    (true, spent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structure::Validation;
    use std::time::Instant;

    // ------------------------------------------------------------------
    // Stub validators. structure.rs is another agent's file; the search
    // mechanics are tested against validators defined here so that the
    // lattice, the bounds and the buffer are checked independently of it.
    // ------------------------------------------------------------------

    fn ok(end: u64, detail: &str) -> Validation {
        Validation { valid: true, end: Some(end), score: 1.0, detail: detail.into() }
    }
    fn bad(detail: &str) -> Validation {
        Validation { valid: false, end: None, score: 0.0, detail: detail.into() }
    }

    /// A validator for a synthetic format: `MAGIC` then a 4-byte big-endian
    /// total length, then that many bytes of a payload whose byte at index `i`
    /// is `(i * 31 + 7) as u8`. It is exact — it accepts only the true bytes —
    /// which is what an honest structure validator does and what makes the
    /// planted-failure assertions mean something.
    const MAGIC: &[u8] = b"SWOBJ";

    fn synth_object(total: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(total);
        v.extend_from_slice(MAGIC);
        v.extend_from_slice(&(total as u32).to_be_bytes());
        for i in 0..total - 9 {
            v.push(payload_byte(i));
        }
        v
    }
    fn payload_byte(i: usize) -> u8 {
        (i.wrapping_mul(31).wrapping_add(7)) as u8
    }

    fn synth_validate(buf: &[u8]) -> Validation {
        if buf.len() < 9 || &buf[..5] != MAGIC {
            return bad("no magic");
        }
        let total = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;
        if total < 9 || total > buf.len() {
            return bad("truncated");
        }
        for i in 0..total - 9 {
            if buf[9 + i] != payload_byte(i) {
                return bad("payload mismatch");
            }
        }
        ok(total as u64, "synthetic object complete")
    }

    /// Lay a synthetic object into a canvas at the given extents.
    fn plant(canvas_len: usize, obj: &[u8], extents: &[(usize, usize)]) -> Vec<u8> {
        // Filler is a deterministic non-matching pattern; it must never equal
        // the object's payload, or the test would be measuring luck.
        let mut c: Vec<u8> = (0..canvas_len).map(|i| (i % 251) as u8 ^ 0xA5).collect();
        let mut cursor = 0usize;
        for &(off, len) in extents {
            c[off..off + len].copy_from_slice(&obj[cursor..cursor + len]);
            cursor += len;
        }
        assert_eq!(cursor, obj.len(), "extents must cover the object exactly");
        c
    }

    fn plan_for(
        data_len: usize,
        header_at: u64,
        max_gap_bytes: u64,
        grid: u64,
        max_head_bytes: u64,
    ) -> Plan {
        Plan::new(
            data_len as u64,
            data_len as u64 - header_at,
            header_at,
            max_gap_bytes,
            grid,
            max_head_bytes,
        )
        .expect("plan")
    }

    // ------------------------------------------------------------------
    // 1 · the lattice: bound, inclusivity, granularity
    // ------------------------------------------------------------------

    /// The property `disposal_certificate.pdf` was planted to expose: a gap of
    /// exactly `max_gap_bytes` is inside the search, and one cluster more is not.
    #[test]
    fn gap_bound_is_inclusive_at_the_boundary() {
        let cluster = 64u64;
        let max_gap_clusters = 8u64;
        let max_gap_bytes = max_gap_clusters * cluster;

        // first fragment 3 clusters, gap exactly 8 clusters, remainder after.
        let obj = synth_object(300);
        let f1 = 3 * cluster as usize;
        let at_bound = plant(
            2048,
            &obj,
            &[(0, f1), (f1 + (max_gap_clusters as usize) * 64, obj.len() - f1)],
        );
        let p = plan_for(at_bound.len(), 0, max_gap_bytes, cluster, 16 * cluster);
        let out = search(&at_bound, &p, |b| synth_validate(b));
        assert_eq!(out.stop, Stop::Solved, "gap == max_gap_bytes must be searched");
        let r = out.found.unwrap();
        assert_eq!(
            r.extents,
            vec![
                (0, f1 as u64),
                ((f1 + max_gap_clusters as usize * 64) as u64, (obj.len() - f1) as u64)
            ]
        );

        // one cluster past the bound: the same object must NOT be found.
        let past = plant(
            2048,
            &obj,
            &[(0, f1), (f1 + (max_gap_clusters as usize + 1) * 64, obj.len() - f1)],
        );
        let out = search(&past, &p, |b| synth_validate(b));
        assert_eq!(out.stop, Stop::Exhausted, "gap > max_gap_bytes must be outside the search");
        assert!(out.found.is_none());
    }

    /// `max_gap_bytes` is the caller's, not the module's.
    #[test]
    fn gap_bound_comes_from_the_caller() {
        let cluster = 64u64;
        let obj = synth_object(300);
        let f1 = 2 * cluster as usize;
        let gap_clusters = 5usize;
        let img = plant(
            2048,
            &obj,
            &[(0, f1), (f1 + gap_clusters * 64, obj.len() - f1)],
        );

        let tight = plan_for(img.len(), 0, 4 * cluster, cluster, 16 * cluster);
        assert_eq!(search(&img, &tight, |b| synth_validate(b)).stop, Stop::Exhausted);

        let loose = plan_for(img.len(), 0, 5 * cluster, cluster, 16 * cluster);
        assert_eq!(search(&img, &loose, |b| synth_validate(b)).stop, Stop::Solved);
    }

    /// Fragments start on cluster boundaries. A split that does not is outside
    /// the lattice by construction, and the search says so rather than finding it.
    #[test]
    fn search_is_confined_to_the_cluster_lattice() {
        let cluster = 64u64;
        let obj = synth_object(300);
        let f1 = 3 * cluster as usize + 17; // deliberately off-grid
        let img = plant(2048, &obj, &[(0, f1), (f1 + 320, obj.len() - f1)]);
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);
        assert_eq!(search(&img, &p, |b| synth_validate(b)).stop, Stop::Exhausted);

        // The same image on a byte grid does find it — the difference is the
        // lattice, not the data.
        let p1 = plan_for(img.len(), 0, 8 * cluster, 1, 16 * cluster);
        assert_eq!(search(&img, &p1, |b| synth_validate(b)).stop, Stop::Solved);
    }

    /// The cost formula in the module header, checked rather than claimed.
    #[test]
    fn validation_count_matches_the_published_formula() {
        let cluster = 64u64;
        let gaps = 8u64;
        let obj = synth_object(700); // longer than the longest first fragment tried
        for (k, g) in [(1usize, 1u64), (3, 5), (5, 8)] {
            let f1 = k * cluster as usize;
            let img = plant(
                4096,
                &obj,
                &[(0, f1), (f1 + (g as usize) * 64, obj.len() - f1)],
            );
            let p = plan_for(img.len(), 0, gaps * cluster, cluster, 16 * cluster);
            let out = search(&img, &p, |b| synth_validate(b));
            assert_eq!(out.stop, Stop::Solved, "k={k} g={g}");
            // sequential probe + lattice walk + up to four determinacy
            // neighbours (fewer when a neighbour falls outside the image).
            let walk = 1 + (k as u64 - 1) * gaps + g;
            assert!(
                out.validations >= walk && out.validations <= walk + 4,
                "k={k} g={g}: {} outside [{}, {}]",
                out.validations,
                walk,
                walk + 4
            );
        }
    }

    /// An exhausted search costs exactly the lattice, plus the probe.
    #[test]
    fn exhausted_search_costs_exactly_the_lattice() {
        let cluster = 64u64;
        let img = vec![0u8; 8192];
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);
        let out = search(&img, &p, |_| bad("never"));
        assert_eq!(out.stop, Stop::Exhausted);
        assert_eq!(p.splits(), 16);
        assert_eq!(p.gaps, 8);
        assert_eq!(out.validations, 1 + p.lattice());
    }

    // ------------------------------------------------------------------
    // 2 · the buffer
    // ------------------------------------------------------------------

    /// The sliding-head buffer must hand the validator exactly the bytes a
    /// naive `head ++ tail` splice would. Checked across the whole lattice.
    #[test]
    fn sliding_head_buffer_equals_a_naive_splice() {
        let cluster = 64u64;
        let data: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        for header_at in [0u64, 64, 1000 /* deliberately unaligned */] {
            let p = plan_for(data.len(), header_at, 6 * cluster, cluster, 10 * cluster);
            let mut seen: Vec<Vec<u8>> = Vec::new();
            search(&data, &p, |b| {
                seen.push(b.to_vec());
                bad("collect")
            });

            let mut expect: Vec<Vec<u8>> = Vec::new();
            // the sequential probe
            let h = header_at as usize;
            let seq = (p.span as usize).min(p.window as usize);
            expect.push(data[h..h + seq].to_vec());
            let mut hl = p.first_head as usize;
            while hl <= p.max_head as usize {
                for g in 1..=p.gaps {
                    let goff = g as usize * cluster as usize;
                    if goff + hl >= p.window as usize {
                        break;
                    }
                    let len = (p.span as usize).min(p.window as usize - goff);
                    if len <= hl {
                        break;
                    }
                    let mut b = Vec::with_capacity(len);
                    b.extend_from_slice(&data[h..h + hl]);
                    let resume = h + hl + goff;
                    b.extend_from_slice(&data[resume..resume + (len - hl)]);
                    expect.push(b);
                }
                hl += cluster as usize;
            }
            assert_eq!(seen.len(), expect.len(), "header_at={header_at}");
            for (i, (a, b)) in seen.iter().zip(expect.iter()).enumerate() {
                assert_eq!(a, b, "candidate {i} differs, header_at={header_at}");
            }
        }
    }

    /// An unaligned header still produces cluster-aligned split and resume
    /// points, because a real allocator aligns the *image*, not the file.
    #[test]
    fn unaligned_header_still_splits_on_image_cluster_boundaries() {
        let cluster = 64u64;
        let header_at = 1000u64; // 1000 = 15*64 + 40
        let p = plan_for(4096, header_at, 4 * cluster, cluster, 8 * cluster);
        assert_eq!(p.first_head, 24, "first split is the next boundary at 1024");
        assert_eq!((header_at + p.first_head) % cluster, 0);
        for k in 0..p.splits() {
            let hl = p.first_head + k * cluster;
            assert_eq!((header_at + hl) % cluster, 0, "split point off-grid");
            for g in 1..=p.gaps {
                assert_eq!((header_at + hl + g * cluster) % cluster, 0, "resume point off-grid");
            }
        }
    }

    // ------------------------------------------------------------------
    // 3 · the two planted failures — load-bearing for the demo's honesty
    // ------------------------------------------------------------------

    /// Three fragments cannot be solved by a two-fragment search. Geometry of
    /// `media_inventory.docx`: extents of 9, 13 and 17 clusters with gaps of 11
    /// and 29 clusters, both inside the gap bound. The search must terminate
    /// and report failure, not return a two-extent object.
    #[test]
    fn three_fragments_are_not_solved_by_a_two_fragment_search() {
        let cluster = 64usize;
        let obj = synth_object(9 * cluster + 13 * cluster + 400);
        let e1 = 9 * cluster;
        let e2 = 13 * cluster;
        let e3 = obj.len() - e1 - e2;
        let o1 = 0usize;
        let o2 = o1 + e1 + 11 * cluster;
        let o3 = o2 + e2 + 29 * cluster;
        let img = plant(o3 + e3 + 4096, &obj, &[(o1, e1), (o2, e2), (o3, e3)]);

        let p = plan_for(img.len(), 0, 128 * cluster as u64, cluster as u64, 256 * cluster as u64);
        let out = search(&img, &p, |b| synth_validate(b));
        assert!(out.found.is_none(), "a two-fragment search must not solve three fragments");
        assert_eq!(out.stop, Stop::Exhausted, "it must terminate cleanly, not run away");
        assert!(
            out.validations <= 1 + p.lattice(),
            "cost must stay inside the published bound: {} > {}",
            out.validations,
            1 + p.lattice()
        );
    }

    /// A physically reversed object is not solvable by a forward-only search.
    /// Geometry of `evidence_bag_seal.jpg`: the header's extent sits 77 clusters
    /// *after* the continuation. The search must not find it, and must not be
    /// taught to look backwards to win.
    #[test]
    fn reversed_object_is_not_solved_by_a_forward_search() {
        let cluster = 64usize;
        let obj = synth_object(18 * cluster + 600);
        let e1 = 18 * cluster;
        let e2 = obj.len() - e1;
        // continuation first, header 77 clusters later.
        let o2 = 1000 * cluster;
        let o1 = o2 + 77 * cluster;
        let img = plant(o1 + e1 + 4096, &obj, &[(o1, e1), (o2, e2)]);

        let p = plan_for(img.len(), o1 as u64, 128 * cluster as u64, cluster as u64, 256 * cluster as u64);
        let out = search(&img, &p, |b| synth_validate(b));
        assert!(out.found.is_none(), "a forward search must not solve a reversed object");
        assert_eq!(out.stop, Stop::Exhausted);

        // And the object IS there — a backward search would find it. Proving the
        // data is present is what makes the failure a decision rather than a bug.
        let mut whole = Vec::new();
        whole.extend_from_slice(&img[o1..o1 + e1]);
        whole.extend_from_slice(&img[o2..o2 + e2]);
        assert!(synth_validate(&whole).valid, "the reversed object is intact in the image");
    }

    // ------------------------------------------------------------------
    // 3b · determinacy
    // ------------------------------------------------------------------

    /// A validator blind to a stretch of the object accepts several splices.
    /// The determinacy probe must catch that and refuse, rather than returning
    /// whichever one the lattice reached first.
    #[test]
    fn a_validator_blind_to_part_of_the_object_yields_a_refusal() {
        let cluster = 64u64;
        let obj = synth_object(600);
        let f1 = 4 * cluster as usize;
        let gap = 3usize;
        let img = plant(4096, &obj, &[(0, f1), (f1 + gap * 64, obj.len() - f1)]);
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);

        // Exact validator: one accepting splice, determined, recovered.
        let out = search(&img, &p, |b| synth_validate(b));
        assert_eq!(out.stop, Stop::Solved);
        assert_eq!(
            out.found.unwrap().extents,
            vec![(0, f1 as u64), ((f1 + gap * 64) as u64, (obj.len() - f1) as u64)]
        );

        // Partial validator: it checks the object's two ends but never its
        // middle — the failure mode of any format that declares its own length
        // and carries no checksum over the body. It rejects the contiguous read
        // (the far end is wrong) yet accepts every splice whose tail lands
        // correctly, whatever the split point.
        let partial = |b: &[u8]| {
            if b.len() < 9 || &b[..5] != MAGIC {
                return bad("no magic");
            }
            let total = u32::from_be_bytes([b[5], b[6], b[7], b[8]]) as usize;
            if total < 9 + 128 || total > b.len() {
                return bad("truncated");
            }
            let body = total - 9;
            for i in (0..64).chain(body - 64..body) {
                if b[9 + i] != payload_byte(i) {
                    return bad("end mismatch");
                }
            }
            ok(total as u64, "ends only, body unchecked")
        };
        let out = search(&img, &p, partial);
        assert!(out.found.is_none(), "an undetermined splice must not be returned");
        assert_eq!(out.stop, Stop::Ambiguous, "and the refusal must say why");
    }

    /// The determinacy probe costs at most four validations per accepted
    /// candidate, and they are counted.
    #[test]
    fn determinacy_cost_is_counted() {
        let cluster = 64u64;
        let obj = synth_object(600);
        let f1 = 4 * cluster as usize;
        let img = plant(4096, &obj, &[(0, f1), (f1 + 3 * 64, obj.len() - f1)]);
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);
        let out = search(&img, &p, |b| synth_validate(b));
        let first_hit = 1 + (4 - 1) * p.gaps + 3;
        assert_eq!(out.validations, first_hit + 4, "probe + lattice walk + 4 neighbours");
    }

    // ------------------------------------------------------------------
    // 4 · refusals
    // ------------------------------------------------------------------

    /// A contiguous object is sequential carving's job. Cost: one validation.
    #[test]
    fn contiguous_object_is_refused_after_one_validation() {
        let cluster = 64u64;
        let obj = synth_object(300);
        let img = plant(2048, &obj, &[(0, obj.len())]);
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);
        let out = search(&img, &p, |b| synth_validate(b));
        assert_eq!(out.stop, Stop::Contiguous);
        assert!(out.found.is_none());
        assert_eq!(out.validations, 1);
    }

    /// A validator that says "valid" but cannot state an end yields no extents,
    /// so no recovery is reported. The search does not invent a length.
    #[test]
    fn valid_without_an_end_is_not_a_recovery() {
        let cluster = 64u64;
        let img = vec![7u8; 4096];
        let p = plan_for(img.len(), 0, 4 * cluster, cluster, 8 * cluster);
        let out = search(&img, &p, |_| Validation {
            valid: true,
            end: None,
            score: 1.0,
            detail: "no end".into(),
        });
        // the sequential probe returns valid -> Contiguous, which is also a refusal
        assert!(out.found.is_none());
    }

    /// Degenerate inputs terminate rather than panicking.
    #[test]
    fn degenerate_inputs_terminate() {
        let img = vec![0u8; 1024];
        assert!(Plan::new(1024, 1024, 0, 0, 64, 512).is_none(), "gap bound below one cluster");
        assert!(Plan::new(1024, 1024, 0, 256, 0, 512).is_none(), "zero cluster");
        assert!(Plan::new(1024, 1024, 2000, 256, 64, 512).is_none(), "header past the end");
        assert!(Plan::new(1024, 1, 0, 256, 64, 512).is_none(), "no room for two extents");
        let p = plan_for(img.len(), 0, 4 * 64, 64, 8 * 64);
        let out = search(&img, &p, |_| bad("x"));
        assert_eq!(out.stop, Stop::Exhausted);
    }

    // ------------------------------------------------------------------
    // 5 · cluster grid versus byte grid — measured, both run to completion
    // ------------------------------------------------------------------

    #[test]
    fn cluster_grid_versus_byte_grid_is_measured() {
        let cluster = 64u64;
        let max_head_bytes = 8 * cluster; // identical byte-space for both grids
        let max_gap_bytes = 8 * cluster;
        let obj = synth_object(400);
        let f1 = 3 * cluster as usize;
        let gap = 2 * cluster as usize;
        let img = plant(4096, &obj, &[(0, f1), (f1 + gap, obj.len() - f1)]);

        let pc = plan_for(img.len(), 0, max_gap_bytes, cluster, max_head_bytes);
        let t0 = Instant::now();
        let oc = search(&img, &pc, |b| synth_validate(b));
        let tc = t0.elapsed();

        let pb = plan_for(img.len(), 0, max_gap_bytes, 1, max_head_bytes);
        let t0 = Instant::now();
        let ob = search(&img, &pb, |b| synth_validate(b));
        let tb = t0.elapsed();

        assert_eq!(oc.stop, Stop::Solved);
        assert_eq!(ob.stop, Stop::Solved);
        assert_eq!(oc.found.as_ref().unwrap().extents, ob.found.as_ref().unwrap().extents);

        println!(
            "GRID  cluster={} lattice={} validations={} elapsed={:?}",
            cluster, pc.lattice(), oc.validations, tc
        );
        println!(
            "GRID  byte    lattice={} validations={} elapsed={:?}",
            pb.lattice(), ob.validations, tb
        );
        println!(
            "GRID  ratio   validations={:.1}x  lattice={:.1}x  (cluster^2 = {})",
            ob.validations as f64 / oc.validations as f64,
            pb.lattice() as f64 / pc.lattice() as f64,
            cluster * cluster
        );
        assert!(ob.validations > oc.validations * 100, "the byte grid must cost far more");
    }

    // ------------------------------------------------------------------
    // 6 · the real fixture
    // ------------------------------------------------------------------

    const FIXTURE_BYTES: u64 = 268_435_456;
    const CLUSTER: u64 = 2048;
    const MAX_GAP_CLUSTERS: u64 = 128;

    /// Ground truth for the seven fragmented plants, transcribed from
    /// `out/fixture.manifest.json` (image sha256
    /// d85612b255ff8e72e1ab8d7a34c227b67c3cb3acda75e2a92e5042758ac2df41).
    /// name, Kind::as_str, header offset, expected extents, expected outcome.
    struct Plant {
        name: &'static str,
        kind: &'static str,
        header_at: u64,
        extents: &'static [(u64, u64)],
        /// The fixture manifest's `expected_recoverable` is "bifragment".
        recoverable: bool,
        /// Whether `structure::validate` pins this object to exactly one splice
        /// in the lattice. MEASURED against `core/carve/src/structure/`, not
        /// assumed: see the determinacy table in the module header. `false`
        /// names a gap in the validator, and `finding` says which.
        determined: bool,
        /// Printed on every run when the plant is not recovered. This is the
        /// "name the two we cannot do" discipline applied to everything we
        /// cannot do, not only to the two the fixture planted.
        finding: &'static str,
    }

    const PLANTS: &[Plant] = &[
        Plant {
            name: "imaging_transcript.txt.gz",
            kind: "gzip",
            header_at: 143_464_448,
            extents: &[(143_464_448, 69_632), (143_566_848, 57_670)],
            recoverable: true,
            determined: true,
            finding: "",
        },
        Plant {
            name: "entropy_heatmap.png",
            kind: "png",
            header_at: 51_361_792,
            extents: &[(51_361_792, 73_728), (51_437_568, 109_622)],
            recoverable: true,
            determined: true,
            finding: "",
        },
        Plant {
            name: "disposal_certificate.pdf",
            kind: "pdf",
            header_at: 170_430_464,
            extents: &[(170_430_464, 12_288), (170_704_896, 33_768)],
            recoverable: true,
            // MEASURED by full-lattice enumeration: 10 splices validate, all
            // at gap = 128 clusters (the true gap) and differing only in the
            // split point, hl = 1..10 clusters. That interval is object 2's
            // ~21 kB FlateDecode body, which structure::pdf never decodes.
            // Exactly 1 of the 10 carries the planted bytes; none is
            // determined; the search refuses.
            determined: false,
            finding: "structure::pdf verifies 34/34 xref offsets but decodes no \
                      stream body, so 10 splices validate and 9 are the wrong \
                      bytes; a per-stream inflate + Adler-32 leaves exactly 1",
        },
        Plant {
            name: "sealing_procedure.mov",
            kind: "mp4",
            header_at: 65_796_096,
            extents: &[(65_796_096, 90_112), (65_988_608, 130_929)],
            recoverable: true,
            determined: false,
            finding: "MP4 declares mdat's length in fragment 1 and carries no \
                      checksum over it, so 6660 splices validate and exactly 1 \
                      is the planted bytes; not repairable by any structure \
                      validator, the container has no field to check",
        },
        Plant {
            name: "handover_briefing.mov",
            kind: "mp4",
            header_at: 65_943_552,
            extents: &[(65_943_552, 32_768), (66_119_680, 33_921)],
            recoverable: true,
            determined: false,
            finding: "same MP4 limit as its twin (4096 splices validate, 1 is \
                      the planted bytes); worse, structure::mp4 accepts the \
                      CONTIGUOUS read at this header, so sequential carving \
                      emits 66 689 bytes with the wrong SHA-256 before \
                      bifragment is ever consulted",
        },
        Plant {
            name: "media_inventory.docx",
            kind: "zip",
            header_at: 1_069_056,
            extents: &[],
            recoverable: false, // three fragments
            determined: false,
            finding: "planted: three fragments, unsolvable by a two-fragment search",
        },
        Plant {
            name: "evidence_bag_seal.jpg",
            kind: "jpeg",
            header_at: 214_231_040,
            extents: &[],
            recoverable: false, // physically reversed, gap -77 clusters
            determined: false,
            finding: "planted: physically reversed, unsolvable by a forward search",
        },
    ];

    fn kind_by_str(s: &str) -> Option<Kind> {
        for sig in crate::signature::SIGNATURES {
            if sig.kind.as_str().eq_ignore_ascii_case(s) {
                return Some(sig.kind);
            }
        }
        None
    }

    fn load_fixture() -> Option<Vec<u8>> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../out/fixture.img");
        let data = std::fs::read(p).ok()?;
        if data.len() as u64 != FIXTURE_BYTES {
            eprintln!("FIXTURE  wrong length {} — skipping", data.len());
            return None;
        }
        Some(data)
    }

    /// The measurement the pitch rests on. Two claims, and they are different
    /// sizes:
    ///
    /// 1. **Never wrong.** For every fragmented plant, the answer is either the
    ///    manifest's extents or nothing. A structurally valid but content-wrong
    ///    reassembly is the failure this module exists to avoid, and it is
    ///    asserted for all five, unconditionally.
    /// 2. **Recovered.** The three plants whose formats carry integrity fields
    ///    over the whole object are recovered exactly. The two MP4s are not: see
    ///    the determinacy table in the module header. They are refused, and the
    ///    refusal is the honest answer, not a hidden one.
    #[test]
    fn fixture_solvable_fragments_are_recovered_or_refused_never_wrong() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let max_gap_bytes = MAX_GAP_CLUSTERS * CLUSTER;
        let mut recovered = 0;
        let mut refused = 0;
        let mut wrong: Vec<String> = Vec::new();
        let mut missing: Vec<String> = Vec::new();

        for p in PLANTS.iter().filter(|p| p.recoverable) {
            let Some(kind) = kind_by_str(p.kind) else {
                missing.push(format!("{}: no signature for kind {}", p.name, p.kind));
                continue;
            };
            let span = span_ceiling(kind, data.len() as u64 - p.header_at);
            let plan = Plan::new(
                data.len() as u64,
                span,
                p.header_at,
                max_gap_bytes,
                CLUSTER,
                MAX_FIRST_FRAGMENT_CLUSTERS * CLUSTER,
            )
            .expect("plan");
            let t0 = Instant::now();
            let out = search(&data, &plan, |b| validate(kind, b));
            let el = t0.elapsed();
            match out.found {
                Some(r) => {
                    let ok = r.extents == p.extents;
                    let gap = (r.extents[1].0 - (r.extents[0].0 + r.extents[0].1)) / CLUSTER;
                    // Extents equal to the manifest's imply the bytes are the
                    // planted file's, but the bytes are what the certificate
                    // hashes, so they are compared directly rather than inferred.
                    let mut got = Vec::new();
                    for &(off, len) in &r.extents {
                        got.extend_from_slice(&data[off as usize..(off + len) as usize]);
                    }
                    let bytes_ok = Some(&got) == true_bytes(&data, p).as_ref();
                    println!(
                        "CARVE  {:<26} RECOVERED extents={:?} gap={}cl size={} validations={} accepted={} elapsed={:?} manifest_match={} bytes_match={}",
                        p.name, r.extents, gap, got.len(), r.validations, out.accepted, el, ok, bytes_ok
                    );
                    assert!(bytes_ok, "{}: recovered bytes are not the planted file", p.name);
                    // The published cost formula, checked against the image
                    // rather than only against a synthetic. Both plants sit on
                    // cluster-aligned headers, so the walk is
                    // (hl/cluster - 1) * gaps + g, plus the sequential probe,
                    // plus at most four determinacy neighbours.
                    assert_eq!(p.header_at % CLUSTER, 0, "{}: header off-grid", p.name);
                    let walk = (r.extents[0].1 / CLUSTER - 1) * plan.gaps + gap;
                    assert!(
                        r.validations >= 1 + walk && r.validations <= 1 + walk + 4,
                        "{}: {} validations outside the published [{}, {}]",
                        p.name,
                        r.validations,
                        1 + walk,
                        1 + walk + 4
                    );
                    if ok {
                        recovered += 1;
                    } else {
                        wrong.push(format!(
                            "{}: {:?} != manifest {:?}",
                            p.name, r.extents, p.extents
                        ));
                    }
                }
                None => {
                    refused += 1;
                    println!(
                        "CARVE  {:<26} REFUSED   stop={:?} accepted={} validations={} lattice={} elapsed={:?}",
                        p.name, out.stop, out.accepted, out.validations, plan.lattice(), el
                    );
                    println!("       FINDING  {}: {}", p.name, p.finding);
                    if p.determined {
                        missing.push(format!("{}: refused but expected exact", p.name));
                    }
                }
            }
        }
        println!("CARVE  fragmented: {recovered} recovered exactly, {refused} refused, {} wrong", wrong.len());

        // Claim 1 — unconditional.
        assert!(wrong.is_empty(), "wrong-but-validating reassembly: {}", wrong.join("; "));
        assert!(missing.is_empty(), "{}", missing.join("; "));
        // Claim 2 — the plants whose formats determine the answer.
        let want = PLANTS.iter().filter(|p| p.recoverable && p.determined).count();
        if recovered > want {
            println!(
                "CARVE  {recovered} recovered, {want} expected: structure::validate now \
                 pins more plants than when this table was measured. Promote them to \
                 `determined: true` so the floor rises with it."
            );
        }
        assert!(
            recovered >= want,
            "expected at least {want} exact recoveries, got {recovered}. A shortfall \
             is a regression in structure::validate's coverage of the object body, \
             not in the search: this module recovers exactly those plants the \
             validator pins to one splice, and refuses the rest by name."
        );
    }

    /// The two the fixture plants to defeat us. These assertions are the demo's
    /// honesty: if either ever passes, the carver has been taught the answer.
    #[test]
    fn fixture_two_planted_failures_fail_and_say_so() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let max_gap_bytes = MAX_GAP_CLUSTERS * CLUSTER;
        for p in PLANTS.iter().filter(|p| !p.recoverable) {
            let Some(kind) = kind_by_str(p.kind) else {
                panic!("no signature for kind {}", p.kind);
            };
            let span = span_ceiling(kind, data.len() as u64 - p.header_at);
            let plan = Plan::new(
                data.len() as u64,
                span,
                p.header_at,
                max_gap_bytes,
                CLUSTER,
                MAX_FIRST_FRAGMENT_CLUSTERS * CLUSTER,
            )
            .expect("plan");
            let t0 = Instant::now();
            let out = search(&data, &plan, |b| validate(kind, b));
            let el = t0.elapsed();
            println!(
                "CARVE  {:<26} stop={:?} accepted={} validations={} lattice={} elapsed={:?}",
                p.name, out.stop, out.accepted, out.validations, plan.lattice(), el
            );
            assert_eq!(
                out.accepted, 0,
                "{} must not produce even a candidate: a two-fragment forward search \
                 cannot assemble it, and any acceptance would be residue passing \
                 structure validation",
                p.name
            );
            assert!(
                out.found.is_none(),
                "{} must not be recovered by a two-fragment forward search",
                p.name
            );
            assert!(
                matches!(out.stop, Stop::Exhausted | Stop::Ambiguous),
                "{} must terminate cleanly, got {:?}",
                p.name,
                out.stop
            );
        }
    }

    /// The byte grid, on the real image, under a budget. It does not reach the
    /// solution; the cluster grid does. Both numbers are measured here.
    #[test]
    fn fixture_byte_grid_control_does_not_finish() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        // disposal_certificate.pdf: the cheapest of the five on the cluster grid.
        let p = &PLANTS[2];
        let kind = kind_by_str(p.kind).expect("pdf signature");
        let max_gap_bytes = MAX_GAP_CLUSTERS * CLUSTER;
        // Both grids get the SAME span and the SAME head ceiling, so the only
        // variable between them is the lattice. 64 KiB comfortably contains the
        // 46 056-byte object and keeps the control affordable in a debug build;
        // the head ceiling is a whole number of clusters below it so the two
        // lattice cardinalities are exactly comparable.
        let span = 65_536u64;
        let max_head_bytes = 31 * CLUSTER;

        let pc = Plan::new(
            data.len() as u64, span, p.header_at, max_gap_bytes, CLUSTER, max_head_bytes,
        )
        .expect("cluster plan");
        let t0 = Instant::now();
        let oc = search(&data, &pc, |b| validate(kind, b));
        let tc = t0.elapsed();

        let mut pb = Plan::new(
            data.len() as u64, span, p.header_at, max_gap_bytes, 1, max_head_bytes,
        )
        .expect("byte plan");
        pb.budget = 250_000;
        let t0 = Instant::now();
        let ob = search(&data, &pb, |b| validate(kind, b));
        let tb = t0.elapsed();

        println!(
            "GRID  fixture cluster lattice={} validations={} stop={:?} elapsed={:?}",
            pc.lattice(), oc.validations, oc.stop, tc
        );
        println!(
            "GRID  fixture byte    lattice={} validations={} stop={:?} elapsed={:?}",
            pb.lattice(), ob.validations, ob.stop, tb
        );
        println!(
            "GRID  fixture lattice ratio = {} (cluster^2 = {})",
            pb.lattice() / pc.lattice().max(1),
            CLUSTER * CLUSTER
        );
        assert_eq!(ob.stop, Stop::Budget, "the byte grid must not finish inside the budget");
        assert!(ob.found.is_none());
    }

    // ------------------------------------------------------------------
    // 7 · the whole lattice, enumerated — where the ambiguity actually is
    // ------------------------------------------------------------------

    /// One accepting splice, in lattice coordinates.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Hit {
        /// First-fragment length in bytes.
        hl: u64,
        /// Gap in clusters.
        g: u64,
        /// Object length the validator reported.
        end: u64,
        /// Did all four one-cluster neighbours fail?
        determined: bool,
        /// Are the assembled bytes the planted file, byte for byte? Ground
        /// truth from the manifest's extents, not from the validator. This is
        /// the column that turns "structurally perfect" into "the right file",
        /// and the gap between the two columns is the whole argument for the
        /// determinacy rule.
        content_ok: bool,
    }

    /// Walk the ENTIRE lattice — no early exit — and return every splice the
    /// validator accepts, each tagged with whether it is determined.
    ///
    /// This is the instrument the early-exit search is judged against. `search`
    /// stops at the first determined hit; enumeration answers the question that
    /// stopping early cannot: is that hit the ONLY determined one? On this
    /// fixture the answer is measured, not assumed.
    ///
    /// Deliberately naive: it splices into a fresh buffer per candidate rather
    /// than using the sliding-head buffer, so it is an independent check of the
    /// buffer as well as of the search.
    fn enumerate_lattice<F>(
        data: &[u8],
        plan: &Plan,
        truth: Option<&[u8]>,
        mut check: F,
    ) -> (Vec<Hit>, u64)
    where
        F: FnMut(&[u8]) -> Validation,
    {
        let mut hits = Vec::new();
        let mut validations = 0u64;
        let mut scratch = Vec::new();
        let mut hl = plan.first_head;
        while hl <= plan.max_head {
            for g in 1..=plan.gaps {
                if !splice(data, plan, hl as usize, g, &mut scratch) {
                    continue;
                }
                let v = check(&scratch);
                validations += 1;
                if !v.valid {
                    continue;
                }
                let Some(end) = v.end else { continue };
                if end <= hl || end > scratch.len() as u64 {
                    continue;
                }
                let content_ok = match truth {
                    Some(t) => t.len() as u64 == end && t == &scratch[..end as usize],
                    None => false,
                };
                let mut probe = Vec::new();
                let (determined, spent) =
                    is_determined(data, plan, hl as usize, g, &mut probe, &mut check);
                validations += spent;
                hits.push(Hit { hl, g, end, determined, content_ok });
            }
            hl += plan.grid;
        }
        (hits, validations)
    }

    fn fixture_plan(data_len: u64, kind: Kind, header_at: u64) -> Plan {
        let span = span_ceiling(kind, data_len - header_at);
        Plan::new(
            data_len,
            span,
            header_at,
            MAX_GAP_CLUSTERS * CLUSTER,
            CLUSTER,
            MAX_FIRST_FRAGMENT_CLUSTERS * CLUSTER,
        )
        .expect("plan")
    }

    /// The planted file's actual bytes, read out of the image at the manifest's
    /// extents. Ground truth for the content column.
    fn true_bytes(data: &[u8], p: &Plant) -> Option<Vec<u8>> {
        if p.extents.is_empty() {
            return None;
        }
        let mut v = Vec::new();
        for &(off, len) in p.extents {
            v.extend_from_slice(&data[off as usize..(off + len) as usize]);
        }
        Some(v)
    }

    /// The true splice of a plant, in lattice coordinates.
    fn true_splice(p: &Plant) -> Option<(u64, u64)> {
        if p.extents.len() != 2 {
            return None;
        }
        let hl = p.extents[0].1;
        let gap = p.extents[1].0 - (p.extents[0].0 + p.extents[0].1);
        Some((hl, gap / CLUSTER))
    }

    /// The measurement behind every "Ambiguous" on the fixture, and the one that
    /// licenses the early exit.
    ///
    /// Expensive by construction — it refuses to stop early — so it is
    /// `#[ignore]`d. Run it with:
    ///
    /// ```text
    /// cargo test --release -p sentinelwipe-carve --lib \
    ///     bifragment::tests::fixture_lattice_enumeration -- --ignored --nocapture
    /// ```
    ///
    /// Three things are asserted rather than printed, because each one is a
    /// claim the demo makes out loud:
    ///
    /// 1. **The inclusive gap bound reaches the boundary plant.** The true
    ///    splice of `disposal_certificate.pdf` sits at gap = 128 clusters =
    ///    `max_gap_bytes` exactly. It must appear in the enumeration. If the
    ///    bound were exclusive it could not, and the PDF's refusal would be a
    ///    bound defect masquerading as ambiguity.
    /// 2. **Every determined hit is the true splice.** A determined hit that is
    ///    not the manifest's answer is the silent wrong-but-validating recovery
    ///    this module exists to prevent, and it would be returned by the early
    ///    exit.
    /// 3. **The two planted failures accept nothing at all.**
    #[test]
    #[ignore = "walks the full 32768-cell lattice for seven plants; run with --release"]
    fn fixture_lattice_enumeration_measures_ambiguity() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let mut wrong: Vec<String> = Vec::new();
        for p in PLANTS {
            let kind = kind_by_str(p.kind).expect("kind");
            let plan = fixture_plan(data.len() as u64, kind, p.header_at);
            let truth_bytes = true_bytes(&data, p);
            let t0 = Instant::now();
            let (hits, validations) =
                enumerate_lattice(&data, &plan, truth_bytes.as_deref(), |b| validate(kind, b));
            let el = t0.elapsed();
            let det: Vec<&Hit> = hits.iter().filter(|h| h.determined).collect();
            let right = hits.iter().filter(|h| h.content_ok).count();
            let truth = true_splice(p);
            let true_accepts = truth
                .map(|(hl, g)| hits.iter().any(|h| h.hl == hl && h.g == g))
                .unwrap_or(false);
            println!(
                "LATTICE {:<26} cells={} accepting={} content_correct={} determined={} true_splice={:?} true_accepted={} validations={} elapsed={:?}",
                p.name,
                plan.lattice(),
                hits.len(),
                right,
                det.len(),
                truth,
                true_accepts,
                validations,
                el
            );
            for h in hits.iter().take(12) {
                println!(
                    "        hit hl={} ({} cl) gap={} cl end={} determined={} content_ok={}",
                    h.hl,
                    h.hl / CLUSTER,
                    h.g,
                    h.end,
                    h.determined,
                    h.content_ok
                );
            }
            if hits.len() > 12 {
                println!("        ... {} more accepting splices", hits.len() - 12);
            }
            // The planted file is IN the accepting set for every solvable plant,
            // exactly once. Everything else the validator accepted is a
            // different file with the same structure -- which is precisely the
            // answer this module must never return.
            if !p.extents.is_empty() {
                assert_eq!(
                    right, 1,
                    "{}: exactly one accepting splice must be the planted bytes",
                    p.name
                );
                assert!(true_accepts, "{}: the manifest's own splice must be accepted", p.name);
            }
            for h in hits.iter().filter(|h| h.determined) {
                assert!(
                    h.content_ok,
                    "{}: determined splice hl={} gap={} is content-WRONG",
                    p.name, h.hl, h.g
                );
            }

            // Claim 2 — every determined hit must be the manifest's answer.
            for h in det {
                if truth != Some((h.hl, h.g)) {
                    wrong.push(format!(
                        "{}: determined splice hl={} gap={} is not the manifest's {:?}",
                        p.name, h.hl, h.g, truth
                    ));
                }
            }
            // Claim 3 — the planted failures accept nothing.
            if !p.recoverable {
                assert!(
                    hits.is_empty(),
                    "{} is planted unsolvable: the lattice must accept nothing, got {:?}",
                    p.name,
                    hits
                );
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("; "));

        // Claim 1 — the boundary plant's true splice is inside the search.
        let pdf = PLANTS.iter().find(|p| p.name == "disposal_certificate.pdf").unwrap();
        let (hl, g) = true_splice(pdf).unwrap();
        assert_eq!(g, MAX_GAP_CLUSTERS, "the boundary plant must sit on the bound");
        let kind = kind_by_str(pdf.kind).unwrap();
        let plan = fixture_plan(data.len() as u64, kind, pdf.header_at);
        assert_eq!(plan.gaps, MAX_GAP_CLUSTERS, "gap {g} must be inside an inclusive bound");
        let mut scratch = Vec::new();
        assert!(splice(&data, &plan, hl as usize, g, &mut scratch));
        let v = validate(kind, &scratch);
        println!(
            "LATTICE boundary  disposal_certificate.pdf hl={hl} gap={g} valid={} end={:?} score={:.2} detail={}",
            v.valid, v.end, v.score, v.detail
        );
        assert!(
            v.valid && v.end == Some(46_056),
            "the manifest's own splice must validate at the inclusive bound: {v:?}"
        );
    }

    // ------------------------------------------------------------------
    // 8 · the public entry point, on the real image
    // ------------------------------------------------------------------

    /// `bifragment()` is the signature the interface contract fixes, and it is
    /// what `carve.rs` calls. Everything above drives `search` so it can read a
    /// failure's cost; this drives the contract itself, on the shipped image,
    /// and checks that `max_gap_bytes` is the caller's number end to end.
    ///
    /// `entropy_heatmap.png` is the subject because its gap is one cluster: the
    /// smallest possible bound that can contain it is 2048 bytes, so the
    /// inclusive/exclusive difference is one byte wide and observable.
    #[test]
    fn fixture_public_entry_point_recovers_png_and_honours_the_gap_bound() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let p = PLANTS.iter().find(|p| p.name == "entropy_heatmap.png").unwrap();
        let kind = kind_by_str(p.kind).unwrap();

        let t0 = Instant::now();
        let got = bifragment(&data, kind, p.header_at, MAX_GAP_CLUSTERS * CLUSTER, CLUSTER);
        let el = t0.elapsed();
        let r = got.expect("entropy_heatmap.png must be recovered through the public entry point");
        println!(
            "PUBLIC entropy_heatmap.png extents={:?} validations={} elapsed={:?}",
            r.extents, r.validations, el
        );
        assert_eq!(r.extents, p.extents, "extents must be the manifest's, byte for byte");
        assert_eq!(
            r.extents.iter().map(|e| e.1).sum::<u64>(),
            183_350,
            "reassembled length must be the manifest's size"
        );

        // The gap is exactly one cluster. An inclusive bound of one cluster
        // finds it; anything below one cluster cannot describe a lattice at all.
        let tight = bifragment(&data, kind, p.header_at, CLUSTER, CLUSTER)
            .expect("a one-cluster inclusive bound must contain a one-cluster gap");
        assert_eq!(tight.extents, p.extents);
        assert!(
            tight.validations < r.validations,
            "a tighter bound must cost less: {} vs {}",
            tight.validations,
            r.validations
        );
        println!(
            "PUBLIC entropy_heatmap.png gap_bound=1cl validations={} (128cl cost {})",
            tight.validations, r.validations
        );
        assert!(
            bifragment(&data, kind, p.header_at, CLUSTER - 1, CLUSTER).is_none(),
            "a bound below one cluster describes no lattice and must recover nothing"
        );

        // And the contract's own refusals, through the contract's own function.
        let jpg = PLANTS.iter().find(|p| p.name == "evidence_bag_seal.jpg").unwrap();
        let jk = kind_by_str(jpg.kind).unwrap();
        assert!(
            bifragment(&data, jk, jpg.header_at, MAX_GAP_CLUSTERS * CLUSTER, CLUSTER).is_none(),
            "the reversed plant must not be recovered through the public entry point"
        );
        assert!(
            bifragment(&data, kind, data.len() as u64, MAX_GAP_CLUSTERS * CLUSTER, CLUSTER)
                .is_none(),
            "a header at the end of the image must not panic"
        );
        assert!(
            bifragment(&data, kind, p.header_at, MAX_GAP_CLUSTERS * CLUSTER, 0).is_none(),
            "a zero cluster size must not panic"
        );
    }

    // ------------------------------------------------------------------
    // 9 · what MAX_OBJECT_BYTES costs — the span/time trade, measured
    // ------------------------------------------------------------------

    /// The number behind [`MAX_OBJECT_BYTES`]. One exhausted PDF search at three
    /// span ceilings: identical lattice, identical validator, only the slice
    /// handed to `validate` changes.
    ///
    /// ```text
    /// cargo test --release -p sentinelwipe-carve --lib \
    ///     bifragment::tests::span_ceiling_cost -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "three full-lattice PDF searches, the widest at a 64 MiB span"]
    fn span_ceiling_cost_is_measured() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let p = PLANTS.iter().find(|p| p.name == "disposal_certificate.pdf").unwrap();
        let kind = kind_by_str(p.kind).unwrap();
        for span in [64 * 1024 * 1024u64, 4 * 1024 * 1024, MAX_OBJECT_BYTES] {
            let plan = Plan::new(
                data.len() as u64,
                span,
                p.header_at,
                MAX_GAP_CLUSTERS * CLUSTER,
                CLUSTER,
                MAX_FIRST_FRAGMENT_CLUSTERS * CLUSTER,
            )
            .expect("plan");
            let t0 = Instant::now();
            let out = search(&data, &plan, |b| validate(kind, b));
            println!(
                "SPAN  ceiling={:>9} validations={} stop={:?} elapsed={:?}",
                span,
                out.validations,
                out.stop,
                t0.elapsed()
            );
        }
    }

}
