//! The carve report emitter — every byte of `sentinelwipe.carve.report/1`.
//!
//! Moved verbatim out of main.rs so `core/verify` can embed the SAME report
//! the binary emits, produced by the same code, in its evidence bundle.
//! Phase 4 step 5 requires the post-wipe carve to run with byte-identical
//! parameters; a bundle whose reports came from a different emitter than the
//! demo's would reintroduce exactly the drift the one-binding design removes.
//! Nothing was rewritten in the move except visibility, and one seam: `emit`
//! now takes `EmitMeta` — the narrow view of the invocation it always read —
//! with the reproducing command as a plain string from whichever caller
//! knows it.

use crate::carve::{sha256_hex, CarveOpts, CarveReport, Recovered};
use crate::confidence::{
    entropy_band, kind_defines_footer, size_bounds, ENTROPY_UNKNOWN, MIN_ENTROPY_SAMPLE,
    NON_STRUCTURE_CEILING, SIG_HEADER_AND_FOOTER, SIG_HEADER_MISMATCH, SIG_HEADER_ONLY,
    SIG_NO_FOOTER_DEFINED, STRUCTURAL_BREACH_POINT, W_ENTROPY, W_SIGNATURE, W_SIZE,
    W_STRUCTURE,
};
use crate::Kind;
use std::path::Path;

pub const SCHEMA: &str = "sentinelwipe.carve.report/1";

pub const KINDS: [Kind; 7] = [
    Kind::Jpeg,
    Kind::Png,
    Kind::Pdf,
    Kind::Zip,
    Kind::Sqlite,
    Kind::Mp4,
    Kind::Gzip,
];

pub const ASSEMBLIES: [&str; 3] = ["contiguous", "reassembled", "signature-span"];

fn is_rooted(p: &Path) -> bool {
    p.has_root()
        || matches!(
            p.components().next(),
            Some(std::path::Component::Prefix(_))
        )
}

pub fn relative_label(image: &Path, explicit: Option<&str>) -> String {
    if let Some(s) = explicit {
        return s.to_string();
    }
    if !is_rooted(image) {
        return image.to_string_lossy().replace('\\', "/");
    }
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = image.strip_prefix(&cwd) {
            return rel.to_string_lossy().replace('\\', "/");
        }
    }
    let base = image
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "image".to_string());
    eprintln!(
        "carve: NOTE {} is outside the working directory; run.image_path is reduced to {:?} \
         so the report carries no absolute path. Pass --image-path to set it exactly.",
        image.display(),
        base
    );
    base
}

// ===========================================================================
// main
// ===========================================================================


pub fn kind_of(s: &str) -> Option<Kind> {
    match s {
        "JPEG" => Some(Kind::Jpeg),
        "PNG" => Some(Kind::Png),
        "PDF" => Some(Kind::Pdf),
        "ZIP" | "DOCX" => Some(Kind::Zip),
        "SQLITE" => Some(Kind::Sqlite),
        "MP4" => Some(Kind::Mp4),
        "GZIP" => Some(Kind::Gzip),
        _ => None,
    }
}

pub struct PlantedFile {
    path: String,
    manifest_kind: String,
    expected_recoverable: String,
    sha256: String,
    first_offset: u64,
}

/// One record's tie to ground truth: (path, manifest kind, expected_recoverable,
/// sha256_matches).
type Match = (String, String, String, bool);

pub struct GroundTruth {
    pub manifest_label: String,
    manifest_sha256: String,
    pub planted_total: u64,
    pub contiguous: u64,
    pub bifragment: u64,
    pub unreachable: Vec<(String, String, String)>,
    /// Per record index into `report.records`, the manifest entry it matched.
    pub matches: Vec<Option<Match>>,
    /// Planted files an ADMITTED record reproduced byte for byte.
    pub recovered_exact: u64,
    /// Records matched to a planted file by offset whose bytes are NOT that
    /// file's. A recovery wearing a success label; counted so it cannot hide
    /// behind a row count.
    pub false_positives: u64,
    sha256_matches_planted: u64,
}

impl GroundTruth {
    pub fn load(path: &Path, bytes: &[u8], report: &CarveReport) -> GroundTruth {
        let man = Json::parse(bytes);
        let files = man.get("files").map(|f| f.arr()).unwrap_or(&[]);

        let planted: Vec<PlantedFile> = files
            .iter()
            .map(|f| PlantedFile {
                path: f.get("path").map(|v| v.s().to_string()).unwrap_or_default(),
                manifest_kind: f.get("kind").map(|v| v.s().to_string()).unwrap_or_default(),
                expected_recoverable: f
                    .get("expected_recoverable")
                    .map(|v| v.s().to_string())
                    .unwrap_or_default(),
                sha256: f.get("sha256").map(|v| v.s().to_string()).unwrap_or_default(),
                first_offset: f
                    .get("extents")
                    .and_then(|e| e.arr().first().and_then(|x| x.get("byte_offset")))
                    .map(|v| v.u())
                    .unwrap_or(u64::MAX),
            })
            .collect();

        // Match by DIGEST first: that is the only join that proves the recovered
        // bytes ARE the planted file. Only when no digest matches does the
        // record fall back to a kind-and-offset join, and that join exists
        // precisely so a wrong-bytes recovery at a right offset is visible as
        // `sha256_matches: false` rather than as a missing row.
        let mut matches: Vec<Option<Match>> = Vec::with_capacity(report.records.len());
        let mut exact_recovered: Vec<bool> = vec![false; planted.len()];
        let mut false_positives = 0u64;
        let mut sha_matches = 0u64;

        for rec in &report.records {
            let by_digest = planted.iter().position(|p| p.sha256 == rec.sha256);
            let m = match by_digest {
                Some(i) => {
                    sha_matches += 1;
                    if rec.admitted {
                        exact_recovered[i] = true;
                    }
                    Some(i)
                }
                None => planted.iter().position(|p| {
                    p.first_offset == rec.offset && kind_of(&p.manifest_kind) == Some(rec.kind)
                }),
            };
            matches.push(m.map(|i| {
                let p = &planted[i];
                let ok = p.sha256 == rec.sha256;
                if !ok && rec.admitted {
                    false_positives += 1;
                }
                (
                    p.path.clone(),
                    p.manifest_kind.clone(),
                    p.expected_recoverable.clone(),
                    ok,
                )
            }));
        }

        let count = |tag: &str| {
            planted
                .iter()
                .filter(|p| p.expected_recoverable == tag)
                .count() as u64
        };

        // Why each unreachable file is unreachable, DERIVED from its manifest
        // row rather than asserted by name. A carver that names its own failures
        // from a list would be reciting, not reporting.
        let mut unreachable = Vec::new();
        for f in files {
            if f.get("expected_recoverable").map(|v| v.s()) != Some("unrecoverable-by-design") {
                continue;
            }
            let p = f.get("path").map(|v| v.s().to_string()).unwrap_or_default();
            let k = f.get("kind").map(|v| v.s().to_string()).unwrap_or_default();
            let ex: Vec<u64> = f
                .get("extents")
                .map(|e| {
                    e.arr()
                        .iter()
                        .map(|x| x.get("byte_offset").map(|v| v.u()).unwrap_or(0))
                        .collect()
                })
                .unwrap_or_default();
            let reason = if kind_of(&k).is_none() {
                format!("kind {k} has no row in signature::SIGNATURES: no header to scan for")
            } else if ex.len() > 2 {
                format!(
                    "{} extents; bifragment gap carving reassembles at most 2",
                    ex.len()
                )
            } else if ex.windows(2).any(|w| w[1] < w[0]) {
                format!(
                    "{} extents stored out of physical order (extent[1] at {} precedes \
                     extent[0] at {}); a forward gap search cannot reach them",
                    ex.len(),
                    ex[1],
                    ex[0]
                )
            } else {
                format!(
                    "the manifest marks this file unrecoverable-by-design; its row shows \
                     {} extent(s) in physical order and a kind the table knows, so the \
                     reason is not derivable here",
                    ex.len()
                )
            };
            unreachable.push((p, k, reason));
        }

        GroundTruth {
            manifest_label: relative_label(path, None),
            manifest_sha256: sha256_hex(bytes),
            planted_total: planted.len() as u64,
            contiguous: count("signature-only"),
            bifragment: count("bifragment"),
            unreachable,
            matches,
            recovered_exact: exact_recovered.iter().filter(|x| **x).count() as u64,
            false_positives,
            sha256_matches_planted: sha_matches,
        }
    }
}

// ===========================================================================
// The report writer. Hand-rolled: CLAUDE.md forbids serde.
// ===========================================================================

/// EVERY float goes through here: exactly six decimal places, per schema §2, so
/// no field is silently more precise than another and the file is byte-stable.
pub fn f(x: f64) -> String {
    let s = format!("{x:.6}");
    if s == "-0.000000" {
        "0.000000".to_string()
    } else {
        s
    }
}

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

pub struct W {
    b: String,
}

impl W {
    pub fn new() -> W {
        W {
            b: String::with_capacity(1 << 16),
        }
    }
    pub fn raw(&mut self, s: &str) -> &mut W {
        self.b.push_str(s);
        self
    }
    pub fn ind(&mut self, n: usize) -> &mut W {
        for _ in 0..n {
            self.b.push(' ');
        }
        self
    }
    pub fn line(&mut self, n: usize, s: &str) -> &mut W {
        self.ind(n).raw(s).raw("\n")
    }
    pub fn tail(comma: bool) -> &'static str {
        if comma {
            ","
        } else {
            ""
        }
    }
    pub fn kv_s(&mut self, n: usize, k: &str, v: &str, comma: bool) -> &mut W {
        self.ind(n);
        let t = W::tail(comma);
        self.b.push_str(&format!("\"{k}\": \"{}\"{t}\n", esc(v)));
        self
    }
    pub fn kv_os(&mut self, n: usize, k: &str, v: Option<&str>, comma: bool) -> &mut W {
        match v {
            Some(v) => self.kv_s(n, k, v, comma),
            None => {
                self.ind(n);
                let t = W::tail(comma);
                self.b.push_str(&format!("\"{k}\": null{t}\n"));
                self
            }
        }
    }
    pub fn kv_u(&mut self, n: usize, k: &str, v: u64, comma: bool) -> &mut W {
        self.ind(n);
        let t = W::tail(comma);
        self.b.push_str(&format!("\"{k}\": {v}{t}\n"));
        self
    }
    pub fn kv_f(&mut self, n: usize, k: &str, v: f64, comma: bool) -> &mut W {
        self.ind(n);
        let t = W::tail(comma);
        self.b.push_str(&format!("\"{k}\": {}{t}\n", f(v)));
        self
    }
    /// A float that may have no measurement behind it.
    ///
    /// The post-wipe carve is the demo's proof frame and it is EXPECTED to find
    /// nothing, so every margin field derived from the admitted or rejected
    /// population has an empty case.  Emitting 0.0 there would put a number on
    /// screen that no measurement produced, which CLAUDE.md rule 2 forbids, and
    /// it is worse than absent: a renderer cannot tell 0.0 "measured" from 0.0
    /// "there was nothing to measure".  `null` cannot be misread.
    pub fn kv_of(&mut self, n: usize, k: &str, v: Option<f64>, comma: bool) -> &mut W {
        match v {
            Some(x) => self.kv_f(n, k, x, comma),
            None => {
                self.ind(n);
                self.raw(&format!("\"{k}\": null{}\n", W::tail(comma)));
                self
            }
        }
    }

    pub fn kv_b(&mut self, n: usize, k: &str, v: bool, comma: bool) -> &mut W {
        self.ind(n);
        let t = W::tail(comma);
        self.b.push_str(&format!("\"{k}\": {v}{t}\n"));
        self
    }
}

/// min / max / mean over a population, with the empty case defined rather than
/// left to produce `Infinity` — which schema §2 forbids and no JSON parser
/// accepts. A reader must read `n` before touching the other three; the report
/// says so in `provenance.notes` when a population is empty.
pub fn stats(v: &[f64]) -> (usize, f64, f64, f64) {
    if v.is_empty() {
        return (0, 0.0, 0.0, 0.0);
    }
    (
        v.len(),
        v.iter().cloned().fold(f64::INFINITY, f64::min),
        v.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        v.iter().sum::<f64>() / v.len() as f64,
    )
}

#[allow(clippy::too_many_arguments)]
/// The narrow view of the invocation the report needs.
pub struct EmitMeta<'a> {
    pub opts: &'a CarveOpts,
    pub phase: &'a str,
    pub read_mode: &'a str,
    pub device: Option<&'a str>,
    pub timing: bool,
    pub command: &'a str,
}

pub fn emit(
    cli: &EmitMeta,
    image: &[u8],
    image_label: &str,
    image_sha: &str,
    report: &CarveReport,
    gt: Option<&GroundTruth>,
    started_utc: &str,
    elapsed_ms: u64,
) -> String {
    let recs = &report.records;
    let admitted: Vec<f64> = recs
        .iter()
        .filter(|r| r.admitted)
        .map(|r| r.confidence.total)
        .collect();
    let rejected: Vec<f64> = recs
        .iter()
        .filter(|r| !r.admitted)
        .map(|r| r.confidence.total)
        .collect();
    let (an, amin, amax, amean) = stats(&admitted);
    let (rn, rmin, rmax, rmean) = stats(&rejected);
    let worst_struct = recs
        .iter()
        .filter(|r| !r.admitted)
        .map(|r| r.confidence.structural_validity)
        .fold(0.0f64, f64::max);

    let mut w = W::new();
    w.line(0, "{");
    w.kv_s(2, "schema", SCHEMA, true);

    // ---- provenance ------------------------------------------------------
    w.line(2, "\"provenance\": {");
    w.kv_s(4, "producer", "core/carve/src/main.rs (carve)", true);
    w.kv_s(4, "command", cli.command, true);
    w.kv_b(4, "is_carve_run", true, true);
    w.line(4, "\"notes\": [");
    let mut notes: Vec<String> = Vec::new();
    notes.push(
        "This IS a carve run: the engine scanned the image named in `run` and reported what it \
         found. Every number here was produced by the shipped signature::scan, \
         structure::validate and confidence::confidence on the bytes at the offsets each record \
         names."
            .to_string(),
    );
    let ra = &report.reassembly;
    if cli.opts.reassemble {
        notes.push(format!(
            "TWO-FRAGMENT REASSEMBLY WAS ON (--reassemble). A candidate the structure validator \
             could not end contiguously was handed one bounded search over split point x gap \
             length, both quantised to a {}-byte cluster grid, with the gap bounded INCLUSIVELY \
             at {} clusters. {} search(es) ran: {} returned a determined two-extent splice, {} \
             ended ambiguous (splices validated but none was pinned in both dimensions, which is \
             a refusal and never a guess), {} exhausted the whole lattice with nothing validating, \
             {} were degenerate. A solved search produces ONE record carrying both extents with \
             assembly \"reassembled\"; it REPLACES the leading-fragment record for that header \
             rather than being emitted beside it, because they are the same discovery. The search \
             is forward-only and joins at most two fragments: an object stored in three pieces, or \
             with its second fragment at a lower offset than its first, is not reachable by it.",
            cli.opts.cluster_bytes,
            cli.opts.max_gap_clusters,
            ra.attempted,
            ra.solved,
            ra.ambiguous,
            ra.exhausted,
            ra.degenerate
        ));
        notes.push(
            "REASSEMBLY ENLARGES THE FALSE-POSITIVE SURFACE, AND HERE IS BY HOW MUCH. Sequential \
             carving gives a residue header one chance to validate; the lattice gives it one per \
             cell of the split-point x gap-length lattice. Over this fixture's own residue candidates — all of them bare signature \
             decoys — no assembly validates at all and the population's structural ceiling does \
             not move. Over a stronger input, one real 2048-byte JPEG header prefix written onto \
             free space, the search still answers with an object that is not in the image at a \
             measured rate of 2 in 100 sampled offsets (13 in 100 before the determinacy and \
             materiality rules that now bound it). The remainder is a structure::jpeg limit — a \
             length-bearing marker inside the entropy-coded scan is reported rather than treated \
             as fatal — and it is named in bifragment.rs rather than hidden. This is why \
             --reassemble is off by default: that default is a safety property as well as a cost \
             decision. Reproduce with `cargo test --release -p sentinelwipe-carve --lib \
             a_real_header_prefix_over_free_space_does_not_manufacture_an_object -- --nocapture`."
                .to_string(),
        );
        notes.push(format!(
            "COST IS NOT IN THIS FILE. The {} searches spent {} structure validations, of which \
             {} splice(s) were accepted by the validator and {} were determined and returned. \
             docs/output_schema.md is frozen and carries no field for a validation count, so that \
             figure is reported on stderr by the carve binary and deliberately NOT added here: \
             adding a field is a schema change with the ceremony section 10 describes, and a cost \
             figure does not earn it. Re-run the command in provenance.command and read stderr to \
             reproduce it.",
            ra.attempted, ra.validations, ra.accepted_splices, ra.solved
        ));
    } else {
        notes.push(
            "CONTIGUOUS OBJECTS ONLY. bifragment.rs was not called — --reassemble was not given — \
             so counts.by_assembly.reassembled is 0 and every extent list has exactly one entry. \
             A planted file split across a gap was NOT recovered. That zero is the honest signal \
             that reassembly was not attempted, not that it was attempted and failed."
                .to_string(),
        );
    }
    notes.push(format!(
        "Overlap suppression: {}. The rule is claimed-bytes. Candidates are scored first; \
         admitted candidates are then ranked by confidence.total descending, then length \
         descending, then offset, then kind, and each one whose span is disjoint from every span \
         already claimed becomes a recovery and claims its span. A rejected candidate whose \
         header falls inside a claimed span is suppressed, because those bytes already belong to \
         a recovered object. A record claims EACH OF ITS EXTENTS and never the hull from the \
         first to the last: the hull of a reassembled record includes the gap, and the gap is \
         where another file can live. A suppressed candidate is NOT emitted as a record: the \
         schema publishes exactly two rejection codes and both mean 'scored under the gate', \
         which a suppressed duplicate is not. {} candidate(s) were scanned, {} suppressed, {} \
         recorded.",
        if cli.opts.dedup { "applied" } else { "DISABLED by --no-dedup; every scored candidate is reported" },
        report.scanned, report.suppressed, recs.len()
    ));
    notes.push(format!(
        "The span for a candidate the structure validator could not end is a signature-layer \
         span, never a validator's claim: header to the format's terminator when the scanner \
         resolved one, and otherwise {}. That window is a POLICY CHOICE, as architecture.md D2 \
         says; only the adversarial ceiling — terms 3 and 4 pinned to 1.0 for every decoy — is \
         safe to quote against a challenge to it. The default is chosen adversarially for that \
         reason, so a rejection reported here is one the carver earned against the strongest \
         form of the candidate.",
        match cli.opts.residue_window {
            Some(n) => format!("a forced window of {n} bytes"),
            None =>
                "the shortest span earning full size credit for that kind, \
                 confidence::size_bounds(kind).full_lo"
                    .to_string(),
        }
    ));
    if !cli.opts.report_rejected {
        notes.push(format!(
            "--no-rejected was given: {} record(s) that scored under the gate are ABSENT from \
             candidates. counts.rejected and score_distribution.rejected therefore describe only \
             what was emitted, not what was scored.",
            report.withheld_rejected
        ));
    }
    if an == 0 || rn == 0 {
        notes.push(format!(
            "A population is empty (admitted n={an}, rejected n={rn}). min, max and mean over an \
             empty population are meaningless and are reported as 0.000000 rather than as \
             Infinity, which the schema forbids and no parser accepts. Read \
             score_distribution.<pop>.n first. The same applies to the margin block, whose \
             fields are derived from those two populations."
        ));
    }
    if recs.is_empty() {
        notes.push(
            "candidates is empty. That is the post-wipe success state, not a failure and not \
             missing data: the carver read the whole image and found nothing to report. Render \
             it as a result alongside the diff against the pre-wipe report."
                .to_string(),
        );
    }
    match gt {
        None => notes.push(
            "No manifest was given, so ground_truth is null and no recall figure exists in this \
             file. Nothing in candidates depends on that block."
                .to_string(),
        ),
        Some(g) => {
            notes.push(format!(
                "ground_truth.reachability is a CEILING read off the manifest — what an engine \
                 could reach on this image if it worked perfectly. \
                 ground_truth.demonstrated_recall is what THIS run measurably recovered, \
                 verified by SHA-256 against the digests fixtures/build_image.py computed \
                 independently. They are two different numbers in two different fields and must \
                 never be rendered as one. {}",
                if cli.opts.reassemble {
                    format!(
                        "This run had two-fragment reassembly ON, so it is bounded above by \
                         reachability.contiguous + reachability.needs_bifragment_reassembly = {}, \
                         and what it actually reached is demonstrated_recall.",
                        g.contiguous + g.bifragment
                    )
                } else {
                    format!(
                        "This run did not reassemble, so it is bounded above by \
                         reachability.contiguous = {}, not by contiguous + \
                         needs_bifragment_reassembly.",
                        g.contiguous
                    )
                }
            ));
            if g.false_positives > 0 {
                notes.push(format!(
                    "{} admitted record(s) matched a planted file by kind and offset but NOT by \
                     digest: the recovered bytes are not the planted bytes. Their per-record \
                     ground_truth.sha256_matches is false. Counting rows instead of comparing \
                     digests is how that hides.",
                    g.false_positives
                ));
            }
        }
    }
    for (i, n) in notes.iter().enumerate() {
        w.ind(6);
        let t = W::tail(i + 1 < notes.len());
        w.raw(&format!("\"{}\"{t}\n", esc(n)));
    }
    w.line(4, "]");
    w.line(2, "},");

    // ---- run -------------------------------------------------------------
    w.line(2, "\"run\": {");
    w.kv_s(4, "phase", cli.phase, true);
    w.kv_s(4, "image_path", image_label, true);
    w.kv_u(4, "image_bytes", image.len() as u64, true);
    w.kv_s(4, "image_sha256", image_sha, true);
    w.kv_s(4, "read_mode", cli.read_mode, true);
    w.kv_os(4, "device", cli.device, true);
    if cli.timing {
        w.line(4, "\"timing\": {");
        w.kv_s(6, "started_utc", started_utc, true);
        w.kv_u(6, "elapsed_ms", elapsed_ms, true);
        w.kv_u(6, "bytes_read", image.len() as u64, false);
        w.line(4, "}");
    } else {
        w.kv_os(4, "timing", None, false);
    }
    w.line(2, "},");

    // ---- policy ----------------------------------------------------------
    w.line(2, "\"policy\": {");
    w.kv_s(
        4,
        "formula",
        &format!(
            "confidence = {W_SIGNATURE:.2}*signature_integrity + \
             {W_STRUCTURE:.2}*structural_validity + {W_ENTROPY:.2}*entropy_consistency + \
             {W_SIZE:.2}*size_plausibility"
        ),
        true,
    );
    w.line(4, "\"weights\": {");
    w.kv_f(6, "signature_integrity", W_SIGNATURE, true);
    w.kv_f(6, "structural_validity", W_STRUCTURE, true);
    w.kv_f(6, "entropy_consistency", W_ENTROPY, true);
    w.kv_f(6, "size_plausibility", W_SIZE, false);
    w.line(4, "},");
    w.kv_f(
        4,
        "weights_sum",
        W_SIGNATURE + W_STRUCTURE + W_ENTROPY + W_SIZE,
        true,
    );
    // The gate the run ACTUALLY used, which is what a score is re-derivable
    // against years later. It defaults to confidence::MIN_CONFIDENCE.
    w.kv_f(4, "min_confidence", cli.opts.min_confidence, true);
    w.kv_f(4, "non_structure_ceiling", NON_STRUCTURE_CEILING, true);
    w.kv_f(4, "structural_breach_point", STRUCTURAL_BREACH_POINT, true);
    w.line(4, "\"signature_ladder\": {");
    w.kv_f(6, "header-mismatch", SIG_HEADER_MISMATCH, true);
    w.kv_f(6, "header-only", SIG_HEADER_ONLY, true);
    w.kv_f(6, "no-footer-defined", SIG_NO_FOOTER_DEFINED, true);
    w.kv_f(6, "header-and-footer", SIG_HEADER_AND_FOOTER, false);
    w.line(4, "},");
    w.kv_u(4, "entropy_min_sample_bytes", MIN_ENTROPY_SAMPLE as u64, true);
    w.kv_f(4, "entropy_unknown", ENTROPY_UNKNOWN, false);
    w.line(2, "},");

    // ---- kind_policy -----------------------------------------------------
    w.line(2, "\"kind_policy\": {");
    for (i, k) in KINDS.iter().enumerate() {
        let b = entropy_band(*k);
        let s = size_bounds(*k);
        w.ind(4);
        w.raw(&format!("\"{}\": {{\n", k.as_str()));
        w.kv_b(6, "defines_footer", kind_defines_footer(*k), true);
        w.ind(6);
        w.raw(&format!(
            "\"entropy_band_bits_per_byte\": [{}, {}, {}, {}],\n",
            f(b.lo_zero),
            f(b.lo_full),
            f(b.hi_full),
            f(b.hi_zero)
        ));
        w.ind(6);
        w.raw(&format!(
            "\"size_bounds_bytes\": [{}, {}, {}, {}]\n",
            s.zero_lo, s.full_lo, s.full_hi, s.zero_hi
        ));
        w.line(4, if i + 1 < KINDS.len() { "}," } else { "}" });
    }
    w.line(2, "},");

    // ---- counts ----------------------------------------------------------
    w.line(2, "\"counts\": {");
    w.kv_u(4, "records", recs.len() as u64, true);
    w.kv_u(4, "admitted", an as u64, true);
    w.kv_u(4, "rejected", rn as u64, true);
    w.kv_u(
        4,
        "sha256_matches_planted",
        gt.map(|g| g.sha256_matches_planted).unwrap_or(0),
        true,
    );
    w.line(4, "\"by_kind\": {");
    let present: Vec<Kind> = KINDS
        .iter()
        .cloned()
        .filter(|k| recs.iter().any(|r| r.kind == *k))
        .collect();
    for (i, k) in present.iter().enumerate() {
        let rr: Vec<&Recovered> = recs.iter().filter(|r| r.kind == *k).collect();
        let a = rr.iter().filter(|r| r.admitted).count();
        w.ind(6);
        w.raw(&format!(
            "\"{}\": {{ \"records\": {}, \"admitted\": {}, \"rejected\": {} }}{}\n",
            k.as_str(),
            rr.len(),
            a,
            rr.len() - a,
            W::tail(i + 1 < present.len())
        ));
    }
    w.line(4, "},");
    w.line(4, "\"by_assembly\": {");
    for (i, a) in ASSEMBLIES.iter().enumerate() {
        let n = recs
            .iter()
            .filter(|r| r.assembly.as_str() == *a)
            .count();
        w.ind(6);
        w.raw(&format!("\"{a}\": {n}{}\n", W::tail(i + 1 < ASSEMBLIES.len())));
    }
    w.line(4, "}");
    w.line(2, "},");

    // ---- score_distribution ----------------------------------------------
    w.line(2, "\"score_distribution\": {");
    for (name, (n, mn, mx, me), comma) in [
        ("admitted", (an, amin, amax, amean), true),
        ("rejected", (rn, rmin, rmax, rmean), false),
    ] {
        w.ind(4);
        w.raw(&format!(
            "\"{name}\": {{ \"n\": {n}, \"min\": {}, \"max\": {}, \"mean\": {} }}{}\n",
            f(mn),
            f(mx),
            f(me),
            W::tail(comma)
        ));
    }
    w.line(2, "},");

    // ---- margin ----------------------------------------------------------
    //
    // Every field here except structural_breach_point describes a MEASURED
    // population.  When that population is empty -- which is the normal and
    // desired post-wipe result -- there is no margin to report and the field is
    // null, not zero.  `admitted_n` and `rejected_n` are carried so a renderer
    // can branch before reading, the way score_distribution's `n` already works.
    let has_a = an > 0;
    let has_r = rn > 0;
    let opt = |ok: bool, v: f64| if ok { Some(v) } else { None };
    w.line(2, "\"margin\": {");
    w.kv_u(4, "admitted_n", an as u64, true);
    w.kv_u(4, "rejected_n", rn as u64, true);
    w.kv_of(4, "lowest_admitted", opt(has_a, amin), true);
    w.kv_of(4, "highest_rejected", opt(has_r, rmax), true);
    w.kv_of(4, "population_gap", opt(has_a && has_r, amin - rmax), true);
    w.kv_of(
        4,
        "gate_headroom",
        opt(has_r, cli.opts.min_confidence - rmax),
        true,
    );
    w.kv_of(
        4,
        "worst_rejected_structural_validity",
        opt(has_r, worst_struct),
        true,
    );
    // Derived from the weights and the gate alone, so it is defined even with
    // nothing on the disk.
    w.kv_f(4, "structural_breach_point", STRUCTURAL_BREACH_POINT, true);
    w.kv_of(
        4,
        "structural_headroom",
        opt(has_r, STRUCTURAL_BREACH_POINT - worst_struct),
        true,
    );
    w.kv_os(
        4,
        "binds",
        if has_r { Some("structural_headroom") } else { None },
        false,
    );
    w.line(2, "},");

    // ---- ground_truth ----------------------------------------------------
    match gt {
        None => {
            w.kv_os(2, "ground_truth", None, true);
        }
        Some(g) => {
            w.line(2, "\"ground_truth\": {");
            w.kv_s(4, "manifest_path", &g.manifest_label, true);
            w.kv_s(4, "manifest_sha256", &g.manifest_sha256, true);
            w.kv_u(4, "planted_total", g.planted_total, true);
            w.line(4, "\"reachability\": {");
            w.kv_u(6, "contiguous", g.contiguous, true);
            w.kv_u(6, "needs_bifragment_reassembly", g.bifragment, true);
            w.kv_u(
                6,
                "unreachable_by_construction",
                g.unreachable.len() as u64,
                false,
            );
            w.line(4, "},");
            w.line(4, "\"unreachable\": [");
            for (i, (path, kind, reason)) in g.unreachable.iter().enumerate() {
                w.line(6, "{");
                w.kv_s(8, "path", path, true);
                w.kv_s(8, "kind", kind, true);
                w.kv_s(8, "reason", reason, false);
                w.line(6, if i + 1 < g.unreachable.len() { "}," } else { "}" });
            }
            w.line(4, "],");
            w.kv_b(4, "recall_measured", true, true);
            w.line(4, "\"demonstrated_recall\": {");
            w.kv_u(6, "recovered", g.recovered_exact, true);
            w.kv_u(6, "of", g.planted_total, true);
            w.kv_s(
                6,
                "method",
                if cli.opts.reassemble {
                    "contiguous engine plus bounded two-fragment reassembly (--reassemble); a \
                     planted file counts as recovered only when an ADMITTED record's SHA-256 \
                     equals the digest the manifest recorded for it, whether that record has one \
                     extent or two. The ceiling for this run is reachability.contiguous + \
                     reachability.needs_bifragment_reassembly, which is a ceiling and is reported \
                     separately."
                } else {
                    "contiguous engine; a planted file counts as recovered only when an ADMITTED \
                     record's SHA-256 equals the digest the manifest recorded for it. \
                     bifragment.rs was not called, so this run is bounded above by \
                     reachability.contiguous — which is a ceiling and is reported separately."
                },
                false,
            );
            w.line(4, "},");
            w.kv_s(
                4,
                "demonstrated_recall_note",
                &if cli.opts.reassemble {
                    format!(
                        "demonstrated recall (contiguous engine + two-fragment reassembly): {} of \
                         {} planted files, compared BY SHA-256 and not by row count. The ceiling \
                         for this run is reachability.contiguous + \
                         reachability.needs_bifragment_reassembly = {}; {} planted files are \
                         reachable by nothing this carver does and are named individually above. \
                         {} of the records here were reassembled from two extents, and what the \
                         searches cost is on stderr, not in this file.",
                        g.recovered_exact,
                        g.planted_total,
                        g.contiguous + g.bifragment,
                        g.unreachable.len(),
                        report.reassembly.solved
                    )
                } else {
                    format!(
                        "demonstrated recall (contiguous engine): {} of {} planted files, \
                         compared BY SHA-256 and not by row count. The ceiling for this engine is \
                         reachability.contiguous = {}; {} more planted files are reachable only \
                         with bifragment reassembly, which was not run, and {} are reachable by \
                         nothing this carver does and are named individually above.",
                        g.recovered_exact,
                        g.planted_total,
                        g.contiguous,
                        g.bifragment,
                        g.unreachable.len()
                    )
                },
                false,
            );
            w.line(2, "},");
        }
    }

    // ---- candidates ------------------------------------------------------
    w.line(2, "\"candidates\": [");
    for (i, r) in recs.iter().enumerate() {
        w.line(4, "{");
        w.kv_s(6, "id", &r.id(), true);
        w.kv_s(6, "kind", r.kind.as_str(), true);
        w.kv_u(6, "offset", r.offset, true);
        w.kv_u(6, "length", r.length, true);
        w.kv_s(6, "assembly", r.assembly.as_str(), true);
        w.ind(6);
        w.raw("\"extents\": [");
        for (j, e) in r.extents.iter().enumerate() {
            w.raw(&format!(
                "{{ \"offset\": {}, \"length\": {} }}{}",
                e.offset,
                e.length,
                if j + 1 < r.extents.len() { ", " } else { "" }
            ));
        }
        w.raw("],\n");
        w.kv_s(6, "sha256", &r.sha256, true);

        w.line(6, "\"signature\": {");
        w.kv_b(8, "header_matched", r.signature.header_matched, true);
        w.kv_b(8, "footer_defined", r.signature.footer_defined, true);
        w.kv_b(8, "footer_found", r.signature.footer_found, true);
        w.kv_s(8, "ladder_rung", r.signature.ladder_rung, false);
        w.line(6, "},");

        w.line(6, "\"structure\": {");
        w.kv_b(8, "valid", r.structure.valid, true);
        match r.structure.end {
            Some(e) => w.kv_u(8, "end_relative", e, true),
            None => w.kv_os(8, "end_relative", None, true),
        };
        w.kv_f(8, "score", r.structure.score, true);
        w.kv_s(8, "detail", &r.structure.detail, false);
        w.line(6, "},");

        w.line(6, "\"entropy\": {");
        w.kv_f(8, "bits_per_byte", r.entropy_bits_per_byte, true);
        w.kv_b(8, "sampled", r.entropy_sampled, false);
        w.line(6, "},");

        let c = &r.confidence;
        w.line(6, "\"confidence\": {");
        w.kv_f(8, "signature_integrity", c.signature_integrity, true);
        w.kv_f(8, "structural_validity", c.structural_validity, true);
        w.kv_f(8, "entropy_consistency", c.entropy_consistency, true);
        w.kv_f(8, "size_plausibility", c.size_plausibility, true);
        w.line(8, "\"weighted\": {");
        w.kv_f(
            10,
            "signature_integrity",
            W_SIGNATURE * c.signature_integrity,
            true,
        );
        w.kv_f(
            10,
            "structural_validity",
            W_STRUCTURE * c.structural_validity,
            true,
        );
        w.kv_f(
            10,
            "entropy_consistency",
            W_ENTROPY * c.entropy_consistency,
            true,
        );
        w.kv_f(10, "size_plausibility", W_SIZE * c.size_plausibility, false);
        w.line(8, "},");
        w.kv_f(8, "total", c.total, false);
        w.line(6, "},");

        w.kv_b(6, "admitted", r.admitted, true);
        w.kv_os(6, "reason_code", r.reason_code, true);
        w.kv_os(6, "reason", r.reason.as_deref(), true);

        match gt.and_then(|g| g.matches.get(i).and_then(|m| m.as_ref())) {
            Some((path, mk, rec, ok)) => {
                w.line(6, "\"ground_truth\": {");
                w.kv_s(8, "path", path, true);
                w.kv_s(8, "manifest_kind", mk, true);
                w.kv_s(8, "expected_recoverable", rec, true);
                w.kv_b(8, "sha256_matches", *ok, false);
                w.line(6, "}");
            }
            None => {
                w.kv_os(6, "ground_truth", None, false);
            }
        }
        w.line(4, if i + 1 < recs.len() { "}," } else { "}" });
    }
    w.line(2, "]");
    w.line(0, "}");
    w.b
}

/// `provenance.command`: the invocation that reproduces this report, with every
/// non-default option spelled out. The post-wipe carve is expected to differ
/// from the pre-wipe one in `--phase` and in nothing else, and this string is
/// how that is checked rather than asserted.

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn parse(bytes: &[u8]) -> Json {
        P { b: bytes, i: 0 }.value()
    }
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(v) => v,
            _ => &[],
        }
    }
    pub fn s(&self) -> &str {
        match self {
            Json::Str(s) => s,
            _ => "",
        }
    }
    pub fn u(&self) -> u64 {
        match self {
            Json::Num(n) => *n as u64,
            _ => 0,
        }
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl P<'_> {
    pub fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    pub fn value(&mut self) -> Json {
        self.ws();
        match self.b.get(self.i) {
            Some(b'{') => {
                self.i += 1;
                let mut kv = Vec::new();
                loop {
                    self.ws();
                    if self.b.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        break;
                    }
                    if self.i >= self.b.len() {
                        break;
                    }
                    let k = match self.value() {
                        Json::Str(s) => s,
                        other => panic!("manifest: object key is not a string: {other:?}"),
                    };
                    self.ws();
                    assert_eq!(self.b.get(self.i), Some(&b':'), "manifest: expected ':'");
                    self.i += 1;
                    let v = self.value();
                    kv.push((k, v));
                    self.ws();
                    if self.b.get(self.i) == Some(&b',') {
                        self.i += 1;
                    }
                }
                Json::Obj(kv)
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    self.ws();
                    if self.b.get(self.i) == Some(&b']') {
                        self.i += 1;
                        break;
                    }
                    if self.i >= self.b.len() {
                        break;
                    }
                    a.push(self.value());
                    self.ws();
                    if self.b.get(self.i) == Some(&b',') {
                        self.i += 1;
                    }
                }
                Json::Arr(a)
            }
            Some(b'"') => {
                self.i += 1;
                let mut s = String::new();
                while let Some(&c) = self.b.get(self.i) {
                    self.i += 1;
                    match c {
                        b'"' => break,
                        b'\\' => {
                            let e = self.b[self.i];
                            self.i += 1;
                            match e {
                                b'n' => s.push('\n'),
                                b't' => s.push('\t'),
                                b'r' => s.push('\r'),
                                b'b' => s.push('\u{8}'),
                                b'f' => s.push('\u{c}'),
                                b'u' => {
                                    let h =
                                        std::str::from_utf8(&self.b[self.i..self.i + 4]).unwrap();
                                    let cp = u32::from_str_radix(h, 16).unwrap();
                                    self.i += 4;
                                    s.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                                }
                                other => s.push(other as char),
                            }
                        }
                        other => s.push(other as char),
                    }
                }
                Json::Str(s)
            }
            Some(b't') => {
                self.i += 4;
                Json::Bool(true)
            }
            Some(b'f') => {
                self.i += 5;
                Json::Bool(false)
            }
            Some(b'n') => {
                self.i += 4;
                Json::Null
            }
            _ => {
                let start = self.i;
                while self.i < self.b.len()
                    && matches!(self.b[self.i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    self.i += 1;
                }
                if start == self.i {
                    return Json::Null;
                }
                let t = std::str::from_utf8(&self.b[start..self.i]).unwrap();
                Json::Num(t.parse().unwrap_or(0.0))
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

