//! `carve` — the operator's handle on the carving engine.
//!
//! Image path in. **One** JSON document on stdout, conforming to
//! `sentinelwipe.carve.report/1` as frozen in `docs/output_schema.md`. Nothing
//! else on stdout, ever: diagnostics go to stderr, so `carve img > report.json`
//! is always a valid report and never a report with a progress line in it.
//!
//! # Exit codes
//!
//! The convention is `grep`'s, which is the one every operator already knows:
//! 0 means found, 1 means a clean run that found nothing, and 2 and above mean
//! the run itself did not happen properly.
//!
//! | code | meaning |
//! |---|---|
//! | 0 | at least one candidate was admitted. The report is on stdout |
//! | 1 | no candidate was admitted. **Not an error.** The report is on stdout and is complete. This is the expected exit of the post-wipe carve, and that exit *is* the proof the wipe worked |
//! | 2 | usage error — an unknown option, a missing value, no image path. Nothing on stdout |
//! | 3 | the image could not be read. Nothing on stdout |
//! | 4 | internal error — the engine broke an invariant of its own. Nothing on stdout |
//!
//! A shell that must not stop on exit 1 should test the code rather than rely on
//! `set -e`. `make demo` does exactly that.
//!
//! # Byte-identical pre-wipe and post-wipe invocations
//!
//! The product claim is that the same carver, with the same parameters, is
//! pointed at the medium before and after the wipe. So every parameter that
//! changes what the engine does is a command-line option — none is a constant
//! compiled in, an environment variable, or a default that differs between
//! runs — and the report republishes all of them in `policy` and in the
//! diagnostics. The two invocations differ in exactly one flag, `--phase`, and
//! `run.image_sha256` is what proves the medium changed underneath them.
//!
//! ```text
//! carve --phase pre-wipe  --manifest out/fixture.manifest.json out/fixture.img > pre.json
//! carve --phase post-wipe --manifest out/fixture.manifest.json out/fixture.img > post.json
//! ```
//!
//! Two-fragment reassembly is one such parameter. It is OFF by default and
//! `--reassemble` turns it on; `--no-reassemble` states the default explicitly,
//! so whichever way it is set, the state is on the command line and
//! `provenance.command` republishes it on both sides. A reassembling demo runs
//! the same two lines with `--reassemble --cluster-bytes N --max-gap-clusters N`
//! added to each.
//!
//! # The one number that is not in the JSON
//!
//! `docs/output_schema.md` is frozen and carries no field for a validation
//! count, so the cost of the two-fragment searches — every `structure::validate`
//! call they spent, the failures included — is reported on **stderr** and named
//! in `provenance.notes` so a reader of the JSON alone is told where it went.
//! Adding a field for it would be a schema change with the ceremony §10
//! describes, and a cost figure does not earn that.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sentinelwipe_carve::carve::{
    carve, sha256_hex, CarveOpts, CarveReport, Recovered, Sha256,
};
use sentinelwipe_carve::confidence::{
    entropy_band, kind_defines_footer, size_bounds, ENTROPY_UNKNOWN,
    MIN_ENTROPY_SAMPLE, NON_STRUCTURE_CEILING, SIG_HEADER_AND_FOOTER, SIG_HEADER_MISMATCH,
    SIG_HEADER_ONLY, SIG_NO_FOOTER_DEFINED, STRUCTURAL_BREACH_POINT, W_ENTROPY, W_SIGNATURE,
    W_SIZE, W_STRUCTURE,
};
use sentinelwipe_carve::Kind;

/// The schema this binary emits. Bumping it is a schema change with the ceremony
/// `docs/output_schema.md` §10 describes.
const SCHEMA: &str = "sentinelwipe.carve.report/1";

/// Every kind the carver knows, in table order. `kind_policy` publishes all
/// seven whether or not a record of that kind appears.
const KINDS: [Kind; 7] = [
    Kind::Jpeg,
    Kind::Png,
    Kind::Pdf,
    Kind::Zip,
    Kind::Sqlite,
    Kind::Mp4,
    Kind::Gzip,
];

const ASSEMBLIES: [&str; 3] = ["contiguous", "reassembled", "signature-span"];

// Exit codes. Named, because a bare `2` in a match arm is a number nobody can
// grep for.
const EXIT_ADMITTED: u8 = 0;
const EXIT_NO_CANDIDATES: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_UNREADABLE: u8 = 3;
const EXIT_INTERNAL: u8 = 4;

const HELP: &str = "\
carve — SENTINELWIPE signature and structure carving engine

USAGE
  carve [OPTIONS] <IMAGE>

  <IMAGE> is a raw image FILE. Nothing is mounted and no block device is
  attached; the carver reads bytes. See docs/architecture.md D1.

OPTIONS
  --phase <pre-wipe|post-wipe|standalone>
                       Which carve of the demo loop this is. Written to
                       run.phase; changes nothing the engine does.
                       [default: standalone]
  --manifest <PATH>    Fixture manifest to compare the result against by
                       SHA-256. Without it, ground_truth is null and the
                       report is still schema-valid. Ground truth is read
                       AFTER the carve and never reaches the engine.
  --min-confidence <F> The admission gate. [default: confidence::MIN_CONFIDENCE
                       = 0.7500, read from the crate, never a literal]
  --residue-window <N> Span in bytes for a candidate with neither a validator
                       end nor a terminator. [default: per kind, the shortest
                       span earning full size credit, confidence::size_bounds
                       (kind).full_lo — deliberately adversarial, so a reported
                       rejection is one the carver earned against the strongest
                       form of that candidate]
  --reassemble         Attempt bounded two-fragment gap carving on every
                       candidate the structure validator could not end
                       contiguously. A search that returns a determined splice
                       produces ONE record with two extents and
                       assembly \"reassembled\"; it REPLACES the leading-fragment
                       record for that header rather than joining it.
                       [default: OFF — see --no-reassemble]
  --no-reassemble      State the default explicitly. The pre-wipe and post-wipe
                       carve must run with byte-identical parameters, and a
                       default nobody wrote down cannot be shown to have been
                       held constant. [default]
  --cluster-bytes <N>  The allocation unit of the medium. The split point and
                       the resume point of a two-fragment search are both
                       constrained to this grid. This is a property of the MEDIUM and is
                       never read from the fixture manifest: ground truth is
                       read after the carve and never reaches the engine.
                       A wrong value costs recoveries and cannot manufacture
                       one. [default: 2048]
  --max-gap-clusters <N>
                       Ceiling on the gap between the two fragments, in
                       clusters, applied INCLUSIVELY: a gap of exactly N
                       clusters is searched. Search cost is linear in N.
                       [default: 128]
  --no-dedup           Report every scored candidate, applying no overlap
                       suppression. This is how the suppression rule is
                       audited. [default: suppression on]
  --no-rejected        Emit admitted records only. The count withheld is
                       reported on stderr rather than silently dropped.
                       [default: rejected records are emitted — they are the
                       evidence the false-positive panel is built from]
  --read-mode <file|device>
                       Written to run.read_mode. [default: file]
  --device <PATH>      Written to run.device. Requires --read-mode device.
  --image-path <PATH>  The repo-relative string written to run.image_path.
                       [default: <IMAGE> made relative to the working
                       directory] A report must not carry a laptop's
                       directory layout.
  --timing             Populate run.timing with the start time, the elapsed
                       milliseconds and the bytes read. OFF by default,
                       because a duration is the one field that stops two
                       runs over the same image producing the same file.
  -o, --out <PATH>     Write the report here instead of stdout. Diagnostics
                       still go to stderr.
  -h, --help           This text.
  -V, --version        Version.

EXIT CODES
  0  at least one candidate was admitted; the report is on stdout
  1  no candidate was admitted; the report is on stdout and is COMPLETE.
     This is not an error. It is the expected exit of the post-wipe carve,
     and that exit is the proof the wipe worked. Test the code; do not rely
     on `set -e`.
  2  usage error. Nothing on stdout
  3  the image could not be read. Nothing on stdout
  4  internal error. Nothing on stdout

  0/1/2 follow grep's convention: found, not found, something went wrong
  with the run itself.

NOTES
  Without --reassemble this is a contiguous engine: bifragment.rs is not
  called, counts.by_assembly.reassembled is 0, and that zero means
  reassembly was not ATTEMPTED rather than attempted and failed. A file
  stored in fragments is not recovered.

  With --reassemble, a candidate that did not validate contiguously pays one
  bounded lattice search of split point x gap length, both on the cluster
  grid. Most of those searches fail, and a failed search is the expensive
  one; the whole cost is printed on stderr because the output schema is
  frozen and has no field for it. Recovering a fragmented file raises what
  the engine can reach; it does not change either published number by
  itself. ground_truth.reachability is a CEILING read off the manifest and
  ground_truth.demonstrated_recall is what the run measurably recovered.
  They are two different numbers in two different fields.

  The search does not go backwards and does not join three fragments. An
  object whose second fragment lies at a lower offset than its first, or
  which is stored in three pieces, is not recoverable by it and is reported
  as not recovered.
";

// ===========================================================================
// Options off the command line
// ===========================================================================

struct Cli {
    image: PathBuf,
    image_path_label: Option<String>,
    manifest: Option<PathBuf>,
    phase: String,
    read_mode: String,
    device: Option<String>,
    timing: bool,
    out: Option<PathBuf>,
    opts: CarveOpts,
}

enum Parsed {
    Run(Box<Cli>),
    /// Print this on stdout and exit 0. `--help` and `--version` are the only
    /// two things other than the report that may reach stdout.
    Print(String),
    Usage(String),
}

fn parse(args: &[String]) -> Parsed {
    let mut image: Option<PathBuf> = None;
    let mut cli = Cli {
        image: PathBuf::new(),
        image_path_label: None,
        manifest: None,
        phase: "standalone".to_string(),
        read_mode: "file".to_string(),
        device: None,
        timing: false,
        out: None,
        opts: CarveOpts::default(),
    };

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let value = |name: &str, i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        let r: Result<(), String> = (|| {
            match a {
                "-h" | "--help" => return Err("\u{0}help".to_string()),
                "-V" | "--version" => return Err("\u{0}version".to_string()),
                "--phase" => {
                    let v = value("--phase", &mut i)?;
                    if !["pre-wipe", "post-wipe", "standalone"].contains(&v.as_str()) {
                        return Err(format!(
                            "--phase must be pre-wipe, post-wipe or standalone, not {v:?}"
                        ));
                    }
                    cli.phase = v;
                }
                "--manifest" => cli.manifest = Some(PathBuf::from(value("--manifest", &mut i)?)),
                "--min-confidence" => {
                    let v = value("--min-confidence", &mut i)?;
                    let f: f64 = v
                        .parse()
                        .map_err(|_| format!("--min-confidence {v:?} is not a number"))?;
                    if !(0.0..=1.0).contains(&f) {
                        return Err(format!("--min-confidence must be in [0,1], got {f}"));
                    }
                    cli.opts.min_confidence = f;
                }
                "--residue-window" => {
                    let v = value("--residue-window", &mut i)?;
                    let n: u64 = v
                        .parse()
                        .map_err(|_| format!("--residue-window {v:?} is not a byte count"))?;
                    if n == 0 {
                        return Err("--residue-window must be at least 1 byte".to_string());
                    }
                    cli.opts.residue_window = Some(n);
                }
                "--reassemble" => cli.opts.reassemble = true,
                "--no-reassemble" => cli.opts.reassemble = false,
                "--cluster-bytes" => {
                    let v = value("--cluster-bytes", &mut i)?;
                    let n: u64 = v
                        .parse()
                        .map_err(|_| format!("--cluster-bytes {v:?} is not a byte count"))?;
                    if n == 0 {
                        return Err("--cluster-bytes must be at least 1 byte".to_string());
                    }
                    cli.opts.cluster_bytes = n;
                }
                "--max-gap-clusters" => {
                    let v = value("--max-gap-clusters", &mut i)?;
                    let n: u64 = v
                        .parse()
                        .map_err(|_| format!("--max-gap-clusters {v:?} is not a cluster count"))?;
                    if n == 0 {
                        return Err(
                            "--max-gap-clusters must be at least 1: a gap of zero clusters is a \
                             contiguous object and sequential carving owns it"
                                .to_string(),
                        );
                    }
                    cli.opts.max_gap_clusters = n;
                }
                "--no-dedup" => cli.opts.dedup = false,
                "--no-rejected" => cli.opts.report_rejected = false,
                "--read-mode" => {
                    let v = value("--read-mode", &mut i)?;
                    if !["file", "device"].contains(&v.as_str()) {
                        return Err(format!("--read-mode must be file or device, not {v:?}"));
                    }
                    cli.read_mode = v;
                }
                "--device" => cli.device = Some(value("--device", &mut i)?),
                "--image-path" => cli.image_path_label = Some(value("--image-path", &mut i)?),
                "--timing" => cli.timing = true,
                "-o" | "--out" => cli.out = Some(PathBuf::from(value("--out", &mut i)?)),
                other if other.starts_with('-') && other != "-" => {
                    return Err(format!("unknown option {other:?}"))
                }
                other => {
                    if image.is_some() {
                        return Err(format!(
                            "more than one image path given ({:?} and {other:?}); \
                             carve reads one image per run",
                            image.as_ref().unwrap()
                        ));
                    }
                    image = Some(PathBuf::from(other));
                }
            }
            Ok(())
        })();
        if let Err(e) = r {
            return match e.as_str() {
                "\u{0}help" => Parsed::Print(HELP.to_string()),
                "\u{0}version" => {
                    Parsed::Print(format!("carve {}\n", env!("CARGO_PKG_VERSION")))
                }
                _ => Parsed::Usage(e),
            };
        }
        i += 1;
    }

    let Some(image) = image else {
        return Parsed::Usage("no image path given".to_string());
    };
    if cli.device.is_some() && cli.read_mode != "device" {
        return Parsed::Usage("--device requires --read-mode device".to_string());
    }
    if cli.read_mode == "device" && cli.device.is_none() {
        return Parsed::Usage("--read-mode device requires --device <PATH>".to_string());
    }
    if cli
        .opts
        .max_gap_clusters
        .checked_mul(cli.opts.cluster_bytes)
        .is_none()
    {
        return Parsed::Usage(format!(
            "--max-gap-clusters {} x --cluster-bytes {} overflows a 64-bit byte count",
            cli.opts.max_gap_clusters, cli.opts.cluster_bytes
        ));
    }
    cli.image = image;
    Parsed::Run(Box::new(cli))
}

/// The string written to `run.image_path`. Schema §4.3: repo-relative, never
/// absolute, because a report must not carry a laptop's directory layout.
fn relative_label(image: &Path, explicit: Option<&str>) -> String {
    if let Some(s) = explicit {
        return s.to_string();
    }
    if image.is_relative() {
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

fn main() -> ExitCode {
    // An invariant the engine breaks is an internal error with its own exit
    // code, not a code 101 nobody can distinguish from a signal.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        eprintln!("carve: INTERNAL ERROR — nothing was written to stdout. exit {EXIT_INTERNAL}");
        std::process::exit(EXIT_INTERNAL as i32);
    }));

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse(&args) {
        Parsed::Run(c) => c,
        Parsed::Print(text) => {
            print!("{text}");
            return ExitCode::from(EXIT_ADMITTED);
        }
        Parsed::Usage(msg) => {
            eprintln!("carve: {msg}");
            eprintln!("carve: run `carve --help`. exit {EXIT_USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let started = std::time::Instant::now();
    let started_utc = utc_now();

    let image = match std::fs::read(&cli.image) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("carve: cannot read {}: {e}", cli.image.display());
            eprintln!("carve: exit {EXIT_UNREADABLE}");
            return ExitCode::from(EXIT_UNREADABLE);
        }
    };
    if image.is_empty() {
        eprintln!(
            "carve: {} is 0 bytes. A zero-length image is read, reported as an empty result, \
             and is not an error.",
            cli.image.display()
        );
    }

    let image_label = relative_label(&cli.image, cli.image_path_label.as_deref());
    let image_sha = {
        let mut h = Sha256::new();
        for chunk in image.chunks(1 << 20) {
            h.update(chunk);
        }
        sentinelwipe_carve::carve::hex(&h.finish())
    };

    eprintln!(
        "carve: image {image_label}  {} bytes  sha256 {image_sha}",
        image.len()
    );
    eprintln!(
        "carve: gate {:.4}  dedup {}  rejected-records {}  residue-window {}",
        cli.opts.min_confidence,
        if cli.opts.dedup { "on" } else { "off" },
        if cli.opts.report_rejected {
            "reported"
        } else {
            "withheld"
        },
        match cli.opts.residue_window {
            Some(n) => format!("{n} bytes (forced)"),
            None => "per-kind size_bounds().full_lo".to_string(),
        }
    );
    if cli.opts.reassemble {
        eprintln!(
            "carve: reassembly ON  cluster {} bytes  max gap {} clusters ({} bytes, inclusive)  \
             first fragment <= {} clusters",
            cli.opts.cluster_bytes,
            cli.opts.max_gap_clusters,
            cli.opts.max_gap_clusters * cli.opts.cluster_bytes,
            sentinelwipe_carve::bifragment::MAX_FIRST_FRAGMENT_CLUSTERS
        );
    } else {
        eprintln!(
            "carve: reassembly OFF (--reassemble turns it on). Contiguous objects only; \
             counts.by_assembly.reassembled will be 0 because nothing was attempted."
        );
    }

    let report = carve(&image, &cli.opts);
    let elapsed = started.elapsed();

    // Ground truth is read AFTER the carve and is never handed to the engine.
    let gt = match &cli.manifest {
        None => None,
        Some(p) => match std::fs::read(p) {
            Ok(bytes) => Some(GroundTruth::load(p, &bytes, &report)),
            Err(e) => {
                eprintln!("carve: cannot read manifest {}: {e}", p.display());
                eprintln!("carve: exit {EXIT_UNREADABLE}");
                return ExitCode::from(EXIT_UNREADABLE);
            }
        },
    };

    let json = emit(
        &cli,
        &image,
        &image_label,
        &image_sha,
        &report,
        gt.as_ref(),
        &started_utc,
        elapsed.as_millis() as u64,
    );

    match &cli.out {
        None => {
            let mut so = std::io::stdout().lock();
            if let Err(e) = so.write_all(json.as_bytes()).and_then(|_| so.flush()) {
                eprintln!("carve: writing the report to stdout failed: {e}");
                return ExitCode::from(EXIT_INTERNAL);
            }
        }
        Some(p) => {
            if let Err(e) = std::fs::write(p, json.as_bytes()) {
                eprintln!("carve: cannot write {}: {e}", p.display());
                return ExitCode::from(EXIT_UNREADABLE);
            }
            eprintln!("carve: report written to {}", p.display());
        }
    }

    // ---- diagnostics, on stderr ------------------------------------------
    let admitted = report.admitted();
    eprintln!(
        "carve: scanned {} candidates, suppressed {} overlapping, recorded {}",
        report.scanned,
        report.suppressed,
        report.records.len()
    );
    eprintln!(
        "carve: admitted {admitted}  rejected {}{}",
        report.rejected(),
        if report.withheld_rejected > 0 {
            format!(" ({} rejected records withheld by --no-rejected)", report.withheld_rejected)
        } else {
            String::new()
        }
    );
    let ra = &report.reassembly;
    if cli.opts.reassemble {
        eprintln!(
            "carve: reassembly attempted {} search(es): solved {}, ambiguous {}, exhausted {}, \
             degenerate {}, refused-contiguous {}, budget {}",
            ra.attempted,
            ra.solved,
            ra.ambiguous,
            ra.exhausted,
            ra.degenerate,
            ra.refused_contiguous,
            ra.budget
        );
        // The schema is frozen and has no field for a cost. Saying where the
        // number went is the difference between a missing figure and a hidden
        // one.
        eprintln!(
            "carve: reassembly cost {} structure validations, {} splice(s) accepted by the \
             validator, {} of them determined and returned. docs/output_schema.md is FROZEN and \
             carries no field for a validation count, so this figure is reported here on stderr \
             and is NOT in the JSON; provenance.notes says so in the report itself.",
            ra.validations, ra.accepted_splices, ra.solved
        );
        for sc in &ra.solved_cost {
            let ext = report
                .records
                .iter()
                .find(|r| r.id() == sc.id)
                .map(|r| {
                    r.extents
                        .iter()
                        .map(|e| format!("{}+{}", e.offset, e.length))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_else(|| "suppressed by overlap suppression".to_string());
            eprintln!(
                "carve:   {} reassembled in {} validations  extents [{}]",
                sc.id, sc.validations, ext
            );
        }
    }
    eprintln!(
        "carve: wall clock {:.3} s over {} bytes",
        elapsed.as_secs_f64(),
        image.len()
    );
    if let Some(g) = &gt {
        eprintln!(
            "carve: SHA-256 cross-check against {} — {} of {} planted files recovered byte-exact",
            g.manifest_label, g.recovered_exact, g.planted_total
        );
        eprintln!(
            "carve: demonstrated recall ({}) {} of {} planted. \
             Reachability CEILING, a different number: contiguous {}, needs bifragment {}, \
             unreachable by construction {}.",
            if cli.opts.reassemble {
                "contiguous engine + two-fragment reassembly"
            } else {
                "contiguous engine"
            },
            g.recovered_exact,
            g.planted_total,
            g.contiguous,
            g.bifragment,
            g.unreachable.len()
        );
        if g.false_positives > 0 {
            eprintln!(
                "carve: WARNING {} admitted record(s) sit at a planted file's offset but do not \
                 hash to it — a recovery whose bytes are not the planted bytes",
                g.false_positives
            );
        }
    }

    if admitted == 0 {
        eprintln!(
            "carve: no candidate reached the gate. exit {EXIT_NO_CANDIDATES} — a complete report, \
             not an error."
        );
        return ExitCode::from(EXIT_NO_CANDIDATES);
    }
    ExitCode::from(EXIT_ADMITTED)
}

// ===========================================================================
// Ground truth off the fixture manifest
// ===========================================================================

/// The manifest's own `kind` label to a carver `Kind`. DOCX is a ZIP container
/// and carves as `Kind::Zip`; TXT has no signature and no row in the table.
fn kind_of(s: &str) -> Option<Kind> {
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

struct PlantedFile {
    path: String,
    manifest_kind: String,
    expected_recoverable: String,
    sha256: String,
    first_offset: u64,
}

/// One record's tie to ground truth: (path, manifest kind, expected_recoverable,
/// sha256_matches).
type Match = (String, String, String, bool);

struct GroundTruth {
    manifest_label: String,
    manifest_sha256: String,
    planted_total: u64,
    contiguous: u64,
    bifragment: u64,
    unreachable: Vec<(String, String, String)>,
    /// Per record index into `report.records`, the manifest entry it matched.
    matches: Vec<Option<Match>>,
    /// Planted files an ADMITTED record reproduced byte for byte.
    recovered_exact: u64,
    /// Records matched to a planted file by offset whose bytes are NOT that
    /// file's. A recovery wearing a success label; counted so it cannot hide
    /// behind a row count.
    false_positives: u64,
    sha256_matches_planted: u64,
}

impl GroundTruth {
    fn load(path: &Path, bytes: &[u8], report: &CarveReport) -> GroundTruth {
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
fn f(x: f64) -> String {
    let s = format!("{x:.6}");
    if s == "-0.000000" {
        "0.000000".to_string()
    } else {
        s
    }
}

fn esc(s: &str) -> String {
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

struct W {
    b: String,
}

impl W {
    fn new() -> W {
        W {
            b: String::with_capacity(1 << 16),
        }
    }
    fn raw(&mut self, s: &str) -> &mut W {
        self.b.push_str(s);
        self
    }
    fn ind(&mut self, n: usize) -> &mut W {
        for _ in 0..n {
            self.b.push(' ');
        }
        self
    }
    fn line(&mut self, n: usize, s: &str) -> &mut W {
        self.ind(n).raw(s).raw("\n")
    }
    fn tail(comma: bool) -> &'static str {
        if comma {
            ","
        } else {
            ""
        }
    }
    fn kv_s(&mut self, n: usize, k: &str, v: &str, comma: bool) -> &mut W {
        self.ind(n);
        let t = W::tail(comma);
        self.b.push_str(&format!("\"{k}\": \"{}\"{t}\n", esc(v)));
        self
    }
    fn kv_os(&mut self, n: usize, k: &str, v: Option<&str>, comma: bool) -> &mut W {
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
    fn kv_u(&mut self, n: usize, k: &str, v: u64, comma: bool) -> &mut W {
        self.ind(n);
        let t = W::tail(comma);
        self.b.push_str(&format!("\"{k}\": {v}{t}\n"));
        self
    }
    fn kv_f(&mut self, n: usize, k: &str, v: f64, comma: bool) -> &mut W {
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
    fn kv_of(&mut self, n: usize, k: &str, v: Option<f64>, comma: bool) -> &mut W {
        match v {
            Some(x) => self.kv_f(n, k, x, comma),
            None => {
                self.ind(n);
                self.raw(&format!("\"{k}\": null{}\n", W::tail(comma)));
                self
            }
        }
    }

    fn kv_b(&mut self, n: usize, k: &str, v: bool, comma: bool) -> &mut W {
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
fn stats(v: &[f64]) -> (usize, f64, f64, f64) {
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
fn emit(
    cli: &Cli,
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
    w.kv_s(4, "command", &reproducing_command(cli), true);
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
    w.kv_s(4, "phase", &cli.phase, true);
    w.kv_s(4, "image_path", image_label, true);
    w.kv_u(4, "image_bytes", image.len() as u64, true);
    w.kv_s(4, "image_sha256", image_sha, true);
    w.kv_s(4, "read_mode", &cli.read_mode, true);
    w.kv_os(4, "device", cli.device.as_deref(), true);
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
fn reproducing_command(cli: &Cli) -> String {
    let mut parts = vec!["carve".to_string()];
    parts.push(format!("--phase {}", cli.phase));
    if let Some(m) = &cli.manifest {
        parts.push(format!("--manifest {}", relative_label(m, None)));
    }
    parts.push(format!("--min-confidence {:.4}", cli.opts.min_confidence));
    if let Some(n) = cli.opts.residue_window {
        parts.push(format!("--residue-window {n}"));
    }
    // Reassembly is spelled out either way. The pre-wipe and post-wipe carve
    // must be shown to have run with identical parameters, and a default nobody
    // wrote down cannot be shown to have been held constant.
    if cli.opts.reassemble {
        parts.push("--reassemble".to_string());
        parts.push(format!("--cluster-bytes {}", cli.opts.cluster_bytes));
        parts.push(format!("--max-gap-clusters {}", cli.opts.max_gap_clusters));
    } else {
        parts.push("--no-reassemble".to_string());
    }
    if !cli.opts.dedup {
        parts.push("--no-dedup".to_string());
    }
    if !cli.opts.report_rejected {
        parts.push("--no-rejected".to_string());
    }
    if cli.read_mode != "file" {
        parts.push(format!("--read-mode {}", cli.read_mode));
    }
    if let Some(d) = &cli.device {
        parts.push(format!("--device {d}"));
    }
    if cli.timing {
        parts.push("--timing".to_string());
    }
    parts.push(
        cli.image_path_label
            .as_ref()
            .map(|s| format!("--image-path {s}"))
            .unwrap_or_default(),
    );
    parts.retain(|s| !s.is_empty());
    parts.push(relative_label(&cli.image, cli.image_path_label.as_deref()));
    parts.join(" ")
}

// ===========================================================================
// UTC clock, without a dependency
// ===========================================================================

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's
/// `civil_from_days`, which is exact for the whole proleptic Gregorian range.
fn civil_from_days(z: i64) -> (i64, u64, u64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let sod = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

// ===========================================================================
// The minimal JSON reader for the fixture manifest. CLAUDE.md forbids serde;
// this is the same reader the crate's integration tests and
// examples/gen_sample_output.rs carry, and it reads one file this project
// wrote itself.
// ===========================================================================

#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn parse(bytes: &[u8]) -> Json {
        P { b: bytes, i: 0 }.value()
    }
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(v) => v,
            _ => &[],
        }
    }
    fn s(&self) -> &str {
        match self {
            Json::Str(s) => s,
            _ => "",
        }
    }
    fn u(&self) -> u64 {
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
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Json {
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

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelwipe_carve::carve::{DEFAULT_CLUSTER_BYTES, DEFAULT_MAX_GAP_CLUSTERS};
    use sentinelwipe_carve::confidence::MIN_CONFIDENCE;

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn run(s: &[&str]) -> Cli {
        match parse(&argv(s)) {
            Parsed::Run(c) => *c,
            Parsed::Print(_) => panic!("expected a run, got --help/--version"),
            Parsed::Usage(m) => panic!("expected a run, got usage error: {m}"),
        }
    }

    fn usage(s: &[&str]) -> String {
        match parse(&argv(s)) {
            Parsed::Usage(m) => m,
            _ => panic!("expected a usage error from {s:?}"),
        }
    }

    #[test]
    fn the_default_gate_is_the_crate_const() {
        let c = run(&["img"]);
        assert_eq!(c.opts.min_confidence, MIN_CONFIDENCE);
        assert!(c.opts.dedup);
        assert!(c.opts.report_rejected);
        assert_eq!(c.opts.residue_window, None);
        assert_eq!(c.phase, "standalone");
        assert_eq!(c.read_mode, "file");
        assert!(!c.timing, "timing is off by default so two runs agree");
        assert!(
            !c.opts.reassemble,
            "reassembly is off by default; the published numbers were measured with it off"
        );
        assert_eq!(c.opts.cluster_bytes, DEFAULT_CLUSTER_BYTES);
        assert_eq!(c.opts.max_gap_clusters, DEFAULT_MAX_GAP_CLUSTERS);
    }

    #[test]
    fn every_engine_parameter_is_reachable_from_the_command_line() {
        let c = run(&[
            "--phase",
            "post-wipe",
            "--min-confidence",
            "0.9",
            "--residue-window",
            "4096",
            "--reassemble",
            "--cluster-bytes",
            "4096",
            "--max-gap-clusters",
            "64",
            "--no-dedup",
            "--no-rejected",
            "--timing",
            "out/fixture.img",
        ]);
        assert_eq!(c.phase, "post-wipe");
        assert_eq!(c.opts.min_confidence, 0.9);
        assert_eq!(c.opts.residue_window, Some(4096));
        assert!(c.opts.reassemble);
        assert_eq!(c.opts.cluster_bytes, 4096);
        assert_eq!(c.opts.max_gap_clusters, 64);
        assert!(!c.opts.dedup);
        assert!(!c.opts.report_rejected);
        assert!(c.timing);
        assert_eq!(c.image, PathBuf::from("out/fixture.img"));
    }

    #[test]
    fn the_reassembly_state_is_spellable_in_both_directions() {
        // A default nobody can write down cannot be shown to have been held
        // constant across the wipe, so BOTH states have a flag.
        assert!(run(&["--reassemble", "i"]).opts.reassemble);
        assert!(!run(&["--no-reassemble", "i"]).opts.reassemble);
        assert!(!run(&["--reassemble", "--no-reassemble", "i"]).opts.reassemble);
        assert!(run(&["--no-reassemble", "--reassemble", "i"]).opts.reassemble);
    }

    #[test]
    fn a_reassembling_pre_and_post_wipe_pair_still_differs_in_exactly_one_flag() {
        let args = ["--reassemble", "--cluster-bytes", "2048", "--max-gap-clusters", "128"];
        let pre = run(&[&["--phase", "pre-wipe"][..], &args[..], &["out/fixture.img"][..]].concat());
        let post =
            run(&[&["--phase", "post-wipe"][..], &args[..], &["out/fixture.img"][..]].concat());
        assert_eq!(pre.opts, post.opts, "the engine parameters must be identical");
        assert_ne!(pre.phase, post.phase);
        // And the reproducing command republishes the geometry on both sides.
        for c in [&pre, &post] {
            let cmd = reproducing_command(c);
            assert!(cmd.contains("--reassemble"), "{cmd}");
            assert!(cmd.contains("--cluster-bytes 2048"), "{cmd}");
            assert!(cmd.contains("--max-gap-clusters 128"), "{cmd}");
        }
    }

    #[test]
    fn the_two_demo_invocations_differ_in_exactly_one_flag() {
        // The product claim: same carver, same parameters, before and after.
        let pre = run(&["--phase", "pre-wipe", "-o", "pre.json", "out/fixture.img"]);
        let post = run(&["--phase", "post-wipe", "-o", "post.json", "out/fixture.img"]);
        assert_eq!(pre.opts, post.opts, "the engine parameters must be identical");
        assert_eq!(pre.image, post.image);
        assert_ne!(pre.phase, post.phase);
    }

    #[test]
    fn bad_arguments_are_usage_errors_and_not_silent_defaults() {
        assert!(usage(&[]).contains("no image path"));
        assert!(usage(&["--phase", "midwipe", "i"]).contains("--phase"));
        assert!(usage(&["--min-confidence", "banana", "i"]).contains("not a number"));
        assert!(usage(&["--min-confidence", "1.5", "i"]).contains("[0,1]"));
        assert!(usage(&["--residue-window", "0", "i"]).contains("at least 1"));
        assert!(usage(&["--cluster-bytes", "0", "i"]).contains("at least 1 byte"));
        assert!(usage(&["--cluster-bytes", "half", "i"]).contains("not a byte count"));
        assert!(usage(&["--max-gap-clusters", "0", "i"]).contains("at least 1"));
        assert!(usage(&["--max-gap-clusters", "lots", "i"]).contains("not a cluster count"));
        assert!(usage(&["--cluster-bytes", "18446744073709551615", "--max-gap-clusters",
                        "18446744073709551615", "i"])
            .contains("overflows"));
        assert!(usage(&["--nope", "i"]).contains("unknown option"));
        assert!(usage(&["--min-confidence"]).contains("needs a value"));
        assert!(usage(&["a", "b"]).contains("more than one image"));
        assert!(usage(&["--device", "/dev/disk9", "i"]).contains("--read-mode device"));
        assert!(usage(&["--read-mode", "device", "i"]).contains("--device"));
    }

    #[test]
    fn help_and_version_go_to_the_print_path_not_to_a_run() {
        assert!(matches!(parse(&argv(&["--help"])), Parsed::Print(_)));
        assert!(matches!(parse(&argv(&["-h"])), Parsed::Print(_)));
        assert!(matches!(parse(&argv(&["-V"])), Parsed::Print(_)));
    }

    #[test]
    fn help_documents_every_flag_that_changes_what_the_engine_does() {
        for flag in [
            "--min-confidence",
            "--residue-window",
            "--reassemble",
            "--no-reassemble",
            "--cluster-bytes",
            "--max-gap-clusters",
            "--no-dedup",
            "--no-rejected",
        ] {
            assert!(HELP.contains(flag), "--help does not document {flag}");
        }
    }

    #[test]
    fn help_documents_every_exit_code() {
        for line in [
            "0  at least one candidate was admitted",
            "1  no candidate was admitted",
            "2  usage error",
            "3  the image could not be read",
            "4  internal error",
        ] {
            assert!(HELP.contains(line), "--help does not document {line:?}");
        }
    }

    #[test]
    fn an_absolute_path_never_reaches_the_report() {
        let label = relative_label(Path::new("/private/var/tmp/somewhere/fixture.img"), None);
        assert!(!label.starts_with('/'), "got {label:?}");
        assert_eq!(label, "fixture.img");
        assert_eq!(
            relative_label(Path::new("/a/b/c.img"), Some("out/fixture.img")),
            "out/fixture.img"
        );
        assert_eq!(
            relative_label(Path::new("out/fixture.img"), None),
            "out/fixture.img"
        );
    }

    #[test]
    fn floats_are_six_places_and_never_negative_zero() {
        assert_eq!(f(0.9), "0.900000");
        assert_eq!(f(STRUCTURAL_BREACH_POINT), "0.285714");
        assert_eq!(f(-0.0), "0.000000");
        assert_eq!(f(1.0), "1.000000");
    }

    #[test]
    fn an_empty_population_reports_zero_and_never_infinity() {
        let (n, mn, mx, me) = stats(&[]);
        assert_eq!((n, mn, mx, me), (0, 0.0, 0.0, 0.0));
        for v in [mn, mx, me] {
            assert!(v.is_finite(), "the schema forbids Infinity and NaN");
        }
    }

    #[test]
    fn the_json_escaper_survives_a_validator_detail_string() {
        // Validator details are quoted verbatim into the report and can carry
        // quotes and backslashes from a filename.
        let s = esc("gzip: 28-byte header naming \"carve\\session.log\"");
        assert_eq!(
            s,
            "gzip: 28-byte header naming \\\"carve\\\\session.log\\\""
        );
        assert_eq!(esc("a\nb\tc"), "a\\nb\\tc");
        assert_eq!(esc("\u{1}"), "\\u0001");
    }

    #[test]
    fn the_utc_clock_agrees_with_known_epochs() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1)); // a leap year start
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn the_minimal_json_reader_reads_a_manifest_shaped_document() {
        let src = br#"{"files":[{"path":"/a.jpg","kind":"JPEG","sha256":"ab","extents":[{"byte_offset":4096,"byte_length":10}],"expected_recoverable":"signature-only"}],"n":40}"#;
        let j = Json::parse(src);
        assert_eq!(j.get("n").unwrap().u(), 40);
        let f0 = &j.get("files").unwrap().arr()[0];
        assert_eq!(f0.get("path").unwrap().s(), "/a.jpg");
        assert_eq!(
            f0.get("extents").unwrap().arr()[0]
                .get("byte_offset")
                .unwrap()
                .u(),
            4096
        );
    }

    #[test]
    fn a_reproducing_command_spells_out_every_non_default_option() {
        let c = run(&[
            "--phase",
            "post-wipe",
            "--residue-window",
            "8192",
            "--no-dedup",
            "out/fixture.img",
        ]);
        let cmd = reproducing_command(&c);
        assert!(cmd.contains("--phase post-wipe"), "{cmd}");
        assert!(cmd.contains("--residue-window 8192"), "{cmd}");
        assert!(cmd.contains("--no-dedup"), "{cmd}");
        assert!(cmd.contains("--min-confidence 0.7500"), "{cmd}");
        assert!(
            cmd.contains("--no-reassemble"),
            "the default state of reassembly is not on the reproducing command: {cmd}"
        );
        assert!(cmd.ends_with("out/fixture.img"), "{cmd}");
    }

    #[test]
    fn the_report_is_one_json_document_with_all_ten_required_keys() {
        // A tiny image with a real object in it, carved through the shipped
        // engine and emitted through the shipped writer.
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = vec![0u8; 512];
        let mut g = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        let n = payload.len() as u16;
        g.push(0x01);
        g.extend_from_slice(&n.to_le_bytes());
        g.extend_from_slice(&(!n).to_le_bytes());
        g.extend_from_slice(&payload);
        g.extend_from_slice(&sentinelwipe_carve::structure::crc32(&payload).to_le_bytes());
        g.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        img.extend_from_slice(&g);
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x33u8; 4096]);

        let cli = run(&["test.img"]);
        let rep = carve(&img, &cli.opts);
        let json = emit(&cli, &img, "test.img", "00", &rep, None, "1970-01-01T00:00:00Z", 0);

        let doc = Json::parse(json.as_bytes());
        for key in [
            "schema",
            "provenance",
            "run",
            "policy",
            "kind_policy",
            "counts",
            "score_distribution",
            "margin",
            "ground_truth",
            "candidates",
        ] {
            assert!(doc.get(key).is_some(), "the report has no {key:?} block");
        }
        assert_eq!(doc.get("schema").unwrap().s(), SCHEMA);
        assert_eq!(doc.get("ground_truth").unwrap(), &Json::Null);
        // Rust prints a non-finite f64 as `inf`/`-inf`/`NaN`, none of which any
        // JSON parser accepts. Matched against the serialized VALUE tokens, so
        // the prose in provenance.notes that names the hazard is not a hit.
        for bad in [" inf", " -inf", " NaN"] {
            assert!(!json.contains(bad), "a non-finite number reached the report: {bad:?}");
        }
        assert!(json.ends_with("}\n"));

        // counts add up, and admission is the one published comparison
        let counts = doc.get("counts").unwrap();
        let recs = doc.get("candidates").unwrap().arr();
        assert_eq!(counts.get("records").unwrap().u(), recs.len() as u64);
        assert_eq!(
            counts.get("admitted").unwrap().u() + counts.get("rejected").unwrap().u(),
            recs.len() as u64
        );
        assert_eq!(
            counts
                .get("by_assembly")
                .unwrap()
                .get("reassembled")
                .unwrap()
                .u(),
            0,
            "--reassemble was not given, so nothing may be reported as reassembled"
        );
        assert!(recs.iter().any(|r| matches!(
            r.get("admitted"),
            Some(Json::Bool(true))
        )));
    }

    /// The smallest GZIP this project builds by hand, same construction as the
    /// engine's own tests.
    fn tiny_gzip(payload: &[u8]) -> Vec<u8> {
        let mut g = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        let n = payload.len() as u16;
        g.push(0x01);
        g.extend_from_slice(&n.to_le_bytes());
        g.extend_from_slice(&(!n).to_le_bytes());
        g.extend_from_slice(payload);
        g.extend_from_slice(&sentinelwipe_carve::structure::crc32(payload).to_le_bytes());
        g.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        g
    }

    #[test]
    fn a_reassembled_record_emits_two_extents_and_the_report_says_where_the_cost_went() {
        const C: usize = 512;
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);

        // Two extents on the cluster grid with a three-cluster gap of filler.
        let mut img = vec![0u8; C];
        img.extend_from_slice(&obj[..2 * C]);
        img.extend((0..3 * C).map(|i| ((i as u32 * 37) % 251) as u8 | 1));
        img.extend_from_slice(&obj[2 * C..]);
        img.extend_from_slice(&vec![0u8; C]);

        let cli = run(&[
            "--reassemble",
            "--cluster-bytes",
            "512",
            "--max-gap-clusters",
            "8",
            "test.img",
        ]);
        let rep = carve(&img, &cli.opts);
        assert_eq!(rep.reassembly.solved, 1, "the engine did not reassemble the object");
        let json = emit(&cli, &img, "test.img", "00", &rep, None, "1970-01-01T00:00:00Z", 0);
        let doc = Json::parse(json.as_bytes());

        assert_eq!(
            doc.get("counts")
                .unwrap()
                .get("by_assembly")
                .unwrap()
                .get("reassembled")
                .unwrap()
                .u(),
            1
        );

        let rec = doc
            .get("candidates")
            .unwrap()
            .arr()
            .iter()
            .find(|r| r.get("assembly").map(|a| a.s()) == Some("reassembled"))
            .expect("no record carries assembly \"reassembled\"");
        let ext = rec.get("extents").unwrap().arr();
        assert_eq!(ext.len(), 2, "a reassembled record must publish both runs");
        assert_eq!(
            ext[0].get("offset").unwrap().u(),
            rec.get("offset").unwrap().u(),
            "schema 5: offset is extents[0].offset"
        );
        let total: u64 = ext.iter().map(|e| e.get("length").unwrap().u()).sum();
        assert_eq!(
            total,
            rec.get("length").unwrap().u(),
            "schema 5: length is the sum of the extents"
        );
        assert_eq!(total, obj.len() as u64);
        assert!(
            ext[0].get("offset").unwrap().u() + ext[0].get("length").unwrap().u()
                < ext[1].get("offset").unwrap().u(),
            "the two extents are not separated by a gap"
        );

        // The cost is NOT in the schema, and the report says so rather than
        // leaving a reader to assume there was none.
        assert!(
            !json.contains("\"validations\""),
            "a validation count reached the frozen schema"
        );
        let notes: Vec<String> = doc
            .get("provenance")
            .unwrap()
            .get("notes")
            .unwrap()
            .arr()
            .iter()
            .map(|n| n.s().to_string())
            .collect();
        assert!(
            notes.iter().any(|n| n.contains("stderr")),
            "no note tells a reader of the JSON where the validation count went"
        );
        assert!(
            notes.iter().any(|n| n.contains("REASSEMBLY WAS ON")),
            "the report does not state that reassembly ran"
        );
    }

    #[test]
    fn an_empty_image_still_emits_a_complete_report() {
        // The post-wipe empty-table state: a valid report, not an error.
        let cli = run(&["wiped.img"]);
        let rep = carve(&[], &cli.opts);
        let json = emit(&cli, &[], "wiped.img", "00", &rep, None, "1970-01-01T00:00:00Z", 0);
        let doc = Json::parse(json.as_bytes());
        assert_eq!(doc.get("counts").unwrap().get("records").unwrap().u(), 0);
        let sd = doc.get("score_distribution").unwrap();
        for pop in ["admitted", "rejected"] {
            let p = sd.get(pop).unwrap();
            assert_eq!(p.get("n").unwrap().u(), 0);
            for k in ["min", "max", "mean"] {
                assert!(matches!(p.get(k), Some(Json::Num(_))));
            }
        }
        // Rust prints a non-finite f64 as `inf`/`-inf`/`NaN`, none of which any
        // JSON parser accepts. Matched against the serialized VALUE tokens, so
        // the prose in provenance.notes that names the hazard is not a hit.
        for bad in [" inf", " -inf", " NaN"] {
            assert!(!json.contains(bad), "a non-finite number reached the report: {bad:?}");
        }
        assert!(doc.get("candidates").unwrap().arr().is_empty());
    }
}
