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
use std::path::PathBuf;
use std::process::ExitCode;

use sentinelwipe_carve::carve::{
    carve, CarveOpts, Sha256,
};
use sentinelwipe_carve::report::{emit, relative_label, EmitMeta, GroundTruth};

/// The schema this binary emits. Bumping it is a schema change with the ceremony
/// `docs/output_schema.md` §10 describes.

/// Every kind the carver knows, in table order. `kind_policy` publishes all
/// seven whether or not a record of that kind appears.


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
/// Does this path name a location from the root of a filesystem, rather than a
/// location relative to the working directory?
///
/// This is deliberately **not** `Path::is_absolute`. On Windows that predicate
/// requires a drive prefix, so `/private/var/tmp/fixture.img` — a perfectly
/// ordinary absolute path on the machine the fixture was built on — reports
/// `is_relative() == true` and would be copied into `run.image_path` whole. The
/// report would then carry another laptop's directory layout, which is the one
/// thing `relative_label` exists to prevent. Testing for a root component *or* a
/// prefix catches POSIX-style and Windows-style roots on either platform.

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

    let meta = EmitMeta {
        opts: &cli.opts,
        phase: &cli.phase,
        read_mode: &cli.read_mode,
        device: cli.device.as_deref(),
        timing: cli.timing,
        command: &reproducing_command(&cli),
    };
    let json = emit(
        &meta,
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
        // A POSIX-style root. On Windows this has a root and no drive prefix, so
        // `Path::is_absolute` is false for it and an earlier version of this
        // function copied it into the report verbatim.
        let label = relative_label(Path::new("/private/var/tmp/somewhere/fixture.img"), None);
        assert!(!label.starts_with('/'), "got {label:?}");
        assert_eq!(label, "fixture.img");

        // A Windows-style root. Only asserted where the path parser understands
        // it: on Unix `C:\a\b.img` is one ordinary relative filename.
        #[cfg(windows)]
        {
            let win = relative_label(Path::new(r"D:\somewhere\else\fixture.img"), None);
            assert_eq!(win, "fixture.img", "a drive-rooted path must not reach the report");
            let unc = relative_label(Path::new(r"\\server\share\fixture.img"), None);
            assert_eq!(unc, "fixture.img", "a UNC path must not reach the report");
        }
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
        let meta = EmitMeta {
            opts: &cli.opts,
            phase: &cli.phase,
            read_mode: &cli.read_mode,
            device: cli.device.as_deref(),
            timing: cli.timing,
            command: "carve test.img",
        };
        let json = emit(&meta, &img, "test.img", "00", &rep, None, "1970-01-01T00:00:00Z", 0);

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
        let meta = EmitMeta {
            opts: &cli.opts,
            phase: &cli.phase,
            read_mode: &cli.read_mode,
            device: cli.device.as_deref(),
            timing: cli.timing,
            command: "carve test.img",
        };
        let json = emit(&meta, &img, "test.img", "00", &rep, None, "1970-01-01T00:00:00Z", 0);
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
        let meta = EmitMeta {
            opts: &cli.opts,
            phase: &cli.phase,
            read_mode: &cli.read_mode,
            device: cli.device.as_deref(),
            timing: cli.timing,
            command: "carve wiped.img",
        };
        let json = emit(&meta, &[], "wiped.img", "00", &rep, None, "1970-01-01T00:00:00Z", 0);
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
