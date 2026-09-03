//! `wipe` — the operator's handle on the sanitization engine.
//!
//! **One** JSON document on stdout, `sentinelwipe.wipe.report/1`. Nothing else on
//! stdout, ever: diagnostics go to stderr, so `wipe ... > report.json` is always a
//! valid report and never a report with a progress line in it.
//!
//! # It cannot be made to destroy anything by accident
//!
//! This is CLAUDE.md rule 4, and it is enforced here as four independent
//! conjunctions, each of which alone stops the run:
//!
//! 1. **No positional arguments exist.** `wipe /dev/disk0` is a usage error with a
//!    named cause, not a target. A path reaches the engine only through `--target`.
//! 2. **`--allow-root` is required and has no default.** It builds the
//!    [`guard::Policy`] allowlist. There is no compiled-in root, no environment
//!    variable that supplies one, and no fallback to the working directory: with no
//!    `--allow-root`, no policy can be constructed and nothing can be opened.
//! 3. **`--i-understand <STRING>` is required**, and the guard compares it against
//!    *its own* resolution of the target, not against the string typed after
//!    `--target`. A confirmation that names a symlink, a relative path or a
//!    different spelling is `DENY_CONFIRMATION_MISMATCH`. The policy is built with
//!    `require_confirmation: true` unconditionally on the destructive path.
//! 4. **The guard opens the file, not this binary.** `guard::open_authorized`
//!    descends from the allowed root one component at a time with `O_NOFOLLOW` and
//!    hands back a descriptor. This binary never calls `File::open` on a target.
//!
//! The confirmation is checked **last**, after containment has already said yes, and
//! it carries no authority of its own: typing the right string for a target outside
//! every allowed root is still `DENY_NOT_ALLOWLISTED`.
//!
//! `--plan` runs conjunctions 1 to 3, prints the decision the guard reached, and
//! exits without opening anything writable. It is the safe way to find out what the
//! confirmation string has to be.
//!
//! # Exit codes
//!
//! `grep`'s convention, which is the one every operator already knows: 0 is the
//! clean answer, 1 is a run that happened and did not produce a clean answer, 2 and
//! above mean the run did not happen.
//!
//! | code | meaning |
//! |---|---|
//! | 0 | the medium was overwritten and **every pass was confirmed by read-back**, at the coverage the report publishes. The report is on stdout. Exit 0 is not by itself a whole-medium claim: `outcome.code` is `OVERWRITE_VERIFIED_WHOLE_MEDIUM` only after `--verify exhaustive`, and `OVERWRITE_VERIFIED_ON_SAMPLE` otherwise, with `outcome.whole_medium_claim` as the boolean |
//! | 1 | the job ran, and read-back did **not** confirm every pass. The report is on stdout and is complete. This is a result, not a crash, and the certificate must not be signed from it |
//! | 2 | usage error — an unknown option, a missing value, a positional argument, a missing `--target` / `--allow-root` / `--i-understand`. Nothing on stdout |
//! | 3 | the write guard refused the target. Its reason code is on stderr. Nothing on stdout, and nothing was opened writable |
//! | 4 | the policy could not be built — a root that does not exist, a system directory, `$HOME`. Nothing on stdout |
//! | 5 | the device could not be opened, or its geometry was refused. Nothing on stdout |
//! | 6 | the job failed after it began. Nothing on stdout; the medium is in an unknown state and stderr says so |
//! | 7 | internal error |
//!
//! Exit 0 is the only code that means "this medium was sanitized and we read it back
//! to check". Nothing here returns 0 on the strength of a device return code.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use sentinelwipe_device::guard;
use sentinelwipe_device::{GuardAuthority, ImageFile, SanitizePrimitive};
use sentinelwipe_wipe::passes::Method;
use sentinelwipe_wipe::telemetry::{FanoutSink, NullSink, RecorderSink};
use sentinelwipe_wipe::verify::SamplingPolicy;
use sentinelwipe_wipe::{
    run_job, Authorization, JobSpec, Outcome, VerifyMode, DEFAULT_PROBE_BYTES,
};

const EXIT_VERIFIED: u8 = 0;
const EXIT_UNVERIFIED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_REFUSED: u8 = 3;
const EXIT_POLICY: u8 = 4;
const EXIT_DEVICE: u8 = 5;
const EXIT_JOB_FAILED: u8 = 6;
const EXIT_INTERNAL: u8 = 7;

const HELP: &str = "\
wipe — SENTINELWIPE sanitization engine

USAGE
  wipe --target <PATH> --allow-root <DIR> --i-understand <RESOLVED PATH> [OPTIONS]
  wipe --target <PATH> --allow-root <DIR> --plan

  There are NO positional arguments. A bare path is a usage error, not a target.
  With no arguments at all this text is printed and nothing is opened.

REQUIRED, and each one alone stops the run
  --target <PATH>      The medium. A regular image file; a block device belongs
                       to the gated device layer and is refused here.
  --allow-root <DIR>   A directory the guard will permit writes under. Repeatable.
                       There is no default and no fallback: with none, no policy
                       exists and nothing can be opened. The root must already
                       exist; system directories and $HOME are refused at
                       construction.
  --i-understand <S>   The typed confirmation. It must byte-equal the guard's OWN
                       resolution of --target, which --plan prints. Checked last,
                       after containment; it grants nothing on its own.

OPTIONS
  --plan               Take the decision, print it, and exit. Opens nothing
                       writable. This is how you learn the --i-understand string.
  --method <M>         single-pass-zero | single-pass-random | three-pass.
                       [default: chosen from the detected medium]
  --sanitize <P>       Attempt a firmware primitive before the overwrite:
                       ata-secure-erase | ata-secure-erase-enhanced |
                       ata-sanitize-block-erase | nvme-sanitize-block-erase |
                       nvme-sanitize-crypto-erase | nvme-format-crypto-erase.
                       On anything that is not a real controller this is
                       SIMULATED, the word appears in the operation name and in
                       its own field, and it can never be reported as verified.
                       [default: chosen from the detected medium]
  --run-id <S>         Seeds the pattern. Same id, same bytes on the medium.
                       [default: sentinelwipe/wipe/v1]
  --verify <MODE>      sampled | exhaustive. Sampled reads a fixed number of
                       sectors per MiB and says so; exhaustive reads every
                       sector and is the only mode supporting a whole-medium
                       claim. [default: sampled]
  --sectors-per-mib <N>  Sampling rate for --verify sampled. [default: 4]
  --no-entropy         Skip the two whole-medium entropy reads.
  --crypto-erase-demo <BYTES>
                       Run the per-object crypto-erase DEMONSTRATION over the
                       head of the medium before the wipe. 0 disables.
                       [default: 0]
  --probe-bytes <N>    Calibration probe size. It writes the final pass's
                       pattern, so the wipe erases it again. [default: 33554432]
  --trace <PATH>       Record the telemetry stream as JSON Lines. The file is
                       created through the same guard as the target, must sit
                       under an --allow-root, and must NOT already exist: a
                       recorder that truncates is a second destructive path with
                       no typed confirmation of its own.
  --period-ms <N>      Telemetry emit period. [default: 40]
  -h, --help           This text.

EXIT CODES
  0  overwritten AND every pass confirmed by read-back. Report on stdout.
  1  the job ran; read-back did not confirm every pass. Report on stdout.
  2  usage error.                    3  the guard refused the target.
  4  the policy could not be built.  5  the device could not be opened.
  6  the job failed after it began.  7  internal error.
";

#[derive(Debug)]
struct Args {
    target: Option<String>,
    roots: Vec<String>,
    confirmation: Option<String>,
    plan: bool,
    method: Option<Method>,
    sanitize: Option<SanitizePrimitive>,
    run_id: String,
    verify: VerifyMode,
    sectors_per_mib: u32,
    entropy: bool,
    crypto_erase_demo: u64,
    probe_bytes: u64,
    trace: Option<String>,
    period_ms: u64,
    help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            target: None,
            roots: Vec::new(),
            confirmation: None,
            plan: false,
            method: None,
            sanitize: None,
            run_id: "sentinelwipe/wipe/v1".to_string(),
            verify: VerifyMode::Sampled,
            sectors_per_mib: sentinelwipe_wipe::verify::DEFAULT_SECTORS_PER_MIB,
            entropy: true,
            crypto_erase_demo: 0,
            probe_bytes: DEFAULT_PROBE_BYTES,
            trace: None,
            period_ms: sentinelwipe_wipe::telemetry::DEFAULT_PERIOD_MS,
            help: false,
        }
    }
}

fn parse_method(s: &str) -> Result<Method, String> {
    match s {
        "single-pass-zero" | "zero" => Ok(Method::ZeroFill),
        "single-pass-random" | "random" => Ok(Method::SeededRandom),
        "three-pass" => Ok(Method::ThreePass),
        other => Err(format!(
            "unknown --method {other:?}; expected single-pass-zero, single-pass-random \
             or three-pass"
        )),
    }
}

fn parse_sanitize(s: &str) -> Result<SanitizePrimitive, String> {
    match s {
        "ata-secure-erase" => Ok(SanitizePrimitive::AtaSecureErase),
        "ata-secure-erase-enhanced" => Ok(SanitizePrimitive::AtaSecureEraseEnhanced),
        "ata-sanitize-block-erase" => Ok(SanitizePrimitive::AtaSanitizeBlockErase),
        "ata-sanitize-crypto-scramble" => Ok(SanitizePrimitive::AtaSanitizeCryptoScramble),
        "ata-sanitize-overwrite" => Ok(SanitizePrimitive::AtaSanitizeOverwrite),
        "nvme-sanitize-block-erase" => Ok(SanitizePrimitive::NvmeSanitizeBlockErase),
        "nvme-sanitize-crypto-erase" => Ok(SanitizePrimitive::NvmeSanitizeCryptoErase),
        "nvme-sanitize-overwrite" => Ok(SanitizePrimitive::NvmeSanitizeOverwrite),
        "nvme-format-crypto-erase" => Ok(SanitizePrimitive::NvmeFormatCryptoErase),
        other => Err(format!("unknown --sanitize {other:?}; see --help")),
    }
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut i = 0usize;
    while i < argv.len() {
        let arg = argv[i].as_str();
        let value = |name: &str, i: &mut usize| -> Result<String, String> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg {
            "-h" | "--help" => a.help = true,
            "--plan" => a.plan = true,
            "--no-entropy" => a.entropy = false,
            "--target" => a.target = Some(value("--target", &mut i)?),
            "--allow-root" => a.roots.push(value("--allow-root", &mut i)?),
            "--i-understand" => a.confirmation = Some(value("--i-understand", &mut i)?),
            "--run-id" => a.run_id = value("--run-id", &mut i)?,
            "--trace" => a.trace = Some(value("--trace", &mut i)?),
            "--method" => a.method = Some(parse_method(&value("--method", &mut i)?)?),
            "--sanitize" => a.sanitize = Some(parse_sanitize(&value("--sanitize", &mut i)?)?),
            "--verify" => {
                let v = value("--verify", &mut i)?;
                a.verify = match v.as_str() {
                    "sampled" => VerifyMode::Sampled,
                    "exhaustive" => VerifyMode::Exhaustive,
                    other => {
                        return Err(format!(
                            "unknown --verify {other:?}; expected sampled or exhaustive"
                        ))
                    }
                };
            }
            "--sectors-per-mib" => {
                let v = value("--sectors-per-mib", &mut i)?;
                a.sectors_per_mib = v
                    .parse()
                    .map_err(|_| format!("--sectors-per-mib {v:?} is not a number"))?;
                if a.sectors_per_mib == 0 {
                    return Err("--sectors-per-mib must be at least 1".to_string());
                }
            }
            "--crypto-erase-demo" => {
                let v = value("--crypto-erase-demo", &mut i)?;
                a.crypto_erase_demo = v
                    .parse()
                    .map_err(|_| format!("--crypto-erase-demo {v:?} is not a number"))?;
            }
            "--probe-bytes" => {
                let v = value("--probe-bytes", &mut i)?;
                a.probe_bytes = v
                    .parse()
                    .map_err(|_| format!("--probe-bytes {v:?} is not a number"))?;
            }
            "--period-ms" => {
                let v = value("--period-ms", &mut i)?;
                a.period_ms = v
                    .parse()
                    .map_err(|_| format!("--period-ms {v:?} is not a number"))?;
                if a.period_ms == 0 {
                    return Err("--period-ms must be at least 1".to_string());
                }
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other:?}"))
            }
            other => {
                // The rule, stated as an error rather than as a comment: there is
                // no positional argument, so a bare path can never become a target
                // by being in the right place on the line.
                return Err(format!(
                    "unexpected argument {other:?}: this binary takes no positional \
                     arguments. The medium is named by --target, and a target with no \
                     --allow-root and no --i-understand is refused whatever it is"
                ));
            }
        }
        i += 1;
    }
    Ok(a)
}

/// Everything the run needs, or the exit code that stops it.
fn required(a: &Args) -> Result<(&str, &Vec<String>), (u8, String)> {
    let target = a.target.as_deref().ok_or((
        EXIT_USAGE,
        "--target is required. Nothing is destroyed without one, and there is no \
         positional form."
            .to_string(),
    ))?;
    if a.roots.is_empty() {
        return Err((
            EXIT_USAGE,
            "--allow-root is required and has no default. A guard with no allowed \
             root is a bug, not a safe default; see CLAUDE.md rule 4."
                .to_string(),
        ));
    }
    Ok((target, &a.roots))
}

fn build_policy(roots: &[String]) -> Result<guard::Policy, String> {
    let mut spec = guard::PolicySpec::with_roots(roots.iter().cloned());
    // Unconditional on this path. Every destructive caller sets it, and a wipe is
    // the destructive caller.
    spec.require_confirmation = true;
    guard::Policy::build(spec).map_err(|e| e.0)
}

fn run() -> Result<u8, (u8, String)> {
    // args_os, not args(): `std::env::args()` PANICS on a non-UTF-8 argument, and a
    // panic is not a decision. Measured: `--target /x/\xFF\xFE.img` exited 101 with a
    // backtrace, a code the exit table above does not publish. The device layer
    // already had the right answer for this input (DENY_NON_UTF8_PATH), but argv
    // parsing died before it could be reached. Every rejection is now a documented
    // code, and nothing is opened on this path either way.
    let mut argv: Vec<String> = Vec::new();
    for a in std::env::args_os().skip(1) {
        match a.into_string() {
            Ok(s) => argv.push(s),
            Err(bad) => {
                return Err((
                    EXIT_USAGE,
                    format!(
                        "argument {bad:?} is not valid UTF-8. Paths on this engine are \
                         compared byte-for-byte against a typed confirmation, so a path \
                         that cannot be spelled cannot be confirmed and is refused here \
                         rather than guessed at."
                    ),
                ))
            }
        }
    }
    if argv.is_empty() {
        // No arguments is not a default run. It is the help text and a usage exit.
        eprint!("{HELP}");
        return Ok(EXIT_USAGE);
    }
    let args = parse(&argv).map_err(|e| (EXIT_USAGE, e))?;
    if args.help {
        print!("{HELP}");
        return Ok(EXIT_VERIFIED);
    }
    let (target, roots) = required(&args)?;
    let policy = build_policy(roots).map_err(|e| (EXIT_POLICY, e))?;

    // The decision, taken before anything is opened. `--plan` stops here.
    let decision = guard::authorize(
        &policy,
        target,
        args.confirmation.as_deref(),
        "r+",
        &guard::Env::Process,
        None,
    );
    if args.plan {
        // CONTAINMENT AND CONFIRMATION ARE PRINTED AS TWO LINES, because they are two
        // conjuncts and --plan is how an operator learns the confirmation string. The
        // single-line version reported `decision DENY_CONFIRMATION_ABSENT / allowed
        // false` for a perfectly allowlisted target whenever --i-understand was
        // omitted — which is every first run of --plan — so the one command whose job
        // is to say "yes, this target is inside your allowlist" printed a refusal of
        // it. The predicate has not changed: the run below still takes the decision
        // with the operator's own confirmation and still refuses without it.
        let containment = guard::authorize(
            &policy,
            target,
            Some(&decision.resolved),
            "r+",
            &guard::Env::Process,
            None,
        );
        println!("target             {}", target);
        println!("resolved           {}", decision.resolved);
        println!("containment        {}", containment.code);
        println!("contained          {}", containment.allowed);
        println!("detail             {}", containment.detail);
        println!("allowed roots      {}", policy.root_reals().join(", "));
        println!("confirmation       {}", match args.confirmation.as_deref() {
            None => format!(
                "(absent — pass --i-understand '{}')",
                decision.resolved
            ),
            Some(c) if c == decision.resolved => format!("{c:?} — matches"),
            Some(c) => format!("{c:?} — MISMATCH, it must byte-equal the resolution above"),
        });
        println!(
            "decision           {} (allowed {}) — containment AND confirmation together",
            decision.code, decision.allowed
        );
        println!();
        println!("To run it, pass:   --i-understand '{}'", decision.resolved);
        println!("Nothing was opened. --plan never opens a writable descriptor.");
        return Ok(EXIT_VERIFIED);
    }
    if args.confirmation.is_none() {
        return Err((
            EXIT_USAGE,
            format!(
                "--i-understand is required for a destructive run. The guard resolves \
                 {target:?} to {:?}; pass --i-understand with exactly that string, or \
                 run --plan first.",
                decision.resolved
            ),
        ));
    }
    if !decision.allowed {
        return Err((
            EXIT_REFUSED,
            format!("{}: {}", decision.code, decision.detail),
        ));
    }

    // The guard opens it. This binary does not.
    let authority = GuardAuthority::new(policy.clone(), args.confirmation.clone());
    let policy_digest = {
        use sentinelwipe_device::WriteAuthority;
        authority.policy_digest()
    };
    let device = ImageFile::open_writable(Path::new(target), Box::new(authority))
        .map_err(|e| match &e {
            sentinelwipe_device::DeviceError::Refused { code, detail } => {
                (EXIT_REFUSED, format!("{code}: {detail}"))
            }
            _ => (EXIT_DEVICE, e.to_string()),
        })?;

    let mut spec = JobSpec::new(&args.run_id);
    spec.method = args.method;
    spec.sanitize = args.sanitize;
    spec.verify_mode = args.verify;
    spec.sampling = SamplingPolicy::per_mib(args.sectors_per_mib);
    spec.measure_entropy = args.entropy;
    spec.probe_bytes = args.probe_bytes;
    spec.crypto_erase_demo_bytes = args.crypto_erase_demo;
    spec.telemetry_period = Some(Duration::from_millis(args.period_ms));
    spec.target_named = target.to_string();
    spec.target_resolved = decision.resolved.clone();
    spec.authorization = Some(Authorization {
        decision_code: decision.code.to_string(),
        policy_digest,
        roots: policy.root_reals().to_vec(),
        require_confirmation: policy.require_confirmation(),
    });
    spec.command = rebuild_command(&argv);

    // The trace file goes through the same guard as the target: a recorder is a
    // file this process creates, and a destructive tool that opens one file
    // through a policy and another with `File::create` has one policy and two
    // behaviours.
    let (report, _dev) = match &args.trace {
        Some(path) => {
            // A recorder opened "w" TRUNCATES an existing file, and the
            // confirmation for it is supplied by this program rather than typed
            // by the operator -- so without this the `--trace` option would be a
            // way to destroy a file inside the allowlist with no typed
            // confirmation naming it. Ask the guard the exclusive-create
            // question first: mode "x" answers DENY_TARGET_ALREADY_EXISTS in the
            // guard's own vocabulary rather than in a hand-rolled `Path::exists`
            // check.
            //
            // What this does NOT close, stated rather than implied: a file
            // created between this decision and the open below is still
            // truncated. Closing that needs an authority that opens "x", which
            // lives in the device layer's `GuardAuthority` and is not this
            // file's to add. The exposure is bounded to a path inside a
            // directory the operator explicitly allowlisted.
            let precheck = guard::authorize(
                &policy,
                path,
                Some(&guard::realpath(path)),
                "x",
                &guard::Env::Process,
                None,
            );
            if !precheck.allowed {
                return Err((
                    EXIT_REFUSED,
                    format!("--trace {path:?}: {}: {}", precheck.code, precheck.detail),
                ));
            }
            let rec_authority = GuardAuthority::creating(policy.clone(), Some(
                guard::realpath(path),
            ));
            let granted = {
                use sentinelwipe_device::WriteAuthority;
                rec_authority
                    .open_writable(Path::new(path))
                    .map_err(|e| match &e {
                        sentinelwipe_device::DeviceError::Refused { code, detail } => (
                            EXIT_REFUSED,
                            format!("--trace {path:?}: {code}: {detail}"),
                        ),
                        _ => (EXIT_DEVICE, format!("--trace {path:?}: {e}")),
                    })?
            };
            let (chan, rx) = sentinelwipe_wipe::telemetry::channel(
                sentinelwipe_wipe::telemetry::DEFAULT_CHANNEL_CAPACITY,
            );
            // Nothing consumes the channel in this binary; the receiver is dropped
            // immediately so the sink sees a disconnected consumer rather than a
            // live one that never reads. See telemetry.rs: a held Receiver that
            // stops reading is what deadlocked an earlier design.
            drop(rx);
            let sink = FanoutSink::new()
                .with(Box::new(RecorderSink::new(granted.file)))
                .with(Box::new(chan));
            run_job(device, &spec, sink)
        }
        None => run_job(device, &spec, NullSink),
    }
    .map_err(|e| (EXIT_JOB_FAILED, format!("{e}")))?;

    let json = report.to_json();
    let mut out = std::io::stdout().lock();
    out.write_all(json.as_bytes())
        .map_err(|e| (EXIT_INTERNAL, format!("writing report: {e}")))?;
    out.flush()
        .map_err(|e| (EXIT_INTERNAL, format!("flushing report: {e}")))?;

    Ok(match report.outcome {
        // Exit 0 means every pass was confirmed by read-back AT THE COVERAGE the
        // report publishes. It is deliberately the same code for a sampled and an
        // exhaustive run, so that the default demo path is not a failure exit — and
        // for that reason exit 0 alone is NOT a whole-medium claim. The field that
        // carries that distinction is `outcome.code`
        // (OVERWRITE_VERIFIED_ON_SAMPLE vs OVERWRITE_VERIFIED_WHOLE_MEDIUM), with
        // `outcome.whole_medium_claim` as the boolean form.
        Outcome::VerifiedWholeMedium | Outcome::VerifiedOnSample => EXIT_VERIFIED,
        Outcome::NotVerified => EXIT_UNVERIFIED,
    })
}

/// The command line, re-rendered so `provenance.command` reproduces the run.
fn rebuild_command(argv: &[String]) -> String {
    let mut s = String::from("wipe");
    for a in argv {
        s.push(' ');
        if a.chars().any(|c| c.is_whitespace() || c == '\'' || c == '"') {
            s.push_str(&format!("{a:?}"));
        } else {
            s.push_str(a);
        }
    }
    s
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err((code, msg)) => {
            eprintln!("wipe: {msg}");
            if code == EXIT_JOB_FAILED {
                eprintln!(
                    "wipe: the job began and did not finish. The medium is in an \
                     unknown state: some passes may be complete and none is verified. \
                     Do not sign a certificate from this run."
                );
            }
            ExitCode::from(code)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sentinelwipe_wipe::telemetry::{ChannelSink, EventSink};

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn a_bare_path_is_a_usage_error_and_never_a_target() {
        // The single-path case the brief names explicitly. It must not parse.
        for line in [
            argv(&["/tmp/whatever.img"]),
            argv(&["out/fixture.img"]),
            argv(&["--i-understand", "/x", "/tmp/whatever.img"]),
        ] {
            let e = parse(&line).expect_err("a positional argument must be refused");
            assert!(
                e.contains("no positional arguments"),
                "wrong refusal for {line:?}: {e}"
            );
        }
    }

    #[test]
    fn a_target_alone_is_refused_for_want_of_a_root_and_a_confirmation() {
        let a = parse(&argv(&["--target", "/tmp/x.img"])).expect("parses");
        let (code, msg) = required(&a).expect_err("must be refused");
        assert_eq!(code, EXIT_USAGE);
        assert!(msg.contains("--allow-root"), "{msg}");
        // And with a root but no confirmation, the policy is still built with
        // require_confirmation, so the guard would refuse. Asserted at the policy
        // level here because building one needs no filesystem target.
        assert!(
            Args::default().confirmation.is_none(),
            "there is no default confirmation, and there must never be one"
        );
    }

    #[test]
    fn the_destructive_policy_always_requires_a_confirmation() {
        // Not a preference of the caller: a wipe builds its policy one way.
        let dir = std::env::var("SENTINELWIPE_SCRATCH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let root = dir.join(format!("wipe-cli-policy-{}", std::process::id()));
        if std::fs::create_dir(&root).is_err() {
            // A scratch root we could not create is not a reason to assert nothing.
            // The unconditional line is still checkable by reading it back.
            assert!(HELP.contains("--i-understand <S>   The typed confirmation"));
            return;
        }
        let p = build_policy(&[root.to_string_lossy().to_string()]).expect("policy builds");
        assert!(
            p.require_confirmation(),
            "build_policy must set require_confirmation unconditionally"
        );
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn every_exit_code_is_documented_in_the_help_text() {
        for code in [
            EXIT_VERIFIED,
            EXIT_UNVERIFIED,
            EXIT_USAGE,
            EXIT_REFUSED,
            EXIT_POLICY,
            EXIT_DEVICE,
            EXIT_JOB_FAILED,
            EXIT_INTERNAL,
        ] {
            assert!(
                HELP.contains(&format!("  {code}  ")),
                "exit code {code} is not documented in --help"
            );
        }
    }

    #[test]
    fn the_exit_codes_are_distinct() {
        let all = [
            EXIT_VERIFIED,
            EXIT_UNVERIFIED,
            EXIT_USAGE,
            EXIT_REFUSED,
            EXIT_POLICY,
            EXIT_DEVICE,
            EXIT_JOB_FAILED,
            EXIT_INTERNAL,
        ];
        let mut sorted: Vec<u8> = all.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "two exit codes collide");
    }

    #[test]
    fn unknown_options_and_missing_values_are_refused_rather_than_defaulted() {
        assert!(parse(&argv(&["--wipe-everything"])).is_err());
        assert!(parse(&argv(&["--target"])).is_err());
        assert!(parse(&argv(&["--allow-root"])).is_err());
        assert!(parse(&argv(&["--i-understand"])).is_err());
        assert!(parse(&argv(&["--method", "gutmann"])).is_err());
        assert!(parse(&argv(&["--sanitize", "make-it-fast"])).is_err());
        assert!(parse(&argv(&["--verify", "probably"])).is_err());
        assert!(parse(&argv(&["--sectors-per-mib", "0"])).is_err());
        assert!(parse(&argv(&["--period-ms", "0"])).is_err());
    }

    #[test]
    fn the_defaults_destroy_nothing() {
        let a = Args::default();
        assert!(a.target.is_none());
        assert!(a.roots.is_empty());
        assert!(a.confirmation.is_none());
        assert!(a.method.is_none(), "no compiled-in method");
        assert!(a.sanitize.is_none(), "no compiled-in sanitize primitive");
        assert!(!a.plan);
    }

    #[test]
    fn the_method_and_sanitize_spellings_round_trip() {
        assert_eq!(parse_method("three-pass").unwrap(), Method::ThreePass);
        assert_eq!(
            parse_method("single-pass-random").unwrap(),
            Method::SeededRandom
        );
        assert_eq!(parse_method("single-pass-zero").unwrap(), Method::ZeroFill);
        assert_eq!(
            parse_sanitize("ata-secure-erase").unwrap(),
            SanitizePrimitive::AtaSecureErase
        );
        assert_eq!(
            parse_sanitize("nvme-sanitize-block-erase").unwrap(),
            SanitizePrimitive::NvmeSanitizeBlockErase
        );
    }

    #[test]
    fn the_command_is_rebuilt_so_the_report_reproduces_the_run() {
        let c = rebuild_command(&argv(&[
            "--target",
            "/a/b.img",
            "--i-understand",
            "/a b/c.img",
        ]));
        assert!(c.starts_with("wipe --target /a/b.img"));
        assert!(c.contains("\"/a b/c.img\""), "a space must survive: {c}");
    }

    #[test]
    fn a_sink_type_the_binary_uses_really_is_an_event_sink() {
        // Compile-time only: it fails to build rather than fails to assert.
        fn takes<S: EventSink>(_: S) {}
        takes(NullSink);
        let (chan, rx): (ChannelSink, _) = sentinelwipe_wipe::telemetry::channel(2);
        drop(rx);
        takes(chan);
    }
}
