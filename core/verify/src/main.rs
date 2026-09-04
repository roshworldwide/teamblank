//! `verify` — the adversarial loop as one command that cannot be run wrong.
//!
//! Exit codes, published here and nowhere narrower:
//!   0  loop complete, ZERO admitted candidates survived, bundle written
//!   2  usage
//!   4  the guard refused (allowlist, confirmation, containment)
//!   5  the wipe failed
//!   6  ledger failure (canonicalization, signature, chain)
//!   7  SURVIVORS: at least one admitted candidate outlived the wipe. The
//!      loop ran to completion and the bundle is still written — evidence of
//!      a failure is still evidence — but the exit code says the claim did
//!      not hold.

use std::path::PathBuf;
use std::process::ExitCode;

use sentinelwipe_carve::carve::CarveOpts;
use sentinelwipe_verify::{audit_bundle, run_loop, LoopError, LoopSpec};

fn usage() -> String {
    "usage: verify --audit <bundle.json> | verify --target <image> --allow-root <dir> --i-understand <resolved-target> \
     [--manifest <manifest.json>] [--out <bundle.json>] [--chain <chain.txt>] \
     [--key <operator.key>] [--run-id <id>]"
        .to_string()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // Auditor mode: nothing destructive, nothing signed — read a bundle and
    // check the two independent proofs it carries.
    if args.first().map(String::as_str) == Some("--audit") {
        let Some(path) = args.get(1) else {
            eprintln!("verify: --audit needs a bundle path");
            return ExitCode::from(2);
        };
        return match std::fs::read_to_string(path).map_err(|e| e.to_string())
            .and_then(|b| audit_bundle(&b))
        {
            Ok(line) => {
                println!("verify: {line}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("verify: AUDIT FAILED: {e}");
                ExitCode::from(6)
            }
        };
    }
    let mut target = None;
    let mut allow_root = None;
    let mut confirmation = None;
    let mut manifest = None;
    let mut out = None;
    let mut chain = PathBuf::from("out/chain.txt");
    let mut key = PathBuf::from("out/operator.key");
    let mut run_id = "sentinelwipe/verify/v1".to_string();
    let mut trace = None;
    let mut period_ms = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut take = |name: &str| -> Result<String, String> {
            it.next().cloned().ok_or(format!("{name} needs a value"))
        };
        let r = match a.as_str() {
            "--target" => take("--target").map(|v| target = Some(PathBuf::from(v))),
            "--allow-root" => take("--allow-root").map(|v| allow_root = Some(PathBuf::from(v))),
            "--i-understand" => take("--i-understand").map(|v| confirmation = Some(v)),
            "--manifest" => take("--manifest").map(|v| manifest = Some(PathBuf::from(v))),
            "--out" => take("--out").map(|v| out = Some(PathBuf::from(v))),
            "--chain" => take("--chain").map(|v| chain = PathBuf::from(v)),
            "--key" => take("--key").map(|v| key = PathBuf::from(v)),
            "--run-id" => take("--run-id").map(|v| run_id = v),
            "--trace" => take("--trace").map(|v| trace = Some(PathBuf::from(v))),
            "--period-ms" => take("--period-ms").and_then(|v| {
                v.parse::<u64>()
                    .map(|n| period_ms = Some(n))
                    .map_err(|_| "--period-ms needs an integer".to_string())
            }),
            other => Err(format!("unknown option {other:?}\n{}", usage())),
        };
        if let Err(e) = r {
            eprintln!("verify: {e}");
            return ExitCode::from(2);
        }
    }
    let (Some(target), Some(allow_root), Some(confirmation)) =
        (target, allow_root, confirmation)
    else {
        eprintln!("verify: --target, --allow-root and --i-understand are required\n{}", usage());
        return ExitCode::from(2);
    };

    // The guard requires absolute roots — a relative root means a different
    // directory per cwd, which is an allowlist that moves. Absolutize here,
    // and let the typed confirmation follow the SAME transformation only when
    // it equals the typed target: the operator confirmed this target, in
    // whatever spelling they used, and the guard compares resolved strings.
    let absolutize = |p: &PathBuf| -> PathBuf {
        if p.is_absolute() {
            p.clone()
        } else {
            std::env::current_dir().map(|d| d.join(p)).unwrap_or_else(|_| p.clone())
        }
    };
    let target_typed = target.to_string_lossy().into_owned();
    let target = absolutize(&target);
    let allow_root = absolutize(&allow_root);
    let confirmation = if confirmation == target_typed {
        target.to_string_lossy().into_owned()
    } else {
        confirmation
    };

    let command = format!(
        "verify --target {} --allow-root {} --i-understand {}",
        target.display(), allow_root.display(), confirmation
    );
    let spec = LoopSpec {
        target,
        allow_root,
        confirmation,
        manifest,
        carve_opts: CarveOpts::default(),
        run_id,
        command,
        chain_path: chain,
        key_path: key,
        trace: trace.map(|t| if t.is_absolute() { t } else {
            std::env::current_dir().map(|d| d.join(&t)).unwrap_or(t)
        }),
        period_ms,
    };

    eprintln!("verify: carve — wipe — carve again, identical parameters by construction");
    let outcome = match run_loop(&spec) {
        Ok(o) => o,
        Err(LoopError::Refused(m)) => {
            eprintln!("verify: REFUSED: {m}");
            return ExitCode::from(4);
        }
        Err(LoopError::Wipe(m)) => {
            eprintln!("verify: wipe failed: {m}");
            return ExitCode::from(5);
        }
        Err(LoopError::ParameterDrift { field }) => {
            eprintln!(
                "verify: PARAMETER DRIFT in {field}: the two scans are not the same scan \
                 and the loop's evidential value is void. Nothing was signed."
            );
            return ExitCode::from(6);
        }
        Err(LoopError::Ledger(m)) => {
            eprintln!("verify: ledger failure: {m}");
            return ExitCode::from(6);
        }
        Err(LoopError::Io(m)) => {
            eprintln!("verify: {m}");
            return ExitCode::from(5);
        }
    };

    if let Some(out) = &out {
        if let Err(e) = std::fs::write(out, &outcome.bundle_json) {
            eprintln!("verify: writing bundle: {e}");
            return ExitCode::from(6);
        }
        eprintln!("verify: bundle {} ({} bytes)", out.display(), outcome.bundle_json.len());
    } else {
        println!("{}", outcome.bundle_json);
    }
    eprintln!(
        "verify: pre-wipe admitted {} · post-wipe admitted {} · chain[{}] head {}",
        outcome.pre_admitted, outcome.survivors_admitted, outcome.chain_index,
        outcome.chain_head_hex
    );
    if outcome.survivors_admitted > 0 {
        eprintln!(
            "verify: {} ADMITTED CANDIDATE(S) SURVIVED THE WIPE. The bundle is written \
             because evidence of a failure is still evidence; the exit code says the \
             claim did not hold.",
            outcome.survivors_admitted
        );
        return ExitCode::from(7);
    }
    ExitCode::SUCCESS
}
