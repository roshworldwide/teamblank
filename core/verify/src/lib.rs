//! The adversarial loop: carve the wiped medium with the engine that found the
//! data, and score what survived.
//!
//! Phase 4 step 5. What makes this crate different from the shell pipeline it
//! replaces (`ui/refresh.py` drove the three binaries by argv):
//!
//! ONE BINDING, TWO SCANS. `carve()` is a pure function over bytes and a
//! `CarveOpts`. Both scans in this loop receive the SAME `&CarveOpts` value,
//! so parameter drift between them is not refused at runtime — it is
//! unrepresentable at compile time. The runtime cross-check below still runs,
//! over the two REPORTS' own policy blocks, because a belt is cheap once the
//! braces are structural.
//!
//! THE SAME EMITTERS AS THE DEMO. The carve reports in the bundle come from
//! `sentinelwipe_carve::report::emit`, the wipe report from
//! `JobReport::to_json` — the code the binaries themselves run. A bundle whose
//! reports came from a private serialiser would be a second truth.
//!
//! WHAT THE EXIT CODE MEANS. The loop exits non-zero if ANY admitted
//! candidate survives the wipe. Zero admitted survivors is not decoration:
//! it is the claim the whole project makes, measured by its own adversary.

use std::fs;
use std::path::{Path, PathBuf};

use sentinelwipe_carve::carve::{carve, sha256_hex, CarveOpts};
use sentinelwipe_carve::report::{emit, EmitMeta, GroundTruth, Json};
use sentinelwipe_device::{guard, GuardAuthority, ImageFile};
use sentinelwipe_ledger::certificate::{build, CoreInput, Dec6, EnvelopeInput, Ratio};
use sentinelwipe_ledger::jcs::{canonical, parse as jcs_parse, Value};
use sentinelwipe_ledger::merkle::{hex as merkle_hex, Chain, Hash, Sibling};
use sentinelwipe_ledger::sign::{generate, sign, verify as verify_signature};
use sentinelwipe_wipe::telemetry::{NullSink, RecorderSink};
use sentinelwipe_wipe::audit::Verdict as TimingVerdict;
use sentinelwipe_device::WriteAuthority;
use sentinelwipe_wipe::{fmt6, run_job, Authorization, JobSpec, Outcome};

/// Every timing verdict carries what was measured; not every one carries a
/// floor (no baseline, not applicable). The certificate stores both integers;
/// a missing floor is 0 and the Ratio denominator is clamped to 1 with the
/// meaning carried by the timing_code string beside it.
fn timing_ns(v: &TimingVerdict) -> (u128, u128) {
    match v {
        TimingVerdict::Verified { measured_ns, expected_min_ns }
        | TimingVerdict::UnverifiedTiming { measured_ns, expected_min_ns }
        | TimingVerdict::UnverifiedSimulated { measured_ns, expected_min_ns } => {
            (*measured_ns, *expected_min_ns)
        }
        TimingVerdict::UnverifiedNoBaseline { measured_ns, .. } => (*measured_ns, 0),
        TimingVerdict::NotApplicable { measured_ns, .. } => (*measured_ns, 0),
    }
}

pub struct LoopSpec {
    pub target: PathBuf,
    pub allow_root: PathBuf,
    /// The operator's typed confirmation — the guard checks it LAST, after
    /// the allowlist has already said yes. It carries no authority alone.
    pub confirmation: String,
    pub manifest: Option<PathBuf>,
    pub carve_opts: CarveOpts,
    pub run_id: String,
    /// The exact command that reproduces this loop, recorded in every report.
    pub command: String,
    pub chain_path: PathBuf,
    pub key_path: PathBuf,
    /// Record the telemetry stream as JSON Lines. Opened through the SAME
    /// guard as the target, with the exclusive-create precheck the wipe
    /// binary uses: a recorder is a file this process creates, and one policy
    /// with two behaviours is no policy.
    pub trace: Option<PathBuf>,
    /// Telemetry period in milliseconds; None keeps the engine default.
    pub period_ms: Option<u64>,
}

pub struct LoopOutcome {
    pub bundle_json: String,
    pub survivors_admitted: u64,
    pub pre_admitted: u64,
    pub chain_head_hex: String,
    pub chain_index: usize,
    pub certificate_sha_hex: String,
}

#[derive(Debug)]
pub enum LoopError {
    Io(String),
    Refused(String),
    Wipe(String),
    /// The two carve reports disagree about their own parameters. With one
    /// CarveOpts binding this is unreachable; the check exists because a belt
    /// is cheap once the braces are structural, and because a future caller
    /// could construct two spec values and believe them equal.
    ParameterDrift { field: String },
    Ledger(String),
}

fn io<E: std::fmt::Display>(e: E) -> LoopError {
    LoopError::Io(e.to_string())
}

/// The policy blocks of the two reports, compared field by field. Extracted
/// with the same minimal JSON reader the carve binary uses on manifests.
fn policy_drift(pre: &str, post: &str) -> Result<(), LoopError> {
    let a = Json::parse(pre.as_bytes());
    let b = Json::parse(post.as_bytes());
    let pa = a.get("policy").ok_or(LoopError::ParameterDrift { field: "policy (pre missing)".into() })?;
    let pb = b.get("policy").ok_or(LoopError::ParameterDrift { field: "policy (post missing)".into() })?;
    if pa != pb {
        return Err(LoopError::ParameterDrift { field: "policy".into() });
    }
    Ok(())
}

pub fn run_loop(spec: &LoopSpec) -> Result<LoopOutcome, LoopError> {
    let started = "1970-01-01T00:00:00Z"; // the certificate carries no wall time:
    // a timestamp is the one field that would break deterministic_core, and the
    // chain's append order already carries "when" in the only sense that is
    // verifiable offline.

    // ---- 1 · carve, before -------------------------------------------------
    let bytes_pre = fs::read(&spec.target).map_err(io)?;
    let image_sha_pre = sha256_hex(&bytes_pre);
    let pre = carve(&bytes_pre, &spec.carve_opts);
    let manifest_bytes = match &spec.manifest {
        Some(m) => Some(fs::read(m).map_err(io)?),
        None => None,
    };
    let target_str = spec.target.to_string_lossy().to_string();
    let gt_pre = manifest_bytes
        .as_ref()
        .map(|mb| GroundTruth::load(spec.manifest.as_ref().unwrap(), mb, &pre));
    let meta_pre = EmitMeta {
        opts: &spec.carve_opts,
        phase: "pre-wipe",
        read_mode: "file",
        device: None,
        timing: false,
        command: &spec.command,
    };
    let report_pre = emit(&meta_pre, &bytes_pre, &target_str, &image_sha_pre,
                          &pre, gt_pre.as_ref(), started, 0);

    // ---- 2 · wipe, through the guard ---------------------------------------
    let mut pspec = guard::PolicySpec::with_roots(
        [spec.allow_root.to_string_lossy().to_string()].into_iter(),
    );
    pspec.require_confirmation = true;
    let policy = guard::Policy::build(pspec).map_err(|e| LoopError::Refused(e.0))?;
    let decision = guard::authorize(
        &policy, &target_str, Some(&spec.confirmation), "w", &guard::Env::Process, None,
    );
    if !decision.allowed {
        return Err(LoopError::Refused(format!("{}: {}", decision.code, decision.detail)));
    }
    let policy_roots = policy.root_reals().to_vec();
    let policy_requires_confirmation = policy.require_confirmation();
    let authority = GuardAuthority::new(policy, Some(spec.confirmation.clone()));
    let policy_digest = authority.policy_digest();
    let device = ImageFile::open_writable(&spec.target, Box::new(authority))
        .map_err(|e| LoopError::Refused(e.to_string()))?;

    let mut jspec = JobSpec::new(&spec.run_id);
    jspec.target_named = target_str.clone();
    jspec.target_resolved = decision.resolved.clone();
    jspec.command = spec.command.clone();
    // The report records WHO allowed this, exactly as the wipe binary does: a
    // loop whose report says "authorization: null" ran outside its own story.
    jspec.authorization = Some(Authorization {
        decision_code: decision.code.to_string(),
        policy_digest,
        roots: policy_roots,
        require_confirmation: policy_requires_confirmation,
    });
    if let Some(ms) = spec.period_ms {
        jspec.telemetry_period = Some(std::time::Duration::from_millis(ms));
    }
    let (job, _device) = match &spec.trace {
        None => run_job(device, &jspec, NullSink)
            .map_err(|e| LoopError::Wipe(e.to_string()))?,
        Some(tp) => {
            let tstr = tp.to_string_lossy().to_string();
            let pre = guard::authorize(
                &guard::Policy::build({
                    let mut ps = guard::PolicySpec::with_roots(
                        [spec.allow_root.to_string_lossy().to_string()].into_iter(),
                    );
                    ps.require_confirmation = true;
                    ps
                })
                .map_err(|e| LoopError::Refused(e.0))?,
                &tstr,
                Some(&guard::realpath(&tstr)),
                "x",
                &guard::Env::Process,
                None,
            );
            if !pre.allowed {
                return Err(LoopError::Refused(format!(
                    "--trace {}: {}: {}",
                    tstr, pre.code, pre.detail
                )));
            }
            let f = fs::File::create(tp).map_err(io)?;
            run_job(device, &jspec, RecorderSink::new(f))
                .map_err(|e| LoopError::Wipe(e.to_string()))?
        }
    };
    let report_wipe = job.to_json();

    // ---- 3 · carve, after — the SAME opts binding --------------------------
    let bytes_post = fs::read(&spec.target).map_err(io)?;
    let image_sha_post = sha256_hex(&bytes_post);
    let post = carve(&bytes_post, &spec.carve_opts);
    let gt_post = manifest_bytes
        .as_ref()
        .map(|mb| GroundTruth::load(spec.manifest.as_ref().unwrap(), mb, &post));
    let meta_post = EmitMeta { phase: "post-wipe", ..meta_pre };
    let report_post = emit(&meta_post, &bytes_post, &target_str, &image_sha_post,
                           &post, gt_post.as_ref(), started, 0);

    policy_drift(&report_pre, &report_post)?;

    // ---- 4 · certificate, signature, chain ---------------------------------
    let audit = &job.overwrite_audit;
    let (measured_ns, expected_ns) = timing_ns(&audit.verdict);
    let cov = job
        .wipe
        .verifications
        .iter()
        .map(|v| (v.sectors_verified, v.sectors_verified + v.sectors_unverified))
        .next()
        .unwrap_or((0, 1));
    let core = CoreInput {
        run_id: job.run_id.clone(),
        target: job.target_resolved.clone(),
        method: job.dispatch.method.label().to_string(),
        nist_category: job.dispatch.method.nist_category().to_string(),
        medium_witness_before: job.sanitize.as_ref().map(|s| s.witness_before.clone()),
        medium_witness_after: job.sanitize.as_ref().map(|s| s.witness_after.clone()),
        medium_unchanged: job.sanitize.as_ref().map(|s| s.medium_unchanged),
        outcome_code: job.outcome.code().to_string(),
        whole_medium_claim: job.outcome.is_whole_medium_claim(),
        sanitized_scope: match job.outcome {
            Outcome::VerifiedWholeMedium => "whole_medium",
            Outcome::VerifiedOnSample => "sampled_sectors_only",
            Outcome::NotVerified => "none",
        }
        .to_string(),
        timing_code: audit.verdict.code().to_string(),
        verification_verdict: job
            .wipe
            .verifications
            .first()
            .map(|v| v.verdict.code().to_string())
            .unwrap_or_else(|| "NO_VERIFICATION".into()),
        coverage: Ratio::new(cov.0 as i64, cov.1 as i64).map_err(|e| LoopError::Ledger(e.to_string()))?,
        passes_verified: job.wipe.all_passes_verified,
    };
    let env = EnvelopeInput {
        baseline_source: audit
            .baseline
            .as_ref()
            .map(|b| b.source().as_str().to_string())
            .unwrap_or_else(|| "none".to_string()),
        probe_bytes: job.probe.bytes as i64,
        probe_elapsed_ns: job.probe.duration_ns as i64,
        work_bytes: audit.work_bytes.unwrap_or(0) as i64,
        observed_elapsed_ns: measured_ns as i64,
        expected_min_ns: expected_ns as i64,
        timing_ratio: Ratio::new(measured_ns as i64, expected_ns.max(1) as i64)
            .map_err(|e| LoopError::Ledger(e.to_string()))?,
        timing_threshold: Ratio::new(1, 20).map_err(|e| LoopError::Ledger(e.to_string()))?,
        // fmt6 is the SAME routine the wipe report writer uses: the string is
        // verbatim-identical by construction, not by re-parsing.
        entropy_before: Dec6::new(&fmt6(job.entropy_before.unwrap_or(0.0)))
            .map_err(|e| LoopError::Ledger(e.to_string()))?,
        entropy_after: Dec6::new(&fmt6(job.entropy_after.unwrap_or(0.0)))
            .map_err(|e| LoopError::Ledger(e.to_string()))?,
    };
    let cert = build(&core, &env).map_err(|e| LoopError::Ledger(e.to_string()))?;

    let key = load_or_create_key(&spec.key_path)?;
    let signed = sign(&cert, &key).map_err(|e| LoopError::Ledger(format!("{e:?}")))?;
    let leaf = verify_signature(&signed).map_err(|e| LoopError::Ledger(format!("{e:?}")))?;

    let mut chain = load_chain(&spec.chain_path)?;
    let (index, head) = chain.append(&leaf);
    save_chain(&spec.chain_path, &chain)?;
    let path = chain.inclusion_path(index).expect("just appended");

    // ---- 5 · one bundle ----------------------------------------------------
    let signed_json = String::from_utf8(canonical(&signed).map_err(|e| LoopError::Ledger(e.to_string()))?)
        .expect("canonical is utf-8");
    let path_json: Vec<String> = path
        .iter()
        .map(|s| match s {
            Sibling::Left(h) => format!("{{\"left\":\"{}\"}}", merkle_hex(h)),
            Sibling::Right(h) => format!("{{\"right\":\"{}\"}}", merkle_hex(h)),
        })
        .collect();
    let survivors = post.records.iter().filter(|r| r.admitted).count() as u64;
    let pre_admitted = pre.records.iter().filter(|r| r.admitted).count() as u64;

    let bundle_json = format!(
        "{{\n\"schema\": \"sentinelwipe.bundle/1\",\n\
         \"note\": \"reports are embedded verbatim as their emitters wrote them; \
         the certificate and its signature are RFC 8785 canonical bytes; the chain \
         entry proves membership against the published head\",\n\
         \"signed_certificate\": {signed_json},\n\
         \"chain\": {{\"index\": {index}, \"head\": \"{head_hex}\", \
         \"leaf_sha256_of\": \"signed_certificate.certificate (canonical bytes)\", \
         \"inclusion_path\": [{path_items}]}},\n\
         \"carve_pre\": {report_pre},\n\
         \"wipe\": {report_wipe},\n\
         \"carve_post\": {report_post}\n}}\n",
        head_hex = merkle_hex(&head),
        path_items = path_json.join(", "),
    );

    Ok(LoopOutcome {
        bundle_json,
        survivors_admitted: survivors,
        pre_admitted,
        chain_head_hex: merkle_hex(&head),
        chain_index: index,
        certificate_sha_hex: {
            use sentinelwipe_ledger::merkle::hex as h2;
            let _ = h2; // sha of leaf lives in chain entry; expose head instead
            merkle_hex(&head)
        },
    })
}

fn load_or_create_key(path: &Path) -> Result<ed25519_dalek_reexport::SigningKey, LoopError> {
    use ed25519_dalek_reexport::SigningKey;
    match fs::read(path) {
        Ok(bytes) => {
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| LoopError::Ledger(format!("{path:?}: not a 32-byte key")))?;
            Ok(SigningKey::from_bytes(&arr))
        }
        Err(_) => {
            let key = generate();
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir).map_err(io)?;
            }
            fs::write(path, key.to_bytes()).map_err(io)?;
            Ok(key)
        }
    }
}

/// One leaf hash per line, hex. Only hashes: see Chain::from_leaf_hashes.
fn load_chain(path: &Path) -> Result<Chain, LoopError> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let mut hashes = Vec::new();
            for (i, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let mut h: Hash = [0u8; 32];
                if line.len() != 64 || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(LoopError::Ledger(format!("chain line {} is not a sha256", i + 1)));
                }
                for (j, chunk) in line.as_bytes().chunks(2).enumerate() {
                    h[j] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
                }
                hashes.push(h);
            }
            Ok(Chain::from_leaf_hashes(hashes))
        }
        Err(_) => Ok(Chain::new()),
    }
}

fn save_chain(path: &Path, chain: &Chain) -> Result<(), LoopError> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io)?;
    }
    let text: String = chain
        .leaf_hashes()
        .iter()
        .map(|h| format!("{}\n", merkle_hex(h)))
        .collect();
    fs::write(path, text).map_err(io)
}

/// The ledger already depends on ed25519-dalek; verify reuses that exact
/// version through the ledger's re-export rather than declaring its own,
/// so the two crates can never disagree about the key type.
mod ed25519_dalek_reexport {
    pub use sentinelwipe_ledger::sign::SigningKeyReexport as SigningKey;
}

/// The auditor's move, with nothing but a bundle in hand: extract the signed
/// certificate, verify the Ed25519 signature over its canonical bytes, then
/// verify the inclusion path against the head the bundle itself published.
/// Two independent checks; each can fail alone, and the message says which.
pub fn audit_bundle(bundle: &str) -> Result<String, String> {
    let start = bundle
        .find("\"signed_certificate\": ")
        .ok_or("bundle has no signed_certificate")?
        + "\"signed_certificate\": ".len();
    let (mut depth, mut in_str, mut esc, mut end) = (0i64, false, false, 0usize);
    for (i, c) in bundle[start..].char_indices() {
        match (in_str, esc, c) {
            (true, true, _) => esc = false,
            (true, false, '\\') => esc = true,
            (true, false, '"') => in_str = false,
            (false, _, '"') => in_str = true,
            (false, _, '{') => depth += 1,
            (false, _, '}') => {
                depth -= 1;
                if depth == 0 {
                    end = start + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if end == 0 {
        return Err("signed_certificate object never closes".into());
    }
    let envelope = jcs_parse(bundle[start..end].as_bytes())
        .map_err(|e| format!("certificate region does not parse strictly: {e}"))?;
    let leaf = verify_signature(&envelope)
        .map_err(|e| format!("SIGNATURE INVALID: {e:?}"))?;

    // chain block: head + inclusion path, parsed from the bundle's own JSON.
    let head_hex = field_after(bundle, "\"head\": \"").ok_or("bundle has no chain head")?;
    let mut head = [0u8; 32];
    parse_hash(&head_hex, &mut head).ok_or("chain head is not a sha256")?;
    let mut path: Vec<Sibling> = Vec::new();
    let chain_area = &bundle[bundle.find("\"inclusion_path\"").ok_or("no inclusion_path")?..];
    let path_end = chain_area.find(']').ok_or("inclusion_path never closes")?;
    let mut cursor = &chain_area[..path_end];
    loop {
        // The writer emits {"left":"<hex>"} with no space; accept a space
        // too, because an auditor may hand-pretty-print a bundle before
        // checking it, and whitespace must never change a verdict.
        let find_key = |k: &str| -> Option<usize> {
            cursor.find(&format!("\"{k}\":\"")).map(|i| i + k.len() + 4)
                .or_else(|| cursor.find(&format!("\"{k}\": \"")).map(|i| i + k.len() + 5))
        };
        let (side, rest) = match (find_key("left"), find_key("right")) {
            (Some(l), r) if r.is_none() || l < r.unwrap() => ("l", &cursor[l..]),
            (_, Some(r)) => ("r", &cursor[r..]),
            _ => break,
        };
        let hexs: String = rest.chars().take(64).collect();
        let mut h = [0u8; 32];
        parse_hash(&hexs, &mut h).ok_or("inclusion step is not a sha256")?;
        path.push(if side == "l" { Sibling::Left(h) } else { Sibling::Right(h) });
        cursor = rest;
    }
    if !sentinelwipe_ledger::merkle::verify_inclusion(&leaf, &path, &head) {
        return Err(format!(
            "INCLUSION FAILED: the certificate's canonical bytes do not prove membership              against head {head_hex} — the presented document is not the one the chain holds"
        ));
    }
    Ok(format!(
        "signature valid · inclusion proved against head {head_hex} · {} path steps",
        path.len()
    ))
}

fn field_after(text: &str, marker: &str) -> Option<String> {
    let i = text.find(marker)? + marker.len();
    Some(text[i..].chars().take_while(|c| *c != '"').collect())
}

fn parse_hash(hexs: &str, out: &mut [u8; 32]) -> Option<()> {
    if hexs.len() != 64 || !hexs.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    for (j, ch) in hexs.as_bytes().chunks(2).enumerate() {
        out[j] = u8::from_str_radix(std::str::from_utf8(ch).ok()?, 16).ok()?;
    }
    Some(())
}

/// Sanity used by main: a bundle must parse as JSON somewhere honest. The
/// strict jcs parser refuses the report floats BY DESIGN, so this check
/// parses only the signed_certificate region, which is float-free.
pub fn bundle_certificate_roundtrips(bundle: &str) -> bool {
    let Some(start) = bundle.find("\"signed_certificate\": ") else { return false };
    let rest = &bundle[start + "\"signed_certificate\": ".len()..];
    // The canonical envelope is one JSON object; find its extent by brace depth
    // OUTSIDE strings (the lesson of the emitter extraction, applied).
    let (mut depth, mut in_str, mut esc) = (0i64, false, false);
    for (i, c) in rest.char_indices() {
        match (in_str, esc, c) {
            (true, true, _) => esc = false,
            (true, false, '\\') => esc = true,
            (true, false, '"') => in_str = false,
            (false, _, '"') => in_str = true,
            (false, _, '{') => depth += 1,
            (false, _, '}') => {
                depth -= 1;
                if depth == 0 {
                    return jcs_parse(rest[..=i].as_bytes()).is_ok();
                }
            }
            _ => {}
        }
    }
    false
}

pub use sentinelwipe_ledger::jcs::Value as CertValue;
pub fn parse_certificate(envelope_json: &[u8]) -> Result<Value, String> {
    jcs_parse(envelope_json).map_err(|e| e.to_string())
}
