//! The loop, end to end, on a medium this test creates and owns. No fixture
//! dependency: a deterministic pseudo-random 1 MiB file exercises every stage
//! (carve finds nothing to admit in noise, the wipe overwrites it, the ledger
//! signs it, the chain grows) without `make fixtures` having run.

use std::fs;
use std::path::PathBuf;

use sentinelwipe_carve::carve::CarveOpts;
use sentinelwipe_ledger::jcs::{canonical, parse};
use sentinelwipe_ledger::merkle::{verify_inclusion, Chain, Sibling};
use sentinelwipe_ledger::sign::verify as verify_signature;
use sentinelwipe_verify::{run_loop, LoopSpec};

fn lab() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("swverify-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// xorshift64* again: deterministic bytes, no dependency.
fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        out.extend_from_slice(&seed.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

fn spec_for(dir: &PathBuf, name: &str) -> LoopSpec {
    let target = dir.join(name);
    fs::write(&target, noise(1 << 20, 0xDEC0DE)).unwrap();
    // The guard compares the typed confirmation against the RESOLVED target,
    // and on macOS /var is a firmlink to /private/var — the exact class of
    // aliasing the resolution exists to defeat. Do what the operator does
    // after `--plan`: confirm the resolved spelling.
    let resolved = fs::canonicalize(&target).unwrap();
    LoopSpec {
        confirmation: resolved.to_string_lossy().into_owned(),
        target: resolved,
        allow_root: fs::canonicalize(dir).unwrap(),
        manifest: None,
        carve_opts: CarveOpts::default(),
        run_id: "sentinelwipe/verify-test/v1".into(),
        command: "verify (integration test)".into(),
        chain_path: dir.join("chain.txt"),
        key_path: dir.join("operator.key"),
        trace: None,
        period_ms: None,
    }
}

#[test]
fn the_loop_signs_chains_and_reports_zero_survivors_on_noise() {
    let dir = lab();
    let out = run_loop(&spec_for(&dir, "m1.img")).expect("loop");
    assert_eq!(out.survivors_admitted, 0, "noise must admit nothing after a wipe");
    assert_eq!(out.chain_index, 0);

    // The bundle's signed certificate: extract, verify the signature, verify
    // the inclusion proof against the published head — the auditor's moves,
    // with nothing but the bundle in hand.
    let bundle = out.bundle_json;
    let start = bundle.find("\"signed_certificate\": ").unwrap()
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
                if depth == 0 { end = start + i + 1; break; }
            }
            _ => {}
        }
    }
    let envelope = parse(bundle[start..end].as_bytes()).expect("envelope parses strictly");
    let leaf = verify_signature(&envelope).expect("signature verifies");

    // Head recomputed from the persisted chain file equals the published one.
    let text = fs::read_to_string(dir.join("chain.txt")).unwrap();
    let hashes: Vec<[u8; 32]> = text.lines().filter(|l| !l.trim().is_empty()).map(|l| {
        let mut h = [0u8; 32];
        for (j, ch) in l.trim().as_bytes().chunks(2).enumerate() {
            h[j] = u8::from_str_radix(std::str::from_utf8(ch).unwrap(), 16).unwrap();
        }
        h
    }).collect();
    let chain = Chain::from_leaf_hashes(hashes);
    assert_eq!(sentinelwipe_ledger::merkle::hex(&chain.head()), out.chain_head_hex);

    // Single-leaf inclusion: empty path, and it verifies. Forged bytes do not.
    let path: Vec<Sibling> = chain.inclusion_path(0).unwrap();
    assert!(verify_inclusion(&leaf, &path, &chain.head()));
    let mut forged = leaf.clone();
    forged[0] ^= 1;
    assert!(!verify_inclusion(&forged, &path, &chain.head()));

    // Determinism where D8 promises it: the SAME target path, recreated with
    // the same bytes, must produce a byte-identical deterministic_core. (The
    // first version of this assertion compared runs over m1.img and m2.img
    // and called the difference drift; the target is IN the core, so a
    // different target is a different certificate, correctly.)
    let out2 = run_loop(&spec_for(&dir, "m2.img")).expect("second loop");
    assert_eq!(out2.chain_index, 1, "the chain grew");
    let b2 = out2.bundle_json;
    let out3 = run_loop(&spec_for(&dir, "m1.img")).expect("third loop, same path");
    let core_of = |b: &str| {
        let s = b.find("\"deterministic_core\":").unwrap();
        let e = b[s..].find(",\"measurement_envelope\"").unwrap();
        b[s..s + e].to_string()
    };
    assert_eq!(core_of(&bundle), core_of(&out3.bundle_json),
        "deterministic_core drifted between identical runs on the same target");
    assert_ne!(core_of(&bundle), core_of(&b2),
        "different targets must be different certificates");

    // And the two certificates canonicalize distinctly (the envelopes differ).
    let env2_start = b2.find("\"signed_certificate\": ").unwrap()
        + "\"signed_certificate\": ".len();
    assert_ne!(bundle[start..end], b2[env2_start..env2_start + (end - start).min(b2.len() - env2_start)]);
    let _ = canonical; // linked deliberately: the auditor path uses the same crate
}
