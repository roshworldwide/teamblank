//! Ed25519 over the canonical bytes — and an honest account of what that buys.
//!
//! A signature demonstrates that the certificate has not been altered since it
//! was signed. It does NOT demonstrate who signed it: that requires a chain of
//! custody for the public key, and in this build the key is generated locally
//! on the operator's machine with no custody story at all. The certificate
//! carries that statement inside its signed bytes (certificate.rs `custody`),
//! and docs/standards_map.md carries it as its own row. Every claim here is
//! ed25519-dalek's; there is no custom crypto and no hand-rolled anything.

use crate::jcs::{canonical, JcsError, Value};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    Canon(JcsError),
    /// The signed envelope is structurally wrong: a field missing or mistyped.
    Envelope(&'static str),
    /// The bytes verify against nothing: the certificate was altered since
    /// signing, or the signature/key are not what they claim.
    Invalid,
}

impl From<JcsError> for SignError {
    fn from(e: JcsError) -> Self {
        SignError::Canon(e)
    }
}

pub fn generate() -> SigningKey {
    SigningKey::generate(&mut rand_core::OsRng)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Wrap a certificate in a signed envelope. The signature covers the
/// certificate's canonical bytes — all of it, both regions, custody and scope
/// included. The envelope itself cannot be inside the signature (a signature
/// cannot sign itself), which is why nothing in the envelope carries meaning
/// beyond "here is the document, here is the proof".
pub fn sign(certificate: &Value, key: &SigningKey) -> Result<Value, SignError> {
    let bytes = canonical(certificate)?;
    let sig: Signature = key.sign(&bytes);
    Ok(Value::Obj(vec![
        ("certificate".into(), certificate.clone()),
        (
            "signature".into(),
            Value::Obj(vec![
                ("algorithm".into(), Value::Str("Ed25519".into())),
                ("public_key_hex".into(), Value::Str(hex(key.verifying_key().as_bytes()))),
                ("signature_hex".into(), Value::Str(hex(&sig.to_bytes()))),
                (
                    "signed_bytes".into(),
                    Value::Int(bytes.len() as i64),
                ),
            ]),
        ),
    ]))
}

/// Verify a signed envelope. Returns the certificate's canonical bytes on
/// success, so a caller can chain them (the Merkle leaf is these exact bytes,
/// never a re-serialisation).
pub fn verify(envelope: &Value) -> Result<Vec<u8>, SignError> {
    let cert = envelope
        .get("certificate")
        .ok_or(SignError::Envelope("no certificate"))?;
    let sig_block = envelope
        .get("signature")
        .ok_or(SignError::Envelope("no signature block"))?;
    let field = |k: &str| -> Result<String, SignError> {
        match sig_block.get(k) {
            Some(Value::Str(s)) => Ok(s.clone()),
            _ => Err(SignError::Envelope("signature field missing or mistyped")),
        }
    };
    if field("algorithm")? != "Ed25519" {
        return Err(SignError::Envelope("unknown algorithm"));
    }
    let pk_bytes = unhex(&field("public_key_hex")?).ok_or(SignError::Envelope("bad key hex"))?;
    let sig_bytes = unhex(&field("signature_hex")?).ok_or(SignError::Envelope("bad sig hex"))?;
    let pk = VerifyingKey::from_bytes(
        pk_bytes.as_slice().try_into().map_err(|_| SignError::Envelope("key length"))?,
    )
    .map_err(|_| SignError::Envelope("not a valid Ed25519 public key"))?;
    let sig = Signature::from_bytes(
        sig_bytes.as_slice().try_into().map_err(|_| SignError::Envelope("sig length"))?,
    );
    let bytes = canonical(cert)?;
    pk.verify(&bytes, &sig).map_err(|_| SignError::Invalid)?;
    Ok(bytes)
}

/// The first path where two documents disagree — the diagnostic behind the
/// forge demo: "signature invalid" alone teaches nothing; the offending field,
/// named, is the argument.
pub fn first_divergence(a: &Value, b: &Value, path: &str) -> Option<String> {
    match (a, b) {
        (Value::Obj(pa), Value::Obj(pb)) => {
            let keys: Vec<&String> = {
                let mut k: Vec<&String> =
                    pa.iter().map(|(k, _)| k).chain(pb.iter().map(|(k, _)| k)).collect();
                k.sort();
                k.dedup();
                k
            };
            for k in keys {
                match (a.get(k), b.get(k)) {
                    (Some(x), Some(y)) => {
                        if let Some(p) = first_divergence(x, y, &format!("{path}.{k}")) {
                            return Some(p);
                        }
                    }
                    _ => return Some(format!("{path}.{k}")),
                }
            }
            None
        }
        (Value::Arr(xa), Value::Arr(xb)) => {
            if xa.len() != xb.len() {
                return Some(format!("{path}.length"));
            }
            for (i, (x, y)) in xa.iter().zip(xb).enumerate() {
                if let Some(p) = first_divergence(x, y, &format!("{path}[{i}]")) {
                    return Some(p);
                }
            }
            None
        }
        _ => (a != b).then(|| path.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{build, CoreInput, Dec6, EnvelopeInput, Ratio};

    fn cert() -> Value {
        build(
            &CoreInput {
                run_id: "sentinelwipe/wipe/v1".into(),
                target: "out/ui-run/medium.img".into(),
                method: "single_pass_seeded_random_shake128".into(),
                nist_category: "Clear".into(),
                medium_witness_before: None,
                medium_witness_after: None,
                medium_unchanged: None,
                outcome_code: "OVERWRITE_VERIFIED_ON_SAMPLE".into(),
                whole_medium_claim: false,
                sanitized_scope: "sampled_sectors_only".into(),
                timing_code: "VERIFIED_TIMING".into(),
                verification_verdict: "PATTERN_CONFIRMED_ON_SAMPLE".into(),
                coverage: Ratio::new(1024, 524_288).unwrap(),
                passes_verified: true,
            },
            &EnvelopeInput {
                baseline_source: "calibration_probe".into(),
                probe_bytes: 33_554_432,
                probe_elapsed_ns: 61_914_500,
                work_bytes: 268_435_456,
                observed_elapsed_ns: 436_719_375,
                expected_min_ns: 495_316_000,
                timing_ratio: Ratio::new(436_719_375, 495_316_000).unwrap(),
                timing_threshold: Ratio::new(1, 20).unwrap(),
                entropy_before: Dec6::new("7.061690").unwrap(),
                entropy_after: Dec6::new("7.999999").unwrap(),
            },
        )
        .unwrap()
    }

    #[test]
    fn a_clean_certificate_signs_and_verifies_and_returns_the_leaf_bytes() {
        let key = generate();
        let signed = sign(&cert(), &key).unwrap();
        let leaf = verify(&signed).unwrap();
        assert_eq!(leaf, crate::jcs::canonical(&cert()).unwrap());
    }

    #[test]
    fn one_forged_field_fails_verification_and_the_divergence_is_named() {
        let key = generate();
        let original = cert();
        let signed = sign(&original, &key).unwrap();

        // The forge the instrument's button performs: whole_medium_claim
        // false -> true, in the presented copy only.
        let mut forged = original.clone();
        if let Value::Obj(pairs) = &mut forged {
            for (k, v) in pairs.iter_mut() {
                if k == "deterministic_core" {
                    if let Value::Obj(inner) = v {
                        for (ik, iv) in inner.iter_mut() {
                            if ik == "whole_medium_claim" {
                                *iv = Value::Bool(true);
                            }
                        }
                    }
                }
            }
        }
        let mut presented = signed.clone();
        if let Value::Obj(pairs) = &mut presented {
            for (k, v) in pairs.iter_mut() {
                if k == "certificate" {
                    *v = forged.clone();
                }
            }
        }
        // Both directions, per the phase order: the corrupted case fails AND
        // the clean case still passes, so a verifier that rejects everything
        // cannot pass this test.
        assert_eq!(verify(&presented), Err(SignError::Invalid));
        assert!(verify(&signed).is_ok());

        assert_eq!(
            first_divergence(&original, &forged, "certificate"),
            Some("certificate.deterministic_core.whole_medium_claim".into())
        );
        assert_eq!(first_divergence(&original, &original, "certificate"), None);
    }

    #[test]
    fn a_single_flipped_bit_in_the_signature_itself_is_invalid() {
        let key = generate();
        let signed = sign(&cert(), &key).unwrap();
        let mut bad = signed.clone();
        if let Value::Obj(pairs) = &mut bad {
            for (k, v) in pairs.iter_mut() {
                if k == "signature" {
                    if let Value::Obj(inner) = v {
                        for (ik, iv) in inner.iter_mut() {
                            if ik == "signature_hex" {
                                if let Value::Str(s) = iv {
                                    let flipped = if s.as_bytes()[0] == b'0' { "1" } else { "0" };
                                    *iv = Value::Str(format!("{}{}", flipped, &s[1..]));
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(verify(&bad), Err(SignError::Invalid));
    }

    #[test]
    fn the_custody_statement_is_inside_the_signed_bytes() {
        let key = generate();
        let signed = sign(&cert(), &key).unwrap();
        let leaf = verify(&signed).unwrap();
        let text = String::from_utf8(leaf).unwrap();
        assert!(text.contains("none — key generated locally, unattested"));
        assert!(text.contains("integrity since signing, not authority of the signer"));
        assert!(text.contains("operator key enrolled against an organisational CA or HSM"));
    }

    #[test]
    fn a_wrong_key_does_not_verify_someone_elses_certificate() {
        let signed = sign(&cert(), &generate()).unwrap();
        let mut swapped = signed.clone();
        if let Value::Obj(pairs) = &mut swapped {
            for (k, v) in pairs.iter_mut() {
                if k == "signature" {
                    if let Value::Obj(inner) = v {
                        for (ik, iv) in inner.iter_mut() {
                            if ik == "public_key_hex" {
                                *iv = Value::Str(super::hex(
                                    generate().verifying_key().as_bytes(),
                                ));
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(verify(&swapped), Err(SignError::Invalid));
    }
}

/// Re-exported so `core/verify` uses the exact key type this crate signs
/// with — one dalek version in the tree, by construction.
pub use ed25519_dalek::SigningKey as SigningKeyReexport;
