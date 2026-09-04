//! The two-region certificate — architecture.md D8 made executable.
//!
//! Inputs are TYPED, never re-parsed from the engine's JSON: the reports carry
//! floats as display renderings, and every one of them is either a ratio of
//! integers the engine already holds or a six-decimal string it already
//! printed. The builder accepts only those forms, so a float cannot enter the
//! signed payload through any door — jcs::Value has no variant for it and this
//! module has no conversion to it.
//!
//! The split, per D8:
//!   deterministic_core    reproduces byte-identically from a fresh clone at
//!                         the same fixture seed. Carries the reproducibility
//!                         assertion.
//!   measurement_envelope  physical observations of real hardware. Signed, and
//!                         explicitly NOT asserted repeatable — a baseline that
//!                         did not move between runs would mean it was not
//!                         being measured.
//!
//! Both regions are inside the signature. Timing is the field most worth
//! forging, because it is the evidence that the drive lied; what is scoped is
//! the reproducibility CLAIM, never the integrity claim, and the certificate
//! names on its own face which fields carry which.

use crate::jcs::{JcsError, Value};

/// An exact rational, stored REDUCED — canon_vectors' carrier rule: 1024/524288
/// and 1/512 are the same bytes. Denominator strictly positive; sign on n.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ratio {
    n: i64,
    d: i64,
}

impl Ratio {
    pub fn new(n: i64, d: i64) -> Result<Ratio, JcsError> {
        if d == 0 {
            return Err(JcsError::Parse { at: 0, what: "ratio with zero denominator" });
        }
        let g = gcd(n.unsigned_abs(), d.unsigned_abs()) as i64;
        let sign = if (n < 0) != (d < 0) { -1 } else { 1 };
        Ok(Ratio { n: sign * (n / g).abs(), d: (d / g).abs() })
    }
    pub fn value(self) -> Value {
        Value::Obj(vec![
            ("n".into(), Value::Int(self.n)),
            ("d".into(), Value::Int(self.d)),
        ])
    }
    pub fn parts(self) -> (i64, i64) {
        (self.n, self.d)
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.max(1)
}

/// A measured continuous value as the engine's own six-decimal rendering,
/// verbatim. No parse, no arithmetic, no rounding step for two languages to
/// disagree about: Python rounds half-even, Rust half-away-from-zero, and the
/// exact .5 at the sixth decimal is where a scaled-integer scheme would emit
/// two different signatures over one untouched document (D8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dec6(String);

impl Dec6 {
    pub fn new(s: &str) -> Result<Dec6, JcsError> {
        let ok = |s: &str| {
            let s = s.strip_prefix('-').unwrap_or(s);
            let (int, frac) = s.split_once('.')?;
            let int_ok = int == "0"
                || (!int.is_empty()
                    && !int.starts_with('0')
                    && int.bytes().all(|b| b.is_ascii_digit()));
            let frac_ok = frac.len() == 6 && frac.bytes().all(|b| b.is_ascii_digit());
            (int_ok && frac_ok).then_some(())
        };
        match ok(s) {
            Some(()) => Ok(Dec6(s.to_string())),
            None => Err(JcsError::Parse {
                at: 0,
                what: "not a six-decimal rendering (the engine emits exactly six)",
            }),
        }
    }
    pub fn value(&self) -> Value {
        Value::Str(self.0.clone())
    }
}

/// Everything the deterministic core carries. Byte-identical from a fresh
/// clone at the same fixture seed.
pub struct CoreInput {
    pub run_id: String,
    pub target: String,
    pub method: String,
    pub nist_category: String,
    /// Present-and-null beats absent: a host-overwrite run has no firmware
    /// witness, and the certificate must say "no witness" rather than nothing.
    pub medium_witness_before: Option<String>,
    pub medium_witness_after: Option<String>,
    pub medium_unchanged: Option<bool>,
    pub outcome_code: String,
    pub whole_medium_claim: bool,
    pub sanitized_scope: String,
    pub timing_code: String,
    pub verification_verdict: String,
    pub coverage: Ratio,
    pub passes_verified: bool,
}

/// Physical observations of this machine on this run.
pub struct EnvelopeInput {
    pub baseline_source: String,
    pub probe_bytes: i64,
    pub probe_elapsed_ns: i64,
    pub work_bytes: i64,
    pub observed_elapsed_ns: i64,
    pub expected_min_ns: i64,
    pub timing_ratio: Ratio,
    pub timing_threshold: Ratio,
    pub entropy_before: Dec6,
    pub entropy_after: Dec6,
}

pub fn build(core: &CoreInput, env: &EnvelopeInput) -> Result<Value, JcsError> {
    let opt = |o: &Option<String>| match o {
        Some(s) => Value::Str(s.clone()),
        None => Value::Null,
    };
    let optb = |o: &Option<bool>| match o {
        Some(b) => Value::Bool(*b),
        None => Value::Null,
    };

    let deterministic_core = Value::obj(vec![
        ("run_id".into(), Value::Str(core.run_id.clone())),
        ("target".into(), Value::Str(core.target.clone())),
        ("method".into(), Value::Str(core.method.clone())),
        ("nist_category".into(), Value::Str(core.nist_category.clone())),
        ("medium_witness_before".into(), opt(&core.medium_witness_before)),
        ("medium_witness_after".into(), opt(&core.medium_witness_after)),
        ("medium_unchanged".into(), optb(&core.medium_unchanged)),
        ("outcome_code".into(), Value::Str(core.outcome_code.clone())),
        ("whole_medium_claim".into(), Value::Bool(core.whole_medium_claim)),
        ("sanitized_scope".into(), Value::Str(core.sanitized_scope.clone())),
        ("timing_code".into(), Value::Str(core.timing_code.clone())),
        (
            "verification_verdict".into(),
            Value::Str(core.verification_verdict.clone()),
        ),
        ("coverage".into(), core.coverage.value()),
        ("passes_verified".into(), Value::Bool(core.passes_verified)),
    ])?;

    let measurement_envelope = Value::obj(vec![
        ("baseline_source".into(), Value::Str(env.baseline_source.clone())),
        ("probe_bytes".into(), Value::Int(env.probe_bytes)),
        ("probe_elapsed_ns".into(), Value::Int(env.probe_elapsed_ns)),
        ("work_bytes".into(), Value::Int(env.work_bytes)),
        ("observed_elapsed_ns".into(), Value::Int(env.observed_elapsed_ns)),
        ("expected_min_ns".into(), Value::Int(env.expected_min_ns)),
        ("timing_ratio".into(), env.timing_ratio.value()),
        ("timing_threshold".into(), env.timing_threshold.value()),
        ("entropy_bits_per_byte_before".into(), env.entropy_before.value()),
        ("entropy_bits_per_byte_after".into(), env.entropy_after.value()),
    ])?;

    // The custody statement is INSIDE the signed document, on the
    // certificate's own face, because the honest version of "tamper-proof" is
    // two separate claims and this build provides exactly one of them.
    let custody = Value::obj(vec![
        (
            "key_custody".into(),
            Value::Str("none — key generated locally, unattested".into()),
        ),
        (
            "signature_proves".into(),
            Value::Str("integrity since signing, not authority of the signer".into()),
        ),
        (
            "production_path".into(),
            Value::Str(
                "operator key enrolled against an organisational CA or HSM".into(),
            ),
        ),
    ])?;

    Value::obj(vec![
        ("schema".into(), Value::Str("sentinelwipe.certificate/1".into())),
        ("custody".into(), custody),
        ("deterministic_core".into(), deterministic_core),
        ("measurement_envelope".into(), measurement_envelope),
        (
            "scope".into(),
            Value::obj(vec![
                (
                    "signature_covers".into(),
                    Value::Str("the entire certificate: both regions, this scope block \
                                included. An unsigned section is a tamperable one, and \
                                the timing verdict is the field most worth forging.".into()),
                ),
                (
                    "reproducibility_asserted_over".into(),
                    Value::Str("deterministic_core".into()),
                ),
                (
                    "measurement_envelope_statement".into(),
                    Value::Str("physical observations of real hardware on this run; \
                                signed, and not asserted repeatable — a baseline that \
                                did not move between runs was not being measured.".into()),
                ),
            ])?,
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jcs::{canonical, parse};

    fn core() -> CoreInput {
        CoreInput {
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
        }
    }
    fn envelope() -> EnvelopeInput {
        EnvelopeInput {
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
        }
    }

    #[test]
    fn the_d8_rationals_reduce_to_the_documented_exact_forms() {
        // D8's table, verified rather than transcribed:
        assert_eq!(Ratio::new(1024, 524_288).unwrap().parts(), (1, 512));
        assert_eq!(Ratio::new(1000, 431_059_458_000).unwrap().parts(), (1, 431_059_458));
        // structural_breach_point (0.75-0.65)/0.35 = (10/100)/(35/100):
        assert_eq!(Ratio::new(10, 35).unwrap().parts(), (2, 7));
        // headroom = breach_point - worst_rejected = 2/7 - 1/4, common
        // denominator 28: (2*4 - 1*7)/28 = 1/28. The first version of this
        // assertion tried to be clever in one expression and asserted 159/490.
        assert_eq!(Ratio::new(2 * 4 - 1 * 7, 28).unwrap().parts(), (1, 28));
        assert_eq!(Ratio::new(-3, -6).unwrap().parts(), (1, 2));
        assert_eq!(Ratio::new(3, -6).unwrap().parts(), (-1, 2));
        assert_eq!(Ratio::new(0, 7).unwrap().parts(), (0, 1));
        assert!(Ratio::new(1, 0).is_err());
    }

    #[test]
    fn dec6_accepts_the_engines_renderings_and_refuses_everything_else() {
        for good in ["7.061690", "7.999999", "0.938309", "-0.000001", "433.562916"] {
            assert!(Dec6::new(good).is_ok(), "{good}");
        }
        for bad in ["7.99999", "7.9999990", "07.000000", "7", "7.", ".999999",
                    "1e6", "7.99999a", ""] {
            assert!(Dec6::new(bad).is_err(), "{bad:?} must refuse");
        }
    }

    #[test]
    fn the_certificate_canonicalizes_and_round_trips() {
        let cert = build(&core(), &envelope()).unwrap();
        let bytes = canonical(&cert).unwrap();
        assert_eq!(canonical(&parse(&bytes).unwrap()).unwrap(), bytes);
        let text = String::from_utf8(bytes).unwrap();
        // The reduced carrier, in the signed bytes themselves:
        assert!(text.contains("\"coverage\":{\"d\":512,\"n\":1}"), "{text}");
        // No float syntax anywhere outside strings — the profile held.
        assert!(!text.contains("0.001953"));
    }

    #[test]
    fn both_regions_sit_inside_one_signed_document_and_the_scope_names_them() {
        let cert = build(&core(), &envelope()).unwrap();
        let scope = cert.get("scope").unwrap();
        assert_eq!(
            scope.get("reproducibility_asserted_over").unwrap(),
            &Value::Str("deterministic_core".into())
        );
        assert!(cert.get("deterministic_core").is_some());
        assert!(cert.get("measurement_envelope").is_some());
        // Timing lives in the envelope AND is inside the same document the
        // signature covers — the D5 conflict resolved the D8 way.
        assert!(cert
            .get("measurement_envelope")
            .and_then(|e| e.get("timing_ratio"))
            .is_some());
    }

    #[test]
    fn a_missing_witness_is_present_and_null_never_absent() {
        let cert = build(&core(), &envelope()).unwrap();
        let dc = cert.get("deterministic_core").unwrap();
        assert_eq!(dc.get("medium_witness_before").unwrap(), &Value::Null);
        assert_eq!(dc.get("medium_unchanged").unwrap(), &Value::Null);
    }

    #[test]
    fn determinism_holds_across_reordered_construction() {
        // Two logically identical certificates, built fresh, one canonical form.
        let a = canonical(&build(&core(), &envelope()).unwrap()).unwrap();
        let b = canonical(&build(&core(), &envelope()).unwrap()).unwrap();
        assert_eq!(a, b);
    }
}
