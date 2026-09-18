use crate::signature::signature_for;
use crate::structure::Validation;
use crate::Kind;

pub const W_SIGNATURE: f64 = 0.40;
pub const W_STRUCTURE: f64 = 0.35;
pub const W_ENTROPY: f64 = 0.15;
pub const W_SIZE: f64 = 0.10;

pub const MIN_CONFIDENCE: f64 = 0.75;

pub const NON_STRUCTURE_CEILING: f64 = W_SIGNATURE + W_ENTROPY + W_SIZE;

pub const STRUCTURAL_BREACH_POINT: f64 = (MIN_CONFIDENCE - NON_STRUCTURE_CEILING) / W_STRUCTURE;

pub const SIG_HEADER_MISMATCH: f64 = 0.00;
pub const SIG_HEADER_ONLY: f64 = 0.50;
pub const SIG_NO_FOOTER_DEFINED: f64 = 0.75;
pub const SIG_HEADER_AND_FOOTER: f64 = 1.00;

pub const MIN_ENTROPY_SAMPLE: usize = 1024;

pub const ENTROPY_UNKNOWN: f64 = 0.5;

#[derive(Debug, Clone, PartialEq)]
pub struct Confidence {
    pub signature_integrity: f64,
    pub structural_validity: f64,
    pub entropy_consistency: f64,
    pub size_plausibility: f64,
    pub total: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyBand {
    pub lo_zero: f64,
    pub lo_full: f64,
    pub hi_full: f64,
    pub hi_zero: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SizeBounds {
    pub zero_lo: u64,
    pub full_lo: u64,
    pub full_hi: u64,
    pub zero_hi: u64,
}

pub fn entropy_band(kind: Kind) -> EntropyBand {
    match kind {
        Kind::Jpeg | Kind::Png | Kind::Gzip => EntropyBand {
            lo_zero: 5.50,
            lo_full: 7.00,
            hi_full: 7.99,
            hi_zero: 8.00,
        },
        Kind::Mp4 => EntropyBand {
            lo_zero: 3.00,
            lo_full: 6.00,
            hi_full: 7.99,
            hi_zero: 8.00,
        },
        Kind::Zip | Kind::Pdf => EntropyBand {
            lo_zero: 1.00,
            lo_full: 3.00,
            hi_full: 7.99,
            hi_zero: 8.00,
        },
        Kind::Sqlite => EntropyBand {
            lo_zero: 0.50,
            lo_full: 1.50,
            hi_full: 7.90,
            hi_zero: 8.00,
        },
    }
}

pub fn size_bounds(kind: Kind) -> SizeBounds {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    match kind {
        Kind::Jpeg => SizeBounds { zero_lo: 107, full_lo: KIB, full_hi: 16 * MIB, zero_hi: 64 * MIB },
        Kind::Png => SizeBounds { zero_lo: 67, full_lo: 512, full_hi: 16 * MIB, zero_hi: 64 * MIB },
        Kind::Pdf => SizeBounds { zero_lo: 300, full_lo: KIB, full_hi: 32 * MIB, zero_hi: 128 * MIB },
        Kind::Zip => SizeBounds { zero_lo: 22, full_lo: 256, full_hi: 64 * MIB, zero_hi: 256 * MIB },
        Kind::Sqlite => SizeBounds { zero_lo: 512, full_lo: 4 * KIB, full_hi: 128 * MIB, zero_hi: 512 * MIB },
        Kind::Mp4 => SizeBounds { zero_lo: 16, full_lo: 4 * KIB, full_hi: 128 * MIB, zero_hi: 512 * MIB },
        Kind::Gzip => SizeBounds { zero_lo: 20, full_lo: 128, full_hi: 32 * MIB, zero_hi: 128 * MIB },
    }
}

pub fn kind_defines_footer(kind: Kind) -> bool {
    signature_for(kind).map(|s| s.footer.is_some()).unwrap_or(false)
}

pub fn signature_integrity(kind: Kind, sig_ok: bool, footer_found: bool) -> f64 {
    if !sig_ok {
        return SIG_HEADER_MISMATCH;
    }
    if !kind_defines_footer(kind) {
        return SIG_NO_FOOTER_DEFINED;
    }
    if footer_found {
        SIG_HEADER_AND_FOOTER
    } else {
        SIG_HEADER_ONLY
    }
}

pub fn structural_validity(v: &Validation) -> f64 {
    clamp01(v.score)
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c != 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    if h < 0.0 {
        0.0
    } else {
        h
    }
}

pub fn entropy_consistency(kind: Kind, data: &[u8]) -> f64 {
    if data.len() < MIN_ENTROPY_SAMPLE {
        return ENTROPY_UNKNOWN;
    }
    let e = shannon_entropy(data);
    let b = entropy_band(kind);
    trapezoid(e, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero)
}

pub fn size_plausibility(kind: Kind, len: u64) -> f64 {
    if len == 0 {
        return 0.0;
    }
    let b = size_bounds(kind);
    let l2 = |v: u64| (v.max(1) as f64).log2();
    trapezoid(
        l2(len),
        l2(b.zero_lo),
        l2(b.full_lo),
        l2(b.full_hi),
        l2(b.zero_hi),
    )
}

pub fn confidence(
    kind: Kind,
    sig_ok: bool,
    footer_found: bool,
    v: &Validation,
    data: &[u8],
) -> Confidence {
    let signature_integrity = signature_integrity(kind, sig_ok, footer_found);
    let structural_validity = structural_validity(v);
    let entropy_consistency = entropy_consistency(kind, data);
    let size_plausibility = size_plausibility(kind, data.len() as u64);

    let total = clamp01(
        W_SIGNATURE * signature_integrity
            + W_STRUCTURE * structural_validity
            + W_ENTROPY * entropy_consistency
            + W_SIZE * size_plausibility,
    );

    Confidence {
        signature_integrity,
        structural_validity,
        entropy_consistency,
        size_plausibility,
        total,
    }
}

fn clamp01(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

fn trapezoid(x: f64, lo_zero: f64, lo_full: f64, hi_full: f64, hi_zero: f64) -> f64 {
    if x <= lo_zero || x >= hi_zero {
        0.0
    } else if x < lo_full {
        clamp01((x - lo_zero) / (lo_full - lo_zero))
    } else if x <= hi_full {
        1.0
    } else {
        clamp01((hi_zero - x) / (hi_zero - hi_full))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(valid: bool, score: f64, end: Option<u64>) -> Validation {
        Validation {
            valid,
            end,
            score,
            detail: String::from("stub"),
        }
    }

    fn uniform_over(k: usize, reps: usize) -> Vec<u8> {
        assert!((1..=256).contains(&k));
        (0..k * reps).map(|i| (i % k) as u8).collect()
    }

    fn plateau_corpus() -> Vec<u8> {
        uniform_over(181, 1200)
    }

    fn high_entropy(n: usize) -> Vec<u8> {
        let mut s: u64 = 0x2545_F491_4F6C_DD1D;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    fn all_kinds() -> Vec<Kind> {
        vec![
            Kind::Jpeg,
            Kind::Png,
            Kind::Pdf,
            Kind::Zip,
            Kind::Sqlite,
            Kind::Mp4,
            Kind::Gzip,
        ]
    }

    #[test]
    fn weights_sum_to_one() {
        assert!((W_SIGNATURE + W_STRUCTURE + W_ENTROPY + W_SIZE - 1.0).abs() < 1e-12);
    }

    #[test]
    fn published_weights_are_the_published_numbers() {
        assert_eq!(W_SIGNATURE, 0.40);
        assert_eq!(W_STRUCTURE, 0.35);
        assert_eq!(W_ENTROPY, 0.15);
        assert_eq!(W_SIZE, 0.10);
    }

    #[test]
    fn total_is_the_weighted_sum_of_the_four_reported_terms() {
        let data = high_entropy(200_000);
        for k in all_kinds() {
            for (ok, ff, sc) in [
                (true, true, 1.0),
                (true, false, 0.5),
                (false, false, 0.0),
                (true, true, 0.25),
            ] {
                let c = confidence(k, ok, ff, &v(sc > 0.0, sc, None), &data);
                let expect = W_SIGNATURE * c.signature_integrity
                    + W_STRUCTURE * c.structural_validity
                    + W_ENTROPY * c.entropy_consistency
                    + W_SIZE * c.size_plausibility;
                assert!(
                    (c.total - expect).abs() < 1e-12,
                    "{:?} total {} != weighted sum {}",
                    k.as_str(),
                    c.total,
                    expect
                );
            }
        }
    }

    #[test]
    fn every_term_is_within_zero_and_one() {
        let corpora: Vec<Vec<u8>> = vec![
            vec![],
            vec![0u8; 1],
            vec![0u8; 4096],
            vec![0xFFu8; 100_000],
            high_entropy(2048),
            high_entropy(500_000),
        ];
        for k in all_kinds() {
            for d in &corpora {
                for sc in [-5.0, 0.0, 0.5, 1.0, 7.0, f64::NAN] {
                    let c = confidence(k, true, true, &v(true, sc, None), d);
                    for (name, t) in [
                        ("signature_integrity", c.signature_integrity),
                        ("structural_validity", c.structural_validity),
                        ("entropy_consistency", c.entropy_consistency),
                        ("size_plausibility", c.size_plausibility),
                        ("total", c.total),
                    ] {
                        assert!(
                            (0.0..=1.0).contains(&t),
                            "{} out of range: {} for {} len {}",
                            name,
                            t,
                            k.as_str(),
                            d.len()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn term1_header_mismatch_is_zero_for_every_kind_regardless_of_footer() {
        for k in all_kinds() {
            assert_eq!(signature_integrity(k, false, false), 0.00);
            assert_eq!(signature_integrity(k, false, true), 0.00);
        }
    }

    #[test]
    fn term1_ladder_for_kinds_that_define_a_terminator() {
        for k in all_kinds() {
            if !kind_defines_footer(k) {
                continue;
            }
            assert_eq!(
                signature_integrity(k, true, true),
                1.00,
                "{} header+footer",
                k.as_str()
            );
            assert_eq!(
                signature_integrity(k, true, false),
                0.50,
                "{} header only",
                k.as_str()
            );
        }
    }

    #[test]
    fn term1_footerless_kinds_are_capped_at_the_published_ceiling() {
        for k in all_kinds() {
            if kind_defines_footer(k) {
                continue;
            }
            assert_eq!(signature_integrity(k, true, false), 0.75, "{}", k.as_str());
            assert_eq!(signature_integrity(k, true, true), 0.75, "{}", k.as_str());
        }
    }

    #[test]
    fn term1_rungs_are_strictly_ordered() {
        assert!(SIG_HEADER_MISMATCH < SIG_HEADER_ONLY);
        assert!(SIG_HEADER_ONLY < SIG_NO_FOOTER_DEFINED);
        assert!(SIG_NO_FOOTER_DEFINED < SIG_HEADER_AND_FOOTER);
    }

    #[test]
    fn term1_footerless_ceiling_caps_the_whole_score_at_0_90() {
        let data = plateau_corpus();
        for k in all_kinds() {
            if kind_defines_footer(k) {
                continue;
            }
            let c = confidence(k, true, true, &v(true, 1.0, Some(217_200)), &data);
            assert!(
                (c.total - 0.90).abs() < 1e-12,
                "{} best case is {}, expected 0.90",
                k.as_str(),
                c.total
            );
        }
    }

    #[test]
    fn term1_never_consults_structure_or_payload() {
        let a = signature_integrity(Kind::Jpeg, true, true);
        let b = signature_integrity(Kind::Jpeg, true, true);
        assert_eq!(a, b);
        let c1 = confidence(Kind::Jpeg, true, true, &v(false, 0.0, None), &high_entropy(2048));
        let c2 = confidence(Kind::Jpeg, true, true, &v(true, 1.0, Some(9)), &vec![0u8; 200_000]);
        assert_eq!(c1.signature_integrity, c2.signature_integrity);
    }

    #[test]
    fn term2_is_the_validation_score_verbatim() {
        for s in [0.0, 0.125, 0.25, 0.5, 0.75, 0.9999, 1.0] {
            assert_eq!(structural_validity(&v(true, s, None)), s);
        }
    }

    #[test]
    fn term2_clamps_out_of_range_scores_but_does_not_otherwise_transform_them() {
        assert_eq!(structural_validity(&v(true, 1.5, None)), 1.0);
        assert_eq!(structural_validity(&v(true, -0.5, None)), 0.0);
        assert_eq!(structural_validity(&v(true, f64::NAN, None)), 0.0);
        assert_eq!(structural_validity(&v(true, f64::INFINITY, None)), 1.0);
    }

    #[test]
    fn term2_ignores_the_valid_flag_by_design() {
        assert_eq!(structural_validity(&v(false, 0.8, None)), 0.8);
        assert_eq!(structural_validity(&v(true, 0.8, None)), 0.8);
    }

    #[test]
    fn term2_rejected_structure_costs_exactly_the_structure_weight() {
        let data = high_entropy(100_000);
        let good = confidence(Kind::Jpeg, true, true, &v(true, 1.0, Some(100_000)), &data);
        let bad = confidence(Kind::Jpeg, true, true, &v(false, 0.0, None), &data);
        assert!((good.total - bad.total - W_STRUCTURE).abs() < 1e-12);
    }

    #[test]
    fn entropy_of_empty_input_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_of_one_repeated_symbol_is_zero() {
        assert_eq!(shannon_entropy(&[0x41u8; 4096]), 0.0);
        assert_eq!(shannon_entropy(&[0x00u8; 1]), 0.0);
    }

    #[test]
    fn entropy_of_two_equiprobable_symbols_is_one_bit() {
        let d: Vec<u8> = (0..4096).map(|i| if i % 2 == 0 { 0u8 } else { 1u8 }).collect();
        assert!((shannon_entropy(&d) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn entropy_of_all_256_bytes_equally_is_exactly_eight_bits() {
        let d: Vec<u8> = (0..=255u8).cycle().take(256 * 64).collect();
        assert!((shannon_entropy(&d) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn entropy_of_sixteen_equiprobable_symbols_is_four_bits() {
        let d: Vec<u8> = (0..16u8).cycle().take(16 * 256).collect();
        assert!((shannon_entropy(&d) - 4.0).abs() < 1e-12);
    }

    #[test]
    fn entropy_never_leaves_zero_to_eight() {
        for d in [
            vec![],
            vec![7u8; 10_000],
            high_entropy(50_000),
            (0..=255u8).collect::<Vec<u8>>(),
        ] {
            let e = shannon_entropy(&d);
            assert!((0.0..=8.0).contains(&e), "entropy {} out of range", e);
        }
    }

    #[test]
    fn term3_short_objects_report_no_information_not_a_score() {
        for n in [0usize, 1, 100, MIN_ENTROPY_SAMPLE - 1] {
            let d = high_entropy(n);
            assert_eq!(
                entropy_consistency(Kind::Jpeg, &d),
                ENTROPY_UNKNOWN,
                "len {}",
                n
            );
        }
        let d = high_entropy(MIN_ENTROPY_SAMPLE);
        assert_ne!(entropy_consistency(Kind::Jpeg, &d), ENTROPY_UNKNOWN);
    }

    #[test]
    fn term3_zero_entropy_payload_scores_zero_for_every_kind() {
        let d = vec![0u8; 100_000];
        for k in all_kinds() {
            assert_eq!(
                entropy_consistency(k, &d),
                0.0,
                "{} scored a run of zeros",
                k.as_str()
            );
        }
    }

    #[test]
    fn term3_every_kind_scores_full_on_a_payload_inside_its_plateau() {
        let d = plateau_corpus();
        let e = shannon_entropy(&d);
        assert!(
            (e - 181f64.log2()).abs() < 1e-12,
            "corpus entropy {} is not log2(181)",
            e
        );
        assert!((7.00..=7.90).contains(&e), "corpus entropy {} left the plateau", e);
        for k in all_kinds() {
            assert_eq!(entropy_consistency(k, &d), 1.0, "{}", k.as_str());
        }
    }

    #[test]
    fn term3_an_exactly_uniform_payload_is_penalised_not_rewarded() {
        let d = uniform_over(256, 800);
        assert!((shannon_entropy(&d) - 8.0).abs() < 1e-12);
        for k in all_kinds() {
            assert_eq!(entropy_consistency(k, &d), 0.0, "{} rewarded a uniform block", k.as_str());
        }
    }

    #[test]
    fn term3_band_edges_are_the_published_edges() {
        for k in all_kinds() {
            let b = entropy_band(k);
            assert!(b.lo_zero < b.lo_full && b.lo_full <= b.hi_full && b.hi_full < b.hi_zero);
            assert_eq!(trapezoid(b.lo_zero, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero), 0.0);
            assert_eq!(trapezoid(b.lo_full, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero), 1.0);
            assert_eq!(trapezoid(b.hi_full, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero), 1.0);
            assert_eq!(trapezoid(b.hi_zero, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero), 0.0);
            let mid = (b.lo_zero + b.lo_full) / 2.0;
            let s = trapezoid(mid, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero);
            assert!((s - 0.5).abs() < 1e-12, "{} midpoint {}", k.as_str(), s);
        }
    }

    #[test]
    fn term3_published_bands_contain_the_measured_fixture_ranges() {
        let measured: &[(Kind, f64, f64)] = &[
            (Kind::Jpeg, 7.8716, 7.8995),
            (Kind::Png, 7.7986, 7.8414),
            (Kind::Gzip, 7.8669, 7.8713),
            (Kind::Zip, 7.8835, 7.8878),
            (Kind::Mp4, 7.7600, 7.7646),
            (Kind::Pdf, 7.9079, 7.9491),
            (Kind::Sqlite, 5.3189, 5.5076),
        ];
        for (k, lo, hi) in measured {
            let b = entropy_band(*k);
            assert!(
                *lo >= b.lo_full && *hi <= b.hi_full,
                "{}: measured {}..{} outside plateau {}..{}",
                k.as_str(),
                lo,
                hi,
                b.lo_full,
                b.hi_full
            );
        }
    }

    #[test]
    fn term3_residue_entropy_scores_below_planted_entropy_for_jpeg() {
        let residue = [6.1800, 6.6964, 6.8861, 6.9463, 7.0426, 7.1645, 7.3280, 7.4172];
        let b = entropy_band(Kind::Jpeg);
        let planted_lo = trapezoid(7.8716, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero);
        assert_eq!(planted_lo, 1.0);
        for e in residue {
            let s = trapezoid(e, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero);
            assert!(s <= planted_lo, "residue {} scored {} >= planted", e, s);
        }
        assert!(trapezoid(6.1800, b.lo_zero, b.lo_full, b.hi_full, b.hi_zero) < 0.5);
    }

    #[test]
    fn term4_zero_length_scores_zero() {
        for k in all_kinds() {
            assert_eq!(size_plausibility(k, 0), 0.0, "{}", k.as_str());
        }
    }

    #[test]
    fn term4_below_the_format_floor_scores_zero() {
        for k in all_kinds() {
            let b = size_bounds(k);
            assert_eq!(size_plausibility(k, b.zero_lo), 0.0, "{}", k.as_str());
            assert_eq!(size_plausibility(k, b.zero_lo / 2), 0.0, "{}", k.as_str());
            assert_eq!(size_plausibility(k, 1), 0.0, "{}", k.as_str());
        }
    }

    #[test]
    fn term4_plateau_scores_full_and_bounds_are_ordered() {
        for k in all_kinds() {
            let b = size_bounds(k);
            assert!(b.zero_lo < b.full_lo && b.full_lo < b.full_hi && b.full_hi < b.zero_hi);
            assert_eq!(size_plausibility(k, b.full_lo), 1.0, "{}", k.as_str());
            assert_eq!(size_plausibility(k, b.full_hi), 1.0, "{}", k.as_str());
            let geo = ((b.full_lo as f64) * (b.full_hi as f64)).sqrt() as u64;
            assert_eq!(size_plausibility(k, geo), 1.0, "{}", k.as_str());
        }
    }

    #[test]
    fn term4_above_the_ceiling_decays_to_zero() {
        for k in all_kinds() {
            let b = size_bounds(k);
            assert_eq!(size_plausibility(k, b.zero_hi), 0.0, "{}", k.as_str());
            assert_eq!(size_plausibility(k, b.zero_hi * 4), 0.0, "{}", k.as_str());
            let mid = ((b.full_hi as f64) * (b.zero_hi as f64)).sqrt() as u64;
            let s = size_plausibility(k, mid);
            assert!(
                s > 0.0 && s < 1.0,
                "{} geometric midpoint above ceiling scored {}",
                k.as_str(),
                s
            );
        }
    }

    #[test]
    fn term4_is_monotone_across_the_low_ramp_and_the_high_ramp() {
        for k in all_kinds() {
            let b = size_bounds(k);
            let mut last = -1.0;
            let mut n = b.zero_lo;
            while n < b.full_lo {
                let s = size_plausibility(k, n);
                assert!(s >= last, "{} not monotone rising at {}", k.as_str(), n);
                last = s;
                n = (n as f64 * 1.1) as u64 + 1;
            }
            let mut last = 2.0;
            let mut n = b.full_hi;
            while n < b.zero_hi {
                let s = size_plausibility(k, n);
                assert!(s <= last, "{} not monotone falling at {}", k.as_str(), n);
                last = s;
                n = (n as f64 * 1.1) as u64 + 1;
            }
        }
    }

    #[test]
    fn term4_the_shipped_max_len_clamp_is_penalised_by_this_table() {
        for k in all_kinds() {
            let b = size_bounds(k);
            let sig = crate::signature::signature_for(k)
                .unwrap_or_else(|| panic!("{} missing from SIGNATURES", k.as_str()));
            assert!(
                sig.max_len <= b.zero_hi,
                "{}: max_len {} exceeds this table's ceiling {}",
                k.as_str(),
                sig.max_len,
                b.zero_hi
            );
            let at_clamp = size_plausibility(k, sig.max_len);
            assert!(
                at_clamp <= 0.5,
                "{}: an object at the {}-byte clamp still scores {} on size",
                k.as_str(),
                sig.max_len,
                at_clamp
            );
        }
    }

    #[test]
    fn term4_published_bounds_contain_the_measured_fixture_sizes() {
        let measured: &[(Kind, u64, u64)] = &[
            (Kind::Jpeg, 92_851, 108_462),
            (Kind::Png, 158_522, 260_595),
            (Kind::Gzip, 54_871, 127_302),
            (Kind::Zip, 32_453, 79_397),
            (Kind::Mp4, 66_689, 221_041),
            (Kind::Pdf, 38_408, 54_214),
            (Kind::Sqlite, 110_592, 221_184),
        ];
        for (k, lo, hi) in measured {
            assert_eq!(size_plausibility(*k, *lo), 1.0, "{} min {}", k.as_str(), lo);
            assert_eq!(size_plausibility(*k, *hi), 1.0, "{} max {}", k.as_str(), hi);
        }
    }

    #[test]
    fn a_perfect_recovery_of_a_footer_bearing_kind_scores_one() {
        let d = plateau_corpus();
        for k in all_kinds() {
            if !kind_defines_footer(k) {
                continue;
            }
            let c = confidence(k, true, true, &v(true, 1.0, Some(217_200)), &d);
            assert!(
                (c.total - 1.0).abs() < 1e-12,
                "{} perfect recovery scored {}",
                k.as_str(),
                c.total
            );
        }
    }

    #[test]
    fn a_structurally_rejected_candidate_cannot_reach_the_admission_gate() {
        let d = plateau_corpus();
        for k in all_kinds() {
            let c = confidence(k, true, true, &v(false, 0.0, None), &d);
            assert!(
                c.total <= NON_STRUCTURE_CEILING + 1e-12,
                "{} rejected candidate reached {}",
                k.as_str(),
                c.total
            );
            assert!(
                c.total < MIN_CONFIDENCE,
                "{} rejected candidate reached {} against the {} gate",
                k.as_str(),
                c.total,
                MIN_CONFIDENCE
            );
        }
    }

    #[test]
    fn the_breach_point_is_derived_from_the_weights_and_the_gate() {
        let expect = (MIN_CONFIDENCE - (W_SIGNATURE + W_ENTROPY + W_SIZE)) / W_STRUCTURE;
        assert!((STRUCTURAL_BREACH_POINT - expect).abs() < 1e-15);
        assert!((NON_STRUCTURE_CEILING - 0.65).abs() < 1e-12);
        assert!(
            (STRUCTURAL_BREACH_POINT - 0.285_714_285_714_285_7).abs() < 1e-9,
            "breach point is {STRUCTURAL_BREACH_POINT}"
        );
        assert!(
            STRUCTURAL_BREACH_POINT > 0.0 && STRUCTURAL_BREACH_POINT <= 1.0,
            "the gate {MIN_CONFIDENCE} is unusable against a ceiling of {NON_STRUCTURE_CEILING}"
        );
    }

    #[test]
    fn a_decoy_at_the_breach_point_reaches_the_gate_and_below_it_does_not() {
        let d = plateau_corpus();
        let at = confidence(
            Kind::Jpeg,
            true,
            true,
            &v(false, STRUCTURAL_BREACH_POINT, None),
            &d,
        );
        assert!(
            at.total >= MIN_CONFIDENCE - 1e-12,
            "a decoy at the breach point scored {} against the {} gate",
            at.total,
            MIN_CONFIDENCE
        );
        let below = confidence(
            Kind::Jpeg,
            true,
            true,
            &v(false, STRUCTURAL_BREACH_POINT - 0.001, None),
            &d,
        );
        assert!(
            below.total < MIN_CONFIDENCE,
            "a decoy just below the breach point scored {}",
            below.total
        );
    }

    #[test]
    fn the_gate_sits_strictly_inside_the_measured_separation() {
        assert!(MIN_CONFIDENCE > 0.65, "the gate admits the highest measured false positive");
        assert!(MIN_CONFIDENCE <= 0.90, "the gate rejects the lowest measured true positive");
        let d = plateau_corpus();
        let footerless_best = confidence(Kind::Gzip, true, true, &v(true, 1.0, Some(217_200)), &d);
        assert!((footerless_best.total - 0.90).abs() < 1e-12);
        assert!(
            footerless_best.total >= MIN_CONFIDENCE,
            "the gate discards a byte-perfect footerless recovery"
        );
    }

    #[test]
    fn the_published_separation_holds_at_its_two_edges() {
        let d = plateau_corpus();
        let worst_tp = confidence(Kind::Gzip, true, false, &v(true, 1.0, Some(217_200)), &d);
        let best_fp = confidence(Kind::Jpeg, true, true, &v(false, 0.0, None), &d);
        assert!((worst_tp.total - 0.90).abs() < 1e-12, "{}", worst_tp.total);
        assert!((best_fp.total - 0.65).abs() < 1e-12, "{}", best_fp.total);
        assert!((worst_tp.total - best_fp.total - 0.25).abs() < 1e-12);
    }
}
