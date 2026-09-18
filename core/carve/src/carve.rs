use crate::bifragment::{
    search, Plan, Stop, DEFAULT_MAX_OBJECT_BYTES, MAX_FIRST_FRAGMENT_CLUSTERS, MAX_OBJECT_BYTES,
};
use crate::confidence::{
    confidence, kind_defines_footer, shannon_entropy, size_bounds, Confidence, MIN_CONFIDENCE,
    MIN_ENTROPY_SAMPLE, SIG_HEADER_AND_FOOTER, SIG_HEADER_MISMATCH, SIG_HEADER_ONLY,
    SIG_NO_FOOTER_DEFINED,
};
use crate::signature::{next_footer, scan, signature_for, Candidate, SIGNATURES};
use crate::structure::{validate, Validation};
use crate::Kind;

#[derive(Debug, Clone, PartialEq)]
pub struct CarveOpts {
    pub min_confidence: f64,

    pub dedup: bool,

    pub report_rejected: bool,

    pub residue_window: Option<u64>,

    pub reassemble: bool,

    pub cluster_bytes: u64,

    pub max_gap_clusters: u64,
}

pub const DEFAULT_CLUSTER_BYTES: u64 = 2048;

pub const DEFAULT_MAX_GAP_CLUSTERS: u64 = 128;

impl Default for CarveOpts {
    fn default() -> CarveOpts {
        CarveOpts {
            min_confidence: MIN_CONFIDENCE,
            dedup: true,
            report_rejected: true,
            residue_window: None,
            reassemble: false,
            cluster_bytes: DEFAULT_CLUSTER_BYTES,
            max_gap_clusters: DEFAULT_MAX_GAP_CLUSTERS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assembly {
    Contiguous,
    Reassembled,
    SignatureSpan,
}

impl Assembly {
    pub fn as_str(&self) -> &'static str {
        match self {
            Assembly::Contiguous => "contiguous",
            Assembly::Reassembled => "reassembled",
            Assembly::SignatureSpan => "signature-span",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureObs {
    pub header_matched: bool,
    pub footer_defined: bool,
    pub footer_found: bool,
    pub ladder_rung: &'static str,
}

pub const REASON_BELOW_GATE: &str = "below-min-confidence";
pub const REASON_BELOW_GATE_STRUCTURE_INVALID: &str = "below-min-confidence-structure-invalid";

#[derive(Debug, Clone, PartialEq)]
pub struct Recovered {
    pub kind: Kind,
    pub offset: u64,
    pub length: u64,
    pub extents: Vec<Extent>,
    pub assembly: Assembly,
    pub sha256: String,
    pub signature: SignatureObs,
    pub structure: Validation,
    pub entropy_bits_per_byte: f64,
    pub entropy_sampled: bool,
    pub confidence: Confidence,
    pub admitted: bool,
    pub reason_code: Option<&'static str>,
    pub reason: Option<String>,
}

impl Recovered {
    pub fn id(&self) -> String {
        format!("{}@{}", self.kind.as_str(), self.offset)
    }

    pub fn end(&self) -> u64 {
        self.offset + self.length
    }

    pub fn claims(&self) -> Vec<(u64, u64)> {
        self.extents
            .iter()
            .map(|e| (e.offset, e.offset + e.length))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolvedCost {
    pub id: String,
    pub validations: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReassemblyStats {
    pub attempted: usize,
    pub solved: usize,
    pub refused_contiguous: usize,
    pub exhausted: usize,
    pub ambiguous: usize,
    pub degenerate: usize,
    pub budget: usize,
    pub validations: u64,
    pub accepted_splices: u64,
    pub solved_cost: Vec<SolvedCost>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CarveReport {
    pub scanned: usize,
    pub suppressed: usize,
    pub withheld_rejected: usize,
    pub records: Vec<Recovered>,
    pub reassembly: ReassemblyStats,
    pub opts: CarveOpts,
}

impl CarveReport {
    pub fn admitted(&self) -> usize {
        self.records.iter().filter(|r| r.admitted).count()
    }
    pub fn rejected(&self) -> usize {
        self.records.len() - self.admitted()
    }
}

fn rung_name(v: f64) -> &'static str {
    if v == SIG_HEADER_AND_FOOTER {
        "header-and-footer"
    } else if v == SIG_NO_FOOTER_DEFINED {
        "no-footer-defined"
    } else if v == SIG_HEADER_ONLY {
        "header-only"
    } else if v == SIG_HEADER_MISMATCH {
        "header-mismatch"
    } else {
        panic!("signature_integrity returned {v}, which is not a published ladder rung")
    }
}

fn header_matches(kind: Kind, buf: &[u8]) -> bool {
    SIGNATURES.iter().any(|s| {
        s.kind == kind && buf.len() >= s.header.len() && &buf[..s.header.len()] == s.header
    })
}

fn footer_in_sequence(buf: &[u8], kind: Kind, span: u64) -> bool {
    let Some(sig) = signature_for(kind) else {
        return false;
    };
    next_footer(buf, kind, sig.header.len() as u64, span).is_some()
}

fn fallback_window(kind: Kind, opts: &CarveOpts) -> u64 {
    opts.residue_window
        .unwrap_or_else(|| size_bounds(kind).full_lo)
}

fn reassembly_span_ceiling(kind: Kind, avail: u64) -> u64 {
    let mut max_len = DEFAULT_MAX_OBJECT_BYTES;
    for sig in SIGNATURES {
        if sig.kind == kind {
            if sig.max_len > 0 {
                max_len = sig.max_len;
            }
            break;
        }
    }
    max_len.min(MAX_OBJECT_BYTES).min(avail)
}

fn reassembly_plan(image_len: u64, kind: Kind, header_at: u64, opts: &CarveOpts) -> Option<Plan> {
    let cluster = opts.cluster_bytes;
    if cluster == 0 || header_at >= image_len {
        return None;
    }
    let max_gap_bytes = opts.max_gap_clusters.checked_mul(cluster)?;
    let span = reassembly_span_ceiling(kind, image_len - header_at);
    Plan::new(
        image_len,
        span,
        header_at,
        max_gap_bytes,
        cluster,
        MAX_FIRST_FRAGMENT_CLUSTERS.saturating_mul(cluster),
    )
}

fn try_reassemble(
    image: &[u8],
    cand: &Candidate,
    opts: &CarveOpts,
    tally: &mut ReassemblyStats,
) -> Option<Recovered> {
    tally.attempted += 1;
    let kind = cand.kind;
    let Some(plan) = reassembly_plan(image.len() as u64, kind, cand.header_at, opts) else {
        tally.degenerate += 1;
        return None;
    };

    let out = search(image, &plan, |buf| validate(kind, buf));
    tally.validations += out.validations;
    tally.accepted_splices += out.accepted;
    match out.stop {
        Stop::Solved => tally.solved += 1,
        Stop::Contiguous => tally.refused_contiguous += 1,
        Stop::Exhausted => tally.exhausted += 1,
        Stop::Ambiguous => tally.ambiguous += 1,
        Stop::Budget => tally.budget += 1,
        Stop::Degenerate => tally.degenerate += 1,
    }

    let r = out.found?;
    if r.extents.len() < 2 {
        return None;
    }

    let mut data: Vec<u8> = Vec::new();
    let mut extents: Vec<Extent> = Vec::with_capacity(r.extents.len());
    for &(offset, length) in &r.extents {
        let lo = offset as usize;
        let hi = lo.checked_add(length as usize)?;
        if hi > image.len() || length == 0 {
            return None;
        }
        data.extend_from_slice(&image[lo..hi]);
        extents.push(Extent { offset, length });
    }
    let total = data.len() as u64;
    let v = validate(kind, &data);
    let header_matched = header_matches(kind, &data);
    let footer_found = footer_in_sequence(&data, kind, total);

    let rec = record(
        kind,
        extents[0].offset,
        extents,
        Assembly::Reassembled,
        &data,
        header_matched,
        footer_found,
        v,
        opts,
    );
    tally.solved_cost.push(SolvedCost {
        id: rec.id(),
        validations: r.validations,
    });
    Some(rec)
}

#[allow(clippy::too_many_arguments)]
fn record(
    kind: Kind,
    offset: u64,
    extents: Vec<Extent>,
    assembly: Assembly,
    data: &[u8],
    header_matched: bool,
    footer_found: bool,
    v: Validation,
    opts: &CarveOpts,
) -> Recovered {
    let length: u64 = extents.iter().map(|e| e.length).sum();
    let c = confidence(kind, header_matched, footer_found, &v, data);
    let admitted = c.total >= opts.min_confidence;

    let (reason_code, reason) = if admitted {
        (None, None)
    } else {
        let code = if v.valid {
            REASON_BELOW_GATE
        } else {
            REASON_BELOW_GATE_STRUCTURE_INVALID
        };
        let line = format!(
            "confidence {:.4} below MIN_CONFIDENCE {:.4}; structure: {}",
            c.total, opts.min_confidence, v.detail
        );
        (Some(code), Some(line))
    };

    Recovered {
        kind,
        offset,
        length,
        extents,
        assembly,
        sha256: sha256_hex(data),
        signature: SignatureObs {
            header_matched,
            footer_defined: kind_defines_footer(kind),
            footer_found,
            ladder_rung: rung_name(c.signature_integrity),
        },
        structure: v,
        entropy_bits_per_byte: shannon_entropy(data),
        entropy_sampled: data.len() >= MIN_ENTROPY_SAMPLE,
        confidence: c,
        admitted,
        reason_code,
        reason,
    }
}

fn score(
    image: &[u8],
    cand: &Candidate,
    opts: &CarveOpts,
    tally: &mut ReassemblyStats,
) -> Recovered {
    let at = cand.header_at as usize;
    let sig = signature_for(cand.kind).expect("every scanned kind has a signature table row");

    let view_end = (cand.header_at.saturating_add(sig.max_len)).min(image.len() as u64) as usize;
    let view = &image[at..view_end];

    let v = validate(cand.kind, view);

    if opts.reassemble && !v.valid {
        if let Some(rec) = try_reassemble(image, cand, opts, tally) {
            return rec;
        }
    }

    let (length, assembly) = match v.end {
        Some(end) if end > 0 => (end.min(view.len() as u64), Assembly::Contiguous),
        _ => {
            let span = match (sig.footer, cand.footer_at) {
                (Some(f), Some(footer_at)) => footer_at + f.len() as u64 - cand.header_at,
                _ => fallback_window(cand.kind, opts),
            };
            (
                span.min(image.len() as u64 - cand.header_at).max(1),
                Assembly::SignatureSpan,
            )
        }
    };

    let data = &image[at..at + length as usize];
    let header_matched = header_matches(cand.kind, view);
    let footer_found = footer_in_sequence(view, cand.kind, length);

    record(
        cand.kind,
        cand.header_at,
        vec![Extent {
            offset: cand.header_at,
            length,
        }],
        assembly,
        data,
        header_matched,
        footer_found,
        v,
        opts,
    )
}

pub fn carve(image: &[u8], opts: &CarveOpts) -> CarveReport {
    let cands = scan(image);
    let scanned = cands.len();

    let mut reassembly = ReassemblyStats::default();
    let mut scored: Vec<Recovered> = cands
        .iter()
        .map(|c| score(image, c, opts, &mut reassembly))
        .collect();

    let mut suppressed = 0usize;
    if opts.dedup {
        let mut order: Vec<usize> = (0..scored.len()).collect();
        order.sort_by(|&a, &b| {
            let (x, y) = (&scored[a], &scored[b]);
            y.admitted
                .cmp(&x.admitted)
                .then(
                    y.confidence
                        .total
                        .partial_cmp(&x.confidence.total)
                        .unwrap_or(core::cmp::Ordering::Equal),
                )
                .then(y.length.cmp(&x.length))
                .then(x.offset.cmp(&y.offset))
                .then(x.kind.as_str().cmp(y.kind.as_str()))
        });

        let mut claimed: Vec<(u64, u64)> = Vec::new();
        let mut keep = vec![false; scored.len()];

        for &i in &order {
            let r = &scored[i];
            if r.admitted {
                let claims = r.claims();
                if claims.iter().any(|&(lo, hi)| intersects(&claimed, lo, hi)) {
                    suppressed += 1;
                } else {
                    for (lo, hi) in claims {
                        if !intersects(&claimed, lo, hi) {
                            insert_span(&mut claimed, lo, hi);
                        }
                    }
                    keep[i] = true;
                }
            } else if contains(&claimed, r.offset) {
                suppressed += 1;
            } else {
                keep[i] = true;
            }
        }

        let mut kept = Vec::with_capacity(scored.len() - suppressed);
        for (i, r) in scored.into_iter().enumerate() {
            if keep[i] {
                kept.push(r);
            }
        }
        scored = kept;
    }

    let mut withheld_rejected = 0usize;
    if !opts.report_rejected {
        let before = scored.len();
        scored.retain(|r| r.admitted);
        withheld_rejected = before - scored.len();
    }

    scored.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then(a.kind.as_str().cmp(b.kind.as_str()))
    });

    CarveReport {
        scanned,
        suppressed,
        withheld_rejected,
        records: scored,
        reassembly,
        opts: opts.clone(),
    }
}

fn intersects(spans: &[(u64, u64)], lo: u64, hi: u64) -> bool {
    let i = spans.partition_point(|s| s.1 <= lo);
    matches!(spans.get(i), Some(&(s_lo, _)) if s_lo < hi)
}

fn contains(spans: &[(u64, u64)], at: u64) -> bool {
    let i = spans.partition_point(|s| s.1 <= at);
    matches!(spans.get(i), Some(&(lo, hi)) if at >= lo && at < hi)
}

fn insert_span(spans: &mut Vec<(u64, u64)>, lo: u64, hi: u64) {
    let i = spans.partition_point(|s| s.1 <= lo);
    spans.insert(i, (lo, hi));
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn sha256_block(h: &mut [u32; 8], b: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b2, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b2) ^ (a & c) ^ (b2 & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b2;
        b2 = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, add) in h.iter_mut().zip([a, b2, c, d, e, f, g, hh]) {
        *slot = slot.wrapping_add(add);
    }
}

#[derive(Debug, Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buffered: usize,
    len: u64,
}

impl Default for Sha256 {
    fn default() -> Sha256 {
        Sha256::new()
    }
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            h: H0,
            buf: [0u8; 64],
            buffered: 0,
            len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                return;
            }
            let block = self.buf;
            sha256_block(&mut self.h, &block);
            self.buffered = 0;
        }
        let full = data.len() - data.len() % 64;
        let mut i = 0;
        while i < full {
            sha256_block(&mut self.h, &data[i..i + 64]);
            i += 64;
        }
        let rest = &data[full..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bitlen = self.len.wrapping_mul(8);
        let mut tail = Vec::with_capacity(128);
        tail.extend_from_slice(&self.buf[..self.buffered]);
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(&bitlen.to_be_bytes());
        let mut i = 0;
        while i < tail.len() {
            sha256_block(&mut self.h, &tail[i..i + 64]);
            i += 64;
        }
        let mut out = [0u8; 32];
        for (i, v) in self.h.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut s = Sha256::new();
    s.update(data);
    hex(&s.finish())
}

pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0x0F) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_million_a_vector() {
        let mut s = Sha256::new();
        let chunk = vec![b'a'; 1000];
        for _ in 0..1000 {
            s.update(&chunk);
        }
        assert_eq!(
            hex(&s.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha256_streaming_matches_one_shot() {
        let data: Vec<u8> = (0u32..5000).map(|i| (i * 31 % 253) as u8).collect();
        let one = sha256_hex(&data);
        for chunk in [1usize, 7, 63, 64, 65, 4096] {
            let mut s = Sha256::new();
            for part in data.chunks(chunk) {
                s.update(part);
            }
            assert_eq!(hex(&s.finish()), one, "chunk size {chunk}");
        }
    }

    #[test]
    fn sha256_length_field_crosses_a_block_boundary() {
        for n in [55usize, 56, 57, 63, 64, 65] {
            let d = vec![0x5Au8; n];
            let mut s = Sha256::new();
            s.update(&d);
            let a = hex(&s.finish());
            let mut s2 = Sha256::new();
            for b in &d {
                s2.update(&[*b]);
            }
            assert_eq!(a, hex(&s2.finish()), "n = {n}");
        }
    }

    #[test]
    fn interval_membership_and_intersection() {
        let mut spans: Vec<(u64, u64)> = Vec::new();
        insert_span(&mut spans, 100, 200);
        insert_span(&mut spans, 300, 400);
        assert_eq!(spans, vec![(100, 200), (300, 400)]);

        assert!(contains(&spans, 100));
        assert!(contains(&spans, 199));
        assert!(!contains(&spans, 200), "the end is exclusive");
        assert!(!contains(&spans, 250));
        assert!(contains(&spans, 399));

        assert!(intersects(&spans, 150, 160));
        assert!(intersects(&spans, 50, 101), "one byte of overlap is overlap");
        assert!(intersects(&spans, 199, 300));
        assert!(!intersects(&spans, 200, 300), "abutting is not overlapping");
        assert!(!intersects(&spans, 0, 100));
        assert!(!intersects(&spans, 400, 500));
    }

    #[test]
    fn insert_keeps_the_list_sorted_whatever_the_arrival_order() {
        let mut spans: Vec<(u64, u64)> = Vec::new();
        for (lo, hi) in [(500u64, 600u64), (100, 200), (900, 1000), (300, 400)] {
            assert!(!intersects(&spans, lo, hi));
            insert_span(&mut spans, lo, hi);
        }
        assert_eq!(spans, vec![(100, 200), (300, 400), (500, 600), (900, 1000)]);
    }

    #[test]
    fn the_default_gate_is_the_exported_const_and_not_a_literal() {
        assert_eq!(CarveOpts::default().min_confidence, MIN_CONFIDENCE);
    }

    #[test]
    fn reassembly_is_off_by_default_and_its_geometry_comes_from_named_consts() {
        let d = CarveOpts::default();
        assert!(
            !d.reassemble,
            "the default engine is the contiguous engine whose numbers are published"
        );
        assert_eq!(d.cluster_bytes, DEFAULT_CLUSTER_BYTES);
        assert_eq!(d.max_gap_clusters, DEFAULT_MAX_GAP_CLUSTERS);
    }

    #[test]
    fn the_default_fallback_window_is_the_full_size_credit_floor() {
        let opts = CarveOpts::default();
        for k in [
            Kind::Jpeg,
            Kind::Png,
            Kind::Pdf,
            Kind::Zip,
            Kind::Sqlite,
            Kind::Mp4,
            Kind::Gzip,
        ] {
            assert_eq!(fallback_window(k, &opts), size_bounds(k).full_lo);
        }
        let forced = CarveOpts {
            residue_window: Some(4096),
            ..CarveOpts::default()
        };
        assert_eq!(fallback_window(Kind::Gzip, &forced), 4096);
    }

    #[test]
    fn the_ladder_rung_names_come_from_the_published_consts() {
        assert_eq!(rung_name(SIG_HEADER_AND_FOOTER), "header-and-footer");
        assert_eq!(rung_name(SIG_NO_FOOTER_DEFINED), "no-footer-defined");
        assert_eq!(rung_name(SIG_HEADER_ONLY), "header-only");
        assert_eq!(rung_name(SIG_HEADER_MISMATCH), "header-mismatch");
    }

    #[test]
    #[should_panic(expected = "not a published ladder rung")]
    fn an_unpublished_term_1_value_is_a_panic_not_a_silent_string() {
        rung_name(0.61);
    }

    fn tiny_gzip(payload: &[u8]) -> Vec<u8> {
        let mut g = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        let n = payload.len() as u16;
        g.push(0x01);
        g.extend_from_slice(&n.to_le_bytes());
        g.extend_from_slice(&(!n).to_le_bytes());
        g.extend_from_slice(payload);
        g.extend_from_slice(&crate::structure::crc32(payload).to_le_bytes());
        g.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        g
    }

    #[test]
    fn an_empty_image_produces_an_empty_report() {
        let r = carve(&[], &CarveOpts::default());
        assert_eq!(r.scanned, 0);
        assert_eq!(r.records.len(), 0);
        assert_eq!(r.admitted(), 0);
        assert_eq!(r.rejected(), 0);
        assert_eq!(r.suppressed, 0);
    }

    #[test]
    fn a_zeroed_image_recovers_nothing() {
        let img = vec![0u8; 1 << 16];
        let r = carve(&img, &CarveOpts::default());
        assert_eq!(r.admitted(), 0, "a wiped image admitted something");
    }

    #[test]
    fn a_planted_object_is_found_and_its_sha256_is_the_bytes_that_were_planted() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);
        let want = sha256_hex(&obj);

        let mut img = vec![0u8; 4096];
        let at = img.len();
        img.extend_from_slice(&obj);
        img.extend_from_slice(&vec![0u8; 4096]);

        let r = carve(&img, &CarveOpts::default());
        let hits: Vec<&Recovered> = r.records.iter().filter(|x| x.admitted).collect();
        assert_eq!(hits.len(), 1, "expected exactly one recovery");
        let hit = hits[0];
        assert_eq!(hit.kind, Kind::Gzip);
        assert_eq!(hit.offset, at as u64);
        assert_eq!(hit.length, obj.len() as u64);
        assert_eq!(hit.assembly, Assembly::Contiguous);
        assert_eq!(hit.extents.len(), 1, "the contiguous engine emits one extent");
        assert_eq!(
            hit.sha256, want,
            "the recovered digest is not the planted object's digest"
        );
        assert_eq!(hit.id(), format!("GZIP@{at}"));
        assert!(hit.reason_code.is_none() && hit.reason.is_none());
    }

    #[test]
    fn admission_is_one_comparison_against_the_gate_and_nothing_else() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let img = tiny_gzip(&payload);

        let r = carve(&img, &CarveOpts::default());
        let rec = &r.records[0];
        assert_eq!(rec.admitted, rec.confidence.total >= MIN_CONFIDENCE);

        let strict = CarveOpts {
            min_confidence: rec.confidence.total + 0.01,
            ..CarveOpts::default()
        };
        let r2 = carve(&img, &strict);
        let rec2 = &r2.records[0];
        assert!(!rec2.admitted);
        assert_eq!(rec2.sha256, rec.sha256);
        assert_eq!(rec2.confidence, rec.confidence);
        assert!(rec2.reason.as_ref().unwrap().contains(&rec2.structure.detail));
    }

    #[test]
    fn structure_valid_is_reported_but_is_not_a_second_gate() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 11 % 249) as u8).collect();
        let img = tiny_gzip(&payload);
        let r = carve(&img, &CarveOpts::default());
        for rec in &r.records {
            assert_eq!(rec.admitted, rec.confidence.total >= MIN_CONFIDENCE);
        }
    }

    #[test]
    fn the_four_weighted_terms_sum_to_the_composite_on_every_record() {
        use crate::confidence::{W_ENTROPY, W_SIGNATURE, W_SIZE, W_STRUCTURE};
        let payload: Vec<u8> = (0u32..5000).map(|i| (i * 13 % 247) as u8).collect();
        let mut img = tiny_gzip(&payload);
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
        img.extend_from_slice(&vec![0x41u8; 2048]);
        let r = carve(&img, &CarveOpts::default());
        assert!(!r.records.is_empty());
        for rec in &r.records {
            let c = &rec.confidence;
            let sum = W_SIGNATURE * c.signature_integrity
                + W_STRUCTURE * c.structural_validity
                + W_ENTROPY * c.entropy_consistency
                + W_SIZE * c.size_plausibility;
            assert!(
                (sum - c.total).abs() < 1e-12,
                "{}: weighted terms sum to {sum}, total is {}",
                rec.id(),
                c.total
            );
        }
    }

    #[test]
    fn dedup_suppresses_a_header_buried_inside_a_recovered_object() {
        let mut payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        payload[1500] = 0xFF;
        payload[1501] = 0xD8;
        payload[1502] = 0xFF;
        let img = tiny_gzip(&payload);

        let loose = carve(
            &img,
            &CarveOpts {
                dedup: false,
                ..CarveOpts::default()
            },
        );
        let tight = carve(&img, &CarveOpts::default());

        assert!(
            loose.records.iter().any(|r| r.kind == Kind::Jpeg),
            "the un-deduplicated run should see the buried JPEG header"
        );
        assert!(
            !tight.records.iter().any(|r| r.kind == Kind::Jpeg),
            "the buried header was not suppressed by the claimed-bytes rule"
        );
        assert_eq!(loose.suppressed, 0, "--no-dedup suppresses nothing");
        assert!(tight.suppressed >= 1);
        assert_eq!(tight.records.len() + tight.suppressed, loose.records.len());
        assert_eq!(tight.scanned, loose.scanned, "dedup is not a scan change");
    }

    #[test]
    fn dedup_keeps_residue_that_lies_outside_every_recovery() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = tiny_gzip(&payload);
        let decoy_at = img.len() as u64;
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x00u8; 4096]);

        let r = carve(&img, &CarveOpts::default());
        let decoy = r
            .records
            .iter()
            .find(|x| x.kind == Kind::Jpeg && x.offset == decoy_at)
            .expect("free-space residue must survive deduplication: it is the evidence");
        assert!(!decoy.admitted);
        assert_eq!(decoy.assembly, Assembly::SignatureSpan);
        assert!(decoy.reason_code.is_some());
    }

    #[test]
    fn withholding_rejections_is_counted_rather_than_silent() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = tiny_gzip(&payload);
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x00u8; 4096]);

        let full = carve(&img, &CarveOpts::default());
        let quiet = carve(
            &img,
            &CarveOpts {
                report_rejected: false,
                ..CarveOpts::default()
            },
        );
        assert_eq!(quiet.records.len(), full.admitted());
        assert_eq!(quiet.withheld_rejected, full.rejected());
        assert!(quiet.withheld_rejected > 0);
    }

    #[test]
    fn records_come_back_in_offset_order() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = vec![0u8; 512];
        img.extend_from_slice(&tiny_gzip(&payload));
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x11u8; 8192]);
        img.extend_from_slice(&tiny_gzip(&payload));
        img.extend_from_slice(&vec![0u8; 512]);

        let r = carve(&img, &CarveOpts::default());
        let offsets: Vec<u64> = r.records.iter().map(|x| x.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort();
        assert_eq!(offsets, sorted);
    }

    #[test]
    fn a_run_is_deterministic() {
        let payload: Vec<u8> = (0u32..4000).map(|i| (i * 17 % 241) as u8).collect();
        let mut img = tiny_gzip(&payload);
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x7Eu8; 6000]);
        img.extend_from_slice(&tiny_gzip(&payload));
        let a = carve(&img, &CarveOpts::default());
        let b = carve(&img, &CarveOpts::default());
        assert_eq!(a, b);
    }

    #[test]
    fn no_record_is_reassembled_and_nothing_is_searched_while_the_flag_is_off() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = tiny_gzip(&payload);
        img.extend_from_slice(&[0xFF, 0xD8, 0xFF]);
        img.extend_from_slice(&vec![0x00u8; 2048]);
        let r = carve(&img, &CarveOpts::default());
        for rec in &r.records {
            assert_ne!(rec.assembly, Assembly::Reassembled);
            assert_eq!(rec.extents.len(), 1);
            assert_eq!(rec.extents[0].offset, rec.offset);
            assert_eq!(rec.extents[0].length, rec.length);
        }
        assert_eq!(r.reassembly, ReassemblyStats::default());
        assert_eq!(r.reassembly.attempted, 0);
        assert_eq!(r.reassembly.validations, 0);
    }

    const C: usize = 512;

    fn reassembly_opts() -> CarveOpts {
        CarveOpts {
            reassemble: true,
            cluster_bytes: C as u64,
            max_gap_clusters: 8,
            ..CarveOpts::default()
        }
    }

    fn filler(n: usize, salt: u8) -> Vec<u8> {
        (0..n)
            .map(|i| ((i as u32 * 37 + salt as u32 * 101) % 251) as u8 | 1)
            .collect()
    }

    fn fragmented(
        obj: &[u8],
        head_clusters: usize,
        gap: &[u8],
        trailing: usize,
    ) -> (Vec<u8>, u64) {
        let hl = head_clusters * C;
        assert!(hl < obj.len(), "the head must not contain the whole object");
        assert_eq!(gap.len() % C, 0, "the gap must be whole clusters");
        let mut img = vec![0u8; C];
        let header_at = img.len() as u64;
        img.extend_from_slice(&obj[..hl]);
        img.extend_from_slice(gap);
        img.extend_from_slice(&obj[hl..]);
        img.extend_from_slice(&vec![0u8; trailing]);
        (img, header_at)
    }

    #[test]
    fn a_fragmented_object_is_reassembled_into_one_record_carrying_both_extents() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);
        let want = sha256_hex(&obj);
        let gap_clusters = 3usize;
        let (img, header_at) = fragmented(&obj, 2, &filler(gap_clusters * C, 5), C);

        let seq = carve(&img, &CarveOpts::default());
        assert!(
            !seq.records.iter().any(|r| r.sha256 == want),
            "the contiguous engine recovered a fragmented object; the fixture for this test is wrong"
        );

        let r = carve(&img, &reassembly_opts());
        let hits: Vec<&Recovered> = r
            .records
            .iter()
            .filter(|x| x.assembly == Assembly::Reassembled)
            .collect();
        assert_eq!(hits.len(), 1, "expected exactly one reassembly");
        let hit = hits[0];

        assert_eq!(hit.sha256, want, "the reassembled bytes are not the object");
        assert_eq!(hit.length, obj.len() as u64);
        assert_eq!(hit.offset, header_at);
        assert_eq!(hit.extents.len(), 2);
        assert_eq!(
            hit.extents[0],
            Extent {
                offset: header_at,
                length: (2 * C) as u64
            }
        );
        assert_eq!(
            hit.extents[1],
            Extent {
                offset: header_at + (2 * C + gap_clusters * C) as u64,
                length: obj.len() as u64 - (2 * C) as u64
            }
        );
        assert_eq!(
            hit.extents.iter().map(|e| e.length).sum::<u64>(),
            hit.length,
            "schema 5: length is the sum of the extents"
        );
        assert_eq!(hit.extents[0].offset, hit.offset, "schema 5: offset is extents[0].offset");
        assert!(hit.admitted, "a byte-exact object scored {:.4}", hit.confidence.total);
        assert!(hit.structure.valid);

        assert_eq!(r.reassembly.solved, 1);
        assert_eq!(r.reassembly.solved_cost.len(), 1);
        assert_eq!(r.reassembly.solved_cost[0].id, hit.id());
        assert!(
            r.reassembly.solved_cost[0].validations > 0,
            "a recovery that cost no validations was not searched for"
        );
        assert!(r.reassembly.validations >= r.reassembly.solved_cost[0].validations);
        assert!(r.reassembly.attempted >= 1);
    }

    #[test]
    fn the_reassembly_replaces_the_leading_fragment_record_and_is_not_a_second_row() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);
        let (img, header_at) = fragmented(&obj, 2, &filler(3 * C, 9), C);

        let off = carve(&img, &CarveOpts::default());
        let on = carve(&img, &reassembly_opts());

        let at_header = |r: &CarveReport| r.records.iter().filter(|x| x.offset == header_at).count();
        assert_eq!(at_header(&off), 1);
        assert_eq!(at_header(&on), 1);
        assert_eq!(
            on.scanned, off.scanned,
            "reassembly is not a scan change"
        );

        let before = off.records.iter().find(|x| x.offset == header_at).unwrap();
        let after = on.records.iter().find(|x| x.offset == header_at).unwrap();
        assert_ne!(before.assembly, Assembly::Reassembled);
        assert_eq!(after.assembly, Assembly::Reassembled);
        assert_ne!(
            before.sha256, after.sha256,
            "the leading fragment and the whole object cannot have the same digest"
        );
        assert_eq!(
            after.sha256,
            sha256_hex(&obj),
            "the record that replaced the leading fragment is not the object"
        );
        assert_eq!(after.length, obj.len() as u64);
    }

    #[test]
    fn an_interleaved_object_inside_a_reassembled_gap_survives_dedup() {
        let payload_a: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj_a = tiny_gzip(&payload_a);
        let payload_b: Vec<u8> = (0u32..900).map(|i| (i * 13 % 249) as u8).collect();
        let obj_b = tiny_gzip(&payload_b);
        let want_a = sha256_hex(&obj_a);
        let want_b = sha256_hex(&obj_b);

        let mut gap = filler(4 * C, 3);
        gap[C..C + obj_b.len()].copy_from_slice(&obj_b);
        let (img, header_at) = fragmented(&obj_a, 2, &gap, C);
        let b_at = header_at + (2 * C + C) as u64;

        let r = carve(&img, &reassembly_opts());
        let a = r
            .records
            .iter()
            .find(|x| x.sha256 == want_a)
            .expect("the fragmented object was not reassembled");
        let b = r
            .records
            .iter()
            .find(|x| x.sha256 == want_b)
            .expect("the object living inside the gap was suppressed by a hull claim");

        assert_eq!(a.assembly, Assembly::Reassembled);
        assert_eq!(b.assembly, Assembly::Contiguous);
        assert_eq!(b.offset, b_at);
        assert!(a.admitted && b.admitted);

        assert!(a.offset < b.offset && b.end() < a.extents[1].offset + a.extents[1].length);
        for (lo, hi) in a.claims() {
            assert!(
                b.offset >= hi || b.end() <= lo,
                "object B at {} overlaps a claimed extent [{lo}, {hi})",
                b.offset
            );
        }
    }

    #[test]
    fn the_plan_built_here_is_the_plan_the_public_entry_point_builds() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);
        let (img, header_at) = fragmented(&obj, 2, &filler(3 * C, 11), C);
        let opts = reassembly_opts();

        let public = crate::bifragment::bifragment(
            &img,
            Kind::Gzip,
            header_at,
            opts.max_gap_clusters * opts.cluster_bytes,
            opts.cluster_bytes,
        )
        .expect("the public entry point did not solve what the driver solves");

        let r = carve(&img, &opts);
        let hit = r
            .records
            .iter()
            .find(|x| x.assembly == Assembly::Reassembled)
            .expect("the driver did not solve what the public entry point solves");

        let mine: Vec<(u64, u64)> = hit.extents.iter().map(|e| (e.offset, e.length)).collect();
        assert_eq!(mine, public.extents, "the two paths disagree on the extents");
        assert_eq!(
            r.reassembly.solved_cost[0].validations, public.validations,
            "the two paths disagree on what the search cost, so the plans differ"
        );
    }

    #[test]
    fn a_contiguous_object_is_never_searched_and_never_relabelled() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);
        let want = sha256_hex(&obj);
        let mut img = vec![0u8; C];
        img.extend_from_slice(&obj);
        img.extend_from_slice(&vec![0u8; C]);

        let r = carve(&img, &reassembly_opts());
        let hit = r.records.iter().find(|x| x.sha256 == want).unwrap();
        assert_eq!(hit.assembly, Assembly::Contiguous);
        assert_eq!(hit.extents.len(), 1);
        assert_eq!(r.reassembly.solved, 0);
        assert_eq!(
            r.reassembly.refused_contiguous, 0,
            "the precondition is applied before the search, so bifragment never has to refuse"
        );
    }

    #[test]
    fn a_residue_header_pays_the_whole_lattice_and_is_still_rejected() {
        let mut img = vec![0u8; C];
        img.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]);
        img.extend_from_slice(&filler(6 * C, 17));

        let r = carve(&img, &reassembly_opts());
        assert_eq!(r.admitted(), 0, "residue was admitted after a lattice search");
        assert_eq!(r.reassembly.solved, 0);
        assert_eq!(r.reassembly.accepted_splices, 0);
        assert!(r.reassembly.attempted >= 1);
        assert!(
            r.reassembly.validations > 1,
            "the lattice was not walked: {} validations",
            r.reassembly.validations
        );
        assert_eq!(r.reassembly.exhausted + r.reassembly.degenerate, r.reassembly.attempted);
    }

    #[test]
    fn a_wrong_cluster_size_costs_the_recovery_and_cannot_manufacture_one() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);
        let want = sha256_hex(&obj);
        let (img, _) = fragmented(&obj, 2, &filler(3 * C, 23), C);

        let wrong = CarveOpts {
            cluster_bytes: (2 * C) as u64,
            ..reassembly_opts()
        };
        let r = carve(&img, &wrong);
        for rec in &r.records {
            if rec.assembly == Assembly::Reassembled {
                assert_eq!(
                    rec.sha256, want,
                    "a wrong cluster size produced a reassembly that is not the object"
                );
            }
        }
        assert_eq!(
            r.reassembly.solved, 0,
            "measured: this grid cannot express the true split, so nothing is solved"
        );
    }

    #[test]
    fn every_reassembled_record_is_internally_consistent() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);
        let (img, _) = fragmented(&obj, 2, &filler(3 * C, 29), C);
        let r = carve(&img, &reassembly_opts());
        for rec in &r.records {
            assert_eq!(rec.offset, rec.extents[0].offset);
            assert_eq!(
                rec.length,
                rec.extents.iter().map(|e| e.length).sum::<u64>()
            );
            let mut bytes: Vec<u8> = Vec::new();
            for e in &rec.extents {
                let lo = e.offset as usize;
                assert!(lo + e.length as usize <= img.len(), "{} runs off the image", rec.id());
                bytes.extend_from_slice(&img[lo..lo + e.length as usize]);
            }
            assert_eq!(
                rec.sha256,
                sha256_hex(&bytes),
                "{}: sha256 is not the digest of the bytes its extents name",
                rec.id()
            );
            for w in rec.extents.windows(2) {
                assert!(w[0].offset + w[0].length <= w[1].offset);
            }
        }
    }

    #[test]
    fn a_reassembling_run_is_deterministic() {
        let payload: Vec<u8> = (0u32..3000).map(|i| (i * 7 % 251) as u8).collect();
        let obj = tiny_gzip(&payload);
        let (img, _) = fragmented(&obj, 2, &filler(3 * C, 31), C);
        let a = carve(&img, &reassembly_opts());
        let b = carve(&img, &reassembly_opts());
        assert_eq!(a, b, "two identical runs disagreed, cost included");
    }

    #[test]
    fn every_record_span_lies_inside_the_image() {
        let payload: Vec<u8> = (0u32..2000).map(|i| (i * 7 % 251) as u8).collect();
        let mut img = tiny_gzip(&payload);
        img.extend_from_slice(&[0x1F, 0x8B, 0x08]);
        let r = carve(&img, &CarveOpts::default());
        for rec in &r.records {
            assert!(rec.length >= 1);
            for (lo, hi) in rec.claims() {
                assert!(
                    hi <= img.len() as u64 && lo < hi,
                    "{} names [{lo}, {hi}) and the image is {} bytes",
                    rec.id(),
                    img.len()
                );
            }
        }
    }
}
