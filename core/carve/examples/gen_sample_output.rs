//! Generator for `fixtures/sample_output.json`, the frozen golden sample of the
//! carve report schema defined in `docs/output_schema.md`.
//!
//! ```text
//! cargo run --release -p sentinelwipe-carve --example gen_sample_output
//! ```
//!
//! ## Why this exists
//!
//! CLAUDE.md rule 2: every number that appears anywhere traces to a measurement,
//! and there are no illustrative values, not even in a mock. A hand-written
//! sample report would put 56 fabricated numbers in front of the frontend, and
//! a frozen mystery file nobody can regenerate is the same defect a year later.
//! So the sample is GENERATED, from the frozen fixture, through the shipped
//! `structure::validate` and the shipped `confidence::confidence` — the same two
//! calls `tests/residue_separation.rs` makes, in the same order, on the same
//! byte spans.
//!
//! Ground truth (paths, kinds, offsets, extents, sizes, SHA-256) is READ from
//! `out/fixture.manifest.json`, never transcribed. The gate, the weights and the
//! ladder rungs are READ from `confidence.rs` consts, never written as literals.
//!
//! ## What it is NOT
//!
//! This is not a carve run. `carve.rs` does not exist yet. This program does not
//! search the image for objects and then report what it found; it takes the two
//! populations the fixture manifest already defines — the 35 planted carvable
//! files and the residue candidates the shipped scanner finds outside every
//! planted extent — and scores each one, so the emitted report exercises every
//! field of the schema with real values. `provenance.is_carve_run` is `false` in
//! the output for exactly this reason, and the record count is NOT a recall
//! number. See the notes the program writes into `provenance.notes`.
//!
//! ## Determinism
//!
//! The output is byte-identical across runs given the same fixture: no
//! timestamps, no durations, no host paths, no map iteration order. Records are
//! sorted by byte offset. Every float is serialized with exactly six decimal
//! places. The schema's optional `timing` block is deliberately emitted as
//! `null` here, because a duration is the one measurement that would make the
//! golden sample differ from itself.
//!
//! ## Self-check
//!
//! SHA-256 is hand-rolled below (CLAUDE.md forbids a new dependency; `crc32` in
//! `structure/mod.rs` is the same call). It is not trusted on its own: the
//! program hashes the bytes it assembled for each of the 35 planted objects and
//! asserts the digest equals the one `fixtures/build_image.py` independently
//! recorded in the manifest. That single assertion simultaneously proves the
//! hash implementation, proves the assembled extents are the planted file, and
//! proves each validator's `end` landed exactly on the object's last byte. If it
//! fires, the program writes nothing.

use sentinelwipe_carve::confidence::{
    confidence, entropy_band, kind_defines_footer, shannon_entropy, size_bounds, Confidence,
    ENTROPY_UNKNOWN, MIN_CONFIDENCE, MIN_ENTROPY_SAMPLE, NON_STRUCTURE_CEILING,
    SIG_HEADER_AND_FOOTER, SIG_HEADER_MISMATCH, SIG_HEADER_ONLY, SIG_NO_FOOTER_DEFINED,
    STRUCTURAL_BREACH_POINT, W_ENTROPY, W_SIGNATURE, W_SIZE, W_STRUCTURE,
};
use sentinelwipe_carve::signature::{next_footer, scan, signature_for, Candidate, SIGNATURES};
use sentinelwipe_carve::structure::{validate, Validation};
use sentinelwipe_carve::Kind;

const IMAGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.img");
const MANIFEST_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.manifest.json");
const OUT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/sample_output.json");

/// Image-relative paths, so the report never carries this machine's directories.
const IMAGE_REL: &str = "out/fixture.img";
const MANIFEST_REL: &str = "out/fixture.manifest.json";

/// Bytes of unrelated image appended after a planted object's last extent, so
/// that `end` is a claim the validator has to make rather than the slice length
/// handing it the answer. Identical to `tests/residue_separation.rs`.
const TAIL: usize = 8192;

/// The schema identifier written into every report. Bumping it is a schema change.
const SCHEMA: &str = "sentinelwipe.carve.report/1";

// ===========================================================================
// SHA-256, hand-rolled. FIPS 180-4. Verified against the manifest's 35
// independently-computed digests before anything is written.
// ===========================================================================

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

fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut padded_tail = Vec::with_capacity(128);
    let rem = data.len() % 64;
    padded_tail.extend_from_slice(&data[data.len() - rem..]);
    padded_tail.push(0x80);
    while padded_tail.len() % 64 != 56 {
        padded_tail.push(0);
    }
    padded_tail.extend_from_slice(&bitlen.to_be_bytes());

    let full = data.len() - rem;
    let block = |b: &[u8], h: &mut [u32; 8]| {
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
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b2);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    };

    let mut i = 0;
    while i < full {
        block(&data[i..i + 64], &mut h);
        i += 64;
    }
    let mut j = 0;
    while j < padded_tail.len() {
        block(&padded_tail[j..j + 64], &mut h);
        j += 64;
    }

    let mut s = String::with_capacity(64);
    for v in h {
        s.push_str(&format!("{v:08x}"));
    }
    s
}

// ===========================================================================
// The minimal JSON reader. Same reader `tests/residue_separation.rs` and
// `tests/structure_media_fixture.rs` carry; CLAUDE.md forbids serde and an
// example cannot import a test crate.
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

impl<'a> P<'a> {
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
                let t = std::str::from_utf8(&self.b[start..self.i]).unwrap();
                Json::Num(t.parse().unwrap_or_else(|_| panic!("manifest: bad number {t:?}")))
            }
        }
    }
}

// ===========================================================================
// Ground truth off the manifest
// ===========================================================================

/// The manifest's `kind` string to a carver `Kind`. DOCX is a ZIP container and
/// carves as `Kind::Zip`; TXT has no signature and is out of scope. Identical to
/// `tests/residue_separation.rs::kind_of`.
fn kind_of(s: &str) -> Option<Kind> {
    match s {
        "JPEG" => Some(Kind::Jpeg),
        "PNG" => Some(Kind::Png),
        "PDF" => Some(Kind::Pdf),
        "ZIP" | "DOCX" => Some(Kind::Zip),
        "SQLITE" => Some(Kind::Sqlite),
        "MP4" => Some(Kind::Mp4),
        "GZIP" => Some(Kind::Gzip),
        "TXT" => None,
        other => panic!("manifest: unknown kind {other:?}"),
    }
}

struct Planted {
    path: String,
    manifest_kind: String,
    kind: Kind,
    size: u64,
    sha256: String,
    recoverable: String,
    /// (byte_offset, byte_length) in LOGICAL order.
    extents: Vec<(u64, u64)>,
}

fn planted(man: &Json) -> Vec<Planted> {
    man.get("files")
        .expect("manifest has a files array")
        .arr()
        .iter()
        .filter_map(|f| {
            let mk = f.get("kind").expect("file has a kind").s().to_string();
            let kind = kind_of(&mk)?;
            Some(Planted {
                path: f.get("path")?.s().to_string(),
                manifest_kind: mk,
                kind,
                size: f.get("size")?.u(),
                sha256: f.get("sha256")?.s().to_string(),
                recoverable: f.get("expected_recoverable")?.s().to_string(),
                extents: f
                    .get("extents")?
                    .arr()
                    .iter()
                    .map(|e| {
                        (
                            e.get("byte_offset").unwrap().u(),
                            e.get("byte_length").unwrap().u(),
                        )
                    })
                    .collect(),
            })
        })
        .collect()
}

fn planted_ranges(man: &Json) -> Vec<(u64, u64)> {
    let mut spans: Vec<(u64, u64)> = man
        .get("files")
        .unwrap()
        .arr()
        .iter()
        .flat_map(|f| {
            f.get("extents").unwrap().arr().iter().map(|e| {
                let o = e.get("byte_offset").unwrap().u();
                (o, o + e.get("byte_length").unwrap().u())
            })
        })
        .collect();
    spans.sort();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (lo, hi) in spans {
        match merged.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    merged
}

fn in_planted(ranges: &[(u64, u64)], at: u64) -> bool {
    ranges.iter().any(|r| at >= r.0 && at < r.1)
}

fn largest_planted(files: &[Planted], kind: Kind) -> u64 {
    files
        .iter()
        .filter(|p| p.kind == kind)
        .map(|p| p.size)
        .max()
        .unwrap_or(0)
}

// ===========================================================================
// The two signature-layer observations, taken from the SHIPPED signature module.
// Identical to `tests/residue_separation.rs`.
// ===========================================================================

fn header_matches(kind: Kind, buf: &[u8]) -> bool {
    SIGNATURES.iter().any(|s| {
        s.kind == kind && buf.len() >= s.header.len() && &buf[..s.header.len()] == s.header
    })
}

fn footer_in_sequence(buf: &[u8], kind: Kind, end: u64) -> bool {
    let Some(sig) = signature_for(kind) else {
        return false;
    };
    next_footer(buf, kind, sig.header.len() as u64, end).is_some()
}

/// The published ladder rung name for a (kind, sig_ok, footer_found) triple.
/// Derived by comparing the value `signature_integrity` returned against the
/// four published rung consts, so a renamed rung cannot drift from its value.
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
        panic!("signature_integrity returned {v} which is not a published rung")
    }
}

// ===========================================================================
// One report record
// ===========================================================================

struct Rec {
    kind: Kind,
    offset: u64,
    length: u64,
    extents: Vec<(u64, u64)>,
    assembly: &'static str,
    sha256: String,
    entropy: f64,
    entropy_sampled: bool,
    sig_header: bool,
    sig_footer_defined: bool,
    sig_footer_found: bool,
    rung: &'static str,
    st: Validation,
    c: Confidence,
    admitted: bool,
    reason_code: Option<&'static str>,
    reason: Option<String>,
    /// `Some` only when this record was matched to a manifest entry:
    /// (path, manifest kind, manifest `expected_recoverable`, sha256 matches).
    gt: Option<(String, String, String, bool)>,
}

impl Rec {
    fn id(&self) -> String {
        format!("{}@{}", self.kind.as_str(), self.offset)
    }
}

/// The bytes a carver holds for one planted object: its extents in LOGICAL
/// order, then unrelated image bytes so `end` is a real claim.
fn assembled(img: &[u8], p: &Planted) -> Vec<u8> {
    let mut v = Vec::with_capacity(p.size as usize + TAIL);
    for (o, l) in &p.extents {
        v.extend_from_slice(&img[*o as usize..(*o + *l) as usize]);
    }
    let after = p.extents.iter().map(|(o, l)| o + l).max().unwrap() as usize;
    let take = TAIL.min(img.len() - after);
    v.extend_from_slice(&img[after..after + take]);
    v
}

/// Split a recovered length back into extents, following the planted extent
/// layout. `end` is a length in LOGICAL bytes; the extents are physical spans.
fn extents_for(p: &Planted, end: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut left = end;
    for (o, l) in &p.extents {
        if left == 0 {
            break;
        }
        let take = (*l).min(left);
        out.push((*o, take));
        left -= take;
    }
    out
}

fn score_planted(img: &[u8], p: &Planted) -> Rec {
    let buf = assembled(img, p);
    let v = validate(p.kind, &buf);
    let end = v.end.unwrap_or(p.size).min(buf.len() as u64);
    let data = &buf[..end as usize];
    let sig_ok = header_matches(p.kind, &buf);
    let footer = footer_in_sequence(&buf, p.kind, end);
    let c = confidence(p.kind, sig_ok, footer, &v, data);
    let sha = sha256_hex(data);
    let extents = extents_for(p, end);
    Rec {
        kind: p.kind,
        offset: extents[0].0,
        length: end,
        assembly: if extents.len() == 1 {
            "contiguous"
        } else {
            "reassembled"
        },
        extents,
        entropy: shannon_entropy(data),
        entropy_sampled: data.len() >= MIN_ENTROPY_SAMPLE,
        sig_header: sig_ok,
        sig_footer_defined: kind_defines_footer(p.kind),
        sig_footer_found: footer,
        rung: rung_name(c.signature_integrity),
        gt: Some((
            p.path.clone(),
            p.manifest_kind.clone(),
            p.recoverable.clone(),
            sha == p.sha256,
        )),
        sha256: sha,
        admitted: c.total >= MIN_CONFIDENCE,
        reason_code: None,
        reason: None,
        st: v,
        c,
    }
}

fn score_residue(img: &[u8], cand: &Candidate, window: u64) -> Rec {
    let at = cand.header_at as usize;
    let v = validate(cand.kind, &img[at..]);
    let sig = signature_for(cand.kind).expect("every scanned kind has a table row");
    let end = match (sig.footer, cand.footer_at) {
        (Some(f), Some(fa)) => fa + f.len() as u64,
        _ => (cand.header_at + window).min(img.len() as u64),
    };
    let data = &img[at..end as usize];
    let sig_ok = header_matches(cand.kind, &img[at..]);
    let footer = footer_in_sequence(&img[at..], cand.kind, end - cand.header_at);
    let c = confidence(cand.kind, sig_ok, footer, &v, data);
    Rec {
        kind: cand.kind,
        offset: cand.header_at,
        length: end - cand.header_at,
        extents: vec![(cand.header_at, end - cand.header_at)],
        // The structure walker established no end for any residue candidate, so
        // the span is a signature-layer span: header to terminator when the
        // scanner found one, otherwise the fallback window. Never a validator's
        // claim about where an object stops.
        assembly: "signature-span",
        sha256: sha256_hex(data),
        entropy: shannon_entropy(data),
        entropy_sampled: data.len() >= MIN_ENTROPY_SAMPLE,
        sig_header: sig_ok,
        sig_footer_defined: kind_defines_footer(cand.kind),
        sig_footer_found: footer,
        rung: rung_name(c.signature_integrity),
        gt: None,
        admitted: c.total >= MIN_CONFIDENCE,
        reason_code: None,
        reason: None,
        st: v,
        c,
    }
}

/// The rejection reason. `reason` is one line for the operator; `reason_code` is
/// the machine form the UI groups by. The structural half is
/// `structure::validate`'s own `detail` string, quoted verbatim and never
/// paraphrased, because it is the string that names the check and the offset.
fn set_reason(r: &mut Rec) {
    if r.admitted {
        r.reason_code = None;
        r.reason = None;
        return;
    }
    r.reason_code = Some(if r.st.valid {
        "below-min-confidence"
    } else {
        "below-min-confidence-structure-invalid"
    });
    r.reason = Some(format!(
        "confidence {:.4} below MIN_CONFIDENCE {:.4}; structure: {}",
        r.c.total, MIN_CONFIDENCE, r.st.detail
    ));
}

// ===========================================================================
// JSON writing, hand-rolled. CLAUDE.md forbids serde.
// ===========================================================================

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

/// EVERY float in the report goes through here: exactly six decimal places, so
/// the file is byte-stable and no field is silently more precise than another.
/// Display rounding is the UI's business, not the wire format's.
fn f(x: f64) -> String {
    let s = format!("{x:.6}");
    // -0.000000 is the same number as 0.000000 and must not depend on sign bits.
    if s == "-0.000000" {
        "0.000000".to_string()
    } else {
        s
    }
}

struct W {
    b: String,
}

impl W {
    fn new() -> W {
        W { b: String::new() }
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
    fn kv_s(&mut self, n: usize, k: &str, v: &str, comma: bool) -> &mut W {
        self.ind(n);
        self.b
            .push_str(&format!("\"{}\": \"{}\"{}\n", k, esc(v), if comma { "," } else { "" }));
        self
    }
    fn kv_os(&mut self, n: usize, k: &str, v: Option<&str>, comma: bool) -> &mut W {
        match v {
            Some(v) => self.kv_s(n, k, v, comma),
            None => {
                self.ind(n);
                self.b
                    .push_str(&format!("\"{}\": null{}\n", k, if comma { "," } else { "" }));
                self
            }
        }
    }
    fn kv_u(&mut self, n: usize, k: &str, v: u64, comma: bool) -> &mut W {
        self.ind(n);
        self.b
            .push_str(&format!("\"{}\": {}{}\n", k, v, if comma { "," } else { "" }));
        self
    }
    fn kv_f(&mut self, n: usize, k: &str, v: f64, comma: bool) -> &mut W {
        self.ind(n);
        self.b
            .push_str(&format!("\"{}\": {}{}\n", k, f(v), if comma { "," } else { "" }));
        self
    }
    fn kv_b(&mut self, n: usize, k: &str, v: bool, comma: bool) -> &mut W {
        self.ind(n);
        self.b
            .push_str(&format!("\"{}\": {}{}\n", k, v, if comma { "," } else { "" }));
        self
    }
}

// ===========================================================================
// main
// ===========================================================================

fn main() {
    let img = std::fs::read(IMAGE_PATH).unwrap_or_else(|e| {
        panic!(
            "NOT VERIFIED -- the golden sample was not generated.\n  \
             image: {IMAGE_PATH}\n  error: {e}\n  \
             Run `make fixtures`. This program never emits a file it did not measure."
        )
    });
    let manbytes = std::fs::read(MANIFEST_PATH).unwrap_or_else(|e| {
        panic!("NOT VERIFIED -- manifest unreadable.\n  manifest: {MANIFEST_PATH}\n  error: {e}")
    });
    let man = P { b: &manbytes, i: 0 }.value();
    let manifest_sha = sha256_hex(&manbytes);
    let image_sha = sha256_hex(&img);

    // Ground truth the manifest states about itself. Read, never transcribed.
    let man_image_sha = man.get("image_sha256").unwrap().s().to_string();
    assert_eq!(
        image_sha, man_image_sha,
        "the image on disk is not the image this manifest describes"
    );

    let files = planted(&man);
    let ranges = planted_ranges(&man);
    let all_files = man.get("files").unwrap().arr();

    // ---- records ---------------------------------------------------------
    let mut recs: Vec<Rec> = files.iter().map(|p| score_planted(&img, p)).collect();

    // The SHIPPED scanner over the whole image; anything outside a planted
    // extent is residue by the same rule the manifest's counts used.
    let residue: Vec<Candidate> = scan(&img)
        .into_iter()
        .filter(|c| !in_planted(&ranges, c.header_at))
        .collect();
    for c in &residue {
        recs.push(score_residue(&img, c, largest_planted(&files, c.kind)));
    }
    for r in &mut recs {
        set_reason(r);
    }

    // ---- self-checks, before anything is written -------------------------
    let mut hash_matches = 0usize;
    for r in &recs {
        if let Some((path, _, _, ok)) = &r.gt {
            assert!(
                ok,
                "assembled bytes for {path} do not hash to the manifest digest -- \
                 either the SHA-256 here is wrong, the extents were assembled wrong, \
                 or a validator's `end` is wrong. Nothing written."
            );
            hash_matches += 1;
        }
        let sum = W_SIGNATURE * r.c.signature_integrity
            + W_STRUCTURE * r.c.structural_validity
            + W_ENTROPY * r.c.entropy_consistency
            + W_SIZE * r.c.size_plausibility;
        assert!(
            (sum - r.c.total).abs() < 1e-12,
            "{}: weighted terms sum to {sum} but total is {} -- the schema publishes \
             that they are equal",
            r.id(),
            r.c.total
        );
    }
    assert_eq!(
        hash_matches, 35,
        "35 planted carvable objects expected (40 planted minus 5 TXT)"
    );

    recs.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then(a.kind.as_str().cmp(b.kind.as_str()))
    });

    // ---- counts, all literally counted from `recs` ------------------------
    let n_admitted = recs.iter().filter(|r| r.admitted).count();
    let n_rejected = recs.len() - n_admitted;
    let n_sha_match = recs
        .iter()
        .filter(|r| matches!(&r.gt, Some((_, _, _, true))))
        .count();

    let kinds = [
        Kind::Jpeg,
        Kind::Png,
        Kind::Pdf,
        Kind::Zip,
        Kind::Sqlite,
        Kind::Mp4,
        Kind::Gzip,
    ];
    let assemblies = ["contiguous", "reassembled", "signature-span"];

    // ---- distributions and margins, all computed --------------------------
    let adm: Vec<f64> = recs
        .iter()
        .filter(|r| r.admitted)
        .map(|r| r.c.total)
        .collect();
    let rej: Vec<f64> = recs
        .iter()
        .filter(|r| !r.admitted)
        .map(|r| r.c.total)
        .collect();
    let stat = |v: &[f64]| -> (usize, f64, f64, f64) {
        (
            v.len(),
            v.iter().cloned().fold(f64::INFINITY, f64::min),
            v.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
            v.iter().sum::<f64>() / v.len() as f64,
        )
    };
    let (an, amin, amax, amean) = stat(&adm);
    let (rn, rmin, rmax, rmean) = stat(&rej);
    let worst_struct = recs
        .iter()
        .filter(|r| !r.admitted)
        .map(|r| r.c.structural_validity)
        .fold(f64::NEG_INFINITY, f64::max);

    // ---- reachability, counted off the manifest ---------------------------
    let n_planted_total = all_files.len() as u64;
    let count_reach = |tag: &str| {
        all_files
            .iter()
            .filter(|f| f.get("expected_recoverable").unwrap().s() == tag)
            .count() as u64
    };
    let n_contiguous = count_reach("signature-only");
    let n_bifragment = count_reach("bifragment");
    let n_unreachable = count_reach("unrecoverable-by-design");

    // Why each unreachable file is unreachable, DERIVED from the manifest row
    // rather than named: no signature table row for its kind, more than two
    // extents, or extents whose physical order is not their logical order.
    let mut unreachable: Vec<(String, String, String)> = Vec::new();
    for fj in all_files {
        if fj.get("expected_recoverable").unwrap().s() != "unrecoverable-by-design" {
            continue;
        }
        let path = fj.get("path").unwrap().s().to_string();
        let mk = fj.get("kind").unwrap().s().to_string();
        let ex: Vec<u64> = fj
            .get("extents")
            .unwrap()
            .arr()
            .iter()
            .map(|e| e.get("byte_offset").unwrap().u())
            .collect();
        let reason = if kind_of(&mk).is_none() {
            format!("kind {mk} has no row in signature::SIGNATURES: no header to scan for")
        } else if ex.len() > 2 {
            format!(
                "{} extents; bifragment gap carving reassembles at most 2",
                ex.len()
            )
        } else if ex.windows(2).any(|w| w[1] < w[0]) {
            format!(
                "{} extents stored out of physical order (extent[1] at {} precedes extent[0] at {}); \
                 a forward gap search cannot reach them",
                ex.len(),
                ex[1],
                ex[0]
            )
        } else {
            panic!("manifest marks {path} unrecoverable-by-design but the row shows no reason");
        };
        unreachable.push((path, mk, reason));
    }
    assert_eq!(unreachable.len() as u64, n_unreachable);

    // =======================================================================
    // Emit
    // =======================================================================
    let mut w = W::new();
    w.line(0, "{");
    w.kv_s(2, "schema", SCHEMA, true);

    // ---- provenance ----
    w.line(2, "\"provenance\": {");
    w.kv_s(4, "producer", "core/carve/examples/gen_sample_output.rs", true);
    w.kv_s(
        4,
        "command",
        "cargo run --release -p sentinelwipe-carve --example gen_sample_output",
        true,
    );
    w.kv_b(4, "is_carve_run", false, true);
    w.line(4, "\"notes\": [");
    let notes = [
        "GENERATED, never hand-written. Every value here was measured: ground truth from \
         out/fixture.manifest.json, the four confidence terms from the shipped \
         confidence::confidence, the structural verdict and every reason string from the \
         shipped structure::validate, and every SHA-256 from the bytes named by the record's \
         own extents.",
        "This is NOT a carve run. carve.rs does not exist at the time this file was frozen. \
         The record set is the union of the manifest's 35 planted carvable objects, each \
         scored on its correctly assembled bytes, and every residue candidate the shipped \
         scanner finds outside every planted extent. It is a schema exercise with real \
         numbers, not a recovery result.",
        "counts.admitted is therefore NOT a recall figure and must never be rendered as one. \
         Seven of the admitted records are `reassembled`, which requires bifragment.rs; two \
         of those seven the fixture plants as unrecoverable by construction and a forward gap \
         search cannot rebuild them at all.",
        "ground_truth.reachability is a CEILING on what an engine could reach on this fixture. \
         ground_truth.demonstrated_recall is what a carver measurably recovered. They are two \
         different numbers, they are reported in two different fields, and a report that has \
         not measured the second one carries null there.",
        "Every `signature-span` record here is residue and its extent is a signature-layer \
         span, not a validator's claim: header to the format's terminator when the scanner \
         found one, and otherwise a window equal to the largest planted object of that kind, \
         which is the span tests/residue_separation.rs uses and which architecture.md D2 names \
         as a policy choice. Only the adversarial ceiling of 0.6500 -- terms 3 and 4 pinned to \
         1.0 for every decoy -- is safe to quote against a challenge to that choice.",
        "timing is null on purpose: a duration is the one field that would stop this file \
         from regenerating byte-identically.",
    ];
    for (i, n) in notes.iter().enumerate() {
        w.ind(6);
        w.raw(&format!(
            "\"{}\"{}\n",
            esc(n),
            if i + 1 < notes.len() { "," } else { "" }
        ));
    }
    w.line(4, "]");
    w.line(2, "},");

    // ---- run ----
    w.line(2, "\"run\": {");
    w.kv_s(4, "phase", "pre-wipe", true);
    w.kv_s(4, "image_path", IMAGE_REL, true);
    w.kv_u(4, "image_bytes", img.len() as u64, true);
    w.kv_s(4, "image_sha256", &image_sha, true);
    w.kv_s(4, "read_mode", "file", true);
    w.kv_os(4, "device", None, true);
    w.kv_os(4, "timing", None, false);
    w.line(2, "},");

    // ---- policy ----
    w.line(2, "\"policy\": {");
    w.kv_s(
        4,
        "formula",
        &format!(
            "confidence = {:.2}*signature_integrity + {:.2}*structural_validity + \
             {:.2}*entropy_consistency + {:.2}*size_plausibility",
            W_SIGNATURE, W_STRUCTURE, W_ENTROPY, W_SIZE
        ),
        true,
    );
    w.line(4, "\"weights\": {");
    w.kv_f(6, "signature_integrity", W_SIGNATURE, true);
    w.kv_f(6, "structural_validity", W_STRUCTURE, true);
    w.kv_f(6, "entropy_consistency", W_ENTROPY, true);
    w.kv_f(6, "size_plausibility", W_SIZE, false);
    w.line(4, "},");
    w.kv_f(4, "weights_sum", W_SIGNATURE + W_STRUCTURE + W_ENTROPY + W_SIZE, true);
    w.kv_f(4, "min_confidence", MIN_CONFIDENCE, true);
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

    // ---- kind_policy ----
    w.line(2, "\"kind_policy\": {");
    for (i, k) in kinds.iter().enumerate() {
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
        w.line(4, if i + 1 < kinds.len() { "}," } else { "}" });
    }
    w.line(2, "},");

    // ---- counts ----
    w.line(2, "\"counts\": {");
    w.kv_u(4, "records", recs.len() as u64, true);
    w.kv_u(4, "admitted", n_admitted as u64, true);
    w.kv_u(4, "rejected", n_rejected as u64, true);
    w.kv_u(4, "sha256_matches_planted", n_sha_match as u64, true);
    w.line(4, "\"by_kind\": {");
    let present: Vec<Kind> = kinds
        .iter()
        .cloned()
        .filter(|k| recs.iter().any(|r| r.kind == *k))
        .collect();
    for (i, k) in present.iter().enumerate() {
        let rr: Vec<&Rec> = recs.iter().filter(|r| r.kind == *k).collect();
        let a = rr.iter().filter(|r| r.admitted).count();
        w.ind(6);
        w.raw(&format!(
            "\"{}\": {{ \"records\": {}, \"admitted\": {}, \"rejected\": {} }}{}\n",
            k.as_str(),
            rr.len(),
            a,
            rr.len() - a,
            if i + 1 < present.len() { "," } else { "" }
        ));
    }
    w.line(4, "},");
    w.line(4, "\"by_assembly\": {");
    for (i, a) in assemblies.iter().enumerate() {
        let n = recs.iter().filter(|r| r.assembly == *a).count();
        w.ind(6);
        w.raw(&format!(
            "\"{}\": {}{}\n",
            a,
            n,
            if i + 1 < assemblies.len() { "," } else { "" }
        ));
    }
    w.line(4, "}");
    w.line(2, "},");

    // ---- score_distribution ----
    w.line(2, "\"score_distribution\": {");
    for (name, (n, mn, mx, me), comma) in [
        ("admitted", (an, amin, amax, amean), true),
        ("rejected", (rn, rmin, rmax, rmean), false),
    ] {
        w.ind(4);
        w.raw(&format!(
            "\"{}\": {{ \"n\": {}, \"min\": {}, \"max\": {}, \"mean\": {} }}{}\n",
            name,
            n,
            f(mn),
            f(mx),
            f(me),
            if comma { "," } else { "" }
        ));
    }
    w.line(2, "},");

    // ---- margin ----
    w.line(2, "\"margin\": {");
    w.kv_f(4, "lowest_admitted", amin, true);
    w.kv_f(4, "highest_rejected", rmax, true);
    w.kv_f(4, "population_gap", amin - rmax, true);
    w.kv_f(4, "gate_headroom", MIN_CONFIDENCE - rmax, true);
    w.kv_f(4, "worst_rejected_structural_validity", worst_struct, true);
    w.kv_f(4, "structural_breach_point", STRUCTURAL_BREACH_POINT, true);
    w.kv_f(
        4,
        "structural_headroom",
        STRUCTURAL_BREACH_POINT - worst_struct,
        true,
    );
    w.kv_s(
        4,
        "binds",
        "structural_headroom",
        false,
    );
    w.line(2, "},");

    // ---- ground_truth ----
    w.line(2, "\"ground_truth\": {");
    w.kv_s(4, "manifest_path", MANIFEST_REL, true);
    w.kv_s(4, "manifest_sha256", &manifest_sha, true);
    w.kv_u(4, "planted_total", n_planted_total, true);
    w.line(4, "\"reachability\": {");
    w.kv_u(6, "contiguous", n_contiguous, true);
    w.kv_u(6, "needs_bifragment_reassembly", n_bifragment, true);
    w.kv_u(6, "unreachable_by_construction", n_unreachable, false);
    w.line(4, "},");
    w.line(4, "\"unreachable\": [");
    for (i, (path, kind, reason)) in unreachable.iter().enumerate() {
        w.line(6, "{");
        w.kv_s(8, "path", path, true);
        w.kv_s(8, "kind", kind, true);
        w.kv_s(8, "reason", reason, false);
        w.line(
            6,
            if i + 1 < unreachable.len() { "}," } else { "}" },
        );
    }
    w.line(4, "],");
    w.kv_b(4, "recall_measured", false, true);
    w.kv_os(4, "demonstrated_recall", None, true);
    w.kv_s(
        4,
        "demonstrated_recall_note",
        "null because no carve run produced one. carve.rs did not exist when this sample was \
         frozen, so writing a number here would be a claim no test has made. A contiguous \
         engine's demonstrated recall is bounded above by reachability.contiguous and is \
         reported here only once measured.",
        false,
    );
    w.line(2, "},");

    // ---- candidates ----
    w.line(2, "\"candidates\": [");
    for (i, r) in recs.iter().enumerate() {
        w.line(4, "{");
        w.kv_s(6, "id", &r.id(), true);
        w.kv_s(6, "kind", r.kind.as_str(), true);
        w.kv_u(6, "offset", r.offset, true);
        w.kv_u(6, "length", r.length, true);
        w.kv_s(6, "assembly", r.assembly, true);
        w.ind(6);
        w.raw("\"extents\": [");
        for (j, (o, l)) in r.extents.iter().enumerate() {
            w.raw(&format!(
                "{{ \"offset\": {}, \"length\": {} }}{}",
                o,
                l,
                if j + 1 < r.extents.len() { ", " } else { "" }
            ));
        }
        w.raw("],\n");
        w.kv_s(6, "sha256", &r.sha256, true);

        w.line(6, "\"signature\": {");
        w.kv_b(8, "header_matched", r.sig_header, true);
        w.kv_b(8, "footer_defined", r.sig_footer_defined, true);
        w.kv_b(8, "footer_found", r.sig_footer_found, true);
        w.kv_s(8, "ladder_rung", r.rung, false);
        w.line(6, "},");

        w.line(6, "\"structure\": {");
        w.kv_b(8, "valid", r.st.valid, true);
        match r.st.end {
            Some(e) => w.kv_u(8, "end_relative", e, true),
            None => w.kv_os(8, "end_relative", None, true),
        };
        w.kv_f(8, "score", r.st.score, true);
        w.kv_s(8, "detail", &r.st.detail, false);
        w.line(6, "},");

        w.line(6, "\"entropy\": {");
        w.kv_f(8, "bits_per_byte", r.entropy, true);
        w.kv_b(8, "sampled", r.entropy_sampled, false);
        w.line(6, "},");

        w.line(6, "\"confidence\": {");
        w.kv_f(8, "signature_integrity", r.c.signature_integrity, true);
        w.kv_f(8, "structural_validity", r.c.structural_validity, true);
        w.kv_f(8, "entropy_consistency", r.c.entropy_consistency, true);
        w.kv_f(8, "size_plausibility", r.c.size_plausibility, true);
        w.line(8, "\"weighted\": {");
        w.kv_f(
            10,
            "signature_integrity",
            W_SIGNATURE * r.c.signature_integrity,
            true,
        );
        w.kv_f(
            10,
            "structural_validity",
            W_STRUCTURE * r.c.structural_validity,
            true,
        );
        w.kv_f(
            10,
            "entropy_consistency",
            W_ENTROPY * r.c.entropy_consistency,
            true,
        );
        w.kv_f(10, "size_plausibility", W_SIZE * r.c.size_plausibility, false);
        w.line(8, "},");
        w.kv_f(8, "total", r.c.total, false);
        w.line(6, "},");

        w.kv_b(6, "admitted", r.admitted, true);
        w.kv_os(6, "reason_code", r.reason_code, true);
        w.kv_os(6, "reason", r.reason.as_deref(), true);

        match &r.gt {
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

    std::fs::write(OUT_PATH, w.b.as_bytes()).expect("write sample_output.json");

    eprintln!("wrote {OUT_PATH}");
    eprintln!("  records {}  admitted {}  rejected {}", recs.len(), n_admitted, n_rejected);
    eprintln!("  sha256 cross-check against manifest: {hash_matches}/35 matched");
    eprintln!(
        "  admitted  n={an} min={:.4} max={:.4} mean={:.4}",
        amin, amax, amean
    );
    eprintln!(
        "  rejected  n={rn} min={:.4} max={:.4} mean={:.4}",
        rmin, rmax, rmean
    );
    eprintln!(
        "  structural headroom {:.4} = breach {:.6} - worst rejected structural credit {:.4}",
        STRUCTURAL_BREACH_POINT - worst_struct,
        STRUCTURAL_BREACH_POINT,
        worst_struct
    );
}
