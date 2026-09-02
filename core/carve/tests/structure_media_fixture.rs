//! The four media validators against the real 256 MB fixture.
//!
//! `out/fixture.manifest.json` is ground truth and this file READS it rather
//! than transcribing it, so a rebuilt fixture moves the test with it instead of
//! quietly testing yesterday's offsets. Two claims are made here and both are
//! measured on the shipped image:
//!
//!   1. every planted JPEG, PNG, GZIP and MP4 validates, and `end` equals the
//!      manifest's `size` to the byte -- which is what makes the carved extent
//!      hashable against the manifest's SHA-256 downstream;
//!   2. every bare signature hit the manifest counts in free space is REJECTED.
//!      The manifest's `residue_signature_false_positives` records 8 for JPEG
//!      and 13 for GZIP. Those 21 are the whole argument for structure
//!      validation, and 0 of them may survive.
//!
//! Covers only the four kinds this half owns. PDF, ZIP and SQLITE are the other
//! structure agent's and are tested in their own modules.

use sentinelwipe_carve::structure::{gzip, jpeg, mp4, png, validate};
use sentinelwipe_carve::Kind;

const IMAGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.img");
const MANIFEST_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.manifest.json");

// ===========================================================================
// A minimal JSON reader. CLAUDE.md forbids a new dependency; the manifest
// schema is small and fixed, so the parser is ~120 lines and reads the whole
// document into an owned tree.
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
    fn b(&self) -> bool {
        match self {
            Json::Bool(b) => *b,
            _ => false,
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
                        other => panic!("manifest: object key is not a string: {:?}", other),
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
                                    let h = std::str::from_utf8(&self.b[self.i..self.i + 4]).unwrap();
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
                    && matches!(self.b[self.i],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                {
                    self.i += 1;
                }
                let t = std::str::from_utf8(&self.b[start..self.i]).unwrap();
                Json::Num(t.parse().unwrap_or_else(|_| panic!("manifest: bad number {:?}", t)))
            }
        }
    }
}

// ===========================================================================
// Fixture loading
// ===========================================================================

/// A skipping test that prints `ok` claims more than it verified, which is
/// CLAUDE.md rule 1 aimed at ourselves. The skip is loud, and
/// `SENTINELWIPE_REQUIRE_FIXTURE=1` turns it into a failure. This mirrors the
/// convention `signature.rs` established.
fn fixture() -> Option<&'static (Vec<u8>, Json)> {
    static CACHE: std::sync::OnceLock<Option<(Vec<u8>, Json)>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let img = std::fs::read(IMAGE_PATH);
            let man = std::fs::read(MANIFEST_PATH);
            match (img, man) {
                (Ok(i), Ok(m)) => {
                    let j = P { b: &m, i: 0 }.value();
                    Some((i, j))
                }
                (a, b) => {
                    let err = a.err().map(|e| e.to_string())
                        .or_else(|| b.err().map(|e| e.to_string()))
                        .unwrap_or_default();
                    let msg = format!(
                        "fixture not read: {IMAGE_PATH} / {MANIFEST_PATH}: {err}. Run `make fixtures`."
                    );
                    if std::env::var("SENTINELWIPE_REQUIRE_FIXTURE").map(|v| v == "1").unwrap_or(false)
                    {
                        panic!("SENTINELWIPE_REQUIRE_FIXTURE=1 and {msg}");
                    }
                    eprintln!("SKIP (NOT VERIFIED): {msg}");
                    None
                }
            }
        })
        .as_ref()
}

struct Planted {
    path: String,
    kind: Kind,
    size: u64,
    fragmented: bool,
    recoverable: String,
    /// (byte_offset, byte_length) in logical order
    extents: Vec<(u64, u64)>,
}

fn kind_of(s: &str) -> Option<Kind> {
    match s {
        "JPEG" => Some(Kind::Jpeg),
        "PNG" => Some(Kind::Png),
        "GZIP" => Some(Kind::Gzip),
        "MP4" => Some(Kind::Mp4),
        _ => None, // PDF, ZIP/DOCX, SQLITE and TXT are not this half's kinds
    }
}

/// The planted files of the four kinds this half owns.
fn planted(man: &Json) -> Vec<Planted> {
    man.get("files")
        .expect("manifest has a files array")
        .arr()
        .iter()
        .filter_map(|f| {
            let kind = kind_of(f.get("kind")?.s())?;
            Some(Planted {
                path: f.get("path")?.s().to_string(),
                kind,
                size: f.get("size")?.u(),
                fragmented: f.get("fragmented")?.b(),
                recoverable: f.get("expected_recoverable")?.s().to_string(),
                extents: f
                    .get("extents")?
                    .arr()
                    .iter()
                    .map(|e| (e.get("byte_offset").unwrap().u(), e.get("byte_length").unwrap().u()))
                    .collect(),
            })
        })
        .collect()
}

/// Every planted byte range in the whole image, merged. Anything outside these
/// is residue, and a signature hit there is a false positive by definition --
/// the same rule `fixtures/plan.py::measure_signature_false_positives` applies.
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
    match ranges.binary_search_by(|r| {
        if at < r.0 {
            std::cmp::Ordering::Greater
        } else if at >= r.1 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    }) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn find_all(hay: &[u8], needle: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    if needle.is_empty() || hay.len() < needle.len() {
        return out;
    }
    let first = needle[0];
    let mut i = 0usize;
    while i + needle.len() <= hay.len() {
        if hay[i] == first && &hay[i..i + needle.len()] == needle {
            out.push(i as u64);
        }
        i += 1;
    }
    out
}

/// The bytes a carver would hold for one planted object: its extents in logical
/// order, then the image tail that follows the last extent. The tail is what
/// makes `end` a real claim -- a validator that just returned the slice length
/// would pass without it.
fn assembled(img: &[u8], p: &Planted, tail: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for (o, l) in &p.extents {
        v.extend_from_slice(&img[*o as usize..(*o + *l) as usize]);
    }
    let (lo, ll) = *p.extents.last().unwrap();
    let after = (lo + ll) as usize;
    let take = tail.min(img.len() - after);
    v.extend_from_slice(&img[after..after + take]);
    v
}

// ===========================================================================
// 1 · every planted object of these four kinds validates, with the exact end
// ===========================================================================

#[test]
fn fixture_image_is_the_one_the_manifest_describes() {
    let Some((img, man)) = fixture() else { return };
    assert_eq!(
        img.len() as u64,
        man.get("image_bytes").unwrap().u(),
        "image length disagrees with the manifest"
    );
    assert_eq!(img.len(), 268_435_456);
    assert_eq!(man.get("bytes_per_cluster").unwrap().u(), 2048);
    // Recorded so a failure report names the image that failed. The SHA-256
    // itself is verified by `make fixtures`, which refuses to write a mismatch.
    eprintln!(
        "fixture image_sha256 {}",
        man.get("image_sha256").unwrap().s()
    );
}

#[test]
fn every_unfragmented_planted_object_validates_with_the_exact_end() {
    let Some((img, man)) = fixture() else { return };
    let files = planted(man);
    let mut checked = 0;
    let mut failures = Vec::new();
    for p in files.iter().filter(|p| !p.fragmented) {
        let at = p.extents[0].0 as usize;
        // The realistic carver input: the header offset through the end of the
        // image. Nothing tells the validator where the object stops.
        let v = validate(p.kind, &img[at..]);
        if !v.valid || v.end != Some(p.size) {
            failures.push(format!(
                "{} {} at {}: valid={} end={:?} expected {} :: {}",
                p.kind.as_str(), p.path, at, v.valid, v.end, p.size, v.detail
            ));
        } else {
            eprintln!(
                "OK  {:<8} {:<32} end={:>7} score={:.4}",
                p.kind.as_str(), p.path, v.end.unwrap(), v.score
            );
        }
        checked += 1;
    }
    assert!(failures.is_empty(), "{} of {} failed:\n{}", failures.len(), checked, failures.join("\n"));
    // 4 JPEG + 4 PNG + 4 GZIP + 3 MP4 planted unfragmented, counted off the
    // manifest rather than asserted from memory.
    assert_eq!(checked, 15, "unfragmented count for these four kinds");
}

#[test]
fn every_bifragment_planted_object_validates_once_reassembled() {
    let Some((img, man)) = fixture() else { return };
    let files = planted(man);
    let mut checked = 0;
    for p in files.iter().filter(|p| p.fragmented && p.recoverable == "bifragment") {
        let buf = assembled(img, p, 8192);
        let v = validate(p.kind, &buf);
        assert!(v.valid, "{} {}: {}", p.kind.as_str(), p.path, v.detail);
        assert_eq!(v.end, Some(p.size), "{} {}: wrong end", p.kind.as_str(), p.path);
        eprintln!(
            "OK  {:<8} {:<32} reassembled end={:>7} score={:.4}",
            p.kind.as_str(), p.path, v.end.unwrap(), v.score
        );
        checked += 1;
    }
    // imaging_transcript.txt.gz, entropy_heatmap.png, sealing_procedure.mov,
    // handover_briefing.mov.
    assert_eq!(checked, 4, "bifragment count for these four kinds");
}

#[test]
fn fragmented_objects_read_contiguously_are_rejected_except_the_one_mp4_that_cannot_be() {
    // This is why bifragment carving exists: if the contiguous read of a
    // fragmented object passed, the gap search would be decoration.
    //
    // It holds for four of the five fragmented objects of these kinds, and NOT
    // for /handover_briefing.mov. MP4 defines no checksum over mdat, so a
    // fragmentation that falls entirely inside the media payload leaves a box
    // tree that still tiles exactly to the true length. The 33,913 wrong bytes
    // it picks up are residue and another file's PCM audio and no structural
    // check can see them. That is recorded here as a measured fact rather than
    // asserted away, and `structure/mp4.rs` names the driver-level fix.
    let Some((img, man)) = fixture() else { return };
    let files = planted(man);
    let mut rejected = Vec::new();
    let mut accepted = Vec::new();
    for p in files.iter().filter(|p| p.fragmented) {
        let at = p.extents[0].0 as usize;
        let v = validate(p.kind, &img[at..]);
        if v.valid && v.end == Some(p.size) {
            eprintln!(
                "ACCEPTED contiguous (WRONG BYTES) {:<8} {:<32} score={:.4} :: {}",
                p.kind.as_str(), p.path, v.score, v.detail
            );
            accepted.push(p.path.clone());
        } else {
            eprintln!(
                "REJECTED contiguous {:<8} {:<32} score={:.4} :: {}",
                p.kind.as_str(), p.path, v.score, v.detail
            );
            rejected.push(p.path.clone());
        }
    }
    assert_eq!(rejected.len() + accepted.len(), 5, "fragmented count for these four kinds");
    assert_eq!(
        accepted,
        vec!["/handover_briefing.mov".to_string()],
        "the set of fragmented objects a contiguous read wrongly accepts has changed"
    );
    assert_eq!(rejected.len(), 4);
}

#[test]
fn the_mp4_whose_gap_swallows_another_header_is_rejected_by_payload_exclusivity() {
    // /sealing_procedure.mov read contiguously tiles perfectly to its true
    // 221,041 bytes. The one thing wrong with it that structure can see is that
    // /handover_briefing.mov's ftyp header sits inside its mdat payload.
    let Some((img, man)) = fixture() else { return };
    let p = planted(man)
        .into_iter()
        .find(|p| p.path == "/sealing_procedure.mov")
        .expect("sealing_procedure.mov is planted");
    let at = p.extents[0].0 as usize;
    let r = mp4::analyze(&img[at..]);

    // every other term is perfect -- the box tree really does tile
    assert_eq!(r.top_level_boxes, 3);
    assert!(r.rubric.tiling > 0.0, "the contiguous read tiles exactly");
    assert!(r.rubric.mdat_present > 0.0);
    assert_eq!(r.rubric.payload_exclusivity, 0.0);
    assert!(!r.validation.valid);

    // and the foreign header is handover_briefing.mov's, at a known offset
    let handover = planted(man)
        .into_iter()
        .find(|p| p.path == "/handover_briefing.mov")
        .unwrap();
    assert_eq!(
        r.foreign_header_at.map(|o| o + at as u64),
        Some(handover.extents[0].0),
        "the ftyp found inside sealing_procedure's mdat is handover_briefing's"
    );
    eprintln!(
        "sealing_procedure.mov contiguous: score {:.4}, rejected by payload exclusivity :: {}",
        r.validation.score, r.validation.detail
    );
}

#[test]
fn the_contiguous_mp4_that_survives_overlaps_another_recovered_object() {
    // The driver-level resolution, measured. /handover_briefing.mov's wrong
    // contiguous extent claims bytes that /sealing_procedure.mov's correct
    // second extent already owns; its true extents claim none. Two recovered
    // objects cannot own the same bytes, which is a check the carve driver can
    // make and a single validate() call cannot.
    let Some((_img, man)) = fixture() else { return };
    let files = planted(man);
    let h = files.iter().find(|p| p.path == "/handover_briefing.mov").unwrap();
    let s = files.iter().find(|p| p.path == "/sealing_procedure.mov").unwrap();

    let wrong = (h.extents[0].0, h.extents[0].0 + h.size);
    let sealing_second = (s.extents[1].0, s.extents[1].0 + s.extents[1].1);
    let overlap = wrong.1.min(sealing_second.1).saturating_sub(wrong.0.max(sealing_second.0));
    assert!(overlap > 0, "the wrong contiguous extent must overlap sealing_procedure");
    assert_eq!(overlap, 21_633, "measured overlap in bytes");

    for e in &h.extents {
        let t = (e.0, e.0 + e.1);
        let o = t.1.min(sealing_second.1).saturating_sub(t.0.max(sealing_second.0));
        assert_eq!(o, 0, "the true extents of handover_briefing overlap nothing");
    }
    eprintln!(
        "handover_briefing.mov: wrong contiguous extent [{}, {}) overlaps sealing_procedure's second extent by {} bytes; its true extents overlap 0",
        wrong.0, wrong.1, overlap
    );
}

// ===========================================================================
// 2 · the two the fixture plants to defeat us
// ===========================================================================

#[test]
fn the_reversed_jpeg_is_unrecoverable_by_a_forward_search_and_the_carver_says_so() {
    // evidence_bag_seal.jpg. The manifest marks it unrecoverable-by-design: its
    // second fragment lies BEFORE its first on disk, so a forward-only
    // bifragment search cannot reach it. Three separate claims are made here,
    // because "we failed" is only credible if we can also say precisely why.
    let Some((img, man)) = fixture() else { return };
    let p = planted(man)
        .into_iter()
        .find(|p| p.path == "/evidence_bag_seal.jpg")
        .expect("the reversed JPEG is planted");
    assert_eq!(p.kind, Kind::Jpeg);
    assert_eq!(p.recoverable, "unrecoverable-by-design");
    assert_eq!(p.extents.len(), 2);

    // (a) the fragments run backwards on disk
    assert!(
        p.extents[1].0 < p.extents[0].0,
        "extent 1 at {} is not before extent 0 at {}",
        p.extents[1].0, p.extents[0].0
    );

    // (b) read contiguously from the header, it fails
    let at = p.extents[0].0 as usize;
    let contiguous = jpeg::validate(&img[at..]);
    assert!(!contiguous.valid, "the reversed JPEG must not carve contiguously");

    // (c) every FORWARD two-fragment split within the manifest's own gap bound
    //     also fails. max_gap_clusters x bytes_per_cluster is the search window
    //     the carver is allowed; nothing inside it reconstructs this file.
    let cluster = man.get("bytes_per_cluster").unwrap().u() as usize;
    let max_gap = man.get("max_gap_clusters").unwrap().u() as usize * cluster;
    let head_len = p.extents[0].1 as usize;
    let mut tried = 0usize;
    // Split the head at every cluster boundary, then resume after every
    // cluster-aligned forward gap. This is the search bifragment.rs performs.
    let mut split = cluster;
    while split <= head_len {
        let mut gap = cluster;
        while gap <= max_gap {
            let resume = at + split + gap;
            let take = p.size as usize - split;
            if resume + take <= img.len() {
                let mut buf = Vec::with_capacity(p.size as usize);
                buf.extend_from_slice(&img[at..at + split]);
                buf.extend_from_slice(&img[resume..resume + take]);
                let v = jpeg::validate(&buf);
                assert!(
                    !(v.valid && v.end == Some(p.size)),
                    "a forward split at {} with a {}-byte gap reconstructed the reversed JPEG",
                    split, gap
                );
                tried += 1;
            }
            gap += cluster;
        }
        split += cluster;
    }
    assert!(tried > 1000, "only {} forward splits were tried", tried);

    // (d) and the object itself is intact -- reassembled in its true order it
    //     validates. The barrier is the search direction, not the carver.
    let buf = assembled(img, &p, 4096);
    let v = jpeg::validate(&buf);
    assert!(v.valid, "the reversed JPEG in true order: {}", v.detail);
    assert_eq!(v.end, Some(p.size));
    eprintln!(
        "evidence_bag_seal.jpg: {} forward splits tried, all rejected; true-order score {:.4}",
        tried, v.score
    );
}

// ===========================================================================
// 3 · THE RESIDUE IS ADVERSARIAL -- every planted false positive is rejected
// ===========================================================================

#[test]
fn every_jpeg_residue_decoy_is_rejected() {
    let Some((img, man)) = fixture() else { return };
    let expected = man
        .get("residue_signature_false_positives")
        .unwrap()
        .get("JPEG")
        .unwrap()
        .u() as usize;
    let ranges = planted_ranges(man);
    let hits: Vec<u64> = find_all(img, &[0xFF, 0xD8, 0xFF])
        .into_iter()
        .filter(|&o| !in_planted(&ranges, o))
        .collect();
    assert_eq!(hits.len(), expected, "residue JPEG hit count moved from the manifest's {}", expected);

    let mut survivors = Vec::new();
    for &o in &hits {
        let v = jpeg::validate(&img[o as usize..]);
        eprintln!(
            "decoy JPEG @{:>9} valid={} score={:.4} :: {}",
            o, v.valid, v.score, v.detail
        );
        if v.valid {
            survivors.push(o);
        }
    }
    assert!(survivors.is_empty(), "{} JPEG decoys survived structure validation: {:?}", survivors.len(), survivors);
    assert_eq!(hits.len(), 8, "the manifest's measured JPEG false-positive floor");
}

#[test]
fn every_gzip_residue_decoy_is_rejected_and_one_needs_the_inflater() {
    let Some((img, man)) = fixture() else { return };
    let expected = man
        .get("residue_signature_false_positives")
        .unwrap()
        .get("GZIP")
        .unwrap()
        .u() as usize;
    let ranges = planted_ranges(man);
    let hits: Vec<u64> = find_all(img, &[0x1F, 0x8B, 0x08])
        .into_iter()
        .filter(|&o| !in_planted(&ranges, o))
        .collect();
    assert_eq!(hits.len(), expected, "residue GZIP hit count moved from the manifest's {}", expected);

    let mut survivors = Vec::new();
    let mut needed_inflate = Vec::new();
    for &o in &hits {
        let r = gzip::analyze(&img[o as usize..]);
        // A decoy whose header is clean got past every cheap check; only
        // inflating its body rejects it.
        if r.rubric.header_fields > 0.0 {
            needed_inflate.push(o);
        }
        eprintln!(
            "decoy GZIP @{:>9} valid={} header_term={:.2} score={:.4} :: {}",
            o, r.validation.valid, r.rubric.header_fields, r.validation.score, r.validation.detail
        );
        if r.validation.valid {
            survivors.push(o);
        }
    }
    assert!(survivors.is_empty(), "{} GZIP decoys survived: {:?}", survivors.len(), survivors);
    assert_eq!(hits.len(), 13, "the manifest's measured GZIP false-positive floor");
    // Measured on this image: exactly one of the thirteen has FLG = 0x00, so
    // twelve die on the header and one dies on the DEFLATE stream. That one is
    // the reason this crate carries an inflater.
    assert_eq!(
        needed_inflate.len(), 1,
        "expected exactly one FLG-clean GZIP decoy, found {:?}", needed_inflate
    );
    assert_eq!(needed_inflate, vec![173_564_124]);
}

#[test]
fn png_and_mp4_residue_floors_are_zero_as_the_manifest_measured() {
    let Some((img, man)) = fixture() else { return };
    let fp = man.get("residue_signature_false_positives").unwrap();
    let ranges = planted_ranges(man);

    let png_hits: Vec<u64> = find_all(img, &png::SIGNATURE)
        .into_iter()
        .filter(|&o| !in_planted(&ranges, o))
        .collect();
    assert_eq!(png_hits.len() as u64, fp.get("PNG").unwrap().u());
    assert_eq!(png_hits.len(), 0);

    // MP4's magic is `ftyp` at offset 4 of the object; the manifest counts the
    // magic, so the scan does too.
    let mp4_hits: Vec<u64> = find_all(img, b"ftyp")
        .into_iter()
        .filter(|&o| !in_planted(&ranges, o))
        .collect();
    assert_eq!(mp4_hits.len() as u64, fp.get("MP4").unwrap().u());
    assert_eq!(mp4_hits.len(), 0);

    // An eight-byte signature does not occur by chance in 134 MB of residue and
    // a four-byte one is already marginal; the three-byte JPEG and GZIP magics
    // are where the false positives live. Still, every hit that DOES exist is
    // rejected, so the claim is not resting on the count being zero.
    for &o in png_hits.iter().chain(mp4_hits.iter()) {
        let start = o.saturating_sub(4) as usize;
        assert!(!png::validate(&img[o as usize..]).valid);
        assert!(!mp4::validate(&img[start..]).valid);
    }
}

// ===========================================================================
// 4 · the measured summary, printed so the numbers on the slide have a source
// ===========================================================================

#[test]
fn measured_summary() {
    let Some((img, man)) = fixture() else { return };
    let files = planted(man);
    let mut rows: Vec<(String, String, bool, f64, u64, u64, u128)> = Vec::new();
    for p in &files {
        let buf = if p.fragmented {
            assembled(img, p, 8192)
        } else {
            img[p.extents[0].0 as usize..].to_vec()
        };
        // Timed because bifragment.rs calls this thousands of times per
        // candidate and needs a real cost, not an assurance. Debug build.
        let t0 = std::time::Instant::now();
        let v = validate(p.kind, &buf);
        let us = t0.elapsed().as_micros();
        rows.push((
            p.kind.as_str().to_string(),
            p.path.clone(),
            v.valid,
            v.score,
            v.end.unwrap_or(0),
            p.size,
            us,
        ));
    }
    eprintln!("\n  KIND     PATH                             VALID  SCORE   END      SIZE    VALIDATE_us");
    for (k, path, valid, score, end, size, us) in &rows {
        eprintln!(
            "  {:<8} {:<32} {:<6} {:.4}  {:>7}  {:>7}  {:>8}",
            k, path, valid, score, end, size, us
        );
    }
    let ok = rows.iter().filter(|r| r.2 && r.4 == r.5).count();
    eprintln!("  {} of {} objects of these four kinds validated with an exact end\n", ok, rows.len());
    assert_eq!(ok, rows.len());
}

/// What one wrong reassembly costs, measured, because `bifragment.rs` will make
/// thousands of them and needs a number rather than an assurance.
///
/// The interesting case is GZIP: it is the only validator here that does real
/// work on the whole object (an inflate), so it is the one that could make a
/// gap search unaffordable. The measurement below separates the two costs that
/// matter -- a wrong split that dies inside the DEFLATE stream, which is what
/// almost every candidate does, and a wrong split that inflates all the way to
/// a mismatched trailer, which is the worst case.
#[test]
fn measured_cost_of_a_rejected_reassembly() {
    let Some((img, man)) = fixture() else { return };
    let files = planted(man);
    let cluster = man.get("bytes_per_cluster").unwrap().u() as usize;
    let p = files.iter().find(|p| p.path == "/imaging_transcript.txt.gz").unwrap();
    let at = p.extents[0].0 as usize;
    let head = p.extents[0].1 as usize;

    let mut n = 0usize;
    let mut total_ns = 0u128;
    let mut accepted = 0usize;
    let mut split = cluster;
    while split <= head {
        let mut gap = cluster;
        while gap <= 16 * cluster {
            let resume = at + split + gap;
            let take = p.size as usize - split;
            // The TRUE reassembly is one of the points in this grid; skip it,
            // and assert separately below that it is the one that passes.
            let is_true = split == head && resume as u64 == p.extents[1].0;
            if !is_true && resume + take <= img.len() {
                let mut buf = Vec::with_capacity(p.size as usize);
                buf.extend_from_slice(&img[at..at + split]);
                buf.extend_from_slice(&img[resume..resume + take]);
                let t0 = std::time::Instant::now();
                let v = gzip::validate(&buf);
                total_ns += t0.elapsed().as_nanos();
                if v.valid {
                    accepted += 1;
                }
                n += 1;
            }
            gap += cluster;
        }
        split += cluster;
    }
    assert!(n > 100, "only {} wrong reassemblies were tried", n);
    assert_eq!(accepted, 0, "a wrong GZIP reassembly was accepted");
    // and the one point in the grid that was skipped is the right answer
    let truth = assembled(img, p, 0);
    let tv = gzip::validate(&truth);
    assert!(tv.valid && tv.end == Some(p.size), "the true reassembly: {}", tv.detail);
    eprintln!(
        "gzip: {} wrong reassemblies of /imaging_transcript.txt.gz, all rejected, mean {:.1} us each",
        n,
        total_ns as f64 / n as f64 / 1000.0
    );

    // The worst case for comparison: the contiguous read, which inflates
    // 250,401 bytes before the trailer disagrees.
    let t0 = std::time::Instant::now();
    let v = gzip::validate(&img[at..]);
    let worst = t0.elapsed().as_micros();
    assert!(!v.valid);
    eprintln!("gzip: the contiguous read costs {} us before the trailer rejects it", worst);
}
