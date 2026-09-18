use sentinelwipe_carve::structure::{gzip, jpeg, mp4, png, validate};
use sentinelwipe_carve::Kind;

const IMAGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.img");
const MANIFEST_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.manifest.json");

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
    extents: Vec<(u64, u64)>,
}

fn kind_of(s: &str) -> Option<Kind> {
    match s {
        "JPEG" => Some(Kind::Jpeg),
        "PNG" => Some(Kind::Png),
        "GZIP" => Some(Kind::Gzip),
        "MP4" => Some(Kind::Mp4),
        _ => None,
    }
}

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
    assert_eq!(checked, 4, "bifragment count for these four kinds");
}

#[test]
fn fragmented_objects_read_contiguously_are_rejected_except_the_one_mp4_that_cannot_be() {
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
    let Some((img, man)) = fixture() else { return };
    let p = planted(man)
        .into_iter()
        .find(|p| p.path == "/sealing_procedure.mov")
        .expect("sealing_procedure.mov is planted");
    let at = p.extents[0].0 as usize;
    let r = mp4::analyze(&img[at..]);

    assert_eq!(r.top_level_boxes, 3);
    assert!(r.rubric.tiling > 0.0, "the contiguous read tiles exactly");
    assert!(r.rubric.mdat_present > 0.0);
    assert_eq!(r.rubric.payload_exclusivity, 0.0);
    assert!(!r.validation.valid);

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

#[test]
fn the_reversed_jpeg_is_unrecoverable_by_a_forward_search_and_the_carver_says_so() {
    let Some((img, man)) = fixture() else { return };
    let p = planted(man)
        .into_iter()
        .find(|p| p.path == "/evidence_bag_seal.jpg")
        .expect("the reversed JPEG is planted");
    assert_eq!(p.kind, Kind::Jpeg);
    assert_eq!(p.recoverable, "unrecoverable-by-design");
    assert_eq!(p.extents.len(), 2);

    assert!(
        p.extents[1].0 < p.extents[0].0,
        "extent 1 at {} is not before extent 0 at {}",
        p.extents[1].0, p.extents[0].0
    );

    let at = p.extents[0].0 as usize;
    let contiguous = jpeg::validate(&img[at..]);
    assert!(!contiguous.valid, "the reversed JPEG must not carve contiguously");

    let cluster = man.get("bytes_per_cluster").unwrap().u() as usize;
    let max_gap = man.get("max_gap_clusters").unwrap().u() as usize * cluster;
    let head_len = p.extents[0].1 as usize;
    let mut tried = 0usize;
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

    let buf = assembled(img, &p, 4096);
    let v = jpeg::validate(&buf);
    assert!(v.valid, "the reversed JPEG in true order: {}", v.detail);
    assert_eq!(v.end, Some(p.size));

    let forward = forward_reassembly_sweep(&buf[..p.size as usize], Kind::Jpeg, cluster);
    let png_control = {
        let png = planted(man).into_iter().find(|q| q.kind == Kind::Png && q.fragmented);
        png.map(|q| {
            let b = assembled(img, &q, 0);
            forward_reassembly_sweep(&b[..q.size as usize], Kind::Png, cluster)
        })
    };
    let gzip_control = {
        let gz = planted(man).into_iter().find(|q| q.kind == Kind::Gzip && q.fragmented);
        gz.map(|q| {
            let b = assembled(img, &q, 0);
            forward_reassembly_sweep(&b[..q.size as usize], Kind::Gzip, cluster)
        })
    };
    eprintln!(
        "evidence_bag_seal.jpg: {} forward splits tried against the image, all rejected; \
         true-order score {:.4}",
        tried, v.score
    );
    eprintln!(
        "evidence_bag_seal.jpg: re-planted FORWARD in benign filler, {} of {} split x gap \
         layouts reassembled. Controls of the same shape: PNG {:?}, GZIP {:?}. Direction is \
         sufficient to explain the non-recovery; it is not shown to be necessary.",
        forward.0, forward.1, png_control, gzip_control
    );
    assert_eq!(
        forward.0, 0,
        "a forward-laid-out two-fragment JPEG WAS reassembled ({} of {}). That is good news and \
         it makes (d)'s wording wrong in the other direction: re-measure and say so.",
        forward.0, forward.1
    );
    let (png_ok, png_n) = png_control.expect("the fixture plants a fragmented PNG");
    let (gz_ok, gz_n) = gzip_control.expect("the fixture plants a fragmented GZIP");
    assert!(
        png_ok == png_n && gz_ok == gz_n,
        "the controls did not recover ({png_ok} of {png_n} PNG, {gz_ok} of {gz_n} GZIP), so the \
         sweep is measuring the harness rather than the kind"
    );
}

fn forward_reassembly_sweep(obj: &[u8], kind: Kind, cluster: usize) -> (usize, usize) {
    const SPLITS: [usize; 6] = [2, 4, 8, 12, 18, 24];
    const GAPS: [usize; 4] = [1, 2, 4, 8];
    let max_gap_clusters = *GAPS.iter().max().unwrap() as u64;
    let mut ok = 0usize;
    let mut tried = 0usize;
    for &sc in SPLITS.iter() {
        let split = sc * cluster;
        if split >= obj.len() {
            continue;
        }
        for &gc in GAPS.iter() {
            let gap = gc * cluster;
            let total = split + gap + (obj.len() - split) + 4 * cluster;
            let mut canvas: Vec<u8> = (0..total).map(|i| (i % 97) as u8 + 1).collect();
            canvas[..split].copy_from_slice(&obj[..split]);
            canvas[split + gap..split + gap + (obj.len() - split)]
                .copy_from_slice(&obj[split..]);
            tried += 1;
            let got = sentinelwipe_carve::bifragment::bifragment(
                &canvas,
                kind,
                0,
                max_gap_clusters * cluster as u64,
                cluster as u64,
            );
            if let Some(r) = got {
                let mut bytes: Vec<u8> = Vec::new();
                for (o, l) in &r.extents {
                    bytes.extend_from_slice(&canvas[*o as usize..(*o + *l) as usize]);
                }
                if bytes == obj {
                    ok += 1;
                }
            }
        }
    }
    (ok, tried)
}

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

    let mp4_hits: Vec<u64> = find_all(img, b"ftyp")
        .into_iter()
        .filter(|&o| !in_planted(&ranges, o))
        .collect();
    assert_eq!(mp4_hits.len() as u64, fp.get("MP4").unwrap().u());
    assert_eq!(mp4_hits.len(), 0);

    for &o in png_hits.iter().chain(mp4_hits.iter()) {
        let start = o.saturating_sub(4) as usize;
        assert!(!png::validate(&img[o as usize..]).valid);
        assert!(!mp4::validate(&img[start..]).valid);
    }
}

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
    let truth = assembled(img, p, 0);
    let tv = gzip::validate(&truth);
    assert!(tv.valid && tv.end == Some(p.size), "the true reassembly: {}", tv.detail);
    eprintln!(
        "gzip: {} wrong reassemblies of /imaging_transcript.txt.gz, all rejected, mean {:.1} us each",
        n,
        total_ns as f64 / n as f64 / 1000.0
    );

    let t0 = std::time::Instant::now();
    let v = gzip::validate(&img[at..]);
    let worst = t0.elapsed().as_micros();
    assert!(!v.valid);
    eprintln!("gzip: the contiguous read costs {} us before the trailer rejects it", worst);
}
