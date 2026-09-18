use sentinelwipe_carve::confidence::{
    confidence, Confidence, MIN_CONFIDENCE, NON_STRUCTURE_CEILING, STRUCTURAL_BREACH_POINT,
    W_ENTROPY, W_SIGNATURE, W_SIZE, W_STRUCTURE,
};
use sentinelwipe_carve::signature::{next_footer, scan, signature_for, Candidate, SIGNATURES};
use sentinelwipe_carve::structure::validate;
use sentinelwipe_carve::Kind;

const IMAGE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.img");
const MANIFEST_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.manifest.json");

const TAIL: usize = 8192;

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
                Json::Num(t.parse().unwrap_or_else(|_| panic!("manifest: bad number {:?}", t)))
            }
        }
    }
}

fn fixture() -> &'static (Vec<u8>, Json) {
    static CACHE: std::sync::OnceLock<(Vec<u8>, Json)> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let img = std::fs::read(IMAGE_PATH);
        let man = std::fs::read(MANIFEST_PATH);
        match (img, man) {
            (Ok(i), Ok(m)) => {
                let j = P { b: &m, i: 0 }.value();
                (i, j)
            }
            (a, b) => {
                let err = a
                    .err()
                    .map(|e| e.to_string())
                    .or_else(|| b.err().map(|e| e.to_string()))
                    .unwrap_or_default();
                let required = std::env::var("SENTINELWIPE_REQUIRE_FIXTURE")
                    .map(|v| v == "1")
                    .unwrap_or(false);
                panic!(
                    "NOT VERIFIED -- the residue separation was not measured.\n  \
                     image:    {IMAGE_PATH}\n  \
                     manifest: {MANIFEST_PATH}\n  \
                     error:    {err}\n  \
                     SENTINELWIPE_REQUIRE_FIXTURE=1: {required}\n  \
                     Run `make fixtures`. This test never skips: a green run here \
                     would be a claim that the confidence score separates, made \
                     without having measured it."
                );
            }
        }
    })
}

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
    kind: Kind,
    size: u64,
    recoverable: String,
    extents: Vec<(u64, u64)>,
}

fn planted(man: &Json) -> Vec<Planted> {
    man.get("files")
        .expect("manifest has a files array")
        .arr()
        .iter()
        .filter_map(|f| {
            let kind = kind_of(f.get("kind").expect("file has a kind").s())?;
            Some(Planted {
                path: f.get("path")?.s().to_string(),
                kind,
                size: f.get("size")?.u(),
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
    ranges
        .binary_search_by(|r| {
            if at < r.0 {
                std::cmp::Ordering::Greater
            } else if at >= r.1 {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn largest_planted(files: &[Planted], kind: Kind) -> u64 {
    files
        .iter()
        .filter(|p| p.kind == kind)
        .map(|p| p.size)
        .max()
        .unwrap_or(0)
}

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

#[derive(Clone)]
struct Row {
    kind: Kind,
    label: String,
    len: u64,
    structurally_valid: bool,
    c: Confidence,
    ceiling: f64,
    detail: String,
}

impl Row {
    fn ceiling_of(c: &Confidence) -> f64 {
        c.total - W_ENTROPY * c.entropy_consistency - W_SIZE * c.size_plausibility
            + W_ENTROPY
            + W_SIZE
    }
}

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

fn score_planted(img: &[u8], p: &Planted) -> Row {
    let buf = assembled(img, p);
    let v = validate(p.kind, &buf);
    let end = v.end.unwrap_or(p.size).min(buf.len() as u64);
    let data = &buf[..end as usize];
    let sig_ok = header_matches(p.kind, &buf);
    let footer = footer_in_sequence(&buf, p.kind, end);
    let c = confidence(p.kind, sig_ok, footer, &v, data);
    Row {
        kind: p.kind,
        label: format!("{} [{}]", p.path, p.recoverable),
        len: end,
        structurally_valid: v.valid,
        ceiling: Row::ceiling_of(&c),
        c,
        detail: v.detail.clone(),
    }
}

fn score_residue(img: &[u8], cand: &Candidate, window: u64) -> Row {
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
    Row {
        kind: cand.kind,
        label: format!("residue @{}", cand.header_at),
        len: end - cand.header_at,
        structurally_valid: v.valid,
        ceiling: Row::ceiling_of(&c),
        c,
        detail: v.detail.clone(),
    }
}

struct Measurement {
    tp: Vec<Row>,
    fp: Vec<Row>,
    residue_by_kind: Vec<(Kind, usize)>,
}

fn measure() -> &'static Measurement {
    static CACHE: std::sync::OnceLock<Measurement> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let (img, man) = fixture();
            let files = planted(man);
            let ranges = planted_ranges(man);

            let tp: Vec<Row> = files.iter().map(|p| score_planted(img, p)).collect();

            let cands = scan(img);
            let residue: Vec<Candidate> = cands
                .into_iter()
                .filter(|c| !in_planted(&ranges, c.header_at))
                .collect();

            let mut residue_by_kind: Vec<(Kind, usize)> = Vec::new();
            for c in &residue {
                match residue_by_kind.iter_mut().find(|(k, _)| *k == c.kind) {
                    Some((_, n)) => *n += 1,
                    None => residue_by_kind.push((c.kind, 1)),
                }
            }

            let fp: Vec<Row> = residue
                .iter()
                .map(|c| score_residue(img, c, largest_planted(&files, c.kind)))
                .collect();

            Measurement { tp, fp, residue_by_kind }
        })
}

fn stats(rows: &[&Row]) -> (usize, f64, f64, f64) {
    let n = rows.len();
    let min = rows.iter().map(|r| r.c.total).fold(f64::INFINITY, f64::min);
    let max = rows.iter().map(|r| r.c.total).fold(f64::NEG_INFINITY, f64::max);
    let mean = rows.iter().map(|r| r.c.total).sum::<f64>() / n as f64;
    (n, min, max, mean)
}

fn kinds_present(rows: &[Row]) -> Vec<Kind> {
    let mut ks: Vec<Kind> = Vec::new();
    for r in rows {
        if !ks.contains(&r.kind) {
            ks.push(r.kind);
        }
    }
    ks
}

fn print_block(title: &str, rows: &[Row]) {
    eprintln!();
    eprintln!("{title}");
    eprintln!(
        "  {:<8} {:<44} {:>9}  {:>6} {:>6} {:>6} {:>6}  {:>6} {:>6}",
        "KIND", "OBJECT", "BYTES", "sig", "struct", "entr", "size", "TOTAL", "CEIL"
    );
    let mut sorted: Vec<&Row> = rows.iter().collect();
    sorted.sort_by(|a, b| {
        a.kind
            .as_str()
            .cmp(b.kind.as_str())
            .then(a.c.total.partial_cmp(&b.c.total).unwrap())
    });
    for r in sorted {
        eprintln!(
            "  {:<8} {:<44} {:>9}  {:>6.4} {:>6.4} {:>6.4} {:>6.4}  {:>6.4} {:>6.4}",
            r.kind.as_str(),
            truncate(&r.label, 44),
            r.len,
            r.c.signature_integrity,
            r.c.structural_validity,
            r.c.entropy_consistency,
            r.c.size_plausibility,
            r.c.total,
            r.ceiling,
        );
    }
    eprintln!();
    eprintln!("  {:<28} {:>4} {:>8} {:>8} {:>8}", "", "n", "min", "max", "mean");
    let all: Vec<&Row> = rows.iter().collect();
    let (n, mn, mx, me) = stats(&all);
    eprintln!("  {:<28} {:>4} {:>8.4} {:>8.4} {:>8.4}", "ALL", n, mn, mx, me);
    for k in kinds_present(rows) {
        let sub: Vec<&Row> = rows.iter().filter(|r| r.kind == k).collect();
        let (n, mn, mx, me) = stats(&sub);
        eprintln!(
            "  {:<28} {:>4} {:>8.4} {:>8.4} {:>8.4}",
            format!("  {}", k.as_str()),
            n,
            mn,
            mx,
            me
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).chain("~".chars()).collect()
    }
}

fn assert_populations_are_the_manifest_counts() {
    let (_, man) = fixture();
    let m = measure();

    let files = planted(man);
    assert_eq!(
        files.len(),
        35,
        "40 planted files minus the 5 TXT files, which carry no signature"
    );
    assert_eq!(man.get("files").unwrap().arr().len(), 40, "planted total");
    assert_eq!(m.tp.len(), 35, "true positives scored");

    let fpk = man.get("residue_signature_false_positives").unwrap();
    let mut expected: Vec<(Kind, usize)> = Vec::new();
    for (name, kind) in [
        ("JPEG", Kind::Jpeg),
        ("PNG", Kind::Png),
        ("PDF", Kind::Pdf),
        ("ZIP", Kind::Zip),
        ("SQLITE", Kind::Sqlite),
        ("MP4", Kind::Mp4),
        ("GZIP", Kind::Gzip),
    ] {
        let n = fpk.get(name).expect("manifest records this kind").u() as usize;
        if n > 0 {
            expected.push((kind, n));
        }
    }
    let mut got: Vec<(Kind, usize)> = m.residue_by_kind.clone();
    got.sort_by_key(|(k, _)| k.as_str());
    expected.sort_by_key(|(k, _)| k.as_str());
    assert_eq!(
        got.iter().map(|(k, n)| (k.as_str(), *n)).collect::<Vec<_>>(),
        expected.iter().map(|(k, n)| (k.as_str(), *n)).collect::<Vec<_>>(),
        "residue candidates from the shipped scanner disagree with the manifest"
    );
    assert_eq!(m.fp.len(), 21, "8 JPEG + 13 GZIP");
    assert_eq!(
        fpk.get("BZ2").unwrap().u(),
        11,
        "the manifest's 11 BZ2 residue hits: excluded, BZ2 is not a Kind variant \
         and no SIGNATURES row detects it"
    );

    for (name, kind, n) in [
        ("JPEG", Kind::Jpeg, 5usize),
        ("PNG", Kind::Png, 5),
        ("PDF", Kind::Pdf, 5),
        ("ZIP/DOCX", Kind::Zip, 5),
        ("SQLITE", Kind::Sqlite, 5),
        ("MP4", Kind::Mp4, 5),
        ("GZIP", Kind::Gzip, 5),
    ] {
        let got = m.tp.iter().filter(|r| r.kind == kind).count();
        assert_eq!(got, n, "planted {name} count");
    }
}

#[test]
fn the_two_populations_are_the_ones_the_manifest_counts() {
    let (img, man) = fixture();
    assert_eq!(img.len(), 268_435_456, "fixture image length");
    assert_eq!(img.len() as u64, man.get("image_bytes").unwrap().u());

    eprintln!(
        "manifest DECLARES image_sha256 {} -- not recomputed here; core/carve computes no hash",
        man.get("image_sha256").unwrap().s()
    );
    eprintln!(
        "verified here instead: image length {} bytes == manifest image_bytes",
        img.len()
    );

    assert_populations_are_the_manifest_counts();
}

#[test]
fn residue_separation_measured_through_shipped_structure_and_confidence() {
    assert_populations_are_the_manifest_counts();
    let m = measure();

    print_block("TRUE POSITIVES -- 35 planted carvable files, scored on correct bytes", &m.tp);
    print_block("FALSE POSITIVES -- 21 residue signature hits in free space", &m.fp);

    let lowest_tp = m.tp.iter().map(|r| r.c.total).fold(f64::INFINITY, f64::min);
    let highest_fp = m.fp.iter().map(|r| r.c.total).fold(f64::NEG_INFINITY, f64::max);
    let highest_fp_ceiling = m.fp.iter().map(|r| r.ceiling).fold(f64::NEG_INFINITY, f64::max);
    let gap = lowest_tp - highest_fp;

    eprintln!();
    eprintln!("SEPARATION");
    eprintln!("  lowest true positive             {lowest_tp:.4}");
    eprintln!("  highest false positive           {highest_fp:.4}");
    eprintln!("  gap                              {gap:.4}");
    eprintln!("  highest false positive CEILING   {highest_fp_ceiling:.4}   (terms 3+4 pinned to 1.0000)");
    eprintln!("  gap against that ceiling         {:.4}", lowest_tp - highest_fp_ceiling);
    eprintln!("  admission gate                   {MIN_CONFIDENCE:.4}");
    eprintln!(
        "  margin below lowest TP           {:.4}",
        lowest_tp - MIN_CONFIDENCE
    );
    eprintln!(
        "  margin above highest FP ceiling  {:.4}",
        MIN_CONFIDENCE - highest_fp_ceiling
    );

    assert!(
        gap > 0.0,
        "the populations OVERLAP: lowest TP {lowest_tp:.4} <= highest FP {highest_fp:.4}"
    );

    let close = |a: f64, b: f64| (a - b).abs() < 1e-9;
    assert_eq!(m.tp.len(), 35, "the 0.9000 edge below is a claim about 35 planted files");
    assert_eq!(m.fp.len(), 21, "the 0.6500 edge below is a claim about 21 residue decoys");
    assert!(close(lowest_tp, 0.9000), "lowest true positive moved to {lowest_tp:.4}");
    assert!(close(highest_fp, 0.6500), "highest false positive moved to {highest_fp:.4}");
    assert!(close(gap, 0.2500), "the separation moved to {gap:.4}");
    assert!(
        close(highest_fp_ceiling, 0.6500),
        "the adversarial ceiling moved to {highest_fp_ceiling:.4}"
    );

    let tp_mean = m.tp.iter().map(|r| r.c.total).sum::<f64>() / m.tp.len() as f64;
    let fp_mean = m.fp.iter().map(|r| r.c.total).sum::<f64>() / m.fp.len() as f64;
    assert!(close((tp_mean * 1e4).round(), 9571.0), "planted mean moved to {tp_mean:.4}");
    assert!(close((fp_mean * 1e4).round(), 5805.0), "residue mean moved to {fp_mean:.4}");
}

#[test]
fn zero_false_positives_reach_the_admission_gate() {
    assert_populations_are_the_manifest_counts();
    let m = measure();

    let admitted: Vec<&Row> = m.fp.iter().filter(|r| r.c.total >= MIN_CONFIDENCE).collect();
    assert!(
        admitted.is_empty(),
        "{} residue decoys reached the {MIN_CONFIDENCE:.2} gate: {:?}",
        admitted.len(),
        admitted.iter().map(|r| (r.label.clone(), r.c.total)).collect::<Vec<_>>()
    );

    let admitted_ceiling: Vec<&Row> = m.fp.iter().filter(|r| r.ceiling >= MIN_CONFIDENCE).collect();
    assert!(
        admitted_ceiling.is_empty(),
        "{} residue decoys reach the {MIN_CONFIDENCE:.2} gate even at their \
         adversarial ceiling (entropy and size pinned to 1.0000): {:?}",
        admitted_ceiling.len(),
        admitted_ceiling.iter().map(|r| (r.label.clone(), r.ceiling)).collect::<Vec<_>>()
    );

    let rejected: Vec<&Row> = m.tp.iter().filter(|r| r.c.total < MIN_CONFIDENCE).collect();
    assert!(
        rejected.is_empty(),
        "{} planted files fall BELOW the {MIN_CONFIDENCE:.2} gate: {:?}",
        rejected.len(),
        rejected.iter().map(|r| (r.label.clone(), r.c.total)).collect::<Vec<_>>()
    );
}

#[test]
fn a_gate_at_0_90_would_discard_the_footerless_kinds() {
    assert_populations_are_the_manifest_counts();
    let m = measure();
    let at_exactly_0_90: Vec<&Row> = m
        .tp
        .iter()
        .filter(|r| (r.c.total - 0.90).abs() < 1e-12)
        .collect();
    eprintln!();
    eprintln!(
        "planted files scoring EXACTLY 0.9000: {} of {}",
        at_exactly_0_90.len(),
        m.tp.len()
    );
    for r in &at_exactly_0_90 {
        eprintln!("  {:<8} {}", r.kind.as_str(), r.label);
    }
    for r in &at_exactly_0_90 {
        assert!(
            matches!(r.kind, Kind::Gzip | Kind::Mp4 | Kind::Sqlite),
            "{} scores exactly 0.9000 but is not a footerless kind",
            r.label
        );
        assert!(
            (r.c.signature_integrity - 0.75).abs() < 1e-12,
            "{}: expected the footerless ceiling on term 1",
            r.label
        );
    }
    assert_eq!(
        at_exactly_0_90.len(),
        15,
        "a strict gate at 0.90 would discard exactly these planted files"
    );
    let strictly_above: usize = m.tp.iter().filter(|r| r.c.total > 0.90).count();
    eprintln!("planted files strictly above 0.9000: {strictly_above} of {}", m.tp.len());

    assert!(
        MIN_CONFIDENCE < 0.90,
        "confidence::MIN_CONFIDENCE is {MIN_CONFIDENCE:.4}; at 0.90 these {} planted files \
         are discarded",
        at_exactly_0_90.len()
    );
}

#[test]
fn structure_is_the_only_term_that_separates_the_populations() {
    assert_populations_are_the_manifest_counts();
    let m = measure();

    let mean = |rows: &[Row], f: fn(&Confidence) -> f64| {
        rows.iter().map(|r| f(&r.c)).sum::<f64>() / rows.len() as f64
    };
    let min = |rows: &[Row], f: fn(&Confidence) -> f64| {
        rows.iter().map(|r| f(&r.c)).fold(f64::INFINITY, f64::min)
    };
    let max = |rows: &[Row], f: fn(&Confidence) -> f64| {
        rows.iter().map(|r| f(&r.c)).fold(f64::NEG_INFINITY, f64::max)
    };

    eprintln!();
    eprintln!("PER-TERM CONTRIBUTION      weight     planted (min/max/mean)      residue (min/max/mean)   weighted separation");
    let terms: [(&str, f64, fn(&Confidence) -> f64); 4] = [
        ("1 signature_integrity", W_SIGNATURE, |c| c.signature_integrity),
        ("2 structural_validity", W_STRUCTURE, |c| c.structural_validity),
        ("3 entropy_consistency", W_ENTROPY, |c| c.entropy_consistency),
        ("4 size_plausibility  ", W_SIZE, |c| c.size_plausibility),
    ];
    for (name, w, f) in terms {
        let sep = w * (mean(&m.tp, f) - mean(&m.fp, f));
        eprintln!(
            "  {name}   {w:.2}     {:.4} {:.4} {:.4}         {:.4} {:.4} {:.4}        {sep:+.4}",
            min(&m.tp, f),
            max(&m.tp, f),
            mean(&m.tp, f),
            min(&m.fp, f),
            max(&m.fp, f),
            mean(&m.fp, f),
        );
    }

    for r in &m.fp {
        assert!(
            !r.structurally_valid,
            "a residue decoy passed structure::validate's hard gate: {} :: {}",
            r.label, r.detail
        );
    }
    let mut partial: Vec<&Row> = m.fp.iter().filter(|r| r.c.structural_validity > 0.0).collect();
    partial.sort_by(|a, b| b.c.structural_validity.partial_cmp(&a.c.structural_validity).unwrap());
    eprintln!();
    eprintln!(
        "residue decoys earning PARTIAL structural credit: {} of {}",
        partial.len(),
        m.fp.len()
    );
    for r in &partial {
        eprintln!(
            "  {:<6} {:<24} structure={:.4}  :: {}",
            r.kind.as_str(),
            r.label,
            r.c.structural_validity,
            r.detail
        );
    }
    let worst_structure = m.fp.iter().map(|r| r.c.structural_validity).fold(0.0f64, f64::max);
    let headroom = STRUCTURAL_BREACH_POINT - worst_structure;

    eprintln!();
    eprintln!("STRUCTURAL HEADROOM -- how far residue is from being admitted as evidence");
    eprintln!("  admission gate         MIN_CONFIDENCE            {MIN_CONFIDENCE:.4}");
    eprintln!("  decoy free credit      NON_STRUCTURE_CEILING     {NON_STRUCTURE_CEILING:.4}   (sig+entropy+size at full marks)");
    eprintln!("  breach point           ({MIN_CONFIDENCE:.4} - {NON_STRUCTURE_CEILING:.4}) / {W_STRUCTURE:.4}   {STRUCTURAL_BREACH_POINT:.6}");
    eprintln!("  worst residue structure                          {worst_structure:.4}");
    eprintln!("  MEASURED HEADROOM                                {headroom:.4}");
    eprintln!(
        "  a decoy at the breach point would total          {:.4}",
        NON_STRUCTURE_CEILING + W_STRUCTURE * STRUCTURAL_BREACH_POINT
    );

    assert!(
        worst_structure < STRUCTURAL_BREACH_POINT,
        "residue structural credit reached {worst_structure:.4}, at or above the derived \
         breach point {STRUCTURAL_BREACH_POINT:.6} = (MIN_CONFIDENCE {MIN_CONFIDENCE:.4} - \
         NON_STRUCTURE_CEILING {NON_STRUCTURE_CEILING:.4}) / W_STRUCTURE. A decoy holding \
         full marks on signature, entropy and size -- which all 8 residue JPEGs already do -- \
         is now ADMITTED by the carver's own gate as recovered evidence."
    );

    assert_eq!(partial.len(), 1, "the count of residue decoys with non-zero structural credit has moved");
    assert_eq!(partial[0].kind.as_str(), "GZIP");
    assert_eq!(partial[0].c.structural_validity, 0.25, "the partial-credit decoy's rubric score has moved");
    for r in &m.tp {
        assert!(
            r.structurally_valid,
            "a planted file failed structure::validate on its own correct bytes: {} :: {}",
            r.label, r.detail
        );
        assert_eq!(
            r.c.structural_validity, 1.0,
            "{} did not score full structural validity: {}",
            r.label, r.detail
        );
    }

    for kind in [Kind::Jpeg, Kind::Gzip] {
        let tps: Vec<f64> = m
            .tp
            .iter()
            .filter(|r| r.kind == kind)
            .map(|r| r.c.signature_integrity)
            .collect();
        let fps: Vec<f64> = m
            .fp
            .iter()
            .filter(|r| r.kind == kind)
            .map(|r| r.c.signature_integrity)
            .collect();
        assert!(!tps.is_empty() && !fps.is_empty());
        let t0 = tps[0];
        assert!(
            tps.iter().all(|&x| x == t0) && fps.iter().all(|&x| x == t0),
            "term 1 separates {} -- planted {:?} residue {:?}",
            kind.as_str(),
            tps,
            fps
        );
        eprintln!(
            "term 1 on {}: planted and residue both score {:.4} -- no separation",
            kind.as_str(),
            t0
        );
    }
}
