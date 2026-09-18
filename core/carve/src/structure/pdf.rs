use super::zip::{inflate_zlib, inflate_zlib_checked};
use super::{clamp01, Validation};

const MAX_SCAN: usize = 64 << 20;
const STARTXREF_LOOKBACK: usize = 160;
const EOF_SCAN_FLOOR: usize = 1 << 20;
const MAX_PREV_HOPS: usize = 16;
const CATALOG_WINDOW: usize = 16 << 10;

const W_HEADER: f64 = 0.10;
const W_EOF: f64 = 0.10;
const W_XREF_AT: f64 = 0.15;
const W_TRAILER: f64 = 0.20;
const W_ENTRIES: f64 = 0.30;
const W_CATALOG: f64 = 0.15;

const VALID_HIT_MIN: f64 = 0.95;
const VALID_MIN_VERIFIED: usize = 3;

#[derive(Clone, Copy, PartialEq)]
enum XrefForm {
    Classic,
    Stream,
}

struct XrefSet {
    inuse: Vec<(u32, u64)>,
    in_objstm: usize,
    root: Option<u32>,
    size: Option<u64>,
    form: XrefForm,
    encrypted: bool,
}

pub fn validate(data: &[u8]) -> Validation {
    let window = &data[..data.len().min(MAX_SCAN)];

    let header_ok = window.len() >= 8
        && &window[..5] == b"%PDF-"
        && window[5].is_ascii_digit()
        && window[6] == b'.'
        && window[7].is_ascii_digit();
    if !header_ok {
        return reject(0.0, "pdf no %PDF-N.M at candidate offset");
    }
    let version = format!("{}.{}", window[5] as char, window[7] as char);

    let (eofs, scanned) = find_eofs_bounded(window);
    if eofs.is_empty() {
        return reject(
            W_HEADER,
            &format!(
                "pdf header {} but no %%EOF within {} bytes",
                version, scanned
            ),
        );
    }

    let mut best: Option<Validation> = None;
    for &eof_at in eofs.iter().rev() {
        let v = try_revision(window, eof_at, &version);
        let better = match &best {
            None => true,
            Some(b) => v.score > b.score || (v.valid && !b.valid),
        };
        if better {
            let done = v.valid;
            best = Some(v);
            if done {
                break;
            }
        }
    }
    best.unwrap_or_else(|| reject(W_HEADER, "pdf header only"))
}

fn try_revision(d: &[u8], eof_at: usize, version: &str) -> Validation {
    let mut score = W_HEADER;
    let mut notes: Vec<String> = Vec::new();

    let mut end = eof_at + 5;
    if d.get(end) == Some(&b'\r') {
        end += 1;
    }
    if d.get(end) == Some(&b'\n') {
        end += 1;
    }

    let lo = eof_at.saturating_sub(STARTXREF_LOOKBACK);
    let sx_kw = match rfind(&d[lo..eof_at], b"startxref") {
        Some(rel) => lo + rel,
        None => {
            return Validation {
                valid: false,
                end: None,
                score: clamp01(score),
                detail: format!("pdf {} %%EOF@{} without startxref", version, eof_at),
            }
        }
    };
    let (sx, _) = match parse_uint(d, skip_ws(d, sx_kw + 9)) {
        Some(v) => v,
        None => {
            return Validation {
                valid: false,
                end: None,
                score: clamp01(score),
                detail: format!("pdf {} startxref@{} has no integer", version, sx_kw),
            }
        }
    };
    score += W_EOF;
    let sx = sx as usize;
    if sx >= eof_at {
        return Validation {
            valid: false,
            end: None,
            score: clamp01(score),
            detail: format!("pdf {} startxref={} is not inside the object", version, sx),
        };
    }

    let set = match collect_xref(d, sx) {
        Some(s) => s,
        None => {
            return Validation {
                valid: false,
                end: None,
                score: clamp01(score),
                detail: format!(
                    "pdf {} startxref={} does not land on `xref` or an /Type /XRef object",
                    version, sx
                ),
            }
        }
    };
    score += W_XREF_AT;

    let root = set.root;
    if root.is_some() {
        let max_obj = set.inuse.iter().map(|e| e.0).max().unwrap_or(0) as u64;
        let size_ok = match set.size {
            Some(s) => s > max_obj,
            None => false,
        };
        score += if size_ok { W_TRAILER } else { W_TRAILER * 0.75 };
        if !size_ok {
            notes.push(format!("size={:?} max_obj={}", set.size, max_obj));
        }
    } else {
        notes.push("trailer=/Root absent".into());
    }

    let total = set.inuse.len();
    let mut hits = 0usize;
    for &(obj, off) in &set.inuse {
        if object_header_at(d, off as usize, obj) {
            hits += 1;
        }
    }
    let ratio = if total == 0 {
        0.0
    } else {
        hits as f64 / total as f64
    };
    score += W_ENTRIES * ratio;

    let mut catalog_ok = false;
    if let Some(r) = root {
        if let Some(&(_, off)) = set.inuse.iter().find(|e| e.0 == r) {
            if object_header_at(d, off as usize, r) {
                let hi = (off as usize + CATALOG_WINDOW).min(d.len());
                let body = &d[off as usize..hi];
                let stop = find(body, b"endobj").unwrap_or(body.len());
                catalog_ok = find(&body[..stop], b"/Catalog").is_some();
            }
        }
    }
    if catalog_ok {
        score += W_CATALOG;
    } else if root.is_some() {
        notes.push("root=not-a-/Catalog".into());
    }

    if set.encrypted {
        notes.push("encrypt=present(content-not-verified)".into());
    }
    if set.in_objstm > 0 {
        notes.push(format!("objstm-entries={}(unverifiable)", set.in_objstm));
    }

    let valid = root.is_some()
        && catalog_ok
        && hits >= VALID_MIN_VERIFIED
        && ratio >= VALID_HIT_MIN
        && end <= d.len();

    let detail = format!(
        "pdf-{} xref={} objs={} verified={}/{} root={} end={}{}{}",
        version,
        match set.form {
            XrefForm::Classic => "table",
            XrefForm::Stream => "stream",
        },
        total,
        hits,
        total,
        root.map(|r| r.to_string()).unwrap_or_else(|| "-".into()),
        end,
        if notes.is_empty() { "" } else { " " },
        notes.join(" ")
    );

    Validation {
        valid,
        end: if end <= d.len() {
            Some(end as u64)
        } else {
            None
        },
        score: clamp01(score),
        detail,
    }
}

fn collect_xref(d: &[u8], at: usize) -> Option<XrefSet> {
    let mut merged: Vec<(u32, u64)> = Vec::new();
    let mut seen_obj: Vec<u32> = Vec::new();
    let mut in_objstm = 0usize;
    let mut root: Option<u32> = None;
    let mut size: Option<u64> = None;
    let mut encrypted = false;
    let mut form: Option<XrefForm> = None;

    let mut visited: Vec<usize> = Vec::new();
    let mut next = Some(at);
    let mut hops = 0usize;
    while let Some(pos) = next {
        if visited.contains(&pos) || hops >= MAX_PREV_HOPS || pos >= d.len() {
            break;
        }
        visited.push(pos);
        hops += 1;

        let section = match parse_xref_section(d, pos) {
            Some(s) => s,
            None if hops == 1 => return None,
            None => break,
        };
        if form.is_none() {
            form = Some(section.form);
        }
        if root.is_none() {
            root = section.root;
        }
        if size.is_none() {
            size = section.size;
        }
        encrypted |= section.encrypted;
        in_objstm += section.in_objstm;
        for (obj, off) in section.inuse {
            if !seen_obj.contains(&obj) {
                seen_obj.push(obj);
                merged.push((obj, off));
            }
        }
        next = section.prev;
    }

    if merged.is_empty() && root.is_none() {
        return None;
    }
    Some(XrefSet {
        inuse: merged,
        in_objstm,
        root,
        size,
        form: form.unwrap_or(XrefForm::Classic),
        encrypted,
    })
}

struct Section {
    inuse: Vec<(u32, u64)>,
    in_objstm: usize,
    root: Option<u32>,
    size: Option<u64>,
    prev: Option<usize>,
    form: XrefForm,
    encrypted: bool,
}

fn parse_xref_section(d: &[u8], at: usize) -> Option<Section> {
    let p = skip_ws(d, at);
    if d.len() > p + 4 && &d[p..p + 4] == b"xref" {
        parse_classic_xref(d, p + 4)
    } else {
        parse_xref_stream(d, p)
    }
}

fn parse_classic_xref(d: &[u8], mut p: usize) -> Option<Section> {
    let mut inuse = Vec::new();
    let mut subsections = 0usize;
    loop {
        p = skip_ws(d, p);
        if p + 7 <= d.len() && &d[p..p + 7] == b"trailer" {
            p += 7;
            break;
        }
        subsections += 1;
        if subsections > 100_000 {
            return None;
        }
        let (first, np) = parse_uint(d, p)?;
        let (count, np) = parse_uint(d, skip_ws(d, np))?;
        p = np;
        if count > 5_000_000 {
            return None;
        }
        for i in 0..count {
            p = skip_ws(d, p);
            let (off, np) = parse_uint(d, p)?;
            let (_gen, np) = parse_uint(d, skip_ws(d, np))?;
            let np = skip_ws(d, np);
            let ty = *d.get(np)?;
            p = np + 1;
            if ty == b'n' {
                inuse.push(((first + i) as u32, off));
            } else if ty != b'f' {
                return None;
            }
        }
        if inuse.len() > 5_000_000 {
            return None;
        }
    }
    let p = skip_ws(d, p);
    if d.get(p) != Some(&b'<') || d.get(p + 1) != Some(&b'<') {
        return None;
    }
    let (ds, de) = dict_extent(d, p)?;
    let dict = &d[ds..de];
    let root = dict_ref(dict, b"/Root");
    let size = dict_int(dict, b"/Size");
    let prev = dict_int(dict, b"/Prev").map(|v| v as usize);
    let encrypted = dict_key(dict, b"/Encrypt").is_some();
    Some(Section {
        inuse,
        in_objstm: 0,
        root,
        size,
        prev,
        form: XrefForm::Classic,
        encrypted,
    })
}

fn parse_xref_stream(d: &[u8], at: usize) -> Option<Section> {
    let (_obj, p) = parse_uint(d, at)?;
    let (_gen, p) = parse_uint(d, skip_ws(d, p))?;
    let p = skip_ws(d, p);
    if p + 3 > d.len() || &d[p..p + 3] != b"obj" {
        return None;
    }
    let p = skip_ws(d, p + 3);
    if d.get(p) != Some(&b'<') || d.get(p + 1) != Some(&b'<') {
        return None;
    }
    let (ds, de) = dict_extent(d, p)?;
    let dict = d[ds..de].to_vec();
    if !dict_is_name(&dict, b"/Type", b"/XRef") {
        return None;
    }

    let sk = de + 2;
    let sk = find(&d[sk..(sk + 64).min(d.len())], b"stream").map(|r| sk + r)?;
    let mut data_at = sk + 6;
    if d.get(data_at) == Some(&b'\r') {
        data_at += 1;
    }
    if d.get(data_at) == Some(&b'\n') {
        data_at += 1;
    }
    let declared = dict_int(&dict, b"/Length").map(|v| v as usize);
    let data_end = match declared {
        Some(n) if data_at + n <= d.len() => data_at + n,
        _ => {
            let hi = (data_at + (64 << 20)).min(d.len());
            data_at + find(&d[data_at..hi], b"endstream")?
        }
    };
    let raw = &d[data_at..data_end];

    let filters = dict_names(&dict, b"/Filter");
    let hint = 1 << 20;
    let decoded: Vec<u8> = if filters.is_empty() {
        raw.to_vec()
    } else if filters.len() == 1 && filters[0] == b"/FlateDecode" {
        match inflate_zlib_checked(raw, hint).or_else(|| inflate_zlib(raw, hint)) {
            Some(v) => v,
            None => return None,
        }
    } else {
        return Some(Section {
            inuse: Vec::new(),
            in_objstm: 0,
            root: dict_ref(&dict, b"/Root"),
            size: dict_int(&dict, b"/Size"),
            prev: dict_int(&dict, b"/Prev").map(|v| v as usize),
            form: XrefForm::Stream,
            encrypted: dict_key(&dict, b"/Encrypt").is_some(),
        });
    };

    let parms = dict_dict(&dict, b"/DecodeParms");
    let predictor = parms
        .as_ref()
        .and_then(|p| dict_int(p, b"/Predictor"))
        .unwrap_or(1);
    let columns = parms
        .as_ref()
        .and_then(|p| dict_int(p, b"/Columns"))
        .unwrap_or(1) as usize;
    let colors = parms
        .as_ref()
        .and_then(|p| dict_int(p, b"/Colors"))
        .unwrap_or(1) as usize;
    let bpc = parms
        .as_ref()
        .and_then(|p| dict_int(p, b"/BitsPerComponent"))
        .unwrap_or(8) as usize;
    let rows: Vec<u8> = if predictor >= 10 {
        let bpp = ((colors * bpc + 7) / 8).max(1);
        let rowlen = (columns * colors * bpc + 7) / 8;
        png_unpredict(&decoded, rowlen, bpp)?
    } else if predictor == 2 {
        return None;
    } else {
        decoded
    };

    let w = dict_ints_array(&dict, b"/W")?;
    if w.len() < 3 {
        return None;
    }
    let (w0, w1, w2) = (w[0] as usize, w[1] as usize, w[2] as usize);
    let stride: usize = w.iter().map(|v| *v as usize).sum();
    if stride == 0 || stride > 32 {
        return None;
    }
    let size = dict_int(&dict, b"/Size");
    let index =
        dict_ints_array(&dict, b"/Index").unwrap_or_else(|| vec![0, size.unwrap_or(0) as i64]);

    let mut inuse = Vec::new();
    let mut in_objstm = 0usize;
    let mut cur = 0usize;
    let mut k = 0usize;
    while k + 1 < index.len() {
        let first = index[k] as u64;
        let count = index[k + 1] as usize;
        k += 2;
        for i in 0..count {
            let at = cur + i * stride;
            if at + stride > rows.len() {
                break;
            }
            let f0 = if w0 == 0 {
                1u64
            } else {
                be_uint(&rows[at..at + w0])
            };
            let f1 = be_uint(&rows[at + w0..at + w0 + w1]);
            let _f2 = be_uint(&rows[at + w0 + w1..at + w0 + w1 + w2]);
            match f0 {
                1 => inuse.push(((first + i as u64) as u32, f1)),
                2 => in_objstm += 1,
                _ => {}
            }
        }
        cur += count * stride;
    }

    Some(Section {
        inuse,
        in_objstm,
        root: dict_ref(&dict, b"/Root"),
        size,
        prev: dict_int(&dict, b"/Prev").map(|v| v as usize),
        form: XrefForm::Stream,
        encrypted: dict_key(&dict, b"/Encrypt").is_some(),
    })
}

fn be_uint(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &x in b.iter().take(8) {
        v = (v << 8) | x as u64;
    }
    v
}

fn png_unpredict(src: &[u8], rowlen: usize, bpp: usize) -> Option<Vec<u8>> {
    if rowlen == 0 {
        return None;
    }
    let stride = rowlen + 1;
    let nrows = src.len() / stride;
    let mut out = vec![0u8; nrows * rowlen];
    for r in 0..nrows {
        let ft = src[r * stride];
        let inrow = &src[r * stride + 1..r * stride + 1 + rowlen];
        let cur_start = r * rowlen;
        let prev_start = if r > 0 { (r - 1) * rowlen } else { 0 };
        for i in 0..rowlen {
            let raw = inrow[i] as i32;
            let a = if i >= bpp {
                out[cur_start + i - bpp] as i32
            } else {
                0
            };
            let b = if r > 0 { out[prev_start + i] as i32 } else { 0 };
            let c = if r > 0 && i >= bpp {
                out[prev_start + i - bpp] as i32
            } else {
                0
            };
            let v = match ft {
                0 => raw,
                1 => raw + a,
                2 => raw + b,
                3 => raw + (a + b) / 2,
                4 => {
                    let p = a + b - c;
                    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
                    raw + if pa <= pb && pa <= pc {
                        a
                    } else if pb <= pc {
                        b
                    } else {
                        c
                    }
                }
                _ => return None,
            };
            out[cur_start + i] = (v & 0xFF) as u8;
        }
    }
    Some(out)
}

fn object_header_at(d: &[u8], at: usize, obj: u32) -> bool {
    if at >= d.len() {
        return false;
    }
    let p = skip_ws(d, at);
    let (n, p) = match parse_uint(d, p) {
        Some(v) => v,
        None => return false,
    };
    if n != obj as u64 {
        return false;
    }
    let p = skip_ws(d, p);
    let (_g, p) = match parse_uint(d, p) {
        Some(v) => v,
        None => return false,
    };
    let p = skip_ws(d, p);
    p + 3 <= d.len() && &d[p..p + 3] == b"obj"
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0C' | b'\0')
}

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn skip_ws(d: &[u8], mut p: usize) -> usize {
    loop {
        while p < d.len() && is_ws(d[p]) {
            p += 1;
        }
        if p < d.len() && d[p] == b'%' {
            while p < d.len() && d[p] != b'\n' && d[p] != b'\r' {
                p += 1;
            }
            continue;
        }
        return p;
    }
}

fn parse_uint(d: &[u8], p: usize) -> Option<(u64, usize)> {
    let mut i = p;
    let mut v: u64 = 0;
    let mut n = 0;
    while i < d.len() && d[i].is_ascii_digit() {
        v = v.checked_mul(10)?.checked_add((d[i] - b'0') as u64)?;
        i += 1;
        n += 1;
        if n > 19 {
            return None;
        }
    }
    if n == 0 {
        None
    } else {
        Some((v, i))
    }
}

fn dict_extent(d: &[u8], p: usize) -> Option<(usize, usize)> {
    if d.get(p) != Some(&b'<') || d.get(p + 1) != Some(&b'<') {
        return None;
    }
    let mut i = p + 2;
    let mut depth = 1usize;
    while i < d.len() {
        match d[i] {
            b'(' => {
                let mut par = 1usize;
                i += 1;
                while i < d.len() && par > 0 {
                    match d[i] {
                        b'\\' => i += 1,
                        b'(' => par += 1,
                        b')' => par -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                continue;
            }
            b'<' if d.get(i + 1) == Some(&b'<') => {
                depth += 1;
                i += 2;
                continue;
            }
            b'<' => {
                while i < d.len() && d[i] != b'>' {
                    i += 1;
                }
                i += 1;
                continue;
            }
            b'>' if d.get(i + 1) == Some(&b'>') => {
                depth -= 1;
                if depth == 0 {
                    return Some((p + 2, i));
                }
                i += 2;
                continue;
            }
            _ => i += 1,
        }
    }
    None
}

fn dict_key(dict: &[u8], key: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    let mut depth = 0i32;
    while i < dict.len() {
        match dict[i] {
            b'(' => {
                let mut par = 1usize;
                i += 1;
                while i < dict.len() && par > 0 {
                    match dict[i] {
                        b'\\' => i += 1,
                        b'(' => par += 1,
                        b')' => par -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                continue;
            }
            b'<' if dict.get(i + 1) == Some(&b'<') => {
                depth += 1;
                i += 2;
                continue;
            }
            b'>' if dict.get(i + 1) == Some(&b'>') => {
                depth -= 1;
                i += 2;
                continue;
            }
            b'<' => {
                while i < dict.len() && dict[i] != b'>' {
                    i += 1;
                }
                i += 1;
                continue;
            }
            b'[' => {
                depth += 1;
                i += 1;
                continue;
            }
            b']' => {
                depth -= 1;
                i += 1;
                continue;
            }
            b'/' if depth == 0 => {
                if dict.len() >= i + key.len() && &dict[i..i + key.len()] == key {
                    let after = i + key.len();
                    let ok = after >= dict.len() || is_ws(dict[after]) || is_delim(dict[after]);
                    if ok {
                        return Some(after);
                    }
                }
                i += 1;
                while i < dict.len() && !is_ws(dict[i]) && !is_delim(dict[i]) {
                    i += 1;
                }
                continue;
            }
            _ => i += 1,
        }
    }
    None
}

fn dict_int(dict: &[u8], key: &[u8]) -> Option<u64> {
    let p = dict_key(dict, key)?;
    parse_uint(dict, skip_ws(dict, p)).map(|(v, _)| v)
}

fn dict_ref(dict: &[u8], key: &[u8]) -> Option<u32> {
    let p = dict_key(dict, key)?;
    let (n, p) = parse_uint(dict, skip_ws(dict, p))?;
    let (_g, p) = parse_uint(dict, skip_ws(dict, p))?;
    let p = skip_ws(dict, p);
    if dict.get(p) == Some(&b'R') {
        Some(n as u32)
    } else {
        None
    }
}

fn dict_name<'a>(dict: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let p = dict_key(dict, key)?;
    let s = skip_ws(dict, p);
    if dict.get(s) != Some(&b'/') {
        return None;
    }
    let mut e = s + 1;
    while e < dict.len() && !is_ws(dict[e]) && !is_delim(dict[e]) {
        e += 1;
    }
    Some(&dict[s..e])
}

fn dict_is_name(dict: &[u8], key: &[u8], want: &[u8]) -> bool {
    dict_name(dict, key) == Some(want)
}

fn dict_names<'a>(dict: &'a [u8], key: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let p = match dict_key(dict, key) {
        Some(p) => p,
        None => return out,
    };
    let s = skip_ws(dict, p);
    if dict.get(s) == Some(&b'/') {
        if let Some(n) = dict_name(dict, key) {
            out.push(n);
        }
        return out;
    }
    if dict.get(s) != Some(&b'[') {
        return out;
    }
    let mut i = s + 1;
    while i < dict.len() && dict[i] != b']' {
        if dict[i] == b'/' {
            let st = i;
            i += 1;
            while i < dict.len() && !is_ws(dict[i]) && !is_delim(dict[i]) {
                i += 1;
            }
            out.push(&dict[st..i]);
        } else {
            i += 1;
        }
    }
    out
}

fn dict_ints_array(dict: &[u8], key: &[u8]) -> Option<Vec<i64>> {
    let p = dict_key(dict, key)?;
    let s = skip_ws(dict, p);
    if dict.get(s) != Some(&b'[') {
        return None;
    }
    let mut out = Vec::new();
    let mut i = s + 1;
    while i < dict.len() && dict[i] != b']' {
        if dict[i].is_ascii_digit() {
            let (v, np) = parse_uint(dict, i)?;
            out.push(v as i64);
            i = np;
        } else {
            i += 1;
        }
    }
    Some(out)
}

fn dict_dict(dict: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let p = dict_key(dict, key)?;
    let s = skip_ws(dict, p);
    let (a, b) = dict_extent(dict, s)?;
    Some(dict[a..b].to_vec())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let n = needle.len();
    let last = hay.len() - n;
    let mut i = 0usize;
    while i <= last {
        match hay[i..=last].iter().position(|&b| b == needle[0]) {
            Some(k) => {
                let j = i + k;
                if &hay[j..j + n] == needle {
                    return Some(j);
                }
                i = j + 1;
            }
            None => return None,
        }
    }
    None
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut i = hay.len() - needle.len();
    loop {
        if hay[i] == first && &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

fn find_eofs_bounded(hay: &[u8]) -> (Vec<usize>, usize) {
    let hard = hay.len();
    let mut out: Vec<usize> = Vec::new();
    let mut base = 0usize;
    let mut limit = hard;
    loop {
        if base >= limit {
            break;
        }
        match find(&hay[base..limit], b"%%EOF") {
            Some(r) => {
                let at = base + r;
                out.push(at);
                base = at + 1;
                limit = hard.min(at.saturating_mul(4).max(EOF_SCAN_FLOOR));
            }
            None => break,
        }
    }
    (out, limit)
}

fn reject(score: f64, detail: &str) -> Validation {
    Validation {
        valid: false,
        end: None,
        score: clamp01(score),
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structure::zip::fixture;

    const SKIP: &str = "SKIP: out/fixture.img absent; run `make fixtures`";

    fn near(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn fixture_pdf_contiguous_are_valid_with_exact_end() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let mut n = 0;
        for p in fixture::planted("PDF") {
            if p.fragmented {
                continue;
            }
            let v = validate(fixture::at_offset(&p));
            assert!(v.valid, "{} -> {}", p.path, v.detail);
            assert_eq!(v.end, Some(p.size), "{} -> {}", p.path, v.detail);
            assert!(
                near(v.score, 1.0),
                "{} score {} {}",
                p.path,
                v.score,
                v.detail
            );
            assert!(v.detail.contains("xref=table"), "{}", v.detail);
            n += 1;
        }
        assert_eq!(n, 4, "manifest should hold 4 contiguous PDF files");
    }

    #[test]
    fn fixture_pdf_truncated_at_60_percent_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        for p in fixture::planted("PDF") {
            let whole = fixture::bytes_of(&p);
            let cut = (whole.len() as f64 * 0.60) as usize;
            let v = validate(&whole[..cut]);
            assert!(
                !v.valid,
                "{} truncated to {} accepted: {}",
                p.path, cut, v.detail
            );
            assert!(v.end.is_none());
            assert!(near(v.score, W_HEADER), "{} score {}", p.path, v.score);
        }
    }

    #[test]
    fn broken_object_offsets_cost_exactly_their_share_and_then_reject() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = fixture::planted("PDF")
            .into_iter()
            .find(|p| !p.fragmented)
            .expect("a contiguous PDF");
        let good = fixture::bytes_of(&p);
        let base = validate(&good);
        assert!(base.valid, "{}", base.detail);

        let sx = {
            let at = rfind(&good, b"startxref").expect("startxref");
            parse_uint(&good, skip_ws(&good, at + 9)).unwrap().0 as usize
        };
        let set = collect_xref(&good, sx).expect("xref");
        let total = set.inuse.len();
        assert_eq!(total, 26, "{} has 26 in-use objects", p.path);
        let root = set.root.unwrap();
        let victims: Vec<u64> = set
            .inuse
            .iter()
            .filter(|e| e.0 != root)
            .map(|e| e.1)
            .take(2)
            .collect();

        let mut one = good.clone();
        for i in 0..8 {
            one[victims[0] as usize + i] = b'X';
        }
        let v1 = validate(&one);
        assert!(v1.valid, "{}", v1.detail);
        assert!(v1.detail.contains("verified=25/26"), "{}", v1.detail);
        assert!(
            near(v1.score, base.score - W_ENTRIES / total as f64),
            "score {} base {}",
            v1.score,
            base.score
        );

        let mut two = one.clone();
        for i in 0..8 {
            two[victims[1] as usize + i] = b'X';
        }
        let v2 = validate(&two);
        assert!(!v2.valid, "two broken offsets accepted: {}", v2.detail);
        assert!(v2.detail.contains("verified=24/26"), "{}", v2.detail);
    }

    #[test]
    fn startxref_pointing_at_junk_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = fixture::planted("PDF")
            .into_iter()
            .find(|p| !p.fragmented)
            .expect("a contiguous PDF");
        let mut bad = fixture::bytes_of(&p);
        let at = rfind(&bad, b"startxref").expect("startxref");
        let ds = skip_ws(&bad, at + 9);
        let (_, de) = parse_uint(&bad, ds).unwrap();
        let digits = de - ds;
        let replacement = format!("{:0width$}", 1234, width = digits);
        bad[ds..de].copy_from_slice(replacement.as_bytes());
        let v = validate(&bad);
        assert!(!v.valid, "junk startxref accepted: {}", v.detail);
        assert!(v.detail.contains("does not land on"), "{}", v.detail);
        assert!(near(v.score, W_HEADER + W_EOF), "score {}", v.score);
    }

    #[test]
    fn trailer_without_root_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = fixture::planted("PDF")
            .into_iter()
            .find(|p| !p.fragmented)
            .expect("a contiguous PDF");
        let good = fixture::bytes_of(&p);
        let mut bad = good.clone();
        let at = find(&bad, b"trailer").expect("trailer");
        let r = at + find(&bad[at..], b"/Root").expect("/Root");
        bad[r..r + 5].copy_from_slice(b"/Ruot");
        let v = validate(&bad);
        assert!(!v.valid, "trailer without /Root accepted: {}", v.detail);
        assert!(v.detail.contains("/Root absent"), "{}", v.detail);
        assert!(
            near(v.score, 1.0 - W_TRAILER - W_CATALOG),
            "score {}",
            v.score
        );
    }

    #[test]
    fn root_that_is_not_a_catalog_loses_exactly_that_term() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = fixture::planted("PDF")
            .into_iter()
            .find(|p| !p.fragmented)
            .expect("a contiguous PDF");
        let mut bad = fixture::bytes_of(&p);
        let c = find(&bad, b"/Catalog").expect("/Catalog");
        bad[c..c + 8].copy_from_slice(b"/Cataloq");
        let v = validate(&bad);
        assert!(!v.valid, "non-catalog root accepted: {}", v.detail);
        assert!(v.detail.contains("not-a-/Catalog"), "{}", v.detail);
        assert_eq!(v.end, Some(p.size));
        assert!(near(v.score, 1.0 - W_CATALOG), "score {}", v.score);
    }

    #[test]
    fn bifragment_pdf_is_not_valid_contiguously() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = fixture::planted("PDF")
            .into_iter()
            .find(|p| p.fragmented)
            .expect("disposal_certificate.pdf");
        assert_eq!(p.extents.len(), 2);
        let v = validate(fixture::at_offset(&p));
        assert!(!v.valid, "{} accepted contiguously: {}", p.path, v.detail);
        let joined = fixture::bytes_of(&p);
        let v2 = validate(&joined);
        assert!(v2.valid, "{} reassembled -> {}", p.path, v2.detail);
        assert_eq!(v2.end, Some(p.size));
        assert!(near(v2.score, 1.0), "score {}", v2.score);
    }

    fn push_row(rows: &mut Vec<u8>, ty: u8, f2: u32, f3: u16) {
        rows.push(ty);
        rows.extend_from_slice(&f2.to_be_bytes());
        rows.extend_from_slice(&f3.to_be_bytes());
    }

    fn zlib_stored(payload: &[u8]) -> Vec<u8> {
        let mut s = vec![0x78u8, 0x01];
        s.push(0x01);
        s.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        s.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        s.extend_from_slice(payload);
        s.extend_from_slice(&crate::structure::zip::adler32(payload).to_be_bytes());
        s
    }

    fn build_xref_stream_pdf(flate_with_predictor: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"%PDF-1.5\n%\xE2\xE3\xCF\xD3\n");
        let mut offs = [0u32; 4];
        offs[1] = out.len() as u32;
        out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        offs[2] = out.len() as u32;
        out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");
        offs[3] = out.len() as u32;

        let mut rows = Vec::new();
        push_row(&mut rows, 0, 0, 65535);
        push_row(&mut rows, 1, offs[1], 0);
        push_row(&mut rows, 1, offs[2], 0);
        push_row(&mut rows, 1, offs[3], 0);

        let (payload, parms) = if flate_with_predictor {
            let mut pred = Vec::new();
            for r in rows.chunks(7) {
                pred.push(0u8);
                pred.extend_from_slice(r);
            }
            (
                zlib_stored(&pred),
                " /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >>".to_string(),
            )
        } else {
            (rows.clone(), String::new())
        };

        let dict = format!(
            "3 0 obj\n<< /Type /XRef /Size 4 /W [1 4 2] /Root 1 0 R{} /Length {} >>\nstream\n",
            parms,
            payload.len()
        );
        out.extend_from_slice(dict.as_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(b"\nendstream\nendobj\n");
        out.extend_from_slice(format!("startxref\n{}\n%%EOF\n", offs[3]).as_bytes());
        out
    }

    #[test]
    fn pdf_15_uncompressed_xref_stream_validates() {
        let d = build_xref_stream_pdf(false);
        let v = validate(&d);
        assert!(v.valid, "{}", v.detail);
        assert!(v.detail.contains("xref=stream"), "{}", v.detail);
        assert!(v.detail.contains("verified=3/3"), "{}", v.detail);
        assert_eq!(v.end, Some(d.len() as u64));
        assert!(near(v.score, 1.0), "score {} {}", v.score, v.detail);
    }

    #[test]
    fn pdf_15_flatedecode_xref_stream_with_png_predictor_validates() {
        let d = build_xref_stream_pdf(true);
        let v = validate(&d);
        assert!(v.valid, "{}", v.detail);
        assert!(v.detail.contains("xref=stream"), "{}", v.detail);
        assert!(v.detail.contains("verified=3/3"), "{}", v.detail);
        assert_eq!(v.end, Some(d.len() as u64));
        assert!(near(v.score, 1.0), "score {} {}", v.score, v.detail);
    }

    #[test]
    fn pdf_15_xref_stream_with_a_lying_row_is_rejected() {
        let mut d = build_xref_stream_pdf(false);
        let at = find(&d, b"1 0 obj").expect("object 1");
        d[at..at + 7].copy_from_slice(b"9 0 obj");
        let v = validate(&d);
        assert!(!v.valid, "lying xref row accepted: {}", v.detail);
        assert!(v.detail.contains("verified=2/3"), "{}", v.detail);
    }

    #[test]
    fn non_pdf_input_is_rejected_immediately() {
        let v = validate(b"not a pdf, nowhere near one");
        assert!(!v.valid);
        assert_eq!(v.score, 0.0);
        assert!(v.detail.contains("no %PDF-N.M"));
    }

    #[test]
    fn header_without_eof_earns_only_the_header_term() {
        let mut d = b"%PDF-1.7\n".to_vec();
        d.extend_from_slice(&[b'a'; 4096]);
        let v = validate(&d);
        assert!(!v.valid);
        assert!(near(v.score, W_HEADER), "score {}", v.score);
        assert!(v.detail.contains("no %%EOF"), "{}", v.detail);
    }

    #[test]
    fn eof_without_startxref_is_rejected() {
        let mut d = b"%PDF-1.7\n".to_vec();
        d.extend_from_slice(&[b'a'; 512]);
        d.extend_from_slice(b"\n%%EOF\n");
        let v = validate(&d);
        assert!(!v.valid);
        assert!(v.detail.contains("without startxref"), "{}", v.detail);
        assert!(near(v.score, W_HEADER), "score {}", v.score);
    }

    #[test]
    fn dict_keys_are_matched_at_the_top_level_only() {
        let d = b"<< /DecodeParms << /Type /Inner /Predictor 12 >> /Type /XRef /Size 9 >>";
        let (a, b) = dict_extent(d, 0).unwrap();
        let inner = &d[a..b];
        assert!(dict_is_name(inner, b"/Type", b"/XRef"));
        assert_eq!(dict_int(inner, b"/Size"), Some(9));
        assert_eq!(dict_int(inner, b"/Predictor"), None);
        let parms = dict_dict(inner, b"/DecodeParms").unwrap();
        assert_eq!(dict_int(&parms, b"/Predictor"), Some(12));
    }

    #[test]
    fn png_predictor_up_filter_reverses() {
        let src = [0u8, 10, 20, 30, 2u8, 1, 2, 3];
        let out = png_unpredict(&src, 3, 1).unwrap();
        assert_eq!(out, vec![10, 20, 30, 11, 22, 33]);
    }
}
