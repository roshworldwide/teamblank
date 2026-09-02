//! PDF structure validation.
//!
//! Garfinkel, "Carving contiguous and fragmented files with fast object
//! validation", DFRWS 2007 (Digital Investigation 4S, pp. S2-S12): a header
//! match is a candidate, not a file.  Garfinkel's point is that a carver is
//! only as good as the decision procedure it runs over a candidate byte range,
//! and that the procedure has to be strong enough to reject the header-shaped
//! noise that a real disk is full of.  `%PDF-1.` is five bytes; this validator
//! refuses to call anything a PDF until the document's own cross-reference
//! table has been followed back into the bytes and found to be telling the
//! truth.
//!
//! The procedure, in order:
//!
//!   1. `%PDF-N.M` header with a plausible version;
//!   2. locate `%%EOF`, and immediately before it `startxref` with a decimal
//!      byte offset -- the pair is what makes a PDF self-locating;
//!   3. follow that offset and require it to land on either the `xref`
//!      keyword (classic table, PDF 1.0-1.4 and most 1.7 producers) or on an
//!      `N G obj` whose dictionary declares `/Type /XRef` (cross-reference
//!      stream, PDF 1.5+).  BOTH forms are parsed here;
//!   4. parse every subsection / stream row into (object number, offset);
//!   5. require the trailer dictionary -- or the xref stream's own dictionary
//!      -- to carry `/Root`;
//!   6. CROSS-CHECK: seek to each in-use entry's byte offset and require the
//!      bytes there to read `N G obj` with N equal to the object number the
//!      table claimed.  This is the step that costs a spliced or truncated
//!      candidate its score;
//!   7. resolve `/Root` and require that object to declare `/Type /Catalog`.
//!
//! `/Prev` chains (incremental updates) are followed to a bounded depth so a
//! multi-revision document is scored on its whole cross-reference set.
//!
//! Cross-reference streams: `/Filter /FlateDecode` is decoded with the
//! hand-rolled inflater in `structure::zip`, and PNG predictors 10-15
//! (`/DecodeParms /Predictor`) are reversed here.  What is NOT done, stated
//! rather than silently scored: type-2 entries name objects living inside an
//! object stream (`/ObjStm`), and this validator does not decompress object
//! streams, so those entries are counted as *unverifiable* and excluded from
//! the cross-check ratio rather than counted as hits.  `/Encrypt`ed documents
//! are reported and not claimed.  Linearised first-page xref tables are read
//! as ordinary tables.

use super::zip::{inflate_zlib, inflate_zlib_checked};
use super::{clamp01, Validation};

/// Upper bound on how far a single PDF candidate is followed.  The carver
/// hands over the rest of the image, so the scan must be bounded; a PDF whose
/// `%%EOF` lies beyond this is reported unrecoverable rather than guessed at.
const MAX_SCAN: usize = 64 << 20;
/// How far back from `%%EOF` `startxref` is allowed to sit.
const STARTXREF_LOOKBACK: usize = 160;
/// The `%%EOF` scan stops this far in once at least one `%%EOF` has been seen
/// (see `find_eofs_bounded`).  Measured effect on the fixture: 20-77 ms per PDF
/// candidate before, 0.3-0.6 ms after, for identical results.
const EOF_SCAN_FLOOR: usize = 1 << 20;
/// Bound on the `/Prev` chain, so a cyclic or hostile chain terminates.
const MAX_PREV_HOPS: usize = 16;
/// Bound on how much of an object body is searched for `/Type /Catalog`.
const CATALOG_WINDOW: usize = 16 << 10;

// -------------------------------------------------------------------------
// score weights -- published, and each term is measured, never asserted
// -------------------------------------------------------------------------
const W_HEADER: f64 = 0.10; // %PDF-N.M with a real version
const W_EOF: f64 = 0.10; // %%EOF preceded by startxref <int>
const W_XREF_AT: f64 = 0.15; // that offset lands on `xref` or an /Type /XRef object
const W_TRAILER: f64 = 0.20; // trailer dictionary carries /Root (and a plausible /Size)
const W_ENTRIES: f64 = 0.30; // fraction of in-use entries that land on `N G obj`
const W_CATALOG: f64 = 0.15; // /Root resolves to an object declaring /Type /Catalog

/// A document with more than 5% of its cross-reference offsets pointing at
/// something other than the object they name is reported as unrecoverable
/// rather than repaired: xref reconstruction is a different tool.
const VALID_HIT_MIN: f64 = 0.95;
/// Below this many verified objects the ratio is not evidence of anything.
const VALID_MIN_VERIFIED: usize = 3;

#[derive(Clone, Copy, PartialEq)]
enum XrefForm {
    Classic,
    Stream,
}

struct XrefSet {
    /// (object number, byte offset) for in-use, directly-addressable objects.
    inuse: Vec<(u32, u64)>,
    /// Entries that name an object inside an /ObjStm: real, but not checkable
    /// here.  Counted separately so the ratio never launders them as hits.
    in_objstm: usize,
    root: Option<u32>,
    size: Option<u64>,
    form: XrefForm,
    encrypted: bool,
}

/// Validate a PDF candidate whose header byte is `data[0]`.
pub fn validate(data: &[u8]) -> Validation {
    let window = &data[..data.len().min(MAX_SCAN)];

    // ---- 1 · header -----------------------------------------------------
    let header_ok = window.len() >= 8
        && &window[..5] == b"%PDF-"
        && window[5].is_ascii_digit()
        && window[6] == b'.'
        && window[7].is_ascii_digit();
    if !header_ok {
        return reject(0.0, "pdf no %PDF-N.M at candidate offset");
    }
    let version = format!("{}.{}", window[5] as char, window[7] as char);

    // ---- 2 · every %%EOF, newest first ----------------------------------
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

    // The last %%EOF whose startxref actually resolves is the true end: an
    // incrementally updated PDF has several, and residue after the object can
    // contribute spurious ones.  Try newest first and keep the best attempt
    // so a total failure still reports why.
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

    // `%%EOF` plus any single trailing end-of-line is the object's last byte.
    let mut end = eof_at + 5;
    if d.get(end) == Some(&b'\r') {
        end += 1;
    }
    if d.get(end) == Some(&b'\n') {
        end += 1;
    }

    // ---- 2 · startxref immediately before %%EOF -------------------------
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

    // ---- 3/4/5 · follow the offset, and its /Prev chain -----------------
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
        // /Size is a weak but free consistency signal: it must be at least one
        // more than the largest object number the table addresses.
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

    // ---- 6 · cross-check every in-use offset against `N G obj` ----------
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

    // ---- 7 · /Root resolves to a /Catalog -------------------------------
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

    // `end` is reported whenever the object's terminator was genuinely
    // established -- `startxref` resolved to a real cross-reference section and
    // `%%EOF` closed it -- even when the document then failed a later check.
    // structure/mod.rs documents that state, and the carver needs the length to
    // step past a damaged object rather than rescan it.
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

// -------------------------------------------------------------------------
// cross-reference collection
// -------------------------------------------------------------------------

/// Follow `at` and its `/Prev` chain, merging every section's in-use entries.
/// The newest section wins for a repeated object number.
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
            // The first hop is the one `startxref` names: if it does not
            // parse, there is no cross-reference set at all.  A later /Prev
            // hop that fails only truncates the chain.
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

/// Classic table:  `xref` (subsection header `first count`, then `count`
/// 20-byte entries)* `trailer` `<< ... >>`.
/// Entries are parsed token-wise rather than by fixed stride, because 19-byte
/// entries from older producers are common and are still unambiguous.
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
            return None; // a digit field that never reaches `trailer`
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
    // Hybrid-reference files put a 1.5 xref stream beside the classic table.
    // It is not followed: the classic table already addresses every object a
    // 1.4 reader needs, and the ratio must not be diluted by a second copy.
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

/// PDF 1.5+ cross-reference stream: `N G obj << /Type /XRef /W [a b c] ... >>
/// stream ... endstream`.
fn parse_xref_stream(d: &[u8], at: usize) -> Option<Section> {
    // `N G obj`
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

    // stream payload
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
        // /Length may be an indirect reference; bound by `endstream` instead.
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
        // /ASCIIHexDecode, /LZWDecode and friends are not implemented.  The
        // dictionary was still verified, so the caller learns the form was
        // recognised and the rows were not read.
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

    // /DecodeParms /Predictor: PNG predictors 10-15 are the common case.
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
        return None; // TIFF predictor 2 is not implemented for xref streams
    } else {
        decoded
    };

    // /W widths and /Index subsections
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

/// Reverse the PNG row filters used by `/Predictor` 10-15 (RFC 2083 §6).
fn png_unpredict(src: &[u8], rowlen: usize, bpp: usize) -> Option<Vec<u8>> {
    if rowlen == 0 {
        return None;
    }
    let stride = rowlen + 1;
    // Whole rows only: a trailing partial row is ignored rather than guessed at.
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

// -------------------------------------------------------------------------
// byte-level helpers.  No regex, no allocation in the hot paths.
// -------------------------------------------------------------------------

/// `data[at..]` reads `obj 0 obj` (any generation) for object number `obj`.
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

/// Span of a dictionary's contents given `p` at its opening `<<`.
/// Returns (inner_start, inner_end); `inner_end` is the index of the closing
/// `>`, so the dictionary occupies `p ..= inner_end + 1`.
fn dict_extent(d: &[u8], p: usize) -> Option<(usize, usize)> {
    if d.get(p) != Some(&b'<') || d.get(p + 1) != Some(&b'<') {
        return None;
    }
    let mut i = p + 2;
    let mut depth = 1usize;
    while i < d.len() {
        match d[i] {
            b'(' => {
                // literal string: balanced parens, backslash escapes
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
                // hex string
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

/// Position just past `key` when it occurs at the dictionary's top level.
/// Nested dictionaries and arrays are skipped so `/Type` inside
/// `/DecodeParms` never masquerades as the outer `/Type`.
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
                // skip the whole name token
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

/// `/Key N G R` -> N
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

/// `/Filter /X` or `/Filter [/X /Y]` -> the names, in order.
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

/// `/Key [a b c]` -> the integers.
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

/// `/Key << ... >>` -> a copy of the nested dictionary's contents.
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
        // `position` over the first byte is the vectorisable part of the scan;
        // the full compare only runs on a first-byte hit.
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

/// Every `%%EOF` in the candidate, with the scan bounded by what it finds.
///
/// The carver hands over the rest of the image, so an unconditional scan costs
/// `MAX_SCAN` on every PDF candidate whether the object is 40 KB or 40 MB --
/// measured at 20-77 ms each on the fixture.  A PDF's revisions are contiguous,
/// so once a `%%EOF` has been seen at offset E the object cannot plausibly
/// continue past `4*E`, and anything further belongs to something else.  The
/// scan therefore runs to `MAX_SCAN` only until the first `%%EOF`, and after
/// that to `max(4*E, EOF_SCAN_FLOOR)`.  Returns the positions and how far the
/// scan actually reached, so a rejection can name a real number.
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

    /// The 4 contiguous fixture PDFs carve to their exact manifest length with
    /// a perfect rubric: classic xref table, every offset landing on the object
    /// it names, /Root resolving to a /Catalog.
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

    /// Cut every PDF at 60% and require rejection.
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
            // The rubric collapses to the header term alone: with the tail gone
            // there is no %%EOF, so nothing downstream of it can be earned.
            assert!(near(v.score, W_HEADER), "{} score {}", p.path, v.score);
        }
    }

    /// The xref cross-check in isolation, and the published 5% tolerance
    /// measured rather than asserted.  Overwrite the `N G obj` line of objects
    /// the table names; every byte offset in the file is untouched.
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

        // One broken offset: 25/26 = 0.9615 is above the 0.95 gate, so the
        // document is still recovered -- and the score records the damage.
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

        // Two broken offsets: 24/26 = 0.923 is below the gate.
        let mut two = one.clone();
        for i in 0..8 {
            two[victims[1] as usize + i] = b'X';
        }
        let v2 = validate(&two);
        assert!(!v2.valid, "two broken offsets accepted: {}", v2.detail);
        assert!(v2.detail.contains("verified=24/26"), "{}", v2.detail);
    }

    /// `startxref` that does not land on a cross-reference section.  Same
    /// length, so nothing in the file moves.
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
        // Header + the startxref/%%EOF pairing were still earned; nothing else.
        assert!(near(v.score, W_HEADER + W_EOF), "score {}", v.score);
    }

    /// A trailer with no /Root is not a document.  `/Root` -> `/Ruot`, same
    /// length, every offset preserved.
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
        // The trailer term and the catalog term both go; the 26 object offsets
        // are untouched and still earn their 0.30.
        assert!(
            near(v.score, 1.0 - W_TRAILER - W_CATALOG),
            "score {}",
            v.score
        );
    }

    /// /Root that resolves to an object which is not a /Catalog.
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
        // startxref resolved and %%EOF closed the object, so the extent is
        // known even though the document is rejected.
        assert_eq!(v.end, Some(p.size));
        assert!(near(v.score, 1.0 - W_CATALOG), "score {}", v.score);
    }

    /// The bifragment PDF: the fixture splits it across a 128-cluster gap, so
    /// contiguous validation from its header must fail.  Reassembly is
    /// bifragment.rs's job, not this validator's.
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
        // ...and the same bytes reassembled by extent DO validate, which is
        // what proves the failure above is fragmentation and not this parser.
        let joined = fixture::bytes_of(&p);
        let v2 = validate(&joined);
        assert!(v2.valid, "{} reassembled -> {}", p.path, v2.detail);
        assert_eq!(v2.end, Some(p.size));
        assert!(near(v2.score, 1.0), "score {}", v2.score);
    }

    // ---- PDF 1.5+ cross-reference streams -------------------------------
    //
    // The fixture corpus is PDF 1.7 with classic xref tables throughout, so
    // the 1.5 path is exercised on documents assembled here, byte by byte,
    // rather than claimed to work off a file nobody carved.

    fn push_row(rows: &mut Vec<u8>, ty: u8, f2: u32, f3: u16) {
        rows.push(ty);
        rows.extend_from_slice(&f2.to_be_bytes());
        rows.extend_from_slice(&f3.to_be_bytes());
    }

    /// A zlib stream (RFC 1950) whose DEFLATE body is a single stored block.
    /// Built by hand because this crate has an inflater and no compressor,
    /// and a stored block needs neither.
    fn zlib_stored(payload: &[u8]) -> Vec<u8> {
        let mut s = vec![0x78u8, 0x01]; // CMF/FLG, (0x7801 % 31 == 0)
        s.push(0x01); // BFINAL=1, BTYPE=00
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
        // Field 1 is the ENTRY TYPE, not the object number: 0 free, 1 in-use
        // at a byte offset, 2 inside an object stream.  Objects 1..3 are all
        // type 1; the object number comes from /Index, which defaults to
        // [0 /Size].
        push_row(&mut rows, 0, 0, 65535);
        push_row(&mut rows, 1, offs[1], 0);
        push_row(&mut rows, 1, offs[2], 0);
        push_row(&mut rows, 1, offs[3], 0);

        let (payload, parms) = if flate_with_predictor {
            // /Predictor 12 is PNG prediction; each row carries its own filter
            // type byte, and 0 (None) is a legal choice for every row.
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

    /// The same 1.5 document with one object body moved: the stream's own rows
    /// now lie, and the cross-check is the only thing that can notice.
    #[test]
    fn pdf_15_xref_stream_with_a_lying_row_is_rejected() {
        let mut d = build_xref_stream_pdf(false);
        let at = find(&d, b"1 0 obj").expect("object 1");
        d[at..at + 7].copy_from_slice(b"9 0 obj");
        let v = validate(&d);
        assert!(!v.valid, "lying xref row accepted: {}", v.detail);
        assert!(v.detail.contains("verified=2/3"), "{}", v.detail);
    }

    // ---- terms that need no fixture -------------------------------------

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

    /// The dictionary reader must not confuse a nested key with an outer one.
    #[test]
    fn dict_keys_are_matched_at_the_top_level_only() {
        let d = b"<< /DecodeParms << /Type /Inner /Predictor 12 >> /Type /XRef /Size 9 >>";
        let (a, b) = dict_extent(d, 0).unwrap();
        let inner = &d[a..b];
        assert!(dict_is_name(inner, b"/Type", b"/XRef"));
        assert_eq!(dict_int(inner, b"/Size"), Some(9));
        // /Predictor lives one level down and must be invisible from here.
        assert_eq!(dict_int(inner, b"/Predictor"), None);
        let parms = dict_dict(inner, b"/DecodeParms").unwrap();
        assert_eq!(dict_int(&parms, b"/Predictor"), Some(12));
    }

    /// PNG predictor reversal, checked against a hand-computed Up filter.
    #[test]
    fn png_predictor_up_filter_reverses() {
        // rowlen 3, two rows: [10 20 30] then Up-filtered [1 2 3] -> [11 22 33]
        let src = [0u8, 10, 20, 30, 2u8, 1, 2, 3];
        let out = png_unpredict(&src, 3, 1).unwrap();
        assert_eq!(out, vec![10, 20, 30, 11, 22, 33]);
    }
}
