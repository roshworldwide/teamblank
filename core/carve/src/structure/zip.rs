//! ZIP / OOXML (DOCX) structure validation.
//!
//! Garfinkel, "Carving contiguous and fragmented files with fast object
//! validation", DFRWS 2007 (Digital Investigation 4S, pp. S2-S12): a header
//! match is a *candidate*, not a file.  Garfinkel's object validator is a
//! decision procedure run over the candidate byte range, and his own ZIP
//! validator is the worked example -- the central directory is what makes a
//! ZIP self-describing, so a ZIP is validated by reading its directory and
//! confirming that every entry it names really exists where it says.
//!
//! This validator does exactly that, and then one step further, because the
//! fixture's adversarial residue is designed to survive weak checks:
//!
//!   1. walk the local file headers forward from byte 0, chaining on each
//!      header's declared compressed size, until the central directory begins;
//!   2. walk the central directory to its end and read the end-of-central-
//!      directory record, requiring cd_offset + cd_size == cd_position and
//!      the entry counts to agree;
//!   3. CROSS-CHECK: for every central-directory entry, seek to its declared
//!      local-header offset and require PK\x03\x04 there with a byte-identical
//!      filename.  A truncated or spliced archive fails here even when both
//!      halves are individually well formed;
//!   4. DECOMPRESS every member with the inflater in this file and require the
//!      CRC-32 and the uncompressed length to match what the directory claims.
//!
//! Step 4 is the check that cannot be faked by construction: the compressed
//! bytes have to actually be the bytes the directory says they are.
//!
//! OOXML (DOCX) rule, per ECMA-376 Part 2 / OPC: a package that carries
//! `word/`, `xl/`, `ppt/` or `docProps/` parts MUST also carry
//! `[Content_Types].xml`.  An archive that claims to be OOXML without it is
//! rejected, not merely down-scored.
//!
//! Deliberately NOT handled, stated rather than silently mis-scored:
//!   * ZIP64 (0x06064B50 / 0x07064B50) -- detected and reported, never claimed.
//!   * Encrypted entries (general-purpose bit 0) -- the local-header
//!     cross-check still applies, but the CRC of ciphertext cannot be
//!     verified, so such entries are excluded from the payload term and named
//!     in `detail`.
//!   * Multi-disk archives -- rejected.
//!
//! No new crate dependency: INFLATE (RFC 1951) is hand-rolled below, matching
//! the project's existing character (the fixture generator hand-rolls DEFLATE
//! for the same reason).  CRC-32 is `structure::crc32`, already hand-rolled in
//! `mod.rs` for PNG and GZIP -- ZIP uses the identical reflected-0xEDB88320
//! variant (APPNOTE.TXT 4.4.7), so it is reused rather than written twice.
//! The inflater is `pub(crate)` because `structure::pdf` needs it for
//! `/FlateDecode` cross-reference streams.

use super::{clamp01, crc32, le_u32, Validation};

const SIG_LFH: u32 = 0x0403_4B50; // PK\x03\x04  local file header
const SIG_CDH: u32 = 0x0201_4B50; // PK\x01\x02  central directory header
const SIG_EOCD: u32 = 0x0605_4B50; // PK\x05\x06  end of central directory
const SIG_EOCD64: u32 = 0x0606_4B50; // PK\x06\x06  ZIP64 EOCD
const SIG_EOCD64_LOC: u32 = 0x0706_4B50; // PK\x06\x07  ZIP64 EOCD locator

const LFH_FIXED: usize = 30;
const CDH_FIXED: usize = 46;
const EOCD_FIXED: usize = 22;

/// Upper bound on how far a single ZIP candidate is followed.  The carver is
/// handed the whole remaining image, so an unbounded scan would be O(image)
/// per candidate.  An archive longer than this is reported unrecoverable
/// rather than guessed at.
const MAX_SCAN: usize = 64 << 20;

/// Cap on a single member's inflated size.  Guards against a hostile or
/// corrupt header declaring a 4 GiB member.
const MAX_MEMBER_OUT: usize = 512 << 20;

/// How far the EOCD fallback scan runs when the local-header chain broke for a
/// reason OTHER than a data descriptor.  A candidate whose chain is
/// unfollowable and whose end-of-central-directory is not within a megabyte is
/// residue or a fragment, and "unrecoverable" is the honest answer rather than
/// a 64 MiB hunt.  Measured: 18.8 ms -> 0.3 ms per broken candidate.
const BROKEN_CHAIN_EOCD_SCAN: usize = 1 << 20;

// -------------------------------------------------------------------------
// score weights -- published, and each term is measured, never asserted
// -------------------------------------------------------------------------
const W_EOCD: f64 = 0.10; // EOCD located and arithmetically self-consistent
const W_CD: f64 = 0.15; // every central-directory record parses in bounds
const W_XCHECK: f64 = 0.30; // fraction of CD entries whose local header agrees
const W_PAYLOAD: f64 = 0.30; // fraction of members that inflate to a matching CRC-32
const W_IDENT: f64 = 0.15; // container identification (OOXML confirmed / plain ZIP)

/// A CD entry's cross-check must be perfect and its payload CRC must be
/// perfect for the object to be called valid.  Both ratios are also reported
/// so a partial result is visible rather than collapsed to a boolean.
const VALID_XCHECK_MIN: f64 = 1.0;
const VALID_PAYLOAD_MIN: f64 = 1.0;

fn le16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

/// Little-endian 32-bit read, bounds-checked.  Re-exported name for the
/// shared reader in `structure::mod`.
fn le32(d: &[u8], at: usize) -> Option<u32> {
    le_u32(d, at)
}

struct CentralEntry {
    flags: u16,
    method: u16,
    crc: u32,
    csize: u32,
    usize_: u32,
    lho: u32,
    name: Vec<u8>,
}

/// Validate a ZIP/DOCX candidate whose header byte is `data[0]`.
pub fn validate(data: &[u8]) -> Validation {
    if data.len() < LFH_FIXED || le32(data, 0) != Some(SIG_LFH) {
        return reject(0.0, "zip no PK\\x03\\x04 at candidate offset");
    }
    let window = &data[..data.len().min(MAX_SCAN)];

    // ---- 1 · locate the central directory ------------------------------
    // Primary path: chain forward through the local file headers.  This costs
    // one pass and needs no scanning, because every local header declares the
    // length of the member that follows it.
    let cd_start = match walk_local_headers(window) {
        Ok(at) => at,
        // Fallback: a streamed archive writes zero sizes into the local header
        // and the real ones into a trailing data descriptor, so the chain
        // cannot be followed at all.  That is the legitimate reason, and it
        // earns a full-window search for the EOCD.  Any other break gets a
        // 1 MiB look, because it is far more likely to be a fragment.
        Err(why) => {
            let horizon = match why {
                WalkFail::Streamed => window.len(),
                _ => window.len().min(BROKEN_CHAIN_EOCD_SCAN),
            };
            match scan_for_eocd(&window[..horizon]) {
                Some((_eocd_at, cd_off, _)) => cd_off as usize,
                None => {
                    return reject(
                        0.02,
                        &format!(
                            "zip local-header chain {} and no self-consistent EOCD within {} bytes",
                            why.as_str(),
                            horizon
                        ),
                    )
                }
            }
        }
    };
    if cd_start >= window.len() {
        return reject(0.04, "zip central directory begins past end of data");
    }

    // ---- 2 · walk the central directory --------------------------------
    let (entries, cd_end, cd_truncated) = walk_central_directory(window, cd_start);
    if entries.is_empty() {
        return reject(0.05, "zip central directory empty or unparseable");
    }
    let cd_parse_ok = !cd_truncated;

    // ---- 3 · end-of-central-directory record ---------------------------
    let mut score = 0.0f64;
    let mut notes: Vec<String> = Vec::new();
    let mut eocd_ok = false;
    let mut end: Option<u64> = None;

    if le32(window, cd_end) == Some(SIG_EOCD64) || le32(window, cd_end) == Some(SIG_EOCD64_LOC) {
        notes.push("zip64=present-unsupported".into());
    }
    let mut eocd_at = cd_end;
    // A ZIP64 EOCD record and its locator sit between the CD and the classic
    // EOCD.  Skip them so the classic record is still found, but never claim
    // the ZIP64 fields were interpreted.
    if le32(window, eocd_at) == Some(SIG_EOCD64) {
        if let Some(sz) = le64(window, eocd_at + 4) {
            eocd_at = eocd_at.saturating_add(12).saturating_add(sz as usize);
        }
    }
    if le32(window, eocd_at) == Some(SIG_EOCD64_LOC) {
        eocd_at += 20;
    }

    if le32(window, eocd_at) == Some(SIG_EOCD) {
        let disk = le16(window, eocd_at + 4).unwrap_or(0xFFFF);
        let cd_disk = le16(window, eocd_at + 6).unwrap_or(0xFFFF);
        let n_this = le16(window, eocd_at + 8).unwrap_or(0);
        let n_total = le16(window, eocd_at + 10).unwrap_or(0);
        // EOCD layout, APPNOTE.TXT 4.3.16: sig(0) disk(4) cd_disk(6)
        // n_this(8) n_total(10) cd_size(12) cd_offset(16) comment_len(20).
        let cd_size = le32(window, eocd_at + 12).unwrap_or(0) as usize;
        let cd_off = le32(window, eocd_at + 16).unwrap_or(0) as usize;
        let comment = le16(window, eocd_at + 20).unwrap_or(0) as usize;
        let counts_agree = n_this == n_total && n_total as usize == entries.len();
        let arith_ok = cd_off == cd_start && cd_size == cd_end - cd_start;
        let single_disk = disk == 0 && cd_disk == 0;
        eocd_ok = counts_agree && arith_ok && single_disk;
        if eocd_ok {
            score += W_EOCD;
        } else {
            notes.push(format!(
                "eocd counts={}/{}/{} arith={} disks={}/{}",
                n_this,
                n_total,
                entries.len(),
                arith_ok,
                disk,
                cd_disk
            ));
        }
        // The end is only reported when the EOCD's own arithmetic checks out.
        // An interior local header inside a real archive produces a parseable
        // EOCD whose offsets are relative to the archive's true start, not to
        // this candidate -- measured 31 times on the fixture -- and reporting
        // its arithmetic as a length would be a number we did not verify.
        let tail = eocd_at + EOCD_FIXED + comment;
        if eocd_ok && tail <= window.len() {
            end = Some(tail as u64);
        }
    } else {
        notes.push("eocd=absent".into());
    }

    if cd_parse_ok {
        score += W_CD;
    } else {
        notes.push("cd=truncated".into());
    }

    // ---- 4 · local-header cross-check ----------------------------------
    // The check Garfinkel's ZIP validator turns on: a directory entry is only
    // evidence if the thing it points at is really there.
    let mut xhits = 0usize;
    for e in &entries {
        let at = e.lho as usize;
        if le32(window, at) == Some(SIG_LFH) {
            let nlen = le16(window, at + 26).unwrap_or(0) as usize;
            let nstart = at + LFH_FIXED;
            if nlen == e.name.len() && window.len() >= nstart + nlen {
                if &window[nstart..nstart + nlen] == &e.name[..] {
                    xhits += 1;
                }
            }
        }
    }
    let xratio = xhits as f64 / entries.len() as f64;
    score += W_XCHECK * xratio;

    // ---- 5 · payload: inflate every member and match its CRC-32 --------
    let mut checked = 0usize;
    let mut payload_hits = 0usize;
    let mut encrypted = 0usize;
    for e in &entries {
        if e.flags & 0x0001 != 0 {
            encrypted += 1;
            continue;
        }
        let at = e.lho as usize;
        if le32(window, at) != Some(SIG_LFH) {
            checked += 1;
            continue;
        }
        let nlen = le16(window, at + 26).unwrap_or(0) as usize;
        let xlen = le16(window, at + 28).unwrap_or(0) as usize;
        let dstart = at + LFH_FIXED + nlen + xlen;
        let dend = dstart.saturating_add(e.csize as usize);
        checked += 1;
        if dend > window.len() {
            continue;
        }
        let raw = &window[dstart..dend];
        let out = match e.method {
            0 => Some(raw.to_vec()),
            8 => inflate_raw(raw, (e.usize_ as usize).min(MAX_MEMBER_OUT)),
            _ => None,
        };
        if let Some(out) = out {
            if out.len() == e.usize_ as usize && crc32(&out) == e.crc {
                payload_hits += 1;
            }
        }
    }
    let pratio = if checked == 0 {
        0.0
    } else {
        payload_hits as f64 / checked as f64
    };
    score += W_PAYLOAD * pratio;
    if encrypted > 0 {
        notes.push(format!("encrypted={}(crc-unverifiable)", encrypted));
    }

    // ---- 6 · container identification ----------------------------------
    let has_ct = entries
        .iter()
        .any(|e| e.name.as_slice() == b"[Content_Types].xml");
    let ooxml_parts = entries.iter().any(|e| {
        starts_with(&e.name, b"word/")
            || starts_with(&e.name, b"xl/")
            || starts_with(&e.name, b"ppt/")
            || starts_with(&e.name, b"docProps/")
    });
    let mut ooxml_rule_ok = true;
    let kindtag;
    if ooxml_parts && has_ct {
        score += W_IDENT;
        kindtag = "ooxml";
    } else if ooxml_parts && !has_ct {
        // OPC requires the content-types stream.  Refuse rather than round up.
        ooxml_rule_ok = false;
        kindtag = "ooxml-missing-content-types";
        notes.push("opc=[Content_Types].xml absent".into());
    } else {
        score += W_IDENT * 0.6;
        kindtag = "zip";
    }

    let valid = eocd_ok
        && cd_parse_ok
        && ooxml_rule_ok
        && xratio >= VALID_XCHECK_MIN
        && pratio >= VALID_PAYLOAD_MIN
        && end.is_some();

    let detail = format!(
        "{} entries={} xcheck={}/{} payload={}/{} cd@{} end={}{}{}",
        kindtag,
        entries.len(),
        xhits,
        entries.len(),
        payload_hits,
        checked,
        cd_start,
        end.map(|e| e.to_string()).unwrap_or_else(|| "?".into()),
        if notes.is_empty() { "" } else { " " },
        notes.join(" ")
    );

    Validation {
        valid,
        end,
        score: clamp01(score),
        detail,
    }
}

fn reject(score: f64, detail: &str) -> Validation {
    Validation {
        valid: false,
        end: None,
        score: clamp01(score),
        detail: detail.to_string(),
    }
}

fn starts_with(hay: &[u8], pre: &[u8]) -> bool {
    hay.len() >= pre.len() && &hay[..pre.len()] == pre
}

fn le64(d: &[u8], at: usize) -> Option<u64> {
    let mut b = [0u8; 8];
    for i in 0..8 {
        b[i] = *d.get(at + i)?;
    }
    Some(u64::from_le_bytes(b))
}

/// Why the local-header chain could not be followed.  The distinction is not
/// cosmetic: `Streamed` is a legitimate archive shape and earns a full EOCD
/// search, everything else is treated as probable residue.
#[derive(Debug, Clone, Copy, PartialEq)]
enum WalkFail {
    /// General-purpose bit 3: sizes live in a trailing data descriptor.
    Streamed,
    /// A 0xFFFFFFFF size escape -- the real value is in a ZIP64 extra field.
    Zip64,
    /// Ran off the end, or hit bytes that are neither a local header nor the
    /// start of the central directory.
    Broken,
}

impl WalkFail {
    fn as_str(self) -> &'static str {
        match self {
            WalkFail::Streamed => "uses data descriptors",
            WalkFail::Zip64 => "uses ZIP64 size escapes (unsupported)",
            WalkFail::Broken => "broken",
        }
    }
}

/// Chain forward through local file headers, using each header's declared
/// compressed size.  Returns the offset at which the central directory begins.
fn walk_local_headers(d: &[u8]) -> Result<usize, WalkFail> {
    let mut pos = 0usize;
    let mut seen = 0usize;
    loop {
        match le32(d, pos) {
            Some(SIG_LFH) => {}
            Some(SIG_CDH) if seen > 0 => return Ok(pos),
            _ => return Err(WalkFail::Broken),
        }
        let flags = le16(d, pos + 6).ok_or(WalkFail::Broken)?;
        let csize = le32(d, pos + 18).ok_or(WalkFail::Broken)?;
        let nlen = le16(d, pos + 26).ok_or(WalkFail::Broken)? as usize;
        let xlen = le16(d, pos + 28).ok_or(WalkFail::Broken)? as usize;
        // Bit 3: sizes live in a trailing data descriptor, not here.
        if flags & 0x0008 != 0 && csize == 0 {
            return Err(WalkFail::Streamed);
        }
        // 0xFFFFFFFF is the ZIP64 escape; the real size is in the extra field.
        if csize == 0xFFFF_FFFF {
            return Err(WalkFail::Zip64);
        }
        pos = pos
            .checked_add(LFH_FIXED)
            .and_then(|p| p.checked_add(nlen))
            .and_then(|p| p.checked_add(xlen))
            .and_then(|p| p.checked_add(csize as usize))
            .ok_or(WalkFail::Broken)?;
        if pos > d.len() {
            return Err(WalkFail::Broken);
        }
        seen += 1;
        if seen > 100_000 {
            return Err(WalkFail::Broken);
        }
    }
}

/// Fallback locator: find an EOCD whose own arithmetic is self-consistent
/// relative to the candidate's start.  Returns (eocd_at, cd_offset, cd_size).
fn scan_for_eocd(d: &[u8]) -> Option<(usize, u32, u32)> {
    let mut best: Option<(usize, u32, u32)> = None;
    let mut i = 0usize;
    while i + EOCD_FIXED <= d.len() {
        match find(&d[i..], b"PK\x05\x06") {
            Some(rel) => {
                let at = i + rel;
                if at + EOCD_FIXED <= d.len() {
                    let cd_size = le32(d, at + 12).unwrap_or(0);
                    let cd_off = le32(d, at + 16).unwrap_or(0);
                    if cd_off as usize + cd_size as usize == at && cd_size > 0 {
                        best = Some((at, cd_off, cd_size));
                    }
                }
                i = at + 4;
            }
            None => break,
        }
    }
    best
}

/// Walk central-directory records from `at`.  Returns the entries, the offset
/// one past the last record, and whether the walk hit a truncation.
fn walk_central_directory(d: &[u8], at: usize) -> (Vec<CentralEntry>, usize, bool) {
    let mut out = Vec::new();
    let mut pos = at;
    loop {
        if le32(d, pos) != Some(SIG_CDH) {
            // Reaching the EOCD (or the ZIP64 records) is the normal end.
            let sig = le32(d, pos);
            let clean = matches!(
                sig,
                Some(SIG_EOCD) | Some(SIG_EOCD64) | Some(SIG_EOCD64_LOC)
            );
            return (out, pos, !clean);
        }
        let flags = match le16(d, pos + 8) {
            Some(v) => v,
            None => return (out, pos, true),
        };
        let method = le16(d, pos + 10).unwrap_or(0xFFFF);
        let crc = le32(d, pos + 16).unwrap_or(0);
        let csize = le32(d, pos + 20).unwrap_or(0);
        let usize_ = le32(d, pos + 24).unwrap_or(0);
        let nlen = le16(d, pos + 28).unwrap_or(0) as usize;
        let xlen = le16(d, pos + 30).unwrap_or(0) as usize;
        let clen = le16(d, pos + 32).unwrap_or(0) as usize;
        let lho = le32(d, pos + 42).unwrap_or(0);
        let nstart = pos + CDH_FIXED;
        let nend = nstart + nlen;
        if nend > d.len() {
            return (out, pos, true);
        }
        out.push(CentralEntry {
            flags,
            method,
            crc,
            csize,
            usize_,
            lho,
            name: d[nstart..nend].to_vec(),
        });
        pos = nend + xlen + clen;
        if pos > d.len() || out.len() > 100_000 {
            return (out, pos.min(d.len()), true);
        }
    }
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

// =========================================================================
// Adler-32 (RFC 1950 section 9), for the zlib wrapper's trailer.
// CRC-32 comes from `structure::crc32`.
// =========================================================================

pub(crate) fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// =========================================================================
// INFLATE, RFC 1951.  Hand-rolled; the decode loop follows the canonical
// counts/symbols formulation used by zlib's reference `puff`.
// Shared with structure::pdf, which needs it for FlateDecode xref streams.
// =========================================================================

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            buf: 0,
            cnt: 0,
        }
    }
    fn bits(&mut self, need: u32) -> Option<u32> {
        while self.cnt < need {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            self.buf |= (b as u32) << self.cnt;
            self.cnt += 8;
        }
        let v = if need == 0 {
            0
        } else {
            self.buf & ((1u32 << need) - 1)
        };
        self.buf >>= need;
        self.cnt -= need;
        Some(v)
    }
    fn align(&mut self) {
        let drop = self.cnt % 8;
        self.buf >>= drop;
        self.cnt -= drop;
    }
}

struct Huff {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

fn huff_build(lengths: &[u8]) -> Option<Huff> {
    let mut counts = [0u16; 16];
    for &l in lengths {
        if l as usize > 15 {
            return None;
        }
        counts[l as usize] += 1;
    }
    if counts[0] as usize == lengths.len() {
        return None; // no codes at all
    }
    let mut left: i32 = 1;
    for len in 1..16 {
        left <<= 1;
        left -= counts[len] as i32;
        if left < 0 {
            return None; // over-subscribed
        }
    }
    let mut offs = [0u16; 16];
    for len in 1..15 {
        offs[len + 1] = offs[len] + counts[len];
    }
    let mut symbols = vec![0u16; lengths.len()];
    for (sym, &l) in lengths.iter().enumerate() {
        if l != 0 {
            symbols[offs[l as usize] as usize] = sym as u16;
            offs[l as usize] += 1;
        }
    }
    Some(Huff { counts, symbols })
}

fn huff_decode(h: &Huff, br: &mut BitReader) -> Option<u16> {
    let mut code: i32 = 0;
    let mut first: i32 = 0;
    let mut index: i32 = 0;
    for len in 1..16 {
        code |= br.bits(1)? as i32;
        let count = h.counts[len] as i32;
        if code - count < first {
            let i = index + (code - first);
            if i < 0 {
                return None;
            }
            return h.symbols.get(i as usize).copied();
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    None
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn fixed_tables() -> (Huff, Huff) {
    let mut ll = [0u8; 288];
    for i in 0..144 {
        ll[i] = 8;
    }
    for i in 144..256 {
        ll[i] = 9;
    }
    for i in 256..280 {
        ll[i] = 7;
    }
    for i in 280..288 {
        ll[i] = 8;
    }
    let dl = [5u8; 30];
    (huff_build(&ll).unwrap(), huff_build(&dl).unwrap())
}

/// Inflate a raw DEFLATE stream.  `hint` is the caller's expected output size;
/// output is capped at `max(hint, 64 KiB) * 2 + 64 KiB` so a corrupt stream
/// cannot be made to allocate without bound.
pub(crate) fn inflate_raw(src: &[u8], hint: usize) -> Option<Vec<u8>> {
    let cap = hint
        .max(64 << 10)
        .saturating_mul(2)
        .saturating_add(64 << 10)
        .min(MAX_MEMBER_OUT);
    let mut br = BitReader::new(src);
    let mut out: Vec<u8> = Vec::with_capacity(hint.min(1 << 20));
    loop {
        let last = br.bits(1)?;
        let btype = br.bits(2)?;
        match btype {
            0 => {
                br.align();
                let len = br.bits(16)? as usize;
                let nlen = br.bits(16)? as usize;
                if len ^ 0xFFFF != nlen {
                    return None;
                }
                for _ in 0..len {
                    let b = *src.get(br.pos)?;
                    br.pos += 1;
                    out.push(b);
                    if out.len() > cap {
                        return None;
                    }
                }
            }
            1 => {
                let (lt, dt) = fixed_tables();
                inflate_block(&mut br, &lt, &dt, &mut out, cap)?;
            }
            2 => {
                let hlit = br.bits(5)? as usize + 257;
                let hdist = br.bits(5)? as usize + 1;
                let hclen = br.bits(4)? as usize + 4;
                if hlit > 286 || hdist > 30 {
                    return None;
                }
                let mut clen = [0u8; 19];
                for i in 0..hclen {
                    clen[CLEN_ORDER[i]] = br.bits(3)? as u8;
                }
                let ct = huff_build(&clen)?;
                let mut lengths = vec![0u8; hlit + hdist];
                let mut i = 0usize;
                while i < hlit + hdist {
                    let sym = huff_decode(&ct, &mut br)?;
                    match sym {
                        0..=15 => {
                            lengths[i] = sym as u8;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return None;
                            }
                            let prev = lengths[i - 1];
                            let n = 3 + br.bits(2)? as usize;
                            for _ in 0..n {
                                if i >= lengths.len() {
                                    return None;
                                }
                                lengths[i] = prev;
                                i += 1;
                            }
                        }
                        17 => {
                            let n = 3 + br.bits(3)? as usize;
                            i = i.checked_add(n)?;
                            if i > lengths.len() {
                                return None;
                            }
                        }
                        18 => {
                            let n = 11 + br.bits(7)? as usize;
                            i = i.checked_add(n)?;
                            if i > lengths.len() {
                                return None;
                            }
                        }
                        _ => return None,
                    }
                }
                let lt = huff_build(&lengths[..hlit])?;
                // A distance table with a single symbol is legal and builds as
                // an incomplete code; huff_build permits incomplete codes and
                // huff_decode fails closed on an unused pattern.
                let dt = huff_build(&lengths[hlit..])
                    .unwrap_or_else(|| huff_build(&[1u8, 1u8]).unwrap());
                inflate_block(&mut br, &lt, &dt, &mut out, cap)?;
            }
            _ => return None,
        }
        if last == 1 {
            break;
        }
    }
    Some(out)
}

fn inflate_block(
    br: &mut BitReader,
    lt: &Huff,
    dt: &Huff,
    out: &mut Vec<u8>,
    cap: usize,
) -> Option<()> {
    loop {
        let sym = huff_decode(lt, br)? as usize;
        if sym < 256 {
            out.push(sym as u8);
            if out.len() > cap {
                return None;
            }
        } else if sym == 256 {
            return Some(());
        } else {
            let li = sym - 257;
            if li >= LEN_BASE.len() {
                return None;
            }
            let len = LEN_BASE[li] as usize + br.bits(LEN_EXTRA[li] as u32)? as usize;
            let ds = huff_decode(dt, br)? as usize;
            if ds >= DIST_BASE.len() {
                return None;
            }
            let dist = DIST_BASE[ds] as usize + br.bits(DIST_EXTRA[ds] as u32)? as usize;
            if dist == 0 || dist > out.len() {
                return None;
            }
            let start = out.len() - dist;
            for k in 0..len {
                let b = out[start + k];
                out.push(b);
            }
            if out.len() > cap {
                return None;
            }
        }
    }
}

/// Inflate a zlib-wrapped stream (RFC 1950): 2-byte header, DEFLATE body,
/// 4-byte big-endian Adler-32.  Used by structure::pdf for FlateDecode.
pub(crate) fn inflate_zlib(src: &[u8], hint: usize) -> Option<Vec<u8>> {
    if src.len() < 6 {
        return None;
    }
    let cmf = src[0];
    let flg = src[1];
    if cmf & 0x0F != 8 {
        return None; // not DEFLATE
    }
    if ((cmf as u16) << 8 | flg as u16) % 31 != 0 {
        return None; // header check
    }
    if flg & 0x20 != 0 {
        return None; // preset dictionary, not supported
    }
    let out = inflate_raw(&src[2..], hint)?;
    // The trailing Adler-32 is verified when the stream length is known.
    Some(out)
}

/// Inflate a zlib stream and verify its trailing Adler-32.  `src` must be the
/// exact stream including the 4-byte trailer.
pub(crate) fn inflate_zlib_checked(src: &[u8], hint: usize) -> Option<Vec<u8>> {
    let out = inflate_zlib(src, hint)?;
    if src.len() >= 4 {
        let t = &src[src.len() - 4..];
        let want = u32::from_be_bytes([t[0], t[1], t[2], t[3]]);
        if adler32(&out) != want {
            return None;
        }
    }
    Some(out)
}

// =========================================================================
// test support -- the Phase 1 fixture, read through its manifest
// =========================================================================
//
// `out/` is gitignored and produced by `make fixtures`, so every fixture test
// in this crate is written to SKIP loudly rather than fail when the image is
// absent.  `make test` should depend on `fixtures`; until it does, a fresh
// clone that runs `cargo test` on its own must not report a red bar for work
// that was never asked to happen.
//
// Lives in zip.rs because the three validators in this half of `structure/`
// share one 256 MB image and must not each read their own copy.  It is
// `pub(crate)` and `#[cfg(test)]`, so it costs the shipped binary nothing.

#[cfg(test)]
pub(crate) mod fixture {
    use std::path::PathBuf;
    use std::sync::OnceLock;

    pub struct Extent {
        pub off: u64,
        pub len: u64,
    }

    pub struct Planted {
        pub path: String,
        pub kind: String,
        pub offset: u64,
        pub size: u64,
        pub sha256: String,
        pub fragmented: bool,
        pub expected: String,
        pub extents: Vec<Extent>,
    }

    /// `SENTINELWIPE_FIXTURE_DIR` wins; otherwise walk up from the crate
    /// looking for `out/fixture.img`.
    fn root() -> Option<PathBuf> {
        if let Ok(d) = std::env::var("SENTINELWIPE_FIXTURE_DIR") {
            let p = PathBuf::from(d);
            if p.join("fixture.img").is_file() {
                return Some(p);
            }
        }
        let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..6 {
            let cand = here.join("out");
            if cand.join("fixture.img").is_file() {
                return Some(cand);
            }
            if !here.pop() {
                break;
            }
        }
        None
    }

    pub fn image() -> Option<&'static [u8]> {
        static IMG: OnceLock<Option<Vec<u8>>> = OnceLock::new();
        IMG.get_or_init(|| root().and_then(|r| std::fs::read(r.join("fixture.img")).ok()))
            .as_deref()
    }

    fn manifest() -> Option<&'static str> {
        static M: OnceLock<Option<String>> = OnceLock::new();
        M.get_or_init(|| {
            root().and_then(|r| std::fs::read_to_string(r.join("fixture.manifest.json")).ok())
        })
        .as_deref()
    }

    /// True when the fixture is present.  Callers print a SKIP line and return.
    pub fn available() -> bool {
        image().is_some() && manifest().is_some()
    }

    /// Every planted file of `kind` ("PDF", "DOCX", "SQLITE", ...), in manifest
    /// order.  Hand-rolled scan, no JSON crate: the schema is fixed and small,
    /// which is the same reasoning CLAUDE.md applies to the JSON writer.
    pub fn planted(kind: &str) -> Vec<Planted> {
        let m = match manifest() {
            Some(m) => m,
            None => return Vec::new(),
        };
        let mut out = Vec::new();
        for obj in objects_in_array(m, "\"files\"") {
            let k = jstr(obj, "kind").unwrap_or_default();
            if k != kind {
                continue;
            }
            let mut extents = Vec::new();
            if let Some(ai) = obj.find("\"extents\"") {
                for e in objects_in_array(&obj[ai..], "\"extents\"") {
                    extents.push(Extent {
                        off: jnum(e, "byte_offset").unwrap_or(0),
                        len: jnum(e, "byte_length").unwrap_or(0),
                    });
                }
            }
            out.push(Planted {
                path: jstr(obj, "path").unwrap_or_default(),
                kind: k,
                offset: jnum(obj, "offset").unwrap_or(0),
                size: jnum(obj, "size").unwrap_or(0),
                sha256: jstr(obj, "sha256").unwrap_or_default(),
                fragmented: jbool(obj, "fragmented").unwrap_or(false),
                expected: jstr(obj, "expected_recoverable").unwrap_or_default(),
                extents,
            });
        }
        out
    }

    /// The object's own bytes, extents concatenated in manifest order.
    pub fn bytes_of(p: &Planted) -> Vec<u8> {
        let img = image().expect("fixture image");
        let mut v = Vec::with_capacity(p.size as usize);
        for e in &p.extents {
            v.extend_from_slice(&img[e.off as usize..(e.off + e.len) as usize]);
        }
        v
    }

    /// What the carver actually hands a validator: the image from the object's
    /// first byte to the end of the image, residue and all.
    pub fn at_offset(p: &Planted) -> &'static [u8] {
        &image().expect("fixture image")[p.offset as usize..]
    }

    // ---- the smallest JSON reader that answers these questions ----------

    /// Top-level `{...}` members of the array introduced by `key`.
    fn objects_in_array<'a>(s: &'a str, key: &str) -> Vec<&'a str> {
        let mut out = Vec::new();
        let at = match s.find(key) {
            Some(a) => a,
            None => return out,
        };
        let b = s.as_bytes();
        let mut i = at + key.len();
        while i < b.len() && b[i] != b'[' {
            if b[i] == b'{' {
                return out;
            }
            i += 1;
        }
        i += 1;
        let mut depth = 0usize;
        let mut start = 0usize;
        while i < b.len() {
            match b[i] {
                b'"' => {
                    i += 1;
                    while i < b.len() && b[i] != b'"' {
                        if b[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                }
                b'{' => {
                    if depth == 0 {
                        start = i;
                    }
                    depth += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        out.push(&s[start..=i]);
                    }
                }
                b']' if depth == 0 => break,
                _ => {}
            }
            i += 1;
        }
        out
    }

    fn value_after<'a>(obj: &'a str, key: &str) -> Option<&'a str> {
        let pat = format!("\"{}\"", key);
        let at = obj.find(&pat)? + pat.len();
        let rest = obj[at..].trim_start();
        let rest = rest.strip_prefix(':')?;
        Some(rest.trim_start())
    }

    fn jstr(obj: &str, key: &str) -> Option<String> {
        let v = value_after(obj, key)?;
        let v = v.strip_prefix('"')?;
        let end = v.find('"')?;
        Some(v[..end].to_string())
    }

    fn jnum(obj: &str, key: &str) -> Option<u64> {
        let v = value_after(obj, key)?;
        let end = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
        v[..end].parse().ok()
    }

    fn jbool(obj: &str, key: &str) -> Option<bool> {
        let v = value_after(obj, key)?;
        if v.starts_with("true") {
            Some(true)
        } else if v.starts_with("false") {
            Some(false)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture;
    use super::*;

    const SKIP: &str = "SKIP: out/fixture.img absent; run `make fixtures`";

    fn near(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// The 4 contiguous DOCX files carve to their exact manifest length with a
    /// perfect rubric: every central-directory entry cross-checks against a
    /// real local header, every member inflates to a matching CRC-32.
    #[test]
    fn fixture_docx_contiguous_are_valid_with_exact_end() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let mut n = 0;
        for p in fixture::planted("DOCX") {
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
            assert!(v.detail.starts_with("ooxml "), "{}", v.detail);
            assert!(v.detail.contains("xcheck=7/7"), "{}", v.detail);
            assert!(v.detail.contains("payload=7/7"), "{}", v.detail);
            n += 1;
        }
        assert_eq!(n, 4, "manifest should hold 4 contiguous DOCX files");
    }

    /// The task's proof that the validator is doing work rather than trusting
    /// a header: cut every DOCX at 60% and require rejection.
    #[test]
    fn fixture_docx_truncated_at_60_percent_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        for p in fixture::planted("DOCX") {
            let whole = fixture::bytes_of(&p);
            let cut = (whole.len() as f64 * 0.60) as usize;
            let v = validate(&whole[..cut]);
            assert!(
                !v.valid,
                "{} truncated to {} accepted: {}",
                p.path, cut, v.detail
            );
            assert!(v.end.is_none(), "{} truncated reported an end", p.path);
        }
    }

    /// The cross-check in isolation.  Break ONLY the local-header signature of
    /// one member; the central directory, the EOCD and every other member stay
    /// byte-identical.  A validator that trusted the directory would pass this.
    #[test]
    fn spliced_local_header_fails_the_cross_check() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = fixture::planted("DOCX")
            .into_iter()
            .find(|p| !p.fragmented)
            .expect("a contiguous DOCX");
        let good = fixture::bytes_of(&p);
        let base = validate(&good);
        assert!(base.valid);

        // `word/document.xml` is the third member; its local header sits at 678
        // in every fixture DOCX (measured -- all five share the first two
        // members byte for byte).
        let lho = 678usize;
        let mut bad = good.clone();
        assert_eq!(&bad[lho..lho + 4], b"PK\x03\x04");
        bad[lho + 3] = 0x05;
        let v = validate(&bad);
        assert!(!v.valid, "spliced local header accepted: {}", v.detail);
        assert!(v.detail.contains("xcheck=6/7"), "{}", v.detail);
        // The EOCD is untouched and self-consistent, so the extent IS known
        // even though the object is rejected -- the state structure/mod.rs
        // documents, and what lets the carver step past this object.
        assert_eq!(v.end, Some(good.len() as u64));
        // Exactly one of seven cross-checks lost, and that member's payload
        // with it: 0.30*(1/7) + 0.30*(1/7) of the rubric.
        let expect = base.score - (W_XCHECK + W_PAYLOAD) / 7.0;
        assert!(
            near(v.score, expect),
            "score {} expected {}",
            v.score,
            expect
        );
    }

    /// The payload term in isolation.  Flip one byte inside a member's
    /// DEFLATE data: every offset in the file is still correct, every
    /// cross-check still passes, and only the CRC-32 catches it.
    #[test]
    fn corrupt_member_payload_fails_only_the_crc_term() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = fixture::planted("DOCX")
            .into_iter()
            .find(|p| !p.fragmented)
            .expect("a contiguous DOCX");
        let good = fixture::bytes_of(&p);
        let base = validate(&good);
        assert!(base.valid);

        let mut bad = good.clone();
        // 5000 bytes into `word/document.xml`'s compressed data.
        let at = 678 + LFH_FIXED + 17 + 5000;
        bad[at] ^= 0xFF;
        let v = validate(&bad);
        assert!(!v.valid, "corrupt member accepted: {}", v.detail);
        assert!(v.detail.contains("xcheck=7/7"), "{}", v.detail);
        assert!(v.detail.contains("payload=6/7"), "{}", v.detail);
        let expect = base.score - W_PAYLOAD / 7.0;
        assert!(
            near(v.score, expect),
            "score {} expected {}",
            v.score,
            expect
        );
    }

    /// ECMA-376 / OPC: an archive carrying `word/` parts without
    /// `[Content_Types].xml` is not a DOCX.  Renamed in BOTH the local header
    /// and the central directory, same length, so nothing else moves and every
    /// other check still passes.
    #[test]
    fn ooxml_without_content_types_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = fixture::planted("DOCX")
            .into_iter()
            .find(|p| !p.fragmented)
            .expect("a contiguous DOCX");
        let good = fixture::bytes_of(&p);
        let mut bad = good.clone();
        let old = b"[Content_Types].xml";
        let new = b"[Content_Typez].xml";
        let mut renamed = 0;
        let mut i = 0;
        while i + old.len() <= bad.len() {
            if &bad[i..i + old.len()] == old {
                bad[i..i + old.len()].copy_from_slice(new);
                renamed += 1;
                i += old.len();
            } else {
                i += 1;
            }
        }
        assert_eq!(renamed, 2, "one local header and one directory entry");
        let v = validate(&bad);
        assert!(
            !v.valid,
            "OOXML without [Content_Types].xml accepted: {}",
            v.detail
        );
        assert!(
            v.detail.contains("ooxml-missing-content-types"),
            "{}",
            v.detail
        );
        assert!(v.detail.contains("xcheck=7/7"), "{}", v.detail);
    }

    /// The tri-fragment DOCX the fixture plants to defeat bifragment gap
    /// carving.  Contiguous validation from its header MUST fail: three
    /// fragments are not solvable by a two-fragment search, and the demo says
    /// so on screen rather than special-casing it.
    #[test]
    fn tri_fragment_docx_is_not_recoverable_contiguously() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = fixture::planted("DOCX")
            .into_iter()
            .find(|p| p.expected == "unrecoverable-by-design")
            .expect("media_inventory.docx");
        assert_eq!(p.extents.len(), 3, "{} should have 3 extents", p.path);
        let v = validate(fixture::at_offset(&p));
        assert!(!v.valid, "{} accepted contiguously: {}", p.path, v.detail);
    }

    /// The residue is adversarial but the manifest counts ZERO bare ZIP
    /// signature hits in it.  Assert that too, from the image, so a future
    /// fixture change that introduces one is caught here.
    #[test]
    fn residue_carries_no_zip_local_header_outside_the_planted_files() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let img = fixture::image().unwrap();
        let planted: Vec<(u64, u64)> = fixture::planted("DOCX")
            .iter()
            .flat_map(|p| p.extents.iter().map(|e| (e.off, e.off + e.len)))
            .collect();
        let mut stray = 0usize;
        let mut i = 0usize;
        while let Some(rel) = find(&img[i..], b"PK\x03\x04") {
            let at = (i + rel) as u64;
            if !planted.iter().any(|&(a, b)| at >= a && at < b) {
                stray += 1;
            }
            i += rel + 1;
        }
        assert_eq!(
            stray, 0,
            "manifest says residue_signature_false_positives.ZIP == 0"
        );
    }

    /// The inflater, exercised on real data rather than a toy: every member of
    /// every fixture DOCX is DEFLATE (method 8, measured), so 35 independent
    /// streams round-trip against a CRC-32 this crate did not compute.
    #[test]
    fn inflater_reproduces_every_docx_member_crc() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let mut members = 0;
        for p in fixture::planted("DOCX") {
            let d = fixture::bytes_of(&p);
            let cd = walk_local_headers(&d).expect("local header chain");
            let (entries, _, trunc) = walk_central_directory(&d, cd);
            assert!(!trunc, "{}", p.path);
            for e in &entries {
                assert_eq!(
                    e.method,
                    8,
                    "{} {:?}",
                    p.path,
                    String::from_utf8_lossy(&e.name)
                );
                let at = e.lho as usize;
                let nlen = le16(&d, at + 26).unwrap() as usize;
                let xlen = le16(&d, at + 28).unwrap() as usize;
                let s = at + LFH_FIXED + nlen + xlen;
                let out =
                    inflate_raw(&d[s..s + e.csize as usize], e.usize_ as usize).expect("inflate");
                assert_eq!(out.len(), e.usize_ as usize);
                assert_eq!(crc32(&out), e.crc);
                members += 1;
            }
        }
        assert_eq!(members, 35, "5 DOCX x 7 members");
    }

    /// A stored (BTYPE=00) DEFLATE block, hand-assembled, so the inflater's
    /// uncompressed path is covered independently of the fixture.
    #[test]
    fn inflate_stored_block() {
        let payload = b"SENTINELWIPE stored block";
        let mut s = vec![0x01u8]; // BFINAL=1, BTYPE=00
        s.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        s.extend_from_slice(&(!(payload.len() as u16)).to_le_bytes());
        s.extend_from_slice(payload);
        assert_eq!(
            inflate_raw(&s, payload.len()).as_deref(),
            Some(&payload[..])
        );
        // A broken length complement must be refused, not tolerated.
        let mut bad = s.clone();
        bad[3] ^= 0xFF;
        assert!(inflate_raw(&bad, payload.len()).is_none());
    }

    #[test]
    fn adler32_reference_vectors() {
        // RFC 1950 defines Adler-32; these are the values zlib produces.
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    /// The hand-rolled manifest reader, checked against the shape the Phase 1
    /// writer commits.  If this drifts, every fixture assertion in pdf.rs,
    /// zip.rs and sqlite.rs is silently testing nothing, so it is asserted
    /// rather than assumed.
    #[test]
    fn manifest_reader_agrees_with_the_committed_schema() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        for (kind, count) in [("PDF", 5), ("DOCX", 5), ("SQLITE", 5)] {
            let files = fixture::planted(kind);
            assert_eq!(files.len(), count, "{} count", kind);
            for f in &files {
                assert_eq!(f.kind, kind);
                assert!(f.path.starts_with('/'), "{}", f.path);
                assert_eq!(f.sha256.len(), 64, "{} sha256", f.path);
                assert!(f.sha256.chars().all(|c| c.is_ascii_hexdigit()));
                assert!(f.size > 0 && f.offset > 0);
                let extent_total: u64 = f.extents.iter().map(|e| e.len).sum();
                assert_eq!(extent_total, f.size, "{} extents", f.path);
                assert_eq!(f.extents[0].off, f.offset, "{} first extent", f.path);
                assert_eq!(f.fragmented, f.extents.len() > 1, "{}", f.path);
                assert_eq!(fixture::bytes_of(f).len(), f.size as usize);
            }
        }
    }

    /// Not a ZIP at all: the first four bytes decide, and nothing else runs.
    #[test]
    fn non_zip_input_is_rejected_immediately() {
        let v = validate(b"not a zip file at all, not even close");
        assert!(!v.valid);
        assert_eq!(v.score, 0.0);
        assert!(v.detail.contains("no PK"));
    }
}
