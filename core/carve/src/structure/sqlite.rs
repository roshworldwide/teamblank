//! SQLite database structure validation.
//!
//! Garfinkel, "Carving contiguous and fragmented files with fast object
//! validation", DFRWS 2007 (Digital Investigation 4S, pp. S2-S12): a header
//! match is a candidate, not a file.  `SQLite format 3\0` is sixteen bytes,
//! and sixteen bytes of coincidence is exactly what a 256 MB disk of
//! adversarial residue is for.  This validator reads the whole 100-byte
//! database header, then the b-tree page header that page 1 is required to
//! carry, and only then reports a length.
//!
//! Reference: <https://sqlite.org/fileformat2.html>, sections 1.2 (database
//! header) and 1.6 (b-tree pages).
//!
//! Checked, in order:
//!
//!   1. magic `SQLite format 3\0`;
//!   2. page size at offset 16 -- a power of two in 512..=65536, with the
//!      spec's `1` escape meaning 65536;
//!   3. reserved-bytes-per-page at offset 20, and the derived usable size
//!      `page_size - reserved`, which the format requires to be >= 480;
//!   4. write/read format versions (1 = rollback journal, 2 = WAL), the three
//!      payload fractions which the format FIXES at 64/32/32, and the text
//!      encoding (1 = UTF-8, 2 = UTF-16le, 3 = UTF-16be);
//!   5. the change counter at offset 24 against the version-valid-for number
//!      at offset 92.  The spec makes the in-header database size authoritative
//!      ONLY when these are equal and the size is non-zero.  This is the hinge
//!      of the whole validator: it is what licenses reporting a length;
//!   6. the b-tree page type byte at offset 100 -- page 1 begins the
//!      `sqlite_master` TABLE b-tree, so it must be 0x0D (leaf table) or 0x05
//!      (interior table); 0x02 and 0x0A are index pages and cannot be page 1 --
//!      plus the page-1 cell count, cell-content start and cell pointer array,
//!      all of which must lie inside the page;
//!   7. size-in-pages consistent with the actual byte length:
//!      `page_size * page_count <= data.len()`.  A truncated database fails
//!      here even though every header field above it is perfect.
//!
//! `end` is `page_size * page_count`, which is the exact on-disk length.
//!
//! Stated limitation rather than a silent guess: when the change counter and
//! the version-valid-for number disagree, or the in-header size is zero (a
//! legacy writer, or a database a crashed process left behind), the file
//! length is NOT recorded in the file and SQLite itself derives it from the
//! host filesystem.  A carver has no filesystem to ask.  Such a candidate is
//! reported with `valid = false` and `end = None` and a `detail` that names
//! the reason -- the header is well formed, the *extent* is undeterminable.
//! Inferring it by walking page type bytes was rejected: freelist, overflow
//! and pointer-map pages carry no b-tree type byte, so the walk would stop
//! early and under-report the length as if it were a measurement.

use super::{be_u16, be_u32, clamp01, Validation};

const MAGIC: &[u8; 16] = b"SQLite format 3\0";
const HEADER_LEN: usize = 100;

const PAGE_INTERIOR_INDEX: u8 = 0x02;
const PAGE_INTERIOR_TABLE: u8 = 0x05;
const PAGE_LEAF_INDEX: u8 = 0x0A;
const PAGE_LEAF_TABLE: u8 = 0x0D;

// -------------------------------------------------------------------------
// score weights -- published, and each term is measured, never asserted
// -------------------------------------------------------------------------
// Weights sum to 1.00.  The extent term carries a third of the score on
// purpose: the six header terms above it can ALL be satisfied by 101 bytes of
// well-chosen residue, so they must not be allowed to dominate.  Only the
// extent check requires the object's body to actually be present.
const W_MAGIC: f64 = 0.12; // the 16-byte magic string
const W_PAGESIZE: f64 = 0.10; // power of two in 512..=65536
const W_USABLE: f64 = 0.06; // reserved space and usable size >= 480
const W_FIELDS: f64 = 0.08; // format versions, payload fractions, text encoding
const W_BTREE: f64 = 0.14; // page-1 b-tree header, half type byte / half cell array
const W_SIZEAUTH: f64 = 0.15; // in-header page count is authoritative per spec
const W_LENGTH: f64 = 0.35; // page_size * page_count fits inside the data

/// Validate a SQLite candidate whose header byte is `data[0]`.
pub fn validate(data: &[u8]) -> Validation {
    if data.len() < 16 || &data[..16] != MAGIC {
        return reject(0.0, "sqlite no `SQLite format 3\\0` at candidate offset");
    }
    let mut score = W_MAGIC;
    let mut notes: Vec<String> = Vec::new();

    if data.len() < HEADER_LEN + 1 {
        return Validation {
            valid: false,
            end: None,
            score: clamp01(score),
            detail: format!(
                "sqlite magic present but only {} bytes available; header needs {}",
                data.len(),
                HEADER_LEN + 1
            ),
        };
    }

    // ---- 2 · page size --------------------------------------------------
    let raw_ps = be16(data, 16);
    let page_size: u32 = if raw_ps == 1 { 65_536 } else { raw_ps as u32 };
    let ps_ok = page_size >= 512 && page_size <= 65_536 && page_size.is_power_of_two();
    if ps_ok {
        score += W_PAGESIZE;
    } else {
        // Everything downstream is derived from the page size, so there is no
        // honest partial result once it is wrong.
        return Validation {
            valid: false,
            end: None,
            score: clamp01(score),
            detail: format!(
                "sqlite page-size field {} is not a power of two in 512..=65536",
                raw_ps
            ),
        };
    }

    // ---- 3 · reserved space / usable size -------------------------------
    let reserved = data[20] as u32;
    let usable = page_size.saturating_sub(reserved);
    let usable_ok = usable >= 480 && reserved <= 255;
    if usable_ok {
        score += W_USABLE;
    } else {
        notes.push(format!("reserved={} usable={}", reserved, usable));
    }

    // ---- 4 · fixed header fields ----------------------------------------
    let write_ver = data[18];
    let read_ver = data[19];
    let (f1, f2, f3) = (data[21], data[22], data[23]);
    let text_enc = be32(data, 56);
    let schema_fmt = be32(data, 44);
    let mut field_hits = 0u32;
    let field_terms = 4u32;
    if (1..=2).contains(&write_ver) && (1..=2).contains(&read_ver) {
        field_hits += 1;
    } else {
        notes.push(format!("fmtver={}/{}", write_ver, read_ver));
    }
    // The format fixes these three; SQLite has never written anything else.
    if (f1, f2, f3) == (64, 32, 32) {
        field_hits += 1;
    } else {
        notes.push(format!("payload-fractions={}/{}/{}", f1, f2, f3));
    }
    if (1..=3).contains(&text_enc) {
        field_hits += 1;
    } else {
        notes.push(format!("text-encoding={}", text_enc));
    }
    if (1..=4).contains(&schema_fmt) {
        field_hits += 1;
    } else {
        notes.push(format!("schema-format={}", schema_fmt));
    }
    score += W_FIELDS * (field_hits as f64 / field_terms as f64);

    // ---- 6 · page-1 b-tree header ---------------------------------------
    // Page 1 carries the 100-byte database header first, so its b-tree header
    // begins at offset 100 rather than 0.
    let ptype = data[HEADER_LEN];
    let type_ok = ptype == PAGE_LEAF_TABLE || ptype == PAGE_INTERIOR_TABLE;
    let type_known = type_ok || ptype == PAGE_LEAF_INDEX || ptype == PAGE_INTERIOR_INDEX;
    let btree_hdr = if ptype == PAGE_INTERIOR_TABLE || ptype == PAGE_INTERIOR_INDEX {
        12
    } else {
        8
    };
    let mut cells_ok = false;
    let mut ncells = 0u16;
    if data.len() >= HEADER_LEN + btree_hdr {
        ncells = be16(data, HEADER_LEN + 3);
        let raw_start = be16(data, HEADER_LEN + 5) as u32;
        // The spec encodes a content area starting at 65536 as 0.
        let content_start = if raw_start == 0 { 65_536 } else { raw_start };
        let ptr_array_end = HEADER_LEN + btree_hdr + 2 * ncells as usize;
        let within = content_start <= page_size
            && content_start as usize >= ptr_array_end
            && ptr_array_end <= page_size as usize;
        let mut ptrs_ok = within;
        if within && data.len() >= page_size as usize {
            for i in 0..ncells as usize {
                let cp = be16(data, HEADER_LEN + btree_hdr + 2 * i) as u32;
                if cp < content_start || cp >= page_size {
                    ptrs_ok = false;
                    break;
                }
            }
        }
        cells_ok = ptrs_ok;
    }
    score += W_BTREE * (if type_ok { 0.5 } else { 0.0 } + if cells_ok { 0.5 } else { 0.0 });
    if !type_ok {
        notes.push(format!(
            "page1-type=0x{:02X}{}",
            ptype,
            if type_known { "(index-btree)" } else { "" }
        ));
    }
    if !cells_ok {
        notes.push(format!("page1-cell-array cells={}", ncells));
    }

    // ---- 5 · is the in-header size authoritative? ------------------------
    let change_counter = be32(data, 24);
    let page_count = be32(data, 28);
    let version_valid_for = be32(data, 92);
    let size_authoritative = page_count > 0 && change_counter == version_valid_for;
    if size_authoritative {
        score += W_SIZEAUTH;
    } else {
        notes.push(format!(
            "size-not-authoritative pages={} change-counter={} version-valid-for={}",
            page_count, change_counter, version_valid_for
        ));
    }

    // ---- 7 · length consistency -----------------------------------------
    let byte_len = (page_size as u64) * (page_count as u64);
    let fits = size_authoritative && byte_len <= data.len() as u64;
    if fits {
        score += W_LENGTH;
    } else if size_authoritative {
        notes.push(format!("declared={}B available={}B", byte_len, data.len()));
    }

    let valid = ps_ok && usable_ok && field_hits == field_terms && type_ok && cells_ok && fits;
    // The extent is reported whenever the header authoritatively records it and
    // the bytes are present, even when a later check failed: structure/mod.rs
    // documents `end = Some` with `valid = false`, and the carver needs the
    // length to step past a damaged object.
    let end = if fits { Some(byte_len) } else { None };

    let detail = format!(
        "sqlite page={} pages={} usable={} page1=0x{:02X} cells={} end={}{}{}",
        page_size,
        page_count,
        usable,
        ptype,
        ncells,
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

/// Big-endian reads over the shared bounds-checked readers in
/// `structure::mod`.  Every call site below is behind an explicit length
/// guard, so an out-of-range read is a bug and reads as zero rather than
/// panicking in the carver's inner loop.
fn be16(d: &[u8], at: usize) -> u16 {
    be_u16(d, at).unwrap_or(0)
}

fn be32(d: &[u8], at: usize) -> u32 {
    be_u32(d, at).unwrap_or(0)
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

    /// All 5 fixture databases carve to their exact manifest length with a
    /// perfect rubric.  `end` is `page_size * page_count`, read out of the
    /// header, and it matches the byte length the fixture recorded.
    #[test]
    fn fixture_sqlite_are_valid_with_exact_end() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let mut n = 0;
        for p in fixture::planted("SQLITE") {
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
            assert!(v.detail.contains("page=4096"), "{}", v.detail);
            assert!(v.detail.contains("page1=0x0D"), "{}", v.detail);
            n += 1;
        }
        assert_eq!(n, 5, "manifest should hold 5 SQLITE files");
    }

    /// Cut every database at 60% and require rejection.  Every header field is
    /// still perfect; only the extent check can catch this, which is why it
    /// carries 0.35 of the rubric on its own.
    #[test]
    fn fixture_sqlite_truncated_at_60_percent_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        for p in fixture::planted("SQLITE") {
            let whole = fixture::bytes_of(&p);
            let cut = (whole.len() as f64 * 0.60) as usize;
            let v = validate(&whole[..cut]);
            assert!(
                !v.valid,
                "{} truncated to {} accepted: {}",
                p.path, cut, v.detail
            );
            assert!(v.end.is_none(), "{} truncated reported an end", p.path);
            assert!(
                near(v.score, 1.0 - W_LENGTH),
                "{} score {}",
                p.path,
                v.score
            );
            assert!(v.detail.contains("declared="), "{}", v.detail);
        }
    }

    /// A single page of a real database: 100 bytes of perfect header and
    /// nothing behind it.  This is the shape a signature-only carver reports as
    /// a recovered database.
    #[test]
    fn one_page_of_a_real_database_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = &fixture::planted("SQLITE")[0];
        let whole = fixture::bytes_of(p);
        let v = validate(&whole[..4096]);
        assert!(!v.valid, "one page accepted: {}", v.detail);
        assert!(near(v.score, 1.0 - W_LENGTH), "score {}", v.score);
    }

    /// The spec makes the in-header size authoritative ONLY when the change
    /// counter equals the version-valid-for number.  Break that equality and
    /// the length is no longer recorded in the file, so the carver must refuse
    /// to report an extent rather than guess one.
    #[test]
    fn change_counter_mismatch_makes_the_length_unknowable() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = &fixture::planted("SQLITE")[0];
        let mut bad = fixture::bytes_of(p);
        bad[95] = bad[95].wrapping_add(1); // version-valid-for, offset 92..96
        let v = validate(&bad);
        assert!(!v.valid, "unauthoritative size accepted: {}", v.detail);
        assert_eq!(v.end, None);
        assert!(v.detail.contains("size-not-authoritative"), "{}", v.detail);
        assert!(
            near(v.score, 1.0 - W_SIZEAUTH - W_LENGTH),
            "score {}",
            v.score
        );
    }

    /// Page 1 starts the `sqlite_master` TABLE b-tree.  An index b-tree page
    /// type there is structurally impossible.
    #[test]
    fn page1_index_btree_type_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = &fixture::planted("SQLITE")[0];
        let mut bad = fixture::bytes_of(p);
        assert_eq!(bad[100], PAGE_LEAF_TABLE);
        bad[100] = PAGE_LEAF_INDEX;
        let v = validate(&bad);
        assert!(!v.valid, "index b-tree on page 1 accepted: {}", v.detail);
        assert!(v.detail.contains("index-btree"), "{}", v.detail);
        // The header still records the extent authoritatively, so it is
        // reported alongside the rejection.
        assert_eq!(v.end, Some(p.size));
        // Half the b-tree term: the cell pointer array is untouched and still
        // consistent, so only the type byte is lost.
        assert!(near(v.score, 1.0 - W_BTREE / 2.0), "score {}", v.score);
    }

    /// A cell pointer outside the page's content area.  The type byte is still
    /// right; only the array check can see this.
    #[test]
    fn page1_cell_pointer_out_of_range_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = &fixture::planted("SQLITE")[0];
        let mut bad = fixture::bytes_of(p);
        // First cell pointer of page 1's b-tree header (8-byte leaf header).
        bad[108] = 0x00;
        bad[109] = 0x05; // 5, far below the cell content area
        let v = validate(&bad);
        assert!(!v.valid, "bad cell pointer accepted: {}", v.detail);
        assert!(v.detail.contains("page1-cell-array"), "{}", v.detail);
        assert!(near(v.score, 1.0 - W_BTREE / 2.0), "score {}", v.score);
    }

    /// The three payload fractions are FIXED at 64/32/32 by the format.
    #[test]
    fn tampered_payload_fractions_lose_one_quarter_of_the_field_term() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = &fixture::planted("SQLITE")[0];
        let mut bad = fixture::bytes_of(p);
        bad[21] = 63;
        let v = validate(&bad);
        assert!(!v.valid, "{}", v.detail);
        assert!(
            v.detail.contains("payload-fractions=63/32/32"),
            "{}",
            v.detail
        );
        assert!(near(v.score, 1.0 - W_FIELDS / 4.0), "score {}", v.score);
    }

    /// Everything downstream of the page size is derived from it, so a page
    /// size that is not a power of two in 512..=65536 ends the validation.
    #[test]
    fn page_size_not_a_power_of_two_is_rejected() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let p = &fixture::planted("SQLITE")[0];
        let mut bad = fixture::bytes_of(p);
        bad[16] = 0x0F;
        bad[17] = 0x00; // 3840
        let v = validate(&bad);
        assert!(!v.valid);
        assert!(v.detail.contains("not a power of two"), "{}", v.detail);
        assert!(near(v.score, W_MAGIC), "score {}", v.score);
    }

    /// The spec's `1` escape at offset 16 means a 65536-byte page.
    #[test]
    fn page_size_escape_one_means_65536() {
        let mut d = vec![0u8; 200];
        d[..16].copy_from_slice(MAGIC);
        d[16] = 0x00;
        d[17] = 0x01; // the escape
        let v = validate(&d);
        // Rejected for length (65536 * page_count is not available here), but
        // NOT for the page size, and the detail must print 65536.
        assert!(v.detail.contains("page=65536"), "{}", v.detail);
        assert!(!v.detail.contains("not a power of two"), "{}", v.detail);
    }

    /// The magic alone, with an empty header behind it: exactly what a
    /// signature-only carver would accept.
    #[test]
    fn magic_with_an_empty_header_is_rejected() {
        let mut d = vec![0u8; 8192];
        d[..16].copy_from_slice(MAGIC);
        let v = validate(&d);
        assert!(!v.valid);
        assert!(near(v.score, W_MAGIC), "score {}", v.score);
    }

    #[test]
    fn non_sqlite_input_is_rejected_immediately() {
        let v = validate(b"SQLite format 2\0 -- close, but no");
        assert!(!v.valid);
        assert_eq!(v.score, 0.0);
        assert!(v.detail.contains("no `SQLite format 3"));
    }

    /// The manifest counts ZERO bare SQLITE signature hits in the adversarial
    /// residue.  Assert it from the image so a future fixture change that adds
    /// one is caught here rather than on stage.
    #[test]
    fn residue_carries_no_sqlite_magic_outside_the_planted_files() {
        if !fixture::available() {
            eprintln!("{}", SKIP);
            return;
        }
        let img = fixture::image().unwrap();
        let planted: Vec<(u64, u64)> = fixture::planted("SQLITE")
            .iter()
            .flat_map(|p| p.extents.iter().map(|e| (e.off, e.off + e.len)))
            .collect();
        let mut stray = 0usize;
        let mut i = 0usize;
        while i + 16 <= img.len() {
            if &img[i..i + 16] == MAGIC {
                let at = i as u64;
                if !planted.iter().any(|&(a, b)| at >= a && at < b) {
                    stray += 1;
                }
                i += 16;
            } else {
                i += 1;
            }
        }
        assert_eq!(
            stray, 0,
            "manifest says residue_signature_false_positives.SQLITE == 0"
        );
    }
}
