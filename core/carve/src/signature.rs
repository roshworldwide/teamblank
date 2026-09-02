//! Header/footer signature scanning.
//!
//! This module answers one question and refuses the rest: *where in this byte
//! range does an object of a known kind plausibly begin, and where is the
//! earliest byte that could end it?* It does not decide whether the object is
//! real. `structure::validate` decides that, and on this project's own fixture
//! it has to: of the 19 JPEG headers in `out/fixture.img`, 5 are planted files
//! and 14 are not.
//!
//! # The table is the design
//!
//! Every format-specific fact lives in [`SIGNATURES`] and nowhere else. The
//! scan loop reads that table and contains no `if kind == ...` and no `match`
//! on [`Kind`] — not one. Adding a format is one row. That constraint is not
//! stylistic: a carver whose per-format behaviour is scattered through control
//! flow cannot be audited by someone reading it for the first time, and this
//! code exists to be read by someone deciding whether to believe its output.
//!
//! # The footer rule
//!
//! `footer_at` is the **first** occurrence of the kind's footer pattern that
//! begins at or after `header_at + header.len()` and whose final byte falls
//! within `header_at + max_len`. First, not last. The reason is measured:
//! `out/fixture.img` contains 2,494 occurrences of the JPEG end-of-image marker
//! `FF D9`, and exactly 5 of them end a planted JPEG. A "last footer in the
//! window" rule would therefore be wrong 2,489 times out of 2,494 and would
//! routinely swallow whole neighbouring objects. First-match cannot: it stops
//! at the earliest byte that could possibly terminate this object.
//!
//! First-match is also *correct* here, not merely safe. Each of the five
//! planted JPEGs contains exactly one `FF D9`, at `size - 2` — which is the
//! format doing its job, since JPEG byte-stuffs `FF` inside entropy-coded data
//! as `FF 00`. Measured the same way, `%%EOF` occurs 5 times in the image and
//! `PK\x05\x06` 5 times, one per planted object, so first and last coincide for
//! PDF and ZIP on the demo path.
//!
//! Where the rule is knowingly incomplete, stated rather than hidden:
//!
//! * a PDF written with incremental updates carries one `%%EOF` per revision,
//!   and first-match recovers the first revision — a valid PDF, but not all of
//!   the bytes that were there;
//! * ZIP defines its end-of-central-directory to be found by searching
//!   *backward* from the end of the archive, and an archive that stores another
//!   archive can carry an inner `PK\x05\x06`.
//!
//! Neither is this module's call. `scan` generates candidates; `Validation.end`
//! overrides `footer_at` and is why the interface contract gives `Validation` an
//! `end` field at all. A validator that needs to walk to a later footer calls
//! [`next_footer`].
//!
//! # Why the JPEG row is three bytes and not four
//!
//! The brief names the `E0`/`E1`/`DB`/`EE` variants of `FF D8 FF xx`. The table
//! carries the 3-byte prefix and stops, deliberately. Filtering on the fourth
//! byte inside `scan` would cut JPEG candidates on the fixture from 19 to 5 —
//! precisely the five planted files, with zero false positives. That is a worse
//! scanner that scores better. The manifest counts 8 bare JPEG hits in free
//! space as a deliberate false-positive test; every non-planted hit in the
//! image carries a fourth byte outside `{E0,E1,DB,EE}` (measured fourth bytes:
//! 05 40 44 4D 4E 61 6C 73 80 9D AD E6 ED FD), so a fourth-byte filter deletes
//! the test rather than passing it. The marker check belongs in
//! `structure::validate`, where a rejection is counted, scored and reportable —
//! not in `scan`, where it would be silent.
//!
//! # Why MP4 occupies nine rows
//!
//! `ftyp` is the only magic in this table that does not sit at offset 0: it is
//! an ISO-BMFF box type, preceded by the box's own 32-bit big-endian size. A
//! scanner that matched the bare `ftyp` would report `header_at` four bytes past
//! the true start of the object, and every byte the carver hashed would be
//! wrong. The alternatives were to teach the loop a per-row back-off (which is
//! the special-casing this module exists to avoid) or to fold the size into the
//! pattern. The size is folded in. An `ftyp` box is
//! `8 (size + type) + 4 (major brand) + 4 (minor version) + 4 * N` bytes for `N`
//! compatible brands, so the table carries one row per `N` in `0..=8`, sizes
//! 0x10 through 0x30. `header_at` is then the object start for every kind
//! uniformly, and the loop still has no per-type branch. The cost is stated
//! plainly: an `ftyp` box declaring more than eight compatible brands is not
//! matched. Measured on the fixture, all five planted `.mov` files declare one
//! compatible brand and a box size of 0x14.
//!
//! # Nested and overlapping candidates
//!
//! `scan` is deliberately **complete and non-suppressing**. It reports every
//! match at every offset, including headers that fall inside another object's
//! payload and headers that overlap each other. Dropping candidates before
//! structure validation is how a carver loses deleted and fragmented files,
//! because at scan time nothing yet knows where any object ends. On the fixture
//! that completeness is worth 30 ZIP candidates (the extra local file headers
//! inside the five DOCX archives), 6 JPEG candidates buried in MOV and PNG
//! payloads, and the 8 + 13 residue hits the manifest requires be seen.
//!
//! [`suppress_nested`] is offered as an *optional* post-filter for callers that
//! want the container case collapsed. Read its documentation before using it: it
//! is right for ZIP and wrong for JPEG, and the measured numbers for both are
//! recorded there.

use crate::Kind;

/// One row of the signature table. All format-specific knowledge in this module
/// is here; the scan loop below reads these fields and nothing else.
#[derive(Debug, Clone, Copy)]
pub struct Signature {
    /// The kind this row detects.
    pub kind: Kind,
    /// Byte pattern that begins the object. Matched at the object's first byte,
    /// so `header_at` is always the object start (see the MP4 note above).
    pub header: &'static [u8],
    /// Byte pattern that ends the object, when the format has one. `None` means
    /// the format carries its length internally rather than terminating with a
    /// sentinel — for those kinds `Candidate::footer_at` is always `None`, and a
    /// caller distinguishing "no footer defined" from "footer not found" must
    /// ask [`signature_for`] rather than reading `footer_at` alone.
    pub footer: Option<&'static [u8]>,
    /// Largest object of this kind the scan will bound a footer search with.
    /// This is a search cap, not a measurement: it is the point past which a
    /// footer is treated as belonging to something else. The measured largest
    /// planted instance of each kind is recorded beside its row so the headroom
    /// is visible rather than asserted.
    pub max_len: u64,
}

// ---- header and footer patterns -------------------------------------------
//
// Written out as named constants so that each one can be pointed at during a
// walkthrough, and so the table below reads as a table.

/// JPEG SOI + the first byte of the following marker. Three bytes, on purpose;
/// see the module documentation.
const JPEG_HEADER: &[u8] = &[0xFF, 0xD8, 0xFF];
/// JPEG EOI.
const JPEG_FOOTER: &[u8] = &[0xFF, 0xD9];

/// PNG signature: high bit, "PNG", CRLF, EOF, LF — the eight bytes the format
/// chose specifically to survive naive text-mode transfer.
const PNG_HEADER: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
/// The IEND chunk's type and its CRC32, which is constant because IEND's data
/// field is empty. Matching the CRC as well as the tag is what makes this an
/// 8-byte terminator rather than a 4-byte word that appears in noise.
const PNG_FOOTER: &[u8] = &[b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82];

const PDF_HEADER: &[u8] = b"%PDF-";
const PDF_FOOTER: &[u8] = b"%%EOF";

/// ZIP local file header. DOCX, XLSX, PPTX, JAR, ODF and EPUB are all ZIP.
const ZIP_HEADER: &[u8] = &[b'P', b'K', 0x03, 0x04];
/// ZIP end-of-central-directory record.
const ZIP_FOOTER: &[u8] = &[b'P', b'K', 0x05, 0x06];

/// The SQLite file header string, including its terminating NUL.
const SQLITE_HEADER: &[u8] = b"SQLite format 3\x00";

/// GZIP magic plus the DEFLATE compression-method byte. GZIP ends with a CRC32
/// and an ISIZE, both arbitrary, so there is no footer pattern to match.
const GZIP_HEADER: &[u8] = &[0x1F, 0x8B, 0x08];

/// ISO-BMFF / QuickTime `ftyp` box, one row per compatible-brand count `N`.
/// Box length is `16 + 4 * N`; see the module documentation for why the length
/// is part of the pattern.
const MP4_FTYP_N0: &[u8] = &[0x00, 0x00, 0x00, 0x10, b'f', b't', b'y', b'p'];
const MP4_FTYP_N1: &[u8] = &[0x00, 0x00, 0x00, 0x14, b'f', b't', b'y', b'p'];
const MP4_FTYP_N2: &[u8] = &[0x00, 0x00, 0x00, 0x18, b'f', b't', b'y', b'p'];
const MP4_FTYP_N3: &[u8] = &[0x00, 0x00, 0x00, 0x1C, b'f', b't', b'y', b'p'];
const MP4_FTYP_N4: &[u8] = &[0x00, 0x00, 0x00, 0x20, b'f', b't', b'y', b'p'];
const MP4_FTYP_N5: &[u8] = &[0x00, 0x00, 0x00, 0x24, b'f', b't', b'y', b'p'];
const MP4_FTYP_N6: &[u8] = &[0x00, 0x00, 0x00, 0x28, b'f', b't', b'y', b'p'];
const MP4_FTYP_N7: &[u8] = &[0x00, 0x00, 0x00, 0x2C, b'f', b't', b'y', b'p'];
const MP4_FTYP_N8: &[u8] = &[0x00, 0x00, 0x00, 0x30, b'f', b't', b'y', b'p'];

const MIB: u64 = 1024 * 1024;

/// The signature table.
///
/// `max_len` is a search bound, and the comment on each row records the largest
/// planted instance of that kind in `out/fixture.img` so the margin between the
/// bound and reality is on the page rather than in someone's head.
pub const SIGNATURES: &[Signature] = &[
    // largest planted JPEG:   108,462 bytes (drive_label_macro.jpg)
    Signature { kind: Kind::Jpeg,   header: JPEG_HEADER,   footer: Some(JPEG_FOOTER), max_len:  32 * MIB },
    // largest planted PNG:    260,595 bytes (seizure_photo_a.png)
    Signature { kind: Kind::Png,    header: PNG_HEADER,    footer: Some(PNG_FOOTER),  max_len:  64 * MIB },
    // largest planted PDF:     54,214 bytes (examiner_affidavit.pdf)
    Signature { kind: Kind::Pdf,    header: PDF_HEADER,    footer: Some(PDF_FOOTER),  max_len:  64 * MIB },
    // largest planted DOCX:    79,397 bytes (media_inventory.docx)
    Signature { kind: Kind::Zip,    header: ZIP_HEADER,    footer: Some(ZIP_FOOTER),  max_len: 128 * MIB },
    // largest planted SQLITE: 221,184 bytes (carve_results.db)
    Signature { kind: Kind::Sqlite, header: SQLITE_HEADER, footer: None,              max_len: 256 * MIB },
    // largest planted GZIP:   127,302 bytes (imaging_transcript.txt.gz)
    Signature { kind: Kind::Gzip,   header: GZIP_HEADER,   footer: None,              max_len: 128 * MIB },
    // largest planted MP4:    221,041 bytes (sealing_procedure.mov); all five
    // planted files declare N = 1 compatible brand, box size 0x14.
    Signature { kind: Kind::Mp4,    header: MP4_FTYP_N0,   footer: None,              max_len: 256 * MIB },
    Signature { kind: Kind::Mp4,    header: MP4_FTYP_N1,   footer: None,              max_len: 256 * MIB },
    Signature { kind: Kind::Mp4,    header: MP4_FTYP_N2,   footer: None,              max_len: 256 * MIB },
    Signature { kind: Kind::Mp4,    header: MP4_FTYP_N3,   footer: None,              max_len: 256 * MIB },
    Signature { kind: Kind::Mp4,    header: MP4_FTYP_N4,   footer: None,              max_len: 256 * MIB },
    Signature { kind: Kind::Mp4,    header: MP4_FTYP_N5,   footer: None,              max_len: 256 * MIB },
    Signature { kind: Kind::Mp4,    header: MP4_FTYP_N6,   footer: None,              max_len: 256 * MIB },
    Signature { kind: Kind::Mp4,    header: MP4_FTYP_N7,   footer: None,              max_len: 256 * MIB },
    Signature { kind: Kind::Mp4,    header: MP4_FTYP_N8,   footer: None,              max_len: 256 * MIB },
];

/// A header match, with the earliest footer that could close it.
///
/// `header_at` is the offset of the object's **first byte**, for every kind,
/// including MP4 — not the offset of the magic within the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub kind: Kind,
    pub header_at: u64,
    /// `None` means either "this kind has no footer pattern" or "no footer was
    /// found inside `max_len`". The second case is the bifragment trigger: a
    /// header whose terminator is missing is exactly the shape of an object
    /// split across a gap. Ask [`signature_for`] which of the two it is.
    pub footer_at: Option<u64>,
}

// ---- the scan loop ---------------------------------------------------------

// The dispatch index. Bit `i` of `FIRST_BYTE_INDEX[b]` is set when
// `SIGNATURES[i].header` starts with byte `b`. Scanning is then one array
// lookup per input byte, and a byte that begins no signature — the overwhelming
// majority of a 256 MB image — costs a load and a branch. Built at compile time
// from the table itself, so a new row indexes itself.
const _: () = assert!(
    SIGNATURES.len() <= 32,
    "FIRST_BYTE_INDEX is a u32 bitmask; widen it before adding a 33rd signature"
);

const fn build_first_byte_index() -> [u32; 256] {
    let mut index = [0u32; 256];
    let mut i = 0;
    while i < SIGNATURES.len() {
        // A zero-length header would match everywhere and mean nothing.
        assert!(
            !SIGNATURES[i].header.is_empty(),
            "signature headers must be non-empty"
        );
        index[SIGNATURES[i].header[0] as usize] |= 1u32 << i;
        i += 1;
    }
    index
}

static FIRST_BYTE_INDEX: [u32; 256] = build_first_byte_index();

// The first byte alone is not always enough. The nine `ftyp` rows share their
// first THREE bytes, so on an all-zero image -- which is exactly what the demo
// carves at step 4, to prove the wipe worked -- every one of 268,435,456
// positions entered the 0x00 bucket and ran nine full header comparisons.
// Measured before this index existed: 6.018 s for the zeroed image against
// 1.424 s for the fixture, making the proof-of-erasure scan the slowest in the
// demo.
//
// So each row also carries a PROBE offset: the earliest byte position at which
// it differs from another row sharing its first byte. Testing that one byte
// first rejects a row in a load and a compare instead of a header-length
// memcmp. For the ftyp rows the probe lands on the box-size byte at offset 3,
// which is precisely the byte that distinguishes them. It is derived from the
// table at compile time, so a new row computes its own probe and no format
// knowledge leaks into the loop.
//
// Measured on this machine, release build, 268,435,456 bytes, before -> after:
//   zeroed image (post-wipe demo path)  6.018 s -> 2.103 s   42.5 -> 121.7 MiB/s
//   out/fixture.img                     1.424 s -> 0.828 s  176.3 -> 309.2 MiB/s
//   uniform random bytes                0.629 s -> 0.619 s  426.9 -> 413.5 MiB/s
// The candidate set is unchanged in all three cases, which is what the fixture
// count tests above assert: this is a dispatch change, not a matching change.
const fn build_probe_offsets() -> [usize; SIGNATURES.len()] {
    let mut probes = [0usize; SIGNATURES.len()];
    let mut i = 0;
    while i < SIGNATURES.len() {
        let mine = SIGNATURES[i].header;
        let mut at = 0;
        'search: while at < mine.len() {
            let mut k = 0;
            while k < SIGNATURES.len() {
                let theirs = SIGNATURES[k].header;
                if k != i && theirs[0] == mine[0] && at < theirs.len() && theirs[at] != mine[at] {
                    break 'search;
                }
                k += 1;
            }
            at += 1;
        }
        // A row whose first byte is unique to it finds no disagreement and ends
        // with `at == header.len()`; probing byte 0 is then a no-op, which is
        // correct, because reaching that row already proved byte 0 matched.
        probes[i] = if at < mine.len() { at } else { 0 };
        i += 1;
    }
    probes
}

static PROBE_AT: [usize; SIGNATURES.len()] = build_probe_offsets();

/// First occurrence of `needle` in `hay`, or `None`.
///
/// Hand-rolled because this project adds no dependencies. Skips on the first
/// byte and only then compares the tail, which is what keeps the footer search
/// linear in practice rather than in `needle.len()` per position.
fn find_from(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let last_start = hay.len() - needle.len();
    let mut i = 0usize;
    while i <= last_start {
        match hay[i..=last_start].iter().position(|&b| b == first) {
            Some(offset) => {
                let at = i + offset;
                if &hay[at..at + needle.len()] == needle {
                    return Some(at);
                }
                i = at + 1;
            }
            None => return None,
        }
    }
    None
}

/// Resolve the footer for one header match, applying the documented rule:
/// first occurrence at or after the end of the header, ending within `max_len`.
fn resolve_footer(data: &[u8], sig: &Signature, header_at: usize) -> Option<u64> {
    let footer = sig.footer?;
    let search_from = header_at + sig.header.len();
    // Saturating: max_len can exceed usize on a 32-bit host, and a candidate
    // near the end of the buffer must clamp rather than wrap.
    let window_end = (header_at as u64)
        .saturating_add(sig.max_len)
        .min(data.len() as u64) as usize;
    if search_from >= window_end {
        return None;
    }
    find_from(&data[search_from..window_end], footer).map(|rel| (search_from + rel) as u64)
}

/// Scan `data` for every signature in [`SIGNATURES`].
///
/// Returns every match, in ascending `header_at` order, ties broken by table
/// order. Nothing is filtered, deduplicated or judged; see the module
/// documentation on why completeness is the contract here.
///
/// Offsets are relative to the start of `data`. A caller scanning an image in
/// windows must add its own base offset and must overlap windows by at least
/// `max header length - 1` bytes, or a header straddling the seam is lost.
pub fn scan(data: &[u8]) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for (i, &byte) in data.iter().enumerate() {
        let mut bits = FIRST_BYTE_INDEX[byte as usize];
        while bits != 0 {
            let row = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            let sig = &SIGNATURES[row];
            let end = i + sig.header.len();
            if end > data.len() {
                continue;
            }
            if data[i + PROBE_AT[row]] != sig.header[PROBE_AT[row]] {
                continue;
            }
            if &data[i..end] == sig.header {
                out.push(Candidate {
                    kind: sig.kind,
                    header_at: i as u64,
                    footer_at: resolve_footer(data, sig, i),
                });
            }
        }
    }
    out
}

// ---- helpers the rest of the crate needs -----------------------------------

/// The table row for `kind`.
///
/// Exists so a caller can tell "this kind has no footer pattern" from "this
/// kind has a footer and we did not find one" — the second is the bifragment
/// trigger and the first is not. MP4 has nine rows; they differ only in the
/// declared box size, and `footer` and `max_len` are identical across them, so
/// returning the first is well defined for both of those fields.
pub fn signature_for(kind: Kind) -> Option<&'static Signature> {
    SIGNATURES.iter().find(|sig| sig.kind == kind)
}

/// The next footer of `kind` beginning at or after `from`, ending before
/// `limit` (an absolute, exclusive bound on the footer's last byte + 1).
///
/// `scan` reports only the first footer, by the rule documented at the top of
/// this module. A validator that must walk past it — PDF incremental updates,
/// ZIP archives whose end-of-central-directory is not the first `PK\x05\x06` —
/// calls this repeatedly. Returns `None` for kinds with no footer pattern.
pub fn next_footer(data: &[u8], kind: Kind, from: u64, limit: u64) -> Option<u64> {
    let sig = signature_for(kind)?;
    let footer = sig.footer?;
    let start = from.min(data.len() as u64) as usize;
    let end = limit.min(data.len() as u64) as usize;
    if start >= end {
        return None;
    }
    find_from(&data[start..end], footer).map(|rel| (start + rel) as u64)
}

/// Optional post-filter: drop a candidate whose header falls strictly inside the
/// `header..footer` span of an earlier candidate **of the same kind**.
///
/// Read this before calling it. It is right for one situation and wrong for
/// another, and both were measured on `out/fixture.img`:
///
/// * **Right for containers.** A ZIP repeats `PK\x03\x04` once per member. The
///   five planted DOCX files produce 35 ZIP candidates; this filter reduces them
///   to 5, one per archive, which is the correct answer.
/// * **Hazardous for formats whose footer occurs in noise.** JPEG's `FF D9`
///   appears 2,494 times in the image, so a residue candidate resolves an
///   arbitrary footer, and therefore an arbitrary span, and a span that happens
///   to be long will swallow a real header behind it. Measured on the fixture
///   the filter takes JPEG from 19 candidates to 17. Neither of the two it drops
///   is a planted file: one at 180,577,290 lies inside the drive_teardown.mov
///   payload, and one at 256,383,792 is one of the eight free-space residue hits
///   the manifest plants as the false-positive test. So on this image the filter
///   costs no recovery and one unit of evidence. The hazard is structural, not
///   hypothetical — it simply did not fire here, and a filter that is safe by
///   luck is not safe.
///
/// So: apply it per kind, and after `structure::validate` has replaced guessed
/// footers with real ends — or do not apply it at all. `carve` decides; `scan`
/// does not decide for it.
///
/// Expects `cands` in ascending `header_at` order, which is what `scan` returns.
pub fn suppress_nested(cands: &[Candidate]) -> Vec<Candidate> {
    // Kind is a fieldless enum, so `as usize` is its declaration index. Seven
    // variants; the array is sized from the table's own kinds rather than a
    // literal so that adding a variant is a compile error here, not a silent
    // out-of-bounds at run time.
    let mut reach: [Option<u64>; KIND_COUNT] = [None; KIND_COUNT];
    let mut out = Vec::with_capacity(cands.len());
    for cand in cands {
        let slot = cand.kind as usize;
        if let Some(covered_to) = reach[slot] {
            if cand.header_at < covered_to {
                continue;
            }
        }
        if let Some(footer_at) = cand.footer_at {
            reach[slot] = Some(match reach[slot] {
                Some(prev) if prev > footer_at => prev,
                _ => footer_at,
            });
        }
        out.push(*cand);
    }
    out
}

/// Number of `Kind` variants. Kept next to the one place that indexes by
/// discriminant. `Kind` is fieldless, so this is also the exhaustive match
/// below failing to compile if a variant is ever added.
const KIND_COUNT: usize = 7;

#[allow(dead_code)]
fn kind_count_is_exhaustive(kind: Kind) -> usize {
    // Not called. It exists so that adding a variant to `Kind` breaks this
    // match, and whoever adds it is forced to look at KIND_COUNT.
    match kind {
        Kind::Jpeg => 0,
        Kind::Png => 1,
        Kind::Pdf => 2,
        Kind::Zip => 3,
        Kind::Sqlite => 4,
        Kind::Mp4 => 5,
        Kind::Gzip => 6,
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The real fixture, when it has been built. Tests that need it skip when it
    /// is absent, the same way `docs/architecture.md` records the Sleuth Kit
    /// cross-check skipping when TSK is not installed. Build it with
    /// `make fixtures`.
    const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.img");

    /// Load the fixture, or `None` if it has not been built.
    ///
    /// A skipping test that prints `ok` is a test that claims more than it
    /// verified, which is CLAUDE.md rule 1 aimed at ourselves. This function was
    /// written without the escape hatch below and it cost real time: a wrong
    /// relative path made all six fixture tests skip while the suite reported 32
    /// passed. So the skip is loud, and setting `SENTINELWIPE_REQUIRE_FIXTURE=1`
    /// turns it into a failure. `make demo` and CI set that variable; a
    /// developer on a fresh clone who has not run `make fixtures` does not.
    fn fixture() -> Option<Vec<u8>> {
        match std::fs::read(FIXTURE_PATH) {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                let required = std::env::var("SENTINELWIPE_REQUIRE_FIXTURE")
                    .map(|v| v == "1")
                    .unwrap_or(false);
                let msg = format!(
                    "fixture not read: {FIXTURE_PATH}: {err}. Run `make fixtures`."
                );
                if required {
                    panic!("SENTINELWIPE_REQUIRE_FIXTURE=1 and {msg}");
                }
                eprintln!("SKIP (NOT VERIFIED): {msg}");
                None
            }
        }
    }

    /// The fixture and its scan, computed once for the whole suite.
    ///
    /// Nine tests read the same 256 MB image; scanning it nine times cost 22
    /// seconds of every `cargo test` run. `fixture_scan_report` deliberately
    /// does its own uncached scan, because its job is to time one.
    fn fixture_scan() -> Option<&'static (Vec<u8>, Vec<Candidate>)> {
        static CACHE: std::sync::OnceLock<Option<(Vec<u8>, Vec<Candidate>)>> =
            std::sync::OnceLock::new();
        CACHE
            .get_or_init(|| {
                fixture().map(|data| {
                    let cands = scan(&data);
                    (data, cands)
                })
            })
            .as_ref()
    }

    fn count(cands: &[Candidate], kind: Kind) -> usize {
        cands.iter().filter(|c| c.kind == kind).count()
    }

    fn offsets(cands: &[Candidate], kind: Kind) -> Vec<u64> {
        cands
            .iter()
            .filter(|c| c.kind == kind)
            .map(|c| c.header_at)
            .collect()
    }

    /// A buffer that begins with `header` and is otherwise inert: 0xAA starts no
    /// signature and forms no footer, so anything found in one of these buffers
    /// was put there by the test.
    fn inert(header: &[u8], total: usize) -> Vec<u8> {
        let mut v = vec![0xAAu8; total];
        v[..header.len()].copy_from_slice(header);
        v
    }

    const ALL_KINDS: [Kind; 7] = [
        Kind::Jpeg,
        Kind::Png,
        Kind::Pdf,
        Kind::Zip,
        Kind::Sqlite,
        Kind::Mp4,
        Kind::Gzip,
    ];

    // ---- the table itself --------------------------------------------------

    #[test]
    fn every_kind_has_at_least_one_row() {
        for kind in ALL_KINDS {
            assert!(
                SIGNATURES.iter().any(|s| s.kind == kind),
                "{} has no row in SIGNATURES",
                kind.as_str()
            );
        }
    }

    #[test]
    fn rows_are_well_formed() {
        for sig in SIGNATURES {
            assert!(!sig.header.is_empty(), "{}: empty header", sig.kind);
            assert!(
                sig.max_len > sig.header.len() as u64,
                "{}: max_len {} cannot hold its own header",
                sig.kind,
                sig.max_len
            );
            if let Some(f) = sig.footer {
                assert!(!f.is_empty(), "{}: empty footer", sig.kind);
                assert!(
                    sig.max_len >= (sig.header.len() + f.len()) as u64,
                    "{}: max_len cannot hold header + footer",
                    sig.kind
                );
            }
        }
    }

    #[test]
    fn max_len_clears_the_largest_planted_instance_of_its_kind() {
        // Measured from out/fixture.manifest.json. If a bound is ever tightened
        // below one of these, the demo loses that file silently; this test makes
        // it loud instead.
        let largest = [
            (Kind::Jpeg, 108_462u64),
            (Kind::Png, 260_595),
            (Kind::Pdf, 54_214),
            (Kind::Zip, 79_397),
            (Kind::Sqlite, 221_184),
            (Kind::Mp4, 221_041),
            (Kind::Gzip, 127_302),
        ];
        for (kind, size) in largest {
            let sig = signature_for(kind).unwrap();
            assert!(
                sig.max_len > size,
                "{}: max_len {} does not clear the largest planted instance {}",
                kind,
                sig.max_len,
                size
            );
        }
    }

    #[test]
    fn kinds_without_a_footer_pattern_are_the_length_carrying_formats() {
        // GZIP ends in CRC32 + ISIZE, SQLite carries a page count in its header,
        // ISO-BMFF is a box tree. None of the three has a terminator to match,
        // so `footer_at: None` from those kinds means "no footer defined" and is
        // NOT a bifragment trigger.
        for kind in [Kind::Gzip, Kind::Sqlite, Kind::Mp4] {
            assert!(signature_for(kind).unwrap().footer.is_none(), "{}", kind);
        }
        for kind in [Kind::Jpeg, Kind::Png, Kind::Pdf, Kind::Zip] {
            assert!(signature_for(kind).unwrap().footer.is_some(), "{}", kind);
        }
    }

    // ---- scanning basics ---------------------------------------------------

    #[test]
    fn the_probe_offset_of_each_row_really_discriminates_it() {
        // The nine ftyp rows share bytes 0..3 and diverge at the box-size byte.
        for (row, sig) in SIGNATURES.iter().enumerate() {
            let at = PROBE_AT[row];
            assert!(at < sig.header.len());
            if sig.kind == Kind::Mp4 {
                assert_eq!(at, 3, "ftyp rows must probe the box-size byte");
            }
            // Whatever offset was chosen, some other row sharing this first byte
            // must actually disagree there -- otherwise the probe buys nothing.
            let shares_first = SIGNATURES
                .iter()
                .enumerate()
                .any(|(k, o)| k != row && o.header[0] == sig.header[0]);
            if shares_first && at != 0 {
                assert!(SIGNATURES.iter().enumerate().any(|(k, o)| {
                    k != row && o.header[0] == sig.header[0] && at < o.header.len() && o.header[at] != sig.header[at]
                }));
            }
        }
    }

    #[test]
    fn empty_input_yields_no_candidates() {
        assert!(scan(&[]).is_empty());
    }

    #[test]
    fn each_row_matches_its_own_header_at_offset_zero() {
        for sig in SIGNATURES {
            let buf = inert(sig.header, sig.header.len() + 64);
            let cands = scan(&buf);
            assert!(
                cands.iter().any(|c| c.kind == sig.kind && c.header_at == 0),
                "{} header {:02X?} did not match itself",
                sig.kind,
                sig.header
            );
        }
    }

    #[test]
    fn header_is_found_at_a_nonzero_offset() {
        let mut buf = vec![0xAAu8; 4096];
        buf[1234..1234 + PNG_HEADER.len()].copy_from_slice(PNG_HEADER);
        let cands = scan(&buf);
        assert_eq!(offsets(&cands, Kind::Png), vec![1234]);
    }

    #[test]
    fn a_header_truncated_by_the_end_of_the_buffer_is_not_a_match() {
        // Seven of PNG's eight signature bytes, and nothing after them.
        let buf = PNG_HEADER[..PNG_HEADER.len() - 1].to_vec();
        assert_eq!(count(&scan(&buf), Kind::Png), 0);
        // The eighth byte arrives and it matches.
        let buf = PNG_HEADER.to_vec();
        assert_eq!(count(&scan(&buf), Kind::Png), 1);
    }

    #[test]
    fn candidates_come_back_in_ascending_header_order() {
        let mut buf = vec![0xAAu8; 8192];
        buf[4000..4000 + PNG_HEADER.len()].copy_from_slice(PNG_HEADER);
        buf[100..100 + GZIP_HEADER.len()].copy_from_slice(GZIP_HEADER);
        buf[2000..2000 + PDF_HEADER.len()].copy_from_slice(PDF_HEADER);
        let cands = scan(&buf);
        let seen: Vec<u64> = cands.iter().map(|c| c.header_at).collect();
        assert_eq!(seen, vec![100, 2000, 4000]);
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        assert_eq!(seen, sorted);
    }

    // ---- MP4, the offset-4 magic ------------------------------------------

    #[test]
    fn mp4_header_at_is_the_box_start_not_the_ftyp_magic() {
        let mut buf = vec![0xAAu8; 4096];
        let obj = 512usize;
        buf[obj..obj + MP4_FTYP_N1.len()].copy_from_slice(MP4_FTYP_N1);
        let cands = scan(&buf);
        assert_eq!(offsets(&cands, Kind::Mp4), vec![obj as u64]);
        // The magic itself is four bytes further in, and the four bytes before
        // it are the box size the carver must include in the recovered object.
        assert_eq!(&buf[obj + 4..obj + 8], b"ftyp");
        assert_eq!(&buf[obj..obj + 4], &[0x00, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn every_declared_ftyp_box_size_is_matched_and_reports_the_box_start() {
        let rows = [
            MP4_FTYP_N0,
            MP4_FTYP_N1,
            MP4_FTYP_N2,
            MP4_FTYP_N3,
            MP4_FTYP_N4,
            MP4_FTYP_N5,
            MP4_FTYP_N6,
            MP4_FTYP_N7,
            MP4_FTYP_N8,
        ];
        for (n, row) in rows.iter().enumerate() {
            // The row's declared box size must be the documented 16 + 4N.
            let declared = u32::from_be_bytes([row[0], row[1], row[2], row[3]]) as usize;
            assert_eq!(declared, 16 + 4 * n, "row {n} declares the wrong box size");
            let mut buf = vec![0xAAu8; 256];
            buf[64..64 + row.len()].copy_from_slice(row);
            assert_eq!(offsets(&scan(&buf), Kind::Mp4), vec![64], "row {n}");
        }
    }

    #[test]
    fn an_ftyp_box_larger_than_the_table_covers_is_missed_and_that_is_documented() {
        // 16 + 4*9 = 52 = 0x34, one brand past the last row. This test exists to
        // pin the stated limitation, not to celebrate it: if a row is ever added
        // for N = 9 this test is the one that must change.
        let mut buf = vec![0xAAu8; 256];
        let row = [0x00, 0x00, 0x00, 0x34, b'f', b't', b'y', b'p'];
        buf[64..64 + row.len()].copy_from_slice(&row);
        assert_eq!(count(&scan(&buf), Kind::Mp4), 0);
    }

    // ---- footers -----------------------------------------------------------

    #[test]
    fn footer_is_resolved_when_present() {
        let mut buf = inert(JPEG_HEADER, 1024);
        buf[500] = 0xFF;
        buf[501] = 0xD9;
        let cands = scan(&buf);
        let jpeg: Vec<&Candidate> = cands.iter().filter(|c| c.kind == Kind::Jpeg).collect();
        assert_eq!(jpeg.len(), 1);
        assert_eq!(jpeg[0].header_at, 0);
        assert_eq!(jpeg[0].footer_at, Some(500));
    }

    #[test]
    fn header_with_no_footer_reports_none_which_is_the_bifragment_trigger() {
        let buf = inert(JPEG_HEADER, 1024); // no FF D9 anywhere
        let cands = scan(&buf);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].kind, Kind::Jpeg);
        assert_eq!(cands[0].footer_at, None);
        // And the caller can tell this apart from a footerless format.
        assert!(signature_for(Kind::Jpeg).unwrap().footer.is_some());
    }

    #[test]
    fn footerless_kinds_always_report_none_even_with_noise_after_them() {
        for (kind, header) in [
            (Kind::Gzip, GZIP_HEADER),
            (Kind::Sqlite, SQLITE_HEADER),
            (Kind::Mp4, MP4_FTYP_N1),
        ] {
            let mut buf = inert(header, 1024);
            // Sprinkle every other kind's footer through the payload.
            buf[200..205].copy_from_slice(PDF_FOOTER);
            buf[300..304].copy_from_slice(ZIP_FOOTER);
            buf[400..402].copy_from_slice(JPEG_FOOTER);
            buf[500..508].copy_from_slice(PNG_FOOTER);
            let cands = scan(&buf);
            let mine: Vec<&Candidate> = cands.iter().filter(|c| c.kind == kind).collect();
            assert_eq!(mine.len(), 1, "{kind}");
            assert_eq!(mine[0].footer_at, None, "{kind}");
        }
    }

    #[test]
    fn multiple_footers_after_one_header_take_the_first() {
        // Three EOI markers after one SOI. The rule is first-match; see the
        // module documentation for the measured reason (2,494 FF D9 in the
        // fixture image, 5 of them real).
        let mut buf = inert(JPEG_HEADER, 4096);
        for at in [800usize, 1600, 2400] {
            buf[at] = 0xFF;
            buf[at + 1] = 0xD9;
        }
        let cands = scan(&buf);
        assert_eq!(cands[0].footer_at, Some(800));
        // And the later ones remain reachable for a validator that needs them.
        assert_eq!(next_footer(&buf, Kind::Jpeg, 802, buf.len() as u64), Some(1600));
        assert_eq!(next_footer(&buf, Kind::Jpeg, 1602, buf.len() as u64), Some(2400));
        assert_eq!(next_footer(&buf, Kind::Jpeg, 2402, buf.len() as u64), None);
    }

    #[test]
    fn a_footer_before_the_header_is_not_taken() {
        let mut buf = vec![0xAAu8; 4096];
        buf[0] = 0xFF;
        buf[1] = 0xD9; // EOI that belongs to something else, ahead of our SOI
        buf[10..13].copy_from_slice(JPEG_HEADER);
        buf[50] = 0xFF;
        buf[51] = 0xD9;
        let cands = scan(&buf);
        let jpeg: Vec<&Candidate> = cands.iter().filter(|c| c.kind == Kind::Jpeg).collect();
        assert_eq!(jpeg.len(), 1);
        assert_eq!(jpeg[0].header_at, 10);
        assert_eq!(jpeg[0].footer_at, Some(50));
    }

    #[test]
    fn a_footer_overlapping_the_header_is_not_taken() {
        // FF D8 FF D9: the D9 shares a byte with the SOI's third byte. A footer
        // must begin at or after the end of the header.
        let mut buf = vec![0xAAu8; 512];
        buf[0..4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xD9]);
        let cands = scan(&buf);
        assert_eq!(cands[0].header_at, 0);
        assert_eq!(cands[0].footer_at, None);
    }

    #[test]
    fn a_footer_at_exactly_max_len_is_taken_and_one_byte_past_it_is_not() {
        let max = signature_for(Kind::Jpeg).unwrap().max_len as usize;
        let mut buf = inert(JPEG_HEADER, max + 8);

        // Footer whose last byte is the last byte of the window.
        buf[max - 2] = 0xFF;
        buf[max - 1] = 0xD9;
        assert_eq!(scan(&buf)[0].footer_at, Some((max - 2) as u64));

        // Shift it one byte later: it now ends outside the window.
        buf[max - 2] = 0xAA;
        buf[max - 1] = 0xFF;
        buf[max] = 0xD9;
        assert_eq!(scan(&buf)[0].footer_at, None);
    }

    #[test]
    fn png_footer_is_the_iend_tag_and_its_constant_crc() {
        assert_eq!(PNG_FOOTER, b"IEND\xAEB`\x82");
        let mut buf = inert(PNG_HEADER, 1024);
        // The bare tag without the CRC must not satisfy the footer.
        buf[400..404].copy_from_slice(b"IEND");
        assert_eq!(scan(&buf)[0].footer_at, None);
        buf[400..408].copy_from_slice(PNG_FOOTER);
        assert_eq!(scan(&buf)[0].footer_at, Some(400));
    }

    #[test]
    fn next_footer_respects_its_limit_and_returns_none_for_footerless_kinds() {
        let mut buf = vec![0xAAu8; 1024];
        buf[600] = 0xFF;
        buf[601] = 0xD9;
        assert_eq!(next_footer(&buf, Kind::Jpeg, 0, 602), Some(600));
        assert_eq!(next_footer(&buf, Kind::Jpeg, 0, 601), None); // footer truncated by limit
        assert_eq!(next_footer(&buf, Kind::Jpeg, 601, 1024), None); // starts past it
        assert_eq!(next_footer(&buf, Kind::Gzip, 0, 1024), None); // no footer pattern
        assert_eq!(next_footer(&buf, Kind::Mp4, 0, 1024), None);
        assert_eq!(next_footer(&buf, Kind::Sqlite, 0, 1024), None);
    }

    // ---- nested, overlapping, embedded ------------------------------------

    #[test]
    fn overlapping_matches_of_the_same_pattern_are_both_reported() {
        // FF D8 FF D8 FF: a JPEG SOI at 0 and another at 2, sharing a byte.
        let mut buf = vec![0xAAu8; 512];
        buf[0..5].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xD8, 0xFF]);
        assert_eq!(offsets(&scan(&buf), Kind::Jpeg), vec![0, 2]);
    }

    #[test]
    fn a_header_inside_another_kinds_payload_is_still_reported() {
        // A JPEG SOI buried in a PNG's payload. scan does not suppress it: at
        // scan time nothing knows where the PNG ends, and the buried header may
        // be a genuine deleted file rather than noise.
        let mut buf = inert(PNG_HEADER, 4096);
        buf[1000..1003].copy_from_slice(JPEG_HEADER);
        buf[2000..2008].copy_from_slice(PNG_FOOTER);
        let cands = scan(&buf);
        assert_eq!(offsets(&cands, Kind::Png), vec![0]);
        assert_eq!(offsets(&cands, Kind::Jpeg), vec![1000]);
        // Different kinds, so the optional filter leaves both alone.
        assert_eq!(suppress_nested(&cands).len(), 2);
    }

    #[test]
    fn nested_same_kind_headers_are_reported_by_scan_and_collapsed_by_the_filter() {
        // The ZIP container case: three local file headers, one end-of-central
        // -directory. scan reports three candidates; suppress_nested reports one.
        let mut buf = vec![0xAAu8; 4096];
        buf[0..4].copy_from_slice(ZIP_HEADER);
        buf[500..504].copy_from_slice(ZIP_HEADER);
        buf[900..904].copy_from_slice(ZIP_HEADER);
        buf[1200..1204].copy_from_slice(ZIP_FOOTER);
        let cands = scan(&buf);
        assert_eq!(offsets(&cands, Kind::Zip), vec![0, 500, 900]);
        for c in cands.iter().filter(|c| c.kind == Kind::Zip) {
            assert_eq!(c.footer_at, Some(1200));
        }
        let kept = suppress_nested(&cands);
        assert_eq!(offsets(&kept, Kind::Zip), vec![0]);
    }

    #[test]
    fn the_filter_keeps_a_header_that_starts_at_or_after_the_previous_footer() {
        // Two archives back to back, not one nested in the other.
        let mut buf = vec![0xAAu8; 4096];
        buf[0..4].copy_from_slice(ZIP_HEADER);
        buf[100..104].copy_from_slice(ZIP_FOOTER);
        buf[200..204].copy_from_slice(ZIP_HEADER);
        buf[300..304].copy_from_slice(ZIP_FOOTER);
        let kept = suppress_nested(&scan(&buf));
        assert_eq!(offsets(&kept, Kind::Zip), vec![0, 200]);
    }

    #[test]
    fn the_filter_never_drops_a_candidate_when_no_footer_was_resolved() {
        // Footerless kinds resolve no span, so nothing can nest inside anything.
        let mut buf = vec![0xAAu8; 4096];
        for at in [0usize, 100, 200] {
            buf[at..at + GZIP_HEADER.len()].copy_from_slice(GZIP_HEADER);
        }
        let cands = scan(&buf);
        assert_eq!(offsets(&cands, Kind::Gzip), vec![0, 100, 200]);
        assert_eq!(offsets(&suppress_nested(&cands), Kind::Gzip), vec![0, 100, 200]);
    }

    // ---- the real image ----------------------------------------------------

    /// Per-kind candidate counts on `out/fixture.img`, measured. These are the
    /// numbers reported to the operator; if the fixture is rebuilt and they
    /// move, the scanner's behaviour moved with it and that must be visible.
    ///
    /// Cross-checked against `out/fixture.manifest.json`:
    ///   JPEG 19 = 5 planted + 8 free-space residue + 6 inside other payloads
    ///   GZIP 18 = 5 planted + 13 free-space residue
    ///   ZIP  35 = 5 planted DOCX x 7 members each, 0 residue
    ///   PNG/PDF/SQLITE/MP4 = 5 planted each, 0 residue
    const FIXTURE_COUNTS: [(Kind, usize); 7] = [
        (Kind::Jpeg, 19),
        (Kind::Png, 5),
        (Kind::Pdf, 5),
        (Kind::Zip, 35),
        (Kind::Sqlite, 5),
        (Kind::Mp4, 5),
        (Kind::Gzip, 18),
    ];

    /// Offset of the first extent of every planted file whose kind this module
    /// can detect, read out of `out/fixture.manifest.json`. The five TXT files
    /// are absent because plain text has no signature; see the report.
    const PLANTED: [(Kind, u64); 35] = [
        (Kind::Zip, 1_069_056),      // media_inventory.docx
        (Kind::Gzip, 8_054_784),     // carve_session.log.gz
        (Kind::Sqlite, 12_900_352),  // hash_baseline.db
        (Kind::Png, 21_317_632),     // seizure_photo_a.png
        (Kind::Pdf, 26_875_904),     // acquisition_worksheet.pdf
        (Kind::Png, 32_710_656),     // sector_map_02.png
        (Kind::Sqlite, 37_040_128),  // carve_results.db
        (Kind::Zip, 43_235_328),     // lab_procedure_v3.docx
        (Kind::Png, 51_361_792),     // entropy_heatmap.png       (bifragment)
        (Kind::Gzip, 59_394_048),    // audit_trail.log.gz
        (Kind::Mp4, 65_796_096),     // sealing_procedure.mov     (bifragment)
        (Kind::Mp4, 65_943_552),     // handover_briefing.mov     (bifragment)
        (Kind::Sqlite, 73_611_264),  // device_registry.db
        (Kind::Png, 79_996_928),     // sector_map_03.png
        (Kind::Zip, 85_690_368),     // incident_summary.docx
        (Kind::Gzip, 89_563_136),    // controller_dump.bin.gz
        (Kind::Pdf, 96_673_792),     // chain_of_custody.pdf
        (Kind::Zip, 101_607_424),    // sanitization_report.docx
        (Kind::Sqlite, 108_763_136), // custody_ledger.db
        (Kind::Pdf, 114_669_568),    // standards_checklist.pdf
        (Kind::Pdf, 119_242_752),    // examiner_affidavit.pdf
        (Kind::Jpeg, 125_999_104),   // platter_surface_01.jpg
        (Kind::Mp4, 133_177_344),    // bench_capture_01.mov
        (Kind::Png, 136_941_568),    // sector_map_01.png
        (Kind::Gzip, 143_464_448),   // imaging_transcript.txt.gz (bifragment)
        (Kind::Sqlite, 150_474_752), // sector_index.db
        (Kind::Jpeg, 156_942_336),   // bench_setup_wide.jpg
        (Kind::Zip, 163_844_096),    // custody_addendum.docx
        (Kind::Pdf, 170_430_464),    // disposal_certificate.pdf  (bifragment)
        (Kind::Jpeg, 176_111_616),   // drive_label_macro.jpg
        (Kind::Mp4, 180_529_152),    // drive_teardown.mov
        (Kind::Jpeg, 200_210_432),   // seizure_photo_b.jpg
        (Kind::Jpeg, 214_231_040),   // evidence_bag_seal.jpg     (unrecoverable)
        (Kind::Mp4, 221_540_352),    // bodycam_intake.mov
        (Kind::Gzip, 228_945_920),   // dmesg_capture.log.gz
    ];

    #[test]
    fn fixture_every_planted_signature_bearing_file_is_found_at_its_exact_offset() {
        let Some((data, cands)) = fixture_scan() else { return };
        assert_eq!(data.len(), 268_435_456, "fixture is not the 256 MB image");
        let mut missing = Vec::new();
        for (kind, at) in PLANTED {
            if !cands
                .iter()
                .any(|c| c.kind == kind && c.header_at == at)
            {
                missing.push((kind, at));
            }
        }
        assert!(
            missing.is_empty(),
            "planted files not found by scan: {missing:?}"
        );
        assert_eq!(PLANTED.len(), 35);
    }

    #[test]
    fn fixture_per_kind_counts_are_exactly_what_was_measured() {
        let Some((data, cands)) = fixture_scan() else { return };
        let _ = data;
        for (kind, expected) in FIXTURE_COUNTS {
            assert_eq!(
                count(cands, kind),
                expected,
                "{kind} candidate count moved"
            );
        }
        assert_eq!(cands.len(), FIXTURE_COUNTS.iter().map(|c| c.1).sum::<usize>());
    }

    #[test]
    fn fixture_the_designed_residue_false_positives_are_all_seen() {
        // The manifest's residue_signature_false_positives records 8 bare JPEG
        // and 13 bare GZIP hits in free space, planted so that structure
        // validation has something real to reject. A scanner that does not
        // surface them is not finding the planted files either, so this is a
        // lower bound on recall, not an upper bound on precision.
        let Some((data, cands)) = fixture_scan() else { return };
        let _ = data;
        let planted_jpeg = PLANTED.iter().filter(|(k, _)| *k == Kind::Jpeg).count();
        let planted_gzip = PLANTED.iter().filter(|(k, _)| *k == Kind::Gzip).count();
        assert!(
            count(cands, Kind::Jpeg) >= planted_jpeg + 8,
            "JPEG: {} candidates, need at least {} planted + 8 residue",
            count(cands, Kind::Jpeg),
            planted_jpeg
        );
        assert!(
            count(cands, Kind::Gzip) >= planted_gzip + 13,
            "GZIP: {} candidates, need at least {} planted + 13 residue",
            count(cands, Kind::Gzip),
            planted_gzip
        );
    }

    #[test]
    fn fixture_the_four_byte_jpeg_variant_filter_would_have_deleted_the_test() {
        // Direct evidence for the module's decision to carry FF D8 FF and not
        // FF D8 FF {E0,E1,DB,EE}: every non-planted JPEG hit in the image has a
        // fourth byte outside that set, so the narrower pattern would score a
        // perfect 5-for-5 with zero false positives by removing the false
        // positives from the input.
        let Some((data, cands)) = fixture_scan() else { return };
        let _ = data;
        let jpeg: Vec<u64> = offsets(cands, Kind::Jpeg);
        let planted: Vec<u64> = PLANTED
            .iter()
            .filter(|(k, _)| *k == Kind::Jpeg)
            .map(|(_, o)| *o)
            .collect();
        let mut variant_matches = 0usize;
        for at in &jpeg {
            let fourth = data[*at as usize + 3];
            let is_variant = matches!(fourth, 0xE0 | 0xE1 | 0xDB | 0xEE);
            if is_variant {
                variant_matches += 1;
                assert!(
                    planted.contains(at),
                    "a non-planted hit at {at} carries a JPEG APP/DQT marker"
                );
            }
        }
        assert_eq!(variant_matches, planted.len());
        assert_eq!(jpeg.len() - variant_matches, 14);
    }

    #[test]
    fn fixture_the_optional_nesting_filter_behaves_as_its_documentation_says() {
        let Some((data, cands)) = fixture_scan() else { return };
        let _ = data;
        let kept = suppress_nested(cands);
        // Right for ZIP: 35 local file headers collapse to the 5 archives.
        assert_eq!(count(cands, Kind::Zip), 35);
        assert_eq!(count(&kept, Kind::Zip), 5);
        for (kind, at) in PLANTED.iter().filter(|(k, _)| *k == Kind::Zip) {
            assert!(kept.iter().any(|c| c.kind == *kind && c.header_at == *at));
        }
        // Hazardous for JPEG, measured, which is why the filter is opt-in: it
        // drops two candidates, both non-planted, one of them a designed residue
        // false positive that the reject pile is supposed to contain.
        assert_eq!(count(cands, Kind::Jpeg), 19);
        assert_eq!(count(&kept, Kind::Jpeg), 17);
        let dropped: Vec<u64> = offsets(cands, Kind::Jpeg)
            .into_iter()
            .filter(|at| !kept.iter().any(|k| k.kind == Kind::Jpeg && k.header_at == *at))
            .collect();
        assert_eq!(dropped, vec![180_577_290, 256_383_792]);
        for (kind, at) in PLANTED {
            assert!(
                kept.iter().any(|c| c.kind == kind && c.header_at == at),
                "the nesting filter dropped a planted {kind} at {at}"
            );
        }
    }

    #[test]
    fn fixture_the_forward_footer_search_crosses_a_forward_gap_to_the_true_end() {
        // The three fragmented objects whose kind has a footer AND whose second
        // extent lies after the first. First-match resolves the real terminator
        // in all three, gap or no gap, because nothing that looks like their
        // footer occurs in the residue that fills the gap. Ends are the last
        // extent's end from out/fixture.manifest.json; the deltas are the
        // terminator lengths (IEND+CRC 8, "%%EOF\n" 6, EOCD 22).
        let Some((data, cands)) = fixture_scan() else { return };
        let _ = data;
        let expect = [
            (Kind::Png, 51_361_792u64, 51_547_182u64, 51_547_190u64), // entropy_heatmap.png
            (Kind::Pdf, 170_430_464, 170_738_658, 170_738_664),       // disposal_certificate.pdf
            (Kind::Zip, 1_069_056, 1_230_351, 1_230_373),             // media_inventory.docx
        ];
        for (kind, header_at, footer_at, true_end) in expect {
            let cand = cands
                .iter()
                .find(|c| c.kind == kind && c.header_at == header_at)
                .unwrap_or_else(|| panic!("{kind} at {header_at} not found"));
            assert_eq!(cand.footer_at, Some(footer_at), "{kind} at {header_at}");
            assert!(footer_at < true_end && true_end - footer_at <= 22);
        }
    }

    #[test]
    fn fixture_the_reversed_jpeg_resolves_a_footer_that_is_not_its_end() {
        // evidence_bag_seal.jpg is planted out of order: its second fragment
        // lies BEFORE its first, so the object truly ends at 214,181,252, which
        // is behind its own header. A forward-only search cannot reach that and
        // must not pretend to. What it finds instead is a residue FF D9
        // 102,848 bytes past the true end. The candidate therefore looks
        // ordinary and is not: structure validation is what rejects it, and this
        // test pins the fact that scan hands over a plausible wrong answer
        // rather than a missing one. This is one of the two files the demo
        // reports as unrecoverable by design.
        let Some((data, cands)) = fixture_scan() else { return };
        let _ = data;
        let cand = cands
            .iter()
            .find(|c| c.kind == Kind::Jpeg && c.header_at == 214_231_040)
            .unwrap();
        assert_eq!(cand.footer_at, Some(214_284_100));
        let true_end = 214_181_252u64; // last extent end, from the manifest
        assert!(cand.footer_at.unwrap() > true_end);
        assert_eq!(cand.footer_at.unwrap() - true_end, 102_848);
    }

    #[test]
    fn fixture_no_footer_bearing_candidate_is_missing_its_footer() {
        // A finding worth pinning for whoever writes bifragment.rs: on this
        // image every one of the 64 JPEG/PNG/PDF/ZIP candidates resolves SOME
        // footer, and the 28 that resolve none are exactly the footerless kinds
        // (5 SQLITE + 5 MP4 + 18 GZIP). So "footer_at is None" is NOT the
        // bifragment trigger here. The trigger has to be structure validation
        // failing on a candidate that has a footer, which is what happens to the
        // reversed JPEG above.
        let Some((data, cands)) = fixture_scan() else { return };
        let _ = data;
        let mut footerless = 0usize;
        for cand in cands {
            let has_pattern = signature_for(cand.kind).unwrap().footer.is_some();
            if has_pattern {
                assert!(
                    cand.footer_at.is_some(),
                    "{} at {} has a footer pattern but resolved none",
                    cand.kind,
                    cand.header_at
                );
            } else {
                assert!(cand.footer_at.is_none());
                footerless += 1;
            }
        }
        assert_eq!(footerless, 28);
        assert_eq!(cands.len() - footerless, 64);
    }

    #[test]
    fn fixture_scan_report() {
        // Prints the measured per-kind table and wall clock. Run with
        //   cargo test -p sentinelwipe-carve -- --nocapture fixture_scan_report
        let Some(data) = fixture() else { return };
        let started = std::time::Instant::now();
        let cands = scan(&data);
        let elapsed = started.elapsed();
        let mib = data.len() as f64 / (1024.0 * 1024.0);
        eprintln!("scan {} bytes in {:?}", data.len(), elapsed);
        eprintln!("     {:.1} MiB/s", mib / elapsed.as_secs_f64());
        eprintln!("kind    candidates  planted  with_footer  no_footer");
        for kind in ALL_KINDS {
            let of_kind: Vec<&Candidate> = cands.iter().filter(|c| c.kind == kind).collect();
            let with = of_kind.iter().filter(|c| c.footer_at.is_some()).count();
            let planted = PLANTED.iter().filter(|(k, _)| *k == kind).count();
            eprintln!(
                "{:<7} {:>11} {:>8} {:>12} {:>10}",
                kind.as_str(),
                of_kind.len(),
                planted,
                with,
                of_kind.len() - with
            );
        }
        eprintln!("total   {:>11} {:>8}", cands.len(), PLANTED.len());
    }
}
