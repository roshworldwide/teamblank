//! Fast object validation.
//!
//! Simson L. Garfinkel, "Carving contiguous and fragmented files with fast
//! object validation", Digital Investigation 4S (DFRWS 2007), pp. S2-S12.
//!
//! The paper's central point is the one this module exists to enforce: a header
//! match is a CANDIDATE, not a file. Signature scanning alone cannot tell a
//! planted JPEG from three bytes of noise that happen to read FF D8 FF, and on
//! this project's own fixture the noise wins eight times for JPEG and thirteen
//! times for GZIP -- counts measured at fixture build time and published in
//! `out/fixture.manifest.json` under `residue_signature_false_positives`. A
//! validator is a cheap decision procedure that reads the object's own internal
//! structure and answers three questions:
//!
//!   1. is this actually an object of this kind?          -> `valid`
//!   2. where does it end?                                -> `end`
//!   3. how intact is what we found?                      -> `score`
//!
//! Question 2 is what makes fragmented carving tractable at all: without a
//! length the carver has nothing to hash and nothing to bound a gap search
//! with. Question 3 is what feeds the published confidence function, which
//! needs a real number in [0,1] and not a boolean dressed up as one.
//!
//! ## How `score` is derived, in general
//!
//! Every validator publishes a RUBRIC: a fixed list of independent structural
//! checks, each with a fixed weight, the weights summing to exactly 1.0. The
//! score is the sum of the weights earned. Some checks are binary (the box tree
//! tiles exactly, or it does not); some are graded fractions (the proportion of
//! PNG chunks whose CRC32 verifies). No check is scored by feel and none is
//! asserted: each one is a byte comparison, and each one is unit tested on its
//! own, by taking a known-good object and breaking exactly that check.
//!
//! `valid` is NOT `score >= threshold`. Validity is a separate hard gate, named
//! per kind, which asks only whether this is an object of this kind whose end
//! is known. Score then grades quality above that gate. An intact planted file
//! scores 1.00; the rubric moves when structure is damaged, missing, or merely
//! optional-and-absent. Keeping the two apart is what stops the carver from
//! rejecting a genuinely recovered but slightly unusual object, and stops it
//! from accepting residue that scored well on the easy half of the rubric.
//!
//! ## Input convention
//!
//! `validate(kind, data)` takes a slice whose byte 0 IS the object's first byte
//! -- the SOI for JPEG, the 8-byte signature for PNG, 1F 8B for GZIP. The slice
//! normally runs to the end of the image, and every validator is written to
//! treat everything past its own computed `end` as unrelated bytes.
//!
//! MP4 is the one kind where "the header" and "the signature" are not the same
//! offset: the scanner matches the four bytes `ftyp`, which sit at offset 4 of
//! the object, inside the first box's header. `mp4::validate` therefore expects
//! `data` to start at the ftyp BOX -- the 32-bit size field -- so a caller
//! holding a `ftyp` match at position p must pass `header_at = p - 4`. Passing
//! the raw match position is detected and rejected with that instruction in
//! `detail` rather than silently mis-parsed.
//!
//! ## Ownership
//!
//! jpeg, png, gzip, mp4 and this dispatcher are one agent's files; pdf, zip and
//! sqlite are another's. All seven are declared here, as the contract requires,
//! and every one of them exposes the same `validate(&[u8]) -> Validation`.

use crate::Kind;

pub mod gzip;
pub mod jpeg;
pub mod mp4;
pub mod png;

// The other structure agent's half.
pub mod pdf;
pub mod sqlite;
pub mod zip;

/// The result of validating one candidate.
///
/// * `valid` -- the hard gate: this is an object of the requested kind and its
///   extent is known. Never a thresholded score.
/// * `end`   -- byte offset, relative to `data[0]`, ONE PAST the object's last
///   byte. `Some` whenever a terminator was reached, which can happen even when
///   `valid` is false (a JPEG that reached EOI but references an undefined
///   Huffman table, say). `None` when no end could be established.
/// * `score` -- rubric total in [0,1]. See each validator's RUBRIC comment.
/// * `detail` -- one line, machine-greppable, naming what was checked and what
///   failed. This is the string that ends up on screen next to the number, so
///   it never says "invalid" without saying which check and at which offset.
#[derive(Debug, Clone, PartialEq)]
pub struct Validation {
    pub valid: bool,
    pub end: Option<u64>,
    pub score: f64,
    pub detail: String,
}

impl Validation {
    /// A rejection with no known end.
    pub fn reject(detail: impl Into<String>) -> Validation {
        Validation { valid: false, end: None, score: 0.0, detail: detail.into() }
    }

    /// A rejection that nonetheless established where the object stops.
    pub fn reject_with_end(end: u64, score: f64, detail: impl Into<String>) -> Validation {
        Validation { valid: false, end: Some(end), score: clamp01(score), detail: detail.into() }
    }

    /// An accepted object.
    pub fn accept(end: u64, score: f64, detail: impl Into<String>) -> Validation {
        Validation { valid: true, end: Some(end), score: clamp01(score), detail: detail.into() }
    }
}

pub(crate) fn clamp01(x: f64) -> f64 {
    if !x.is_finite() {
        0.0
    } else if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

/// Dispatch to the validator for `kind`. `data` starts AT the object header.
pub fn validate(kind: Kind, data: &[u8]) -> Validation {
    match kind {
        Kind::Jpeg => jpeg::validate(data),
        Kind::Png => png::validate(data),
        Kind::Gzip => gzip::validate(data),
        Kind::Mp4 => mp4::validate(data),
        Kind::Pdf => pdf::validate(data),
        Kind::Zip => zip::validate(data),
        Kind::Sqlite => sqlite::validate(data),
    }
}

// ---------------------------------------------------------------------------
// CRC-32, hand-rolled
// ---------------------------------------------------------------------------
//
// PNG (ISO 15948 section 5.5) and GZIP (RFC 1952 section 2.3.1) both specify
// the same CRC-32: reflected, polynomial 0xEDB88320, init and final xor
// 0xFFFFFFFF. CLAUDE.md's dependency rule says hand-roll it, and the table is
// built at compile time so no lazy-init lock sits in the carver's inner loop.

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

static CRC32_TABLE: [u32; 256] = crc32_table();

/// CRC-32 as used by PNG and GZIP.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

/// Streaming form: feed successive slices, seed with `0xFFFFFFFF`, finish by
/// xoring with `0xFFFFFFFF`.
pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

// ---------------------------------------------------------------------------
// small shared readers
// ---------------------------------------------------------------------------

#[inline]
pub(crate) fn be_u16(d: &[u8], at: usize) -> Option<u16> {
    if at + 2 > d.len() {
        return None;
    }
    Some(((d[at] as u16) << 8) | d[at + 1] as u16)
}

#[inline]
pub(crate) fn be_u32(d: &[u8], at: usize) -> Option<u32> {
    if at + 4 > d.len() {
        return None;
    }
    Some(u32::from_be_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]))
}

#[inline]
pub(crate) fn be_u64(d: &[u8], at: usize) -> Option<u64> {
    if at + 8 > d.len() {
        return None;
    }
    let mut v = 0u64;
    let mut i = 0;
    while i < 8 {
        v = (v << 8) | d[at + i] as u64;
        i += 1;
    }
    Some(v)
}

#[inline]
pub(crate) fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    if at + 4 > d.len() {
        return None;
    }
    Some(u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The three CRC-32 vectors every implementation is checked against.
    // "123456789" -> 0xCBF43926 is the CRC catalogue's check value for
    // CRC-32/ISO-HDLC, which is the variant PNG and GZIP both use.
    #[test]
    fn crc32_catalogue_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn crc32_streaming_matches_one_shot() {
        let data: Vec<u8> = (0u32..1000).map(|i| (i * 37 % 251) as u8).collect();
        let one = crc32(&data);
        let mut c = 0xFFFF_FFFFu32;
        for chunk in data.chunks(7) {
            c = crc32_update(c, chunk);
        }
        assert_eq!(one, c ^ 0xFFFF_FFFF);
    }

    #[test]
    fn crc32_matches_png_iend_constant() {
        // The CRC over the four bytes "IEND" is a fixed constant every PNG
        // in existence ends with.
        assert_eq!(crc32(b"IEND"), 0xAE42_6082);
        assert_eq!(crc32(b"IHDR"), 0xA8A1_AE0A);
    }

    #[test]
    fn clamp01_bounds() {
        assert_eq!(clamp01(-1.0), 0.0);
        assert_eq!(clamp01(2.0), 1.0);
        assert_eq!(clamp01(0.5), 0.5);
        assert_eq!(clamp01(f64::NAN), 0.0);
    }
}
