use crate::Kind;

pub mod gzip;
pub mod jpeg;
pub mod mp4;
pub mod png;

pub mod pdf;
pub mod sqlite;
pub mod zip;

#[derive(Debug, Clone, PartialEq)]
pub struct Validation {
    pub valid: bool,
    pub end: Option<u64>,
    pub score: f64,
    pub detail: String,
}

impl Validation {
    pub fn reject(detail: impl Into<String>) -> Validation {
        Validation { valid: false, end: None, score: 0.0, detail: detail.into() }
    }

    pub fn reject_with_end(end: u64, score: f64, detail: impl Into<String>) -> Validation {
        Validation { valid: false, end: Some(end), score: clamp01(score), detail: detail.into() }
    }

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

pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

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
