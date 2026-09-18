use super::{be_u32, clamp01, crc32_update, Validation};

pub const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_CHUNKS: usize = 65536;

pub const MAX_PIXELS: u64 = 1 << 28;

pub const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

const W_CRC: f64 = 0.30;
const W_IHDR: f64 = 0.15;
const W_IEND: f64 = 0.15;
const W_DIMS: f64 = 0.15;
const W_IDAT: f64 = 0.10;
const W_NAMES: f64 = 0.10;
const W_ZLIB: f64 = 0.05;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PngRubric {
    pub crc_integrity: f64,
    pub ihdr_first: f64,
    pub iend_last: f64,
    pub dimension_sanity: f64,
    pub idat_contiguity: f64,
    pub chunk_names: f64,
    pub zlib_header: f64,
}

impl PngRubric {
    pub fn total(&self) -> f64 {
        clamp01(
            self.crc_integrity
                + self.ihdr_first
                + self.iend_last
                + self.dimension_sanity
                + self.idat_contiguity
                + self.chunk_names
                + self.zlib_header,
        )
    }
}

#[derive(Debug, Clone)]
pub struct PngReport {
    pub validation: Validation,
    pub rubric: PngRubric,
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub colour_type: u8,
    pub chunks: usize,
    pub crc_ok: usize,
    pub crc_bad: usize,
    pub idat_chunks: usize,
    pub idat_payload_bytes: u64,
}

pub fn validate(data: &[u8]) -> Validation {
    analyze(data).validation
}

fn depth_colour_legal(depth: u8, colour: u8) -> bool {
    match colour {
        0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
        2 => matches!(depth, 8 | 16),
        3 => matches!(depth, 1 | 2 | 4 | 8),
        4 => matches!(depth, 8 | 16),
        6 => matches!(depth, 8 | 16),
        _ => false,
    }
}

fn is_ascii_letters(t: &[u8]) -> bool {
    t.len() == 4 && t.iter().all(|b| b.is_ascii_alphabetic())
}

pub fn analyze(data: &[u8]) -> PngReport {
    let mut r = PngReport {
        validation: Validation::reject("png: not evaluated"),
        rubric: PngRubric::default(),
        width: 0,
        height: 0,
        bit_depth: 0,
        colour_type: 0,
        chunks: 0,
        crc_ok: 0,
        crc_bad: 0,
        idat_chunks: 0,
        idat_payload_bytes: 0,
    };

    if data.len() < 8 || data[..8] != SIGNATURE {
        r.validation = Validation::reject(format!(
            "png: no 8-byte signature at offset 0 ({} bytes available)",
            data.len()
        ));
        return r;
    }

    let limit = data.len().min(MAX_OBJECT_BYTES);

    let mut ihdr_first = false;
    let mut iend_last = false;
    let mut dims_ok = false;
    let mut names_ok = true;
    let mut zlib_ok = false;

    let mut idat_run_closed = false;
    let mut idat_broken = false;
    let mut last_was_idat = false;

    let mut end: Option<usize> = None;
    let mut fail: Option<String> = None;

    let mut pos = 8usize;
    loop {
        if pos == limit && end.is_none() {
            fail = Some(format!(
                "png: chunk list ended at offset {} without an IEND",
                pos
            ));
            break;
        }
        if pos + 12 > limit {
            fail = Some(format!(
                "png: chunk header at offset {} needs 12 bytes, {} remain",
                pos,
                limit.saturating_sub(pos)
            ));
            break;
        }
        let len = match be_u32(data, pos) {
            Some(l) => l as usize,
            None => break,
        };
        if len > 0x7FFF_FFFF {
            fail = Some(format!(
                "png: chunk at offset {} declares length {} which exceeds 2^31-1",
                pos, len
            ));
            break;
        }
        if pos + 12 + len > limit {
            fail = Some(format!(
                "png: chunk at offset {} declares length {} which runs past the {} bytes available",
                pos, len, limit
            ));
            break;
        }
        let ctype = &data[pos + 4..pos + 8];
        let payload = &data[pos + 8..pos + 8 + len];
        let stored = match be_u32(data, pos + 8 + len) {
            Some(c) => c,
            None => break,
        };

        let computed = {
            let c = crc32_update(0xFFFF_FFFF, ctype);
            crc32_update(c, payload) ^ 0xFFFF_FFFF
        };
        if computed == stored {
            r.crc_ok += 1;
        } else {
            r.crc_bad += 1;
            if fail.is_none() {
                fail = Some(format!(
                    "png: CRC-32 mismatch on chunk {} at offset {}, stored {:08X} computed {:08X}",
                    String::from_utf8_lossy(ctype),
                    pos,
                    stored,
                    computed
                ));
            }
        }

        if !is_ascii_letters(ctype) {
            names_ok = false;
        } else {
            let critical = ctype[0].is_ascii_uppercase();
            if critical && !matches!(ctype, b"IHDR" | b"PLTE" | b"IDAT" | b"IEND") {
                names_ok = false;
            }
        }

        if r.chunks == 0 {
            if ctype == b"IHDR" && len == 13 {
                ihdr_first = true;
                r.width = be_u32(payload, 0).unwrap_or(0);
                r.height = be_u32(payload, 4).unwrap_or(0);
                r.bit_depth = payload[8];
                r.colour_type = payload[9];
                let compression = payload[10];
                let filter = payload[11];
                let interlace = payload[12];
                let pixels = r.width as u64 * r.height as u64;
                dims_ok = r.width >= 1
                    && r.height >= 1
                    && r.width <= 0x7FFF_FFFF
                    && r.height <= 0x7FFF_FFFF
                    && pixels <= MAX_PIXELS
                    && depth_colour_legal(r.bit_depth, r.colour_type)
                    && compression == 0
                    && filter == 0
                    && interlace <= 1;
            } else {
                fail = Some(format!(
                    "png: first chunk is {} length {}, expected IHDR length 13",
                    String::from_utf8_lossy(ctype),
                    len
                ));
            }
        }

        if ctype == b"IDAT" {
            if idat_run_closed {
                idat_broken = true;
            }
            if r.idat_chunks == 0 && len >= 2 {
                let cmf = payload[0];
                let flg = payload[1];
                zlib_ok = (cmf & 0x0F) == 8
                    && (cmf >> 4) <= 7
                    && (((cmf as u16) << 8) | flg as u16) % 31 == 0;
            }
            r.idat_chunks += 1;
            r.idat_payload_bytes += len as u64;
            last_was_idat = true;
        } else {
            if last_was_idat {
                idat_run_closed = true;
            }
            last_was_idat = false;
        }

        r.chunks += 1;
        pos = pos + 12 + len;

        if ctype == b"IEND" {
            end = Some(pos);
            iend_last = len == 0;
            if len != 0 && fail.is_none() {
                fail = Some(format!("png: IEND carries a {}-byte payload, must be empty", len));
            }
            break;
        }
        if r.chunks > MAX_CHUNKS {
            fail = Some(format!("png: chunk list exceeded {} chunks", MAX_CHUNKS));
            break;
        }
    }

    let idat_ok = r.idat_chunks >= 1 && !idat_broken;

    r.rubric = PngRubric {
        crc_integrity: if r.chunks == 0 {
            0.0
        } else {
            W_CRC * (r.crc_ok as f64 / r.chunks as f64)
        },
        ihdr_first: if ihdr_first { W_IHDR } else { 0.0 },
        iend_last: if iend_last { W_IEND } else { 0.0 },
        dimension_sanity: if dims_ok { W_DIMS } else { 0.0 },
        idat_contiguity: if idat_ok { W_IDAT } else { 0.0 },
        chunk_names: if names_ok { W_NAMES } else { 0.0 },
        zlib_header: if zlib_ok { W_ZLIB } else { 0.0 },
    };
    let score = r.rubric.total();

    let gate = ihdr_first && iend_last && dims_ok && idat_ok && r.crc_bad == 0 && end.is_some();

    r.validation = match (gate, end) {
        (true, Some(e)) => Validation::accept(
            e as u64,
            score,
            format!(
                "png: {}x{} depth {} colour {}, {} chunks all CRC-verified, {} IDAT holding {} compressed bytes, {} total",
                r.width, r.height, r.bit_depth, r.colour_type, r.chunks,
                r.idat_chunks, r.idat_payload_bytes, e
            ),
        ),
        (false, Some(e)) => Validation::reject_with_end(
            e as u64,
            score,
            fail.unwrap_or_else(|| {
                format!(
                    "png: reached IEND at {} but {} of {} chunk CRCs failed or the header was not sane",
                    e, r.crc_bad, r.chunks
                )
            }),
        ),
        (_, None) => {
            let mut v = Validation::reject(
                fail.unwrap_or_else(|| "png: no IEND found".to_string()),
            );
            v.score = score;
            v
        }
    };
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structure::crc32;

    fn chunk(ctype: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(ctype);
        v.extend_from_slice(payload);
        let mut c = Vec::new();
        c.extend_from_slice(ctype);
        c.extend_from_slice(payload);
        v.extend_from_slice(&crc32(&c).to_be_bytes());
        v
    }

    fn ihdr(w: u32, h: u32, depth: u8, colour: u8) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&w.to_be_bytes());
        p.extend_from_slice(&h.to_be_bytes());
        p.push(depth);
        p.push(colour);
        p.extend_from_slice(&[0, 0, 0]);
        chunk(b"IHDR", &p)
    }

    fn good_png() -> Vec<u8> {
        let mut v = SIGNATURE.to_vec();
        v.extend(ihdr(16, 16, 8, 2));
        v.extend(chunk(b"tEXt", b"Source\0sentinelwipe"));
        v.extend(chunk(b"IDAT", &[0x78, 0x01, 0x01, 0x02, 0x03, 0x04]));
        v.extend(chunk(b"IDAT", &[0x05, 0x06, 0x07, 0x08]));
        v.extend(chunk(b"IEND", b""));
        v
    }

    #[test]
    fn intact_png_is_valid_and_scores_one() {
        let p = good_png();
        let r = analyze(&p);
        assert!(r.validation.valid, "detail: {}", r.validation.detail);
        assert_eq!(r.validation.end, Some(p.len() as u64));
        assert!((r.validation.score - 1.0).abs() < 1e-12, "score {}", r.validation.score);
        assert_eq!(r.chunks, 5);
        assert_eq!(r.crc_ok, 5);
        assert_eq!(r.crc_bad, 0);
        assert_eq!(r.idat_chunks, 2);
        assert_eq!(r.idat_payload_bytes, 10);
        assert_eq!((r.width, r.height, r.bit_depth, r.colour_type), (16, 16, 8, 2));
    }

    #[test]
    fn end_stops_at_iend_not_at_the_slice_end() {
        let mut p = good_png();
        let n = p.len();
        p.extend(std::iter::repeat(0x33u8).take(9999));
        let v = validate(&p);
        assert!(v.valid);
        assert_eq!(v.end, Some(n as u64));
    }

    #[test]
    fn term_crc_integrity_is_a_fraction_and_gates() {
        let mut p = good_png();
        let idat_at = SIGNATURE.len() + 25 + (12 + 19);
        assert_eq!(&p[idat_at + 4..idat_at + 8], b"IDAT");
        p[idat_at + 9] ^= 0xFF;
        let r = analyze(&p);
        assert_eq!(r.crc_bad, 1);
        assert_eq!(r.crc_ok, 4);
        assert!((r.rubric.crc_integrity - W_CRC * (4.0 / 5.0)).abs() < 1e-12,
                "crc_integrity {}", r.rubric.crc_integrity);
        assert!(!r.validation.valid, "one bad CRC must fail the object");
        assert!(r.validation.detail.contains("CRC-32 mismatch"), "detail: {}", r.validation.detail);
        assert_eq!(r.validation.end, Some(p.len() as u64), "end is still known");
    }

    #[test]
    fn term_ihdr_first_falls_when_ihdr_is_not_first() {
        let mut v = SIGNATURE.to_vec();
        v.extend(chunk(b"tEXt", b"a\0b"));
        v.extend(ihdr(16, 16, 8, 2));
        v.extend(chunk(b"IDAT", &[0x78, 0x01, 0x01]));
        v.extend(chunk(b"IEND", b""));
        let r = analyze(&v);
        assert_eq!(r.rubric.ihdr_first, 0.0);
        assert_eq!(r.rubric.crc_integrity, W_CRC, "every CRC is still correct");
        assert!(!r.validation.valid);
    }

    #[test]
    fn term_iend_last_falls_when_iend_carries_a_payload() {
        let mut v = SIGNATURE.to_vec();
        v.extend(ihdr(16, 16, 8, 2));
        v.extend(chunk(b"IDAT", &[0x78, 0x01, 0x01]));
        v.extend(chunk(b"IEND", b"x"));
        let r = analyze(&v);
        assert_eq!(r.rubric.iend_last, 0.0);
        assert!(!r.validation.valid);
        assert!(r.validation.detail.contains("IEND carries"), "detail: {}", r.validation.detail);
    }

    #[test]
    fn term_dimension_sanity_falls_on_an_absurd_header() {
        let mut v = SIGNATURE.to_vec();
        v.extend(ihdr(0x7FFF_FFFF, 0x7FFF_FFFF, 8, 2));
        v.extend(chunk(b"IDAT", &[0x78, 0x01, 0x01]));
        v.extend(chunk(b"IEND", b""));
        let r = analyze(&v);
        assert_eq!(r.rubric.dimension_sanity, 0.0);
        assert!(!r.validation.valid);
        assert!((r.validation.score - (1.0 - W_DIMS)).abs() < 1e-12,
                "only dimension_sanity should move, got {}", r.validation.score);
    }

    #[test]
    fn term_dimension_sanity_falls_on_an_illegal_depth_colour_pair() {
        let mut v = SIGNATURE.to_vec();
        v.extend(ihdr(16, 16, 4, 2));
        v.extend(chunk(b"IDAT", &[0x78, 0x01, 0x01]));
        v.extend(chunk(b"IEND", b""));
        let r = analyze(&v);
        assert_eq!(r.rubric.dimension_sanity, 0.0);
        assert!(!r.validation.valid);
    }

    #[test]
    fn term_idat_contiguity_falls_when_a_chunk_splits_the_idat_run() {
        let mut v = SIGNATURE.to_vec();
        v.extend(ihdr(16, 16, 8, 2));
        v.extend(chunk(b"IDAT", &[0x78, 0x01, 0x01]));
        v.extend(chunk(b"tEXt", b"a\0b"));
        v.extend(chunk(b"IDAT", &[0x02, 0x03]));
        v.extend(chunk(b"IEND", b""));
        let r = analyze(&v);
        assert_eq!(r.rubric.idat_contiguity, 0.0);
        assert!(!r.validation.valid);
        assert!((r.validation.score - (1.0 - W_IDAT)).abs() < 1e-12,
                "only idat_contiguity should move, got {}", r.validation.score);
    }

    #[test]
    fn term_idat_contiguity_falls_with_no_idat_at_all() {
        let mut v = SIGNATURE.to_vec();
        v.extend(ihdr(16, 16, 8, 2));
        v.extend(chunk(b"IEND", b""));
        let r = analyze(&v);
        assert_eq!(r.rubric.idat_contiguity, 0.0);
        assert_eq!(r.rubric.zlib_header, 0.0);
        assert!(!r.validation.valid);
    }

    #[test]
    fn term_chunk_names_falls_on_an_unknown_critical_chunk() {
        let mut v = SIGNATURE.to_vec();
        v.extend(ihdr(16, 16, 8, 2));
        v.extend(chunk(b"ZZZZ", b"payload"));
        v.extend(chunk(b"IDAT", &[0x78, 0x01, 0x01]));
        v.extend(chunk(b"IEND", b""));
        let r = analyze(&v);
        assert_eq!(r.rubric.chunk_names, 0.0);
        assert!((r.validation.score - (1.0 - W_NAMES)).abs() < 1e-12,
                "only chunk_names should move, got {}", r.validation.score);
        assert!(r.validation.valid, "an unknown critical chunk grades, it does not gate");
    }

    #[test]
    fn term_chunk_names_holds_for_an_unknown_ancillary_chunk() {
        let mut v = SIGNATURE.to_vec();
        v.extend(ihdr(16, 16, 8, 2));
        v.extend(chunk(b"zZzZ", b"payload"));
        v.extend(chunk(b"IDAT", &[0x78, 0x01, 0x01]));
        v.extend(chunk(b"IEND", b""));
        let r = analyze(&v);
        assert_eq!(r.rubric.chunk_names, W_NAMES);
        assert!((r.validation.score - 1.0).abs() < 1e-12);
    }

    #[test]
    fn term_zlib_header_falls_on_a_bad_cmf_flg() {
        let mut v = SIGNATURE.to_vec();
        v.extend(ihdr(16, 16, 8, 2));
        v.extend(chunk(b"IDAT", &[0x78, 0x02, 0x01]));
        v.extend(chunk(b"IEND", b""));
        let r = analyze(&v);
        assert_eq!(r.rubric.zlib_header, 0.0);
        assert!((r.validation.score - (1.0 - W_ZLIB)).abs() < 1e-12,
                "only zlib_header should move, got {}", r.validation.score);
        assert!(r.validation.valid, "the CRC already covers those bytes; this grades only");
    }

    #[test]
    fn weights_sum_to_one() {
        let s = W_CRC + W_IHDR + W_IEND + W_DIMS + W_IDAT + W_NAMES + W_ZLIB;
        assert!((s - 1.0).abs() < 1e-12, "rubric weights sum to {}", s);
    }

    #[test]
    fn rejects_bare_signature() {
        let v = validate(&SIGNATURE);
        assert!(!v.valid);
        assert_eq!(v.end, None);
    }

    #[test]
    fn rejects_wrong_signature() {
        let mut d = SIGNATURE.to_vec();
        d[3] = b'Q';
        d.extend(std::iter::repeat(0u8).take(64));
        let v = validate(&d);
        assert!(!v.valid);
        assert!(v.detail.contains("no 8-byte signature"), "detail: {}", v.detail);
    }

    #[test]
    fn rejects_truncated_object() {
        let mut p = good_png();
        p.truncate(p.len() - 6);
        let v = validate(&p);
        assert!(!v.valid);
        assert_eq!(v.end, None);
    }

    #[test]
    fn rejects_signature_followed_by_noise() {
        let mut s: u32 = 0xDEAD_BEEF;
        let mut d = SIGNATURE.to_vec();
        for _ in 0..4096 {
            s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
            d.push((s >> 16) as u8);
        }
        let v = validate(&d);
        assert!(!v.valid);
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let mut s: u32 = 0x0BAD_F00D;
        for trial in 0..200 {
            let mut d = SIGNATURE.to_vec();
            for _ in 0..(16 + trial * 5) {
                s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
                d.push((s >> 16) as u8);
            }
            let _ = validate(&d);
        }
    }
}
