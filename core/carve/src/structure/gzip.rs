use super::{clamp01, crc32, le_u32, Validation};

pub const MAX_INFLATE_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_MEMBER_BYTES: usize = 64 * 1024 * 1024;

const W_HEADER: f64 = 0.15;
const W_OPTIONAL: f64 = 0.10;
const W_INFLATE: f64 = 0.35;
const W_CRC: f64 = 0.25;
const W_ISIZE: f64 = 0.15;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GzipRubric {
    pub header_fields: f64,
    pub optional_fields: f64,
    pub inflate: f64,
    pub crc_match: f64,
    pub isize_match: f64,
}

impl GzipRubric {
    pub fn total(&self) -> f64 {
        clamp01(
            self.header_fields
                + self.optional_fields
                + self.inflate
                + self.crc_match
                + self.isize_match,
        )
    }
}

#[derive(Debug, Clone)]
pub struct GzipReport {
    pub validation: Validation,
    pub rubric: GzipRubric,
    pub header_bytes: usize,
    pub deflate_bytes: usize,
    pub inflated_bytes: u64,
    pub stored_crc32: u32,
    pub computed_crc32: u32,
    pub stored_isize: u32,
    pub inner_name: Option<String>,
    pub blocks: usize,
}

pub fn validate(data: &[u8]) -> Validation {
    analyze(data).validation
}

pub fn analyze(data: &[u8]) -> GzipReport {
    let mut r = GzipReport {
        validation: Validation::reject("gzip: not evaluated"),
        rubric: GzipRubric::default(),
        header_bytes: 0,
        deflate_bytes: 0,
        inflated_bytes: 0,
        stored_crc32: 0,
        computed_crc32: 0,
        stored_isize: 0,
        inner_name: None,
        blocks: 0,
    };

    if data.len() < 18 {
        r.validation = Validation::reject(format!(
            "gzip: {} bytes available, a member needs at least 18",
            data.len()
        ));
        return r;
    }
    if data[0] != 0x1F || data[1] != 0x8B {
        r.validation = Validation::reject(format!(
            "gzip: no 1F 8B magic at offset 0, found {:02X} {:02X}",
            data[0], data[1]
        ));
        return r;
    }

    let cm = data[2];
    let flg = data[3];
    let reserved = flg & 0xE0;
    let header_ok = cm == 8 && reserved == 0;
    if !header_ok {
        r.rubric.header_fields = 0.0;
        r.validation = Validation::reject(if cm != 8 {
            format!("gzip: CM is {}, RFC 1952 defines only 8 (deflate)", cm)
        } else {
            format!(
                "gzip: FLG is {:#04X}, reserved bits 5-7 are {:#04X} and RFC 1952 requires them zero",
                flg, reserved
            )
        });
        return r;
    }
    r.rubric.header_fields = W_HEADER;

    const FTEXT: u8 = 0x01;
    const FHCRC: u8 = 0x02;
    const FEXTRA: u8 = 0x04;
    const FNAME: u8 = 0x08;
    const FCOMMENT: u8 = 0x10;
    let _ = FTEXT;

    let mut opt_ok = true;
    let mut pos = 10usize;

    if flg & FEXTRA != 0 {
        if pos + 2 > data.len() {
            r.validation = Validation::reject("gzip: FEXTRA set but XLEN is truncated");
            return r;
        }
        let xlen = ((data[pos + 1] as usize) << 8) | data[pos] as usize;
        pos += 2;
        if pos + xlen > data.len() {
            r.validation = Validation::reject(format!(
                "gzip: FEXTRA declares {} bytes which run past the {} available",
                xlen,
                data.len()
            ));
            return r;
        }
        pos += xlen;
    }

    let read_cstr = |start: usize, what: &str| -> Result<(usize, String), String> {
        let mut i = start;
        while i < data.len() && data[i] != 0 {
            if i - start > 1024 {
                return Err(format!("gzip: {} exceeds 1024 bytes without a NUL", what));
            }
            i += 1;
        }
        if i >= data.len() {
            return Err(format!("gzip: {} is not NUL-terminated within the data", what));
        }
        let raw = &data[start..i];
        let printable = raw.iter().all(|&b| b >= 0x20 && b != 0x7F);
        Ok((
            i + 1,
            if printable {
                String::from_utf8_lossy(raw).into_owned()
            } else {
                String::new()
            },
        ))
    };

    if flg & FNAME != 0 {
        match read_cstr(pos, "FNAME") {
            Ok((next, s)) => {
                if s.is_empty() {
                    opt_ok = false;
                }
                r.inner_name = Some(s);
                pos = next;
            }
            Err(e) => {
                r.validation = Validation::reject(e);
                return r;
            }
        }
    }
    if flg & FCOMMENT != 0 {
        match read_cstr(pos, "FCOMMENT") {
            Ok((next, s)) => {
                if s.is_empty() {
                    opt_ok = false;
                }
                pos = next;
            }
            Err(e) => {
                r.validation = Validation::reject(e);
                return r;
            }
        }
    }
    if flg & FHCRC != 0 {
        if pos + 2 > data.len() {
            r.validation = Validation::reject("gzip: FHCRC set but the CRC16 is truncated");
            return r;
        }
        let stored = ((data[pos + 1] as u16) << 8) | data[pos] as u16;
        let computed = (crc32(&data[..pos]) & 0xFFFF) as u16;
        if stored != computed {
            opt_ok = false;
        }
        pos += 2;
    }
    r.header_bytes = pos;
    r.rubric.optional_fields = if opt_ok { W_OPTIONAL } else { 0.0 };

    let body = &data[pos..data.len().min(pos + MAX_MEMBER_BYTES)];
    let inflated = match inflate(body, MAX_INFLATE_BYTES) {
        Ok(i) => i,
        Err(e) => {
            r.validation = Validation::reject(format!(
                "gzip: header parsed over {} bytes but the DEFLATE stream failed: {}",
                pos, e
            ));
            r.validation.score = r.rubric.total();
            return r;
        }
    };
    r.rubric.inflate = W_INFLATE;
    r.deflate_bytes = inflated.consumed;
    r.inflated_bytes = inflated.out.len() as u64;
    r.blocks = inflated.blocks;

    let trailer_at = pos + inflated.consumed;
    if trailer_at + 8 > data.len() {
        r.validation = Validation::reject(format!(
            "gzip: DEFLATE stream ended at offset {} but the 8-byte trailer runs past the {} bytes available",
            trailer_at,
            data.len()
        ));
        r.validation.score = r.rubric.total();
        return r;
    }
    r.stored_crc32 = le_u32(data, trailer_at).unwrap_or(0);
    r.stored_isize = le_u32(data, trailer_at + 4).unwrap_or(0);
    r.computed_crc32 = crc32(&inflated.out);
    let crc_ok = r.computed_crc32 == r.stored_crc32;
    let isize_ok = (inflated.out.len() as u64 & 0xFFFF_FFFF) == r.stored_isize as u64;
    r.rubric.crc_match = if crc_ok { W_CRC } else { 0.0 };
    r.rubric.isize_match = if isize_ok { W_ISIZE } else { 0.0 };

    let end = (trailer_at + 8) as u64;
    let score = r.rubric.total();
    r.validation = if crc_ok && isize_ok {
        Validation::accept(
            end,
            score,
            format!(
                "gzip: {}-byte header{}, {} DEFLATE bytes in {} block(s) -> {} bytes, CRC-32 {:08X} verified, ISIZE {} matched, {} total",
                r.header_bytes,
                r.inner_name
                    .as_deref()
                    .map(|n| format!(" naming '{}'", n))
                    .unwrap_or_default(),
                r.deflate_bytes,
                r.blocks,
                r.inflated_bytes,
                r.stored_crc32,
                r.stored_isize,
                end
            ),
        )
    } else {
        Validation::reject_with_end(
            end,
            score,
            format!(
                "gzip: inflated {} bytes but the trailer disagrees -- CRC-32 stored {:08X} computed {:08X}, ISIZE stored {} actual {}",
                r.inflated_bytes, r.stored_crc32, r.computed_crc32, r.stored_isize, r.inflated_bytes
            ),
        )
    };
    r
}

#[derive(Debug, Clone)]
pub struct Inflated {
    pub out: Vec<u8>,
    pub consumed: usize,
    pub blocks: usize,
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

struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

fn build_huffman(lengths: &[u8]) -> Result<Huffman, String> {
    let mut counts = [0u16; 16];
    for &l in lengths {
        if l > 15 {
            return Err(format!("code length {} exceeds 15", l));
        }
        counts[l as usize] += 1;
    }
    if counts[0] as usize == lengths.len() {
        return Err("Huffman table has no codes".to_string());
    }
    let mut left: i32 = 1;
    for n in 1..16 {
        left <<= 1;
        left -= counts[n] as i32;
        if left < 0 {
            return Err(format!("Huffman table is over-subscribed at length {}", n));
        }
    }
    let mut offs = [0u16; 16];
    for n in 1..15 {
        offs[n + 1] = offs[n] + counts[n];
    }
    let mut symbols = vec![0u16; lengths.len()];
    for (sym, &l) in lengths.iter().enumerate() {
        if l != 0 {
            symbols[offs[l as usize] as usize] = sym as u16;
            offs[l as usize] += 1;
        }
    }
    Ok(Huffman { counts, symbols })
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u32,
    nbits: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> BitReader<'a> {
        BitReader { data, pos: 0, acc: 0, nbits: 0 }
    }

    fn bits(&mut self, need: u32) -> Result<u32, String> {
        while self.nbits < need {
            if self.pos >= self.data.len() {
                return Err(format!(
                    "stream ran out of input after {} bytes",
                    self.data.len()
                ));
            }
            self.acc |= (self.data[self.pos] as u32) << self.nbits;
            self.pos += 1;
            self.nbits += 8;
        }
        let v = self.acc & ((1u32 << need) - 1);
        self.acc >>= need;
        self.nbits -= need;
        Ok(v)
    }

    fn align(&mut self) {
        self.acc = 0;
        self.nbits = 0;
    }

    fn consumed(&self) -> usize {
        self.pos - (self.nbits / 8) as usize
    }

    fn decode(&mut self, h: &Huffman) -> Result<u16, String> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..16usize {
            code |= self.bits(1)? as i32;
            let count = h.counts[len] as i32;
            if code - count < first {
                let at = (index + (code - first)) as usize;
                return h
                    .symbols
                    .get(at)
                    .copied()
                    .ok_or_else(|| "symbol index out of range".to_string());
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err("no Huffman code matched in 15 bits".to_string())
    }
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut ll = [0u8; 288];
    for (i, l) in ll.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let d = [5u8; 30];
    (
        build_huffman(&ll).expect("fixed literal/length table is well formed"),
        build_huffman(&d).expect("fixed distance table is well formed"),
    )
}

pub fn inflate(input: &[u8], max_out: usize) -> Result<Inflated, String> {
    let mut br = BitReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    let mut blocks = 0usize;

    loop {
        let bfinal = br.bits(1)?;
        let btype = br.bits(2)?;
        blocks += 1;
        match btype {
            0 => {
                br.align();
                let p = br.pos;
                if p + 4 > input.len() {
                    return Err("stored block header is truncated".to_string());
                }
                let len = ((input[p + 1] as usize) << 8) | input[p] as usize;
                let nlen = ((input[p + 3] as usize) << 8) | input[p + 2] as usize;
                if len != (!nlen & 0xFFFF) {
                    return Err(format!(
                        "stored block LEN {} and NLEN {} are not complements",
                        len, nlen
                    ));
                }
                if p + 4 + len > input.len() {
                    return Err("stored block runs past the input".to_string());
                }
                if out.len() + len > max_out {
                    return Err(format!("output exceeded the {}-byte ceiling", max_out));
                }
                out.extend_from_slice(&input[p + 4..p + 4 + len]);
                br.pos = p + 4 + len;
            }
            1 | 2 => {
                let (lit, dist) = if btype == 1 {
                    fixed_tables()
                } else {
                    let hlit = br.bits(5)? as usize + 257;
                    let hdist = br.bits(5)? as usize + 1;
                    let hclen = br.bits(4)? as usize + 4;
                    if hlit > 286 || hdist > 30 {
                        return Err(format!(
                            "dynamic block declares HLIT {} HDIST {}, limits are 286 and 30",
                            hlit, hdist
                        ));
                    }
                    let mut clen = [0u8; 19];
                    for i in 0..hclen {
                        clen[CLEN_ORDER[i]] = br.bits(3)? as u8;
                    }
                    let clh = build_huffman(&clen)
                        .map_err(|e| format!("code-length table: {}", e))?;
                    let mut lengths = vec![0u8; hlit + hdist];
                    let mut i = 0usize;
                    while i < lengths.len() {
                        let sym = br.decode(&clh)?;
                        match sym {
                            0..=15 => {
                                lengths[i] = sym as u8;
                                i += 1;
                            }
                            16 => {
                                if i == 0 {
                                    return Err("repeat code 16 with no previous length".to_string());
                                }
                                let prev = lengths[i - 1];
                                let n = 3 + br.bits(2)? as usize;
                                if i + n > lengths.len() {
                                    return Err("repeat code 16 overruns the length list".to_string());
                                }
                                for _ in 0..n {
                                    lengths[i] = prev;
                                    i += 1;
                                }
                            }
                            17 => {
                                let n = 3 + br.bits(3)? as usize;
                                if i + n > lengths.len() {
                                    return Err("repeat code 17 overruns the length list".to_string());
                                }
                                i += n;
                            }
                            18 => {
                                let n = 11 + br.bits(7)? as usize;
                                if i + n > lengths.len() {
                                    return Err("repeat code 18 overruns the length list".to_string());
                                }
                                i += n;
                            }
                            _ => return Err(format!("code-length symbol {} is undefined", sym)),
                        }
                    }
                    if lengths[256] == 0 {
                        return Err("dynamic block defines no end-of-block code".to_string());
                    }
                    let lit = build_huffman(&lengths[..hlit])
                        .map_err(|e| format!("literal/length table: {}", e))?;
                    let dist = build_huffman(&lengths[hlit..])
                        .map_err(|e| format!("distance table: {}", e))?;
                    (lit, dist)
                };

                loop {
                    let sym = br.decode(&lit)?;
                    if sym < 256 {
                        if out.len() + 1 > max_out {
                            return Err(format!("output exceeded the {}-byte ceiling", max_out));
                        }
                        out.push(sym as u8);
                    } else if sym == 256 {
                        break;
                    } else {
                        let li = sym as usize - 257;
                        if li >= LEN_BASE.len() {
                            return Err(format!("length symbol {} is undefined", sym));
                        }
                        let length =
                            LEN_BASE[li] as usize + br.bits(LEN_EXTRA[li] as u32)? as usize;
                        let dsym = br.decode(&dist)? as usize;
                        if dsym >= DIST_BASE.len() {
                            return Err(format!("distance symbol {} is undefined", dsym));
                        }
                        let d = DIST_BASE[dsym] as usize + br.bits(DIST_EXTRA[dsym] as u32)? as usize;
                        if d > out.len() {
                            return Err(format!(
                                "distance {} reaches {} bytes behind the start of output",
                                d,
                                d - out.len()
                            ));
                        }
                        if out.len() + length > max_out {
                            return Err(format!("output exceeded the {}-byte ceiling", max_out));
                        }
                        let start = out.len() - d;
                        for k in 0..length {
                            let b = out[start + k];
                            out.push(b);
                        }
                    }
                }
            }
            _ => return Err("BTYPE 11 is reserved and never legal".to_string()),
        }
        if bfinal == 1 {
            break;
        }
        if blocks > 1_000_000 {
            return Err("block count exceeded 1,000,000".to_string());
        }
    }

    Ok(Inflated { out, consumed: br.consumed(), blocks })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DYNAMIC_STREAM: &[u8] = &[
        0xED, 0xCC, 0x41, 0x0A, 0x80, 0x30, 0x0C, 0x04, 0xC0, 0xAF, 0xE4, 0x6B,
        0x25, 0xAE, 0x12, 0x4C, 0x5B, 0x48, 0x96, 0x82, 0xBE, 0xDE, 0x43, 0x5F,
        0x21, 0xE4, 0x38, 0x97, 0xC9, 0x36, 0x8C, 0xF6, 0x36, 0xDA, 0x1C, 0xB2,
        0x10, 0x76, 0x9A, 0x6E, 0x28, 0x82, 0x5B, 0x90, 0x8E, 0xB8, 0x1D, 0xE2,
        0x38, 0x2E, 0x84, 0x24, 0x94, 0x33, 0x84, 0x70, 0x74, 0x30, 0x1E, 0xC9,
        0x4A, 0x2A, 0xA9, 0xE4, 0xE7, 0xC9, 0x07,
    ];
    const DYNAMIC_TEXT: &str =
        "sanitization verification certificate merkle ledger sector telemetry ";

    const FIXED_STREAM: &[u8] = &[
        0x2B, 0x4E, 0xCD, 0x2B, 0xC9, 0xCC, 0x4B, 0xCD, 0x29, 0xCF, 0x2C, 0x48,
        0x55, 0x48, 0x4E, 0x2C, 0x2A, 0xCB, 0xCC, 0x4B, 0x57, 0x48, 0xCD, 0x4B,
        0x07, 0x8A, 0xE9, 0x28, 0xA4, 0x65, 0x56, 0xA4, 0xA6, 0x28, 0x64, 0x94,
        0xA6, 0xA5, 0xE5, 0x26, 0xE6, 0x29, 0x14, 0x24, 0x96, 0x64, 0x00, 0x00,
    ];
    const FIXED_TEXT: &str = "sentinelwipe carving engine, fixed huffman path";

    #[test]
    fn inflate_dynamic_huffman_block() {
        let expect = DYNAMIC_TEXT.repeat(15);
        let got = inflate(DYNAMIC_STREAM, MAX_INFLATE_BYTES).expect("dynamic block inflates");
        assert_eq!(got.out.len(), expect.len());
        assert_eq!(got.out, expect.as_bytes());
        assert_eq!(got.consumed, DYNAMIC_STREAM.len());
        assert_eq!(got.blocks, 1);
        assert_eq!(crc32(&got.out), 0x60A3_C119);
    }

    #[test]
    fn inflate_fixed_huffman_block() {
        let got = inflate(FIXED_STREAM, MAX_INFLATE_BYTES).expect("fixed block inflates");
        assert_eq!(got.out, FIXED_TEXT.as_bytes());
        assert_eq!(got.consumed, FIXED_STREAM.len());
        assert_eq!(crc32(&got.out), 0x9B00_D09A);
    }

    #[test]
    fn inflate_stored_block() {
        let s: Vec<u8> = [0x01u8, 0x05, 0x00, 0xFA, 0xFF]
            .iter()
            .copied()
            .chain(b"BLOCK".iter().copied())
            .collect();
        let got = inflate(&s, MAX_INFLATE_BYTES).expect("stored block inflates");
        assert_eq!(got.out, b"BLOCK");
        assert_eq!(got.consumed, s.len());
    }

    #[test]
    fn inflate_multiple_blocks() {
        let mut s: Vec<u8> = vec![0x00, 0x05, 0x00, 0xFA, 0xFF];
        s.extend_from_slice(b"BLOCK");
        s.extend_from_slice(FIXED_STREAM);
        let got = inflate(&s, MAX_INFLATE_BYTES).expect("two-block stream inflates");
        assert_eq!(got.blocks, 2);
        assert_eq!(got.out, format!("BLOCK{}", FIXED_TEXT).as_bytes());
        assert_eq!(got.consumed, s.len());
    }

    #[test]
    fn inflate_rejects_reserved_btype() {
        assert!(inflate(&[0x07, 0x00, 0x00, 0x00], 4096).is_err());
    }

    #[test]
    fn inflate_rejects_bad_stored_nlen() {
        let s: Vec<u8> = vec![0x01, 0x05, 0x00, 0x00, 0x00, b'A', b'B', b'C', b'D', b'E'];
        let e = inflate(&s, 4096).unwrap_err();
        assert!(e.contains("complements"), "error was: {}", e);
    }

    #[test]
    fn inflate_rejects_truncation() {
        let mut s = FIXED_STREAM.to_vec();
        s.truncate(20);
        assert!(inflate(&s, MAX_INFLATE_BYTES).is_err());
    }

    #[test]
    fn inflate_honours_the_output_ceiling() {
        let e = inflate(FIXED_STREAM, 8).unwrap_err();
        assert!(e.contains("ceiling"), "error was: {}", e);
    }

    #[test]
    fn inflate_rejects_arbitrary_bytes_and_never_panics() {
        let mut s: u32 = 0xC0FF_EE00;
        let mut accepted = 0;
        for trial in 0..500 {
            let mut d = Vec::new();
            for _ in 0..(24 + trial % 97) {
                s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
                d.push((s >> 16) as u8);
            }
            if inflate(&d, 1 << 20).is_ok() {
                accepted += 1;
            }
        }
        assert!(accepted < 60, "{} of 500 random streams inflated", accepted);
    }

    fn member(flg: u8, extra: &[u8], deflate: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1F, 0x8B, 0x08, flg, 0, 0, 0, 0, 0x00, 0xFF];
        v.extend_from_slice(extra);
        v.extend_from_slice(deflate);
        v.extend_from_slice(&crc32(payload).to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v
    }

    fn good_member() -> Vec<u8> {
        member(0x08, b"carve_session.log\0", FIXED_STREAM, FIXED_TEXT.as_bytes())
    }

    #[test]
    fn intact_member_is_valid_and_scores_one() {
        let m = good_member();
        let r = analyze(&m);
        assert!(r.validation.valid, "detail: {}", r.validation.detail);
        assert_eq!(r.validation.end, Some(m.len() as u64));
        assert!((r.validation.score - 1.0).abs() < 1e-12, "score {}", r.validation.score);
        assert_eq!(r.inner_name.as_deref(), Some("carve_session.log"));
        assert_eq!(r.inflated_bytes, FIXED_TEXT.len() as u64);
        assert_eq!(r.header_bytes, 10 + 18);
        assert_eq!(r.deflate_bytes, FIXED_STREAM.len());
    }

    #[test]
    fn end_stops_at_the_trailer_not_at_the_slice_end() {
        let mut m = good_member();
        let n = m.len();
        m.extend(std::iter::repeat(0x77u8).take(5000));
        let v = validate(&m);
        assert!(v.valid);
        assert_eq!(v.end, Some(n as u64));
    }

    #[test]
    fn term_header_fields_falls_on_reserved_flag_bits() {
        let mut m = good_member();
        m[3] |= 0x40;
        let r = analyze(&m);
        assert_eq!(r.rubric.header_fields, 0.0);
        assert_eq!(r.validation.score, 0.0);
        assert!(!r.validation.valid);
        assert!(r.validation.detail.contains("reserved bits 5-7"), "detail: {}", r.validation.detail);
    }

    #[test]
    fn term_header_fields_falls_on_a_non_deflate_cm() {
        let mut m = good_member();
        m[2] = 7;
        let r = analyze(&m);
        assert_eq!(r.rubric.header_fields, 0.0);
        assert!(r.validation.detail.contains("CM is 7"), "detail: {}", r.validation.detail);
    }

    #[test]
    fn term_optional_fields_falls_on_a_control_character_in_fname() {
        let m = member(0x08, b"bad\x01name\0", FIXED_STREAM, FIXED_TEXT.as_bytes());
        let r = analyze(&m);
        assert_eq!(r.rubric.optional_fields, 0.0);
        assert!((r.validation.score - (1.0 - W_OPTIONAL)).abs() < 1e-12,
                "only optional_fields should move, got {}", r.validation.score);
        assert!(r.validation.valid, "an odd FNAME grades; the data still checks out");
    }

    #[test]
    fn term_optional_fields_holds_for_a_correct_fhcrc() {
        let mut head: Vec<u8> = vec![0x1F, 0x8B, 0x08, 0x08 | 0x02, 0, 0, 0, 0, 0x00, 0xFF];
        head.extend_from_slice(b"n\0");
        let c = (crc32(&head) & 0xFFFF) as u16;
        head.extend_from_slice(&c.to_le_bytes());
        let mut m = head;
        m.extend_from_slice(FIXED_STREAM);
        m.extend_from_slice(&crc32(FIXED_TEXT.as_bytes()).to_le_bytes());
        m.extend_from_slice(&(FIXED_TEXT.len() as u32).to_le_bytes());
        let r = analyze(&m);
        assert_eq!(r.rubric.optional_fields, W_OPTIONAL);
        assert!(r.validation.valid, "detail: {}", r.validation.detail);
        assert!((r.validation.score - 1.0).abs() < 1e-12);
    }

    #[test]
    fn term_optional_fields_falls_on_a_wrong_fhcrc() {
        let mut head: Vec<u8> = vec![0x1F, 0x8B, 0x08, 0x08 | 0x02, 0, 0, 0, 0, 0x00, 0xFF];
        head.extend_from_slice(b"n\0");
        head.extend_from_slice(&[0xAA, 0xBB]);
        let mut m = head;
        m.extend_from_slice(FIXED_STREAM);
        m.extend_from_slice(&crc32(FIXED_TEXT.as_bytes()).to_le_bytes());
        m.extend_from_slice(&(FIXED_TEXT.len() as u32).to_le_bytes());
        let r = analyze(&m);
        assert_eq!(r.rubric.optional_fields, 0.0);
        assert!(r.validation.valid);
    }

    #[test]
    fn term_inflate_falls_on_a_clean_header_over_noise() {
        let mut s: u32 = 0xA5A5_1234;
        let mut m: Vec<u8> = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
        for _ in 0..512 {
            s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
            m.push((s >> 16) as u8);
        }
        let r = analyze(&m);
        assert_eq!(r.rubric.header_fields, W_HEADER, "the header is genuinely clean");
        assert_eq!(r.rubric.inflate, 0.0);
        assert_eq!(r.rubric.crc_match, 0.0);
        assert_eq!(r.rubric.isize_match, 0.0);
        assert!(!r.validation.valid);
        assert!(r.validation.detail.contains("DEFLATE stream failed"),
                "detail: {}", r.validation.detail);
    }

    #[test]
    fn term_crc_match_falls_on_a_wrong_trailer_crc() {
        let mut m = good_member();
        let n = m.len();
        m[n - 8] ^= 0xFF;
        let r = analyze(&m);
        assert_eq!(r.rubric.inflate, W_INFLATE);
        assert_eq!(r.rubric.crc_match, 0.0);
        assert_eq!(r.rubric.isize_match, W_ISIZE);
        assert!((r.validation.score - (1.0 - W_CRC)).abs() < 1e-12,
                "only crc_match should move, got {}", r.validation.score);
        assert!(!r.validation.valid);
        assert_eq!(r.validation.end, Some(n as u64), "end is still known");
    }

    #[test]
    fn term_isize_match_falls_on_a_wrong_trailer_length() {
        let mut m = good_member();
        let n = m.len();
        m[n - 4] = m[n - 4].wrapping_add(1);
        let r = analyze(&m);
        assert_eq!(r.rubric.crc_match, W_CRC);
        assert_eq!(r.rubric.isize_match, 0.0);
        assert!((r.validation.score - (1.0 - W_ISIZE)).abs() < 1e-12,
                "only isize_match should move, got {}", r.validation.score);
        assert!(!r.validation.valid);
    }

    #[test]
    fn weights_sum_to_one() {
        let s = W_HEADER + W_OPTIONAL + W_INFLATE + W_CRC + W_ISIZE;
        assert!((s - 1.0).abs() < 1e-12, "rubric weights sum to {}", s);
    }

    #[test]
    fn rejects_bare_signature() {
        let v = validate(&[0x1F, 0x8B, 0x08]);
        assert!(!v.valid);
        assert_eq!(v.end, None);
    }

    #[test]
    fn rejects_truncated_trailer() {
        let mut m = good_member();
        m.truncate(m.len() - 3);
        let v = validate(&m);
        assert!(!v.valid);
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let mut s: u32 = 0x5EED_5EED;
        for trial in 0..300 {
            let mut d = vec![0x1F, 0x8B, 0x08];
            for _ in 0..(32 + trial % 211) {
                s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
                d.push((s >> 16) as u8);
            }
            let _ = validate(&d);
        }
    }
}
