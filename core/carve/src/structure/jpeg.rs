//! JPEG structure validation: walk the segment chain from SOI to EOI.
//!
//! Garfinkel, "Carving contiguous and fragmented files with fast object
//! validation", DFRWS 2007. JPEG is the paper's motivating case and it is this
//! fixture's too: `FF D8 FF` is a three-byte signature, and three bytes occur
//! by chance about eight times in 134 MB of uniform residue. The measured count
//! on `out/fixture.img` is exactly 8, published in the manifest as
//! `residue_signature_false_positives.JPEG`. Every one of those eight is
//! rejected here, and two of them are rejected only because the walk keeps
//! going: they carry a genuine APP marker (APP6 and APP13) immediately after
//! the SOI, so a validator that checked "is byte 3 a legal marker" would pass
//! them. What kills them is honouring the segment length and finding no marker
//! where the chain says the next one must be.
//!
//! ## The walk
//!
//! ISO/IEC 10918-1 Annex B. After SOI (FF D8) the file is a chain of marker
//! segments. Standalone markers (TEM, RST0-7, SOI, EOI) are two bytes. Every
//! other marker is followed by a big-endian 16-bit length that INCLUDES the two
//! length bytes but not the two marker bytes, so the next marker sits at
//! `pos + 2 + length`. The chain runs through DQT / DHT / SOF / APPn / COM to
//! SOS, after which the bytes are entropy-coded and no longer self-delimiting:
//! the only way out is to scan for FF, understanding that FF 00 is a stuffed
//! literal FF (Annex B.1.1.5) and FF D0..D7 are restart markers. FF D9 is EOI
//! and is where `end` comes from.
//!
//! ## RUBRIC -- how `score` is derived
//!
//! Seven independent checks, fixed weights, summing to exactly 1.00. Each is a
//! byte comparison and each has its own unit test that takes an intact JPEG and
//! breaks that one check.
//!
//!   0.20  chain_integrity     every marker recognised, every length in bounds
//!                             and consumed exactly by its own payload parser,
//!                             no FF fill padding
//!   0.15  quant_tables        fraction of SOF components whose Tq names a
//!                             quantisation table an earlier DQT actually
//!                             defined
//!   0.15  huffman_tables      fraction of the SOS components' Td/Ta selectors
//!                             that name a Huffman table an earlier DHT defined
//!   0.15  frame_sanity        SOF length exact, precision 8/12/16, dimensions
//!                             1..=65535, 1..=4 components, sampling factors
//!                             1..=4, Tq <= 3
//!   0.15  scan_header_sanity  SOS length exact, Ns 1..=4 and <= Nf, every Cs
//!                             resolves to a SOF component, Ss/Se/Ah/Al legal
//!                             for the frame's coding mode
//!   0.10  restart_consistency an entropy-coded scan was reached, its restart
//!                             markers appear in cyclic RST0..RST7 order, and
//!                             they appear at all only if a DRI segment
//!                             declared a non-zero interval
//!   0.10  app_identification  an APP0 'JFIF\0'/'JFXX\0' or APP1 'Exif\0\0'
//!                             identifier is present
//!
//! An intact baseline JPEG scores 1.00. The rubric is not a repackaged boolean:
//! `quant_tables` and `huffman_tables` are fractions, and the other five fail
//! independently of validity -- a JPEG can reach EOI, be `valid`, and still
//! score 0.85 because it references a Huffman table no DHT ever defined.
//!
//! ## VALIDITY GATE -- separate from the score
//!
//! `valid` requires all of: SOI at offset 0; the segment chain reached SOS
//! without an unrecognised marker or an out-of-bounds length; a SOF was seen
//! with an exact length and sane fields; the SOS header is exact and every one
//! of its components resolves to a SOF component; and the entropy-coded scan
//! terminated at EOI with only legal FF sequences inside it. Table-reference
//! completeness (score terms 2 and 3) grades but does not gate, because a
//! recovered object with a missing table is still a recovered object and the
//! operator should see it with a lower number rather than not see it.

use super::{be_u16, clamp01, Validation};

/// Longest JPEG this carver will accept. A carving bound, not a format limit:
/// the largest planted object in `out/fixture.img` is 260,595 bytes, and an
/// unbounded entropy scan over a 256 MB image is a denial of service against
/// the bifragment search that calls this thousands of times.
pub const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;

/// A real JPEG carries about a dozen marker segments. The cap exists so a
/// residue candidate whose length fields happen to chain cannot walk the whole
/// image one segment at a time.
pub const MAX_SEGMENTS: usize = 1024;

const W_CHAIN: f64 = 0.20;
const W_QUANT: f64 = 0.15;
const W_HUFF: f64 = 0.15;
const W_FRAME: f64 = 0.15;
const W_SCAN: f64 = 0.15;
const W_RESTART: f64 = 0.10;
const W_APP: f64 = 0.10;

/// The seven rubric terms, each already multiplied by its weight, so
/// `total()` is their sum and each one is separately reportable.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct JpegRubric {
    pub chain_integrity: f64,
    pub quant_tables: f64,
    pub huffman_tables: f64,
    pub frame_sanity: f64,
    pub scan_header_sanity: f64,
    pub restart_consistency: f64,
    pub app_identification: f64,
}

impl JpegRubric {
    pub fn total(&self) -> f64 {
        clamp01(
            self.chain_integrity
                + self.quant_tables
                + self.huffman_tables
                + self.frame_sanity
                + self.scan_header_sanity
                + self.restart_consistency
                + self.app_identification,
        )
    }
}

/// Everything the walk learned. `validate` throws all but the `Validation`
/// away; the tests and the report writer want the rest.
#[derive(Debug, Clone)]
pub struct JpegReport {
    pub validation: Validation,
    pub rubric: JpegRubric,
    /// SOF marker byte, e.g. 0xC0 for baseline sequential.
    pub sof_marker: Option<u8>,
    pub width: u16,
    pub height: u16,
    pub components: usize,
    /// Marker segments walked before SOS.
    pub segments: usize,
    /// Bytes of entropy-coded data between the SOS header and EOI.
    pub entropy_bytes: u64,
    pub restart_markers: u64,
}

/// `data` starts AT the SOI. See `structure/mod.rs` for the input convention.
pub fn validate(data: &[u8]) -> Validation {
    analyze(data).validation
}

#[inline]
fn is_sof(m: u8) -> bool {
    // C0..CF are the frame markers, minus DHT (C4), the reserved JPG (C8) and
    // DAC (CC). C0/C1 sequential, C2/C3 progressive and lossless, C5..C7 and
    // C9..CF the differential and arithmetic variants.
    matches!(m, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF)
}

#[inline]
fn has_length(m: u8) -> bool {
    // Annex B.1.1.3: everything except the standalone markers carries a
    // two-byte length. 0x00 is byte stuffing, 0x02..=0xBF are reserved and
    // 0xFF is fill, so none of them reach here as a segment marker.
    matches!(m, 0xC0..=0xCF | 0xDA..=0xDF | 0xE0..=0xEF | 0xF0..=0xFE)
}

pub fn analyze(data: &[u8]) -> JpegReport {
    let mut r = JpegReport {
        validation: Validation::reject("jpeg: not evaluated"),
        rubric: JpegRubric::default(),
        sof_marker: None,
        width: 0,
        height: 0,
        components: 0,
        segments: 0,
        entropy_bytes: 0,
        restart_markers: 0,
    };

    if data.len() < 4 {
        r.validation = Validation::reject(format!(
            "jpeg: {} bytes available, SOI plus one marker needs 4",
            data.len()
        ));
        return r;
    }
    if data[0] != 0xFF || data[1] != 0xD8 {
        r.validation = Validation::reject(format!(
            "jpeg: no SOI at offset 0, found {:02X} {:02X}",
            data[0], data[1]
        ));
        return r;
    }

    let limit = data.len().min(MAX_OBJECT_BYTES);

    // Rubric accumulators.
    let mut chain_clean = true;
    let mut frame_sane = false;
    let mut scan_sane = false;
    let mut app_ident = false;

    // Tables the chain has actually defined.
    let mut dqt_defined = [false; 4];
    let mut dc_defined = [false; 4];
    let mut ac_defined = [false; 4];

    // SOF state.
    let mut sof_seen = false;
    let mut sof_progressive = false;
    // (component id, Tq)
    let mut sof_comps: Vec<(u8, u8)> = Vec::new();

    let mut restart_interval: u16 = 0;
    let mut quant_resolved: Option<f64> = None;
    let mut huff_resolved: Option<f64> = None;

    let mut pos = 2usize;
    let mut sos_at: Option<usize> = None;
    let mut fail: Option<String> = None;

    while pos + 1 < limit {
        if data[pos] != 0xFF {
            fail = Some(format!(
                "jpeg: expected a marker at offset {}, found {:02X}",
                pos, data[pos]
            ));
            chain_clean = false;
            break;
        }
        // Annex B.1.1.2 allows any number of FF fill bytes before a marker.
        // Legal, but our encoder emits none, so it costs chain_integrity.
        let mut m_at = pos + 1;
        let mut filled = false;
        while m_at < limit && data[m_at] == 0xFF {
            m_at += 1;
            filled = true;
        }
        if filled {
            chain_clean = false;
        }
        if m_at >= limit {
            fail = Some(format!("jpeg: FF fill runs off the end at offset {}", pos));
            chain_clean = false;
            break;
        }
        let marker = data[m_at];

        if marker == 0xD9 {
            fail = Some(format!("jpeg: EOI at offset {} before any SOS", m_at - 1));
            break;
        }
        if marker == 0x01 || (0xD0..=0xD8).contains(&marker) {
            // TEM, RST0-7 or a second SOI outside a scan. Legal bytes, wrong
            // place; the chain is still walkable so keep going.
            chain_clean = false;
            pos = m_at + 1;
            r.segments += 1;
            continue;
        }
        if !has_length(marker) {
            fail = Some(format!(
                "jpeg: reserved marker FF{:02X} at offset {}, chain broken",
                marker,
                m_at - 1
            ));
            chain_clean = false;
            break;
        }

        let len = match be_u16(data, m_at + 1) {
            Some(l) => l as usize,
            None => {
                fail = Some(format!("jpeg: length field at offset {} is truncated", m_at + 1));
                chain_clean = false;
                break;
            }
        };
        if len < 2 {
            fail = Some(format!(
                "jpeg: FF{:02X} at offset {} declares length {}, minimum is 2",
                marker,
                m_at - 1,
                len
            ));
            chain_clean = false;
            break;
        }
        let payload_at = m_at + 3;
        let seg_end = m_at + 1 + len;
        if seg_end > limit {
            fail = Some(format!(
                "jpeg: FF{:02X} at offset {} declares length {} which runs past the {} bytes available",
                marker,
                m_at - 1,
                len,
                limit
            ));
            chain_clean = false;
            break;
        }
        let payload = &data[payload_at..seg_end];
        r.segments += 1;
        if r.segments > MAX_SEGMENTS {
            fail = Some(format!("jpeg: segment chain exceeded {} segments", MAX_SEGMENTS));
            chain_clean = false;
            break;
        }

        match marker {
            0xDB => {
                // DQT, Annex B.2.4.1. Payload is a run of (Pq<<4|Tq) headers
                // each followed by 64 or 128 table bytes, consuming the
                // payload exactly.
                let mut i = 0usize;
                let mut ok = true;
                while i < payload.len() {
                    let pq = payload[i] >> 4;
                    let tq = payload[i] & 0x0F;
                    if pq > 1 || tq > 3 {
                        ok = false;
                        break;
                    }
                    let n = if pq == 0 { 64 } else { 128 };
                    if i + 1 + n > payload.len() {
                        ok = false;
                        break;
                    }
                    dqt_defined[tq as usize] = true;
                    i += 1 + n;
                }
                if !ok || i != payload.len() {
                    chain_clean = false;
                }
            }
            0xC4 => {
                // DHT, Annex B.2.4.2. (Tc<<4|Th), 16 length counts, then that
                // many symbol values.
                let mut i = 0usize;
                let mut ok = true;
                while i < payload.len() {
                    if i + 17 > payload.len() {
                        ok = false;
                        break;
                    }
                    let tc = payload[i] >> 4;
                    let th = payload[i] & 0x0F;
                    if tc > 1 || th > 3 {
                        ok = false;
                        break;
                    }
                    let total: usize = payload[i + 1..i + 17].iter().map(|&b| b as usize).sum();
                    if total > 256 || i + 17 + total > payload.len() {
                        ok = false;
                        break;
                    }
                    if tc == 0 {
                        dc_defined[th as usize] = true;
                    } else {
                        ac_defined[th as usize] = true;
                    }
                    i += 17 + total;
                }
                if !ok || i != payload.len() {
                    chain_clean = false;
                }
            }
            0xDD => {
                // DRI, Annex B.2.4.4.
                if payload.len() == 2 {
                    restart_interval = ((payload[0] as u16) << 8) | payload[1] as u16;
                } else {
                    chain_clean = false;
                }
            }
            0xE0 | 0xE1 => {
                if marker == 0xE0 && (payload.starts_with(b"JFIF\0") || payload.starts_with(b"JFXX\0"))
                {
                    app_ident = true;
                }
                if marker == 0xE1 && payload.starts_with(b"Exif\0\0") {
                    app_ident = true;
                }
            }
            m if is_sof(m) => {
                // SOF, Annex B.2.2. P, Y, X, Nf, then Nf x (Ci, Hi<<4|Vi, Tq).
                if payload.len() < 6 {
                    chain_clean = false;
                } else {
                    let precision = payload[0];
                    let height = ((payload[1] as u16) << 8) | payload[2] as u16;
                    let width = ((payload[3] as u16) << 8) | payload[4] as u16;
                    let nf = payload[5] as usize;
                    let exact = payload.len() == 6 + 3 * nf;
                    let mut comps_ok = exact && (1..=4).contains(&nf);
                    let mut comps: Vec<(u8, u8)> = Vec::new();
                    if exact {
                        for c in 0..nf {
                            let ci = payload[6 + 3 * c];
                            let hv = payload[7 + 3 * c];
                            let tq = payload[8 + 3 * c];
                            let h = hv >> 4;
                            let v = hv & 0x0F;
                            if !(1..=4).contains(&h) || !(1..=4).contains(&v) || tq > 3 {
                                comps_ok = false;
                            }
                            comps.push((ci, tq));
                        }
                    } else {
                        chain_clean = false;
                    }
                    let dims_ok = height >= 1 && width >= 1;
                    let prec_ok = matches!(precision, 8 | 12 | 16);
                    if !sof_seen {
                        sof_seen = true;
                        sof_progressive = matches!(m, 0xC2 | 0xC6 | 0xCA | 0xCE);
                        r.sof_marker = Some(m);
                        r.width = width;
                        r.height = height;
                        r.components = comps.len();
                        sof_comps = comps;
                        frame_sane = comps_ok && dims_ok && prec_ok;
                        // How many of the frame's components name a
                        // quantisation table that a DQT actually defined.
                        let n = sof_comps.len();
                        quant_resolved = Some(if n == 0 {
                            0.0
                        } else {
                            sof_comps
                                .iter()
                                .filter(|(_, tq)| (*tq as usize) < 4 && dqt_defined[*tq as usize])
                                .count() as f64
                                / n as f64
                        });
                    } else {
                        // A second frame header before any scan is a
                        // hierarchical-mode shape we do not carve.
                        chain_clean = false;
                    }
                }
            }
            0xDA => {
                // SOS, Annex B.2.3. Ns, Ns x (Cs, Td<<4|Ta), Ss, Se, Ah<<4|Al.
                sos_at = Some(seg_end);
                if payload.len() < 4 {
                    scan_sane = false;
                    chain_clean = false;
                } else {
                    let ns = payload[0] as usize;
                    let exact = payload.len() == 4 + 2 * ns;
                    if !exact {
                        chain_clean = false;
                    }
                    let mut ok = exact && (1..=4).contains(&ns);
                    let mut resolved = 0usize;
                    if exact {
                        for c in 0..ns {
                            let cs = payload[1 + 2 * c];
                            let tdta = payload[2 + 2 * c];
                            let td = (tdta >> 4) as usize;
                            let ta = (tdta & 0x0F) as usize;
                            if !sof_comps.iter().any(|(id, _)| *id == cs) {
                                ok = false;
                            }
                            if td > 3 || ta > 3 {
                                ok = false;
                            } else {
                                if dc_defined[td] {
                                    resolved += 1;
                                }
                                // A progressive AC-only or DC-only scan may
                                // legitimately not use the AC table; grading,
                                // not gating, so count it plainly.
                                if ac_defined[ta] {
                                    resolved += 1;
                                }
                            }
                        }
                        let ss = payload[1 + 2 * ns];
                        let se = payload[2 + 2 * ns];
                        let ahal = payload[3 + 2 * ns];
                        let ah = ahal >> 4;
                        let al = ahal & 0x0F;
                        if sof_progressive {
                            if ss > 63 || se > 63 || (ss > 0 && se < ss) || ah > 13 || al > 13 {
                                ok = false;
                            }
                        } else if ss != 0 || se != 63 || ah != 0 || al != 0 {
                            // Baseline and extended sequential fix the
                            // spectral selection to the whole block.
                            ok = false;
                        }
                        if ns > sof_comps.len() {
                            ok = false;
                        }
                        huff_resolved =
                            Some(if ns == 0 { 0.0 } else { resolved as f64 / (2 * ns) as f64 });
                    }
                    scan_sane = ok;
                }
                break;
            }
            _ => {}
        }

        pos = seg_end;
    }

    // ---- entropy-coded scan ------------------------------------------------
    let mut eoi_at: Option<usize> = None;
    let mut scan_clean = true;
    let mut rst_expect: u8 = 0;
    let mut rst_ordered = true;
    if let Some(scan_start) = sos_at {
        let mut i = scan_start;
        while i + 1 < limit {
            if data[i] != 0xFF {
                i += 1;
                continue;
            }
            let b = data[i + 1];
            match b {
                0x00 => i += 2,          // stuffed literal FF, Annex B.1.1.5
                0xFF => i += 1,          // fill byte
                0xD9 => {
                    eoi_at = Some(i + 2);
                    break;
                }
                0xD0..=0xD7 => {
                    r.restart_markers += 1;
                    if b - 0xD0 != rst_expect {
                        rst_ordered = false;
                    }
                    rst_expect = (rst_expect + 1) % 8;
                    i += 2;
                }
                0x01 => i += 2,          // TEM
                m if has_length(m) => {
                    // A further marker segment inside the entropy stream is a
                    // progressive multi-scan shape. Our corpus is baseline, so
                    // seeing one here is an anomaly the scan reports rather
                    // than a fatal error.
                    scan_clean = false;
                    let len = match be_u16(data, i + 2) {
                        Some(l) => l as usize,
                        None => break,
                    };
                    if len < 2 || i + 2 + len > limit {
                        break;
                    }
                    i = i + 2 + len;
                }
                _ => {
                    scan_clean = false;
                    if fail.is_none() {
                        fail = Some(format!(
                            "jpeg: illegal sequence FF{:02X} at offset {} inside the entropy-coded scan",
                            b, i
                        ));
                    }
                    break;
                }
            }
        }
        if eoi_at.is_none() && fail.is_none() {
            fail = Some(format!(
                "jpeg: entropy-coded scan from offset {} reached the end of the {} bytes available without an EOI",
                scan_start, limit
            ));
        }
        if let Some(e) = eoi_at {
            r.entropy_bytes = (e - 2 - scan_start) as u64;
        }
    } else if fail.is_none() {
        fail = Some("jpeg: segment chain ended without an SOS".to_string());
    }

    // ---- rubric ------------------------------------------------------------
    // Earned only if an entropy-coded scan was actually reached. A candidate
    // whose chain broke at the second byte never had restart markers to be
    // inconsistent about, and awarding it the term would put a non-zero score
    // on residue that failed every check it was given.
    let restart_ok =
        sos_at.is_some() && rst_ordered && (restart_interval != 0 || r.restart_markers == 0);
    r.rubric = JpegRubric {
        chain_integrity: if chain_clean && scan_clean { W_CHAIN } else { 0.0 },
        quant_tables: W_QUANT * quant_resolved.unwrap_or(0.0),
        huffman_tables: W_HUFF * huff_resolved.unwrap_or(0.0),
        frame_sanity: if frame_sane { W_FRAME } else { 0.0 },
        scan_header_sanity: if scan_sane { W_SCAN } else { 0.0 },
        restart_consistency: if restart_ok { W_RESTART } else { 0.0 },
        app_identification: if app_ident { W_APP } else { 0.0 },
    };
    let score = r.rubric.total();

    // ---- validity gate -----------------------------------------------------
    let gate = sof_seen && frame_sane && scan_sane && eoi_at.is_some() && fail.is_none();
    r.validation = match (gate, eoi_at) {
        (true, Some(e)) => Validation::accept(
            e as u64,
            score,
            format!(
                "jpeg: SOI..EOI over {} bytes, {} segments, SOF{} {}x{} {}c, {} entropy bytes, {} restart markers",
                e,
                r.segments,
                r.sof_marker.map(|m| (m & 0x0F).to_string()).unwrap_or_else(|| "?".into()),
                r.width,
                r.height,
                r.components,
                r.entropy_bytes,
                r.restart_markers
            ),
        ),
        (false, Some(e)) => Validation::reject_with_end(
            e as u64,
            score,
            fail.unwrap_or_else(|| {
                "jpeg: reached EOI but the frame or scan header failed its sanity check".to_string()
            }),
        ),
        (_, None) => {
            let mut v = Validation::reject(
                fail.unwrap_or_else(|| "jpeg: no EOI found".to_string()),
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

    // ---- a minimal but genuinely well-formed baseline JPEG -----------------
    //
    // Built here rather than loaded, so a test that breaks one rubric term can
    // break exactly that term and nothing else. The entropy-coded payload is
    // not decodable image data and does not need to be: no validator in any
    // carver decodes the scan, and this module documents that it does not.

    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, marker];
        let l = (payload.len() + 2) as u16;
        v.push((l >> 8) as u8);
        v.push((l & 0xFF) as u8);
        v.extend_from_slice(payload);
        v
    }

    fn dqt(tq: u8) -> Vec<u8> {
        let mut p = vec![tq & 0x0F];
        p.extend(std::iter::repeat(16u8).take(64));
        seg(0xDB, &p)
    }

    fn dht(tc: u8, th: u8) -> Vec<u8> {
        // One code of length 2, one symbol. BITS sums to 1, so the payload is
        // 1 + 16 + 1 bytes.
        let mut p = vec![(tc << 4) | th];
        let mut bits = [0u8; 16];
        bits[1] = 1;
        p.extend_from_slice(&bits);
        p.push(0x00);
        seg(0xC4, &p)
    }

    fn good_jpeg() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE0, b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00"));
        v.extend(dqt(0));
        v.extend(dqt(1));
        // SOF0: P=8, Y=16, X=16, Nf=3
        v.extend(seg(
            0xC0,
            &[8, 0, 16, 0, 16, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1],
        ));
        v.extend(dht(0, 0));
        v.extend(dht(1, 0));
        v.extend(dht(0, 1));
        v.extend(dht(1, 1));
        // SOS: Ns=3, (1,00) (2,11) (3,11), Ss=0 Se=63 AhAl=0
        v.extend(seg(0xDA, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]));
        // entropy-coded data with one stuffed FF
        v.extend_from_slice(&[0xAB, 0xCD, 0xFF, 0x00, 0x12, 0x34]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    #[test]
    fn intact_jpeg_is_valid_and_scores_one() {
        let j = good_jpeg();
        let r = analyze(&j);
        assert!(r.validation.valid, "detail: {}", r.validation.detail);
        assert_eq!(r.validation.end, Some(j.len() as u64));
        assert!((r.validation.score - 1.0).abs() < 1e-12, "score {}", r.validation.score);
        assert_eq!(r.width, 16);
        assert_eq!(r.height, 16);
        assert_eq!(r.components, 3);
        assert_eq!(r.entropy_bytes, 6);
    }

    #[test]
    fn end_is_reported_even_with_trailing_bytes() {
        let mut j = good_jpeg();
        let n = j.len();
        j.extend(std::iter::repeat(0x5Au8).take(4096));
        let v = validate(&j);
        assert!(v.valid);
        assert_eq!(v.end, Some(n as u64), "end must stop at EOI, not at the slice end");
    }

    // ---- one test per rubric term -----------------------------------------

    #[test]
    fn term_chain_integrity_falls_on_ff_fill() {
        let mut j = good_jpeg();
        // Insert one legal-but-unusual FF fill byte before the APP0 marker.
        j.splice(2..2, [0xFFu8]);
        let r = analyze(&j);
        assert_eq!(r.rubric.chain_integrity, 0.0);
        assert!((r.validation.score - (1.0 - W_CHAIN)).abs() < 1e-12,
                "only chain_integrity should move, got {}", r.validation.score);
        assert!(r.validation.valid, "fill bytes are legal; validity must not move");
    }

    #[test]
    fn term_quant_tables_is_a_fraction() {
        // Drop the chroma DQT (Tq=1). Two of three SOF components name it.
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE0, b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00"));
        v.extend(dqt(0));
        v.extend(seg(0xC0, &[8, 0, 16, 0, 16, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]));
        v.extend(dht(0, 0));
        v.extend(dht(1, 0));
        v.extend(dht(0, 1));
        v.extend(dht(1, 1));
        v.extend(seg(0xDA, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]));
        v.extend_from_slice(&[0xAB, 0xCD, 0xFF, 0xD9]);
        let r = analyze(&v);
        assert!((r.rubric.quant_tables - W_QUANT * (1.0 / 3.0)).abs() < 1e-12,
                "quant_tables {}", r.rubric.quant_tables);
        assert!(r.validation.valid, "a missing table grades, it does not gate");
    }

    #[test]
    fn term_huffman_tables_is_a_fraction() {
        // Drop both chroma Huffman tables (Td/Ta = 1). Components 2 and 3 use
        // them, so 2 of 6 selectors resolve.
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE0, b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00"));
        v.extend(dqt(0));
        v.extend(dqt(1));
        v.extend(seg(0xC0, &[8, 0, 16, 0, 16, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]));
        v.extend(dht(0, 0));
        v.extend(dht(1, 0));
        v.extend(seg(0xDA, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]));
        v.extend_from_slice(&[0xAB, 0xCD, 0xFF, 0xD9]);
        let r = analyze(&v);
        assert!((r.rubric.huffman_tables - W_HUFF * (2.0 / 6.0)).abs() < 1e-12,
                "huffman_tables {}", r.rubric.huffman_tables);
    }

    #[test]
    fn term_frame_sanity_falls_on_zero_width() {
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE0, b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00"));
        v.extend(dqt(0));
        v.extend(dqt(1));
        v.extend(seg(0xC0, &[8, 0, 16, 0, 0, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]));
        v.extend(dht(0, 0));
        v.extend(dht(1, 0));
        v.extend(dht(0, 1));
        v.extend(dht(1, 1));
        v.extend(seg(0xDA, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]));
        v.extend_from_slice(&[0xAB, 0xCD, 0xFF, 0xD9]);
        let r = analyze(&v);
        assert_eq!(r.rubric.frame_sanity, 0.0);
        assert!(!r.validation.valid, "a zero-width frame must not pass the gate");
        assert_eq!(r.validation.end, Some(v.len() as u64), "end is still known");
    }

    #[test]
    fn term_scan_header_sanity_falls_on_unknown_component() {
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE0, b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00"));
        v.extend(dqt(0));
        v.extend(dqt(1));
        v.extend(seg(0xC0, &[8, 0, 16, 0, 16, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]));
        v.extend(dht(0, 0));
        v.extend(dht(1, 0));
        v.extend(dht(0, 1));
        v.extend(dht(1, 1));
        // Cs = 9 names no component in the frame.
        v.extend(seg(0xDA, &[3, 9, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]));
        v.extend_from_slice(&[0xAB, 0xCD, 0xFF, 0xD9]);
        let r = analyze(&v);
        assert_eq!(r.rubric.scan_header_sanity, 0.0);
        assert!(!r.validation.valid);
    }

    #[test]
    fn term_restart_consistency_falls_on_rst_without_dri() {
        let mut j = good_jpeg();
        let n = j.len();
        // Put an RST0 inside the scan without a DRI segment having declared one.
        j.splice(n - 2..n - 2, [0xFFu8, 0xD0]);
        let r = analyze(&j);
        assert_eq!(r.restart_markers, 1);
        assert_eq!(r.rubric.restart_consistency, 0.0);
        assert!((r.validation.score - (1.0 - W_RESTART)).abs() < 1e-12,
                "only restart_consistency should move, got {}", r.validation.score);
        assert!(r.validation.valid);
    }

    #[test]
    fn term_restart_consistency_holds_with_dri_and_cyclic_order() {
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE0, b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00"));
        v.extend(dqt(0));
        v.extend(dqt(1));
        v.extend(seg(0xDD, &[0x00, 0x04])); // DRI, interval 4
        v.extend(seg(0xC0, &[8, 0, 16, 0, 16, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]));
        v.extend(dht(0, 0));
        v.extend(dht(1, 0));
        v.extend(dht(0, 1));
        v.extend(dht(1, 1));
        v.extend(seg(0xDA, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]));
        v.extend_from_slice(&[0x11, 0xFF, 0xD0, 0x22, 0xFF, 0xD1, 0x33, 0xFF, 0xD9]);
        let r = analyze(&v);
        assert_eq!(r.restart_markers, 2);
        assert!((r.rubric.restart_consistency - W_RESTART).abs() < 1e-12);
        assert!(r.validation.valid, "detail: {}", r.validation.detail);
    }

    #[test]
    fn term_restart_consistency_falls_on_out_of_order_rst() {
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE0, b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00"));
        v.extend(dqt(0));
        v.extend(dqt(1));
        v.extend(seg(0xDD, &[0x00, 0x04]));
        v.extend(seg(0xC0, &[8, 0, 16, 0, 16, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]));
        v.extend(dht(0, 0));
        v.extend(dht(1, 0));
        v.extend(dht(0, 1));
        v.extend(dht(1, 1));
        v.extend(seg(0xDA, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]));
        v.extend_from_slice(&[0x11, 0xFF, 0xD0, 0x22, 0xFF, 0xD5, 0x33, 0xFF, 0xD9]);
        let r = analyze(&v);
        assert_eq!(r.rubric.restart_consistency, 0.0);
    }

    #[test]
    fn term_app_identification_falls_without_jfif() {
        let mut v = vec![0xFF, 0xD8];
        v.extend(dqt(0));
        v.extend(dqt(1));
        v.extend(seg(0xC0, &[8, 0, 16, 0, 16, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]));
        v.extend(dht(0, 0));
        v.extend(dht(1, 0));
        v.extend(dht(0, 1));
        v.extend(dht(1, 1));
        v.extend(seg(0xDA, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]));
        v.extend_from_slice(&[0xAB, 0xCD, 0xFF, 0xD9]);
        let r = analyze(&v);
        assert_eq!(r.rubric.app_identification, 0.0);
        assert!((r.validation.score - (1.0 - W_APP)).abs() < 1e-12);
        assert!(r.validation.valid, "JFIF is optional; its absence grades only");
    }

    #[test]
    fn weights_sum_to_one() {
        let s = W_CHAIN + W_QUANT + W_HUFF + W_FRAME + W_SCAN + W_RESTART + W_APP;
        assert!((s - 1.0).abs() < 1e-12, "rubric weights sum to {}", s);
    }

    // ---- rejections --------------------------------------------------------

    #[test]
    fn rejects_bare_signature() {
        let v = validate(&[0xFF, 0xD8, 0xFF, 0xE0]);
        assert!(!v.valid);
        assert_eq!(v.end, None);
    }

    #[test]
    fn rejects_reserved_marker_after_soi() {
        // FF D8 FF 80 -- the shape of five of the eight fixture JPEG decoys.
        let mut d = vec![0xFF, 0xD8, 0xFF, 0x80];
        d.extend(std::iter::repeat(0xA7u8).take(256));
        let v = validate(&d);
        assert!(!v.valid);
        assert!(v.detail.contains("reserved marker FF80"), "detail: {}", v.detail);
    }

    #[test]
    fn rejects_app_marker_whose_length_lands_on_noise() {
        // The shape of the other three decoys: a real APPn marker, then a
        // length that points at bytes which are not a marker.
        let mut d = vec![0xFF, 0xD8, 0xFF, 0xE6, 0x00, 0x20];
        d.extend(std::iter::repeat(0x5Cu8).take(4096));
        let v = validate(&d);
        assert!(!v.valid);
        assert!(v.detail.contains("expected a marker"), "detail: {}", v.detail);
    }

    #[test]
    fn rejects_truncated_scan_with_no_eoi() {
        let mut j = good_jpeg();
        j.truncate(j.len() - 2);
        let v = validate(&j);
        assert!(!v.valid);
        assert_eq!(v.end, None);
        assert!(v.detail.contains("without an EOI"), "detail: {}", v.detail);
    }

    #[test]
    fn rejects_empty_and_short_input() {
        assert!(!validate(&[]).valid);
        assert!(!validate(&[0xFF]).valid);
        assert!(!validate(&[0xFF, 0xD8]).valid);
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        // Deterministic pseudo-random bytes prefixed with a JPEG signature.
        let mut s: u32 = 0x1234_5678;
        for trial in 0..200 {
            let mut d = vec![0xFF, 0xD8];
            for _ in 0..(64 + trial * 3) {
                s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
                d.push((s >> 16) as u8);
            }
            let _ = validate(&d);
        }
    }
}
