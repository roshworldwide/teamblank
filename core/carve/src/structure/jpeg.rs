use super::{be_u16, clamp01, Validation};

pub const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_SEGMENTS: usize = 1024;

const W_CHAIN: f64 = 0.20;
const W_QUANT: f64 = 0.15;
const W_HUFF: f64 = 0.15;
const W_FRAME: f64 = 0.15;
const W_SCAN: f64 = 0.15;
const W_RESTART: f64 = 0.10;
const W_APP: f64 = 0.10;

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

#[derive(Debug, Clone)]
pub struct JpegReport {
    pub validation: Validation,
    pub rubric: JpegRubric,
    pub sof_marker: Option<u8>,
    pub width: u16,
    pub height: u16,
    pub components: usize,
    pub segments: usize,
    pub entropy_bytes: u64,
    pub restart_markers: u64,
}

pub fn validate(data: &[u8]) -> Validation {
    analyze(data).validation
}

#[inline]
fn is_sof(m: u8) -> bool {
    matches!(m, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF)
}

#[inline]
fn has_length(m: u8) -> bool {
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

    let mut chain_clean = true;
    let mut frame_sane = false;
    let mut scan_sane = false;
    let mut app_ident = false;

    let mut dqt_defined = [false; 4];
    let mut dc_defined = [false; 4];
    let mut ac_defined = [false; 4];

    let mut sof_seen = false;
    let mut sof_progressive = false;
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
                        chain_clean = false;
                    }
                }
            }
            0xDA => {
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
                0x00 => i += 2,
                0xFF => i += 1,
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
                0x01 => i += 2,
                m if has_length(m) => {
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
        v.extend(seg(
            0xC0,
            &[8, 0, 16, 0, 16, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1],
        ));
        v.extend(dht(0, 0));
        v.extend(dht(1, 0));
        v.extend(dht(0, 1));
        v.extend(dht(1, 1));
        v.extend(seg(0xDA, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]));
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

    #[test]
    fn term_chain_integrity_falls_on_ff_fill() {
        let mut j = good_jpeg();
        j.splice(2..2, [0xFFu8]);
        let r = analyze(&j);
        assert_eq!(r.rubric.chain_integrity, 0.0);
        assert!((r.validation.score - (1.0 - W_CHAIN)).abs() < 1e-12,
                "only chain_integrity should move, got {}", r.validation.score);
        assert!(r.validation.valid, "fill bytes are legal; validity must not move");
    }

    #[test]
    fn term_quant_tables_is_a_fraction() {
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
        v.extend(seg(0xDD, &[0x00, 0x04]));
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

    #[test]
    fn rejects_bare_signature() {
        let v = validate(&[0xFF, 0xD8, 0xFF, 0xE0]);
        assert!(!v.valid);
        assert_eq!(v.end, None);
    }

    #[test]
    fn rejects_reserved_marker_after_soi() {
        let mut d = vec![0xFF, 0xD8, 0xFF, 0x80];
        d.extend(std::iter::repeat(0xA7u8).take(256));
        let v = validate(&d);
        assert!(!v.valid);
        assert!(v.detail.contains("reserved marker FF80"), "detail: {}", v.detail);
    }

    #[test]
    fn rejects_app_marker_whose_length_lands_on_noise() {
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
