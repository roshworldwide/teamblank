use crate::Kind;

#[derive(Debug, Clone, Copy)]
pub struct Signature {
    pub kind: Kind,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub max_len: u64,
}

const JPEG_HEADER: &[u8] = &[0xFF, 0xD8, 0xFF];
const JPEG_FOOTER: &[u8] = &[0xFF, 0xD9];

const PNG_HEADER: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
const PNG_FOOTER: &[u8] = &[b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82];

const PDF_HEADER: &[u8] = b"%PDF-";
const PDF_FOOTER: &[u8] = b"%%EOF";

const ZIP_HEADER: &[u8] = &[b'P', b'K', 0x03, 0x04];
const ZIP_FOOTER: &[u8] = &[b'P', b'K', 0x05, 0x06];

const SQLITE_HEADER: &[u8] = b"SQLite format 3\x00";

const GZIP_HEADER: &[u8] = &[0x1F, 0x8B, 0x08];

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

pub const SIGNATURES: &[Signature] = &[
    Signature { kind: Kind::Jpeg,   header: JPEG_HEADER,   footer: Some(JPEG_FOOTER), max_len:  32 * MIB },
    Signature { kind: Kind::Png,    header: PNG_HEADER,    footer: Some(PNG_FOOTER),  max_len:  64 * MIB },
    Signature { kind: Kind::Pdf,    header: PDF_HEADER,    footer: Some(PDF_FOOTER),  max_len:  64 * MIB },
    Signature { kind: Kind::Zip,    header: ZIP_HEADER,    footer: Some(ZIP_FOOTER),  max_len: 128 * MIB },
    Signature { kind: Kind::Sqlite, header: SQLITE_HEADER, footer: None,              max_len: 256 * MIB },
    Signature { kind: Kind::Gzip,   header: GZIP_HEADER,   footer: None,              max_len: 128 * MIB },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub kind: Kind,
    pub header_at: u64,
    pub footer_at: Option<u64>,
}

const _: () = assert!(
    SIGNATURES.len() <= 32,
    "FIRST_BYTE_INDEX is a u32 bitmask; widen it before adding a 33rd signature"
);

const fn build_first_byte_index() -> [u32; 256] {
    let mut index = [0u32; 256];
    let mut i = 0;
    while i < SIGNATURES.len() {
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
        probes[i] = if at < mine.len() { at } else { 0 };
        i += 1;
    }
    probes
}

static PROBE_AT: [usize; SIGNATURES.len()] = build_probe_offsets();

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

fn resolve_footer(data: &[u8], sig: &Signature, header_at: usize) -> Option<u64> {
    let footer = sig.footer?;
    let search_from = header_at + sig.header.len();
    let window_end = (header_at as u64)
        .saturating_add(sig.max_len)
        .min(data.len() as u64) as usize;
    if search_from >= window_end {
        return None;
    }
    find_from(&data[search_from..window_end], footer).map(|rel| (search_from + rel) as u64)
}

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

pub fn signature_for(kind: Kind) -> Option<&'static Signature> {
    SIGNATURES.iter().find(|sig| sig.kind == kind)
}

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

pub fn suppress_nested(cands: &[Candidate]) -> Vec<Candidate> {
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

const KIND_COUNT: usize = 7;

#[allow(dead_code)]
fn kind_count_is_exhaustive(kind: Kind) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../out/fixture.img");

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
        for kind in [Kind::Gzip, Kind::Sqlite, Kind::Mp4] {
            assert!(signature_for(kind).unwrap().footer.is_none(), "{}", kind);
        }
        for kind in [Kind::Jpeg, Kind::Png, Kind::Pdf, Kind::Zip] {
            assert!(signature_for(kind).unwrap().footer.is_some(), "{}", kind);
        }
    }

    #[test]
    fn the_probe_offset_of_each_row_really_discriminates_it() {
        for (row, sig) in SIGNATURES.iter().enumerate() {
            let at = PROBE_AT[row];
            assert!(at < sig.header.len());
            if sig.kind == Kind::Mp4 {
                assert_eq!(at, 3, "ftyp rows must probe the box-size byte");
            }
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
        let buf = PNG_HEADER[..PNG_HEADER.len() - 1].to_vec();
        assert_eq!(count(&scan(&buf), Kind::Png), 0);
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

    #[test]
    fn mp4_header_at_is_the_box_start_not_the_ftyp_magic() {
        let mut buf = vec![0xAAu8; 4096];
        let obj = 512usize;
        buf[obj..obj + MP4_FTYP_N1.len()].copy_from_slice(MP4_FTYP_N1);
        let cands = scan(&buf);
        assert_eq!(offsets(&cands, Kind::Mp4), vec![obj as u64]);
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
            let declared = u32::from_be_bytes([row[0], row[1], row[2], row[3]]) as usize;
            assert_eq!(declared, 16 + 4 * n, "row {n} declares the wrong box size");
            let mut buf = vec![0xAAu8; 256];
            buf[64..64 + row.len()].copy_from_slice(row);
            assert_eq!(offsets(&scan(&buf), Kind::Mp4), vec![64], "row {n}");
        }
    }

    #[test]
    fn an_ftyp_box_larger_than_the_table_covers_is_missed_and_that_is_documented() {
        let mut buf = vec![0xAAu8; 256];
        let row = [0x00, 0x00, 0x00, 0x34, b'f', b't', b'y', b'p'];
        buf[64..64 + row.len()].copy_from_slice(&row);
        assert_eq!(count(&scan(&buf), Kind::Mp4), 0);
    }

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
        let buf = inert(JPEG_HEADER, 1024);
        let cands = scan(&buf);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].kind, Kind::Jpeg);
        assert_eq!(cands[0].footer_at, None);
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
        let mut buf = inert(JPEG_HEADER, 4096);
        for at in [800usize, 1600, 2400] {
            buf[at] = 0xFF;
            buf[at + 1] = 0xD9;
        }
        let cands = scan(&buf);
        assert_eq!(cands[0].footer_at, Some(800));
        assert_eq!(next_footer(&buf, Kind::Jpeg, 802, buf.len() as u64), Some(1600));
        assert_eq!(next_footer(&buf, Kind::Jpeg, 1602, buf.len() as u64), Some(2400));
        assert_eq!(next_footer(&buf, Kind::Jpeg, 2402, buf.len() as u64), None);
    }

    #[test]
    fn a_footer_before_the_header_is_not_taken() {
        let mut buf = vec![0xAAu8; 4096];
        buf[0] = 0xFF;
        buf[1] = 0xD9;
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

        buf[max - 2] = 0xFF;
        buf[max - 1] = 0xD9;
        assert_eq!(scan(&buf)[0].footer_at, Some((max - 2) as u64));

        buf[max - 2] = 0xAA;
        buf[max - 1] = 0xFF;
        buf[max] = 0xD9;
        assert_eq!(scan(&buf)[0].footer_at, None);
    }

    #[test]
    fn png_footer_is_the_iend_tag_and_its_constant_crc() {
        assert_eq!(PNG_FOOTER, b"IEND\xAEB`\x82");
        let mut buf = inert(PNG_HEADER, 1024);
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
        assert_eq!(next_footer(&buf, Kind::Jpeg, 0, 601), None);
        assert_eq!(next_footer(&buf, Kind::Jpeg, 601, 1024), None);
        assert_eq!(next_footer(&buf, Kind::Gzip, 0, 1024), None);
        assert_eq!(next_footer(&buf, Kind::Mp4, 0, 1024), None);
        assert_eq!(next_footer(&buf, Kind::Sqlite, 0, 1024), None);
    }

    #[test]
    fn overlapping_matches_of_the_same_pattern_are_both_reported() {
        let mut buf = vec![0xAAu8; 512];
        buf[0..5].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xD8, 0xFF]);
        assert_eq!(offsets(&scan(&buf), Kind::Jpeg), vec![0, 2]);
    }

    #[test]
    fn a_header_inside_another_kinds_payload_is_still_reported() {
        let mut buf = inert(PNG_HEADER, 4096);
        buf[1000..1003].copy_from_slice(JPEG_HEADER);
        buf[2000..2008].copy_from_slice(PNG_FOOTER);
        let cands = scan(&buf);
        assert_eq!(offsets(&cands, Kind::Png), vec![0]);
        assert_eq!(offsets(&cands, Kind::Jpeg), vec![1000]);
        assert_eq!(suppress_nested(&cands).len(), 2);
    }

    #[test]
    fn nested_same_kind_headers_are_reported_by_scan_and_collapsed_by_the_filter() {
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
        let mut buf = vec![0xAAu8; 4096];
        for at in [0usize, 100, 200] {
            buf[at..at + GZIP_HEADER.len()].copy_from_slice(GZIP_HEADER);
        }
        let cands = scan(&buf);
        assert_eq!(offsets(&cands, Kind::Gzip), vec![0, 100, 200]);
        assert_eq!(offsets(&suppress_nested(&cands), Kind::Gzip), vec![0, 100, 200]);
    }

    const FIXTURE_COUNTS: [(Kind, usize); 7] = [
        (Kind::Jpeg, 19),
        (Kind::Png, 5),
        (Kind::Pdf, 5),
        (Kind::Zip, 35),
        (Kind::Sqlite, 5),
        (Kind::Mp4, 5),
        (Kind::Gzip, 18),
    ];

    const PLANTED: [(Kind, u64); 35] = [
        (Kind::Zip, 1_069_056),
        (Kind::Gzip, 8_054_784),
        (Kind::Sqlite, 12_900_352),
        (Kind::Png, 21_317_632),
        (Kind::Pdf, 26_875_904),
        (Kind::Png, 32_710_656),
        (Kind::Sqlite, 37_040_128),
        (Kind::Zip, 43_235_328),
        (Kind::Png, 51_361_792),
        (Kind::Gzip, 59_394_048),
        (Kind::Mp4, 65_796_096),
        (Kind::Mp4, 65_943_552),
        (Kind::Sqlite, 73_611_264),
        (Kind::Png, 79_996_928),
        (Kind::Zip, 85_690_368),
        (Kind::Gzip, 89_563_136),
        (Kind::Pdf, 96_673_792),
        (Kind::Zip, 101_607_424),
        (Kind::Sqlite, 108_763_136),
        (Kind::Pdf, 114_669_568),
        (Kind::Pdf, 119_242_752),
        (Kind::Jpeg, 125_999_104),
        (Kind::Mp4, 133_177_344),
        (Kind::Png, 136_941_568),
        (Kind::Gzip, 143_464_448),
        (Kind::Sqlite, 150_474_752),
        (Kind::Jpeg, 156_942_336),
        (Kind::Zip, 163_844_096),
        (Kind::Pdf, 170_430_464),
        (Kind::Jpeg, 176_111_616),
        (Kind::Mp4, 180_529_152),
        (Kind::Jpeg, 200_210_432),
        (Kind::Jpeg, 214_231_040),
        (Kind::Mp4, 221_540_352),
        (Kind::Gzip, 228_945_920),
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
        assert_eq!(count(cands, Kind::Zip), 35);
        assert_eq!(count(&kept, Kind::Zip), 5);
        for (kind, at) in PLANTED.iter().filter(|(k, _)| *k == Kind::Zip) {
            assert!(kept.iter().any(|c| c.kind == *kind && c.header_at == *at));
        }
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
        let Some((data, cands)) = fixture_scan() else { return };
        let _ = data;
        let expect = [
            (Kind::Png, 51_361_792u64, 51_547_182u64, 51_547_190u64),
            (Kind::Pdf, 170_430_464, 170_738_658, 170_738_664),
            (Kind::Zip, 1_069_056, 1_230_351, 1_230_373),
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
        let Some((data, cands)) = fixture_scan() else { return };
        let _ = data;
        let cand = cands
            .iter()
            .find(|c| c.kind == Kind::Jpeg && c.header_at == 214_231_040)
            .unwrap();
        assert_eq!(cand.footer_at, Some(214_284_100));
        let true_end = 214_181_252u64;
        assert!(cand.footer_at.unwrap() > true_end);
        assert_eq!(cand.footer_at.unwrap() - true_end, 102_848);
    }

    #[test]
    fn fixture_no_footer_bearing_candidate_is_missing_its_footer() {
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
