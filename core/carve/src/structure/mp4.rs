//! MP4 / QuickTime structure validation: walk the box tree from ftyp.
//!
//! Garfinkel, "Carving contiguous and fragmented files with fast object
//! validation", DFRWS 2007. MP4 is the paper's other worked example and the
//! reason is the box tree: every box declares its own size, so the boxes tile
//! the object end to end and a single wrong byte in any size field derails the
//! whole chain. That makes the walk a cheap and unusually decisive validator,
//! and it is also where `end` comes from -- there is no footer to search for.
//!
//! This fixture's measured `residue_signature_false_positives.MP4` is 0,
//! because the scanner's four-byte `ftyp` magic does not occur by chance in
//! 134 MB of residue. The box walk is therefore not carrying the
//! false-positive load here; it is carrying the LENGTH, which is what the
//! bifragment search needs and what the SHA-256 comparison against the
//! manifest depends on.
//!
//! ## Input convention -- read this before calling
//!
//! The signature scanner matches the four bytes `ftyp`, which sit at offset 4
//! of the object, INSIDE the first box's header. This validator wants `data` to
//! start at the ftyp BOX, meaning the 32-bit size field, so a caller holding a
//! match at position p must pass `header_at = p - 4`. Being handed the raw
//! match position is detected and rejected with that instruction in `detail`
//! rather than silently mis-parsed.
//!
//! ## The walk
//!
//! ISO/IEC 14496-12 section 4.2. A box is a big-endian 32-bit size, a 4-byte
//! type, then the payload; the size COUNTS the 8-byte header. Size 1 means a
//! 64-bit `largesize` follows the type, making the header 16 bytes; size 0
//! means the box runs to the end of the file, which for a carver is an
//! unbounded claim and is refused. Container boxes (moov, trak, mdia, minf,
//! stbl, edts, dinf, udta) hold child boxes that tile their payload exactly.
//!
//! The top-level walk stops at the first box whose type is not one the format
//! places at the top level. That whitelist is what bounds `end` against the
//! residue that follows the object on disk: without it, four bytes of noise
//! that happen to read as printable ASCII would extend the object and change
//! its SHA-256.
//!
//! ## RUBRIC -- how `score` is derived
//!
//! Six independent checks, fixed weights, summing to exactly 1.00.
//!
//!   0.15  ftyp_box        the first box is `ftyp`, at least 16 bytes, with a
//!                         printable major brand and a compatible-brand list
//!                         that is a whole number of 4-byte entries
//!   0.20  tiling          every top-level box declared a size that is at
//!                         least its header, fit entirely inside the data, and
//!                         carried a known top-level type; no box used the
//!                         open-ended size 0
//!   0.20  moov_tree       FRACTION of the eight boxes a playable track
//!                         requires -- mvhd, trak, tkhd, mdia, mdhd, minf,
//!                         stbl, stsd -- found by a recursive descent in which
//!                         every container's children tile it exactly
//!   0.15  mdat_present    an `mdat` box exists with a payload longer than 0
//!   0.20  sample_tables   the stsz/stco cross-check, in two halves of 0.10:
//!                         the sample sizes sum to no more than the mdat
//!                         payload, and every chunk offset in stco (or co64)
//!                         lands inside the mdat payload's byte range
//!   0.10  payload_exclusivity
//!                         no `ftyp` box header occurs INSIDE the mdat payload
//!
//! `sample_tables` ties the metadata to the media: a box tree can tile
//! perfectly and still describe chunk offsets that point nowhere.
//! `payload_exclusivity` is the only check that reaches into the media bytes at
//! all, and it can say only one thing about them -- that another object does
//! not start there.
//!
//! ## VALIDITY GATE -- separate from the score
//!
//! `valid` requires: ftyp first and sane; a clean top-level tiling; a `moov`
//! containing at least `mvhd` and one `trak`; an `mdat` with a non-empty
//! payload; and payload exclusivity. The sample-table cross-check grades but
//! does not gate, because layouts this carver does not model (fragmented MP4,
//! external data references) legitimately lack a usable stco.
//!
//! ## THE LIMIT OF THIS VALIDATOR -- measured, and stated because it matters
//!
//! MP4 defines NO checksum over `mdat`. PNG puts a CRC-32 on every chunk and
//! GZIP puts one on the whole decompressed stream, so a wrong reassembly of
//! either is caught by arithmetic. MP4 has nothing equivalent: once the box
//! tree tiles, the media bytes are opaque and unverifiable. The consequence,
//! measured on `out/fixture.img` rather than reasoned about:
//!
//!   /sealing_procedure.mov   read contiguously from its header, the top-level
//!                            boxes STILL tile exactly to its true 221,041
//!                            bytes, because the mdat size field is intact and
//!                            the fragmentation falls inside the payload. Only
//!                            `payload_exclusivity` rejects it, and only
//!                            because the 192,400-byte gap it steps over
//!                            happens to contain /handover_briefing.mov's own
//!                            ftyp header at image offset 65,943,552.
//!
//!   /handover_briefing.mov   read contiguously from its header, the boxes tile
//!                            exactly to its true 66,689 bytes, the sample
//!                            tables agree, and the 33,913 wrong bytes it picks
//!                            up are residue and another file's PCM audio --
//!                            no ftyp header among them. THIS VALIDATOR
//!                            ACCEPTS IT, with a score of 1.00, and the bytes
//!                            it accepts are not the file. No structural check
//!                            exists that would reject it, and inventing one
//!                            fitted to this fixture would be worse than
//!                            saying so.
//!
//! The resolution is not available inside a single `validate` call and must be
//! made by the carve driver, which sees all objects at once: the contiguous
//! claim for /handover_briefing.mov spans [65,943,552, 66,010,241), which
//! OVERLAPS the second extent of the correctly recovered /sealing_procedure.mov
//! at [65,988,608, 66,119,537) by 21,633 bytes. Two recovered objects cannot
//! own the same bytes. Its true extents, [65,943,552, 65,976,320) and
//! [66,119,680, 66,153,601), overlap nothing. Cross-object overlap detection
//! resolves it; structure validation alone cannot, and this module does not
//! pretend otherwise. Every accepted MP4 reports its unverified mdat byte count
//! in `detail` for exactly this reason.

use super::{be_u32, be_u64, clamp01, Validation};

/// Longest MP4 this carver will accept. A carving bound: the largest planted
/// object in `out/fixture.img` is 260,595 bytes.
pub const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;

/// Cap on boxes visited, across the whole tree.
pub const MAX_BOXES: usize = 100_000;

/// Cap on container nesting.
pub const MAX_DEPTH: usize = 12;

/// Box types the format places at the top level of a file. The walk stops at
/// anything else, which is what stops residue from extending the object.
/// ISO/IEC 14496-12 plus the QuickTime File Format's `pnot`, `wide` and `cmov`.
const TOP_LEVEL: &[&[u8; 4]] = &[
    b"ftyp", b"styp", b"moov", b"moof", b"mfra", b"mdat", b"free", b"skip", b"wide", b"pnot",
    b"udta", b"uuid", b"meta", b"sidx", b"ssix", b"prft", b"pdin", b"cmov", b"mfro", b"junk",
];

/// Boxes whose payload is a list of child boxes.
const CONTAINERS: &[&[u8; 4]] = &[
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf", b"udta", b"mvex", b"moof",
    b"traf", b"mfra",
];

const W_FTYP: f64 = 0.15;
const W_TILING: f64 = 0.20;
const W_MOOV: f64 = 0.20;
const W_MDAT: f64 = 0.15;
const W_TABLES: f64 = 0.20;
const W_EXCLUSIVE: f64 = 0.10;

/// The eight boxes a playable track requires; `moov_tree` is the fraction found.
const REQUIRED_TREE: [&[u8; 4]; 8] = [
    b"mvhd", b"trak", b"tkhd", b"mdia", b"mdhd", b"minf", b"stbl", b"stsd",
];

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Mp4Rubric {
    pub ftyp_box: f64,
    pub tiling: f64,
    pub moov_tree: f64,
    pub mdat_present: f64,
    pub sample_tables: f64,
    pub payload_exclusivity: f64,
}

impl Mp4Rubric {
    pub fn total(&self) -> f64 {
        clamp01(
            self.ftyp_box
                + self.tiling
                + self.moov_tree
                + self.mdat_present
                + self.sample_tables
                + self.payload_exclusivity,
        )
    }
}

#[derive(Debug, Clone)]
pub struct Mp4Report {
    pub validation: Validation,
    pub rubric: Mp4Rubric,
    pub major_brand: String,
    pub top_level_boxes: usize,
    pub boxes_visited: usize,
    /// Byte range of the mdat PAYLOAD, relative to `data[0]`.
    pub mdat_payload: Option<(u64, u64)>,
    /// Total bytes the sample-size table accounts for.
    pub sample_bytes: Option<u64>,
    pub sample_count: Option<u32>,
    pub chunk_offsets: usize,
    pub tracks: usize,
    /// Offset, relative to `data[0]`, of an `ftyp` box header found INSIDE the
    /// mdat payload -- another MP4 object beginning inside this one's media
    /// data, which means the extent is wrong. `None` when the payload is clean.
    pub foreign_header_at: Option<u64>,
}

/// `data` starts AT the ftyp BOX -- the 32-bit size field, four bytes before
/// the `ftyp` the scanner matched.
pub fn validate(data: &[u8]) -> Validation {
    analyze(data).validation
}

#[derive(Debug, Clone, Copy)]
struct BoxHdr {
    kind: [u8; 4],
    /// 8 normally, 16 for the 64-bit largesize form.
    header: usize,
    /// total box size including the header
    size: u64,
    /// the declared size was 0, meaning "to end of file"
    open_ended: bool,
}

fn printable_type(t: &[u8; 4]) -> bool {
    // 0xA9 is QuickTime's copyright-sign metadata prefix, e.g. "(c)nam".
    t.iter().all(|&b| (0x20..=0x7E).contains(&b) || b == 0xA9)
}

fn read_box(d: &[u8], at: usize) -> Option<BoxHdr> {
    if at + 8 > d.len() {
        return None;
    }
    let size32 = be_u32(d, at)? as u64;
    let mut kind = [0u8; 4];
    kind.copy_from_slice(&d[at + 4..at + 8]);
    if !printable_type(&kind) {
        return None;
    }
    if size32 == 1 {
        let large = be_u64(d, at + 8)?;
        if large < 16 {
            return None;
        }
        Some(BoxHdr { kind, header: 16, size: large, open_ended: false })
    } else if size32 == 0 {
        Some(BoxHdr {
            kind,
            header: 8,
            size: (d.len() - at) as u64,
            open_ended: true,
        })
    } else if size32 < 8 {
        None
    } else {
        Some(BoxHdr { kind, header: 8, size: size32, open_ended: false })
    }
}

fn is_in(list: &[&[u8; 4]], k: &[u8; 4]) -> bool {
    list.iter().any(|x| *x == k)
}

/// Recursive descent through a container's payload. Returns false if the
/// children do not tile the container exactly.
fn walk_children(
    d: &[u8],
    from: usize,
    to: usize,
    depth: usize,
    found: &mut [bool; 8],
    tracks: &mut usize,
    stsz: &mut Option<(u64, u32)>,
    chunk_offsets: &mut Vec<u64>,
    visited: &mut usize,
) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let mut at = from;
    while at < to {
        if *visited >= MAX_BOXES {
            return false;
        }
        let b = match read_box(d, at) {
            Some(b) => b,
            None => return false,
        };
        if b.open_ended {
            return false;
        }
        let end = at as u64 + b.size;
        if end > to as u64 || b.size < b.header as u64 {
            return false;
        }
        *visited += 1;

        for (i, want) in REQUIRED_TREE.iter().enumerate() {
            if &b.kind == *want {
                found[i] = true;
            }
        }
        if &b.kind == b"trak" {
            *tracks += 1;
        }

        let payload_at = at + b.header;
        let payload_end = end as usize;

        if &b.kind == b"stsz" && payload_end >= payload_at + 12 {
            // ISO/IEC 14496-12 section 8.7.3.
            let sample_size = be_u32(d, payload_at + 4).unwrap_or(0);
            let count = be_u32(d, payload_at + 8).unwrap_or(0);
            let total = if sample_size != 0 {
                sample_size as u64 * count as u64
            } else {
                let mut s = 0u64;
                let n = count as usize;
                if payload_at + 12 + 4 * n <= payload_end {
                    for i in 0..n {
                        s += be_u32(d, payload_at + 12 + 4 * i).unwrap_or(0) as u64;
                    }
                    s
                } else {
                    // Truncated entry list: no honest total to report.
                    u64::MAX
                }
            };
            *stsz = Some((total, count));
        } else if &b.kind == b"stco" && payload_end >= payload_at + 8 {
            // section 8.7.5, 32-bit chunk offsets
            let n = be_u32(d, payload_at + 4).unwrap_or(0) as usize;
            for i in 0..n.min(1_000_000) {
                match be_u32(d, payload_at + 8 + 4 * i) {
                    Some(v) if payload_at + 8 + 4 * (i + 1) <= payload_end => {
                        chunk_offsets.push(v as u64)
                    }
                    _ => break,
                }
            }
        } else if &b.kind == b"co64" && payload_end >= payload_at + 8 {
            let n = be_u32(d, payload_at + 4).unwrap_or(0) as usize;
            for i in 0..n.min(1_000_000) {
                match be_u64(d, payload_at + 8 + 8 * i) {
                    Some(v) if payload_at + 8 + 8 * (i + 1) <= payload_end => {
                        chunk_offsets.push(v)
                    }
                    _ => break,
                }
            }
        }

        if is_in(CONTAINERS, &b.kind)
            && !walk_children(
                d, payload_at, payload_end, depth + 1, found, tracks, stsz, chunk_offsets, visited,
            )
        {
            return false;
        }

        at = payload_end;
    }
    at == to
}

pub fn analyze(data: &[u8]) -> Mp4Report {
    let mut r = Mp4Report {
        validation: Validation::reject("mp4: not evaluated"),
        rubric: Mp4Rubric::default(),
        major_brand: String::new(),
        top_level_boxes: 0,
        boxes_visited: 0,
        mdat_payload: None,
        sample_bytes: None,
        sample_count: None,
        chunk_offsets: 0,
        tracks: 0,
        foreign_header_at: None,
    };

    if data.len() >= 4 && &data[0..4] == b"ftyp" {
        r.validation = Validation::reject(
            "mp4: data begins with the four bytes 'ftyp', which sit at offset 4 of the object; \
             pass header_at = match_position - 4 so the slice starts at the box size field",
        );
        return r;
    }
    if data.len() < 16 {
        r.validation = Validation::reject(format!(
            "mp4: {} bytes available, an ftyp box needs at least 16",
            data.len()
        ));
        return r;
    }
    if &data[4..8] != b"ftyp" {
        r.validation = Validation::reject(format!(
            "mp4: no ftyp box at offset 0, type bytes are {:?}",
            String::from_utf8_lossy(&data[4..8])
        ));
        return r;
    }

    let limit = data.len().min(MAX_OBJECT_BYTES);

    // ---- top-level tiling --------------------------------------------------
    let mut tiling_ok = true;
    let mut end = 0usize;
    let mut at = 0usize;
    let mut ftyp_ok = false;
    let mut moov_range: Option<(usize, usize)> = None;
    let mut stop_reason = String::new();

    while at < limit {
        let b = match read_box(data, at) {
            Some(b) => b,
            None => {
                stop_reason = format!("no parsable box header at offset {}", at);
                break;
            }
        };
        if b.open_ended {
            // Size 0 claims the rest of the medium. A carver cannot honour an
            // unbounded claim, so the tiling is not exact.
            tiling_ok = false;
            stop_reason = format!("box '{}' at offset {} declares size 0 (open-ended)",
                                  String::from_utf8_lossy(&b.kind), at);
            break;
        }
        if !is_in(TOP_LEVEL, &b.kind) {
            stop_reason = format!(
                "box type '{}' at offset {} is not a top-level box; object ends here",
                String::from_utf8_lossy(&b.kind),
                at
            );
            break;
        }
        let box_end = at as u64 + b.size;
        if box_end > limit as u64 || b.size < b.header as u64 {
            tiling_ok = false;
            stop_reason = format!(
                "box '{}' at offset {} declares size {} which runs past the {} bytes available",
                String::from_utf8_lossy(&b.kind),
                at,
                b.size,
                limit
            );
            break;
        }
        let box_end = box_end as usize;

        if r.top_level_boxes == 0 {
            if &b.kind == b"ftyp" {
                let payload = &data[at + b.header..box_end];
                // section 4.3: major_brand(4), minor_version(4), then a list
                // of 4-byte compatible brands.
                ftyp_ok = b.size >= 16
                    && payload.len() >= 8
                    && (payload.len() - 8) % 4 == 0
                    && payload[..4].iter().all(|&c| (0x20..=0x7E).contains(&c));
                if payload.len() >= 4 {
                    r.major_brand = String::from_utf8_lossy(&payload[..4]).trim_end().to_string();
                }
            }
        }
        if &b.kind == b"moov" {
            moov_range = Some((at + b.header, box_end));
        }
        if &b.kind == b"mdat" && r.mdat_payload.is_none() {
            r.mdat_payload = Some(((at + b.header) as u64, box_end as u64));
        }

        r.top_level_boxes += 1;
        r.boxes_visited += 1;
        at = box_end;
        end = box_end;
        if r.top_level_boxes > MAX_BOXES {
            tiling_ok = false;
            stop_reason = format!("top-level box count exceeded {}", MAX_BOXES);
            break;
        }
    }

    if r.top_level_boxes == 0 {
        r.validation = Validation::reject(format!("mp4: no walkable box at offset 0 -- {}", stop_reason));
        return r;
    }

    // ---- moov subtree ------------------------------------------------------
    let mut found = [false; 8];
    let mut stsz: Option<(u64, u32)> = None;
    let mut chunk_offsets: Vec<u64> = Vec::new();
    let mut tracks = 0usize;
    let mut subtree_ok = false;
    if let Some((from, to)) = moov_range {
        let mut visited = r.boxes_visited;
        subtree_ok = walk_children(
            data,
            from,
            to,
            1,
            &mut found,
            &mut tracks,
            &mut stsz,
            &mut chunk_offsets,
            &mut visited,
        );
        r.boxes_visited = visited;
    }
    r.tracks = tracks;
    r.chunk_offsets = chunk_offsets.len();
    if let Some((total, count)) = stsz {
        r.sample_bytes = if total == u64::MAX { None } else { Some(total) };
        r.sample_count = Some(count);
    }

    let moov_fraction = if moov_range.is_none() || !subtree_ok {
        // A container whose children do not tile it is not a tree we walked;
        // reporting a partial score off a broken walk would be a claim we did
        // not verify.
        0.0
    } else {
        found.iter().filter(|f| **f).count() as f64 / found.len() as f64
    };

    // ---- mdat and the sample-table cross-check -----------------------------
    let mdat_ok = r.mdat_payload.map(|(a, b)| b > a).unwrap_or(false);

    let mut tables = 0.0f64;
    if let (Some((m0, m1)), Some(total)) = (r.mdat_payload, r.sample_bytes) {
        if total <= m1 - m0 {
            tables += W_TABLES / 2.0;
        }
        if !chunk_offsets.is_empty() && chunk_offsets.iter().all(|&o| o >= m0 && o < m1) {
            tables += W_TABLES / 2.0;
        }
    }

    // ---- payload exclusivity ----------------------------------------------
    // Media data is opaque, so the only thing that can be said about it is that
    // it must not contain the START OF ANOTHER OBJECT. An `ftyp` box header
    // inside the mdat payload means a second MP4 begins inside this one's media
    // data, and two files cannot legitimately nest that way. On this fixture it
    // is the check that rejects the contiguous mis-read of
    // /sealing_procedure.mov, whose gap swallows /handover_briefing.mov's
    // header. See the module doc for what it does NOT catch.
    if let Some((m0, m1)) = r.mdat_payload {
        let (a, b) = (m0 as usize, (m1 as usize).min(limit));
        let mut i = a + 4;
        while i + 8 <= b {
            if data[i] == b'f' && &data[i..i + 4] == b"ftyp" {
                let size = be_u32(data, i - 4).unwrap_or(0) as u64;
                let brand_ok = i + 8 <= b && data[i + 4..i + 8].iter().all(|&c| (0x20..=0x7E).contains(&c));
                if size >= 16 && (i as u64 - 4) + size <= m1 && brand_ok {
                    r.foreign_header_at = Some(i as u64 - 4);
                    break;
                }
            }
            i += 1;
        }
    }
    let exclusive = r.foreign_header_at.is_none();

    r.rubric = Mp4Rubric {
        ftyp_box: if ftyp_ok { W_FTYP } else { 0.0 },
        tiling: if tiling_ok { W_TILING } else { 0.0 },
        moov_tree: W_MOOV * moov_fraction,
        mdat_present: if mdat_ok { W_MDAT } else { 0.0 },
        sample_tables: tables,
        payload_exclusivity: if exclusive { W_EXCLUSIVE } else { 0.0 },
    };
    let score = r.rubric.total();

    let moov_ok = subtree_ok && found[0] && found[1] && tracks >= 1; // mvhd and a trak
    let gate = ftyp_ok && tiling_ok && moov_ok && mdat_ok && exclusive && end > 0;

    r.validation = if gate {
        Validation::accept(
            end as u64,
            score,
            format!(
                "mp4: brand '{}', {} top-level boxes tiling {} bytes, {} boxes walked, {} track(s), mdat payload {} bytes, {} sample(s) totalling {} bytes across {} chunk offset(s)",
                r.major_brand,
                r.top_level_boxes,
                end,
                r.boxes_visited,
                r.tracks,
                r.mdat_payload.map(|(a, b)| b - a).unwrap_or(0),
                r.sample_count.unwrap_or(0),
                r.sample_bytes.unwrap_or(0),
                r.chunk_offsets
            ) + &format!(
                "; {} mdat bytes are NOT covered by any checksum -- MP4 defines none",
                r.mdat_payload.map(|(a, b)| b - a).unwrap_or(0)
            ),
        )
    } else {
        let why = if !ftyp_ok {
            "the ftyp box failed its sanity check".to_string()
        } else if !tiling_ok {
            format!("the top-level boxes do not tile -- {}", stop_reason)
        } else if !moov_ok {
            format!(
                "the moov subtree is unusable: {} of {} required boxes found, {} track(s), children tile: {}",
                found.iter().filter(|f| **f).count(),
                found.len(),
                tracks,
                subtree_ok
            )
        } else if !mdat_ok {
            "no mdat box with a non-empty payload".to_string()
        } else {
            format!(
                "the mdat payload contains an ftyp box header at offset {}, so another object begins inside this one's media data and the extent is wrong",
                r.foreign_header_at.unwrap_or(0)
            )
        };
        Validation::reject_with_end(end as u64, score, format!("mp4: {}", why))
    };
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bx(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut v = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(kind);
        v.extend_from_slice(payload);
        v
    }

    fn full(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8, 0, 0, 0]; // version + flags
        v.extend_from_slice(payload);
        v
    }

    /// The same shape the fixture's own writer emits: ftyp, moov holding a
    /// single audio trak, then mdat. 4-byte samples, one chunk.
    fn good_mp4(samples: u32) -> Vec<u8> {
        let audio: Vec<u8> = (0..samples * 4).map(|i| (i % 251) as u8).collect();

        let mvhd = bx(b"mvhd", &full(&[0u8; 96]));
        let tkhd = bx(b"tkhd", &full(&[0u8; 80]));
        let mdhd = bx(b"mdhd", &full(&[0u8; 20]));
        let hdlr = bx(b"hdlr", &full(&[0u8; 20]));
        let smhd = bx(b"smhd", &full(&[0u8; 4]));
        let dinf = bx(b"dinf", &bx(b"dref", &full(&[0, 0, 0, 0])));
        let stsd = bx(b"stsd", &full(&[0, 0, 0, 0]));
        let stts = bx(b"stts", &full(&[0, 0, 0, 0]));
        let stsc = bx(b"stsc", &full(&[0, 0, 0, 0]));

        let mut stsz_p = full(&[]);
        stsz_p.extend_from_slice(&4u32.to_be_bytes());
        stsz_p.extend_from_slice(&samples.to_be_bytes());
        let stsz = bx(b"stsz", &stsz_p);

        // stco's single chunk offset depends on the size of moov, which
        // depends on stco. The offset field is fixed width, so assemble once
        // with a placeholder and again with the real value.
        let assemble = |chunk_off: u32| -> Vec<u8> {
            let mut stco_p = full(&1u32.to_be_bytes());
            stco_p.extend_from_slice(&chunk_off.to_be_bytes());
            let stco = bx(b"stco", &stco_p);
            let mut stbl_p = Vec::new();
            stbl_p.extend(stsd.clone());
            stbl_p.extend(stts.clone());
            stbl_p.extend(stsc.clone());
            stbl_p.extend(stsz.clone());
            stbl_p.extend(stco);
            let stbl = bx(b"stbl", &stbl_p);
            let mut minf_p = Vec::new();
            minf_p.extend(smhd.clone());
            minf_p.extend(dinf.clone());
            minf_p.extend(stbl);
            let minf = bx(b"minf", &minf_p);
            let mut mdia_p = Vec::new();
            mdia_p.extend(mdhd.clone());
            mdia_p.extend(hdlr.clone());
            mdia_p.extend(minf);
            let mdia = bx(b"mdia", &mdia_p);
            let mut trak_p = Vec::new();
            trak_p.extend(tkhd.clone());
            trak_p.extend(mdia);
            let trak = bx(b"trak", &trak_p);
            let mut moov_p = Vec::new();
            moov_p.extend(mvhd.clone());
            moov_p.extend(trak);
            bx(b"moov", &moov_p)
        };

        let mut ftyp_p = b"qt  ".to_vec();
        ftyp_p.extend_from_slice(&0x2005_0300u32.to_be_bytes());
        ftyp_p.extend_from_slice(b"qt  ");
        let ftyp = bx(b"ftyp", &ftyp_p);

        let moov = assemble(0);
        let data_off = (ftyp.len() + moov.len() + 8) as u32;
        let moov = assemble(data_off);

        let mut v = Vec::new();
        v.extend(ftyp);
        v.extend(moov);
        v.extend(bx(b"mdat", &audio));
        v
    }

    #[test]
    fn intact_mp4_is_valid_and_scores_one() {
        let m = good_mp4(64);
        let r = analyze(&m);
        assert!(r.validation.valid, "detail: {}", r.validation.detail);
        assert_eq!(r.validation.end, Some(m.len() as u64));
        assert!((r.validation.score - 1.0).abs() < 1e-12, "score {} rubric {:?}",
                r.validation.score, r.rubric);
        assert_eq!(r.top_level_boxes, 3);
        assert_eq!(r.tracks, 1);
        assert_eq!(r.major_brand, "qt");
        assert_eq!(r.sample_count, Some(64));
        assert_eq!(r.sample_bytes, Some(256));
        assert_eq!(r.chunk_offsets, 1);
        assert_eq!(r.mdat_payload.map(|(a, b)| b - a), Some(256));
    }

    #[test]
    fn end_stops_at_the_last_top_level_box_not_at_the_slice_end() {
        let mut m = good_mp4(32);
        let n = m.len();
        // Residue that is not a top-level box type.
        m.extend(std::iter::repeat(0x9Cu8).take(8192));
        let v = validate(&m);
        assert!(v.valid, "detail: {}", v.detail);
        assert_eq!(v.end, Some(n as u64));
    }

    // ---- one test per rubric term -----------------------------------------

    #[test]
    fn term_ftyp_box_falls_on_a_short_ftyp() {
        // A 12-byte ftyp carries a major brand and nothing else: legal-looking,
        // but below the 16 bytes the format's own field list requires.
        let mut m = Vec::new();
        m.extend(bx(b"ftyp", b"qt  "));
        m.extend(good_mp4(16)[20..].to_vec());
        let r = analyze(&m);
        assert_eq!(r.rubric.ftyp_box, 0.0);
        assert!(!r.validation.valid);
    }

    #[test]
    fn term_tiling_falls_when_a_size_overruns_the_data() {
        let mut m = good_mp4(32);
        // Inflate the moov size so it claims more than the object holds.
        let moov_at = 20;
        assert_eq!(&m[moov_at + 4..moov_at + 8], b"moov");
        let big = (m.len() as u32) + 4096;
        m[moov_at..moov_at + 4].copy_from_slice(&big.to_be_bytes());
        let r = analyze(&m);
        assert_eq!(r.rubric.tiling, 0.0);
        assert!(!r.validation.valid);
        assert!(r.validation.detail.contains("do not tile"), "detail: {}", r.validation.detail);
    }

    #[test]
    fn term_tiling_falls_on_an_open_ended_size_zero_box() {
        let mut m = good_mp4(32);
        let moov_at = 20;
        m[moov_at..moov_at + 4].copy_from_slice(&0u32.to_be_bytes());
        let r = analyze(&m);
        assert_eq!(r.rubric.tiling, 0.0);
        assert!(!r.validation.valid);
        assert!(r.validation.detail.contains("open-ended"), "detail: {}", r.validation.detail);
    }

    #[test]
    fn term_moov_tree_is_a_fraction_of_the_required_boxes() {
        // ftyp + a moov holding only mvhd + mdat. Two of eight required boxes.
        let mut ftyp_p = b"qt  ".to_vec();
        ftyp_p.extend_from_slice(&0u32.to_be_bytes());
        ftyp_p.extend_from_slice(b"qt  ");
        let mut m = bx(b"ftyp", &ftyp_p);
        m.extend(bx(b"moov", &bx(b"mvhd", &full(&[0u8; 96]))));
        m.extend(bx(b"mdat", &[0u8; 64]));
        let r = analyze(&m);
        assert!((r.rubric.moov_tree - W_MOOV * (1.0 / 8.0)).abs() < 1e-12,
                "moov_tree {}", r.rubric.moov_tree);
        assert_eq!(r.rubric.ftyp_box, W_FTYP);
        assert_eq!(r.rubric.tiling, W_TILING);
        assert_eq!(r.rubric.mdat_present, W_MDAT);
        assert_eq!(r.rubric.sample_tables, 0.0, "no stsz or stco to cross-check");
        assert!(!r.validation.valid, "a moov with no trak is not a playable object");
    }

    #[test]
    fn term_moov_tree_falls_to_zero_when_children_do_not_tile() {
        let mut m = good_mp4(32);
        // Shrink the trak box by 4 so moov's children no longer tile it.
        let moov_at = 20;
        let trak_at = moov_at + 8 + 8 + 100; // moov header + mvhd (8 + 4 + 96)
        assert_eq!(&m[trak_at + 4..trak_at + 8], b"trak", "test fixture offset drifted");
        let sz = u32::from_be_bytes([m[trak_at], m[trak_at + 1], m[trak_at + 2], m[trak_at + 3]]);
        m[trak_at..trak_at + 4].copy_from_slice(&(sz - 4).to_be_bytes());
        let r = analyze(&m);
        assert_eq!(r.rubric.moov_tree, 0.0);
        assert!(!r.validation.valid);
    }

    #[test]
    fn term_mdat_present_falls_without_an_mdat() {
        let m = good_mp4(32);
        let mdat_at = m.len() - (32 * 4 + 8);
        assert_eq!(&m[mdat_at + 4..mdat_at + 8], b"mdat");
        let r = analyze(&m[..mdat_at]);
        assert_eq!(r.rubric.mdat_present, 0.0);
        assert_eq!(r.rubric.sample_tables, 0.0);
        assert!((r.validation.score - (1.0 - W_MDAT - W_TABLES)).abs() < 1e-12,
                "score {} rubric {:?}", r.validation.score, r.rubric);
        assert!(!r.validation.valid);
    }

    #[test]
    fn term_sample_tables_falls_when_the_chunk_offset_points_outside_mdat() {
        let mut m = good_mp4(32);
        // Find the stco entry and push it past the end of the object.
        let pos = m
            .windows(4)
            .position(|w| w == b"stco")
            .expect("stco is present");
        let entry_at = pos + 4 + 4 + 4; // type, version+flags, entry_count
        m[entry_at..entry_at + 4].copy_from_slice(&0xFFFF_0000u32.to_be_bytes());
        let r = analyze(&m);
        assert!((r.rubric.sample_tables - W_TABLES / 2.0).abs() < 1e-12,
                "the size half still holds; sample_tables {}", r.rubric.sample_tables);
        assert!(r.validation.valid, "the cross-check grades, it does not gate");
        assert!((r.validation.score - (1.0 - W_TABLES / 2.0)).abs() < 1e-12);
    }

    #[test]
    fn term_sample_tables_falls_when_the_sample_sizes_exceed_mdat() {
        let mut m = good_mp4(32);
        let pos = m.windows(4).position(|w| w == b"stsz").expect("stsz is present");
        // sample_count field: type(4) + version/flags(4) + sample_size(4)
        let count_at = pos + 4 + 4 + 4;
        m[count_at..count_at + 4].copy_from_slice(&9999u32.to_be_bytes());
        let r = analyze(&m);
        assert!((r.rubric.sample_tables - W_TABLES / 2.0).abs() < 1e-12,
                "the offset half still holds; sample_tables {}", r.rubric.sample_tables);
        assert_eq!(r.sample_bytes, Some(9999 * 4));
    }

    #[test]
    fn term_payload_exclusivity_falls_on_a_foreign_ftyp_inside_mdat() {
        // Splice a second, complete MP4 into the middle of the first one's
        // media data. This is exactly the shape /sealing_procedure.mov takes
        // when it is read contiguously across its gap.
        let inner = good_mp4(8);
        let mut m = good_mp4(256);
        let mdat_payload_at = m.len() - (256 * 4);
        let at = mdat_payload_at + 64;
        m[at..at + inner.len()].copy_from_slice(&inner);
        let r = analyze(&m);
        assert_eq!(r.foreign_header_at, Some(at as u64));
        assert_eq!(r.rubric.payload_exclusivity, 0.0);
        assert_eq!(r.rubric.tiling, W_TILING, "the box tree still tiles perfectly");
        assert_eq!(r.rubric.mdat_present, W_MDAT);
        assert!((r.validation.score - (1.0 - W_EXCLUSIVE)).abs() < 1e-12,
                "only payload_exclusivity should move, got {}", r.validation.score);
        assert!(!r.validation.valid);
        assert!(r.validation.detail.contains("another object begins inside"),
                "detail: {}", r.validation.detail);
    }

    #[test]
    fn an_accepted_mp4_states_how_many_bytes_it_could_not_verify() {
        // MP4 defines no checksum over mdat. Rule 1: the tool never claims more
        // than it verified, so the acceptance names the gap in its own detail.
        let m = good_mp4(64);
        let v = validate(&m);
        assert!(v.valid);
        assert!(v.detail.contains("256 mdat bytes are NOT covered by any checksum"),
                "detail: {}", v.detail);
    }

    #[test]
    fn weights_sum_to_one() {
        let s = W_FTYP + W_TILING + W_MOOV + W_MDAT + W_TABLES + W_EXCLUSIVE;
        assert!((s - 1.0).abs() < 1e-12, "rubric weights sum to {}", s);
    }

    // ---- rejections --------------------------------------------------------

    #[test]
    fn rejects_a_slice_that_starts_at_the_ftyp_magic_instead_of_the_box() {
        let m = good_mp4(16);
        let v = validate(&m[4..]);
        assert!(!v.valid);
        assert!(v.detail.contains("header_at = match_position - 4"), "detail: {}", v.detail);
    }

    #[test]
    fn rejects_bare_signature() {
        let v = validate(&[0, 0, 0, 20, b'f', b't', b'y', b'p']);
        assert!(!v.valid);
    }

    #[test]
    fn rejects_ftyp_over_noise() {
        let mut s: u32 = 0x1357_9BDF;
        let mut d = vec![0, 0, 0x10, 0x00, b'f', b't', b'y', b'p'];
        for _ in 0..8192 {
            s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
            d.push((s >> 16) as u8);
        }
        let v = validate(&d);
        assert!(!v.valid);
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let mut s: u32 = 0x2468_ACE0;
        for trial in 0..300 {
            let mut d = vec![0, 0, 0, 24, b'f', b't', b'y', b'p'];
            for _ in 0..(32 + trial % 173) {
                s = s.wrapping_mul(1_103_515_245).wrapping_add(12345);
                d.push((s >> 16) as u8);
            }
            let _ = validate(&d);
        }
    }
}
