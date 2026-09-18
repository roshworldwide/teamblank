use crate::structure::{validate, Validation};
use crate::Kind;

#[derive(Clone, Debug, PartialEq)]
pub struct Reassembly {
    pub extents: Vec<(u64, u64)>,
    pub validations: u64,
}

pub const MAX_FIRST_FRAGMENT_CLUSTERS: u64 = 256;

pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024;

pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 16 * 1024 * 1024;

pub const MIN_SECOND_EXTENT_CLUSTERS: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Stop {
    Solved,
    Contiguous,
    Exhausted,
    Ambiguous,
    Budget,
    Degenerate,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct Plan {
    pub header_at: u64,
    pub grid: u64,
    pub gaps: u64,
    pub first_head: u64,
    pub max_head: u64,
    pub span: u64,
    pub window: u64,
    pub budget: u64,
}

#[allow(dead_code)]
impl Plan {
    pub(crate) fn new(
        data_len: u64,
        span: u64,
        header_at: u64,
        max_gap_bytes: u64,
        grid: u64,
        max_head_bytes: u64,
    ) -> Option<Plan> {
        if grid == 0 || header_at >= data_len {
            return None;
        }
        let avail = data_len - header_at;
        let span = span.min(avail);
        if span < 2 {
            return None;
        }
        let gaps = max_gap_bytes / grid;
        if gaps == 0 {
            return None;
        }
        let first_head = ((header_at / grid) + 1) * grid - header_at;
        let max_head = max_head_bytes.min(span - 1);
        if first_head > max_head {
            return None;
        }
        let window = avail.min(gaps.saturating_mul(grid).saturating_add(span));
        Some(Plan {
            header_at,
            grid,
            gaps,
            first_head,
            max_head,
            span,
            window,
            budget: u64::MAX,
        })
    }

    pub(crate) fn splits(&self) -> u64 {
        (self.max_head - self.first_head) / self.grid + 1
    }

    pub(crate) fn lattice(&self) -> u64 {
        self.splits().saturating_mul(self.gaps)
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct Outcome {
    pub found: Option<Reassembly>,
    pub validations: u64,
    pub stop: Stop,
    pub accepted: u64,
}

fn span_ceiling(kind: Kind, avail: u64) -> u64 {
    let want = kind.as_str();
    let mut max_len = DEFAULT_MAX_OBJECT_BYTES;
    for sig in crate::signature::SIGNATURES {
        if sig.kind.as_str() == want {
            if sig.max_len > 0 {
                max_len = sig.max_len;
            }
            break;
        }
    }
    max_len.min(MAX_OBJECT_BYTES).min(avail)
}

pub fn bifragment(
    data: &[u8],
    kind: Kind,
    header_at: u64,
    max_gap_bytes: u64,
    cluster: u64,
) -> Option<Reassembly> {
    let data_len = data.len() as u64;
    if header_at >= data_len || cluster == 0 {
        return None;
    }
    let span = span_ceiling(kind, data_len - header_at);
    let plan = Plan::new(
        data_len,
        span,
        header_at,
        max_gap_bytes,
        cluster,
        MAX_FIRST_FRAGMENT_CLUSTERS.saturating_mul(cluster),
    )?;
    search(data, &plan, |buf| validate(kind, buf)).found
}

pub(crate) fn search<F>(data: &[u8], plan: &Plan, mut check: F) -> Outcome
where
    F: FnMut(&[u8]) -> Validation,
{
    let h = plan.header_at as usize;
    let window = plan.window as usize;
    let grid = plan.grid as usize;
    if window == 0 || h + window > data.len() {
        return Outcome { found: None, validations: 0, stop: Stop::Degenerate, accepted: 0 };
    }

    let mut validations: u64 = 0;

    {
        let seq_len = (plan.span as usize).min(window);
        let v = check(&data[h..h + seq_len]);
        validations += 1;
        if v.valid {
            return Outcome { found: None, validations, stop: Stop::Contiguous, accepted: 1 };
        }
        if validations >= plan.budget {
            return Outcome { found: None, validations, stop: Stop::Budget, accepted: 0 };
        }
    }

    let mut x = data[h..h + window].to_vec();
    let head_src = &data[h..];

    let mut hl = plan.first_head as usize;
    let max_head = plan.max_head as usize;
    let mut accepted: u64 = 0;
    let mut indeterminate: u64 = 0;
    let mut scratch: Vec<u8> = Vec::new();

    while hl <= max_head {
        let mut dirty_to = 0usize;

        for g in 1..=plan.gaps {
            let goff = (g as usize).saturating_mul(grid);
            if goff + hl >= window {
                break;
            }
            let len = (plan.span as usize).min(window - goff);
            if len <= hl {
                break;
            }

            x[goff..goff + hl].copy_from_slice(&head_src[..hl]);
            dirty_to = dirty_to.max(goff + hl);

            let v = check(&x[goff..goff + len]);
            validations += 1;

            if v.valid {
                if let Some(end) = v.end {
                    let end = end as usize;
                    if end <= hl {
                        return Outcome {
                            found: None,
                            validations,
                            stop: Stop::Contiguous,
                            accepted: accepted + 1,
                        };
                    }
                    if end <= len {
                        let second_len = (end - hl) as u64;
                        let resume = plan.header_at + hl as u64 + goff as u64;
                        if resume + second_len <= data.len() as u64 {
                            accepted += 1;
                            if second_len
                                < MIN_SECOND_EXTENT_CLUSTERS.saturating_mul(plan.grid)
                            {
                                indeterminate += 1;
                                if validations >= plan.budget {
                                    return Outcome {
                                        found: None,
                                        validations,
                                        stop: Stop::Budget,
                                        accepted,
                                    };
                                }
                                continue;
                            }
                            let (determined, spent) =
                                is_determined(data, plan, hl, g, &mut scratch, &mut check);
                            validations += spent;
                            if determined {
                                return Outcome {
                                    found: Some(Reassembly {
                                        extents: vec![
                                            (plan.header_at, hl as u64),
                                            (resume, second_len),
                                        ],
                                        validations,
                                    }),
                                    validations,
                                    stop: Stop::Solved,
                                    accepted,
                                };
                            }
                            indeterminate += 1;
                        }
                    }
                }
            }

            if validations >= plan.budget {
                return Outcome { found: None, validations, stop: Stop::Budget, accepted };
            }
        }

        let lo = grid.min(window);
        let hi = dirty_to.min(window);
        if hi > lo {
            x[lo..hi].copy_from_slice(&data[h + lo..h + hi]);
        }

        hl += grid;
    }

    let stop = if indeterminate > 0 { Stop::Ambiguous } else { Stop::Exhausted };
    Outcome { found: None, validations, stop, accepted }
}

fn splice(
    data: &[u8],
    plan: &Plan,
    hl: usize,
    gap_clusters: u64,
    scratch: &mut Vec<u8>,
) -> bool {
    if hl == 0 || gap_clusters == 0 {
        return false;
    }
    let h = plan.header_at as usize;
    let avail = data.len() - h;
    let goff = match (gap_clusters as usize).checked_mul(plan.grid as usize) {
        Some(v) => v,
        None => return false,
    };
    if goff >= avail {
        return false;
    }
    let len = (plan.span as usize).min(avail - goff);
    if len <= hl {
        return false;
    }
    let resume = h + hl + goff;
    if resume + (len - hl) > data.len() {
        return false;
    }
    scratch.clear();
    scratch.reserve(len);
    scratch.extend_from_slice(&data[h..h + hl]);
    scratch.extend_from_slice(&data[resume..resume + (len - hl)]);
    true
}

fn is_determined<F>(
    data: &[u8],
    plan: &Plan,
    hl: usize,
    gap: u64,
    scratch: &mut Vec<u8>,
    check: &mut F,
) -> (bool, u64)
where
    F: FnMut(&[u8]) -> Validation,
{
    let grid = plan.grid as usize;
    let neighbours: [(usize, u64, bool); 4] = [
        (hl.saturating_sub(grid), gap, true),
        (hl + grid, gap, true),
        (hl, gap.wrapping_sub(1), gap > 1),
        (hl, gap + 1, true),
    ];
    let mut spent = 0u64;
    for (nhl, ngap, required) in neighbours {
        if nhl == hl && ngap == gap {
            continue;
        }
        if !splice(data, plan, nhl, ngap, scratch) {
            if required {
                return (false, spent);
            }
            continue;
        }
        let v = check(scratch);
        spent += 1;
        if v.valid {
            return (false, spent);
        }
    }
    (true, spent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structure::Validation;
    use std::time::Instant;

    fn ok(end: u64, detail: &str) -> Validation {
        Validation { valid: true, end: Some(end), score: 1.0, detail: detail.into() }
    }
    fn bad(detail: &str) -> Validation {
        Validation { valid: false, end: None, score: 0.0, detail: detail.into() }
    }

    const MAGIC: &[u8] = b"SWOBJ";

    fn synth_object(total: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(total);
        v.extend_from_slice(MAGIC);
        v.extend_from_slice(&(total as u32).to_be_bytes());
        for i in 0..total - 9 {
            v.push(payload_byte(i));
        }
        v
    }
    fn payload_byte(i: usize) -> u8 {
        (i.wrapping_mul(31).wrapping_add(7)) as u8
    }

    fn synth_validate(buf: &[u8]) -> Validation {
        if buf.len() < 9 || &buf[..5] != MAGIC {
            return bad("no magic");
        }
        let total = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;
        if total < 9 || total > buf.len() {
            return bad("truncated");
        }
        for i in 0..total - 9 {
            if buf[9 + i] != payload_byte(i) {
                return bad("payload mismatch");
            }
        }
        ok(total as u64, "synthetic object complete")
    }

    fn plant(canvas_len: usize, obj: &[u8], extents: &[(usize, usize)]) -> Vec<u8> {
        let mut c: Vec<u8> = (0..canvas_len).map(|i| (i % 251) as u8 ^ 0xA5).collect();
        let mut cursor = 0usize;
        for &(off, len) in extents {
            c[off..off + len].copy_from_slice(&obj[cursor..cursor + len]);
            cursor += len;
        }
        assert_eq!(cursor, obj.len(), "extents must cover the object exactly");
        c
    }

    fn plan_for(
        data_len: usize,
        header_at: u64,
        max_gap_bytes: u64,
        grid: u64,
        max_head_bytes: u64,
    ) -> Plan {
        Plan::new(
            data_len as u64,
            data_len as u64 - header_at,
            header_at,
            max_gap_bytes,
            grid,
            max_head_bytes,
        )
        .expect("plan")
    }

    #[test]
    fn gap_bound_is_inclusive_at_the_boundary() {
        let cluster = 64u64;
        let max_gap_clusters = 8u64;
        let max_gap_bytes = max_gap_clusters * cluster;

        let obj = synth_object(300);
        let f1 = 3 * cluster as usize;
        let at_bound = plant(
            2048,
            &obj,
            &[(0, f1), (f1 + (max_gap_clusters as usize) * 64, obj.len() - f1)],
        );
        let p = plan_for(at_bound.len(), 0, max_gap_bytes, cluster, 16 * cluster);
        let out = search(&at_bound, &p, |b| synth_validate(b));
        assert_eq!(out.stop, Stop::Solved, "gap == max_gap_bytes must be searched");
        let r = out.found.unwrap();
        assert_eq!(
            r.extents,
            vec![
                (0, f1 as u64),
                ((f1 + max_gap_clusters as usize * 64) as u64, (obj.len() - f1) as u64)
            ]
        );

        let past = plant(
            2048,
            &obj,
            &[(0, f1), (f1 + (max_gap_clusters as usize + 1) * 64, obj.len() - f1)],
        );
        let out = search(&past, &p, |b| synth_validate(b));
        assert_eq!(out.stop, Stop::Exhausted, "gap > max_gap_bytes must be outside the search");
        assert!(out.found.is_none());
    }

    #[test]
    fn gap_bound_comes_from_the_caller() {
        let cluster = 64u64;
        let obj = synth_object(300);
        let f1 = 2 * cluster as usize;
        let gap_clusters = 5usize;
        let img = plant(
            2048,
            &obj,
            &[(0, f1), (f1 + gap_clusters * 64, obj.len() - f1)],
        );

        let tight = plan_for(img.len(), 0, 4 * cluster, cluster, 16 * cluster);
        assert_eq!(search(&img, &tight, |b| synth_validate(b)).stop, Stop::Exhausted);

        let loose = plan_for(img.len(), 0, 5 * cluster, cluster, 16 * cluster);
        assert_eq!(search(&img, &loose, |b| synth_validate(b)).stop, Stop::Solved);
    }

    #[test]
    fn search_is_confined_to_the_cluster_lattice() {
        let cluster = 64u64;
        let obj = synth_object(300);
        let f1 = 3 * cluster as usize + 17;
        let img = plant(2048, &obj, &[(0, f1), (f1 + 320, obj.len() - f1)]);
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);
        assert_eq!(search(&img, &p, |b| synth_validate(b)).stop, Stop::Exhausted);

        let p1 = plan_for(img.len(), 0, 8 * cluster, 1, 16 * cluster);
        assert_eq!(search(&img, &p1, |b| synth_validate(b)).stop, Stop::Solved);
    }

    #[test]
    fn validation_count_matches_the_published_formula() {
        let cluster = 64u64;
        let gaps = 8u64;
        let obj = synth_object(700);
        for (k, g) in [(2usize, 1u64), (3, 5), (5, 8)] {
            let f1 = k * cluster as usize;
            let img = plant(
                4096,
                &obj,
                &[(0, f1), (f1 + (g as usize) * 64, obj.len() - f1)],
            );
            let p = plan_for(img.len(), 0, gaps * cluster, cluster, 16 * cluster);
            let out = search(&img, &p, |b| synth_validate(b));
            assert_eq!(out.stop, Stop::Solved, "k={k} g={g}");
            let walk = 1 + (k as u64 - 1) * gaps + g;
            assert!(
                out.validations >= walk && out.validations <= walk + 4,
                "k={k} g={g}: {} outside [{}, {}]",
                out.validations,
                walk,
                walk + 4
            );
        }
    }

    #[test]
    fn a_head_at_the_lattice_floor_is_not_pinned_from_below() {
        let cluster = 64u64;
        let gaps = 8u64;
        let obj = synth_object(700);
        let f1 = cluster as usize;
        let img = plant(4096, &obj, &[(0, f1), (f1 + 64, obj.len() - f1)]);
        let p = plan_for(img.len(), 0, gaps * cluster, cluster, 16 * cluster);
        let out = search(&img, &p, |b| synth_validate(b));
        assert_eq!(
            out.stop,
            Stop::Ambiguous,
            "a splice at the lattice floor was stated as an object"
        );
        assert!(out.found.is_none());
        assert_eq!(out.accepted, 1, "the true splice should still be accepted");

        let f2 = 2 * cluster as usize;
        let img2 = plant(4096, &obj, &[(0, f2), (f2 + 64, obj.len() - f2)]);
        let out2 = search(&img2, &p, |b| synth_validate(b));
        assert_eq!(out2.stop, Stop::Solved);
        assert_eq!(
            out2.found.unwrap().extents,
            vec![(0, f2 as u64), ((f2 + 64) as u64, obj.len() as u64 - f2 as u64)]
        );
    }

    #[test]
    fn a_second_extent_below_the_materiality_floor_is_refused() {
        let cluster = 64u64;
        let gaps = 8u64;
        let total = 3 * cluster as usize + 20;
        let obj = synth_object(total);
        let f1 = 3 * cluster as usize;
        let img = plant(4096, &obj, &[(0, f1), (f1 + 128, obj.len() - f1)]);
        let p = plan_for(img.len(), 0, gaps * cluster, cluster, 16 * cluster);
        let out = search(&img, &p, |b| synth_validate(b));
        assert!(
            out.accepted >= 1,
            "the planted splice should still be ACCEPTED by the validator; \
             materiality is a rule about what is returned, not about what validates"
        );
        assert!(out.found.is_none(), "a {}-byte second extent was stated as an object", 20);
        assert_eq!(out.stop, Stop::Ambiguous);
    }

    #[test]
    fn exhausted_search_costs_exactly_the_lattice() {
        let cluster = 64u64;
        let img = vec![0u8; 8192];
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);
        let out = search(&img, &p, |_| bad("never"));
        assert_eq!(out.stop, Stop::Exhausted);
        assert_eq!(p.splits(), 16);
        assert_eq!(p.gaps, 8);
        assert_eq!(out.validations, 1 + p.lattice());
    }

    #[test]
    fn sliding_head_buffer_equals_a_naive_splice() {
        let cluster = 64u64;
        let data: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        for header_at in [0u64, 64, 1000 ] {
            let p = plan_for(data.len(), header_at, 6 * cluster, cluster, 10 * cluster);
            let mut seen: Vec<Vec<u8>> = Vec::new();
            search(&data, &p, |b| {
                seen.push(b.to_vec());
                bad("collect")
            });

            let mut expect: Vec<Vec<u8>> = Vec::new();
            let h = header_at as usize;
            let seq = (p.span as usize).min(p.window as usize);
            expect.push(data[h..h + seq].to_vec());
            let mut hl = p.first_head as usize;
            while hl <= p.max_head as usize {
                for g in 1..=p.gaps {
                    let goff = g as usize * cluster as usize;
                    if goff + hl >= p.window as usize {
                        break;
                    }
                    let len = (p.span as usize).min(p.window as usize - goff);
                    if len <= hl {
                        break;
                    }
                    let mut b = Vec::with_capacity(len);
                    b.extend_from_slice(&data[h..h + hl]);
                    let resume = h + hl + goff;
                    b.extend_from_slice(&data[resume..resume + (len - hl)]);
                    expect.push(b);
                }
                hl += cluster as usize;
            }
            assert_eq!(seen.len(), expect.len(), "header_at={header_at}");
            for (i, (a, b)) in seen.iter().zip(expect.iter()).enumerate() {
                assert_eq!(a, b, "candidate {i} differs, header_at={header_at}");
            }
        }
    }

    #[test]
    fn unaligned_header_still_splits_on_image_cluster_boundaries() {
        let cluster = 64u64;
        let header_at = 1000u64;
        let p = plan_for(4096, header_at, 4 * cluster, cluster, 8 * cluster);
        assert_eq!(p.first_head, 24, "first split is the next boundary at 1024");
        assert_eq!((header_at + p.first_head) % cluster, 0);
        for k in 0..p.splits() {
            let hl = p.first_head + k * cluster;
            assert_eq!((header_at + hl) % cluster, 0, "split point off-grid");
            for g in 1..=p.gaps {
                assert_eq!((header_at + hl + g * cluster) % cluster, 0, "resume point off-grid");
            }
        }
    }

    #[test]
    fn three_fragments_are_not_solved_by_a_two_fragment_search() {
        let cluster = 64usize;
        let obj = synth_object(9 * cluster + 13 * cluster + 400);
        let e1 = 9 * cluster;
        let e2 = 13 * cluster;
        let e3 = obj.len() - e1 - e2;
        let o1 = 0usize;
        let o2 = o1 + e1 + 11 * cluster;
        let o3 = o2 + e2 + 29 * cluster;
        let img = plant(o3 + e3 + 4096, &obj, &[(o1, e1), (o2, e2), (o3, e3)]);

        let p = plan_for(img.len(), 0, 128 * cluster as u64, cluster as u64, 256 * cluster as u64);
        let out = search(&img, &p, |b| synth_validate(b));
        assert!(out.found.is_none(), "a two-fragment search must not solve three fragments");
        assert_eq!(out.stop, Stop::Exhausted, "it must terminate cleanly, not run away");
        assert!(
            out.validations <= 1 + p.lattice(),
            "cost must stay inside the published bound: {} > {}",
            out.validations,
            1 + p.lattice()
        );
    }

    #[test]
    fn reversed_object_is_not_solved_by_a_forward_search() {
        let cluster = 64usize;
        let obj = synth_object(18 * cluster + 600);
        let e1 = 18 * cluster;
        let e2 = obj.len() - e1;
        let o2 = 1000 * cluster;
        let o1 = o2 + 77 * cluster;
        let img = plant(o1 + e1 + 4096, &obj, &[(o1, e1), (o2, e2)]);

        let p = plan_for(img.len(), o1 as u64, 128 * cluster as u64, cluster as u64, 256 * cluster as u64);
        let out = search(&img, &p, |b| synth_validate(b));
        assert!(out.found.is_none(), "a forward search must not solve a reversed object");
        assert_eq!(out.stop, Stop::Exhausted);

        let mut whole = Vec::new();
        whole.extend_from_slice(&img[o1..o1 + e1]);
        whole.extend_from_slice(&img[o2..o2 + e2]);
        assert!(synth_validate(&whole).valid, "the reversed object is intact in the image");
    }

    #[test]
    fn a_validator_blind_to_part_of_the_object_yields_a_refusal() {
        let cluster = 64u64;
        let obj = synth_object(600);
        let f1 = 4 * cluster as usize;
        let gap = 3usize;
        let img = plant(4096, &obj, &[(0, f1), (f1 + gap * 64, obj.len() - f1)]);
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);

        let out = search(&img, &p, |b| synth_validate(b));
        assert_eq!(out.stop, Stop::Solved);
        assert_eq!(
            out.found.unwrap().extents,
            vec![(0, f1 as u64), ((f1 + gap * 64) as u64, (obj.len() - f1) as u64)]
        );

        let partial = |b: &[u8]| {
            if b.len() < 9 || &b[..5] != MAGIC {
                return bad("no magic");
            }
            let total = u32::from_be_bytes([b[5], b[6], b[7], b[8]]) as usize;
            if total < 9 + 128 || total > b.len() {
                return bad("truncated");
            }
            let body = total - 9;
            for i in (0..64).chain(body - 64..body) {
                if b[9 + i] != payload_byte(i) {
                    return bad("end mismatch");
                }
            }
            ok(total as u64, "ends only, body unchecked")
        };
        let out = search(&img, &p, partial);
        assert!(out.found.is_none(), "an undetermined splice must not be returned");
        assert_eq!(out.stop, Stop::Ambiguous, "and the refusal must say why");
    }

    #[test]
    fn determinacy_cost_is_counted() {
        let cluster = 64u64;
        let obj = synth_object(600);
        let f1 = 4 * cluster as usize;
        let img = plant(4096, &obj, &[(0, f1), (f1 + 3 * 64, obj.len() - f1)]);
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);
        let out = search(&img, &p, |b| synth_validate(b));
        let first_hit = 1 + (4 - 1) * p.gaps + 3;
        assert_eq!(out.validations, first_hit + 4, "probe + lattice walk + 4 neighbours");
    }

    #[test]
    fn contiguous_object_is_refused_after_one_validation() {
        let cluster = 64u64;
        let obj = synth_object(300);
        let img = plant(2048, &obj, &[(0, obj.len())]);
        let p = plan_for(img.len(), 0, 8 * cluster, cluster, 16 * cluster);
        let out = search(&img, &p, |b| synth_validate(b));
        assert_eq!(out.stop, Stop::Contiguous);
        assert!(out.found.is_none());
        assert_eq!(out.validations, 1);
    }

    #[test]
    fn valid_without_an_end_is_not_a_recovery() {
        let cluster = 64u64;
        let img = vec![7u8; 4096];
        let p = plan_for(img.len(), 0, 4 * cluster, cluster, 8 * cluster);
        let out = search(&img, &p, |_| Validation {
            valid: true,
            end: None,
            score: 1.0,
            detail: "no end".into(),
        });
        assert!(out.found.is_none());
    }

    #[test]
    fn degenerate_inputs_terminate() {
        let img = vec![0u8; 1024];
        assert!(Plan::new(1024, 1024, 0, 0, 64, 512).is_none(), "gap bound below one cluster");
        assert!(Plan::new(1024, 1024, 0, 256, 0, 512).is_none(), "zero cluster");
        assert!(Plan::new(1024, 1024, 2000, 256, 64, 512).is_none(), "header past the end");
        assert!(Plan::new(1024, 1, 0, 256, 64, 512).is_none(), "no room for two extents");
        let p = plan_for(img.len(), 0, 4 * 64, 64, 8 * 64);
        let out = search(&img, &p, |_| bad("x"));
        assert_eq!(out.stop, Stop::Exhausted);
    }

    #[test]
    fn cluster_grid_versus_byte_grid_is_measured() {
        let cluster = 64u64;
        let max_head_bytes = 8 * cluster;
        let max_gap_bytes = 8 * cluster;
        let obj = synth_object(400);
        let f1 = 3 * cluster as usize;
        let gap = 2 * cluster as usize;
        let img = plant(4096, &obj, &[(0, f1), (f1 + gap, obj.len() - f1)]);

        let pc = plan_for(img.len(), 0, max_gap_bytes, cluster, max_head_bytes);
        let t0 = Instant::now();
        let oc = search(&img, &pc, |b| synth_validate(b));
        let tc = t0.elapsed();

        let pb = plan_for(img.len(), 0, max_gap_bytes, 1, max_head_bytes);
        let t0 = Instant::now();
        let ob = search(&img, &pb, |b| synth_validate(b));
        let tb = t0.elapsed();

        assert_eq!(oc.stop, Stop::Solved);
        assert_eq!(ob.stop, Stop::Solved);
        assert_eq!(oc.found.as_ref().unwrap().extents, ob.found.as_ref().unwrap().extents);

        println!(
            "GRID  cluster={} lattice={} validations={} elapsed={:?}",
            cluster, pc.lattice(), oc.validations, tc
        );
        println!(
            "GRID  byte    lattice={} validations={} elapsed={:?}",
            pb.lattice(), ob.validations, tb
        );
        println!(
            "GRID  ratio   validations={:.1}x  lattice={:.1}x  (cluster^2 = {})",
            ob.validations as f64 / oc.validations as f64,
            pb.lattice() as f64 / pc.lattice() as f64,
            cluster * cluster
        );
        assert!(ob.validations > oc.validations * 100, "the byte grid must cost far more");
    }

    const FIXTURE_BYTES: u64 = 268_435_456;
    const CLUSTER: u64 = 2048;
    const MAX_GAP_CLUSTERS: u64 = 128;

    struct Plant {
        name: &'static str,
        kind: &'static str,
        header_at: u64,
        extents: &'static [(u64, u64)],
        recoverable: bool,
        determined: bool,
        finding: &'static str,
    }

    const PLANT_REJECTED_CEILING: f64 = 0.989_285_714_285_714_2;

    const PLANT_TRIFRAGMENT_REJECTED_CEILING: f64 = 0.957_142_857_142_857_1;

    const PLANTS: &[Plant] = &[
        Plant {
            name: "imaging_transcript.txt.gz",
            kind: "gzip",
            header_at: 143_464_448,
            extents: &[(143_464_448, 69_632), (143_566_848, 57_670)],
            recoverable: true,
            determined: true,
            finding: "",
        },
        Plant {
            name: "entropy_heatmap.png",
            kind: "png",
            header_at: 51_361_792,
            extents: &[(51_361_792, 73_728), (51_437_568, 109_622)],
            recoverable: true,
            determined: true,
            finding: "",
        },
        Plant {
            name: "disposal_certificate.pdf",
            kind: "pdf",
            header_at: 170_430_464,
            extents: &[(170_430_464, 12_288), (170_704_896, 33_768)],
            recoverable: true,
            determined: false,
            finding: "structure::pdf verifies 34/34 xref offsets but decodes no \
                      stream body, so 10 splices validate and 9 are the wrong \
                      bytes; a per-stream inflate + Adler-32 leaves exactly 1",
        },
        Plant {
            name: "sealing_procedure.mov",
            kind: "mp4",
            header_at: 65_796_096,
            extents: &[(65_796_096, 90_112), (65_988_608, 130_929)],
            recoverable: true,
            determined: false,
            finding: "MP4 declares mdat's length in fragment 1 and carries no \
                      checksum over it, so 6660 splices validate and exactly 1 \
                      is the planted bytes; not repairable by any structure \
                      validator, the container has no field to check",
        },
        Plant {
            name: "handover_briefing.mov",
            kind: "mp4",
            header_at: 65_943_552,
            extents: &[(65_943_552, 32_768), (66_119_680, 33_921)],
            recoverable: true,
            determined: false,
            finding: "same MP4 limit as its twin (4096 splices validate, 1 is \
                      the planted bytes); worse, structure::mp4 accepts the \
                      CONTIGUOUS read at this header, so sequential carving \
                      emits 66 689 bytes with the wrong SHA-256 before \
                      bifragment is ever consulted",
        },
        Plant {
            name: "media_inventory.docx",
            kind: "zip",
            header_at: 1_069_056,
            extents: &[],
            recoverable: false,
            determined: false,
            finding: "planted: three fragments, unsolvable by a two-fragment search",
        },
        Plant {
            name: "evidence_bag_seal.jpg",
            kind: "jpeg",
            header_at: 214_231_040,
            extents: &[],
            recoverable: false,
            determined: false,
            finding: "planted: physically reversed, unsolvable by a forward search",
        },
    ];

    fn kind_by_str(s: &str) -> Option<Kind> {
        for sig in crate::signature::SIGNATURES {
            if sig.kind.as_str().eq_ignore_ascii_case(s) {
                return Some(sig.kind);
            }
        }
        None
    }

    fn load_fixture() -> Option<Vec<u8>> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../out/fixture.img");
        let data = std::fs::read(p).ok()?;
        if data.len() as u64 != FIXTURE_BYTES {
            eprintln!("FIXTURE  wrong length {} — skipping", data.len());
            return None;
        }
        Some(data)
    }

    #[test]
    fn fixture_solvable_fragments_are_recovered_or_refused_never_wrong() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let max_gap_bytes = MAX_GAP_CLUSTERS * CLUSTER;
        let mut recovered = 0;
        let mut refused = 0;
        let mut wrong: Vec<String> = Vec::new();
        let mut missing: Vec<String> = Vec::new();

        for p in PLANTS.iter().filter(|p| p.recoverable) {
            let Some(kind) = kind_by_str(p.kind) else {
                missing.push(format!("{}: no signature for kind {}", p.name, p.kind));
                continue;
            };
            let span = span_ceiling(kind, data.len() as u64 - p.header_at);
            let plan = Plan::new(
                data.len() as u64,
                span,
                p.header_at,
                max_gap_bytes,
                CLUSTER,
                MAX_FIRST_FRAGMENT_CLUSTERS * CLUSTER,
            )
            .expect("plan");
            let t0 = Instant::now();
            let out = search(&data, &plan, |b| validate(kind, b));
            let el = t0.elapsed();
            match out.found {
                Some(r) => {
                    let ok = r.extents == p.extents;
                    let gap = (r.extents[1].0 - (r.extents[0].0 + r.extents[0].1)) / CLUSTER;
                    let mut got = Vec::new();
                    for &(off, len) in &r.extents {
                        got.extend_from_slice(&data[off as usize..(off + len) as usize]);
                    }
                    let bytes_ok = Some(&got) == true_bytes(&data, p).as_ref();
                    println!(
                        "CARVE  {:<26} RECOVERED extents={:?} gap={}cl size={} validations={} accepted={} elapsed={:?} manifest_match={} bytes_match={}",
                        p.name, r.extents, gap, got.len(), r.validations, out.accepted, el, ok, bytes_ok
                    );
                    assert!(bytes_ok, "{}: recovered bytes are not the planted file", p.name);
                    assert_eq!(p.header_at % CLUSTER, 0, "{}: header off-grid", p.name);
                    let walk = (r.extents[0].1 / CLUSTER - 1) * plan.gaps + gap;
                    assert!(
                        r.validations >= 1 + walk && r.validations <= 1 + walk + 4,
                        "{}: {} validations outside the published [{}, {}]",
                        p.name,
                        r.validations,
                        1 + walk,
                        1 + walk + 4
                    );
                    if ok {
                        recovered += 1;
                    } else {
                        wrong.push(format!(
                            "{}: {:?} != manifest {:?}",
                            p.name, r.extents, p.extents
                        ));
                    }
                }
                None => {
                    refused += 1;
                    println!(
                        "CARVE  {:<26} REFUSED   stop={:?} accepted={} validations={} lattice={} elapsed={:?}",
                        p.name, out.stop, out.accepted, out.validations, plan.lattice(), el
                    );
                    println!("       FINDING  {}: {}", p.name, p.finding);
                    if p.determined {
                        missing.push(format!("{}: refused but expected exact", p.name));
                    }
                }
            }
        }
        println!("CARVE  fragmented: {recovered} recovered exactly, {refused} refused, {} wrong", wrong.len());

        assert!(wrong.is_empty(), "wrong-but-validating reassembly: {}", wrong.join("; "));
        assert!(missing.is_empty(), "{}", missing.join("; "));
        let want = PLANTS.iter().filter(|p| p.recoverable && p.determined).count();
        if recovered > want {
            println!(
                "CARVE  {recovered} recovered, {want} expected: structure::validate now \
                 pins more plants than when this table was measured. Promote them to \
                 `determined: true` so the floor rises with it."
            );
        }
        assert!(
            recovered >= want,
            "expected at least {want} exact recoveries, got {recovered}. A shortfall \
             is a regression in structure::validate's coverage of the object body, \
             not in the search: this module recovers exactly those plants the \
             validator pins to one splice, and refuses the rest by name."
        );
    }

    #[test]
    fn fixture_two_planted_failures_fail_and_say_so() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let max_gap_bytes = MAX_GAP_CLUSTERS * CLUSTER;
        for p in PLANTS.iter().filter(|p| !p.recoverable) {
            let Some(kind) = kind_by_str(p.kind) else {
                panic!("no signature for kind {}", p.kind);
            };
            let span = span_ceiling(kind, data.len() as u64 - p.header_at);
            let plan = Plan::new(
                data.len() as u64,
                span,
                p.header_at,
                max_gap_bytes,
                CLUSTER,
                MAX_FIRST_FRAGMENT_CLUSTERS * CLUSTER,
            )
            .expect("plan");
            let t0 = Instant::now();
            let out = search(&data, &plan, |b| validate(kind, b));
            let el = t0.elapsed();
            println!(
                "CARVE  {:<26} stop={:?} accepted={} validations={} lattice={} elapsed={:?}",
                p.name, out.stop, out.accepted, out.validations, plan.lattice(), el
            );
            assert_eq!(
                out.accepted, 0,
                "{} must not produce even a candidate: a two-fragment forward search \
                 cannot assemble it, and any acceptance would be residue passing \
                 structure validation",
                p.name
            );
            assert!(
                out.found.is_none(),
                "{} must not be recovered by a two-fragment forward search",
                p.name
            );
            assert!(
                matches!(out.stop, Stop::Exhausted | Stop::Ambiguous),
                "{} must terminate cleanly, got {:?}",
                p.name,
                out.stop
            );
        }
    }

    #[test]
    fn fixture_byte_grid_control_does_not_finish() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let p = &PLANTS[2];
        let kind = kind_by_str(p.kind).expect("pdf signature");
        let max_gap_bytes = MAX_GAP_CLUSTERS * CLUSTER;
        let span = 65_536u64;
        let max_head_bytes = 31 * CLUSTER;

        let pc = Plan::new(
            data.len() as u64, span, p.header_at, max_gap_bytes, CLUSTER, max_head_bytes,
        )
        .expect("cluster plan");
        let t0 = Instant::now();
        let oc = search(&data, &pc, |b| validate(kind, b));
        let tc = t0.elapsed();

        let mut pb = Plan::new(
            data.len() as u64, span, p.header_at, max_gap_bytes, 1, max_head_bytes,
        )
        .expect("byte plan");
        pb.budget = 250_000;
        let t0 = Instant::now();
        let ob = search(&data, &pb, |b| validate(kind, b));
        let tb = t0.elapsed();

        println!(
            "GRID  fixture cluster lattice={} validations={} stop={:?} elapsed={:?}",
            pc.lattice(), oc.validations, oc.stop, tc
        );
        println!(
            "GRID  fixture byte    lattice={} validations={} stop={:?} elapsed={:?}",
            pb.lattice(), ob.validations, ob.stop, tb
        );
        println!(
            "GRID  fixture lattice ratio = {} (cluster^2 = {})",
            pb.lattice() / pc.lattice().max(1),
            CLUSTER * CLUSTER
        );
        assert_eq!(ob.stop, Stop::Budget, "the byte grid must not finish inside the budget");
        assert!(ob.found.is_none());
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Hit {
        hl: u64,
        g: u64,
        end: u64,
        determined: bool,
        content_ok: bool,
    }

    fn enumerate_lattice<F>(
        data: &[u8],
        plan: &Plan,
        truth: Option<&[u8]>,
        mut check: F,
    ) -> (Vec<Hit>, u64)
    where
        F: FnMut(&[u8]) -> Validation,
    {
        let mut hits = Vec::new();
        let mut validations = 0u64;
        let mut scratch = Vec::new();
        let mut hl = plan.first_head;
        while hl <= plan.max_head {
            for g in 1..=plan.gaps {
                if !splice(data, plan, hl as usize, g, &mut scratch) {
                    continue;
                }
                let v = check(&scratch);
                validations += 1;
                if !v.valid {
                    continue;
                }
                let Some(end) = v.end else { continue };
                if end <= hl || end > scratch.len() as u64 {
                    continue;
                }
                let content_ok = match truth {
                    Some(t) => t.len() as u64 == end && t == &scratch[..end as usize],
                    None => false,
                };
                let mut probe = Vec::new();
                let (determined, spent) =
                    is_determined(data, plan, hl as usize, g, &mut probe, &mut check);
                validations += spent;
                hits.push(Hit { hl, g, end, determined, content_ok });
            }
            hl += plan.grid;
        }
        (hits, validations)
    }

    fn fixture_plan(data_len: u64, kind: Kind, header_at: u64) -> Plan {
        let span = span_ceiling(kind, data_len - header_at);
        Plan::new(
            data_len,
            span,
            header_at,
            MAX_GAP_CLUSTERS * CLUSTER,
            CLUSTER,
            MAX_FIRST_FRAGMENT_CLUSTERS * CLUSTER,
        )
        .expect("plan")
    }

    fn true_bytes(data: &[u8], p: &Plant) -> Option<Vec<u8>> {
        if p.extents.is_empty() {
            return None;
        }
        let mut v = Vec::new();
        for &(off, len) in p.extents {
            v.extend_from_slice(&data[off as usize..(off + len) as usize]);
        }
        Some(v)
    }

    fn true_splice(p: &Plant) -> Option<(u64, u64)> {
        if p.extents.len() != 2 {
            return None;
        }
        let hl = p.extents[0].1;
        let gap = p.extents[1].0 - (p.extents[0].0 + p.extents[0].1);
        Some((hl, gap / CLUSTER))
    }

    #[test]
    #[ignore = "walks the full 32768-cell lattice for seven plants; run with --release"]
    fn fixture_lattice_enumeration_measures_ambiguity() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let mut wrong: Vec<String> = Vec::new();
        for p in PLANTS {
            let kind = kind_by_str(p.kind).expect("kind");
            let plan = fixture_plan(data.len() as u64, kind, p.header_at);
            let truth_bytes = true_bytes(&data, p);
            let t0 = Instant::now();
            let (hits, validations) =
                enumerate_lattice(&data, &plan, truth_bytes.as_deref(), |b| validate(kind, b));
            let el = t0.elapsed();
            let det: Vec<&Hit> = hits.iter().filter(|h| h.determined).collect();
            let right = hits.iter().filter(|h| h.content_ok).count();
            let truth = true_splice(p);
            let true_accepts = truth
                .map(|(hl, g)| hits.iter().any(|h| h.hl == hl && h.g == g))
                .unwrap_or(false);
            println!(
                "LATTICE {:<26} cells={} accepting={} content_correct={} determined={} true_splice={:?} true_accepted={} validations={} elapsed={:?}",
                p.name,
                plan.lattice(),
                hits.len(),
                right,
                det.len(),
                truth,
                true_accepts,
                validations,
                el
            );
            for h in hits.iter().take(12) {
                println!(
                    "        hit hl={} ({} cl) gap={} cl end={} determined={} content_ok={}",
                    h.hl,
                    h.hl / CLUSTER,
                    h.g,
                    h.end,
                    h.determined,
                    h.content_ok
                );
            }
            if hits.len() > 12 {
                println!("        ... {} more accepting splices", hits.len() - 12);
            }
            if !p.extents.is_empty() {
                assert_eq!(
                    right, 1,
                    "{}: exactly one accepting splice must be the planted bytes",
                    p.name
                );
                assert!(true_accepts, "{}: the manifest's own splice must be accepted", p.name);
            }
            for h in hits.iter().filter(|h| h.determined) {
                assert!(
                    h.content_ok,
                    "{}: determined splice hl={} gap={} is content-WRONG",
                    p.name, h.hl, h.g
                );
            }

            for h in det {
                if truth != Some((h.hl, h.g)) {
                    wrong.push(format!(
                        "{}: determined splice hl={} gap={} is not the manifest's {:?}",
                        p.name, h.hl, h.g, truth
                    ));
                }
            }
            if !p.recoverable {
                assert!(
                    hits.is_empty(),
                    "{} is planted unsolvable: the lattice must accept nothing, got {:?}",
                    p.name,
                    hits
                );
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("; "));

        let pdf = PLANTS.iter().find(|p| p.name == "disposal_certificate.pdf").unwrap();
        let (hl, g) = true_splice(pdf).unwrap();
        assert_eq!(g, MAX_GAP_CLUSTERS, "the boundary plant must sit on the bound");
        let kind = kind_by_str(pdf.kind).unwrap();
        let plan = fixture_plan(data.len() as u64, kind, pdf.header_at);
        assert_eq!(plan.gaps, MAX_GAP_CLUSTERS, "gap {g} must be inside an inclusive bound");
        let mut scratch = Vec::new();
        assert!(splice(&data, &plan, hl as usize, g, &mut scratch));
        let v = validate(kind, &scratch);
        println!(
            "LATTICE boundary  disposal_certificate.pdf hl={hl} gap={g} valid={} end={:?} score={:.2} detail={}",
            v.valid, v.end, v.score, v.detail
        );
        assert!(
            v.valid && v.end == Some(46_056),
            "the manifest's own splice must validate at the inclusive bound: {v:?}"
        );
    }

    #[test]
    fn fixture_public_entry_point_recovers_png_and_honours_the_gap_bound() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let p = PLANTS.iter().find(|p| p.name == "entropy_heatmap.png").unwrap();
        let kind = kind_by_str(p.kind).unwrap();

        let t0 = Instant::now();
        let got = bifragment(&data, kind, p.header_at, MAX_GAP_CLUSTERS * CLUSTER, CLUSTER);
        let el = t0.elapsed();
        let r = got.expect("entropy_heatmap.png must be recovered through the public entry point");
        println!(
            "PUBLIC entropy_heatmap.png extents={:?} validations={} elapsed={:?}",
            r.extents, r.validations, el
        );
        assert_eq!(r.extents, p.extents, "extents must be the manifest's, byte for byte");
        assert_eq!(
            r.extents.iter().map(|e| e.1).sum::<u64>(),
            183_350,
            "reassembled length must be the manifest's size"
        );

        let tight = bifragment(&data, kind, p.header_at, CLUSTER, CLUSTER)
            .expect("a one-cluster inclusive bound must contain a one-cluster gap");
        assert_eq!(tight.extents, p.extents);
        assert!(
            tight.validations < r.validations,
            "a tighter bound must cost less: {} vs {}",
            tight.validations,
            r.validations
        );
        println!(
            "PUBLIC entropy_heatmap.png gap_bound=1cl validations={} (128cl cost {})",
            tight.validations, r.validations
        );
        assert!(
            bifragment(&data, kind, p.header_at, CLUSTER - 1, CLUSTER).is_none(),
            "a bound below one cluster describes no lattice and must recover nothing"
        );

        let jpg = PLANTS.iter().find(|p| p.name == "evidence_bag_seal.jpg").unwrap();
        let jk = kind_by_str(jpg.kind).unwrap();
        assert!(
            bifragment(&data, jk, jpg.header_at, MAX_GAP_CLUSTERS * CLUSTER, CLUSTER).is_none(),
            "the reversed plant must not be recovered through the public entry point"
        );
        assert!(
            bifragment(&data, kind, data.len() as u64, MAX_GAP_CLUSTERS * CLUSTER, CLUSTER)
                .is_none(),
            "a header at the end of the image must not panic"
        );
        assert!(
            bifragment(&data, kind, p.header_at, MAX_GAP_CLUSTERS * CLUSTER, 0).is_none(),
            "a zero cluster size must not panic"
        );
    }

    #[test]
    #[ignore = "three full-lattice PDF searches, the widest at a 64 MiB span"]
    fn span_ceiling_cost_is_measured() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let p = PLANTS.iter().find(|p| p.name == "disposal_certificate.pdf").unwrap();
        let kind = kind_by_str(p.kind).unwrap();
        for span in [64 * 1024 * 1024u64, 4 * 1024 * 1024, MAX_OBJECT_BYTES] {
            let plan = Plan::new(
                data.len() as u64,
                span,
                p.header_at,
                MAX_GAP_CLUSTERS * CLUSTER,
                CLUSTER,
                MAX_FIRST_FRAGMENT_CLUSTERS * CLUSTER,
            )
            .expect("plan");
            let t0 = Instant::now();
            let out = search(&data, &plan, |b| validate(kind, b));
            println!(
                "SPAN  ceiling={:>9} validations={} stop={:?} elapsed={:?}",
                span,
                out.validations,
                out.stop,
                t0.elapsed()
            );
        }
    }


    const CONTROL_DOCX_AT: u64 = 85_690_368;
    const CONTROL_DOCX_LEN: u64 = 63_749;

    #[test]
    fn a_real_docx_recovers_at_two_fragments_and_refuses_at_three() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let at = CONTROL_DOCX_AT as usize;
        let obj = &data[at..at + CONTROL_DOCX_LEN as usize];
        let cluster = CLUSTER as usize;
        let gap = 4 * cluster;
        let filler = |n: usize| -> Vec<u8> { (0..n).map(|i| (i % 97) as u8 + 1).collect() };

        let split = 8 * cluster;
        let mut two = filler(obj.len() + gap + 4 * cluster);
        two[..split].copy_from_slice(&obj[..split]);
        two[split + gap..split + gap + obj.len() - split].copy_from_slice(&obj[split..]);
        let got = bifragment(&two, Kind::Zip, 0, 8 * CLUSTER, CLUSTER)
            .expect("a real DOCX in two forward fragments was not reassembled");
        let mut bytes: Vec<u8> = Vec::new();
        for (o, l) in &got.extents {
            bytes.extend_from_slice(&two[*o as usize..(*o + *l) as usize]);
        }
        assert_eq!(bytes, obj, "the two-fragment reassembly is not the file's bytes");

        let a = 6 * cluster;
        let b = 6 * cluster;
        let mut three = filler(obj.len() + 2 * gap + 4 * cluster);
        three[..a].copy_from_slice(&obj[..a]);
        three[a + gap..a + gap + b].copy_from_slice(&obj[a..a + b]);
        let tail_at = a + gap + b + gap;
        three[tail_at..tail_at + obj.len() - a - b].copy_from_slice(&obj[a + b..]);
        let none = bifragment(&three, Kind::Zip, 0, 8 * CLUSTER, CLUSTER);
        println!(
            "TRI-FRAGMENT CONTROL  /incident_summary.docx, {} bytes, real OOXML: 2 forward \
             fragments -> RECOVERED byte-exact in {} validations; 3 forward fragments -> {}. \
             The refusal is about the fragment count, not the kind.",
            obj.len(),
            got.validations,
            match &none {
                None => "refused".to_string(),
                Some(r) => format!("{:?}", r.extents),
            }
        );
        assert!(
            none.is_none(),
            "a two-fragment search solved a three-fragment object: {none:?}"
        );
    }

    const REAL_JPEG_HEADER_AT: u64 = 200_210_432;

    const LAST_PLANTED_BYTE_END: u64 = 236_487_573;
    const FREE_SPACE_FROM: u64 = 240 * 1024 * 1024;

    const FABRICATION_SAMPLE: u64 = 100;
    const FABRICATION_STRIDE_CLUSTERS: u64 = 81;

    const FABRICATED_OF_SAMPLE: usize = 2;

    #[test]
    fn a_real_header_prefix_over_free_space_does_not_manufacture_an_object() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        assert!(
            LAST_PLANTED_BYTE_END < FREE_SPACE_FROM,
            "the manifest's last planted byte moved past {FREE_SPACE_FROM}; this measurement is \
             no longer over free space"
        );
        let max_gap_bytes = MAX_GAP_CLUSTERS * CLUSTER;
        let src = REAL_JPEG_HEADER_AT as usize;
        let header = data[src..src + CLUSTER as usize].to_vec();
        let mut copy = data.clone();

        let probe = |copy: &mut Vec<u8>, at: u64| -> Option<Reassembly> {
            let a = at as usize;
            copy[a..a + CLUSTER as usize].copy_from_slice(&header);
            let out = bifragment(copy, Kind::Jpeg, at, max_gap_bytes, CLUSTER);
            copy[a..a + CLUSTER as usize]
                .copy_from_slice(&data[a..a + CLUSTER as usize]);
            out
        };

        let reported = probe(&mut copy, 253_691_904);
        println!("FABRICATION  the reported case, JPEG@253691904: {reported:?}");
        assert!(
            reported.is_none(),
            "the search still answers the reported fabrication with {reported:?}"
        );

        let t0 = Instant::now();
        let mut fabricated: Vec<String> = Vec::new();
        for k in 0..FABRICATION_SAMPLE {
            let at = FREE_SPACE_FROM + k * FABRICATION_STRIDE_CLUSTERS * CLUSTER;
            assert!(at + CLUSTER < data.len() as u64);
            if let Some(r) = probe(&mut copy, at) {
                let second = r.extents[1];
                assert!(
                    second.1 >= MIN_SECOND_EXTENT_CLUSTERS * CLUSTER,
                    "a returned splice is below the materiality floor: {r:?}"
                );
                fabricated.push(format!("JPEG@{at} -> {:?}", r.extents));
            }
        }
        let el = t0.elapsed();
        println!(
            "FABRICATION  one real 2048-byte JPEG header prefix (from {REAL_JPEG_HEADER_AT}) \
             written onto each of {FABRICATION_SAMPLE} free offsets {FABRICATION_STRIDE_CLUSTERS} \
             clusters apart from {FREE_SPACE_FROM}, nothing else changed, {el:?}"
        );
        println!(
            "FABRICATION  {} of {FABRICATION_SAMPLE} answered with a two-extent object that is \
             not in the image: [{}]",
            fabricated.len(),
            fabricated.join(", ")
        );
        println!(
            "FABRICATION  13 of {FABRICATION_SAMPLE} before the two-sided determinacy rule, 6 \
             after it, {} after MIN_SECOND_EXTENT_CLUSTERS. The rest is a structure::jpeg limit, \
             named on FABRICATED_OF_SAMPLE, and it is the reason --reassemble is off by default.",
            fabricated.len()
        );
        assert_eq!(
            fabricated.len(),
            FABRICATED_OF_SAMPLE,
            "the fabrication rate over free space moved from the published \
             {FABRICATED_OF_SAMPLE} of {FABRICATION_SAMPLE} to {}. Republish it in either \
             direction; a stale number here is the one an operator would quote.",
            fabricated.len()
        );
    }

    #[test]
    fn reassembly_does_not_lift_a_residue_candidate_past_its_contiguous_credit() {
        let Some(data) = load_fixture() else {
            eprintln!("FIXTURE  out/fixture.img absent — run `make fixtures`. Skipping.");
            return;
        };
        let breach = crate::confidence::STRUCTURAL_BREACH_POINT;
        let max_gap_bytes = MAX_GAP_CLUSTERS * CLUSTER;
        let plant_at = |at: u64| PLANTS.iter().find(|p| p.header_at == at);

        struct PlantRow {
            name: &'static str,
            kind: &'static str,
            at: u64,
            baseline: f64,
            hi_rejected: f64,
            hi_rejected_detail: String,
            hi_accepted: f64,
            solved: bool,
        }
        let mut plant_validations = 0u64;
        let mut plant_time = std::time::Duration::ZERO;
        let mut plant_contiguous: Vec<String> = Vec::new();
        let mut plant_rows: Vec<PlantRow> = Vec::new();

        let t_scan = Instant::now();
        let cands = crate::signature::scan(&data);
        let scan_elapsed = t_scan.elapsed();

        let mut examined = 0u64;
        let mut contiguous = 0u64;
        let mut validations = 0u64;
        let mut accepted_total = 0u64;
        let mut worst_accepted = 0.0f64;
        let mut worst_lattice = 0.0f64;
        let mut worst_lattice_at = 0u64;
        let mut worst_baseline = 0.0f64;
        let mut worst_baseline_at = 0u64;
        let mut over_breach_contiguously = 0u64;
        let mut lifted: Vec<String> = Vec::new();
        let mut lifted_accepted: Vec<String> = Vec::new();
        let mut reassembled: Vec<String> = Vec::new();
        let mut by_kind: Vec<(&'static str, u64, u64, u64)> = Vec::new();

        let t0 = Instant::now();
        for c in &cands {
            let plant = plant_at(c.header_at);
            let avail = data.len() as u64 - c.header_at;
            let span = span_ceiling(c.kind, avail);
            let at = c.header_at as usize;
            let seq_len = (span as usize).min(data.len() - at);

            let seq = validate(c.kind, &data[at..at + seq_len]);
            let baseline = crate::confidence::structural_validity(&seq);
            if seq.valid {
                contiguous += 1;
                if let Some(p) = plant {
                    plant_contiguous.push(format!("{} {}@{}", p.name, c.kind.as_str(), c.header_at));
                }
                continue;
            }
            let Some(plan) = Plan::new(
                data.len() as u64,
                span,
                c.header_at,
                max_gap_bytes,
                CLUSTER,
                MAX_FIRST_FRAGMENT_CLUSTERS * CLUSTER,
            ) else {
                continue;
            };

            if let Some(p) = plant {
                let t_plant = Instant::now();
                let mut hi = 0.0f64;
                let mut hi_detail = String::new();
                let mut hi_accepted = 0.0f64;
                let out = search(&data, &plan, |b| {
                    let v = validate(c.kind, b);
                    let credit = crate::confidence::structural_validity(&v);
                    if v.valid {
                        if credit > hi_accepted {
                            hi_accepted = credit;
                        }
                    } else if credit > hi {
                        hi = credit;
                        hi_detail = v.detail.clone();
                    }
                    v
                });
                plant_validations += out.validations;
                plant_time += t_plant.elapsed();
                plant_rows.push(PlantRow {
                    name: p.name,
                    kind: c.kind.as_str(),
                    at: c.header_at,
                    baseline,
                    hi_rejected: hi,
                    hi_rejected_detail: hi_detail,
                    hi_accepted,
                    solved: out.found.is_some(),
                });
                continue;
            }

            examined += 1;
            if baseline >= breach {
                over_breach_contiguously += 1;
            }
            if baseline > worst_baseline {
                worst_baseline = baseline;
                worst_baseline_at = c.header_at;
            }

            let mut hi_accepted = 0.0f64;
            let mut hi_lattice = 0.0f64;
            let out = search(&data, &plan, |b| {
                let v = validate(c.kind, b);
                let credit = crate::confidence::structural_validity(&v);
                if credit > hi_lattice {
                    hi_lattice = credit;
                }
                if v.valid && credit > hi_accepted {
                    hi_accepted = credit;
                }
                v
            });
            validations += out.validations;
            accepted_total += out.accepted;

            match by_kind.iter_mut().find(|(k, _, _, _)| *k == c.kind.as_str()) {
                Some((_, n, v, b)) => {
                    *n += 1;
                    *v += out.validations;
                    *b += u64::from(baseline >= breach);
                }
                None => by_kind.push((
                    c.kind.as_str(),
                    1,
                    out.validations,
                    u64::from(baseline >= breach),
                )),
            }
            if hi_accepted > worst_accepted {
                worst_accepted = hi_accepted;
            }
            if hi_lattice > worst_lattice {
                worst_lattice = hi_lattice;
                worst_lattice_at = c.header_at;
            }
            if hi_lattice > baseline {
                lifted.push(format!(
                    "{}@{} {:.6} -> {:.6}",
                    c.kind.as_str(),
                    c.header_at,
                    baseline,
                    hi_lattice
                ));
            }
            if hi_accepted > baseline {
                lifted_accepted.push(format!(
                    "{}@{} {:.6} -> {:.6}",
                    c.kind.as_str(),
                    c.header_at,
                    baseline,
                    hi_accepted
                ));
            }
            if let Some(r) = out.found {
                reassembled.push(format!(
                    "{}@{} reassembled to {:?} — not a planted header",
                    c.kind.as_str(),
                    c.header_at,
                    r.extents
                ));
            }
        }
        let el = t0.elapsed().saturating_sub(plant_time);

        by_kind.sort();
        println!(
            "RESIDUE scan={} candidates in {:?}; {} validate contiguously; {} entered the lattice",
            cands.len(),
            scan_elapsed,
            contiguous,
            examined
        );
        for (k, n, v, b) in &by_kind {
            println!(
                "RESIDUE   {k:<6} {n:>3} searched  {v:>9} validations  {b:>2} already at/over \
                 the breach point contiguously"
            );
        }
        println!("RESIDUE {examined} searches, {validations} validations, {el:?}");
        println!(
            "RESIDUE breach={breach:.6}  worst contiguous baseline={worst_baseline:.6} @{worst_baseline_at} \
             ({over_breach_contiguously} candidates are at or over the breach point BEFORE reassembly)"
        );
        println!(
            "RESIDUE lattice: {accepted_total} assemblies accepted, worst accepted credit={worst_accepted:.6}, \
             worst credit of any assembly={worst_lattice:.6} @{worst_lattice_at}"
        );
        println!(
            "RESIDUE reassembled false positives={}  accepted assemblies above own baseline={}",
            reassembled.len(),
            lifted_accepted.len()
        );
        println!(
            "PLANTS  {} planted fragmented headers reach the lattice, {plant_validations} \
             validations, {plant_time:?}. {} never reach it: the contiguous read validates, so `carve.rs` and \
             `search` both stand down before a lattice exists — [{}]",
            plant_rows.len(),
            plant_contiguous.len(),
            plant_contiguous.join(", ")
        );
        for r in &plant_rows {
            println!(
                "PLANTS   {:<26} {:<4} @{:<10} contiguous {:.6}  rejected-assembly ceiling \
                 {:.6}  accepted ceiling {:.6}  {}",
                r.name,
                r.kind,
                r.at,
                r.baseline,
                r.hi_rejected,
                r.hi_accepted,
                if r.solved { "SOLVED" } else { "refused" }
            );
        }
        let top = plant_rows
            .iter()
            .max_by(|a, b| a.hi_rejected.partial_cmp(&b.hi_rejected).unwrap())
            .expect("no planted header reached the lattice");
        let lift = plant_rows
            .iter()
            .max_by(|a, b| {
                (a.hi_rejected - a.baseline)
                    .partial_cmp(&(b.hi_rejected - b.baseline))
                    .unwrap()
            })
            .expect("no planted header reached the lattice");
        let admitted_if_scored = |credit: f64| {
            crate::confidence::NON_STRUCTURE_CEILING + crate::confidence::W_STRUCTURE * credit
        };
        println!(
            "PLANTS  CEILING over rejected assemblies {:.6}  {} {}@{}  (contiguous {:.6})\n\
             PLANTS    {}",
            top.hi_rejected, top.name, top.kind, top.at, top.baseline, top.hi_rejected_detail
        );
        println!(
            "PLANTS  WIDEST LIFT {:.6} -> {:.6}  {} {}@{}\n\
             PLANTS    {}",
            lift.baseline,
            lift.hi_rejected,
            lift.name,
            lift.kind,
            lift.at,
            lift.hi_rejected_detail
        );
        println!(
            "PLANTS  CONSEQUENCE  every one of those assemblies is REJECTED by the validator, so \
             `search` never returns it and `carve.rs` never scores it. If anything ever scored a \
             rejected assembly, {} would be admitted at {:.4} and {} at {:.4} — the second is the \
             tri-fragment plant the demo names on stage as unrecoverable by design, and it would \
             be admitted as itself, at a length its own validator resolves to the byte. THAT is \
             what stands behind the single rule that `search` returns only splices the validator \
             accepted AND the four-neighbour probe pinned.",
            top.name,
            admitted_if_scored(top.hi_rejected),
            lift.name,
            admitted_if_scored(lift.hi_rejected)
        );

        println!(
            "RESIDUE FINDING  {} candidates reach a HIGHER structural credit on a REJECTED \
             assembly than on their contiguous read: [{}]. That credit is unreachable today — \
             `search` returns a splice only when `Validation::valid`, so a rejected assembly is \
             never emitted and never scored — and it does not raise the population ceiling, which \
             stays at the contiguous {:.6} of ZIP@{}. It becomes reachable the moment anything \
             scores a reassembly the validator rejected.",
            lifted.len(),
            lifted.join(", "),
            worst_baseline,
            worst_baseline_at
        );

        assert!(
            reassembled.is_empty(),
            "reassembly admitted residue as evidence: {}",
            reassembled.join("; ")
        );
        assert_eq!(
            accepted_total, 0,
            "a non-planted candidate produced {accepted_total} structurally valid \
             assemblies; the search's refusal would then be resting on the determinacy \
             rule alone, which is a much weaker position than the measured one"
        );
        assert_eq!(worst_accepted, 0.0);
        assert!(
            lifted_accepted.is_empty(),
            "reassembly raised the credit of an ACCEPTED assembly above its candidate's \
             contiguous baseline — the false-positive surface growing on the path that \
             reaches the output: {}",
            lifted_accepted.join("; ")
        );
        assert!(
            worst_lattice <= worst_baseline,
            "reassembly raised the residue population's structural ceiling from \
             {worst_baseline:.6} (contiguous, ZIP@{worst_baseline_at}) to \
             {worst_lattice:.6} (ZIP@{worst_lattice_at}): the false-positive surface grew"
        );
        assert!(
            examined >= 21,
            "expected at least the manifest's 21 residue hits to enter the lattice, got {examined}"
        );

        assert_eq!(
            plant_rows.len() + plant_contiguous.len(),
            PLANTS.len(),
            "a planted header was neither measured in the lattice nor accounted for as \
             contiguous-validating"
        );
        assert!(
            (top.hi_rejected - PLANT_REJECTED_CEILING).abs() <= 1e-9,
            "the planted population's rejected-assembly ceiling moved from the published \
             {PLANT_REJECTED_CEILING:.6} to {:.6} ({} {}@{}). It is unreachable only because \
             `search` returns nothing the validator rejected. Re-measure and republish the \
             figure — in either direction — rather than leaving a wrong number standing.",
            top.hi_rejected,
            top.name,
            top.kind,
            top.at
        );
        assert_eq!(
            lift.name, "media_inventory.docx",
            "the widest contiguous-to-lattice lift moved to {}; the published figure names \
             media_inventory.docx",
            lift.name
        );
        assert!(
            (lift.hi_rejected - PLANT_TRIFRAGMENT_REJECTED_CEILING).abs() <= 1e-9,
            "the tri-fragment plant's rejected-assembly ceiling moved from the published \
             {PLANT_TRIFRAGMENT_REJECTED_CEILING:.6} to {:.6}",
            lift.hi_rejected
        );
        assert!(
            admitted_if_scored(lift.hi_rejected) >= crate::confidence::MIN_CONFIDENCE,
            "the consequence sentence no longer holds: scoring that rejected assembly would \
             give {:.4}, under the {:.4} gate",
            admitted_if_scored(lift.hi_rejected),
            crate::confidence::MIN_CONFIDENCE
        );
        for r in &plant_rows {
            assert!(
                !r.solved || r.hi_accepted > 0.0,
                "{} was solved without any assembly being accepted by the validator",
                r.name
            );
        }
    }
}
