use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn leaf_hash(leaf: &[u8]) -> Hash {
    let mut d = Sha256::new();
    d.update([0x00]);
    d.update(leaf);
    d.finalize().into()
}

fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut d = Sha256::new();
    d.update([0x01]);
    d.update(l);
    d.update(r);
    d.finalize().into()
}

fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn mth(hashes: &[Hash]) -> Hash {
    match hashes.len() {
        0 => Sha256::digest([]).into(),
        1 => hashes[0],
        n => {
            let k = split(n);
            node_hash(&mth(&hashes[..k]), &mth(&hashes[k..]))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sibling {
    Left(Hash),
    Right(Hash),
}

fn path(hashes: &[Hash], index: usize) -> Vec<Sibling> {
    match hashes.len() {
        0 | 1 => Vec::new(),
        n => {
            let k = split(n);
            if index < k {
                let mut p = path(&hashes[..k], index);
                p.push(Sibling::Right(mth(&hashes[k..])));
                p
            } else {
                let mut p = path(&hashes[k..], index - k);
                p.push(Sibling::Left(mth(&hashes[..k])));
                p
            }
        }
    }
}

pub fn verify_inclusion(leaf: &[u8], path: &[Sibling], head: &Hash) -> bool {
    let mut h = leaf_hash(leaf);
    for step in path {
        h = match step {
            Sibling::Left(l) => node_hash(l, &h),
            Sibling::Right(r) => node_hash(&h, r),
        };
    }
    &h == head
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub index: usize,
    pub leaf_sha: Hash,
    pub prev_head: Hash,
}

#[derive(Default)]
pub struct Chain {
    leaves: Vec<Hash>,
    entries: Vec<Entry>,
}

impl Chain {
    pub fn new() -> Chain {
        Chain::default()
    }
    pub fn head(&self) -> Hash {
        mth(&self.leaves)
    }
    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
    pub fn from_leaf_hashes(hashes: Vec<Hash>) -> Chain {
        let mut c = Chain::new();
        for h in hashes {
            let prev = c.head();
            let idx = c.leaves.len();
            c.leaves.push(h);
            c.entries.push(Entry { index: idx, leaf_sha: h, prev_head: prev });
        }
        c
    }
    pub fn leaf_hashes(&self) -> &[Hash] {
        &self.leaves
    }

    pub fn append(&mut self, leaf: &[u8]) -> (usize, Hash) {
        let prev = self.head();
        let idx = self.leaves.len();
        self.leaves.push(leaf_hash(leaf));
        self.entries.push(Entry { index: idx, leaf_sha: leaf_hash(leaf), prev_head: prev });
        (idx, self.head())
    }
    pub fn inclusion_path(&self, index: usize) -> Option<Vec<Sibling>> {
        (index < self.leaves.len()).then(|| path(&self.leaves, index))
    }
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    #[cfg(test)]
    fn corrupt_for_test(&mut self, index: usize, byte: usize) {
        self.leaves[index][byte] ^= 0x01;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("certificate-{i}").into_bytes()).collect()
    }
    fn chain_of(n: usize) -> (Chain, Vec<Vec<u8>>) {
        let ls = leaves(n);
        let mut c = Chain::new();
        for l in &ls {
            c.append(l);
        }
        (c, ls)
    }

    #[test]
    fn the_rfc_6962_shapes_hold_for_hand_computable_sizes() {
        assert_eq!(
            hex(&Chain::new().head()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let (c, ls) = chain_of(1);
        let mut d = Sha256::new();
        d.update([0x00]);
        d.update(&ls[0]);
        assert_eq!(c.head(), <Hash>::from(d.finalize()));
        let (c2, ls2) = chain_of(2);
        let h0 = super::leaf_hash(&ls2[0]);
        let h1 = super::leaf_hash(&ls2[1]);
        let mut d = Sha256::new();
        d.update([0x01]);
        d.update(h0);
        d.update(h1);
        assert_eq!(c2.head(), <Hash>::from(d.finalize()));
    }

    #[test]
    fn inclusion_verifies_for_every_leaf_at_every_size_up_to_thirty_three() {
        for n in 1..=33 {
            let (c, ls) = chain_of(n);
            let head = c.head();
            for (i, l) in ls.iter().enumerate() {
                let p = c.inclusion_path(i).unwrap();
                assert!(
                    verify_inclusion(l, &p, &head),
                    "n={n} i={i}: clean proof failed — a verifier that rejects \
                     everything must not pass this suite"
                );
                assert!(p.len() <= (usize::BITS - (n - 1).leading_zeros()) as usize + 1,
                    "n={n}: path longer than O(log n)");
            }
        }
    }

    #[test]
    fn one_mutated_byte_in_one_historical_leaf_moves_the_head_and_kills_the_proof() {
        let (mut c, ls) = chain_of(7);
        let clean_head = c.head();
        let clean_path_for_2 = c.inclusion_path(2).unwrap();
        assert!(verify_inclusion(&ls[2], &clean_path_for_2, &clean_head));

        c.corrupt_for_test(4, 0);
        let dirty_head = c.head();
        assert_ne!(clean_head, dirty_head, "a corrupted leaf left the head unmoved");
        assert!(!verify_inclusion(&ls[2], &clean_path_for_2, &dirty_head));
        let p4 = c.inclusion_path(4).unwrap();
        assert!(!verify_inclusion(&ls[4], &p4, &dirty_head));
        assert!(verify_inclusion(&ls[2], &clean_path_for_2, &clean_head));
    }

    #[test]
    fn every_entry_carries_the_head_that_stood_before_it() {
        let (c, ls) = chain_of(5);
        let mut replay = Chain::new();
        for (e, l) in c.entries().iter().zip(&ls) {
            assert_eq!(e.prev_head, replay.head(), "lineage broken at {}", e.index);
            replay.append(l);
        }
        assert_eq!(replay.head(), c.head());
    }

    #[test]
    fn the_forged_document_fails_while_the_ledger_stays_intact() {
        let (c, ls) = chain_of(3);
        let head = c.head();
        let p = c.inclusion_path(1).unwrap();
        let mut forged = ls[1].clone();
        forged[0] ^= 0x01;
        assert!(verify_inclusion(&ls[1], &p, &head), "original must remain provable");
        assert!(!verify_inclusion(&forged, &p, &head), "forgery must not prove");
    }
}
