//! The append-only chain: a Merkle tree over signed-certificate bytes, plus a
//! head lineage. A signed hash chain, not a blockchain — no consensus, no
//! network, no peers, and the README keeps calling it what it is.
//!
//! Tree structure is RFC 6962 §2.1 (Certificate Transparency's Merkle Tree
//! Hash), chosen because it is published, widely reviewed, and small enough to
//! explain line by line under questioning:
//!
//!   MTH([])            = SHA-256()                      (empty string)
//!   MTH([leaf])        = SHA-256(0x00 || leaf)
//!   MTH(D[n])          = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//!                        where k is the largest power of two < n
//!
//! The 0x00/0x01 domain prefixes are load-bearing: without them a leaf that
//! happens to contain two hashes is indistinguishable from an interior node,
//! and a forger gets a second preimage for free (RFC 6962 notes this).
//!
//! LEAVES ARE THE CANONICAL BYTES from sign::verify — never a re-serialisation.
//! Each appended entry also records the head BEFORE it: the lineage is what
//! makes the log append-only in the eyes of someone holding an old head.

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

/// RFC 6962's split point: the largest power of two strictly less than n.
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

/// One step of an inclusion path: the sibling hash and which side it joins on.
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

/// Recompute the head from a leaf and its path. O(log n), no tree needed:
/// this is what an auditor runs with nothing but the certificate, the printed
/// path, and a head they trust.
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

/// One appended entry: the leaf's hash and the head as it stood BEFORE this
/// append. The prev_head lineage is the append-only claim.
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
    /// Rebuild a chain from persisted leaf hashes. The chain file stores ONLY
    /// hashes — inclusion paths are computed over hashes, so the certificates
    /// themselves never need re-reading, and a certificate the operator moved
    /// or deleted still has its membership provable from the bundle's copy.
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

    /// Append canonical certificate bytes; returns (index, new head).
    /// The head is PUBLISHED by the caller after every append — the whole
    /// point of a head is that other people are holding it.
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
    /// Corrupt one historical leaf hash — test-only, private: the public API
    /// has no mutation besides append, which is the data structure's claim.
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
        // n = 0: hash of the empty string — the one universally known value.
        assert_eq!(
            hex(&Chain::new().head()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // n = 1: H(0x00 || leaf), computed here independently of mth().
        let (c, ls) = chain_of(1);
        let mut d = Sha256::new();
        d.update([0x00]);
        d.update(&ls[0]);
        assert_eq!(c.head(), <Hash>::from(d.finalize()));
        // n = 2: H(0x01 || h0 || h1), likewise by hand.
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

        c.corrupt_for_test(4, 0); // a DIFFERENT leaf, one bit
        let dirty_head = c.head();
        // Direction one: the head changed.
        assert_ne!(clean_head, dirty_head, "a corrupted leaf left the head unmoved");
        // Direction two: leaf 2's old proof fails against the new head...
        assert!(!verify_inclusion(&ls[2], &clean_path_for_2, &dirty_head));
        // ...and the ORIGINAL bytes of the corrupted position no longer
        // verify against the corrupted head. (Not against the clean one:
        // leaf 4's siblings are other subtrees, untouched by corrupting
        // leaf 4's stored hash, so true-bytes + true-siblings still reach
        // the CLEAN head — the first version of this test asserted the
        // opposite and the mathematics said no.)
        let p4 = c.inclusion_path(4).unwrap();
        assert!(!verify_inclusion(&ls[4], &p4, &dirty_head));
        // And the clean case STILL passes, so a broken verifier cannot hide:
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
        // The step-6 demo, end to end at the data layer: the chain holds the
        // ORIGINAL certificate; the presented copy is forged. The inclusion
        // proof still verifies the original bytes — the ledger is intact —
        // and refuses the forged bytes. That distinction is the whole demo.
        let (c, ls) = chain_of(3);
        let head = c.head();
        let p = c.inclusion_path(1).unwrap();
        let mut forged = ls[1].clone();
        forged[0] ^= 0x01; // one bit
        assert!(verify_inclusion(&ls[1], &p, &head), "original must remain provable");
        assert!(!verify_inclusion(&forged, &p, &head), "forgery must not prove");
    }
}
