//! Append-only Merkle log of evidence bundles, Ed25519-signed. A signed hash
//! chain, not a blockchain.
//!
//! Everything the ledger signs is canonicalized first — see [`jcs`] for the
//! RFC 8785 profile and the reasons floats never enter the signed payload.

pub mod jcs;
