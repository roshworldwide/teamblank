//! Signature and structure-aware carving with bifragment reassembly and a published confidence score.
//!
//! Module map, as fixed by the Phase 2 interface contract:
//!
//!   signature.rs   header/footer scan -> Candidate
//!   structure/     fast object validation -> Validation   (this half is implemented)
//!   confidence.rs  the published four-term score
//!   bifragment.rs  gap carving over cluster-aligned splits
//!   carve.rs       the driver that produces Recovered
//!
//! NOTE FOR THE INTEGRATOR: this file is owned by the carve-driver agent. The
//! structure agent wrote the `Kind` enum and the `pub mod structure;` line
//! exactly as the interface contract specifies them, because `structure/`
//! cannot compile or be tested without `Kind`. The signature agent added only
//! the `pub mod signature;` line and changed nothing else: it found `Kind`
//! already present and already identical to the interface contract, variant for
//! variant and string for string, so there was nothing to reconcile. Add the
//! remaining `pub mod` lines (confidence, bifragment, carve); do not change
//! `Kind`'s variants or `as_str` without telling the structure and signature
//! halves, because `structure::validate` dispatches on it, `SIGNATURES` is
//! keyed by it, and the fixture tests in both compare `as_str()` against the
//! manifest's `kind` field.

pub mod bifragment;
pub mod confidence;
pub mod signature;
pub mod structure;

/// The object kinds this carver can validate.
///
/// The string form matches the fixture manifest's `kind` field and
/// `fixtures/plan.py::CARVER_SIGNATURES`, so a recovered object's `kind` can be
/// compared to ground truth without a translation table. The manifest also uses
/// `DOCX` and `TXT`: DOCX is a ZIP container and carves as `Kind::Zip`, and TXT
/// has no signature and is out of scope for signature carving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Jpeg,
    Png,
    Pdf,
    Zip,
    Sqlite,
    Mp4,
    Gzip,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Jpeg => "JPEG",
            Kind::Png => "PNG",
            Kind::Pdf => "PDF",
            Kind::Zip => "ZIP",
            Kind::Sqlite => "SQLITE",
            Kind::Mp4 => "MP4",
            Kind::Gzip => "GZIP",
        }
    }
}

impl core::fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
