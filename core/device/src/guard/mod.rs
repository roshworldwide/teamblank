//! The write guard, in two platform backends behind one API.
//!
//! # Why this is a directory and not one file
//!
//! CLAUDE.md rule 4 says a destructive operation refuses to run against any
//! target that is not on an allowlist, and that a forensics tool able to wipe
//! the demo laptop is a disqualifying defect. The guard is where that rule is
//! enforced, so it is the last file in the tree that should grow `if windows`
//! branches through its decision path. Instead each platform gets its own
//! implementation and this file picks one, so neither backend can weaken the
//! other by accident and the Unix file the vector table was measured against
//! stays untouched.
//!
//! # The two backends are NOT equivalent, and that is published
//!
//! | | Unix | Windows |
//! |---|---|---|
//! | containment | `(st_dev, st_ino)` identity walk | canonicalised path components |
//! | link refusal | `O_NOFOLLOW` on every component | reparse-point check per component |
//! | TOCTOU | hardened: `openat` descent, re-checked on the fd | **not hardened**: resolve then open |
//! | device targets | gated, allowlisted, arming required | **always refused** |
//!
//! The Windows column is weaker in the third row and that is a real difference,
//! not a formatting artefact. `openat` with a directory descriptor is how the
//! Unix backend guarantees that the path it checked is the path it opened;
//! Windows exposes no `dir_fd` equivalent through `std`, and the identity
//! primitives that would substitute (`volume_serial_number`, `file_index`) are
//! unstable, so a zero-dependency backend cannot reach them. What the Windows
//! backend does instead is stated in its own file and in docs/architecture.md
//! D7, and it is reported in the decision detail of every allow it issues, so
//! an operator reading a certificate is never left to infer it.
//!
//! Nothing here narrows to the weaker backend: `authorize` on Windows refuses
//! several things the Unix backend permits, never the reverse.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(not(any(unix, windows)))]
compile_error!(
    "sentinelwipe-device: no write guard exists for this target. The guard is the      only thing standing between the wipe engine and an operator's own disk, so      this crate refuses to build without one rather than compiling a permissive      default. Add a backend in src/guard/ and select it above."
);
