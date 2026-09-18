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
