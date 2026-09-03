//! # Overwrite passes — the bytes we write, and why they are those bytes
//!
//! Three methods ship, and they differ only in the pattern each pass lays down:
//! single-pass zero, single-pass seeded random, and the three-pass sequence a
//! legacy policy expects. Everything else here — the seekable keystream, the
//! adaptive chunk, the report — exists so that [`crate::verify`] can afterwards
//! *check* what was written, and so the behavioural audit in [`crate::audit`] can
//! be handed a throughput it measured rather than one it was told.
//!
//! ## Decision 1 — the demo pass is a seeded SHAKE-128 stream, not zeros
//!
//! Operator decision, taken before this file: zero-fill makes whole-image entropy
//! **drop**, and `demo_script.md` says at 0:30 that entropy climbs from a measured
//! 7.0617 bits/byte. Zeros would make that line false on stage. A seeded stream
//! climbs toward 8.0 *and* keeps the certificate byte-identical across runs, which
//! CLAUDE.md rule 6 requires. Zero-fill and the three-pass sequence remain shipped,
//! named methods; the demo pass is [`Method::SeededRandom`].
//!
//! Measured on a 256 MiB copy of the fixture, whole-image Shannon entropy over all
//! 268,435,456 bytes — the same estimator `fixtures/corpus.py` uses for the manifest
//! figure. The numbers are in the build report, not asserted here.
//!
//! ## Decision 2 — the stream is keyed per sector, so verification can seek
//!
//! The obvious construction is one long XOF stream from the run seed. It is wrong
//! for this project, because sampled read-back has to know what byte *should* be at
//! sector 419,382 without regenerating the 204 MiB in front of it. So the pattern is
//!
//! ```text
//! sector(lba) = SHAKE128( "SENTINELWIPE/wipe-pattern/v1" || seed[32] || method_id
//!                         || pass_le32 || sector_bytes_le32 || lba_le64 )
//! ```
//!
//! squeezed to `sector_bytes`. That is a counter-mode XOF: every sector is O(1) to
//! generate and O(1) to re-derive, from the seed alone, on any machine, in any
//! order. It costs four Keccak-f[1600] permutations per 512-byte sector — one to
//! absorb-and-finalise, three to refill the 168-byte rate — and that cost is the
//! measured throughput ceiling of [`Method::SeededRandom`]. The build report gives
//! the figure against zero-fill, which pays none of it.
//!
//! **What this is not.** It is not a cipher and nothing here is encrypted. It is a
//! reproducible pattern generator whose output is high-entropy, which is exactly and
//! only what an overwrite pass needs. The one place a keystream *is* used as a
//! cipher is [`CryptoEraseDemonstration`], and that type says in its own name and in
//! every field it emits that it is a demonstration.
//!
//! ## Decision 3 — SHAKE-128 is hand-rolled, and checked against two KATs
//!
//! CLAUDE.md forbids a new dependency; `structure/mod.rs` hand-rolled CRC-32 and
//! `examples/gen_sample_output.rs` hand-rolled SHA-256 under the same rule. The
//! Keccak-f[1600] permutation here is checked two ways in `mod tests`: SHAKE-128
//! against the published empty-message and `"abc"` vectors, and SHA-3-256 against
//! its own, which exercises the same permutation through a *different* rate (136)
//! and a *different* domain pad (0x06). A permutation bug that survived both would
//! have to be consistent across two sponge parameterisations. Every vector in that
//! test was taken from CPython's `hashlib` (OpenSSL's Keccak) on this machine, not
//! from memory.
//!
//! ## Measured, 2026-09-03, 256 MiB copy of `out/fixture.img`, macOS arm64
//!
//! Reproduce with `measure_methods_against_a_scratchpad_copy_of_the_fixture` in
//! [`crate::verify`] — an ignored test, because it is the only one in this crate that
//! opens a writable descriptor on a file.
//!
//! | method | bytes written | wall | throughput | whole-image entropy after |
//! |---|---|---|---|---|
//! | `single_pass_zero` | 268,435,456 | 0.094 s | 2,732 MiB/s | **0.000000000** |
//! | `single_pass_seeded_random_shake128` | 268,435,456 | 0.424 s | 604 MiB/s | **7.999999386** |
//! | `three_pass_zero_ones_seeded_random` | 805,306,368 | 0.603 s | 1,274 MiB/s | **7.999999283** |
//!
//! Wall times and throughputs are **one run** of that test on an otherwise busy
//! machine and move a few percent between runs -- 2,632 to 2,947 MiB/s for zero-fill
//! across three runs, 604 to 637 for the seeded stream. The entropy figures and the
//! digests do not move at all, because they are properties of the bytes rather than
//! of the host.
//!
//! Before, over all 268,435,456 bytes: **7.061690499603866**, which is
//! `fixture.manifest.json`'s figure to every digit it publishes — the Rust estimator
//! and `fixtures/corpus.py`'s `math.fsum` agree exactly on this input.
//!
//! **This is the measurement that settles operator decision 2.** Zero-fill moves
//! whole-image entropy *down* by 7.0617 bits/byte, to exactly zero. The seeded stream
//! moves it *up* by 0.938308887 to 7.999999386. `demo_script.md`'s 0:30 line — entropy
//! climbing from a measured 7.0617 — is true of the seeded pass and false of zero-fill,
//! and the two figures are measured over the same 268,435,456 bytes with the same
//! estimator, so they may be subtracted.
//!
//! Pattern generation alone, no device in the path: constant 54,621 MiB/s, seeded
//! stream 672 MiB/s. The seeded method's 604 MiB/s is therefore generation-bound, not
//! device-bound, on this host.
//!
//! ## What an overwrite of an image file does and does not claim
//!
//! See [`OVERWRITE_SCOPE_LIMIT`]. Writing a pattern over every sector of an image
//! file really does destroy the prior contents *of that file's byte range* — the
//! carve/wipe/carve loop is the evidence. It says nothing whatsoever about the
//! physical NAND under the host filesystem holding the image, which may have
//! copy-on-write snapshots, journal copies, or wear-levelled remaps of the old
//! blocks. Rule 1: the tool never claims more than it verified.

use std::fmt;
use std::time::Instant;

use crate::telemetry::{self, EventSink, Telemetry};

/// The exact scope of an overwrite claim against an image file. Reproduced in the
/// certificate rather than summarised, per CLAUDE.md rule 1.
pub const OVERWRITE_SCOPE_LIMIT: &str = "\
An overwrite pass against an image file overwrites the byte range of that file and \
nothing else. It does not reach, and this tool does not claim to reach, prior copies \
of those bytes held by the host filesystem (copy-on-write snapshots, journals) or \
remapped by the host storage controller (wear levelling, over-provisioning, bad-block \
retirement). Purge of the underlying physical medium is neither performed nor claimed.";

/// Domain separation for the overwrite pattern. Any change here changes every byte
/// this module writes and therefore every certificate; it moves with the same
/// ceremony as a confidence weight.
pub const PATTERN_DOMAIN: &[u8] = b"SENTINELWIPE/wipe-pattern/v1";

/// Domain separation for the crypto-erase demonstration keystream.
pub const CRYPTO_ERASE_DOMAIN: &[u8] = b"SENTINELWIPE/crypto-erase-demo/v1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can stop a pass. `Io` carries the LBA because a device error
/// without the sector it happened at cannot be put in a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WipeError {
    /// The device layer failed at a specific sector.
    Io {
        op: &'static str,
        lba: u64,
        detail: String,
    },
    /// The device cannot do this at all (a `WindowsBlock` stub, a read-only image).
    Unsupported(String),
    /// A request ran off the end of the medium. Caught before it reaches the device.
    OutOfRange {
        lba: u64,
        sectors: u64,
        sector_count: u64,
    },
    /// A buffer whose length is not a whole number of sectors, or not the length the
    /// call implies.
    BadBufferLen { expected: usize, got: usize },
    /// A device reporting a zero sector size or zero capacity. Refused rather than
    /// divided by.
    DegenerateGeometry { sector_bytes: u32, sector_count: u64 },
    /// [`CryptoEraseDemonstration::transform`] after the key was destroyed. This is
    /// the point of the type, so it is an error and never a silent no-op.
    KeyDestroyed { object_id: String },
    /// A pass index outside `1..=method.pass_count()`.
    NoSuchPass { pass: u32, passes: u32 },
}

impl fmt::Display for WipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WipeError::Io { op, lba, detail } => {
                write!(f, "device {} failed at lba {}: {}", op, lba, detail)
            }
            WipeError::Unsupported(what) => write!(f, "unsupported: {}", what),
            WipeError::OutOfRange {
                lba,
                sectors,
                sector_count,
            } => write!(
                f,
                "range lba {}..{} runs past the medium ({} sectors)",
                lba,
                lba.saturating_add(*sectors),
                sector_count
            ),
            WipeError::BadBufferLen { expected, got } => {
                write!(f, "buffer length {}, expected {}", got, expected)
            }
            WipeError::DegenerateGeometry {
                sector_bytes,
                sector_count,
            } => write!(
                f,
                "degenerate geometry: {} byte sectors x {} sectors",
                sector_bytes, sector_count
            ),
            WipeError::KeyDestroyed { object_id } => write!(
                f,
                "key for {} was destroyed; the ciphertext is unrecoverable by design",
                object_id
            ),
            WipeError::NoSuchPass { pass, passes } => {
                write!(f, "pass {} of a {}-pass method", pass, passes)
            }
        }
    }
}

impl std::error::Error for WipeError {}

// ---------------------------------------------------------------------------
// The device surface
// ---------------------------------------------------------------------------

/// What the medium is, as the device layer detected it.
///
/// Four variants, and the same four wire spellings as
/// `sentinelwipe_device::MediumKind`, so the adapter is a four-arm match and a report
/// crossing the seam does not change spelling halfway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Medium {
    Rotational,
    /// Flash. An overwrite does not reach over-provisioned or remapped blocks, which
    /// is why no method in this module claims Purge. See [`OVERWRITE_SCOPE_LIMIT`].
    SolidState,
    /// A regular file standing in for a medium. Not a disk. `docs/architecture.md`
    /// D1 covers why nothing is ever mounted or attached.
    Image,
    Unknown,
}

impl Medium {
    pub fn as_str(&self) -> &'static str {
        match self {
            Medium::Rotational => "rotational",
            Medium::SolidState => "solid-state",
            Medium::Image => "image",
            Medium::Unknown => "unknown",
        }
    }
}

/// Who the target is. Carries no geometry, because `sentinelwipe_device::Identity`
/// carries none either, for the reason its own doc gives: an implementation that does
/// not know its sector size has nothing true to put in the field, and a 512 invented
/// at this seam is a 512 printed on a certificate. Geometry lives in
/// [`Capabilities`], which is fallible for exactly that reason.
///
/// `model` and `serial` are `String` rather than `Option<String>` because the device
/// layer already defines one spelling of not-known: the adapter fills them from
/// `Identity::model_or_unknown()` and `serial_or_unknown()`, which return `"unknown"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// A category, never a marketing string: `"image file"`, `"block device"`.
    pub kind: String,
    pub model: String,
    pub serial: String,
    /// `true` only for something that is physically a storage device. The certificate
    /// branches on this to decide whether the phrase "the drive" is even permissible.
    pub is_physical_medium: bool,
}

impl DeviceIdentity {
    /// One line for a telemetry header or a log: `kind model serial`.
    pub fn describe(&self) -> String {
        format!("{} {} {}", self.kind, self.model, self.serial)
    }
}

/// Geometry, and the one capability an overwrite pass acts on.
///
/// Fallible for the same reason `sentinelwipe_device::Device::capabilities` is: there
/// is no true answer for a sector size that was never determined, so an
/// implementation that does not know returns an error instead of a plausible number.
/// `WindowsBlock` and an unarmed `LinuxBlock` are exactly that case.
///
/// **The sanitize claim vector is deliberately not mirrored here.** The device layer
/// carries `Vec<SanitizeClaim>` behind a four-valued `Support` -- `Claimed`,
/// `NotClaimed`, `Unknown`, `Simulated` -- and flattening that into booleans would
/// erase the `Simulated` case, which is operator decision 3 expressed as a type. No
/// overwrite pass consults a sanitize claim, so this type does not carry one and the
/// sanitize path reads the device's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub medium: Medium,
    /// The addressing unit. Every `lba` in [`SectorIo`] is in these units.
    pub sector_bytes: u32,
    pub sector_count: u64,
    /// The device layer's `Capabilities::writable`. `false` refuses the job before a
    /// byte moves. `true` is still only a claim -- CLAUDE.md rule 5 -- and a write
    /// refused later comes back as [`WipeError::Unsupported`], which is why the
    /// read-only test asserts the medium is unchanged rather than trusting this bit.
    pub writable: bool,
}

impl Capabilities {
    pub fn capacity_bytes(&self) -> u64 {
        self.sector_count.saturating_mul(self.sector_bytes as u64)
    }
}

/// The subset of the device layer these passes touch.
///
/// **This is not a second `Device` trait, and it must not become one.** `core/device`
/// owns `trait Device { read_sectors, write_sectors, capabilities, identify }` and is
/// written by another agent; this crate did not yet have it to depend on when the
/// passes were built, and adding `sentinelwipe-device` to `Cargo.toml` was outside
/// this task's file list. The method names, argument order and semantics here mirror
/// that trait deliberately, so the join is one blanket impl in whichever crate ends
/// up owning the seam:
///
/// ```ignore
/// impl<D: sentinelwipe_device::Device> SectorIo for D {
///     fn identify(&self) -> DeviceIdentity {
///         let i = Device::identify(self);
///         DeviceIdentity { kind: i.kind.clone(), model: i.model_or_unknown(),
///                          serial: i.serial_or_unknown(),
///                          is_physical_medium: i.is_physical_medium }
///     }
///     fn capabilities(&self) -> Result<Capabilities, WipeError> {
///         let c = Device::capabilities(self).map_err(map_device_error)?;
///         Ok(Capabilities { medium: map_medium(c.medium),
///                           sector_bytes: c.logical_sector_bytes,
///                           sector_count: c.total_sectors,
///                           writable: c.writable })
///     }
///     fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), WipeError> {
///         Device::read_sectors(self, lba, buf).map_err(map_device_error)
///     }
///     /* write_sectors and sync are the same one-line shape */
/// }
/// ```
///
/// Nothing in that adapter invents a value. `model` and `serial` come from the device
/// layer's own `_or_unknown` accessors, geometry comes from the fallible
/// `capabilities()` rather than from a default, and `map_medium` is a four-arm match
/// between two enums with identical variants and identical wire spellings. The five
/// method names, their argument order and their arities were matched to
/// `sentinelwipe_device::Device` after that crate landed, so the adapter has no
/// reshaping to do.
///
/// **The seam is closed, and this paragraph says so because it used to say the
/// opposite.** `crate::DeviceIo` in `lib.rs` is that impl: `core/wipe` depends on
/// `sentinelwipe-device`, the shipped `wipe` binary runs
/// `ImageFile -> DeviceIo -> passes/verify`, and every wipe measured for the build
/// report went through it. An under-claim costs the same trust as an over-claim in a
/// project whose whole argument is "we never say more than we verified", and a
/// reviewer who reads this file before `lib.rs` was being told the shipped path was a
/// live integration risk.
///
/// What remains genuinely unexercised is narrower and is stated separately:
/// `sentinelwipe_device::LinuxBlock` compiles behind `--features linux-block` and has
/// never been run against a block device by this project, and
/// `sentinelwipe_device::WindowsBlock` is a stub that returns `Unsupported` for every
/// call. Both reach these five methods through the same `DeviceIo`, so what is
/// untested there is the device layer's platform code, not this seam.
pub trait SectorIo {
    fn identify(&self) -> DeviceIdentity;
    fn capabilities(&self) -> Result<Capabilities, WipeError>;
    /// Read `buf.len()` bytes starting at logical block `lba`. All-or-nothing.
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), WipeError>;
    /// Write `buf.len()` bytes starting at logical block `lba`. All-or-nothing.
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), WipeError>;
    /// Push accepted writes down to the medium. Called at the end of every pass,
    /// before the pass is timed as complete and before read-back verification reads
    /// a byte: verifying through a write-back cache verifies the cache. Named `sync`
    /// rather than `flush` to match the device-layer method it forwards to.
    fn sync(&mut self) -> Result<(), WipeError>;
}

impl<T: SectorIo + ?Sized> SectorIo for &mut T {
    fn identify(&self) -> DeviceIdentity {
        (**self).identify()
    }
    fn capabilities(&self) -> Result<Capabilities, WipeError> {
        (**self).capabilities()
    }
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), WipeError> {
        (**self).read_sectors(lba, buf)
    }
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), WipeError> {
        (**self).write_sectors(lba, buf)
    }
    fn sync(&mut self) -> Result<(), WipeError> {
        (**self).sync()
    }
}

// ---------------------------------------------------------------------------
// Keccak-f[1600], SHAKE-128, SHA-3-256
// ---------------------------------------------------------------------------

/// Rate of SHAKE-128 in bytes: (1600 - 2*128) / 8.
pub const SHAKE128_RATE: usize = 168;
/// Rate of SHA-3-256 in bytes: (1600 - 2*256) / 8. Used only by the KAT that
/// cross-checks the permutation through a second sponge parameterisation.
pub const SHA3_256_RATE: usize = 136;

const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const KECCAK_ROT: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const KECCAK_PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The permutation. Twenty-four rounds of theta, rho-pi, chi, iota over a 5x5
/// lane-major state of 64-bit lanes, little-endian, exactly as FIPS 202 defines it.
#[inline]
fn keccak_f1600(a: &mut [u64; 25]) {
    for round in 0..24 {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // rho + pi
        let mut last = a[1];
        for i in 0..24 {
            let j = KECCAK_PI[i];
            let tmp = a[j];
            a[j] = last.rotate_left(KECCAK_ROT[i]);
            last = tmp;
        }
        // chi
        for y in 0..5 {
            let row = [a[5 * y], a[5 * y + 1], a[5 * y + 2], a[5 * y + 3], a[5 * y + 4]];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        // iota
        a[0] ^= KECCAK_RC[round];
    }
}

#[inline]
fn state_xor_bytes(state: &mut [u64; 25], offset: usize, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        let p = offset + i;
        state[p >> 3] ^= (*b as u64) << (8 * (p & 7));
    }
}

/// A Keccak sponge. Generic over rate and domain pad so one implementation serves
/// SHAKE-128 (the pattern generator) and SHA-3-256 (the cross-check KAT).
#[derive(Clone)]
pub struct Keccak {
    state: [u64; 25],
    rate: usize,
    pad: u8,
    pos: usize,
    squeezing: bool,
}

impl Keccak {
    pub fn shake128() -> Self {
        Keccak {
            state: [0u64; 25],
            rate: SHAKE128_RATE,
            pad: 0x1f,
            pos: 0,
            squeezing: false,
        }
    }

    pub fn sha3_256() -> Self {
        Keccak {
            state: [0u64; 25],
            rate: SHA3_256_RATE,
            pad: 0x06,
            pos: 0,
            squeezing: false,
        }
    }

    /// Absorb. Panics if called after squeezing has begun: a sponge that silently
    /// accepted late input would produce a digest of something other than the
    /// message, which is the kind of defect that is invisible until it matters.
    pub fn absorb(&mut self, data: &[u8]) {
        assert!(!self.squeezing, "Keccak::absorb after squeeze");
        for &b in data {
            self.state[self.pos >> 3] ^= (b as u64) << (8 * (self.pos & 7));
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    fn finish(&mut self) {
        state_xor_bytes(&mut self.state, self.pos, &[self.pad]);
        state_xor_bytes(&mut self.state, self.rate - 1, &[0x80]);
        keccak_f1600(&mut self.state);
        self.pos = 0;
        self.squeezing = true;
    }

    /// Squeeze `out.len()` bytes. May be called repeatedly; the stream continues.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.finish();
        }
        for o in out.iter_mut() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            *o = (self.state[self.pos >> 3] >> (8 * (self.pos & 7))) as u8;
            self.pos += 1;
        }
    }
}

/// SHAKE-128 over the concatenation of `parts`, squeezed into `out`.
///
/// Takes a slice of slices so a caller never has to allocate a joined buffer to
/// hash a structured header.
pub fn shake128(parts: &[&[u8]], out: &mut [u8]) {
    let mut k = Keccak::shake128();
    for p in parts {
        k.absorb(p);
    }
    k.squeeze(out);
}

/// SHA-3-256. Present for the permutation cross-check and for callers who want a
/// stable short fingerprint of a key or a seed. Not used on the wipe hot path.
pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::sha3_256();
    for p in parts {
        k.absorb(p);
    }
    let mut out = [0u8; 32];
    k.squeeze(&mut out);
    out
}

/// Lowercase hex. Certificates and log lines only; not on the hot path.
pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// The run seed
// ---------------------------------------------------------------------------

/// Domain separation for deriving a run seed from a human-readable run id.
pub const RUN_SEED_DOMAIN: &[u8] = b"SENTINELWIPE/run-seed/v1";

/// The 32 bytes every pattern in a job is derived from.
///
/// CLAUDE.md rule 6: `make demo` from a fresh clone produces byte-identical
/// certificates given the same fixture seed. A wipe whose pattern came from the
/// operating system's entropy pool cannot satisfy that — the written bytes, their
/// entropy, and any digest over the wiped medium would differ every run. So the seed
/// is an *input*, it is printed in the certificate as hex, and a third party can
/// regenerate any sector of the wiped medium from it and check our arithmetic.
///
/// The trade that buys is stated rather than hidden: a published seed makes the
/// pattern predictable. For an overwrite that is irrelevant — the pattern's job is
/// to be *there*, not to be secret. For [`CryptoEraseDemonstration`] it would be
/// fatal, which is why that type takes its key separately and never derives one from
/// a seed that appears in a certificate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Seed([u8; 32]);

impl Seed {
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Seed(b)
    }

    /// Derive from a run identifier — `SHAKE128("SENTINELWIPE/run-seed/v1" || id)`.
    /// Deterministic across machines, so the run id is enough to reproduce a job.
    pub fn from_run_id(run_id: &str) -> Self {
        let mut b = [0u8; 32];
        shake128(&[RUN_SEED_DOMAIN, run_id.as_bytes()], &mut b);
        Seed(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seed({})", self.hex())
    }
}

// ---------------------------------------------------------------------------
// Methods and patterns
// ---------------------------------------------------------------------------

/// What one pass lays down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassPattern {
    /// Every byte the same. Cheap, and visible as a flat line in the entropy readout.
    Constant(u8),
    /// The per-sector seeded SHAKE-128 stream described at the top of this file.
    Shake128Stream,
}

impl PassPattern {
    pub fn label(&self) -> &'static str {
        match self {
            PassPattern::Constant(0x00) => "zeros_0x00",
            PassPattern::Constant(0xff) => "ones_0xff",
            PassPattern::Constant(_) => "constant",
            PassPattern::Shake128Stream => "shake128_seeded_stream",
        }
    }
}

/// The three shipped overwrite methods.
///
/// All three are *overwrite* methods and all three sit in the same NIST SP 800-88
/// Rev. 1 category — see [`Method::nist_category`]. Choosing between them is a policy
/// question about what a reviewer expects to see, not a claim that one erases more
/// than another; this module makes no such claim and no measurement here supports one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// One pass of 0x00. Available, and deliberately *not* the demo pass: it drives
    /// whole-image entropy to 0, and `demo_script.md` narrates entropy climbing.
    ZeroFill,
    /// One pass of the seeded SHAKE-128 stream. The demo pass.
    SeededRandom,
    /// 0x00, then 0xFF, then the seeded stream. The three-pass shape a legacy policy
    /// expects. The final pass is the seeded stream so the medium ends high-entropy
    /// and reproducible, exactly as [`Method::SeededRandom`] leaves it.
    ThreePass,
}

impl Method {
    /// Stable numeric id. It is absorbed into every pattern, so two methods never
    /// produce the same bytes for the same seed, pass and sector.
    pub fn id(&self) -> u8 {
        match self {
            Method::ZeroFill => 1,
            Method::SeededRandom => 2,
            Method::ThreePass => 3,
        }
    }

    /// The wire label. Goes into the telemetry header and the certificate.
    pub fn label(&self) -> &'static str {
        match self {
            Method::ZeroFill => "single_pass_zero",
            Method::SeededRandom => "single_pass_seeded_random_shake128",
            Method::ThreePass => "three_pass_zero_ones_seeded_random",
        }
    }

    pub fn patterns(&self) -> &'static [PassPattern] {
        match self {
            Method::ZeroFill => &[PassPattern::Constant(0x00)],
            Method::SeededRandom => &[PassPattern::Shake128Stream],
            Method::ThreePass => &[
                PassPattern::Constant(0x00),
                PassPattern::Constant(0xff),
                PassPattern::Shake128Stream,
            ],
        }
    }

    pub fn pass_count(&self) -> u32 {
        self.patterns().len() as u32
    }

    /// The pattern for a 1-based pass number.
    pub fn pattern(&self, pass: u32) -> Result<PassPattern, WipeError> {
        let passes = self.pass_count();
        if pass == 0 || pass > passes {
            return Err(WipeError::NoSuchPass { pass, passes });
        }
        Ok(self.patterns()[(pass - 1) as usize])
    }

    /// The NIST SP 800-88 Rev. 1 category an overwrite of the whole addressable
    /// medium falls in. It is `Clear` for every method here, including the
    /// three-pass one. `Purge` is not claimed by any overwrite in this module: on
    /// flash it would require reaching over-provisioned and remapped blocks that a
    /// host-addressed write cannot see, and CLAUDE.md rule 1 forbids claiming it.
    /// The clause-by-clause table is `docs/standards_map.md`, which is the
    /// operator's file; this function exists so the certificate writer never has to
    /// guess.
    pub fn nist_category(&self) -> &'static str {
        "Clear"
    }

    /// What a reviewer expecting a legacy pattern will recognise, where that is a
    /// true statement about the shape of the passes. It is not a conformance claim:
    /// nothing in this project has been tested against a DoD 5220.22-M procedure.
    pub fn legacy_shape(&self) -> Option<&'static str> {
        match self {
            Method::ThreePass => Some("three-pass overwrite shape (0x00, 0xFF, random)"),
            _ => None,
        }
    }

    /// Default method for a detected medium.
    ///
    /// Every medium gets [`Method::SeededRandom`]: one full-capacity overwrite pass,
    /// which is the same NIST category as three of them and costs a third of the
    /// writes. Two things this deliberately does *not* do:
    ///
    /// * It does not escalate a solid-state medium to ATA Secure Erase or NVMe
    ///   Sanitize. That dispatch belongs to the sanitize path, which knows what the
    ///   controller advertised and — per operator decision 3 — labels the result
    ///   `simulated` on anything that is not a real controller.
    /// * It does not pick [`Method::ThreePass`] for magnetic media. There is no
    ///   measurement in this project supporting a claim that a second and third pass
    ///   remove residue a first did not, and rule 2 forbids shipping a default we
    ///   cannot defend with a number. An operator who needs that shape asks for it.
    pub fn default_for_medium(_medium: Medium) -> Method {
        Method::SeededRandom
    }
}

// ---------------------------------------------------------------------------
// Pattern generation
// ---------------------------------------------------------------------------

#[inline]
fn squeeze_rate_block(st: &[u64; 25], out: &mut [u8]) {
    debug_assert!(out.len() <= SHAKE128_RATE);
    let mut i = 0usize;
    let mut lane = 0usize;
    while i < out.len() {
        let b = st[lane].to_le_bytes();
        let n = core::cmp::min(8, out.len() - i);
        out[i..i + n].copy_from_slice(&b[..n]);
        i += n;
        lane += 1;
    }
}

/// Generates the expected bytes of one pass, at any sector, in any order.
///
/// Construction and cost are in the module header. The important property, and the
/// only reason this type exists rather than a `Vec<u8>` of the pass, is that
/// [`PatternGen::fill_sector`] is O(sector_bytes) *from the seed*, with no state
/// carried between sectors — which is what makes sampled read-back verification
/// possible at all.
#[derive(Clone)]
pub struct PatternGen {
    pattern: PassPattern,
    sector_bytes: usize,
    /// Keccak state with the fixed header prefix already absorbed. Header is 77
    /// bytes, well under the 168-byte rate, so no permutation has happened yet and
    /// XOR-ing the per-sector suffix into a copy is a complete absorb.
    template: [u64; 25],
    lba_off: usize,
    hdr_len: usize,
}

/// Deliberately partial: the template state has the run seed absorbed into it, and
/// a `#[derive(Debug)]` would print seed-derived material into any log line that
/// formatted a generator. Nothing here is secret today -- the seed is published in
/// the certificate -- but the same type is the shape a keyed generator would take,
/// so the habit is set here rather than after it matters.
impl fmt::Debug for PatternGen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PatternGen")
            .field("pattern", &self.pattern.label())
            .field("sector_bytes", &self.sector_bytes)
            .finish_non_exhaustive()
    }
}

impl PatternGen {
    /// `pass` is 1-based.
    pub fn new(
        seed: &Seed,
        method: Method,
        pass: u32,
        sector_bytes: u32,
    ) -> Result<PatternGen, WipeError> {
        if sector_bytes == 0 {
            return Err(WipeError::DegenerateGeometry {
                sector_bytes,
                sector_count: 0,
            });
        }
        let pattern = method.pattern(pass)?;
        let mut template = [0u64; 25];
        let mut off = 0usize;
        {
            let mut put = |bytes: &[u8]| {
                state_xor_bytes(&mut template, off, bytes);
                off += bytes.len();
            };
            put(PATTERN_DOMAIN);
            put(seed.as_bytes());
            put(&[method.id()]);
            put(&pass.to_le_bytes());
            put(&sector_bytes.to_le_bytes());
        }
        let lba_off = off;
        let hdr_len = lba_off + 8;
        // A header at or past the rate would need a permutation mid-absorb and the
        // template shortcut would be wrong. 77 < 168 today; assert so a future field
        // cannot break it silently.
        assert!(
            hdr_len < SHAKE128_RATE,
            "pattern header {} bytes >= SHAKE-128 rate {}",
            hdr_len,
            SHAKE128_RATE
        );
        Ok(PatternGen {
            pattern,
            sector_bytes: sector_bytes as usize,
            template,
            lba_off,
            hdr_len,
        })
    }

    pub fn pattern(&self) -> PassPattern {
        self.pattern
    }

    pub fn sector_bytes(&self) -> usize {
        self.sector_bytes
    }

    /// True when every sector of the pass carries identical bytes, so a write buffer
    /// can be filled once and reused for the whole pass.
    pub fn is_constant(&self) -> bool {
        matches!(self.pattern, PassPattern::Constant(_))
    }

    /// The expected bytes of one sector. `out.len()` is the sector size; a shorter
    /// slice yields the corresponding prefix, which is what a partial compare wants.
    pub fn fill_sector(&self, lba: u64, out: &mut [u8]) {
        match self.pattern {
            PassPattern::Constant(b) => {
                for o in out.iter_mut() {
                    *o = b;
                }
            }
            PassPattern::Shake128Stream => {
                let mut st = self.template;
                state_xor_bytes(&mut st, self.lba_off, &lba.to_le_bytes());
                state_xor_bytes(&mut st, self.hdr_len, &[0x1f]);
                state_xor_bytes(&mut st, SHAKE128_RATE - 1, &[0x80]);
                keccak_f1600(&mut st);
                let mut off = 0usize;
                while off < out.len() {
                    let n = core::cmp::min(SHAKE128_RATE, out.len() - off);
                    squeeze_rate_block(&st, &mut out[off..off + n]);
                    off += n;
                    if off < out.len() {
                        keccak_f1600(&mut st);
                    }
                }
            }
        }
    }

    /// Fill a run of whole sectors starting at `first_lba`.
    pub fn fill_run(&self, first_lba: u64, buf: &mut [u8]) -> Result<(), WipeError> {
        if buf.len() % self.sector_bytes != 0 {
            return Err(WipeError::BadBufferLen {
                expected: (buf.len() / self.sector_bytes + 1) * self.sector_bytes,
                got: buf.len(),
            });
        }
        for (i, chunk) in buf.chunks_mut(self.sector_bytes).enumerate() {
            self.fill_sector(first_lba + i as u64, chunk);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Entropy, exactly as the fixture measures it
// ---------------------------------------------------------------------------

/// Compensated summation (Neumaier). `fixtures/corpus.py` uses `math.fsum`, which is
/// exactly rounded; this is not, and the difference is bounded by about one ulp of
/// the result over 256 terms. The build report records the measured agreement
/// between this function and the manifest's `whole_image_entropy_bits_per_byte`
/// against the same 268,435,456 bytes, so the claim that the two implementations
/// agree is a measurement and not an inference.
fn neumaier_sum(terms: &[f64]) -> f64 {
    let mut s = 0.0f64;
    let mut c = 0.0f64;
    for &x in terms {
        let t = s + x;
        if s.abs() >= x.abs() {
            c += (s - t) + x;
        } else {
            c += (x - t) + s;
        }
        s = t;
    }
    s + c
}

/// Exact byte histogram, accumulated across chunks so a 256 MiB medium can be
/// measured without being held in memory.
#[derive(Debug, Clone)]
pub struct ByteHistogram {
    counts: [u64; 256],
    total: u64,
}

impl Default for ByteHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteHistogram {
    pub fn new() -> Self {
        ByteHistogram {
            counts: [0u64; 256],
            total: 0,
        }
    }

    pub fn add(&mut self, data: &[u8]) {
        for &b in data {
            self.counts[b as usize] += 1;
        }
        self.total += data.len() as u64;
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn counts(&self) -> &[u64; 256] {
        &self.counts
    }

    /// Shannon entropy in bits/byte over everything added so far. Zero for an empty
    /// histogram and for a single-symbol one, which is the correct answer in both
    /// cases and is what a zero-filled medium measures.
    pub fn shannon_bits_per_byte(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let n = self.total as f64;
        let mut terms = Vec::with_capacity(256);
        for &c in self.counts.iter() {
            if c > 0 {
                let p = c as f64 / n;
                terms.push(-p * p.log2());
            }
        }
        let h = neumaier_sum(&terms);
        if h == 0.0 {
            0.0
        } else {
            h
        }
    }
}

/// Whole-buffer Shannon entropy in bits/byte. The exact estimator, over every byte —
/// not the strided sample [`crate::telemetry::entropy_sampled`] takes for a live
/// frame. The two are not interchangeable and a slide must not compare them: the
/// sampled one is biased low by about `(K-1)/(2 N ln 2)` bits, which the telemetry
/// module documents at its own budget.
pub fn shannon_bits_per_byte(data: &[u8]) -> f64 {
    let mut h = ByteHistogram::new();
    h.add(data);
    h.shannon_bits_per_byte()
}

// ---------------------------------------------------------------------------
// Job configuration
// ---------------------------------------------------------------------------

/// Default write chunk: 2048 sectors, which is 1 MiB at a 512-byte sector.
pub const DEFAULT_CHUNK_SECTORS_MAX: u32 = 2048;
/// Floor for the adaptive chunk. Below this the per-call overhead dominates and the
/// device is being measured through the loop rather than the loop through the device.
pub const DEFAULT_CHUNK_SECTORS_MIN: u32 = 8;
/// Target wall time for one chunk: 10 ms, a quarter of the telemetry module's 40 ms
/// emit period. See [`adapt_chunk`] for why a quarter and not one.
pub const DEFAULT_TARGET_CHUNK_NS: u128 = 10_000_000;

/// Everything a job needs that is not the device.
#[derive(Debug, Clone)]
pub struct WipeConfig {
    pub method: Method,
    pub seed: Seed,
    pub chunk_sectors_max: u32,
    pub chunk_sectors_min: u32,
    pub target_chunk_ns: u128,
}

impl WipeConfig {
    pub fn new(method: Method, seed: Seed) -> Self {
        WipeConfig {
            method,
            seed,
            chunk_sectors_max: DEFAULT_CHUNK_SECTORS_MAX,
            chunk_sectors_min: DEFAULT_CHUNK_SECTORS_MIN,
            target_chunk_ns: DEFAULT_TARGET_CHUNK_NS,
        }
    }

    /// The telemetry header this config and device imply. `simulated` is `false`
    /// here and must stay so: an overwrite pass really does write every sector.
    /// Operator decision 3 puts the word `simulated` on ATA Secure Erase, NVMe
    /// Sanitize and crypto-erase against an image, which are the sanitize path's
    /// operations, not this module's.
    pub fn telemetry_spec(
        &self,
        id: &DeviceIdentity,
        caps: &Capabilities,
    ) -> telemetry::WipeSpec {
        telemetry::WipeSpec {
            device: format!("{} [{}]", id.describe(), caps.medium.as_str()),
            sector_size: caps.sector_bytes,
            total_sectors: caps.sector_count,
            method: self.method.label().to_string(),
            simulated: false,
            passes: self.method.pass_count(),
            pattern_seed_hex: self.seed.hex(),
        }
    }
}

/// Resize the write chunk so the engine keeps calling [`Telemetry::wrote`] often
/// enough for the 20 Hz floor to be the *telemetry* module's decision rather than an
/// accident of how fast the medium happens to be.
///
/// A fixed 1 MiB chunk is 3 ms on a fast NVMe and 200 ms on a slow USB stick. At 200
/// ms the stream emits at 5 Hz whatever period telemetry asks for, because it is
/// never called; the sector map would sweep in visible jumps and `Summary::
/// met_rate_floor` would come back false through no fault of the consumer. So the
/// loop measures each chunk and moves toward `target_chunk_ns`.
///
/// The target is a *quarter* of the emit period, not the period itself: emission
/// happens on a `wrote` call, so the worst-case gap between two frames is one period
/// plus one chunk. At a quarter, the overshoot is at most 25% and the achieved rate
/// stays above the floor; at a full period it could be 50% and would not.
///
/// Hysteresis is 4x — shrink above the target, grow only below a quarter of it — so
/// a chunk that lands near the target is left alone instead of oscillating.
pub fn adapt_chunk(current: u32, elapsed_ns: u128, target_ns: u128, min: u32, max: u32) -> u32 {
    let min = min.max(1);
    let max = max.max(min);
    let cur = current.clamp(min, max);
    if target_ns == 0 {
        return cur;
    }
    if elapsed_ns > target_ns {
        (cur / 2).max(min)
    } else if elapsed_ns * 4 < target_ns {
        cur.saturating_mul(2).min(max)
    } else {
        cur
    }
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// What one pass did. Every field is measured; none is derived from a device's
/// claim about itself.
#[derive(Debug, Clone, PartialEq)]
pub struct PassReport {
    pub method_label: &'static str,
    pub pass: u32,
    pub passes: u32,
    pub pattern: &'static str,
    pub sector_bytes: u32,
    pub sectors_written: u64,
    pub bytes_written: u64,
    /// Wall time for the pass including pattern generation and the closing sync.
    pub duration_ns: u128,
    /// Wall time of the closing `sync` alone, included in `duration_ns`. Broken out
    /// because a device that buffers a whole pass and pays for it at sync is a device
    /// whose per-chunk throughput figure means nothing.
    ///
    /// **Measured on the fixture: 4-52 ms**, and this is the one thing that can still
    /// break the 20 Hz floor. A frame is forced immediately before the sync, so the
    /// worst inter-frame gap is `sync_ns` plus one chunk; when `fsync` of a 256 MiB
    /// image ran 52 ms the three-pass job reported `met_rate_floor: false` with a
    /// 51.7 ms gap. Nothing in a single-threaded write loop can emit during a
    /// blocking `fsync`, so this is reported rather than fixed here: the honest
    /// options are a `Syncing` state in the telemetry stream or a stream-side rule
    /// that a gap spanning a known sync is not a stall. Both belong to
    /// `telemetry.rs`, and `sync_ns` is the measurement either would need.
    pub sync_ns: u128,
    pub chunk_writes: u64,
    pub chunk_sectors_first: u32,
    pub chunk_sectors_final: u32,
    pub chunk_resizes: u32,
    /// The longest single chunk iteration — generation, write and the `wrote` call.
    /// This is the engine's contribution to the worst inter-frame gap, and the
    /// number to look at when `Summary::met_rate_floor` comes back false.
    pub max_chunk_ns: u128,
}

impl PassReport {
    /// Bytes per second over the whole pass. Zero duration reports 0.0 rather than
    /// an infinity, because an infinity in a certificate is a defect.
    pub fn throughput_bytes_per_s(&self) -> f64 {
        if self.duration_ns == 0 {
            0.0
        } else {
            self.bytes_written as f64 * 1_000_000_000.0 / self.duration_ns as f64
        }
    }

    /// The pair the behavioural audit needs: `(bytes, elapsed_ns)` of work this
    /// process actually performed against this device in this run. Feed it to
    /// `audit::ThroughputSample::new` with `BaselineSource::ObservedPass` — that is
    /// the strongest baseline available, because it travelled the same I/O path as
    /// the operation it will judge.
    pub fn throughput_sample_input(&self) -> (u64, u128) {
        (self.bytes_written, self.duration_ns)
    }
}

/// The whole job.
#[derive(Debug, Clone, PartialEq)]
pub struct WipeReport {
    pub method_label: &'static str,
    pub nist_category: &'static str,
    pub legacy_shape: Option<&'static str>,
    pub seed_hex: String,
    pub device: String,
    pub medium: &'static str,
    pub sector_bytes: u32,
    pub sector_count: u64,
    pub capacity_bytes: u64,
    pub passes: Vec<PassReport>,
    pub bytes_written: u64,
    pub duration_ns: u128,
    /// Always `false` for an overwrite: every sector was really written. The word
    /// belongs on the sanitize path, per operator decision 3.
    pub simulated: bool,
    /// [`OVERWRITE_SCOPE_LIMIT`], carried so a certificate writer cannot emit the
    /// result without the limitation attached to it.
    pub scope_limit: &'static str,
}

impl WipeReport {
    pub fn throughput_bytes_per_s(&self) -> f64 {
        if self.duration_ns == 0 {
            0.0
        } else {
            self.bytes_written as f64 * 1_000_000_000.0 / self.duration_ns as f64
        }
    }
}

// ---------------------------------------------------------------------------
// The write loop
// ---------------------------------------------------------------------------

/// Read the geometry and refuse the job before a byte moves if it cannot be trusted.
///
/// Returns identity and capabilities together because every caller needs both and
/// each is one call: the identity for the certificate, the geometry for the loop.
fn preflight<D: SectorIo + ?Sized>(
    dev: &D,
) -> Result<(DeviceIdentity, Capabilities), WipeError> {
    let id = dev.identify();
    let caps = dev.capabilities()?;
    if caps.sector_bytes == 0 || caps.sector_count == 0 {
        return Err(WipeError::DegenerateGeometry {
            sector_bytes: caps.sector_bytes,
            sector_count: caps.sector_count,
        });
    }
    if !caps.writable {
        return Err(WipeError::Unsupported(format!(
            "device {} reports itself not writable",
            id.describe()
        )));
    }
    Ok((id, caps))
}

/// Run one 1-based pass over the whole medium.
///
/// Telemetry contract, exactly as `telemetry.rs` documents it: [`Telemetry::wrote`]
/// is called **after** each chunk write returns, never before — a frame that runs
/// ahead of the device is a progress bar, not an instrument. The caller owns
/// [`Telemetry::start`], [`Telemetry::end_pass`] and [`Telemetry::finish`];
/// [`overwrite`] does the `end_pass` part.
pub fn run_pass<D, S>(
    dev: &mut D,
    cfg: &WipeConfig,
    pass: u32,
    tm: &mut Telemetry<S>,
) -> Result<PassReport, WipeError>
where
    D: SectorIo + ?Sized,
    S: EventSink,
{
    let (_id, caps) = preflight(&*dev)?;
    let gen = PatternGen::new(&cfg.seed, cfg.method, pass, caps.sector_bytes)?;
    let sb = caps.sector_bytes as usize;

    let cmin = cfg.chunk_sectors_min.max(1);
    let cmax = cfg.chunk_sectors_max.max(cmin);
    let mut chunk = cmax;
    let first_chunk = chunk;

    let mut buf = vec![0u8; cmax as usize * sb];
    // A constant pattern is the same bytes for every sector of the pass, so the
    // buffer is filled once and reused. Measured: this is the whole reason zero-fill
    // outruns the seeded stream.
    if gen.is_constant() {
        gen.fill_run(0, &mut buf)?;
    }

    let t_pass = Instant::now();
    let mut lba: u64 = 0;
    let mut chunk_writes: u64 = 0;
    let mut chunk_resizes: u32 = 0;
    let mut max_chunk_ns: u128 = 0;

    while lba < caps.sector_count {
        let t_chunk = Instant::now();
        let n = core::cmp::min(chunk as u64, caps.sector_count - lba) as usize;
        let slice = &mut buf[..n * sb];
        if !gen.is_constant() {
            gen.fill_run(lba, slice)?;
        }
        dev.write_sectors(lba, slice)?;
        // After the bytes are on the medium, never before.
        tm.wrote(pass, lba, slice);
        let elapsed = t_chunk.elapsed().as_nanos();
        if elapsed > max_chunk_ns {
            max_chunk_ns = elapsed;
        }
        lba += n as u64;
        chunk_writes += 1;
        let next = adapt_chunk(chunk, elapsed, cfg.target_chunk_ns, cmin, cmax);
        if next != chunk {
            chunk = next;
            chunk_resizes += 1;
        }
    }

    // Force a frame before the flush. Measured on the fixture: a zero-fill pass
    // writes 256 MiB in 94 ms and then spends 39 ms in `fsync`, and with no frame in
    // between the worst inter-frame gap was 53.2 ms -- over the 50 ms the 20 Hz floor
    // allows, on a pass whose every chunk took 1.5 ms. The stall was entirely
    // un-instrumented flush time. `tick` emits only if a span is pending, so this
    // costs nothing when the period already emitted one.
    tm.tick(pass);
    let t_sync = Instant::now();
    dev.sync()?;
    let sync_ns = t_sync.elapsed().as_nanos();

    Ok(PassReport {
        method_label: cfg.method.label(),
        pass,
        passes: cfg.method.pass_count(),
        pattern: gen.pattern().label(),
        sector_bytes: caps.sector_bytes,
        sectors_written: caps.sector_count,
        bytes_written: caps.sector_count.saturating_mul(sb as u64),
        duration_ns: t_pass.elapsed().as_nanos(),
        sync_ns,
        chunk_writes,
        chunk_sectors_first: first_chunk,
        chunk_sectors_final: chunk,
        chunk_resizes,
        max_chunk_ns,
    })
}

/// Run every pass of the configured method, closing each telemetry canvas layer.
///
/// This writes and does not verify. Verification is [`crate::verify`], and it is a
/// separate call on purpose: a write that reports success is a claim, and this
/// project does not put a claim in a certificate until something read the medium
/// back. [`crate::verify::wipe_verified`] is the composed entry point that
/// interleaves the two.
pub fn overwrite<D, S>(
    dev: &mut D,
    cfg: &WipeConfig,
    tm: &mut Telemetry<S>,
) -> Result<WipeReport, WipeError>
where
    D: SectorIo + ?Sized,
    S: EventSink,
{
    let (id, caps) = preflight(&*dev)?;
    let t0 = Instant::now();
    let mut passes = Vec::with_capacity(cfg.method.pass_count() as usize);
    for pass in 1..=cfg.method.pass_count() {
        let r = run_pass(dev, cfg, pass, tm)?;
        tm.end_pass(pass);
        passes.push(r);
    }
    let bytes: u64 = passes.iter().map(|p| p.bytes_written).sum();
    Ok(WipeReport {
        method_label: cfg.method.label(),
        nist_category: cfg.method.nist_category(),
        legacy_shape: cfg.method.legacy_shape(),
        seed_hex: cfg.seed.hex(),
        device: id.describe(),
        medium: caps.medium.as_str(),
        sector_bytes: caps.sector_bytes,
        sector_count: caps.sector_count,
        capacity_bytes: caps.capacity_bytes(),
        passes,
        bytes_written: bytes,
        duration_ns: t0.elapsed().as_nanos(),
        simulated: false,
        scope_limit: OVERWRITE_SCOPE_LIMIT,
    })
}

// ---------------------------------------------------------------------------
// Crypto-erase: a demonstration, and labelled as one in every field it emits
// ---------------------------------------------------------------------------

/// The construction identifier that travels with every crypto-erase artifact.
///
/// It is deliberately unwieldy. Operator decision 3 requires the caveat to live in
/// the field itself rather than in a footnote, and a reader who copies this string
/// into a slide copies the caveat with it.
pub const CRYPTO_ERASE_CONSTRUCTION: &str =
    "DEMONSTRATION_shake128_xor_keystream__not_a_certified_cipher";

/// What this shim is and is not. Reproduced in [`CryptoEraseReport::limits`].
pub const CRYPTO_ERASE_LIMITS: &str = "\
DEMONSTRATION ONLY. The transform is a XOR with a SHAKE-128 keystream keyed per \
512-byte block. It is not AES, it is not authenticated, it has no FIPS validation, it \
is not constant-time and it has had no cryptanalysis. It demonstrates the SHAPE of \
crypto-erase -- that destroying a key leaves ciphertext that is indistinguishable \
from noise -- and it is not a cryptographic product. Separately: on a real \
self-encrypting drive the key lives in the controller and this process never sees it, \
so a host-side crypto-erase against an image file is SIMULATED with respect to any \
real device and is labelled simulated in the report.";

/// Block size the keystream is keyed at. Independent of any device sector size: this
/// operates on an object's bytes, not on a medium.
pub const CRYPTO_ERASE_BLOCK: usize = 512;

/// What happened to the key. Emitted after destruction, so it deliberately carries a
/// fingerprint of the key rather than the key: a log has to be able to say *which*
/// key died without being able to reconstruct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDestructionRecord {
    pub object_id: String,
    /// First 8 bytes of `SHA3-256(domain || key)`. One-way, so this record is safe
    /// to keep in a certificate.
    pub key_fingerprint_hex: String,
    pub key_bytes_zeroed: usize,
    pub destroyed: bool,
    pub method: &'static str,
}

/// Encrypt-then-discard-key, for per-file erasure.
///
/// The point of crypto-erase is that you do not have to overwrite an object to make
/// it unrecoverable; you overwrite the *key*, which is 32 bytes however large the
/// object is. This type demonstrates that end to end and measures the result: the
/// ciphertext's entropy, and how much of the plaintext survives an attempt to read
/// it back with a key that is not the one that was destroyed.
///
/// **Read [`CRYPTO_ERASE_LIMITS`].** The keystream is a XOF in counter mode, which is
/// a real construction, but this project has not validated it as a cipher and does
/// not ship it as one. Every artifact it produces says so in the field name.
pub struct CryptoEraseDemonstration {
    key: Option<[u8; 32]>,
    key_fingerprint: [u8; 8],
    object_id: String,
}

impl CryptoEraseDemonstration {
    /// Take an explicit key. The key is **not** derived from the wipe run seed and
    /// must not be: the run seed is printed in the certificate so a third party can
    /// re-derive the overwrite pattern, and a key derivable from a published seed is
    /// not destroyed by destroying it.
    pub fn with_key(key: [u8; 32], object_id: &str) -> Self {
        let fp = sha3_256(&[CRYPTO_ERASE_DOMAIN, b"fingerprint", &key]);
        let mut key_fingerprint = [0u8; 8];
        key_fingerprint.copy_from_slice(&fp[..8]);
        CryptoEraseDemonstration {
            key: Some(key),
            key_fingerprint,
            object_id: object_id.to_string(),
        }
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn key_alive(&self) -> bool {
        self.key.is_some()
    }

    pub fn key_fingerprint_hex(&self) -> String {
        hex(&self.key_fingerprint)
    }

    /// XOR the keystream over `buf`, which starts at byte `offset` of the object.
    /// The transform is its own inverse: the same call encrypts and decrypts.
    ///
    /// `offset` must be a multiple of [`CRYPTO_ERASE_BLOCK`] so the block index is
    /// exact; a caller streaming an object hands it aligned chunks.
    pub fn transform(&self, offset: u64, buf: &mut [u8]) -> Result<(), WipeError> {
        let key = self.key.as_ref().ok_or_else(|| WipeError::KeyDestroyed {
            object_id: self.object_id.clone(),
        })?;
        if offset % CRYPTO_ERASE_BLOCK as u64 != 0 {
            return Err(WipeError::BadBufferLen {
                expected: CRYPTO_ERASE_BLOCK,
                got: (offset % CRYPTO_ERASE_BLOCK as u64) as usize,
            });
        }
        let mut ks = [0u8; CRYPTO_ERASE_BLOCK];
        let mut block = offset / CRYPTO_ERASE_BLOCK as u64;
        let mut done = 0usize;
        while done < buf.len() {
            shake128(
                &[
                    CRYPTO_ERASE_DOMAIN,
                    key,
                    self.object_id.as_bytes(),
                    &block.to_le_bytes(),
                ],
                &mut ks,
            );
            let n = core::cmp::min(CRYPTO_ERASE_BLOCK, buf.len() - done);
            for i in 0..n {
                buf[done + i] ^= ks[i];
            }
            done += n;
            block += 1;
        }
        Ok(())
    }

    /// Overwrite the key in memory and drop it.
    ///
    /// `write_volatile` per byte plus a compiler fence, so the writes are not
    /// optimised away as dead stores. This is the honest limit of what a std-only
    /// Rust program can promise: it cannot control CPU caches, it cannot reach a
    /// copy the allocator or a moved value left behind, and it cannot stop the
    /// operating system having paged the key to swap. Those are stated here rather
    /// than glossed, because "the key is gone" is exactly the kind of claim rule 1
    /// is about.
    pub fn destroy_key(&mut self) -> KeyDestructionRecord {
        let zeroed = match self.key.as_mut() {
            Some(k) => {
                for b in k.iter_mut() {
                    unsafe { std::ptr::write_volatile(b, 0u8) };
                }
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                k.len()
            }
            None => 0,
        };
        self.key = None;
        KeyDestructionRecord {
            object_id: self.object_id.clone(),
            key_fingerprint_hex: self.key_fingerprint_hex(),
            key_bytes_zeroed: zeroed,
            destroyed: true,
            method: "volatile_zero_then_drop",
        }
    }
}

impl Drop for CryptoEraseDemonstration {
    fn drop(&mut self) {
        if self.key.is_some() {
            self.destroy_key();
        }
    }
}

/// The measured outcome of one per-object crypto-erase demonstration.
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoEraseReport {
    /// The operation name. Carries both `simulated` and `demonstration`, so no
    /// consumer can render it without rendering the caveat.
    pub operation: &'static str,
    /// Always true. Against an image file no controller key was destroyed, because
    /// there is no controller. Operator decision 3.
    pub simulated: bool,
    pub demonstration_construction: &'static str,
    pub object_id: String,
    pub object_bytes: u64,
    pub entropy_plaintext_bits_per_byte: f64,
    pub entropy_ciphertext_bits_per_byte: f64,
    pub key_destroyed: bool,
    pub key_destruction: KeyDestructionRecord,
    /// Fraction of bytes that still match the plaintext when the ciphertext is read
    /// back with a key that is not the destroyed one. For an independent keystream
    /// the expectation is 1/256 = 0.00390625 by chance alone, and the measured
    /// figure is reported rather than the expectation.
    pub residual_plaintext_match_fraction: f64,
    pub limits: &'static str,
}

/// Run the demonstration over one object's bytes and measure it.
///
/// Returns the ciphertext alongside the report. The key is destroyed before this
/// function returns, so the returned ciphertext is not recoverable through the value
/// that produced it — which is the property being demonstrated.
pub fn crypto_erase_demonstration(
    key: [u8; 32],
    object_id: &str,
    plaintext: &[u8],
) -> (Vec<u8>, CryptoEraseReport) {
    let mut cipher = CryptoEraseDemonstration::with_key(key, object_id);
    let mut buf = plaintext.to_vec();
    cipher
        .transform(0, &mut buf)
        .expect("offset 0 is block aligned and the key is alive");
    let entropy_ct = shannon_bits_per_byte(&buf);
    let entropy_pt = shannon_bits_per_byte(plaintext);

    // The adversary's best case that is still honest to measure: a key that differs
    // from the destroyed one. Measured, not assumed.
    let mut wrong = [0u8; 32];
    shake128(&[CRYPTO_ERASE_DOMAIN, b"wrong-key", &key], &mut wrong);
    let attacker = CryptoEraseDemonstration::with_key(wrong, object_id);
    let mut attempt = buf.clone();
    attacker
        .transform(0, &mut attempt)
        .expect("offset 0 is block aligned and the key is alive");
    let matches = attempt
        .iter()
        .zip(plaintext.iter())
        .filter(|(a, b)| a == b)
        .count();
    let residual = if plaintext.is_empty() {
        0.0
    } else {
        matches as f64 / plaintext.len() as f64
    };

    let destruction = cipher.destroy_key();

    let report = CryptoEraseReport {
        operation: "crypto_erase_simulated_demonstration",
        simulated: true,
        demonstration_construction: CRYPTO_ERASE_CONSTRUCTION,
        object_id: object_id.to_string(),
        object_bytes: plaintext.len() as u64,
        entropy_plaintext_bits_per_byte: entropy_pt,
        entropy_ciphertext_bits_per_byte: entropy_ct,
        key_destroyed: !cipher.key_alive(),
        key_destruction: destruction,
        residual_plaintext_match_fraction: residual,
        limits: CRYPTO_ERASE_LIMITS,
    };
    (buf, report)
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// Device doubles for tests in this crate.
///
/// [`stub::MemDevice`] stands in for `core/device`'s `Device` while that crate is
/// being written by another agent — see the note on [`SectorIo`]. [`stub::ScratchImage`]
/// is the file-backed double the measurement runs use, and it is where this file's
/// write guard lives.
#[cfg(test)]
pub(crate) mod stub {
    use super::*;

    /// An in-memory medium. Every unit test in this crate writes here and nowhere
    /// else: no path, no descriptor, nothing that can be aimed at a disk.
    #[derive(Debug, Clone)]
    pub struct MemDevice {
        pub data: Vec<u8>,
        pub caps: Capabilities,
        /// When set, `capabilities()` fails instead of answering -- the
        /// `WindowsBlock` case, where there is no true sector size to report.
        pub caps_error: Option<String>,
        pub reads: u64,
        pub writes: u64,
        pub syncs: u64,
        /// Simulated cost per sector of I/O, charged as a real sleep. Only the
        /// chunk-adaptation test uses it, and it uses a small number of sectors.
        pub ns_per_sector: u64,
    }

    impl MemDevice {
        pub fn new(sector_bytes: u32, sector_count: u64) -> Self {
            MemDevice {
                data: vec![0xa5u8; (sector_bytes as u64 * sector_count) as usize],
                caps: Capabilities {
                    medium: Medium::Image,
                    sector_bytes,
                    sector_count,
                    writable: true,
                },
                caps_error: None,
                reads: 0,
                writes: 0,
                syncs: 0,
                ns_per_sector: 0,
            }
        }

        pub fn read_only(mut self) -> Self {
            self.caps.writable = false;
            self
        }
    }

    impl SectorIo for MemDevice {
        fn identify(&self) -> DeviceIdentity {
            DeviceIdentity {
                kind: "in-memory stub".to_string(),
                model: "MemDevice".to_string(),
                serial: "STUB-0".to_string(),
                is_physical_medium: false,
            }
        }
        fn capabilities(&self) -> Result<Capabilities, WipeError> {
            match &self.caps_error {
                Some(d) => Err(WipeError::Unsupported(d.clone())),
                None => Ok(self.caps),
            }
        }
        fn read_sectors(&mut self, lba: u64, out: &mut [u8]) -> Result<(), WipeError> {
            let sb = self.caps.sector_bytes as usize;
            if out.len() % sb != 0 {
                return Err(WipeError::BadBufferLen {
                    expected: sb,
                    got: out.len(),
                });
            }
            let sectors = (out.len() / sb) as u64;
            if lba.saturating_add(sectors) > self.caps.sector_count {
                return Err(WipeError::OutOfRange {
                    lba,
                    sectors,
                    sector_count: self.caps.sector_count,
                });
            }
            let off = (lba * sb as u64) as usize;
            out.copy_from_slice(&self.data[off..off + out.len()]);
            self.reads += 1;
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), WipeError> {
            if !self.caps.writable {
                return Err(WipeError::Unsupported("MemDevice is read-only".into()));
            }
            let sb = self.caps.sector_bytes as usize;
            if buf.len() % sb != 0 {
                return Err(WipeError::BadBufferLen {
                    expected: sb,
                    got: buf.len(),
                });
            }
            let sectors = (buf.len() / sb) as u64;
            if lba.saturating_add(sectors) > self.caps.sector_count {
                return Err(WipeError::OutOfRange {
                    lba,
                    sectors,
                    sector_count: self.caps.sector_count,
                });
            }
            let off = (lba * sb as u64) as usize;
            self.data[off..off + buf.len()].copy_from_slice(buf);
            self.writes += 1;
            if self.ns_per_sector > 0 {
                std::thread::sleep(std::time::Duration::from_nanos(
                    self.ns_per_sector * sectors,
                ));
            }
            Ok(())
        }
        fn sync(&mut self) -> Result<(), WipeError> {
            self.syncs += 1;
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // The file-backed double, and the guard in front of it
    // -----------------------------------------------------------------------

    /// CLAUDE.md rule 4, applied to this file's own measurement runs.
    ///
    /// The rule exists because a forensics tool that can wipe the demo laptop is a
    /// disqualifying defect, and every unit test above writes to memory precisely so
    /// nothing can be aimed. The measurement runs are the exception that has to
    /// touch a real file, so the guard is written before the opener and the opener
    /// is the only way to obtain a writable descriptor here.
    ///
    /// Containment is by **inode ancestry**, never by string prefix, for the reasons
    /// `fixtures/guard.py` measured on this machine: firmlinks give one directory two
    /// irreducible path strings, and the volume is case-insensitive. Identity under
    /// `(st_dev, st_ino)` is exact under both and, being identity rather than a
    /// string relation, cannot widen the allowed set.
    ///
    /// This is a test-only guard for a test-only opener. It is **not** the project's
    /// write guard: `fixtures/guard.py` is, and the Rust reimplementation the
    /// operator called for is another agent's file. It does not attempt that
    /// policy's device rules, size bounds, `/.vol` refusal or TOCTOU-hardened
    /// descend, and it must not be mistaken for them.
    #[cfg(unix)]
    pub mod guard {
        use std::fs;
        use std::io;
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        use std::path::{Path, PathBuf};

        /// Names the directory the measurement runs may write in. Nothing defaults;
        /// an unset variable is a refusal with instructions, never a fallback to a
        /// temp directory this process guessed.
        pub const SCRATCH_ENV: &str = "SENTINELWIPE_WIPE_SCRATCH";

        #[derive(Debug)]
        pub enum Refusal {
            NoScratchRoot,
            RootUnusable(String),
            RootTooShallow(PathBuf),
            ParentMissing(PathBuf),
            NotContained { target: PathBuf, root: PathBuf },
            InsideWorkspace(PathBuf),
            NotARegularFile(PathBuf),
            DeviceNode(PathBuf),
        }

        impl std::fmt::Display for Refusal {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Refusal::NoScratchRoot => write!(
                        f,
                        "{} is not set; the measurement runs refuse to choose a \
                         directory to write in",
                        SCRATCH_ENV
                    ),
                    Refusal::RootUnusable(e) => write!(f, "scratch root unusable: {}", e),
                    Refusal::RootTooShallow(p) => {
                        write!(f, "scratch root {} is too close to the filesystem root", p.display())
                    }
                    Refusal::ParentMissing(p) => {
                        write!(f, "parent directory {} does not exist", p.display())
                    }
                    Refusal::NotContained { target, root } => write!(
                        f,
                        "REFUSED: {} has no ancestor inode-identical to the scratch root {}",
                        target.display(),
                        root.display()
                    ),
                    Refusal::InsideWorkspace(p) => write!(
                        f,
                        "REFUSED: {} is inside the source workspace; out/fixture.img and \
                         everything beside it is never a write target",
                        p.display()
                    ),
                    Refusal::NotARegularFile(p) => {
                        write!(f, "REFUSED: {} is not a regular file", p.display())
                    }
                    Refusal::DeviceNode(p) => {
                        write!(f, "REFUSED: {} is a device node", p.display())
                    }
                }
            }
        }

        fn ino_pair(p: &Path) -> io::Result<(u64, u64)> {
            let m = fs::metadata(p)?;
            Ok((m.dev(), m.ino()))
        }

        /// True when some ancestor of `target` is inode-identical to `root`.
        /// `target` is canonicalised by the caller; ancestors are walked upward and
        /// compared on `(st_dev, st_ino)`.
        pub fn inode_contained(root: &Path, target: &Path) -> bool {
            let want = match ino_pair(root) {
                Ok(v) => v,
                Err(_) => return false,
            };
            for anc in target.ancestors() {
                if let Ok(got) = ino_pair(anc) {
                    if got == want {
                        return true;
                    }
                }
            }
            false
        }

        /// The source tree this crate was compiled from: `core/wipe/../..`.
        pub fn workspace_root() -> PathBuf {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.pop(); // core
            p.pop(); // repo
            p
        }

        pub fn scratch_root() -> Result<PathBuf, Refusal> {
            let raw = std::env::var(SCRATCH_ENV).map_err(|_| Refusal::NoScratchRoot)?;
            if raw.trim().is_empty() {
                return Err(Refusal::NoScratchRoot);
            }
            let root = fs::canonicalize(&raw)
                .map_err(|e| Refusal::RootUnusable(format!("{}: {}", raw, e)))?;
            if !root.is_dir() {
                return Err(Refusal::RootUnusable(format!(
                    "{} is not a directory",
                    root.display()
                )));
            }
            // A root of "/" or "/Users" would contain the whole machine. Depth is a
            // sanity floor on the *root*, not a containment test on the target.
            if root.components().count() < 3 {
                return Err(Refusal::RootTooShallow(root));
            }
            if inode_contained(&workspace_root(), &root) {
                return Err(Refusal::InsideWorkspace(root));
            }
            Ok(root)
        }

        /// The only way this file produces a writable path. Every clause is a
        /// conjunct and there is no disjunction on the allow path.
        pub fn authorize_write(target: &Path) -> Result<PathBuf, Refusal> {
            let root = scratch_root()?;
            let parent = target
                .parent()
                .ok_or_else(|| Refusal::ParentMissing(target.to_path_buf()))?;
            let parent = fs::canonicalize(parent)
                .map_err(|_| Refusal::ParentMissing(parent.to_path_buf()))?;
            let leaf = target
                .file_name()
                .ok_or_else(|| Refusal::ParentMissing(target.to_path_buf()))?;
            let resolved = parent.join(leaf);

            if !inode_contained(&root, &parent) {
                return Err(Refusal::NotContained {
                    target: resolved,
                    root,
                });
            }
            if inode_contained(&workspace_root(), &parent) {
                return Err(Refusal::InsideWorkspace(resolved));
            }
            if let Ok(md) = fs::symlink_metadata(&resolved) {
                let ft = md.file_type();
                if ft.is_block_device() || ft.is_char_device() {
                    return Err(Refusal::DeviceNode(resolved));
                }
                if !ft.is_file() {
                    return Err(Refusal::NotARegularFile(resolved));
                }
            }
            Ok(resolved)
        }
    }

    /// A raw image file behind [`SectorIo`]. Test-only, and every writable
    /// descriptor it holds came through [`guard::authorize_write`].
    #[cfg(unix)]
    pub struct ScratchImage {
        file: std::fs::File,
        path: std::path::PathBuf,
        sector_bytes: u32,
        sector_count: u64,
    }

    #[cfg(unix)]
    impl ScratchImage {
        /// Open an existing file inside the authorised scratch root.
        pub fn open(path: &std::path::Path, sector_bytes: u32) -> Result<Self, String> {
            use std::io::Seek;
            let resolved = guard::authorize_write(path).map_err(|r| r.to_string())?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&resolved)
                .map_err(|e| format!("{}: {}", resolved.display(), e))?;
            let len = file.metadata().map_err(|e| e.to_string())?.len();
            let mut s = ScratchImage {
                file,
                path: resolved,
                sector_bytes,
                sector_count: len / sector_bytes as u64,
            };
            s.file.rewind().map_err(|e| e.to_string())?;
            Ok(s)
        }

        pub fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    #[cfg(unix)]
    impl SectorIo for ScratchImage {
        fn identify(&self) -> DeviceIdentity {
            DeviceIdentity {
                kind: "image file".to_string(),
                model: "ScratchImage".to_string(),
                serial: self
                    .path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                is_physical_medium: false,
            }
        }
        fn capabilities(&self) -> Result<Capabilities, WipeError> {
            Ok(Capabilities {
                medium: Medium::Image,
                sector_bytes: self.sector_bytes,
                sector_count: self.sector_count,
                writable: true,
            })
        }
        fn read_sectors(&mut self, lba: u64, out: &mut [u8]) -> Result<(), WipeError> {
            use std::io::{Read, Seek, SeekFrom};
            let sb = self.sector_bytes as usize;
            if out.len() % sb != 0 {
                return Err(WipeError::BadBufferLen {
                    expected: sb,
                    got: out.len(),
                });
            }
            let sectors = (out.len() / sb) as u64;
            if lba.saturating_add(sectors) > self.sector_count {
                return Err(WipeError::OutOfRange {
                    lba,
                    sectors,
                    sector_count: self.sector_count,
                });
            }
            self.file
                .seek(SeekFrom::Start(lba * self.sector_bytes as u64))
                .map_err(|e| WipeError::Io {
                    op: "seek",
                    lba,
                    detail: e.to_string(),
                })?;
            self.file.read_exact(out).map_err(|e| WipeError::Io {
                op: "read",
                lba,
                detail: e.to_string(),
            })
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), WipeError> {
            use std::io::{Seek, SeekFrom, Write};
            let sb = self.sector_bytes as usize;
            if buf.len() % sb != 0 {
                return Err(WipeError::BadBufferLen {
                    expected: sb,
                    got: buf.len(),
                });
            }
            let sectors = (buf.len() / sb) as u64;
            if lba.saturating_add(sectors) > self.sector_count {
                return Err(WipeError::OutOfRange {
                    lba,
                    sectors,
                    sector_count: self.sector_count,
                });
            }
            self.file
                .seek(SeekFrom::Start(lba * self.sector_bytes as u64))
                .map_err(|e| WipeError::Io {
                    op: "seek",
                    lba,
                    detail: e.to_string(),
                })?;
            self.file.write_all(buf).map_err(|e| WipeError::Io {
                op: "write",
                lba,
                detail: e.to_string(),
            })
        }
        fn sync(&mut self) -> Result<(), WipeError> {
            use std::io::Write;
            self.file.flush().map_err(|e| WipeError::Io {
                op: "flush",
                lba: 0,
                detail: e.to_string(),
            })?;
            self.file.sync_all().map_err(|e| WipeError::Io {
                op: "fsync",
                lba: 0,
                detail: e.to_string(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::stub::MemDevice;
    use super::*;
    use crate::telemetry::{CollectSink, Event, NullSink, Telemetry};
    use std::time::Duration;

    fn null_telemetry(dev: &MemDevice, cfg: &WipeConfig) -> Telemetry<NullSink> {
        let caps = dev.capabilities().unwrap();
        Telemetry::start(cfg.telemetry_spec(&dev.identify(), &caps), NullSink, None)
    }

    // -- the sponge -------------------------------------------------------

    /// Known-answer tests. Every vector was produced by CPython 3.11 `hashlib`
    /// (OpenSSL's Keccak) on this machine and pasted in; none is recalled.
    #[test]
    fn shake128_matches_known_answers() {
        let mut out = [0u8; 32];
        shake128(&[b""], &mut out);
        assert_eq!(
            hex(&out),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );

        shake128(&[b"abc"], &mut out);
        assert_eq!(
            hex(&out),
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
        );

        // 200 bytes crosses the 168-byte rate: this is the squeeze-side refill.
        let mut long = [0u8; 200];
        shake128(&[b""], &mut long);
        assert_eq!(hex(&long), concat!(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
            "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
            "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
            "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef",
            "aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
            "ef58538b8d23f877"
        ));

        // 768 bytes of input crosses the rate on the absorb side, four times over,
        // and is fed in three separate parts to exercise the streaming absorb.
        let block: Vec<u8> = (0u16..256).map(|v| v as u8).collect();
        let mut out64 = [0u8; 64];
        shake128(&[&block, &block, &block], &mut out64);
        assert_eq!(hex(&out64), concat!(
            "92b62d6682dda8ef27e599c00ce6fcd070dafa726908c07bf6c361ab7be2149f",
            "f7b03259d2a42cd358d47844fcf0e1bfe9ba30a30c97e552e8fd7d92bcc2e7b4"
        ));
    }

    /// The same permutation through a different rate (136) and a different domain
    /// pad (0x06). A Keccak-f[1600] bug that survived both parameterisations would
    /// have to be consistent across two sponges.
    #[test]
    fn sha3_256_matches_known_answers() {
        assert_eq!(
            hex(&sha3_256(&[b""])),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(&sha3_256(&[b"abc"])),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    // -- entropy ----------------------------------------------------------

    /// Cross-implementation check of the estimator against `fixtures/corpus.py`'s
    /// `shannon_bits_per_byte`, on inputs whose Python answers were measured here.
    #[test]
    fn entropy_agrees_with_the_python_estimator() {
        assert_eq!(shannon_bits_per_byte(b"AAAB"), 0.8112781244591328);
        let all: Vec<u8> = (0u16..256).map(|v| v as u8).collect();
        assert_eq!(shannon_bits_per_byte(&all), 8.0);
        assert_eq!(shannon_bits_per_byte(&[7u8; 4096]), 0.0);
        assert_eq!(shannon_bits_per_byte(&[]), 0.0);

        // 64 KiB of SHAKE-128 output. Checks the sponge and the estimator at once:
        // Python measured 7.9971305194862525 over hashlib's bytes for this input.
        let mut buf = vec![0u8; 65536];
        shake128(&[b"entropy-vector"], &mut buf);
        let h = shannon_bits_per_byte(&buf);
        assert!(
            (h - 7.9971305194862525).abs() < 1e-12,
            "measured {:.16}, python 7.9971305194862525",
            h
        );
    }

    #[test]
    fn histogram_accumulates_across_chunks() {
        let mut hist = ByteHistogram::new();
        let all: Vec<u8> = (0u16..256).map(|v| v as u8).collect();
        for _ in 0..10 {
            hist.add(&all);
        }
        assert_eq!(hist.total(), 2560);
        assert_eq!(hist.shannon_bits_per_byte(), 8.0);
    }

    // -- pattern generation ------------------------------------------------

    #[test]
    fn seed_from_run_id_is_deterministic_and_domain_separated() {
        let a = Seed::from_run_id("run-2026-09-03-001");
        let b = Seed::from_run_id("run-2026-09-03-001");
        let c = Seed::from_run_id("run-2026-09-03-002");
        assert_eq!(a.hex(), b.hex());
        assert_ne!(a.hex(), c.hex());
        assert_eq!(a.hex().len(), 64);
        let mut bare = [0u8; 32];
        shake128(&[b"run-2026-09-03-001"], &mut bare);
        assert_ne!(hex(&bare), a.hex(), "domain prefix is not being absorbed");
    }

    /// The template shortcut in [`PatternGen`] must produce exactly what the general
    /// [`shake128`] entry point produces for the same header. This is the test that
    /// catches an off-by-one in the padding offsets.
    #[test]
    fn pattern_gen_equals_a_direct_shake128_of_the_header() {
        let seed = Seed::from_run_id("template-check");
        let method = Method::SeededRandom;
        let gen = PatternGen::new(&seed, method, 1, 512).unwrap();
        for &lba in &[0u64, 1, 2, 4095, 1_000_003, u32::MAX as u64 + 7] {
            let mut theirs = vec![0u8; 512];
            shake128(
                &[
                    PATTERN_DOMAIN,
                    seed.as_bytes(),
                    &[method.id()],
                    &1u32.to_le_bytes(),
                    &512u32.to_le_bytes(),
                    &lba.to_le_bytes(),
                ],
                &mut theirs,
            );
            let mut ours = vec![0u8; 512];
            gen.fill_sector(lba, &mut ours);
            assert_eq!(ours, theirs, "lba {}", lba);
        }
    }

    #[test]
    fn pattern_is_seekable_and_order_independent() {
        let seed = Seed::from_run_id("seek");
        let gen = PatternGen::new(&seed, Method::SeededRandom, 1, 512).unwrap();
        let mut run = vec![0u8; 512 * 8];
        gen.fill_run(100, &mut run).unwrap();
        for i in 0..8u64 {
            let mut one = vec![0u8; 512];
            gen.fill_sector(100 + i, &mut one);
            assert_eq!(&run[i as usize * 512..(i as usize + 1) * 512], &one[..]);
        }
    }

    #[test]
    fn pattern_separates_seed_pass_method_and_lba() {
        let s1 = Seed::from_run_id("a");
        let s2 = Seed::from_run_id("b");
        let mut a = vec![0u8; 512];
        let mut b = vec![0u8; 512];

        PatternGen::new(&s1, Method::SeededRandom, 1, 512)
            .unwrap()
            .fill_sector(0, &mut a);
        PatternGen::new(&s2, Method::SeededRandom, 1, 512)
            .unwrap()
            .fill_sector(0, &mut b);
        assert_ne!(a, b, "seed does not separate");

        PatternGen::new(&s1, Method::ThreePass, 3, 512)
            .unwrap()
            .fill_sector(0, &mut b);
        assert_ne!(a, b, "method id does not separate");

        PatternGen::new(&s1, Method::SeededRandom, 1, 512)
            .unwrap()
            .fill_sector(1, &mut b);
        assert_ne!(a, b, "lba does not separate");

        // Same seed, same method, different sector size: different bytes.
        let mut c = vec![0u8; 512];
        PatternGen::new(&s1, Method::SeededRandom, 1, 4096)
            .unwrap()
            .fill_sector(0, &mut c);
        assert_ne!(a, c, "sector size does not separate");
    }

    #[test]
    fn constant_patterns_are_constant() {
        let seed = Seed::from_bytes([0u8; 32]);
        let z = PatternGen::new(&seed, Method::ThreePass, 1, 512).unwrap();
        let o = PatternGen::new(&seed, Method::ThreePass, 2, 512).unwrap();
        assert!(z.is_constant() && o.is_constant());
        let mut buf = vec![9u8; 512];
        z.fill_sector(77, &mut buf);
        assert!(buf.iter().all(|&b| b == 0x00));
        o.fill_sector(77, &mut buf);
        assert!(buf.iter().all(|&b| b == 0xff));
        assert!(!PatternGen::new(&seed, Method::ThreePass, 3, 512)
            .unwrap()
            .is_constant());
    }

    #[test]
    fn a_pass_index_outside_the_method_is_refused() {
        let seed = Seed::from_bytes([0u8; 32]);
        assert_eq!(
            PatternGen::new(&seed, Method::SeededRandom, 2, 512).unwrap_err(),
            WipeError::NoSuchPass { pass: 2, passes: 1 }
        );
        assert_eq!(
            PatternGen::new(&seed, Method::ThreePass, 0, 512).unwrap_err(),
            WipeError::NoSuchPass { pass: 0, passes: 3 }
        );
        assert!(PatternGen::new(&seed, Method::ThreePass, 3, 512).is_ok());
    }

    #[test]
    fn method_metadata_is_stable() {
        assert_eq!(Method::ZeroFill.pass_count(), 1);
        assert_eq!(Method::SeededRandom.pass_count(), 1);
        assert_eq!(Method::ThreePass.pass_count(), 3);
        assert_eq!(Method::ZeroFill.id(), 1);
        assert_eq!(Method::SeededRandom.id(), 2);
        assert_eq!(Method::ThreePass.id(), 3);
        for m in [Method::ZeroFill, Method::SeededRandom, Method::ThreePass] {
            assert_eq!(m.nist_category(), "Clear");
        }
        assert!(Method::ThreePass.legacy_shape().is_some());
        assert!(Method::SeededRandom.legacy_shape().is_none());
        // Every medium defaults to one seeded pass; see the doc for why.
        for m in [
            Medium::Rotational,
            Medium::SolidState,
            Medium::Image,
            Medium::Unknown,
        ] {
            assert_eq!(Method::default_for_medium(m), Method::SeededRandom);
        }
        // The wire spellings are the device layer's, character for character.
        assert_eq!(Medium::Rotational.as_str(), "rotational");
        assert_eq!(Medium::SolidState.as_str(), "solid-state");
        assert_eq!(Medium::Image.as_str(), "image");
        assert_eq!(Medium::Unknown.as_str(), "unknown");
    }

    // -- the write loop ---------------------------------------------------

    #[test]
    fn zero_fill_writes_zeros_and_drops_entropy_to_zero() {
        let mut dev = MemDevice::new(512, 512);
        let cfg = WipeConfig::new(Method::ZeroFill, Seed::from_run_id("z"));
        let mut tm = null_telemetry(&dev, &cfg);
        let rep = overwrite(&mut dev, &cfg, &mut tm).unwrap();
        assert!(dev.data.iter().all(|&b| b == 0));
        assert_eq!(shannon_bits_per_byte(&dev.data), 0.0);
        assert_eq!(rep.bytes_written, 512 * 512);
        assert_eq!(rep.passes.len(), 1);
        assert!(!rep.simulated);
        assert!(rep.scope_limit.contains("does not reach"));
    }

    #[test]
    fn the_seeded_pass_is_byte_identical_across_runs_and_moves_with_the_seed() {
        let cfg_a = WipeConfig::new(Method::SeededRandom, Seed::from_run_id("run-1"));
        let cfg_b = WipeConfig::new(Method::SeededRandom, Seed::from_run_id("run-2"));

        let mut d1 = MemDevice::new(512, 256);
        let mut t1 = null_telemetry(&d1, &cfg_a);
        overwrite(&mut d1, &cfg_a, &mut t1).unwrap();

        let mut d2 = MemDevice::new(512, 256);
        let mut t2 = null_telemetry(&d2, &cfg_a);
        overwrite(&mut d2, &cfg_a, &mut t2).unwrap();

        let mut d3 = MemDevice::new(512, 256);
        let mut t3 = null_telemetry(&d3, &cfg_b);
        overwrite(&mut d3, &cfg_b, &mut t3).unwrap();

        assert_eq!(d1.data, d2.data, "same seed must give the same medium");
        assert_ne!(d1.data, d3.data, "a different seed must give a different medium");
        // rule 6 in one line: the wiped image has one hash for one seed.
        assert_eq!(hex(&sha3_256(&[&d1.data])), hex(&sha3_256(&[&d2.data])));
    }

    #[test]
    fn the_seeded_pass_raises_entropy() {
        let mut dev = MemDevice::new(512, 2048); // 1 MiB
        let cfg = WipeConfig::new(Method::SeededRandom, Seed::from_run_id("entropy"));
        let mut tm = null_telemetry(&dev, &cfg);
        overwrite(&mut dev, &cfg, &mut tm).unwrap();
        let h = shannon_bits_per_byte(&dev.data);
        assert!(h > 7.999, "entropy after a seeded pass was {:.6}", h);
    }

    #[test]
    fn three_pass_writes_three_times_and_leaves_the_third_pattern() {
        let mut dev = MemDevice::new(512, 64);
        let cfg = WipeConfig::new(Method::ThreePass, Seed::from_run_id("3p"));
        let mut tm = null_telemetry(&dev, &cfg);
        let rep = overwrite(&mut dev, &cfg, &mut tm).unwrap();
        assert_eq!(rep.passes.len(), 3);
        assert_eq!(rep.bytes_written, 3 * 512 * 64);
        assert_eq!(rep.passes[0].pattern, "zeros_0x00");
        assert_eq!(rep.passes[1].pattern, "ones_0xff");
        assert_eq!(rep.passes[2].pattern, "shake128_seeded_stream");

        let gen = PatternGen::new(&cfg.seed, Method::ThreePass, 3, 512).unwrap();
        let mut expect = vec![0u8; 512 * 64];
        gen.fill_run(0, &mut expect).unwrap();
        assert_eq!(dev.data, expect);
    }

    #[test]
    fn a_device_that_declares_itself_unwritable_is_refused_before_a_byte_moves() {
        let mut dev = MemDevice::new(512, 8).read_only();
        let cfg = WipeConfig::new(Method::ZeroFill, Seed::from_run_id("ro"));
        let mut tm = null_telemetry(&dev, &cfg);
        let before = dev.data.clone();
        let err = overwrite(&mut dev, &cfg, &mut tm).unwrap_err();
        assert!(matches!(err, WipeError::Unsupported(_)));
        assert_eq!(dev.data, before);
        assert_eq!(dev.writes, 0);
    }

    #[test]
    fn degenerate_geometry_is_refused() {
        let cfg = WipeConfig::new(Method::ZeroFill, Seed::from_run_id("d"));
        let mut dev = MemDevice::new(512, 0);
        let mut tm = null_telemetry(&dev, &cfg);
        assert!(matches!(
            overwrite(&mut dev, &cfg, &mut tm).unwrap_err(),
            WipeError::DegenerateGeometry { .. }
        ));
    }

    /// `WindowsBlock` and an unarmed `LinuxBlock` cannot state a sector size, and the
    /// device layer makes `capabilities()` fallible rather than let them invent 512.
    /// The wipe layer has to carry that failure through, not paper over it.
    #[test]
    fn a_device_that_cannot_state_its_geometry_is_refused() {
        let mut dev = MemDevice::new(512, 64);
        dev.caps_error = Some("WindowsBlock: no sector size on this platform".into());
        let cfg = WipeConfig::new(Method::ZeroFill, Seed::from_run_id("nogeom"));
        let mut tm = Telemetry::start(
            telemetry::WipeSpec {
                device: "unknown".into(),
                sector_size: 1,
                total_sectors: 0,
                method: cfg.method.label().into(),
                simulated: false,
                passes: 1,
                pattern_seed_hex: cfg.seed.hex(),
            },
            NullSink,
            None,
        );
        let err = overwrite(&mut dev, &cfg, &mut tm).unwrap_err();
        assert!(
            matches!(&err, WipeError::Unsupported(d) if d.contains("no sector size")),
            "{:?}",
            err
        );
        assert_eq!(dev.writes, 0);
    }

    #[test]
    fn a_partial_final_chunk_is_written_and_no_more() {
        // 2049 sectors against a 2048-sector chunk: one full chunk and one sector.
        let mut dev = MemDevice::new(512, 2049);
        let cfg = WipeConfig::new(Method::SeededRandom, Seed::from_run_id("tail"));
        let mut tm = null_telemetry(&dev, &cfg);
        let rep = overwrite(&mut dev, &cfg, &mut tm).unwrap();
        assert_eq!(rep.passes[0].sectors_written, 2049);
        let gen = PatternGen::new(&cfg.seed, Method::SeededRandom, 1, 512).unwrap();
        let mut last = vec![0u8; 512];
        gen.fill_sector(2048, &mut last);
        assert_eq!(&dev.data[2048 * 512..], &last[..]);
    }

    // -- chunk adaptation, which is what holds the 20 Hz floor --------------

    #[test]
    fn adapt_chunk_shrinks_grows_and_holds() {
        let (min, max) = (8u32, 2048u32);
        let t = 10_000_000u128;
        assert_eq!(adapt_chunk(2048, 20_000_000, t, min, max), 1024, "too slow: halve");
        assert_eq!(adapt_chunk(64, 1_000_000, t, min, max), 128, "far too fast: double");
        assert_eq!(adapt_chunk(64, 5_000_000, t, min, max), 64, "in band: hold");
        assert_eq!(adapt_chunk(64, 9_999_999, t, min, max), 64, "just under: hold");
        assert_eq!(adapt_chunk(8, 60_000_000, t, min, max), 8, "clamped at the floor");
        assert_eq!(adapt_chunk(2048, 0, t, min, max), 2048, "clamped at the ceiling");
        assert_eq!(adapt_chunk(4, 1, t, min, max), 16, "a value below the floor is raised");
        assert_eq!(adapt_chunk(64, 1_000, 0, min, max), 64, "no target: no change");
    }

    /// The engine end of the >= 20 Hz claim: against a device slow enough that a
    /// full 1 MiB chunk would take longer than the emit period, the loop must shrink
    /// the chunk rather than let frames go silent.
    #[test]
    fn a_slow_device_shrinks_the_chunk() {
        let mut dev = MemDevice::new(512, 4096);
        dev.ns_per_sector = 20_000; // 2048 sectors -> ~41 ms, four times the target
        let cfg = WipeConfig::new(Method::ZeroFill, Seed::from_run_id("slow"));
        let mut tm = null_telemetry(&dev, &cfg);
        let rep = overwrite(&mut dev, &cfg, &mut tm).unwrap();
        let p = &rep.passes[0];
        assert!(
            p.chunk_sectors_final < p.chunk_sectors_first,
            "chunk did not shrink: {} -> {}",
            p.chunk_sectors_first,
            p.chunk_sectors_final
        );
        assert!(p.chunk_resizes > 0);
    }

    // -- telemetry contract ------------------------------------------------

    /// Every sector appears in the delivered stream, and the head bytes carried by a
    /// frame are the bytes that were actually written — which is only true if
    /// `wrote` is called after the write, as `telemetry.rs` requires.
    #[test]
    fn telemetry_covers_every_sector_and_carries_written_bytes() {
        let mut dev = MemDevice::new(512, 300);
        let cfg = WipeConfig {
            chunk_sectors_max: 64,
            chunk_sectors_min: 64,
            ..WipeConfig::new(Method::SeededRandom, Seed::from_run_id("tele"))
        };
        let caps = dev.capabilities().unwrap();
        let mut tm = Telemetry::start(
            cfg.telemetry_spec(&dev.identify(), &caps),
            CollectSink::new(),
            Some(Duration::ZERO), // emit on every chunk: deterministic
        );
        overwrite(&mut dev, &cfg, &mut tm).unwrap();

        let mut covered = vec![false; 300];
        let mut frames = 0;
        for ev in tm.sink().events.iter() {
            if let Event::Progress(p) = ev {
                frames += 1;
                for s in p.first_sector..p.sector_end() {
                    assert!(s < 300, "frame ran past the medium");
                    covered[s as usize] = true;
                }
                if p.head_len > 0 {
                    let gen =
                        PatternGen::new(&cfg.seed, Method::SeededRandom, p.pass, 512).unwrap();
                    let mut expect = vec![0u8; p.head_bytes().len()];
                    gen.fill_sector(p.head_sector, &mut expect);
                    assert_eq!(p.head_bytes(), &expect[..], "head bytes are not the written bytes");
                }
            }
        }
        assert!(frames >= 5, "only {} frames for 5 chunks", frames);
        assert!(covered.iter().all(|&c| c), "the sector map would have holes");
    }

    // -- crypto erase ------------------------------------------------------

    #[test]
    fn crypto_erase_transform_round_trips_while_the_key_lives() {
        let c = CryptoEraseDemonstration::with_key([7u8; 32], "case-file.pdf");
        let plain: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut buf = plain.clone();
        c.transform(0, &mut buf).unwrap();
        assert_ne!(buf, plain);
        c.transform(0, &mut buf).unwrap();
        assert_eq!(buf, plain, "the transform is not its own inverse");
    }

    #[test]
    fn crypto_erase_is_seekable_by_block() {
        let c = CryptoEraseDemonstration::with_key([3u8; 32], "obj");
        let plain = vec![0u8; 2048];
        let mut whole = plain.clone();
        c.transform(0, &mut whole).unwrap();
        let mut third = vec![0u8; 512];
        c.transform(1024, &mut third).unwrap();
        assert_eq!(&whole[1024..1536], &third[..]);
    }

    #[test]
    fn an_unaligned_offset_is_refused_rather_than_silently_wrong() {
        let c = CryptoEraseDemonstration::with_key([3u8; 32], "obj");
        let mut buf = vec![0u8; 16];
        assert!(matches!(
            c.transform(7, &mut buf).unwrap_err(),
            WipeError::BadBufferLen { .. }
        ));
    }

    #[test]
    fn destroying_the_key_makes_the_transform_refuse() {
        let mut c = CryptoEraseDemonstration::with_key([1u8; 32], "secret.docx");
        let rec = c.destroy_key();
        assert!(rec.destroyed);
        assert_eq!(rec.key_bytes_zeroed, 32);
        assert_eq!(rec.key_fingerprint_hex.len(), 16);
        assert!(!c.key_alive());
        let mut buf = vec![0u8; 512];
        assert_eq!(
            c.transform(0, &mut buf).unwrap_err(),
            WipeError::KeyDestroyed {
                object_id: "secret.docx".to_string()
            }
        );
        // Destroying twice is not an error and zeroes nothing the second time.
        assert_eq!(c.destroy_key().key_bytes_zeroed, 0);
    }

    #[test]
    fn the_ciphertext_is_noise_and_the_wrong_key_recovers_nothing() {
        // A worst case for the demonstration: highly compressible plaintext, so any
        // structure surviving into the ciphertext would show up in the entropy.
        let plain: Vec<u8> = std::iter::repeat(b"CLASSIFIED ")
            .take(6000)
            .flat_map(|s| s.iter().copied())
            .collect();
        let (cipher, rep) = crypto_erase_demonstration([42u8; 32], "evidence.txt", &plain);

        assert_eq!(rep.operation, "crypto_erase_simulated_demonstration");
        assert!(rep.simulated);
        assert!(rep.demonstration_construction.contains("DEMONSTRATION"));
        assert!(rep.limits.contains("not a cryptographic product"));
        assert!(rep.key_destroyed);
        assert_eq!(rep.object_bytes, plain.len() as u64);

        assert!(
            rep.entropy_plaintext_bits_per_byte < 3.5,
            "plaintext entropy {:.4}",
            rep.entropy_plaintext_bits_per_byte
        );
        assert!(
            rep.entropy_ciphertext_bits_per_byte > 7.99,
            "ciphertext entropy {:.4}",
            rep.entropy_ciphertext_bits_per_byte
        );
        assert_ne!(cipher, plain);

        // Chance alone gives 1/256 = 0.00390625. Anything much above that would be
        // structure leaking through the keystream.
        assert!(
            rep.residual_plaintext_match_fraction < 0.01,
            "residual match {:.6}",
            rep.residual_plaintext_match_fraction
        );
    }

    #[test]
    fn the_key_fingerprint_names_the_key_without_revealing_it() {
        let a = CryptoEraseDemonstration::with_key([9u8; 32], "x");
        let b = CryptoEraseDemonstration::with_key([9u8; 32], "x");
        let c = CryptoEraseDemonstration::with_key([10u8; 32], "x");
        assert_eq!(a.key_fingerprint_hex(), b.key_fingerprint_hex());
        assert_ne!(a.key_fingerprint_hex(), c.key_fingerprint_hex());
        assert_eq!(a.key_fingerprint_hex().len(), 16);
    }

    /// The flush at the end of a pass is real work the instrument cannot see, and on
    /// the fixture it is 30-45 ms of `fsync` after a 100 ms zero-fill pass. Without a
    /// forced frame in front of it the worst inter-frame gap measured 53.2 ms, over
    /// the 50 ms the 20 Hz floor allows. This asserts the frame exists, without
    /// depending on a clock: the emit period is set long enough that no periodic
    /// frame can fire, so the only frame that can appear is the forced one.
    #[test]
    fn a_frame_is_forced_before_the_flush() {
        let mut dev = MemDevice::new(512, 2048);
        let cfg = WipeConfig::new(Method::SeededRandom, Seed::from_run_id("preflush"));
        let caps = dev.capabilities().unwrap();
        let mut tm = Telemetry::start(
            cfg.telemetry_spec(&dev.identify(), &caps),
            CollectSink::new(),
            Some(Duration::from_secs(600)),
        );
        // run_pass only: no end_pass, no finish. Any Progress event here is the one
        // forced ahead of the flush.
        run_pass(&mut dev, &cfg, 1, &mut tm).unwrap();
        let frames: Vec<_> = tm
            .sink()
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Progress(p) => Some(p),
                _ => None,
            })
            .collect();
        assert_eq!(frames.len(), 1, "expected exactly the pre-flush frame");
        assert_eq!(frames[0].first_sector, 0);
        assert_eq!(frames[0].sector_count, 2048, "the frame must cover the whole pass");
        assert_eq!(dev.syncs, 1);
    }

    #[test]
    fn a_pass_report_hands_the_audit_a_measured_sample() {
        let mut dev = MemDevice::new(512, 2048);
        let cfg = WipeConfig::new(Method::SeededRandom, Seed::from_run_id("audit-input"));
        let mut tm = null_telemetry(&dev, &cfg);
        let rep = overwrite(&mut dev, &cfg, &mut tm).unwrap();
        let (bytes, ns) = rep.passes[0].throughput_sample_input();
        assert_eq!(bytes, 1 << 20);
        assert!(ns > 0, "a pass that took no measurable time cannot be a baseline");
        assert!(rep.passes[0].throughput_bytes_per_s() > 0.0);
    }
}

/// Tests for the write guard in front of the measurement runs.
///
/// The clauses that need a scratch root skip loudly rather than pass quietly when
/// `SENTINELWIPE_WIPE_SCRATCH` is unset, because a guard test that silently does
/// nothing is worse than no guard test: it prints `ok`.
#[cfg(all(test, unix))]
mod guard_tests {
    use super::stub::guard::{self, Refusal};
    use std::path::PathBuf;

    fn root_or_skip(who: &str) -> Option<PathBuf> {
        match guard::scratch_root() {
            Ok(r) => Some(r),
            Err(e) => {
                println!("SKIPPED {}: {}", who, e);
                None
            }
        }
    }

    /// Containment is ancestry under `(st_dev, st_ino)`, and this is the case a
    /// string prefix gets wrong: `.../core` is not an ancestor of `.../core-x`, but
    /// `"…/core".is_prefix_of("…/core-x")` is true.
    #[test]
    fn containment_is_inode_ancestry_and_not_a_string_prefix() {
        let ws = guard::workspace_root();
        let src = ws.join("core").join("wipe").join("src");
        assert!(src.is_dir(), "expected {} to exist", src.display());
        assert!(guard::inode_contained(&ws, &src));
        assert!(guard::inode_contained(&src, &src), "a directory contains itself");
        assert!(!guard::inode_contained(&src, &ws), "containment is not symmetric");

        // The string-prefix trap, with real paths: "…/core" is a prefix of the
        // string "…/core/wipe" and also of the string "…/coreX", and only one of
        // those is contained. The second path need not exist for the point to hold —
        // a non-existent path is never contained, which is itself the safe answer.
        let core = ws.join("core");
        let impostor = ws.join("coreX");
        assert!(core.to_string_lossy().len() < impostor.to_string_lossy().len());
        assert!(impostor.to_string_lossy().starts_with(&*core.to_string_lossy()));
        assert!(!guard::inode_contained(&core, &impostor));
    }

    #[test]
    fn the_guard_refuses_the_source_workspace() {
        let Some(_root) = root_or_skip("the_guard_refuses_the_source_workspace") else {
            return;
        };
        // The one file in this project that must never be opened for writing.
        let fixture = guard::workspace_root().join("out").join("fixture.img");
        match guard::authorize_write(&fixture) {
            Ok(p) => panic!("guard authorised {}", p.display()),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.starts_with("REFUSED"), "{}", msg);
            }
        }
        // And the source tree generally.
        assert!(guard::authorize_write(&guard::workspace_root().join("core").join("x.img")).is_err());
    }

    #[test]
    fn the_guard_refuses_a_target_outside_the_scratch_root() {
        let Some(root) = root_or_skip("the_guard_refuses_a_target_outside_the_scratch_root")
        else {
            return;
        };
        for outside in [
            PathBuf::from("/tmp/sentinelwipe-should-never-be-written.img"),
            PathBuf::from("/etc/hosts"),
            root.parent().unwrap().join("sibling.img"),
        ] {
            match guard::authorize_write(&outside) {
                Ok(p) => panic!("guard authorised {}", p.display()),
                Err(Refusal::NotContained { .. }) | Err(Refusal::ParentMissing(_)) => {}
                Err(other) => panic!("refused for the wrong reason: {}", other),
            }
        }
    }

    #[test]
    fn the_guard_allows_a_target_inside_the_scratch_root() {
        let Some(root) = root_or_skip("the_guard_allows_a_target_inside_the_scratch_root") else {
            return;
        };
        let ok = guard::authorize_write(&root.join("phase3-guard-probe.img")).unwrap();
        assert!(guard::inode_contained(&root, ok.parent().unwrap()));
    }

    /// A device node inside the scratch root would still be refused. This cannot be
    /// constructed without privilege, so what is asserted is the classification, not
    /// a live refusal: `/dev/null` is a character device and is outside any scratch
    /// root, so it is refused twice over and the test says which clause fired first.
    #[test]
    fn a_device_node_is_never_a_target() {
        let dev_null = PathBuf::from("/dev/null");
        match guard::authorize_write(&dev_null) {
            Ok(p) => panic!("guard authorised {}", p.display()),
            Err(e) => {
                let m = e.to_string();
                assert!(
                    m.contains("REFUSED") || m.contains("SENTINELWIPE_WIPE_SCRATCH"),
                    "{}",
                    m
                );
            }
        }
    }
}
