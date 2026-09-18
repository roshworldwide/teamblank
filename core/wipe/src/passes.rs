use std::fmt;
use std::time::Instant;

use crate::telemetry::{self, EventSink, Telemetry};

pub const OVERWRITE_SCOPE_LIMIT: &str = "\
An overwrite pass against an image file overwrites the byte range of that file and \
nothing else. It does not reach, and this tool does not claim to reach, prior copies \
of those bytes held by the host filesystem (copy-on-write snapshots, journals) or \
remapped by the host storage controller (wear levelling, over-provisioning, bad-block \
retirement). Purge of the underlying physical medium is neither performed nor claimed.";

pub const PATTERN_DOMAIN: &[u8] = b"SENTINELWIPE/wipe-pattern/v1";

pub const CRYPTO_ERASE_DOMAIN: &[u8] = b"SENTINELWIPE/crypto-erase-demo/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WipeError {
    Io {
        op: &'static str,
        lba: u64,
        detail: String,
    },
    Unsupported(String),
    OutOfRange {
        lba: u64,
        sectors: u64,
        sector_count: u64,
    },
    BadBufferLen { expected: usize, got: usize },
    DegenerateGeometry { sector_bytes: u32, sector_count: u64 },
    KeyDestroyed { object_id: String },
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Medium {
    Rotational,
    SolidState,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub kind: String,
    pub model: String,
    pub serial: String,
    pub is_physical_medium: bool,
}

impl DeviceIdentity {
    pub fn describe(&self) -> String {
        format!("{} {} {}", self.kind, self.model, self.serial)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub medium: Medium,
    pub sector_bytes: u32,
    pub sector_count: u64,
    pub writable: bool,
}

impl Capabilities {
    pub fn capacity_bytes(&self) -> u64 {
        self.sector_count.saturating_mul(self.sector_bytes as u64)
    }
}

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
pub trait SectorIo {
    fn identify(&self) -> DeviceIdentity;
    fn capabilities(&self) -> Result<Capabilities, WipeError>;
    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), WipeError>;
    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), WipeError>;
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

pub const SHAKE128_RATE: usize = 168;
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

#[inline]
fn keccak_f1600(a: &mut [u64; 25]) {
    for round in 0..24 {
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
        let mut last = a[1];
        for i in 0..24 {
            let j = KECCAK_PI[i];
            let tmp = a[j];
            a[j] = last.rotate_left(KECCAK_ROT[i]);
            last = tmp;
        }
        for y in 0..5 {
            let row = [a[5 * y], a[5 * y + 1], a[5 * y + 2], a[5 * y + 3], a[5 * y + 4]];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
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

pub fn shake128(parts: &[&[u8]], out: &mut [u8]) {
    let mut k = Keccak::shake128();
    for p in parts {
        k.absorb(p);
    }
    k.squeeze(out);
}

pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::sha3_256();
    for p in parts {
        k.absorb(p);
    }
    let mut out = [0u8; 32];
    k.squeeze(&mut out);
    out
}

pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

pub const RUN_SEED_DOMAIN: &[u8] = b"SENTINELWIPE/run-seed/v1";

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Seed([u8; 32]);

impl Seed {
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Seed(b)
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassPattern {
    Constant(u8),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    ZeroFill,
    SeededRandom,
    ThreePass,
}

impl Method {
    pub fn id(&self) -> u8 {
        match self {
            Method::ZeroFill => 1,
            Method::SeededRandom => 2,
            Method::ThreePass => 3,
        }
    }

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

    pub fn pattern(&self, pass: u32) -> Result<PassPattern, WipeError> {
        let passes = self.pass_count();
        if pass == 0 || pass > passes {
            return Err(WipeError::NoSuchPass { pass, passes });
        }
        Ok(self.patterns()[(pass - 1) as usize])
    }

    pub fn nist_category(&self) -> &'static str {
        "Clear"
    }

    pub fn legacy_shape(&self) -> Option<&'static str> {
        match self {
            Method::ThreePass => Some("three-pass overwrite shape (0x00, 0xFF, random)"),
            _ => None,
        }
    }

    pub fn default_for_medium(_medium: Medium) -> Method {
        Method::SeededRandom
    }
}

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

#[derive(Clone)]
pub struct PatternGen {
    pattern: PassPattern,
    sector_bytes: usize,
    template: [u64; 25],
    lba_off: usize,
    hdr_len: usize,
}

impl fmt::Debug for PatternGen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PatternGen")
            .field("pattern", &self.pattern.label())
            .field("sector_bytes", &self.sector_bytes)
            .finish_non_exhaustive()
    }
}

impl PatternGen {
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

    pub fn is_constant(&self) -> bool {
        matches!(self.pattern, PassPattern::Constant(_))
    }

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

pub fn shannon_bits_per_byte(data: &[u8]) -> f64 {
    let mut h = ByteHistogram::new();
    h.add(data);
    h.shannon_bits_per_byte()
}

pub const DEFAULT_CHUNK_SECTORS_MAX: u32 = 2048;
pub const DEFAULT_CHUNK_SECTORS_MIN: u32 = 8;
pub const DEFAULT_TARGET_CHUNK_NS: u128 = 10_000_000;

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

#[derive(Debug, Clone, PartialEq)]
pub struct PassReport {
    pub method_label: &'static str,
    pub pass: u32,
    pub passes: u32,
    pub pattern: &'static str,
    pub sector_bytes: u32,
    pub sectors_written: u64,
    pub bytes_written: u64,
    pub duration_ns: u128,
    pub sync_ns: u128,
    pub chunk_writes: u64,
    pub chunk_sectors_first: u32,
    pub chunk_sectors_final: u32,
    pub chunk_resizes: u32,
    pub max_chunk_ns: u128,
}

impl PassReport {
    pub fn throughput_bytes_per_s(&self) -> f64 {
        if self.duration_ns == 0 {
            0.0
        } else {
            self.bytes_written as f64 * 1_000_000_000.0 / self.duration_ns as f64
        }
    }

    pub fn throughput_sample_input(&self) -> (u64, u128) {
        (self.bytes_written, self.duration_ns)
    }
}

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
    pub simulated: bool,
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

pub const CRYPTO_ERASE_CONSTRUCTION: &str =
    "DEMONSTRATION_shake128_xor_keystream__not_a_certified_cipher";

pub const CRYPTO_ERASE_LIMITS: &str = "\
DEMONSTRATION ONLY. The transform is a XOR with a SHAKE-128 keystream keyed per \
512-byte block. It is not AES, it is not authenticated, it has no FIPS validation, it \
is not constant-time and it has had no cryptanalysis. It demonstrates the SHAPE of \
crypto-erase -- that destroying a key leaves ciphertext that is indistinguishable \
from noise -- and it is not a cryptographic product. Separately: on a real \
self-encrypting drive the key lives in the controller and this process never sees it, \
so a host-side crypto-erase against an image file is SIMULATED with respect to any \
real device and is labelled simulated in the report.";

pub const CRYPTO_ERASE_BLOCK: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDestructionRecord {
    pub object_id: String,
    pub key_fingerprint_hex: String,
    pub key_bytes_zeroed: usize,
    pub destroyed: bool,
    pub method: &'static str,
}

pub struct CryptoEraseDemonstration {
    key: Option<[u8; 32]>,
    key_fingerprint: [u8; 8],
    object_id: String,
}

impl CryptoEraseDemonstration {
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

#[derive(Debug, Clone, PartialEq)]
pub struct CryptoEraseReport {
    pub operation: &'static str,
    pub simulated: bool,
    pub demonstration_construction: &'static str,
    pub object_id: String,
    pub object_bytes: u64,
    pub entropy_plaintext_bits_per_byte: f64,
    pub entropy_ciphertext_bits_per_byte: f64,
    pub key_destroyed: bool,
    pub key_destruction: KeyDestructionRecord,
    pub residual_plaintext_match_fraction: f64,
    pub limits: &'static str,
}

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

#[cfg(test)]
pub(crate) mod stub {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct MemDevice {
        pub data: Vec<u8>,
        pub caps: Capabilities,
        pub caps_error: Option<String>,
        pub reads: u64,
        pub writes: u64,
        pub syncs: u64,
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

    #[cfg(unix)]
    pub mod guard {
        use std::fs;
        use std::io;
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        use std::path::{Path, PathBuf};

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

        pub fn workspace_root() -> PathBuf {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.pop();
            p.pop();
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
            if root.components().count() < 3 {
                return Err(Refusal::RootTooShallow(root));
            }
            if inode_contained(&workspace_root(), &root) {
                return Err(Refusal::InsideWorkspace(root));
            }
            Ok(root)
        }

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

    #[cfg(unix)]
    pub struct ScratchImage {
        file: std::fs::File,
        path: std::path::PathBuf,
        sector_bytes: u32,
        sector_count: u64,
    }

    #[cfg(unix)]
    impl ScratchImage {
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

        let block: Vec<u8> = (0u16..256).map(|v| v as u8).collect();
        let mut out64 = [0u8; 64];
        shake128(&[&block, &block, &block], &mut out64);
        assert_eq!(hex(&out64), concat!(
            "92b62d6682dda8ef27e599c00ce6fcd070dafa726908c07bf6c361ab7be2149f",
            "f7b03259d2a42cd358d47844fcf0e1bfe9ba30a30c97e552e8fd7d92bcc2e7b4"
        ));
    }

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

    #[test]
    fn entropy_agrees_with_the_python_estimator() {
        assert_eq!(shannon_bits_per_byte(b"AAAB"), 0.8112781244591328);
        let all: Vec<u8> = (0u16..256).map(|v| v as u8).collect();
        assert_eq!(shannon_bits_per_byte(&all), 8.0);
        assert_eq!(shannon_bits_per_byte(&[7u8; 4096]), 0.0);
        assert_eq!(shannon_bits_per_byte(&[]), 0.0);

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
        for m in [
            Medium::Rotational,
            Medium::SolidState,
            Medium::Image,
            Medium::Unknown,
        ] {
            assert_eq!(Method::default_for_medium(m), Method::SeededRandom);
        }
        assert_eq!(Medium::Rotational.as_str(), "rotational");
        assert_eq!(Medium::SolidState.as_str(), "solid-state");
        assert_eq!(Medium::Image.as_str(), "image");
        assert_eq!(Medium::Unknown.as_str(), "unknown");
    }

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
        assert_eq!(hex(&sha3_256(&[&d1.data])), hex(&sha3_256(&[&d2.data])));
    }

    #[test]
    fn the_seeded_pass_raises_entropy() {
        let mut dev = MemDevice::new(512, 2048);
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

    #[test]
    fn a_slow_device_shrinks_the_chunk() {
        let mut dev = MemDevice::new(512, 4096);
        dev.ns_per_sector = 20_000;
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
            Some(Duration::ZERO),
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
        assert_eq!(c.destroy_key().key_bytes_zeroed, 0);
    }

    #[test]
    fn the_ciphertext_is_noise_and_the_wrong_key_recovers_nothing() {
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

    #[test]
    fn containment_is_inode_ancestry_and_not_a_string_prefix() {
        let ws = guard::workspace_root();
        let src = ws.join("core").join("wipe").join("src");
        assert!(src.is_dir(), "expected {} to exist", src.display());
        assert!(guard::inode_contained(&ws, &src));
        assert!(guard::inode_contained(&src, &src), "a directory contains itself");
        assert!(!guard::inode_contained(&src, &ws), "containment is not symmetric");

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
        let fixture = guard::workspace_root().join("out").join("fixture.img");
        match guard::authorize_write(&fixture) {
            Ok(p) => panic!("guard authorised {}", p.display()),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.starts_with("REFUSED"), "{}", msg);
            }
        }
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
