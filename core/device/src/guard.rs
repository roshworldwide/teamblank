//! SENTINELWIPE write guard, Rust. CLAUDE.md rule 4. Phase 3 gate.
//!
//! Nothing in the Rust engine obtains a writable descriptor on a fixture or a
//! wipe target except through [`open_authorized`]. Standard library only, no
//! new crate, no subprocess: nothing on PATH may influence a refusal.
//!
//! # Why this file exists at all, given `fixtures/guard.py`
//!
//! This is a deliberate, declared reimplementation. The Tauri frontend calls the
//! Rust binary directly, so a Python-only allowlist is not merely duplicated on
//! the demo path -- it is *absent* from it. A guard that the destructive path
//! does not execute is not a guard.
//!
//! The duplication is contained by `fixtures/guard_vectors.json`: a committed
//! table of (target, policy, expected decision code) rows whose expectations were
//! *measured* from `fixtures/guard.py`. Both implementations run every row. The
//! Rust half runs it in [`conformance`] below. Drift then fails a test instead of
//! silently opening a hole.
//!
//! # THE PREDICATE, in evaluation order. Every clause is a conjunct.
//!
//! There is no disjunction anywhere on the allow path.
//!
//! ```text
//! Target is an EXISTING FILE (modes "r", "r+", "w" on a file that is there):
//!   F1  path is non-empty, contains no NUL, and is absolute
//!   F2  resolved = realpath(path) -- resolves every symlink component and the
//!       macOS /tmp -> /private/tmp alias
//!   F3  on macOS, resolved is not under /.vol -- the volfs namespace that
//!       addresses any file by inode number
//!   F4  resolved exists; a block or character device is handed to the DEVICE
//!       path, which is default-deny
//!   F5  containment: some ancestor of resolved is inode-identical
//!       ((st_dev, st_ino)) to an allowed root. Checked BEFORE any property of
//!       the file itself, so a refusal names the control that refused it
//!   F6  S_ISREG -- a directory, FIFO or socket is refused
//!   F7  st_nlink == 1 -- a hardlink inside an allowed root whose inode lives
//!       outside it is the one escape realpath cannot see
//!   F8  min_file_bytes <= st_size <= max_file_bytes  (modes "r" and "r+")
//!   F9  st_dev equals the matched root's st_dev (nothing was mounted inside it)
//!   F10 if require_confirmation: confirmation byte-equals resolved
//! Target does NOT exist (modes "w" and "x"):
//!   C1  F1 and F3
//!   C2  the leaf is one component and is not "", "." or ".."
//!   C3  the parent directory exists and is a directory
//!   C4  containment on the PARENT, by inode ancestry (F5)
//!   C5  parent st_dev equals the matched root's st_dev
//!   C6  F10, against realpath(parent) + "/" + leaf
//! Target is a DEVICE:
//!   D0  the platform is not macOS -- a MEASURED defect fix, not caution
//!   D1  allow_device_targets is true                (config-file factor)
//!   D2  env SENTINELWIPE_DEVICE_MODE == "1"         (environment factor)
//!   D3  path byte-equals an entry in policy.devices AND realpath(path) byte-
//!       equals that same entry
//!   D4  the target is S_ISBLK or S_ISCHR
//!   D5  the device is not the one backing "/" nor a slice of the same whole
//!       disk (DESIGNED BUT UNVERIFIED on Linux; no Linux host was available)
//!   D6  confirmation byte-equals the device name, unconditionally
//! ```
//!
//! `devices` is empty by default, so D3 refuses every device until a human edits
//! a config on purpose, and D0 refuses it again on this platform.
//!
//! # WHY INODE CONTAINMENT AND NOT A STRING PREFIX
//!
//! Measured on the dev machine, macOS 26.6.2 arm64:
//!
//! * `/Users` and `/System/Volumes/Data/Users` report the same `(st_dev, st_ino)`
//!   -- one directory -- but `realpath` returns each unchanged. `realpath` does
//!   not resolve firmlinks, so one directory has two irreducible path strings. A
//!   string prefix test denies a legitimate target reached by the other name.
//! * The working volume is case-insensitive, so `/x/FIXTURES/a.img` and
//!   `/x/fixtures/a.img` are the same file. A case-sensitive prefix test denies
//!   one of them; a case-insensitive one is wrong on a case-sensitive volume.
//!
//! Inode identity is exact under both, and being identity rather than a string
//! relation it can never widen the allowed set.
//!
//! # TOCTOU
//!
//! [`authorize`] is a decision about a path and is inherently racy.
//! [`open_authorized`] re-establishes every fact against descriptors: it descends
//! from the allowed root one component at a time with `O_NOFOLLOW|O_DIRECTORY`,
//! opens the leaf `O_NOFOLLOW`, and re-checks type, identity, nlink and size on
//! the descriptor. The returned `File`, not the path, is what callers write
//! through. `openat` is declared here as an `extern "C"` symbol from the libc
//! that `std` already links; that is not a new dependency, and it is the only
//! way to descend a path one component at a time without `std::os::fd` gaining
//! an `openat`.
//!
//! # WHAT THIS PORT DOES NOT EXPRESS
//!
//! Recorded here rather than discovered later. See `fixtures/guard_vectors.json`
//! and the Phase 3 report for the full list.
//!
//! * **`Policy::digest`.** Python hashes the canonical payload with SHA-256. The
//!   device crate has no hash primitive and Phase 3 adds no dependency, so
//!   [`Policy::digest_payload`] returns the *exact bytes Python hashes* and the
//!   conformance test asserts they match the committed payload template. Any
//!   crate that has SHA-256 (the ledger, the carver) produces the identical
//!   digest from them. The Rust guard cannot produce the hex digest itself.
//! * **Non-UTF-8 target paths.** The API takes `&str`, so a path that is not
//!   valid UTF-8 cannot be passed at all. That is strictly narrower than Python,
//!   which accepts any `str`; it is a refusal by construction, not a hole.
//! * **`collect_confirmation`.** TTY prompting is a CLI concern and lives with
//!   the caller. The guard evaluates the confirmation it is given and never
//!   sources one itself.
//! * **The injected-race tests.** Python monkeypatches `os.open` to widen the
//!   window between decision and open. That is not expressible in a static
//!   vector table in either language; the descend-with-`O_NOFOLLOW` machinery it
//!   exercises is ported and covered by the static symlink rows.
//! * **Detail strings.** Only `code`, `allowed` and `kind` are conformance
//!   surface. The human-readable `detail` is written to be equivalent in
//!   substance, not byte-identical.

#![cfg(unix)]

use std::ffi::CString;
use std::fs::{File, Metadata};
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;

// ------------------------------------------------------------- reason codes
//
// Byte-identical to fixtures/guard.py. These strings are the conformance
// surface; changing one is a schema change, not a rename.

pub const ALLOW_FILE: &str = "ALLOW_FILE";
pub const ALLOW_CREATE: &str = "ALLOW_CREATE";
pub const ALLOW_DEVICE: &str = "ALLOW_DEVICE";

pub const DENY_EMPTY: &str = "DENY_EMPTY_TARGET";
pub const DENY_NUL: &str = "DENY_NUL_IN_PATH";
pub const DENY_RELATIVE: &str = "DENY_RELATIVE_PATH";
pub const DENY_SYNTHETIC: &str = "DENY_SYNTHETIC_NAMESPACE_PATH";
pub const DENY_MODE: &str = "DENY_UNSUPPORTED_MODE";
pub const DENY_MISSING: &str = "DENY_TARGET_MISSING";
pub const DENY_EXISTS: &str = "DENY_TARGET_ALREADY_EXISTS";
pub const DENY_NOT_REGULAR: &str = "DENY_NOT_A_REGULAR_FILE";
pub const DENY_HARDLINK: &str = "DENY_MULTIPLE_HARDLINKS";
pub const DENY_SIZE: &str = "DENY_SIZE_OUT_OF_BOUNDS";
pub const DENY_NOT_ALLOWLISTED: &str = "DENY_NOT_ALLOWLISTED";
pub const DENY_CROSSED_MOUNT: &str = "DENY_CROSSED_MOUNT_POINT";
pub const DENY_BAD_LEAF: &str = "DENY_INVALID_LEAF_NAME";
pub const DENY_PARENT_MISSING: &str = "DENY_PARENT_DIRECTORY_MISSING";
pub const DENY_CONFIRMATION: &str = "DENY_CONFIRMATION_MISMATCH";
pub const DENY_CONFIRMATION_ABSENT: &str = "DENY_CONFIRMATION_ABSENT";

pub const DENY_DEVICE_MODE_OFF: &str = "DENY_DEVICE_MODE_NOT_ENABLED";
pub const DENY_DEVICE_ENV_OFF: &str = "DENY_DEVICE_ENV_NOT_SET";
pub const DENY_DEVICE_NOT_ALLOWLISTED: &str = "DENY_DEVICE_NOT_ALLOWLISTED";
pub const DENY_DEVICE_ALIAS: &str = "DENY_DEVICE_NAME_IS_AN_ALIAS";
pub const DENY_DEVICE_NOT_A_DEVICE: &str = "DENY_NOT_A_DEVICE_NODE";
pub const DENY_DEVICE_IS_SYSTEM: &str = "DENY_DEVICE_BACKS_RUNNING_SYSTEM";
pub const DENY_DEVICE_PLATFORM: &str = "DENY_DEVICE_TARGETS_UNSUPPORTED_ON_THIS_PLATFORM";

pub const DENY_RACE: &str = "DENY_RACE_DETECTED_AT_OPEN";
pub const DENY_SYMLINK_AT_OPEN: &str = "DENY_SYMLINK_COMPONENT_AT_OPEN";

/// Every decision code this implementation can produce. Enumerated so the
/// conformance test can assert that the committed table accounts for all of
/// them -- exercised by a row, or named in `codes_not_exercised` with a reason.
/// A code that exists in one implementation and not the other is exactly the
/// drift the shared table exists to catch.
pub const ALL_CODES: [&str; 28] = [
    ALLOW_FILE, ALLOW_CREATE, ALLOW_DEVICE,
    DENY_EMPTY, DENY_NUL, DENY_RELATIVE, DENY_SYNTHETIC, DENY_MODE, DENY_MISSING,
    DENY_EXISTS, DENY_NOT_REGULAR, DENY_HARDLINK, DENY_SIZE, DENY_NOT_ALLOWLISTED,
    DENY_CROSSED_MOUNT, DENY_BAD_LEAF, DENY_PARENT_MISSING, DENY_CONFIRMATION,
    DENY_CONFIRMATION_ABSENT, DENY_DEVICE_MODE_OFF, DENY_DEVICE_ENV_OFF,
    DENY_DEVICE_NOT_ALLOWLISTED, DENY_DEVICE_ALIAS, DENY_DEVICE_NOT_A_DEVICE,
    DENY_DEVICE_IS_SYSTEM, DENY_DEVICE_PLATFORM, DENY_RACE, DENY_SYMLINK_AT_OPEN,
];

/// The environment variable that arms the second device factor.
pub const DEVICE_MODE_ENV: &str = "SENTINELWIPE_DEVICE_MODE";

/// A root must be at least `/a/b`; `/` and `/Users` are refused.
pub const MIN_ROOT_DEPTH: usize = 2;

/// The default size ceiling: 8 GiB, matching `fixtures/guard.py`.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 8 * (1 << 30);

/// Directories that may never be a write root, nor contain one that is offered.
/// Compared by inode after realpath, never by string: `realpath("/etc")` is
/// `/private/etc`, which no string test for `/etc` catches.
pub const FORBIDDEN_ROOTS: &[&str] = &[
    "/", "/dev", "/.vol", "/System", "/System/Volumes/Data", "/Volumes", "/Library",
    "/Applications", "/bin", "/sbin", "/usr", "/etc", "/var", "/private",
    "/private/etc", "/private/var", "/private/var/db", "/private/tmp", "/tmp",
    "/Users", "/home", "/opt", "/net", "/cores", "/Network",
];

/// The accepted modes. Deliberately Python's `open()` spelling so a reader does
/// not have to learn a second vocabulary, and deliberately a closed set: an
/// unrecognised mode is `DENY_UNSUPPORTED_MODE`, never a guess.
pub const MODES: [&str; 4] = ["r", "r+", "w", "x"];

/// A trailing or embedded `b` is accepted and ignored: every descriptor this
/// module returns is binary, because it is a file descriptor.
fn normalize_mode(mode: &str) -> Option<&'static str> {
    Some(match mode {
        "r" | "rb" => "r",
        "r+" | "rb+" | "r+b" | "+r" => "r+",
        "w" | "wb" | "w+" | "wb+" | "w+b" => "w",
        "x" | "xb" | "x+" | "xb+" | "x+b" => "x",
        _ => return None,
    })
}

// ------------------------------------------------------------------ platform

/// The platform string this guard compares against, spelled as Python's
/// `sys.platform` spells it, because the two implementations share a vector
/// table that names platforms.
pub fn native_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

// ----------------------------------------------------------------- errno/flags
//
// Values taken from the platform headers rather than a crate. macOS values were
// read from `$(xcrun --show-sdk-path)/usr/include/sys/fcntl.h`; the Linux values
// are the asm-generic ones shared by x86_64 and aarch64. The Linux device layer
// is gated and untested per the scope rules, and so are these constants.

#[cfg(target_os = "macos")]
mod oflags {
    use std::os::raw::c_int;
    pub const O_RDONLY: c_int = 0x0000;
    pub const O_RDWR: c_int = 0x0002;
    pub const O_NOFOLLOW: c_int = 0x0000_0100;
    pub const O_CREAT: c_int = 0x0000_0200;
    pub const O_EXCL: c_int = 0x0000_0800;
    pub const O_DIRECTORY: c_int = 0x0010_0000;
    pub const O_CLOEXEC: c_int = 0x0100_0000;
    pub const ELOOP: i32 = 62;
    pub const ENOTDIR: i32 = 20;
    pub const EMLINK: i32 = 31;
    pub const EEXIST: i32 = 17;
    pub const ENOENT: i32 = 2;
}

#[cfg(not(target_os = "macos"))]
mod oflags {
    use std::os::raw::c_int;
    pub const O_RDONLY: c_int = 0o0;
    pub const O_RDWR: c_int = 0o2;
    pub const O_CREAT: c_int = 0o100;
    pub const O_EXCL: c_int = 0o200;
    pub const O_DIRECTORY: c_int = 0o200000;
    pub const O_NOFOLLOW: c_int = 0o400000;
    pub const O_CLOEXEC: c_int = 0o2000000;
    pub const ELOOP: i32 = 40;
    pub const ENOTDIR: i32 = 20;
    pub const EMLINK: i32 = 31;
    pub const EEXIST: i32 = 17;
    pub const ENOENT: i32 = 2;
}

extern "C" {
    /// Declared variadic because it is variadic. On aarch64-apple-darwin the
    /// variadic argument passing convention differs from the fixed one, so
    /// calling `openat` through a non-variadic declaration would be wrong.
    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
}

fn openat_checked(dirfd: c_int, name: &str, flags: c_int) -> Result<File, std::io::Error> {
    let c = CString::new(name).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path component")
    })?;
    // SAFETY: `c` is a NUL-terminated C string that outlives the call, `dirfd`
    // is a live descriptor owned by the caller, and the mode argument is only
    // consulted by the kernel when O_CREAT is set. The returned descriptor is
    // handed straight to `File::from_raw_fd`, which takes ownership of it.
    let fd = unsafe { openat(dirfd, c.as_ptr(), flags, 0o600 as c_int) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

// ------------------------------------------------------------------- helpers

fn stat(path: &str) -> Option<Metadata> {
    std::fs::metadata(Path::new(path)).ok()
}

fn ids_of(path: &str) -> Option<(u64, u64)> {
    stat(path).map(|m| (m.dev(), m.ino()))
}

fn is_dir(path: &str) -> bool {
    stat(path).map(|m| m.is_dir()).unwrap_or(false)
}

/// `os.path.dirname` for an absolute POSIX path.
fn dirname(path: &str) -> String {
    match path.rfind('/') {
        None => String::new(),
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

/// `os.path.basename` for an absolute POSIX path.
fn basename(path: &str) -> &str {
    match path.rfind('/') {
        None => path,
        Some(i) => &path[i + 1..],
    }
}

fn join(dir: &str, leaf: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{leaf}")
    } else {
        format!("{dir}/{leaf}")
    }
}

/// `os.path.realpath`: resolves every symlink component, `.` and `..`, and
/// tolerates components that do not exist (the create path needs that).
///
/// `..` is applied to the already-resolved prefix, which is POSIX-correct
/// precisely because the prefix is symlink-free by then.
pub fn realpath(path: &str) -> String {
    if !path.starts_with('/') {
        // Callers reject relative paths before reaching here; resolving one
        // against the working directory would import attacker-influenced state.
        return path.to_string();
    }
    let mut stack: Vec<String> = Vec::new();
    let mut pending: Vec<String> = path
        .split('/')
        .rev()
        .map(|s| s.to_string())
        .collect();
    let mut budget = 64_i32; // MAXSYMLINKS-ish; a cycle exhausts it and is left alone
    while let Some(name) = pending.pop() {
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            stack.pop();
            continue;
        }
        let candidate = format!("/{}", {
            let mut v = stack.clone();
            v.push(name.clone());
            v.join("/")
        });
        let lst = std::fs::symlink_metadata(Path::new(&candidate));
        let is_link = lst.map(|m| m.file_type().is_symlink()).unwrap_or(false);
        if !is_link {
            stack.push(name);
            continue;
        }
        budget -= 1;
        if budget < 0 {
            // A cycle, or pathological nesting. Leave the rest literal; the
            // caller's stat() then fails and the decision is DENY_TARGET_MISSING,
            // which is what Python reaches by the same route.
            stack.push(name);
            while let Some(rest) = pending.pop() {
                if !rest.is_empty() && rest != "." {
                    stack.push(rest);
                }
            }
            break;
        }
        let target = match std::fs::read_link(Path::new(&candidate)) {
            Ok(t) => t,
            Err(_) => {
                stack.push(name);
                continue;
            }
        };
        let t = String::from_utf8_lossy(target.as_os_str().as_bytes()).into_owned();
        if t.starts_with('/') {
            stack.clear();
        }
        for part in t.split('/').rev() {
            pending.push(part.to_string());
        }
    }
    if stack.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", stack.join("/"))
    }
}

/// Walk `resolved` upward comparing `(st_dev, st_ino)` against `root_ids`.
///
/// `resolved` must already be a realpath, so every component is symlink-free and
/// walking by string is sound. Identity comparison at each step is what makes
/// this correct across macOS firmlinks (two path strings, one inode) and
/// case-insensitive volumes (two spellings, one inode).
/// Whether `walk_from` is reachable from its matching root's own spelling by
/// name — the predicate `open_authorized`'s O_NOFOLLOW descent applies.
///
/// `authorize` calls this as a final conjunct so the decision and the open cannot
/// disagree. Inode containment and a name-based descent are different tests, and on
/// a case-insensitive volume they measurably diverge; the certificate quotes the
/// decision, so the decision has to be the stricter of the two.
fn reachable_by_descent(policy: &Policy, walk_from: &str, resolved: &str) -> bool {
    match matching_root_real(policy, walk_from) {
        Some(root_real) => rel_parts(resolved, &root_real).map(|p| !p.is_empty()).unwrap_or(false),
        None => false,
    }
}

pub fn contained_by_inode(resolved: &str, root_ids: &[(u64, u64)]) -> Option<(u64, u64)> {
    if root_ids.is_empty() {
        return None;
    }
    let mut cur = resolved.to_string();
    let mut steps = 0;
    loop {
        if let Some(got) = ids_of(&cur) {
            if root_ids.contains(&got) {
                return Some(got);
            }
        }
        let parent = dirname(&cur);
        if parent == cur || parent.is_empty() {
            return None;
        }
        cur = parent;
        steps += 1;
        if steps > 256 {
            // pathological depth; refuse rather than spin
            return None;
        }
    }
}

/// The `/dev/diskNsM` (or `/dev/sdXN`) whose `st_rdev` equals `st_dev` of `/`.
/// Computed with `stat` only; the guard spawns nothing.
pub fn root_backing_device() -> Option<String> {
    let rootdev = std::fs::metadata("/").ok()?.dev();
    let mut names: Vec<String> = std::fs::read_dir("/dev")
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("disk"))
        .collect();
    names.sort();
    for n in names {
        let p = format!("/dev/{n}");
        if let Ok(m) = std::fs::symlink_metadata(Path::new(&p)) {
            if m.file_type().is_block_device() && m.rdev() == rootdev {
                return Some(p);
            }
        }
    }
    None
}

/// `/dev/disk3s5` -> `disk3` ; `/dev/rdisk3s5` -> `disk3`.
pub fn whole_disk(dev_name: &str) -> String {
    let mut base = basename(dev_name).to_string();
    if base.starts_with('r') {
        base.remove(0);
    }
    let mut out = String::new();
    for ch in base.chars() {
        if ch == 's' && out.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            break;
        }
        out.push(ch);
    }
    out
}

/// Byte comparison that does not short-circuit on the first difference.
fn ct_eq(a: &str, b: &str) -> bool {
    let (x, y) = (a.as_bytes(), b.as_bytes());
    let mut diff = (x.len() ^ y.len()) as u32;
    let n = x.len().min(y.len());
    for i in 0..n {
        diff |= (x[i] ^ y[i]) as u32;
    }
    diff == 0
}

// ------------------------------------------------------------------ environment

/// Where the environment factor is read from. `Map` exists so a test can state
/// the environment instead of inheriting one.
pub enum Env<'a> {
    Process,
    Map(&'a [(String, String)]),
}

impl<'a> Env<'a> {
    fn get(&self, key: &str) -> Option<String> {
        match self {
            Env::Process => std::env::var(key).ok(),
            Env::Map(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()),
        }
    }
}

// ---------------------------------------------------------------------- policy

/// The policy itself is unsafe. Returned at construction, never at use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PolicyError {}

/// What a caller asks for. Validated into a [`Policy`] by [`Policy::build`].
#[derive(Debug, Clone)]
pub struct PolicySpec {
    pub roots: Vec<String>,
    pub devices: Vec<String>,
    pub allow_device_targets: bool,
    /// False by default because building a fixture into a scratch directory is
    /// not a destructive operation on anyone's data. Every destructive caller --
    /// the wipe path -- sets it, and arming devices forces it.
    pub require_confirmation: bool,
    pub min_file_bytes: u64,
    pub max_file_bytes: u64,
}

impl Default for PolicySpec {
    fn default() -> Self {
        PolicySpec {
            roots: Vec::new(),
            devices: Vec::new(),
            allow_device_targets: false,
            require_confirmation: false,
            min_file_bytes: 0,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        }
    }
}

impl PolicySpec {
    pub fn with_roots<S: Into<String>, I: IntoIterator<Item = S>>(roots: I) -> Self {
        PolicySpec {
            roots: roots.into_iter().map(Into::into).collect(),
            ..PolicySpec::default()
        }
    }
}

/// The allowlist. Constructed once, validated loudly at construction.
///
/// Roots must already exist: a root that is not a directory is a
/// [`PolicyError`], so callers create it first. A guard that creates its own
/// allowed root has no allowlist.
#[derive(Debug, Clone)]
pub struct Policy {
    spec: PolicySpec,
    root_ids: Vec<(u64, u64)>,
    root_reals: Vec<String>,
}

fn forbidden_ids() -> Vec<((u64, u64), String)> {
    let mut out: Vec<((u64, u64), String)> = Vec::new();
    for name in FORBIDDEN_ROOTS {
        for spelling in [name.to_string(), realpath(name)] {
            if let Some(got) = ids_of(&spelling) {
                if !out.iter().any(|(g, _)| *g == got) {
                    out.push((got, spelling));
                }
            }
        }
    }
    out
}

impl Policy {
    pub fn build(spec: PolicySpec) -> Result<Policy, PolicyError> {
        if spec.roots.is_empty() {
            return Err(PolicyError(
                "roots is empty; a guard with no allowed root is a bug, not a safe default"
                    .into(),
            ));
        }
        if spec.max_file_bytes < spec.min_file_bytes {
            return Err(PolicyError(format!(
                "nonsensical size bounds [{}, {}]",
                spec.min_file_bytes, spec.max_file_bytes
            )));
        }
        if spec.allow_device_targets && !spec.require_confirmation {
            return Err(PolicyError(
                "allow_device_targets=true requires require_confirmation=true; a device \
                 target is destructive by definition"
                    .into(),
            ));
        }

        let forbidden = forbidden_ids();
        let home_real = std::env::var("HOME").ok().map(|h| realpath(&h));
        let home_ids = home_real.as_deref().and_then(ids_of);

        let mut ids = Vec::new();
        let mut reals = Vec::new();
        for r in &spec.roots {
            if r.is_empty() || r.contains('\0') {
                return Err(PolicyError(format!("invalid root {r:?}")));
            }
            if !r.starts_with('/') {
                return Err(PolicyError(format!("root must be absolute: {r:?}")));
            }
            let real = realpath(r);
            if !is_dir(&real) {
                return Err(PolicyError(format!(
                    "root does not exist or is not a directory: {real:?} (create it before \
                     constructing the Policy; the guard never creates its own root)"
                )));
            }
            let got = match ids_of(&real) {
                Some(g) => g,
                None => return Err(PolicyError(format!("root vanished during validation: {real:?}"))),
            };

            // (a) the root IS a system directory, under any spelling. Redundant
            // with (b), because containment is reflexive; kept because it
            // produces the message a reader can act on.
            if let Some((_, spelling)) = forbidden.iter().find(|(g, _)| *g == got) {
                return Err(PolicyError(format!(
                    "refusing system directory as a write root: {r:?} -> {real:?} \
                     (matches {spelling})"
                )));
            }
            // (b) the root CONTAINS a system directory, so writing under it could
            //     reach one.
            for (_, spelling) in &forbidden {
                let freal = realpath(spelling);
                if contained_by_inode(&freal, &[got]).is_some() {
                    return Err(PolicyError(format!(
                        "refusing write root {real:?}: it contains the system directory {freal:?}"
                    )));
                }
            }
            let depth = real.split('/').filter(|p| !p.is_empty()).count();
            if depth < MIN_ROOT_DEPTH {
                return Err(PolicyError(format!(
                    "root is too shallow ({depth} components): {real:?}"
                )));
            }
            if home_real.as_deref() == Some(real.as_str()) || home_ids == Some(got) {
                return Err(PolicyError(format!("refusing $HOME as a write root: {real:?}")));
            }
            ids.push(got);
            reals.push(real);
        }
        Ok(Policy { spec, root_ids: ids, root_reals: reals })
    }

    pub fn roots(&self) -> &[String] {
        &self.spec.roots
    }
    pub fn root_reals(&self) -> &[String] {
        &self.root_reals
    }
    pub fn root_ids(&self) -> &[(u64, u64)] {
        &self.root_ids
    }
    pub fn devices(&self) -> &[String] {
        &self.spec.devices
    }
    pub fn require_confirmation(&self) -> bool {
        self.spec.require_confirmation
    }

    /// The exact bytes `fixtures/guard.py` feeds to SHA-256 to produce
    /// `Policy.digest()`. This crate has no hash primitive and Phase 3 adds no
    /// dependency, so the payload is what is offered: it is stable over spelling
    /// (two teammates who name the same root `/tmp/x` and `/private/tmp/x`
    /// produce the same payload) and any crate holding SHA-256 turns it into the
    /// identical digest.
    pub fn digest_payload(&self) -> String {
        let mut roots: Vec<String> = self.spec.roots.iter().map(|r| realpath(r)).collect();
        roots.sort();
        let mut s = String::from("{\"allow_device_targets\":");
        s.push_str(if self.spec.allow_device_targets { "true" } else { "false" });
        s.push_str(",\"devices\":[");
        for (i, d) in self.spec.devices.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json_string(d));
        }
        s.push_str(&format!(
            "],\"max_file_bytes\":{},\"min_file_bytes\":{},\"require_confirmation\":",
            self.spec.max_file_bytes, self.spec.min_file_bytes
        ));
        s.push_str(if self.spec.require_confirmation { "true" } else { "false" });
        s.push_str(",\"roots\":[");
        for (i, r) in roots.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json_string(r));
        }
        s.push_str("]}");
        s
    }
}

/// A JSON string literal escaped the way Python's `json.dumps` escapes with
/// default settings: ASCII output, non-ASCII as `\uXXXX`, astral planes as a
/// surrogate pair. The audit line has to be byte-comparable across the two
/// implementations or it is not one record format.
fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xffff {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    let v = cp - 0x1_0000;
                    out.push_str(&format!("\\u{:04x}", 0xd800 + (v >> 10)));
                    out.push_str(&format!("\\u{:04x}", 0xdc00 + (v & 0x3ff)));
                }
            }
        }
    }
    out.push('"');
    out
}

// -------------------------------------------------------------------- decision

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Device,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Device => "device",
        }
    }
}

/// The verdict. No timestamp, no random, no host state: two identical calls
/// produce equal `Decision`s, which is what makes the audit line reproducible
/// alongside the image it authorised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub code: &'static str,
    pub resolved: String,
    pub detail: String,
    pub target: String,
    pub st_dev: Option<u64>,
    pub st_ino: Option<u64>,
    pub kind: Kind,
}

impl Decision {
    /// One JSONL audit record, keys sorted, compact separators, matching
    /// `fixtures/guard.py`'s `audit_append`. The digest is supplied by the
    /// caller because this crate cannot compute it; see [`Policy::digest_payload`].
    pub fn as_json_record(&self, policy_digest: &str) -> String {
        let mut s = String::from("{\"allowed\":");
        s.push_str(if self.allowed { "true" } else { "false" });
        s.push_str(",\"code\":");
        s.push_str(&json_string(self.code));
        s.push_str(",\"detail\":");
        s.push_str(&json_string(&self.detail));
        s.push_str(",\"kind\":");
        s.push_str(&json_string(self.kind.as_str()));
        s.push_str(",\"policy_digest\":");
        s.push_str(&json_string(policy_digest));
        s.push_str(",\"resolved\":");
        s.push_str(&json_string(&self.resolved));
        s.push_str(",\"st_dev\":");
        match self.st_dev {
            Some(v) => s.push_str(&v.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(",\"st_ino\":");
        match self.st_ino {
            Some(v) => s.push_str(&v.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(",\"target\":");
        s.push_str(&json_string(&self.target));
        s.push('}');
        s
    }
}

fn deny(code: &'static str, detail: String, target: &str, resolved: &str, kind: Kind) -> Decision {
    Decision {
        allowed: false,
        code,
        resolved: resolved.to_string(),
        detail,
        target: target.to_string(),
        st_dev: None,
        st_ino: None,
        kind,
    }
}

// ------------------------------------------------------------------- authorize

/// Decide whether `path` may be opened under `policy`. Pure: no descriptor, no
/// side effect, nothing on disk is changed.
///
/// `confirmation` is checked LAST, and only after the allowlist has already said
/// yes, so a refused target never reveals that typing something would have
/// helped. It carries no authority of its own: the value it must equal is the
/// guard's own resolution of the target, not the string the operator passed.
///
/// `platform` is a TEST SEAM and nothing else. Clause D0 refuses every device
/// target on macOS before any other factor is consulted, which on a macOS host
/// makes D1..D6 unreachable and therefore untested -- and those are precisely
/// the clauses CLAUDE.md rule 4 calls a disqualifying defect area. Passing
/// `Some("linux")` bypasses D0 ONLY. It does not reach the file rules: the
/// `/.vol` refusal below still keys on the real platform.
pub fn authorize(
    policy: &Policy,
    path: &str,
    confirmation: Option<&str>,
    mode: &str,
    env: &Env<'_>,
    platform: Option<&str>,
) -> Decision {
    let plat: &str = match platform {
        Some(p) => p,
        None => native_platform(),
    };

    let norm = match normalize_mode(mode) {
        Some(n) => n,
        None => {
            return deny(
                DENY_MODE,
                format!("mode {mode:?} is not one of {MODES:?}"),
                path,
                "",
                Kind::File,
            )
        }
    };

    if path.is_empty() {
        return deny(DENY_EMPTY, "target is empty".into(), path, "", Kind::File);
    }
    if path.contains('\0') {
        return deny(
            DENY_NUL,
            "target contains NUL".into(),
            &path.replace('\0', "?"),
            "",
            Kind::File,
        );
    }
    if !path.starts_with('/') {
        return deny(
            DENY_RELATIVE,
            "target must be an absolute path; the working directory is attacker-influenced"
                .into(),
            path,
            "",
            Kind::File,
        );
    }

    let resolved = realpath(path);

    // macOS volfs. MEASURED unprivileged: /.vol/<st_dev>/<st_ino> addresses any
    // file on the volume, realpath leaves the string untouched, stat reports the
    // underlying regular file (S_ISREG, nlink 1, true size), and O_RDWR succeeds.
    // So F5, F6 and F7 all pass and inode containment is the only clause left
    // standing -- and /.vol/<dev>/<ino-of-the-root>/disk.img satisfies even that,
    // because the walk hits the allowed root's own inode.
    //
    // Nothing in this project ever legitimately produces a /.vol path, so the
    // namespace is refused whole. This is a string test, and soundly so: it is
    // applied to the REALPATH, which has already collapsed ".", "..", repeated
    // separators and every symlink.
    //
    // Keyed on the REAL platform, not on `plat`: the seam widens the device
    // clause it names and nothing else.
    if native_platform() == "darwin" && (resolved == "/.vol" || resolved.starts_with("/.vol/")) {
        return deny(
            DENY_SYNTHETIC,
            format!(
                "{resolved}: /.vol addresses files by inode number and is refused whole. \
                 A fixture is named by its path, and the operator must be able to read \
                 the target being confirmed."
            ),
            path,
            &resolved,
            Kind::File,
        );
    }

    let st = match std::fs::metadata(Path::new(&resolved)) {
        Ok(m) => m,
        Err(e) => {
            if (norm == "w" || norm == "x") && e.raw_os_error() == Some(oflags::ENOENT) {
                return authorize_create(policy, path, &resolved, confirmation);
            }
            return deny(
                DENY_MISSING,
                format!("cannot stat {resolved}: {e}"),
                path,
                &resolved,
                Kind::File,
            );
        }
    };

    let ft = st.file_type();
    if ft.is_block_device() || ft.is_char_device() {
        return authorize_device(policy, path, &resolved, &st, confirmation, env, plat);
    }

    if norm == "x" {
        // Checked before containment on purpose: "x" asserts the target does not
        // exist, and an existing file is a failure of the caller's own premise,
        // not a policy question.
        return deny(
            DENY_EXISTS,
            format!("{resolved} already exists and mode 'x' refuses to replace it"),
            path,
            &resolved,
            Kind::File,
        );
    }

    // Containment is evaluated FIRST, before any property of the file itself.
    // Ordering is not cosmetic: with the size check first, /dev/stdout was
    // refused as DENY_SIZE_OUT_OF_BOUNDS rather than DENY_NOT_ALLOWLISTED
    // (measured in the Python guard). Both refuse, but the audit line then
    // records an incidental reason instead of the controlling one, and the
    // certificate quotes that line.
    let matched = match contained_by_inode(&resolved, &policy.root_ids) {
        Some(m) => m,
        None => {
            return deny(
                DENY_NOT_ALLOWLISTED,
                format!("{resolved} is not inside any allowed root"),
                path,
                &resolved,
                Kind::File,
            )
        }
    };
    if !ft.is_file() {
        return deny(
            DENY_NOT_REGULAR,
            format!("{resolved} is not a regular file (mode {:o})", st.mode()),
            path,
            &resolved,
            Kind::File,
        );
    }

    // AND the descent's own predicate, so this decision is a SOUND predicate for
    // `open_authorized` rather than merely a necessary one.
    //
    // Containment above is inode identity, which is case-insensitive by nature on
    // APFS; the descent re-identifies the root by STRING, because it has to walk
    // components. Measured divergence: `<lab>/FIXTURES/disk.img` under a root
    // spelled `<lab>/fixtures` was ALLOW_FILE at decision time and
    // DENY_NOT_ALLOWLISTED at open time. It failed closed, so it was never a hole
    // — but `--plan` and the certificate's `authorization.decision_code` both read
    // the DECISION, so they published ALLOW_FILE for a target the engine would
    // refuse. Both halves must agree, and they agree by the stricter one winning.
    //
    // It sits AFTER the type check on purpose: the allowed root itself is a
    // directory no descent can reach strictly below itself, and the controlling
    // reason for refusing a directory is that it is a directory.
    if !reachable_by_descent(policy, &resolved, &resolved) {
        return deny(
            DENY_NOT_ALLOWLISTED,
            format!(
                "{resolved} is inside an allowed root by inode but is not reachable \
                 from that root's own spelling by name; the open would refuse it"
            ),
            path,
            &resolved,
            Kind::File,
        );
    }

    if st.nlink() != 1 {
        return deny(
            DENY_HARDLINK,
            format!(
                "{resolved} has {} links; a hardlink can place an inode from outside the \
                 allowed root inside it",
                st.nlink()
            ),
            path,
            &resolved,
            Kind::File,
        );
    }

    // Size bounds apply to the modes that READ existing content. "w" truncates
    // and "x" creates, so the size the file happens to have now is not a policy
    // question -- and a rule that denied "w" on a 10-byte file while allowing
    // "w" on no file at all would be incoherent.
    if (norm == "r" || norm == "r+")
        && !(st.size() >= policy.spec.min_file_bytes && st.size() <= policy.spec.max_file_bytes)
    {
        return deny(
            DENY_SIZE,
            format!(
                "{} bytes is outside [{}, {}]",
                st.size(),
                policy.spec.min_file_bytes,
                policy.spec.max_file_bytes
            ),
            path,
            &resolved,
            Kind::File,
        );
    }

    if st.dev() != matched.0 {
        return deny(
            DENY_CROSSED_MOUNT,
            format!(
                "{resolved} is on device {} but its allowed root is on {}; a filesystem was \
                 mounted inside the root",
                st.dev(),
                matched.0
            ),
            path,
            &resolved,
            Kind::File,
        );
    }

    if let Some(bad) = confirm(policy, path, &resolved, confirmation, Kind::File) {
        return bad;
    }

    Decision {
        allowed: true,
        code: ALLOW_FILE,
        resolved: resolved.clone(),
        detail: "regular file inside an allowed root".into(),
        target: path.to_string(),
        st_dev: Some(st.dev()),
        st_ino: Some(st.ino()),
        kind: Kind::File,
    }
}

/// The last conjunct. Returns a denial, or `None` if the clause is satisfied
/// (including the case where the policy does not require it).
fn confirm(
    policy: &Policy,
    path: &str,
    resolved: &str,
    confirmation: Option<&str>,
    kind: Kind,
) -> Option<Decision> {
    if !policy.spec.require_confirmation {
        return None;
    }
    match confirmation {
        None => Some(deny(
            DENY_CONFIRMATION_ABSENT,
            format!("destructive operation needs --i-understand '{resolved}'"),
            path,
            resolved,
            kind,
        )),
        Some(c) if !ct_eq(c, resolved) => Some(deny(
            DENY_CONFIRMATION,
            "typed confirmation does not name the resolved target".into(),
            path,
            resolved,
            kind,
        )),
        Some(_) => None,
    }
}

/// The target does not exist and the caller asked for "w" or "x".
///
/// Containment moves to the parent directory. The leaf never participates in a
/// path walk: it is a single component opened relative to a descended directory
/// descriptor with `O_CREAT|O_EXCL|O_NOFOLLOW`, so no symlink can be followed and
/// no file that appeared after this decision can be clobbered.
fn authorize_create(
    policy: &Policy,
    path: &str,
    resolved: &str,
    confirmation: Option<&str>,
) -> Decision {
    let parent_arg = dirname(resolved);
    let leaf = basename(resolved).to_string();
    if leaf.is_empty() || leaf == "." || leaf == ".." || leaf.contains('/') {
        return deny(
            DENY_BAD_LEAF,
            format!("{path:?} does not name a single file below a directory"),
            path,
            resolved,
            Kind::File,
        );
    }

    let parent = realpath(&parent_arg);
    if !is_dir(&parent) {
        return deny(
            DENY_PARENT_MISSING,
            format!("parent directory {parent} does not exist; the guard creates no directories"),
            path,
            resolved,
            Kind::File,
        );
    }

    let matched = match contained_by_inode(&parent, &policy.root_ids) {
        Some(m) => m,
        None => {
            return deny(
                DENY_NOT_ALLOWLISTED,
                format!("{parent} is not inside any allowed root"),
                path,
                &join(&parent, &leaf),
                Kind::File,
            )
        }
    };

    let resolved = join(&parent, &leaf);
    // The create path takes the same conjunct, against the parent the descent will
    // actually walk from. See the file branch above for the measured reason.
    if !reachable_by_descent(policy, &parent, &resolved) {
        return deny(
            DENY_NOT_ALLOWLISTED,
            format!(
                "{parent} is inside an allowed root by inode but is not reachable \
                 from that root's own spelling by name; the open would refuse it"
            ),
            path,
            &resolved,
            Kind::File,
        );
    }

    let pst = match ids_of(&parent) {
        Some(p) => p,
        None => {
            return deny(
                DENY_PARENT_MISSING,
                format!("parent {parent} vanished"),
                path,
                &resolved,
                Kind::File,
            )
        }
    };
    if pst.0 != matched.0 {
        return deny(
            DENY_CROSSED_MOUNT,
            format!(
                "{parent} is on device {} but its allowed root is on {}; a filesystem was \
                 mounted inside the root",
                pst.0, matched.0
            ),
            path,
            &resolved,
            Kind::File,
        );
    }

    if let Some(bad) = confirm(policy, path, &resolved, confirmation, Kind::File) {
        return bad;
    }

    Decision {
        allowed: true,
        code: ALLOW_CREATE,
        resolved,
        detail: "new file in a directory inside an allowed root".into(),
        target: path.to_string(),
        st_dev: None,
        st_ino: None,
        kind: Kind::File,
    }
}

fn authorize_device(
    policy: &Policy,
    path: &str,
    resolved: &str,
    st: &Metadata,
    confirmation: Option<&str>,
    env: &Env<'_>,
    plat: &str,
) -> Decision {
    // D0. macOS: refuse every device target, unconditionally, before any factor
    // is consulted. Not conservatism -- a MEASURED defect in an earlier version
    // of the Python guard:
    //
    //   "/" is on /dev/disk3s5. /dev/disk3 is a SYNTHESIZED APFS container whose
    //   physical store is /dev/disk0s2, a partition of the internal drive
    //   /dev/disk0. The whole-disk rule below derives "disk3" from "disk3s5" and
    //   never reaches disk0, so an operator who allowlisted /dev/disk0 and set
    //   both other factors got ALLOW_DEVICE for the boot drive. It failed only
    //   with EPERM because the process was not root -- the guard had already said
    //   yes. That is the disqualifying defect in CLAUDE.md rule 4, reached
    //   through the documented escape hatch.
    //
    // Walking the synthesis chain correctly needs `diskutil info -plist` or
    // IOKit. The guard spawns no subprocess, on purpose. So on darwin the honest
    // predicate is "no". The device layer is Linux-only per the scope rules and
    // is never demoed.
    if plat == "darwin" {
        return deny(
            DENY_DEVICE_PLATFORM,
            format!(
                "{resolved}: raw device targets are refused on macOS. APFS containers are \
                 synthesized, so a device name cannot be shown unrelated to the boot volume \
                 without trusting an external tool. The device layer is Linux-only."
            ),
            path,
            resolved,
            Kind::Device,
        );
    }
    if !policy.spec.allow_device_targets {
        return deny(
            DENY_DEVICE_MODE_OFF,
            "device targets are disabled in the policy".into(),
            path,
            resolved,
            Kind::Device,
        );
    }
    if env.get(DEVICE_MODE_ENV).as_deref() != Some("1") {
        return deny(
            DENY_DEVICE_ENV_OFF,
            format!("{DEVICE_MODE_ENV} is not set to 1"),
            path,
            resolved,
            Kind::Device,
        );
    }
    if !policy.spec.devices.iter().any(|d| d == path) {
        return deny(
            DENY_DEVICE_NOT_ALLOWLISTED,
            format!("{path} is not in the device allowlist"),
            path,
            resolved,
            Kind::Device,
        );
    }
    if resolved != path {
        return deny(
            DENY_DEVICE_ALIAS,
            format!(
                "{path} resolves to {resolved}; device names are compared literally and may \
                 not be reached through a link or alias"
            ),
            path,
            resolved,
            Kind::Device,
        );
    }
    let ft = st.file_type();
    if !(ft.is_block_device() || ft.is_char_device()) {
        return deny(
            DENY_DEVICE_NOT_A_DEVICE,
            "not a device node".into(),
            path,
            resolved,
            Kind::Device,
        );
    }

    if let Some(rootdev) = root_backing_device() {
        if whole_disk(resolved) == whole_disk(&rootdev) {
            return deny(
                DENY_DEVICE_IS_SYSTEM,
                format!(
                    "{resolved} is on {}, the disk backing the running system ({rootdev})",
                    whole_disk(&rootdev)
                ),
                path,
                resolved,
                Kind::Device,
            );
        }
    }

    // Devices always require the typed confirmation, whatever the policy says.
    match confirmation {
        None => {
            return deny(
                DENY_CONFIRMATION_ABSENT,
                format!("destructive operation needs --i-understand '{resolved}'"),
                path,
                resolved,
                Kind::Device,
            )
        }
        Some(c) if !ct_eq(c, resolved) => {
            return deny(
                DENY_CONFIRMATION,
                "typed confirmation does not name the device".into(),
                path,
                resolved,
                Kind::Device,
            )
        }
        Some(_) => {}
    }

    Decision {
        allowed: true,
        code: ALLOW_DEVICE,
        resolved: resolved.to_string(),
        detail: "allowlisted device, three factors present".into(),
        target: path.to_string(),
        st_dev: Some(st.dev()),
        st_ino: Some(st.ino()),
        kind: Kind::Device,
    }
}

// ---------------------------------------------------------------- hardened open

/// A target was refused, or the open failed for a reason the guard did not
/// predict. `Refused` is the only variant a correctly-written caller reports to
/// an operator; `Io` means the kernel said no after the guard said yes, which is
/// the shape of the defect this whole module exists to prevent.
#[derive(Debug)]
pub enum GuardError {
    Refused(Decision),
    Io(std::io::Error),
}

impl GuardError {
    pub fn code(&self) -> &str {
        match self {
            GuardError::Refused(d) => d.code,
            GuardError::Io(_) => "IO",
        }
    }
    pub fn decision(&self) -> Option<&Decision> {
        match self {
            GuardError::Refused(d) => Some(d),
            GuardError::Io(_) => None,
        }
    }
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::Refused(d) => write!(f, "{}: {}", d.code, d.detail),
            GuardError::Io(e) => write!(f, "IO: {e}"),
        }
    }
}

impl std::error::Error for GuardError {}

fn rel_parts(resolved: &str, root_real: &str) -> Option<Vec<String>> {
    let r: Vec<&str> = resolved.split('/').filter(|p| !p.is_empty()).collect();
    let b: Vec<&str> = root_real.split('/').filter(|p| !p.is_empty()).collect();
    if r.len() <= b.len() || r[..b.len()] != b[..] {
        // Python computes os.path.relpath and refuses any ".." component. A
        // prefix test is the same predicate, computed without building the
        // string. Note this is a STRING relation, which is why a case-variant
        // spelling that inode containment admits is refused here -- fail-closed,
        // recorded as a row in fixtures/guard_vectors.json.
        return None;
    }
    Some(r[b.len()..].iter().map(|s| s.to_string()).collect())
}

/// The realpath spelling of the allowed root that contains `resolved`.
/// Containment matched an inode; the descent needs a string to start from.
/// Firmlinks mean the two are not interchangeable, so the root that matched is
/// re-identified here rather than assumed.
fn matching_root_real(policy: &Policy, resolved: &str) -> Option<String> {
    for r in &policy.spec.roots {
        let rr = realpath(r);
        if let Some(got) = ids_of(&rr) {
            if contained_by_inode(resolved, &[got]).is_some() {
                return Some(rr);
            }
        }
    }
    None
}

/// The only way the Rust engine obtains a descriptor on a fixture or wipe target.
///
/// Runs [`authorize`], then re-establishes every fact against descriptors:
/// descends from the allowed root one component at a time with
/// `O_NOFOLLOW|O_DIRECTORY` and opens the leaf with `O_NOFOLLOW`, so a component
/// swapped for a symlink between decision and open fails with `ELOOP` instead of
/// escaping. The `File`, not the path, is what callers write through.
///
/// Note that `authorize` runs here under the REAL platform: there is no seam on
/// this path, because there is no test that needs one and every seam on a
/// destructive path is a liability.
pub fn open_authorized(
    policy: &Policy,
    path: &str,
    mode: &str,
    confirmation: Option<&str>,
    env: &Env<'_>,
) -> Result<File, GuardError> {
    let d = authorize(policy, path, confirmation, mode, env, None);
    if !d.allowed {
        return Err(GuardError::Refused(d));
    }
    let norm = normalize_mode(mode).expect("authorize accepted the mode");
    let creating = d.code == ALLOW_CREATE;

    if d.kind == Kind::Device {
        let flags = (if norm == "r" { oflags::O_RDONLY } else { oflags::O_RDWR })
            | oflags::O_NOFOLLOW
            | oflags::O_CLOEXEC;
        let c = CString::new(d.resolved.as_str())
            .map_err(|_| GuardError::Io(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        // SAFETY: as in `openat_checked`; AT_FDCWD is not consulted because the
        // path is absolute.
        let fd = unsafe { openat(-2 /* AT_FDCWD */, c.as_ptr(), flags, 0o600 as c_int) };
        if fd < 0 {
            return Err(GuardError::Io(std::io::Error::last_os_error()));
        }
        return Ok(unsafe { File::from_raw_fd(fd) });
    }

    let resolved = d.resolved.clone();
    let walk_from = if creating { dirname(&resolved) } else { resolved.clone() };
    let root_real = match matching_root_real(policy, &walk_from) {
        Some(r) => r,
        None => {
            return Err(GuardError::Refused(deny(
                DENY_NOT_ALLOWLISTED,
                "root disappeared between decision and open".into(),
                path,
                &resolved,
                Kind::File,
            )))
        }
    };

    let parts = match rel_parts(&resolved, &root_real) {
        Some(p) if !p.is_empty() => p,
        _ => {
            return Err(GuardError::Refused(deny(
                DENY_NOT_ALLOWLISTED,
                "target does not sit strictly below its root".into(),
                path,
                &resolved,
                Kind::File,
            )))
        }
    };

    // O_NOFOLLOW on the ROOT's own open, not only on the descent below.
    // `root_real` is already a realpath, so its final component is symlink-free
    // by construction and no legitimate root is lost -- but if the root's
    // directory entry is swapped for a symlink between the decision and this
    // instant, following it starts the descent OUTSIDE the allowlist. This was
    // the one open on the path that omitted O_NOFOLLOW, and a racing rename
    // escaped through it: MEASURED, before this fix, as a 4096-byte file
    // outside every allowed root truncated to 0 at attempt 87,502 of 200,000.
    //
    // The errno mapping is the descent's, so this exit is a Decision an audit
    // line can carry rather than a bare io::Error.
    let mut dir = match openat_checked(
        -2, /* AT_FDCWD; root_real is absolute */
        &root_real,
        oflags::O_RDONLY | oflags::O_DIRECTORY | oflags::O_NOFOLLOW | oflags::O_CLOEXEC,
    ) {
        Ok(f) => f,
        Err(e) => {
            let raw = e.raw_os_error().unwrap_or(0);
            let (code, detail) = if raw == oflags::ELOOP
                || raw == oflags::EMLINK
                || raw == oflags::ENOTDIR
            {
                (
                    DENY_SYMLINK_AT_OPEN,
                    "allowed root is a symlink or not a directory at open time".to_string(),
                )
            } else {
                (DENY_RACE, format!("allowed root could not be opened: {e}"))
            };
            return Err(GuardError::Refused(deny(
                code, detail, path, &resolved, Kind::File,
            )));
        }
    };
    for comp in &parts[..parts.len() - 1] {
        let nxt = openat_checked(
            dir.as_raw_fd(),
            comp,
            oflags::O_RDONLY | oflags::O_DIRECTORY | oflags::O_NOFOLLOW | oflags::O_CLOEXEC,
        );
        dir = match nxt {
            Ok(f) => f,
            Err(e) => {
                let raw = e.raw_os_error().unwrap_or(0);
                let (code, detail) = if raw == oflags::ELOOP
                    || raw == oflags::EMLINK
                    || raw == oflags::ENOTDIR
                {
                    (
                        DENY_SYMLINK_AT_OPEN,
                        format!("component {comp:?} is a symlink or not a directory at open time"),
                    )
                } else {
                    (DENY_RACE, format!("descend failed at {comp:?}: {e}"))
                };
                return Err(GuardError::Refused(deny(
                    code, detail, path, &resolved, Kind::File,
                )));
            }
        };
    }

    let flags = match norm {
        "r" => oflags::O_RDONLY | oflags::O_NOFOLLOW,
        "r+" => oflags::O_RDWR | oflags::O_NOFOLLOW,
        "x" => oflags::O_RDWR | oflags::O_CREAT | oflags::O_EXCL | oflags::O_NOFOLLOW,
        _ => {
            // "w": create-exclusive when the decision said the file was absent.
            // When it said the file was there, DELIBERATELY NO O_TRUNC: that
            // flag would make the kernel zero the file in the very syscall that
            // establishes its identity, before the (dev,ino) re-check below can
            // prove the fd landed on the file the decision authorised. The
            // truncation happens after that proof, at the set_len(0) below.
            oflags::O_RDWR
                | oflags::O_NOFOLLOW
                | if creating {
                    oflags::O_CREAT | oflags::O_EXCL
                } else {
                    0
                }
        }
    } | oflags::O_CLOEXEC;

    let leaf = &parts[parts.len() - 1];
    let file = match openat_checked(dir.as_raw_fd(), leaf, flags) {
        Ok(f) => f,
        Err(e) => {
            let raw = e.raw_os_error().unwrap_or(0);
            let (code, detail) = if raw == oflags::ELOOP {
                (DENY_SYMLINK_AT_OPEN, "leaf became a symlink at open time".to_string())
            } else if raw == oflags::EEXIST {
                (
                    DENY_RACE,
                    "target appeared between the decision and the create; refusing rather \
                     than replacing it"
                        .to_string(),
                )
            } else {
                (DENY_RACE, format!("open failed: {e}"))
            };
            return Err(GuardError::Refused(deny(
                code, detail, path, &resolved, Kind::File,
            )));
        }
    };
    drop(dir);

    let fst = file.metadata().map_err(GuardError::Io)?;
    if !fst.file_type().is_file() {
        return Err(GuardError::Refused(deny(
            DENY_NOT_REGULAR,
            "fd is not a regular file".into(),
            path,
            &resolved,
            Kind::File,
        )));
    }
    if fst.nlink() != 1 {
        return Err(GuardError::Refused(deny(
            DENY_HARDLINK,
            format!("fd has {} links", fst.nlink()),
            path,
            &resolved,
            Kind::File,
        )));
    }
    if !creating {
        if (Some(fst.dev()), Some(fst.ino())) != (d.st_dev, d.st_ino) {
            return Err(GuardError::Refused(deny(
                DENY_RACE,
                format!(
                    "target changed identity between decision ({:?},{:?}) and open ({},{})",
                    d.st_dev,
                    d.st_ino,
                    fst.dev(),
                    fst.ino()
                ),
                path,
                &resolved,
                Kind::File,
            )));
        }
        if (norm == "r" || norm == "r+")
            && !(fst.size() >= policy.spec.min_file_bytes
                && fst.size() <= policy.spec.max_file_bytes)
        {
            return Err(GuardError::Refused(deny(
                DENY_SIZE,
                format!("fd size {} out of bounds", fst.size()),
                path,
                &resolved,
                Kind::File,
            )));
        }
    }
    if norm == "w" && !creating {
        // The truncation O_TRUNC would have done, moved to after the type,
        // nlink and (dev,ino) proofs. A refused run now costs no data: the file
        // being emptied is provably the file the decision named, and a file the
        // operator never confirmed is never emptied at all.
        file.set_len(0).map_err(GuardError::Io)?;
    }
    Ok(file)
}

// ============================================================================
//                        THE SHARED CONFORMANCE TABLE
// ============================================================================

#[cfg(test)]
mod json {
    //! A minimal JSON reader, hand-rolled for the same reason the carver's JSON
    //! writer is: Phase 3 adds no dependency. Test-only.

    #[derive(Debug, Clone, PartialEq)]
    pub enum J {
        Null,
        Bool(bool),
        Num(f64),
        Str(String),
        Arr(Vec<J>),
        Obj(Vec<(String, J)>),
    }

    impl J {
        pub fn get(&self, key: &str) -> Option<&J> {
            match self {
                J::Obj(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
        pub fn s(&self) -> &str {
            match self {
                J::Str(s) => s,
                other => panic!("expected string, got {other:?}"),
            }
        }
        pub fn b(&self) -> bool {
            match self {
                J::Bool(b) => *b,
                other => panic!("expected bool, got {other:?}"),
            }
        }
        pub fn u(&self) -> u64 {
            match self {
                J::Num(n) => *n as u64,
                other => panic!("expected number, got {other:?}"),
            }
        }
        pub fn arr(&self) -> &[J] {
            match self {
                J::Arr(a) => a,
                other => panic!("expected array, got {other:?}"),
            }
        }
        pub fn obj(&self) -> &[(String, J)] {
            match self {
                J::Obj(o) => o,
                other => panic!("expected object, got {other:?}"),
            }
        }
        pub fn str_or(&self, key: &str, default: &str) -> String {
            self.get(key).map(|v| v.s().to_string()).unwrap_or_else(|| default.to_string())
        }
        pub fn bool_or(&self, key: &str, default: bool) -> bool {
            self.get(key).map(|v| v.b()).unwrap_or(default)
        }
    }

    pub fn parse(src: &str) -> J {
        let b: Vec<char> = src.chars().collect();
        let mut i = 0usize;
        let v = value(&b, &mut i);
        ws(&b, &mut i);
        assert_eq!(i, b.len(), "trailing bytes in JSON at {i}");
        v
    }

    fn ws(b: &[char], i: &mut usize) {
        while *i < b.len() && (b[*i] == ' ' || b[*i] == '\n' || b[*i] == '\t' || b[*i] == '\r') {
            *i += 1;
        }
    }

    fn value(b: &[char], i: &mut usize) -> J {
        ws(b, i);
        match b[*i] {
            '{' => {
                *i += 1;
                let mut kv = Vec::new();
                ws(b, i);
                if b[*i] == '}' {
                    *i += 1;
                    return J::Obj(kv);
                }
                loop {
                    ws(b, i);
                    let k = string(b, i);
                    ws(b, i);
                    assert_eq!(b[*i], ':');
                    *i += 1;
                    kv.push((k, value(b, i)));
                    ws(b, i);
                    match b[*i] {
                        ',' => *i += 1,
                        '}' => {
                            *i += 1;
                            return J::Obj(kv);
                        }
                        c => panic!("unexpected {c:?} in object"),
                    }
                }
            }
            '[' => {
                *i += 1;
                let mut a = Vec::new();
                ws(b, i);
                if b[*i] == ']' {
                    *i += 1;
                    return J::Arr(a);
                }
                loop {
                    a.push(value(b, i));
                    ws(b, i);
                    match b[*i] {
                        ',' => *i += 1,
                        ']' => {
                            *i += 1;
                            return J::Arr(a);
                        }
                        c => panic!("unexpected {c:?} in array"),
                    }
                }
            }
            '"' => J::Str(string(b, i)),
            't' => {
                *i += 4;
                J::Bool(true)
            }
            'f' => {
                *i += 5;
                J::Bool(false)
            }
            'n' => {
                *i += 4;
                J::Null
            }
            _ => {
                let start = *i;
                while *i < b.len()
                    && (b[*i].is_ascii_digit()
                        || b[*i] == '-'
                        || b[*i] == '+'
                        || b[*i] == '.'
                        || b[*i] == 'e'
                        || b[*i] == 'E')
                {
                    *i += 1;
                }
                let s: String = b[start..*i].iter().collect();
                J::Num(s.parse().expect("number"))
            }
        }
    }

    fn hex4(b: &[char], i: &mut usize) -> u32 {
        let s: String = b[*i..*i + 4].iter().collect();
        *i += 4;
        u32::from_str_radix(&s, 16).expect("\\u escape")
    }

    fn string(b: &[char], i: &mut usize) -> String {
        assert_eq!(b[*i], '"', "expected a string");
        *i += 1;
        let mut out = String::new();
        loop {
            let c = b[*i];
            *i += 1;
            match c {
                '"' => return out,
                '\\' => {
                    let e = b[*i];
                    *i += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'b' => out.push('\u{08}'),
                        'f' => out.push('\u{0c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => {
                            let hi = hex4(b, i);
                            let cp = if (0xd800..0xdc00).contains(&hi) {
                                assert_eq!(b[*i], '\\');
                                assert_eq!(b[*i + 1], 'u');
                                *i += 2;
                                let lo = hex4(b, i);
                                0x1_0000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).expect("code point"));
                        }
                        other => panic!("bad escape \\{other}"),
                    }
                }
                c => out.push(c),
            }
        }
    }
}

#[cfg(test)]
mod conformance {
    //! Every row of `fixtures/guard_vectors.json`, run against this
    //! implementation. The expectations in that file were MEASURED from
    //! `fixtures/guard.py`; nothing here authors one.
    //!
    //! A row is satisfied only when the decision code matches AND, where the row
    //! asks for it, a descriptor was obtained exactly when the decision allowed
    //! one. A refusal that arrives as an `io::Error` is a FAILURE, not a pass:
    //! it means the guard said yes and only the kernel said no. That distinction
    //! is the whole point -- the measured defect in the previous prototype was a
    //! red-team row that read "refused" because the process lacked root, while
    //! the guard had already returned ALLOW_DEVICE for the boot drive.

    use super::json::{parse, J};
    use super::*;
    use std::ffi::CString;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    extern "C" {
        fn mkfifo(path: *const c_char, mode: u32) -> c_int;
    }

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn vectors_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("guard_vectors.json")
    }

    /// The lab lives under the system temp directory unless
    /// `SENTINELWIPE_GUARD_LAB_DIR` names somewhere else. On macOS the temp
    /// directory is reached through a symlinked ancestor (`/var` ->
    /// `/private/var`), which is what makes the two aliasing control rows real
    /// rather than decorative.
    fn lab_base() -> PathBuf {
        let base = std::env::var("SENTINELWIPE_GUARD_LAB_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        base.join(format!("sw-guard-rs-{}-{}-{}", std::process::id(), n, stamp))
    }

    struct Lab {
        base: String,
        real: String,
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn subst(s: &str, sub: &[(&str, Option<String>)]) -> String {
        let mut out = s.to_string();
        for (k, v) in sub {
            if let Some(v) = v {
                out = out.replace(k, v);
            }
        }
        out
    }

    fn build_lab(spec: &J, base: &str) -> Lab {
        std::fs::create_dir_all(base).expect("lab base");
        let real = realpath(base);
        let sub: Vec<(&str, Option<String>)> =
            vec![("{lab}", Some(base.to_string())), ("{lab_real}", Some(real.clone()))];

        for d in spec.get("dirs").unwrap().arr() {
            std::fs::create_dir_all(format!("{}/{}", base, d.s())).unwrap();
        }
        for f in spec.get("files").unwrap().arr() {
            let p = format!("{}/{}", base, f.get("path").unwrap().s());
            let n = f.get("bytes").unwrap().u() as usize;
            let fill = f.get("fill").unwrap().u() as u8;
            let mut fh = std::fs::File::create(&p).unwrap();
            fh.write_all(&vec![fill; n]).unwrap();
        }
        for s in spec.get("symlinks").unwrap().arr() {
            let link = format!("{}/{}", base, s.get("link").unwrap().s());
            let to = subst(s.get("to").unwrap().s(), &sub);
            std::os::unix::fs::symlink(&to, &link).unwrap();
        }
        for h in spec.get("hardlinks").unwrap().arr() {
            let link = format!("{}/{}", base, h.get("link").unwrap().s());
            let to = subst(h.get("to").unwrap().s(), &sub);
            std::fs::hard_link(&to, &link).unwrap();
        }
        for p in spec.get("fifos").unwrap().arr() {
            let path = format!("{}/{}", base, p.s());
            let c = CString::new(path.as_str()).unwrap();
            // SAFETY: a NUL-terminated path that outlives the call.
            let rc = unsafe { mkfifo(c.as_ptr(), 0o600) };
            assert_eq!(rc, 0, "mkfifo {path}: {}", std::io::Error::last_os_error());
        }
        Lab { base: base.to_string(), real }
    }

    fn build_policy(spec: &J, sub: &[(&str, Option<String>)]) -> Result<Policy, PolicyError> {
        let mut ps = PolicySpec::default();
        ps.roots = spec
            .get("roots")
            .map(|r| r.arr().iter().map(|x| subst(x.s(), sub)).collect())
            .unwrap_or_default();
        if let Some(d) = spec.get("devices") {
            ps.devices = d.arr().iter().map(|x| subst(x.s(), sub)).collect();
        }
        ps.allow_device_targets = spec.bool_or("allow_device_targets", false);
        ps.require_confirmation = spec.bool_or("require_confirmation", false);
        if let Some(v) = spec.get("min_file_bytes") {
            ps.min_file_bytes = v.u();
        }
        if let Some(v) = spec.get("max_file_bytes") {
            ps.max_file_bytes = v.u();
        }
        Policy::build(ps)
    }

    fn requirement_met(req: &str, sub: &[(&str, Option<String>)]) -> bool {
        if req == "darwin" {
            return native_platform() == "darwin";
        }
        if req == "volfs" {
            return is_dir("/.vol");
        }
        if req == "boot_device" {
            return sub.iter().any(|(k, v)| *k == "{boot_device}" && v.is_some());
        }
        if req == "boot_whole_disk" {
            return sub
                .iter()
                .find(|(k, _)| *k == "{boot_whole_disk}")
                .and_then(|(_, v)| v.clone())
                .map(|p| std::fs::symlink_metadata(&p).is_ok())
                .unwrap_or(false);
        }
        if let Some(rest) = req.strip_prefix("path_exists:") {
            let p = subst(rest, sub);
            return std::fs::symlink_metadata(&p).is_ok();
        }
        panic!("unknown requirement {req:?}");
    }

    /// Returns the target string, plus a descriptor the row keeps alive.
    fn resolve_target(t: &J, sub: &[(&str, Option<String>)]) -> (String, Option<File>) {
        match t.get("kind").unwrap().s() {
            "path" => (subst(t.get("tpl").unwrap().s(), sub), None),
            "volfs" => {
                let of = subst(t.get("of").unwrap().s(), sub);
                let m = std::fs::metadata(&of).expect("volfs subject");
                let suffix = t.str_or("suffix", "");
                (format!("/.vol/{}/{}{}", m.dev(), m.ino(), suffix), None)
            }
            "devfd" => {
                let of = subst(t.get("of").unwrap().s(), sub);
                let f = File::open(&of).expect("devfd subject");
                (format!("/dev/fd/{}", f.as_raw_fd()), Some(f))
            }
            other => panic!("unknown target kind {other:?}"),
        }
    }

    fn make_conf(c: &J, target: &str, sub: &[(&str, Option<String>)]) -> Option<String> {
        match c {
            J::Null => None,
            _ => Some(match c.get("kind").unwrap().s() {
                "literal" => subst(c.get("tpl").unwrap().s(), sub),
                "resolved" => realpath(target),
                "resolved_drop_last" => {
                    let r = realpath(target);
                    r[..r.len() - 1].to_string()
                }
                "resolved_plus" => format!("{}{}", realpath(target), c.get("suffix").unwrap().s()),
                other => panic!("unknown confirmation kind {other:?}"),
            }),
        }
    }

    #[test]
    fn the_vector_table_is_present_and_not_vacuous() {
        // Guard the guard: an empty or truncated table would make every
        // assertion below pass while measuring nothing.
        let src = std::fs::read_to_string(vectors_path()).expect("fixtures/guard_vectors.json");
        let doc = parse(&src);
        assert_eq!(doc.get("schema").unwrap().s(), "sentinelwipe.guard_vectors/1");
        let rows = doc.get("rows").unwrap().arr();
        let pol = doc.get("policy_rows").unwrap().arr();
        assert!(rows.len() >= 80, "only {} rows in the table", rows.len());
        assert!(pol.len() >= 18, "only {} policy rows", pol.len());
        let allows = rows.iter().filter(|r| r.get("expect_allowed").unwrap().b()).count();
        let denies = rows.len() - allows;
        assert!(allows >= 15, "only {allows} positive controls; a table of refusals proves nothing");
        assert!(denies >= 60, "only {denies} refusals");
        assert!(
            rows.iter().any(|r| r.get("expect_code").map(|c| c.s() == ALLOW_DEVICE).unwrap_or(false)),
            "no ALLOW_DEVICE row: the device path could be refusing everything"
        );
        assert!(
            rows.iter().any(|r| r.get("name").unwrap().s().contains("MEASURED DEFECT")),
            "the regression row for the boot-disk defect is missing from the table"
        );

        // Every code this implementation can produce is accounted for: either a
        // row exercises it, or the table names it in codes_not_exercised with a
        // reason. A code present in one implementation and absent from the other
        // is the drift this whole file exists to catch.
        let mut seen: Vec<String> = Vec::new();
        for r in rows {
            if let Some(c) = r.get("expect_code") {
                seen.push(c.s().to_string());
            }
            if let Some(set) = r.get("expect_code_any") {
                for c in set.arr() {
                    seen.push(c.s().to_string());
                }
            }
            if let Some(c) = r.get("expect_open_code") {
                if !c.s().is_empty() {
                    seen.push(c.s().to_string());
                }
            }
        }
        // A code is accounted for in exactly one of three ways, and each one has to
        // carry something a reader can check. Keys beginning with `_` are prose
        // addressed to that reader and are skipped here.
        //
        //   1. a row exercises it;
        //   2. `codes_not_exercised` states why it is unreachable on this host;
        //   3. `codes_exercised_by_race_test` names a RACING test in EACH language
        //      that reaches it, with the measured census from both.
        //
        // The third bucket exists because the second one used to hold
        // DENY_RACE_DETECTED_AT_OPEN and DENY_SYMLINK_COMPONENT_AT_OPEN — the two
        // clauses guarding the window between the decision and the open — excused as
        // "not expressible in a static table". They are not inexpressible, only not
        // TABLE rows, and while that excuse stood, all 85 rows passed in both
        // languages against two guards that would truncate a file outside every
        // allowed root under a racing rename. An unreached clause is not a guard.
        let excused: Vec<String> = doc
            .get("codes_not_exercised")
            .unwrap()
            .obj()
            .iter()
            .filter(|(k, _)| !k.starts_with('_'))
            .map(|(k, v)| {
                assert!(!v.s().trim().is_empty(), "{k} is excused without a reason");
                k.clone()
            })
            .collect();

        let this_file = include_str!("guard.rs");
        let py_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join("test_guard.py");
        let py_file = std::fs::read_to_string(&py_path).expect("tests/test_guard.py");
        let raced: Vec<String> = doc
            .get("codes_exercised_by_race_test")
            .expect("codes_exercised_by_race_test")
            .obj()
            .iter()
            .filter(|(k, _)| !k.starts_with('_'))
            .map(|(k, v)| {
                for field in ["rust_test", "python_test", "measured_rust", "measured_python"] {
                    let got = v.get(field).unwrap_or_else(|| panic!("{k} has no {field}"));
                    assert!(!got.s().trim().is_empty(), "{k}.{field} is empty");
                }
                // The named tests must EXIST. A table that names a test nobody
                // wrote is the same paper excuse in a different field.
                let rname = v.get("rust_test").unwrap().s();
                let rleaf = rname.rsplit("::").next().unwrap();
                assert!(
                    this_file.contains(&format!("fn {rleaf}(")),
                    "{k}.rust_test names {rleaf}, which is not in guard.rs"
                );
                let pname = v.get("python_test").unwrap().s();
                let pleaf = pname.rsplit("::").next().unwrap();
                assert!(
                    py_file.contains(&format!("def {pleaf}(")),
                    "{k}.python_test names {pleaf}, which is not in tests/test_guard.py"
                );
                k.clone()
            })
            .collect();
        assert!(
            raced.iter().any(|c| c == DENY_RACE)
                && raced.iter().any(|c| c == DENY_SYMLINK_AT_OPEN),
            "the two open-time race clauses must be accounted for by a race test"
        );

        for code in ALL_CODES {
            assert!(
                seen.iter().any(|c| c == code)
                    || excused.iter().any(|c| c == code)
                    || raced.iter().any(|c| c == code),
                "code {code} is neither exercised by a row, nor named in \
                 codes_not_exercised with a reason, nor reached by a race test"
            );
        }
        for code in seen.iter().chain(excused.iter()).chain(raced.iter()) {
            assert!(
                ALL_CODES.contains(&code.as_str()),
                "the table names {code}, which this implementation cannot produce"
            );
        }
        assert_eq!(doc.get("codes_defined").unwrap().u() as usize, ALL_CODES.len());
    }

    #[test]
    fn every_vector_row_agrees_with_the_python_guard() {
        let src = std::fs::read_to_string(vectors_path()).expect("fixtures/guard_vectors.json");
        let doc = parse(&src);
        let base_pb = lab_base();
        let base = base_pb.to_string_lossy().into_owned();
        let lab = build_lab(doc.get("lab").unwrap(), &base);

        let boot = root_backing_device();
        let whole = boot.as_deref().map(|b| format!("/dev/{}", whole_disk(b)));
        let home = std::env::var("HOME").ok().map(|h| realpath(&h));
        let first = format!(
            "/{}",
            lab.real.split('/').find(|p| !p.is_empty()).unwrap_or("")
        );
        let sub: Vec<(&str, Option<String>)> = vec![
            ("{lab_real_first_component}", Some(first)),
            ("{lab_real}", Some(lab.real.clone())),
            ("{lab}", Some(lab.base.clone())),
            ("{home}", home),
            ("{boot_whole_disk}", whole),
            ("{boot_device}", boot),
        ];

        let policies = doc.get("policies").unwrap();
        let mut checked = 0usize;
        let mut skipped: Vec<String> = Vec::new();
        let mut refusals = 0usize;
        let mut allows = 0usize;
        let mut failures: Vec<String> = Vec::new();

        // --- the canonical policy payload, which is what this crate can offer
        // --- in place of Python's SHA-256 digest.
        for (name, spec) in policies.obj() {
            let tpl = match spec.get("digest_payload_tpl") {
                Some(t) => t.s(),
                None => continue,
            };
            let needs_boot = tpl.contains("{boot_");
            if needs_boot
                && sub.iter().any(|(k, v)| k.starts_with("{boot_") && v.is_none())
            {
                continue;
            }
            let p = match build_policy(spec, &sub) {
                Ok(p) => p,
                Err(e) => panic!("policy {name} did not build: {e}"),
            };
            assert_eq!(
                p.digest_payload(),
                subst(tpl, &sub),
                "policy {name}: the canonical digest payload has drifted from guard.py's"
            );
        }

        for row in doc.get("rows").unwrap().arr() {
            let name = row.get("name").unwrap().s().to_string();
            let reqs: Vec<String> =
                row.get("requires").unwrap().arr().iter().map(|r| r.s().to_string()).collect();
            if !reqs.iter().all(|r| requirement_met(r, &sub)) {
                skipped.push(name);
                continue;
            }
            let policy = match build_policy(
                policies.get(row.get("policy").unwrap().s()).unwrap(),
                &sub,
            ) {
                Ok(p) => p,
                Err(e) => {
                    failures.push(format!("{name}: policy did not build: {e}"));
                    continue;
                }
            };
            let (target, held) = resolve_target(row.get("target").unwrap(), &sub);
            let conf = make_conf(row.get("confirmation").unwrap(), &target, &sub);
            let mode = row.get("mode").unwrap().s();
            let envv: Vec<(String, String)> = row
                .get("env")
                .unwrap()
                .obj()
                .iter()
                .map(|(k, v)| (k.clone(), v.s().to_string()))
                .collect();
            let env = Env::Map(&envv);
            let plat = row.get("platform").unwrap().s();
            let platform = if plat == "native" { None } else { Some(plat) };

            let d = authorize(&policy, &target, conf.as_deref(), mode, &env, platform);

            let want_allowed = row.get("expect_allowed").unwrap().b();
            if d.allowed != want_allowed {
                failures.push(format!(
                    "{name}: allowed={} want {} (code {})",
                    d.allowed, want_allowed, d.code
                ));
            }
            match row.get("expect_code_any") {
                Some(set) => {
                    let ok = set.arr().iter().any(|c| c.s() == d.code);
                    if !ok {
                        failures.push(format!("{name}: code {} not in the admitted set", d.code));
                    }
                }
                None => {
                    let want = row.get("expect_code").unwrap().s();
                    if d.code != want {
                        failures.push(format!("{name}: code {} want {want}", d.code));
                    }
                }
            }
            let want_kind = row.get("expect_kind").unwrap().s();
            if d.kind.as_str() != want_kind {
                failures.push(format!("{name}: kind {} want {want_kind}", d.kind.as_str()));
            }
            if d.allowed {
                allows += 1;
            } else {
                refusals += 1;
                if !d.code.starts_with("DENY_") {
                    failures.push(format!("{name}: refusal code {} is not a DENY_", d.code));
                }
            }

            if row.get("open").unwrap().b() {
                let want_fd = row.get("expect_fd").unwrap().b();
                match open_authorized(&policy, &target, mode, conf.as_deref(), &env) {
                    Ok(f) => {
                        drop(f);
                        if !want_fd {
                            failures.push(format!("{name}: DESCRIPTOR OBTAINED on a refused row"));
                        }
                    }
                    Err(GuardError::Refused(rd)) => {
                        if want_fd {
                            failures.push(format!("{name}: open refused with {}", rd.code));
                        } else {
                            let want_open = row.get("expect_open_code").unwrap().s();
                            if rd.code != want_open {
                                failures.push(format!(
                                    "{name}: open code {} want {want_open}",
                                    rd.code
                                ));
                            }
                        }
                    }
                    Err(GuardError::Io(e)) => failures.push(format!(
                        "{name}: open refused by errno {e}, NOT by policy. A guard stopped \
                         by the kernel is not a guard."
                    )),
                }
            }
            drop(held);
            checked += 1;
        }

        // --- policy construction rows
        let mut pol_checked = 0usize;
        for row in doc.get("policy_rows").unwrap().arr() {
            let name = row.get("name").unwrap().s().to_string();
            let reqs: Vec<String> = row
                .get("requires")
                .map(|r| r.arr().iter().map(|x| x.s().to_string()).collect())
                .unwrap_or_default();
            if !reqs.iter().all(|r| requirement_met(r, &sub)) {
                skipped.push(name);
                continue;
            }
            let want = row.get("expect").unwrap().s();
            let got = match build_policy(row, &sub) {
                Ok(_) => "OK",
                Err(_) => "POLICY_ERROR",
            };
            if got != want {
                failures.push(format!("{name}: policy {got} want {want}"));
            }
            pol_checked += 1;
        }

        // The victim outside the allowed root must be untouched, byte for byte.
        let victim = format!("{}/outside/victim.img", lab.real);
        let bytes = std::fs::read(&victim).expect("victim");
        assert!(
            bytes.iter().all(|b| *b == 0xaa),
            "a file OUTSIDE the allowed root was modified"
        );

        eprintln!(
            "\nSENTINELWIPE guard - Rust conformance against fixtures/guard_vectors.json\n\
             {checked} target rows + {pol_checked} policy rows executed, {} skipped\n\
             {refusals} refusals, {allows} allows, {} failures\n\
             skipped: {:?}",
            skipped.len(),
            failures.len(),
            skipped
        );

        assert!(
            checked >= 80,
            "only {checked} rows executed; the table is skipping itself into vacuity"
        );
        assert!(
            failures.is_empty(),
            "the Rust guard disagrees with the committed table:\n  {}",
            failures.join("\n  ")
        );
    }

    // ------------------------------------------------------------ unit checks
    //
    // Small properties the table cannot state, because they are about the guard's
    // own primitives rather than about a decision.

    #[test]
    fn realpath_resolves_dot_dotdot_and_repeated_separators() {
        let base_pb = lab_base();
        let base = base_pb.to_string_lossy().into_owned();
        std::fs::create_dir_all(format!("{base}/a/b")).unwrap();
        let lab = Lab { base: base.clone(), real: realpath(&base) };
        std::fs::write(format!("{base}/a/f"), b"x").unwrap();
        let want = format!("{}/a/f", lab.real);
        for spelling in [
            format!("{base}/a/f"),
            format!("{base}//a//f"),
            format!("{base}/a/./f"),
            format!("{base}/a/b/../f"),
            format!("{base}/./a/././f"),
        ] {
            assert_eq!(realpath(&spelling), want, "{spelling}");
        }
        assert_eq!(realpath("/"), "/");
        assert_eq!(realpath("/.."), "/");
    }

    #[test]
    fn whole_disk_strips_the_slice_and_the_raw_prefix() {
        assert_eq!(whole_disk("/dev/disk3s5"), "disk3");
        assert_eq!(whole_disk("/dev/rdisk3s5"), "disk3");
        assert_eq!(whole_disk("/dev/disk0"), "disk0");
        assert_eq!(whole_disk("/dev/rdisk0"), "disk0");
    }

    #[test]
    fn containment_is_identity_and_never_a_string_relation() {
        let base_pb = lab_base();
        let base = base_pb.to_string_lossy().into_owned();
        std::fs::create_dir_all(format!("{base}/root/sub")).unwrap();
        std::fs::create_dir_all(format!("{base}/root-evil")).unwrap();
        let lab = Lab { base: base.clone(), real: realpath(&base) };
        let root_ids = [ids_of(&format!("{}/root", lab.real)).unwrap()];
        assert!(contained_by_inode(&format!("{}/root/sub", lab.real), &root_ids).is_some());
        assert!(contained_by_inode(&format!("{}/root", lab.real), &root_ids).is_some());
        // the sibling whose name shares a prefix
        assert!(contained_by_inode(&format!("{}/root-evil", lab.real), &root_ids).is_none());
        // an empty allowlist can never match, whatever the path
        assert!(contained_by_inode(&format!("{}/root", lab.real), &[]).is_none());
    }

    #[test]
    fn the_audit_record_escapes_the_way_python_json_does() {
        // json.dumps defaults to ensure_ascii=True, so a combining accent leaves
        // the process as é. The audit line has to be byte-comparable across
        // the two implementations or it is not one record format.
        let d = Decision {
            allowed: true,
            code: ALLOW_FILE,
            resolved: "/x/café.img".into(),
            detail: "a\"b\\c\nd".into(),
            target: "/x/café.img".into(),
            st_dev: Some(1),
            st_ino: Some(2),
            kind: Kind::File,
        };
        assert_eq!(
            d.as_json_record("deadbeef"),
            "{\"allowed\":true,\"code\":\"ALLOW_FILE\",\"detail\":\"a\\\"b\\\\c\\nd\",\
             \"kind\":\"file\",\"policy_digest\":\"deadbeef\",\
             \"resolved\":\"/x/caf\\u00e9.img\",\"st_dev\":1,\"st_ino\":2,\
             \"target\":\"/x/caf\\u00e9.img\"}"
        );
    }

    #[test]
    fn the_measured_defect_is_not_reintroduced() {
        //! THE regression test for the defect this component exists to not repeat.
        //!
        //! Previous prototype, red-team row "/dev/disk0 allowlisted + env set":
        //! result "refused", clause "OSERROR/1". EPERM. The guard had returned
        //! ALLOW_DEVICE for the internal boot drive and only the absence of root
        //! privilege stopped the write. That is CLAUDE.md rule 4's disqualifying
        //! defect reached through the documented escape hatch.
        //!
        //! Here the refusal must come from POLICY: `authorize` says no with a
        //! DENY_ code of device kind, and `open_authorized` returns
        //! `GuardError::Refused` -- never `GuardError::Io`. A decision is what a
        //! guard produces; an errno is what the kernel produces after the guard
        //! has already failed. Nothing in this test opens a device node.
        if std::fs::symlink_metadata("/dev/disk0").is_err() {
            return; // no /dev/disk0 on this host
        }
        let base_pb = lab_base();
        let base = base_pb.to_string_lossy().into_owned();
        std::fs::create_dir_all(format!("{base}/fixtures")).unwrap();
        let lab = Lab { base: base.clone(), real: realpath(&base) };

        let mut ps = PolicySpec::with_roots([format!("{}/fixtures", lab.base)]);
        ps.devices = vec!["/dev/disk0".into()];
        ps.allow_device_targets = true;
        ps.require_confirmation = true;
        let pol = Policy::build(ps).expect("armed policy");
        let envv = vec![(DEVICE_MODE_ENV.to_string(), "1".to_string())];
        let env = Env::Map(&envv);

        // All three factors present and the confirmation correct.
        let d = authorize(&pol, "/dev/disk0", Some("/dev/disk0"), "r+", &env, None);
        assert!(!d.allowed, "the guard PERMITTED the internal disk");
        assert!(d.code.starts_with("DENY_"), "{}", d.code);
        assert_eq!(d.kind, Kind::Device);
        if native_platform() == "darwin" {
            assert_eq!(d.code, DENY_DEVICE_PLATFORM);
        }

        match open_authorized(&pol, "/dev/disk0", "r+", Some("/dev/disk0"), &env) {
            Ok(_) => panic!("a descriptor was obtained on /dev/disk0"),
            Err(GuardError::Io(e)) => panic!(
                "refused by errno {e}, not by policy. A guard stopped by the kernel \
                 is not a guard -- this is the exact defect being regression-tested."
            ),
            Err(GuardError::Refused(rd)) => {
                assert_eq!(rd.code, d.code);
                assert_eq!(rd.kind, Kind::Device);
            }
        }

        // The refusal is not "the device path refuses everything". Behind the D0
        // blanket the allowlist can still say yes, and the boot-disk clause still
        // says no -- both asserted here so the row above cannot pass vacuously.
        let mut ps2 = PolicySpec::with_roots([format!("{}/fixtures", lab.base)]);
        ps2.devices = vec!["/dev/null".into()];
        ps2.allow_device_targets = true;
        ps2.require_confirmation = true;
        let pol2 = Policy::build(ps2).expect("armed /dev/null policy");
        let yes = authorize(&pol2, "/dev/null", Some("/dev/null"), "r+", &env, Some("linux"));
        assert!(yes.allowed && yes.code == ALLOW_DEVICE, "{}", yes.code);

        if let Some(boot) = root_backing_device() {
            let mut ps3 = PolicySpec::with_roots([format!("{}/fixtures", lab.base)]);
            ps3.devices = vec![boot.clone()];
            ps3.allow_device_targets = true;
            ps3.require_confirmation = true;
            let pol3 = Policy::build(ps3).expect("armed boot policy");
            let d3 = authorize(&pol3, &boot, Some(&boot), "r+", &env, Some("linux"));
            assert!(!d3.allowed);
            assert_eq!(d3.code, DENY_DEVICE_IS_SYSTEM, "target {boot}");
        }
    }

    #[test]
    fn arming_devices_without_a_confirmation_requirement_is_refused_at_construction() {
        // Why the "unconditional" device confirmation cannot be mutated away
        // meaningfully: the pair is enforced one layer up, so a policy that arms
        // devices without demanding the typed confirmation does not exist.
        let base_pb = lab_base();
        let base = base_pb.to_string_lossy().into_owned();
        std::fs::create_dir_all(format!("{base}/fixtures")).unwrap();
        let lab = Lab { base: base.clone(), real: realpath(&base) };
        let mut ps = PolicySpec::with_roots([format!("{}/fixtures", lab.base)]);
        ps.devices = vec!["/dev/disk9".into()];
        ps.allow_device_targets = true;
        ps.require_confirmation = false;
        assert!(Policy::build(ps).is_err());
    }

    #[test]
    fn the_platform_seam_bypasses_d0_and_only_d0() {
        // The control for every seam row in the table. If this stops being true
        // those rows are measuring nothing.
        if native_platform() != "darwin" {
            return;
        }
        let base_pb = lab_base();
        let base = base_pb.to_string_lossy().into_owned();
        std::fs::create_dir_all(format!("{base}/fixtures")).unwrap();
        let lab = Lab { base: base.clone(), real: realpath(&base) };
        let pol = Policy::build(PolicySpec::with_roots([format!("{}/fixtures", lab.base)])).unwrap();
        let env = Env::Map(&[]);
        assert_eq!(
            authorize(&pol, "/dev/null", None, "r+", &env, None).code,
            DENY_DEVICE_PLATFORM
        );
        assert_eq!(
            authorize(&pol, "/dev/null", None, "r+", &env, Some("linux")).code,
            DENY_DEVICE_MODE_OFF
        );
    }
}

// ============================================================================
//                          THE RACE TESTS
// ============================================================================

#[cfg(test)]
mod race {
    //! The two clauses the shared conformance table CANNOT reach.
    //!
    //! `fixtures/guard_vectors.json` is a static table of (target, policy,
    //! expected code) rows. It proves the two implementations AGREE. It cannot
    //! reach `DENY_RACE_DETECTED_AT_OPEN` or `DENY_SYMLINK_COMPONENT_AT_OPEN`,
    //! because both require the filesystem to CHANGE between the decision and
    //! the open -- there is no row that expresses "and now another process
    //! renames this directory". The table's `codes_not_exercised` field said so
    //! and left it there, and that omission is exactly what hid a real escape:
    //! every one of the 85 rows passed in both languages while both guards
    //! would truncate a file outside every allowed root under a racing rename.
    //!
    //! These tests need no table. A thread flips one path node while a loop
    //! calls `open_authorized`, and two things are asserted:
    //!
    //!   1. SAFETY -- a pinned victim file outside every allowed root is
    //!      byte-identical afterwards, and its inode never changed. A refusal
    //!      that costs data is not a refusal.
    //!   2. REACHABILITY -- the census contains the race code, so the clause is
    //!      known to be executed rather than merely present, and every outcome
    //!      is a policy Decision. `GuardError::Io` is a FAILURE here: a guard
    //!      stopped by the kernel is not a guard.
    //!
    //! Measured before the fix, with this harness's Python twin: the victim was
    //! truncated 4096 -> 0 at attempt 87,502 of 200,000 in mode "w", inode
    //! unchanged, while the guard returned DENY_RACE_DETECTED_AT_OPEN for that
    //! same call. Two independent causes compounded -- the allowed root's own
    //! open omitted O_NOFOLLOW, and O_TRUNC rode in the openat that established
    //! identity, before the (dev,ino) re-check could fire. Both are fixed; these
    //! tests are what keep them fixed.

    use super::*;
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, Ordering as AtOrd};
    use std::sync::Arc;

    fn lab_dir(tag: &str) -> String {
        let base = std::env::var("SENTINELWIPE_GUARD_LAB_DIR")
            .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{base}/sw-guard-race-{tag}-{}-{stamp}", std::process::id())
    }

    struct Census {
        counts: Vec<(String, u64)>,
    }

    impl Census {
        fn new() -> Census {
            Census { counts: Vec::new() }
        }
        fn bump(&mut self, k: &str) {
            match self.counts.iter_mut().find(|(n, _)| n == k) {
                Some((_, c)) => *c += 1,
                None => self.counts.push((k.to_string(), 1)),
            }
        }
        fn get(&self, k: &str) -> u64 {
            self.counts.iter().find(|(n, _)| n == k).map(|(_, c)| *c).unwrap_or(0)
        }
        fn render(&self) -> String {
            let mut v = self.counts.clone();
            v.sort();
            v.iter().map(|(k, c)| format!("{k}={c}")).collect::<Vec<_>>().join(" ")
        }
    }

    /// Read a whole file by path, or None if it is not there right now.
    fn slurp(p: &str) -> Option<Vec<u8>> {
        let mut f = std::fs::File::open(p).ok()?;
        let mut b = Vec::new();
        f.read_to_end(&mut b).ok()?;
        Some(b)
    }

    #[test]
    fn racing_the_allowed_root_never_truncates_a_file_outside_it() {
        //! Cause (1): the allowed root's own open. Every other component of the
        //! descent was opened O_NOFOLLOW; the root was not, so a rename that
        //! turned the root into a symlink in that instant started the descent
        //! outside the allowlist -- and O_TRUNC in the leaf's openat then zeroed
        //! whatever it landed on before identity was re-checked.
        let base = lab_dir("root");
        let root = format!("{base}/fixtures");
        let outside = format!("{base}/outside");
        let hidden = format!("{base}/fixtures.real");
        std::fs::create_dir_all(format!("{root}/sub")).unwrap();
        std::fs::create_dir_all(format!("{outside}/sub")).unwrap();

        let victim = format!("{outside}/sub/disk.img");
        std::fs::write(&victim, vec![0xAAu8; 4096]).unwrap();
        let victim_ids = ids_of(&victim).expect("victim");
        let victim_before = slurp(&victim).expect("victim readable");

        let target = format!("{root}/sub/disk.img");
        std::fs::write(&target, vec![0xBBu8; 4096]).unwrap();

        // The policy is fixed BEFORE the race starts. An allowlist whose root is
        // chosen while the attacker holds the directory entry names whatever the
        // attacker wants and proves nothing; the threat model is a FIXED policy
        // and a moving filesystem.
        let pol = Policy::build(PolicySpec::with_roots([root.clone()])).expect("policy");
        let env = Env::Map(&[]);

        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let (stop, root, outside, hidden) =
                (stop.clone(), root.clone(), outside.clone(), hidden.clone());
            std::thread::spawn(move || {
                while !stop.load(AtOrd::Relaxed) {
                    let _ = std::fs::rename(&root, &hidden);
                    let _ = std::os::unix::fs::symlink(&outside, &root);
                    let _ = std::fs::remove_file(&root);
                    let _ = std::fs::rename(&hidden, &root);
                }
            })
        };

        let mut census = Census::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut attempts = 0u64;
        let mut io_errors = 0u64;
        while attempts < 200_000 && std::time::Instant::now() < deadline {
            attempts += 1;
            match open_authorized(&pol, &target, "w", Some(&target), &env) {
                Ok(_f) => census.bump("ALLOW"),
                Err(GuardError::Refused(d)) => census.bump(d.code),
                Err(GuardError::Io(e)) => {
                    io_errors += 1;
                    census.bump(&format!("IO:{}", e.raw_os_error().unwrap_or(0)));
                }
            }
            // Check the victim on every single attempt, not at the end: a
            // truncation followed by a restore would otherwise go unseen.
            if let Some(now) = slurp(&victim) {
                assert_eq!(
                    now.len(),
                    4096,
                    "THE GUARD TRUNCATED A FILE OUTSIDE EVERY ALLOWED ROOT on \
                     attempt {attempts}: {} -> {} bytes. census: {}",
                    4096,
                    now.len(),
                    census.render()
                );
            }
        }
        stop.store(true, AtOrd::Relaxed);
        let _ = flipper.join();
        // Put the root back so the cleanup below can run.
        let _ = std::fs::remove_file(&root);
        let _ = std::fs::rename(&hidden, &root);

        let victim_after = slurp(&victim).expect("victim still there");
        assert_eq!(
            victim_after, victim_before,
            "victim outside the allowlist changed. census: {}",
            census.render()
        );
        assert_eq!(ids_of(&victim), Some(victim_ids), "victim inode changed");
        assert_eq!(
            io_errors,
            0,
            "open_authorized exited by errno rather than by policy {io_errors} times. \
             A guard stopped by the kernel is not a guard. census: {}",
            census.render()
        );
        assert!(
            census.get(DENY_RACE) > 0,
            "the DENY_RACE_DETECTED_AT_OPEN clause was never reached in {attempts} \
             attempts, so this test proved nothing about it. census: {}",
            census.render()
        );
        eprintln!(
            "race/root: {attempts} attempts, victim intact, census: {}",
            census.render()
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn racing_a_mid_path_component_reaches_the_symlink_clause() {
        //! The O_NOFOLLOW descent, which was always correct, and which is the
        //! reason cause (1) was a single hole rather than a general one. A
        //! component BELOW the root is swapped for a symlink pointing outside;
        //! the openat must fail ELOOP and become DENY_SYMLINK_COMPONENT_AT_OPEN.
        let base = lab_dir("mid");
        let root = format!("{base}/fixtures");
        let outside = format!("{base}/outside");
        let sub = format!("{root}/sub");
        let hidden = format!("{root}/sub.real");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let victim = format!("{outside}/disk.img");
        std::fs::write(&victim, vec![0xAAu8; 4096]).unwrap();
        let victim_ids = ids_of(&victim).expect("victim");
        let victim_before = slurp(&victim).expect("victim readable");

        let target = format!("{sub}/disk.img");
        std::fs::write(&target, vec![0xBBu8; 4096]).unwrap();

        let pol = Policy::build(PolicySpec::with_roots([root.clone()])).expect("policy");
        let env = Env::Map(&[]);

        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let (stop, sub, outside, hidden) =
                (stop.clone(), sub.clone(), outside.clone(), hidden.clone());
            std::thread::spawn(move || {
                while !stop.load(AtOrd::Relaxed) {
                    let _ = std::fs::rename(&sub, &hidden);
                    let _ = std::os::unix::fs::symlink(&outside, &sub);
                    let _ = std::fs::remove_file(&sub);
                    let _ = std::fs::rename(&hidden, &sub);
                }
            })
        };

        let mut census = Census::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut attempts = 0u64;
        let mut io_errors = 0u64;
        while attempts < 200_000
            && std::time::Instant::now() < deadline
            && census.get(DENY_SYMLINK_AT_OPEN) < 1
        {
            attempts += 1;
            match open_authorized(&pol, &target, "w", Some(&target), &env) {
                Ok(_f) => census.bump("ALLOW"),
                Err(GuardError::Refused(d)) => census.bump(d.code),
                Err(GuardError::Io(e)) => {
                    io_errors += 1;
                    census.bump(&format!("IO:{}", e.raw_os_error().unwrap_or(0)));
                }
            }
            if let Some(now) = slurp(&victim) {
                assert_eq!(
                    now.len(),
                    4096,
                    "THE GUARD TRUNCATED A FILE OUTSIDE EVERY ALLOWED ROOT on \
                     attempt {attempts}. census: {}",
                    census.render()
                );
            }
        }
        stop.store(true, AtOrd::Relaxed);
        let _ = flipper.join();
        let _ = std::fs::remove_file(&sub);
        let _ = std::fs::rename(&hidden, &sub);

        let victim_after = slurp(&victim).expect("victim still there");
        assert_eq!(victim_after, victim_before, "victim outside the allowlist changed");
        assert_eq!(ids_of(&victim), Some(victim_ids), "victim inode changed");
        assert_eq!(
            io_errors, 0,
            "open_authorized exited by errno rather than by policy {io_errors} times. \
             census: {}",
            census.render()
        );
        assert!(
            census.get(DENY_SYMLINK_AT_OPEN) > 0,
            "the DENY_SYMLINK_COMPONENT_AT_OPEN clause was never reached in \
             {attempts} attempts. census: {}",
            census.render()
        );
        eprintln!(
            "race/mid: {attempts} attempts, victim intact, census: {}",
            census.render()
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
