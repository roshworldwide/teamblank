use std::ffi::CString;
use std::fs::{File, Metadata};
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;

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

pub const ALL_CODES: [&str; 28] = [
    ALLOW_FILE, ALLOW_CREATE, ALLOW_DEVICE,
    DENY_EMPTY, DENY_NUL, DENY_RELATIVE, DENY_SYNTHETIC, DENY_MODE, DENY_MISSING,
    DENY_EXISTS, DENY_NOT_REGULAR, DENY_HARDLINK, DENY_SIZE, DENY_NOT_ALLOWLISTED,
    DENY_CROSSED_MOUNT, DENY_BAD_LEAF, DENY_PARENT_MISSING, DENY_CONFIRMATION,
    DENY_CONFIRMATION_ABSENT, DENY_DEVICE_MODE_OFF, DENY_DEVICE_ENV_OFF,
    DENY_DEVICE_NOT_ALLOWLISTED, DENY_DEVICE_ALIAS, DENY_DEVICE_NOT_A_DEVICE,
    DENY_DEVICE_IS_SYSTEM, DENY_DEVICE_PLATFORM, DENY_RACE, DENY_SYMLINK_AT_OPEN,
];

pub const DEVICE_MODE_ENV: &str = "SENTINELWIPE_DEVICE_MODE";

pub const MIN_ROOT_DEPTH: usize = 2;

pub const DEFAULT_MAX_FILE_BYTES: u64 = 8 * (1 << 30);

pub const FORBIDDEN_ROOTS: &[&str] = &[
    "/", "/dev", "/.vol", "/System", "/System/Volumes/Data", "/Volumes", "/Library",
    "/Applications", "/bin", "/sbin", "/usr", "/etc", "/var", "/private",
    "/private/etc", "/private/var", "/private/var/db", "/private/tmp", "/tmp",
    "/Users", "/home", "/opt", "/net", "/cores", "/Network",
];

pub const MODES: [&str; 4] = ["r", "r+", "w", "x"];

fn normalize_mode(mode: &str) -> Option<&'static str> {
    Some(match mode {
        "r" | "rb" => "r",
        "r+" | "rb+" | "r+b" | "+r" => "r+",
        "w" | "wb" | "w+" | "wb+" | "w+b" => "w",
        "x" | "xb" | "x+" | "xb+" | "x+b" => "x",
        _ => return None,
    })
}

pub fn native_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

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

fn stat(path: &str) -> Option<Metadata> {
    std::fs::metadata(Path::new(path)).ok()
}

fn ids_of(path: &str) -> Option<(u64, u64)> {
    stat(path).map(|m| (m.dev(), m.ino()))
}

fn is_dir(path: &str) -> bool {
    stat(path).map(|m| m.is_dir()).unwrap_or(false)
}

fn dirname(path: &str) -> String {
    match path.rfind('/') {
        None => String::new(),
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

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

pub fn realpath(path: &str) -> String {
    if !path.starts_with('/') {
        return path.to_string();
    }
    let mut stack: Vec<String> = Vec::new();
    let mut pending: Vec<String> = path
        .split('/')
        .rev()
        .map(|s| s.to_string())
        .collect();
    let mut budget = 64_i32;
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
            return None;
        }
    }
}

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

fn ct_eq(a: &str, b: &str) -> bool {
    let (x, y) = (a.as_bytes(), b.as_bytes());
    let mut diff = (x.len() ^ y.len()) as u32;
    let n = x.len().min(y.len());
    for i in 0..n {
        diff |= (x[i] ^ y[i]) as u32;
    }
    diff == 0
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone)]
pub struct PolicySpec {
    pub roots: Vec<String>,
    pub devices: Vec<String>,
    pub allow_device_targets: bool,
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

            if let Some((_, spelling)) = forbidden.iter().find(|(g, _)| *g == got) {
                return Err(PolicyError(format!(
                    "refusing system directory as a write root: {r:?} -> {real:?} \
                     (matches {spelling})"
                )));
            }
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
        return deny(
            DENY_EXISTS,
            format!("{resolved} already exists and mode 'x' refuses to replace it"),
            path,
            &resolved,
            Kind::File,
        );
    }

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
        return None;
    }
    Some(r[b.len()..].iter().map(|s| s.to_string()).collect())
}

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
        let fd = unsafe { openat(-2 , c.as_ptr(), flags, 0o600 as c_int) };
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

    let mut dir = match openat_checked(
        -2,
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
        file.set_len(0).map_err(GuardError::Io)?;
    }
    Ok(file)
}

#[cfg(test)]
mod json {

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

        let this_file = include_str!("unix.rs");
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
        assert!(contained_by_inode(&format!("{}/root-evil", lab.real), &root_ids).is_none());
        assert!(contained_by_inode(&format!("{}/root", lab.real), &[]).is_none());
    }

    #[test]
    fn the_audit_record_escapes_the_way_python_json_does() {
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
        if std::fs::symlink_metadata("/dev/disk0").is_err() {
            return;
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

#[cfg(test)]
mod race {

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

    fn slurp(p: &str) -> Option<Vec<u8>> {
        let mut f = std::fs::File::open(p).ok()?;
        let mut b = Vec::new();
        f.read_to_end(&mut b).ok()?;
        Some(b)
    }

    #[test]
    fn racing_the_allowed_root_never_truncates_a_file_outside_it() {
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
