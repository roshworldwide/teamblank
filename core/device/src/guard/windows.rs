use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};

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
    ALLOW_FILE,
    ALLOW_CREATE,
    ALLOW_DEVICE,
    DENY_EMPTY,
    DENY_NUL,
    DENY_RELATIVE,
    DENY_SYNTHETIC,
    DENY_MODE,
    DENY_MISSING,
    DENY_EXISTS,
    DENY_NOT_REGULAR,
    DENY_HARDLINK,
    DENY_SIZE,
    DENY_NOT_ALLOWLISTED,
    DENY_CROSSED_MOUNT,
    DENY_BAD_LEAF,
    DENY_PARENT_MISSING,
    DENY_CONFIRMATION,
    DENY_CONFIRMATION_ABSENT,
    DENY_DEVICE_MODE_OFF,
    DENY_DEVICE_ENV_OFF,
    DENY_DEVICE_NOT_ALLOWLISTED,
    DENY_DEVICE_ALIAS,
    DENY_DEVICE_NOT_A_DEVICE,
    DENY_DEVICE_IS_SYSTEM,
    DENY_DEVICE_PLATFORM,
    DENY_RACE,
    DENY_SYMLINK_AT_OPEN,
];

pub const DEVICE_MODE_ENV: &str = "SENTINELWIPE_DEVICE_MODE";

pub const MIN_ROOT_DEPTH: usize = 2;

pub const DEFAULT_MAX_FILE_BYTES: u64 = 8 * (1 << 30);

pub const FORBIDDEN_TOP: &[&str] = &[
    "WINDOWS",
    "PROGRAM FILES",
    "PROGRAM FILES (X86)",
    "PROGRAMDATA",
    "USERS",
    "$RECYCLE.BIN",
    "SYSTEM VOLUME INFORMATION",
    "RECOVERY",
    "PERFLOGS",
];

pub const FORBIDDEN_UNDER: &[&str] = &[
    "WINDOWS",
    "PROGRAM FILES",
    "PROGRAM FILES (X86)",
    "PROGRAMDATA",
    "$RECYCLE.BIN",
    "SYSTEM VOLUME INFORMATION",
    "RECOVERY",
    "PERFLOGS",
];

const RESERVED_LEAFS: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
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
    "windows"
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

pub enum Env<'a> {
    Process,
    Map(&'a [(String, String)]),
}

impl Env<'_> {
    #[allow(dead_code)]
    fn get(&self, key: &str) -> Option<String> {
        match self {
            Env::Process => std::env::var(key).ok(),
            Env::Map(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()),
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

#[derive(Debug)]
pub enum GuardError {
    Refused(Decision),
    Io(std::io::Error),
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::Refused(d) => write!(f, "{}: {}", d.code, d.detail),
            GuardError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for GuardError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    spec: PolicySpec,
    root_reals: Vec<String>,
}

impl Policy {
    pub fn build(spec: PolicySpec) -> Result<Policy, PolicyError> {
        if spec.allow_device_targets || !spec.devices.is_empty() {
            return Err(PolicyError(
                "device targets are not supported on windows: this build has no \
                 Windows block-device layer, so a policy that armed one would \
                 authorise an operation nothing can carry out. Remove \
                 allow_device_targets and devices, or run the device path on Linux."
                    .to_string(),
            ));
        }
        if spec.min_file_bytes > spec.max_file_bytes {
            return Err(PolicyError(format!(
                "min_file_bytes {} exceeds max_file_bytes {}",
                spec.min_file_bytes, spec.max_file_bytes
            )));
        }
        if spec.roots.is_empty() {
            return Err(PolicyError(
                "no write roots: a policy with no root allows nothing and is refused \
                 at construction rather than silently denying every target later"
                    .to_string(),
            ));
        }

        let mut root_reals: Vec<String> = Vec::with_capacity(spec.roots.len());
        for r in &spec.roots {
            if r.is_empty() {
                return Err(PolicyError("empty write root".to_string()));
            }
            let p = Path::new(r);
            if !is_absolute_windows(p) {
                return Err(PolicyError(format!(
                    "write root {r:?} is relative; a root is resolved against nothing \
                     and must name a drive or a UNC share"
                )));
            }
            if !p.is_dir() {
                return Err(PolicyError(format!(
                    "write root {r:?} is not an existing directory. The root must exist \
                     before the policy is built: creating it here would make the guard \
                     the thing that widened its own allowlist."
                )));
            }
            let real = realpath(r);
            let comps: Vec<String> = body_components(Path::new(&real))
                .map(|c| c.to_string_lossy().to_uppercase())
                .collect();
            let depth = comps.len();
            if depth < MIN_ROOT_DEPTH {
                return Err(PolicyError(format!(
                    "root is too shallow ({depth} components): {real:?}"
                )));
            }
            if depth == 1 && FORBIDDEN_TOP.contains(&comps[0].as_str()) {
                return Err(PolicyError(format!(
                    "refusing system directory as a write root: {r:?} -> {real:?}"
                )));
            }
            if depth > 1 && FORBIDDEN_UNDER.contains(&comps[0].as_str()) {
                return Err(PolicyError(format!(
                    "refusing write root {real:?}: it lies under the system directory {}",
                    comps[0]
                )));
            }
            let upper = real.to_uppercase();
            if let Some(profile) = std::env::var_os("USERPROFILE") {
                let prof = realpath(&profile.to_string_lossy());
                if !prof.is_empty() && upper == prof.to_uppercase() {
                    return Err(PolicyError(format!(
                        "refusing the user profile directory as a write root: {real:?}"
                    )));
                }
            }
            root_reals.push(real);
        }

        Ok(Policy { spec, root_reals })
    }

    pub fn roots(&self) -> &[String] {
        &self.spec.roots
    }

    pub fn root_reals(&self) -> &[String] {
        &self.root_reals
    }

    pub fn root_ids(&self) -> &[(u64, u64)] {
        &[]
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
        s.push_str(if self.spec.allow_device_targets {
            "true"
        } else {
            "false"
        });
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
        s.push_str(if self.spec.require_confirmation {
            "true"
        } else {
            "false"
        });
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

fn is_absolute_windows(p: &Path) -> bool {
    let mut c = p.components();
    matches!(c.next(), Some(Component::Prefix(_))) && matches!(c.next(), Some(Component::RootDir))
}

fn body_components(p: &Path) -> impl Iterator<Item = std::ffi::OsString> + '_ {
    p.components().filter_map(|c| match c {
        Component::Normal(s) => Some(s.to_os_string()),
        _ => None,
    })
}

fn strip_verbatim(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    match s.strip_prefix(r"\\?\") {
        Some(rest) => rest.to_string(),
        None => s,
    }
}

pub fn realpath(path: &str) -> String {
    let p = Path::new(path);
    if !is_absolute_windows(p) {
        return path.to_string();
    }
    if let Ok(c) = std::fs::canonicalize(p) {
        return strip_verbatim(&c);
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.to_path_buf();
    while let Some(parent) = cur.parent().map(|q| q.to_path_buf()) {
        let name = match cur.file_name() {
            Some(n) => n.to_os_string(),
            None => break,
        };
        tail.push(name);
        if let Ok(c) = std::fs::canonicalize(&parent) {
            let mut out = PathBuf::from(strip_verbatim(&c));
            for n in tail.iter().rev() {
                out.push(n);
            }
            return out.to_string_lossy().to_string();
        }
        cur = parent;
    }
    lexical_normalize(p)
}

fn lexical_normalize(p: &Path) -> String {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out.to_string_lossy().to_string()
}

fn contained_by_components(resolved: &str, root_real: &str) -> bool {
    let rp: Vec<String> = Path::new(root_real)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_uppercase())
        .collect();
    let tp: Vec<String> = Path::new(resolved)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_uppercase())
        .collect();
    tp.len() > rp.len() && tp[..rp.len()] == rp[..]
}

fn matching_root<'a>(policy: &'a Policy, resolved: &str) -> Option<&'a String> {
    policy
        .root_reals
        .iter()
        .find(|r| contained_by_components(resolved, r))
}

fn reparse_component(root_real: &str, resolved: &str) -> Option<String> {
    let root = Path::new(root_real);
    let mut cur = root.to_path_buf();
    let rest = Path::new(resolved).strip_prefix(root).ok()?;
    for part in rest.components() {
        cur.push(part.as_os_str());
        if let Ok(md) = std::fs::symlink_metadata(&cur) {
            if md.file_type().is_symlink() {
                return Some(cur.to_string_lossy().to_string());
            }
        }
    }
    None
}

fn is_reserved_leaf(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_uppercase();
    RESERVED_LEAFS.contains(&stem.as_str())
}

fn is_synthetic_namespace(path: &str) -> bool {
    let p = path.replace('/', "\\");
    p.starts_with(r"\\.\") || p.starts_with(r"\\?\") || p.starts_with(r"\??\")
}

const TOCTOU_NOTE: &str = "windows backend: containment was checked on the resolved path \
and re-checked on the open handle, not held across the open. Unlike the unix backend there \
is no openat(O_NOFOLLOW) descent, so a directory on this path that an attacker can write to \
is a race this guard does not close";

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

fn allow(code: &'static str, detail: String, target: &str, resolved: &str) -> Decision {
    Decision {
        allowed: true,
        code,
        resolved: resolved.to_string(),
        detail,
        target: target.to_string(),
        st_dev: None,
        st_ino: None,
        kind: Kind::File,
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
    let _ = env;

    if let Some(p) = platform {
        if p != native_platform() {
            return deny(
                DENY_DEVICE_PLATFORM,
                format!(
                    "this backend answers for {:?} only; a decision was requested for \
                     {p:?} and is refused rather than guessed",
                    native_platform()
                ),
                path,
                "",
                Kind::File,
            );
        }
    }

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
        return deny(DENY_EMPTY, "empty target".to_string(), path, "", Kind::File);
    }
    if path.contains('\0') {
        return deny(DENY_NUL, "NUL byte in path".to_string(), path, "", Kind::File);
    }
    if is_synthetic_namespace(path) {
        return deny(
            DENY_DEVICE_PLATFORM,
            format!(
                "{path:?} names the Windows device or verbatim namespace. This build has \
                 no Windows block-device layer, so there is nothing here to authorise; \
                 the device path is Linux-gated and never demoed. See \
                 core/device/src/windows.rs."
            ),
            path,
            "",
            Kind::Device,
        );
    }

    let p = Path::new(path);
    if !is_absolute_windows(p) {
        return deny(
            DENY_RELATIVE,
            format!(
                "{path:?} is not absolute. A POSIX-style path such as \"/tmp/x\" has a \
                 root but no drive and is relative on this platform; name a drive or a \
                 UNC share."
            ),
            path,
            "",
            Kind::File,
        );
    }

    match p.file_name().map(|s| s.to_string_lossy().to_string()) {
        Some(leaf) => {
            if is_reserved_leaf(&leaf) {
                return deny(
                    DENY_SYNTHETIC,
                    format!(
                        "leaf {leaf:?} is a reserved DOS device name; it resolves to a \
                         device in every directory and at any extension"
                    ),
                    path,
                    "",
                    Kind::Device,
                );
            }
            if leaf.is_empty() || leaf == "." || leaf == ".." {
                return deny(
                    DENY_BAD_LEAF,
                    format!("leaf {leaf:?} does not name a file"),
                    path,
                    "",
                    Kind::File,
                );
            }
        }
        None => {
            return deny(
                DENY_BAD_LEAF,
                format!("{path:?} has no leaf component"),
                path,
                "",
                Kind::File,
            )
        }
    }

    let resolved = realpath(path);

    let root = match matching_root(policy, &resolved) {
        Some(r) => r.clone(),
        None => {
            return deny(
                DENY_NOT_ALLOWLISTED,
                format!(
                    "{resolved:?} is not inside any allowed root {:?}",
                    policy.root_reals
                ),
                path,
                &resolved,
                Kind::File,
            )
        }
    };

    if let Some(link) = reparse_component(&root, &resolved) {
        return deny(
            DENY_SYMLINK_AT_OPEN,
            format!(
                "{link:?} on the path from the allowed root is a symlink or junction; a \
                 reparse point can redirect outside the root after this check"
            ),
            path,
            &resolved,
            Kind::File,
        );
    }

    let md = std::fs::symlink_metadata(Path::new(&resolved));

    if norm == "x" {
        if md.is_ok() {
            return deny(
                DENY_EXISTS,
                format!("{resolved:?} already exists and mode \"x\" requires it not to"),
                path,
                &resolved,
                Kind::File,
            );
        }
        return match Path::new(&resolved).parent() {
            Some(q) if q.is_dir() => confirm_then(
                policy,
                confirmation,
                path,
                &resolved,
                ALLOW_CREATE,
                format!("create under {root:?}. {TOCTOU_NOTE}"),
            ),
            _ => deny(
                DENY_PARENT_MISSING,
                format!("the parent directory of {resolved:?} does not exist"),
                path,
                &resolved,
                Kind::File,
            ),
        };
    }

    let md = match md {
        Ok(m) => m,
        Err(e) => {
            if norm == "w" {
                return match Path::new(&resolved).parent() {
                    Some(q) if q.is_dir() => confirm_then(
                        policy,
                        confirmation,
                        path,
                        &resolved,
                        ALLOW_CREATE,
                        format!("create under {root:?}. {TOCTOU_NOTE}"),
                    ),
                    _ => deny(
                        DENY_PARENT_MISSING,
                        format!("the parent directory of {resolved:?} does not exist"),
                        path,
                        &resolved,
                        Kind::File,
                    ),
                };
            }
            return deny(
                DENY_MISSING,
                format!("{resolved:?} could not be examined: {e}"),
                path,
                &resolved,
                Kind::File,
            );
        }
    };

    if md.file_type().is_symlink() {
        return deny(
            DENY_SYMLINK_AT_OPEN,
            format!("{resolved:?} is itself a reparse point"),
            path,
            &resolved,
            Kind::File,
        );
    }
    if !md.is_file() {
        return deny(
            DENY_NOT_REGULAR,
            format!("{resolved:?} is not a regular file"),
            path,
            &resolved,
            Kind::File,
        );
    }

    let len = md.len();
    if len < policy.spec.min_file_bytes || len > policy.spec.max_file_bytes {
        return deny(
            DENY_SIZE,
            format!(
                "{resolved:?} is {len} bytes, outside the allowed [{}, {}]",
                policy.spec.min_file_bytes, policy.spec.max_file_bytes
            ),
            path,
            &resolved,
            Kind::File,
        );
    }

    confirm_then(
        policy,
        confirmation,
        path,
        &resolved,
        ALLOW_FILE,
        format!("regular file of {len} bytes under {root:?}. {TOCTOU_NOTE}"),
    )
}

fn confirm_then(
    policy: &Policy,
    confirmation: Option<&str>,
    path: &str,
    resolved: &str,
    code: &'static str,
    detail: String,
) -> Decision {
    if !policy.spec.require_confirmation {
        return allow(code, detail, path, resolved);
    }
    match confirmation {
        None => deny(
            DENY_CONFIRMATION_ABSENT,
            format!(
                "this policy requires a typed confirmation and none was given. It must \
                 byte-equal the guard's own resolution of the target: {resolved:?}"
            ),
            path,
            resolved,
            Kind::File,
        ),
        Some(c) if c == resolved => allow(code, detail, path, resolved),
        Some(c) => deny(
            DENY_CONFIRMATION,
            format!(
                "confirmation {c:?} does not byte-equal the guard's resolution of the \
                 target {resolved:?}"
            ),
            path,
            resolved,
            Kind::File,
        ),
    }
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

    let mut opts = OpenOptions::new();
    match norm {
        "r" => opts.read(true),
        "r+" => opts.read(true).write(true),
        "w" => opts.read(true).write(true).create(true).truncate(true),
        "x" => opts.read(true).write(true).create_new(true),
        _ => unreachable!("normalize_mode returned an unknown mode"),
    };

    let file = opts.open(&d.resolved).map_err(GuardError::Io)?;

    let md = file.metadata().map_err(GuardError::Io)?;
    if !md.is_file() {
        return Err(GuardError::Refused(deny(
            DENY_RACE,
            format!(
                "{:?} was a regular file when it was authorised and is not one on the \
                 handle that was opened",
                d.resolved
            ),
            path,
            &d.resolved,
            Kind::File,
        )));
    }
    if md.file_type().is_symlink() {
        return Err(GuardError::Refused(deny(
            DENY_SYMLINK_AT_OPEN,
            format!(
                "{:?} became a reparse point between the check and the open",
                d.resolved
            ),
            path,
            &d.resolved,
            Kind::File,
        )));
    }
    let again = realpath(&d.resolved);
    if matching_root(policy, &again).is_none() {
        return Err(GuardError::Refused(deny(
            DENY_RACE,
            format!(
                "{again:?} is no longer inside any allowed root {:?}; the path moved \
                 between the decision and the open",
                policy.root_reals
            ),
            path,
            &again,
            Kind::File,
        )));
    }
    Ok(file)
}

pub fn root_backing_device() -> Option<String> {
    None
}

pub fn whole_disk(dev_name: &str) -> String {
    dev_name.to_string()
}

pub fn contained_by_inode(_resolved: &str, _root_ids: &[(u64, u64)]) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let root = match std::env::var_os("SENTINELWIPE_SCRATCH") {
            Some(v) => PathBuf::from(v),
            None => std::env::temp_dir().join("sentinelwipe-guard-win"),
        };
        let dir = root.join(format!("{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn policy_over(dir: &Path) -> Policy {
        Policy::build(PolicySpec::with_roots([dir.to_str().unwrap()]))
            .expect("policy over an existing scratch directory")
    }

    #[test]
    fn every_published_code_is_distinct() {
        let mut seen = ALL_CODES.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), ALL_CODES.len(), "a code string is duplicated");
    }

    #[test]
    fn a_posix_absolute_path_is_relative_here_and_is_refused() {
        let dir = scratch("posix-path");
        let p = policy_over(&dir);
        let d = authorize(&p, "/private/tmp/x.img", None, "r+", &Env::Process, None);
        assert!(!d.allowed);
        assert_eq!(d.code, DENY_RELATIVE);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_inside_the_root_is_allowed_and_one_outside_is_not() {
        let dir = scratch("inside-outside");
        let inside = dir.join("image.img");
        std::fs::write(&inside, vec![0u8; 4096]).unwrap();
        let p = policy_over(&dir);

        let d = authorize(&p, inside.to_str().unwrap(), None, "r+", &Env::Process, None);
        assert!(d.allowed, "{d:?}");
        assert_eq!(d.code, ALLOW_FILE);
        assert!(
            d.detail.contains("openat"),
            "every allow must publish its own limit"
        );

        let other = scratch("inside-outside-other");
        let outside = other.join("image.img");
        std::fs::write(&outside, vec![0u8; 4096]).unwrap();
        let d2 = authorize(&p, outside.to_str().unwrap(), None, "r+", &Env::Process, None);
        assert!(!d2.allowed);
        assert_eq!(d2.code, DENY_NOT_ALLOWLISTED);

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&other).ok();
    }

    #[test]
    fn a_sibling_that_merely_shares_a_prefix_is_not_inside() {
        assert!(contained_by_components(r"C:\out\a.img", r"C:\out"));
        assert!(!contained_by_components(r"C:\out2\a.img", r"C:\out"));
        assert!(
            !contained_by_components(r"C:\out", r"C:\out"),
            "a root does not contain itself"
        );
        assert!(
            contained_by_components(r"c:\OUT\A.IMG", r"C:\out"),
            "matching is case-insensitive"
        );
    }

    #[test]
    fn reserved_dos_names_are_devices_in_any_directory() {
        assert!(is_reserved_leaf("NUL"));
        assert!(is_reserved_leaf("nul.img"));
        assert!(is_reserved_leaf("COM1.txt"));
        assert!(!is_reserved_leaf("NULL.img"));
        assert!(!is_reserved_leaf("fixture.img"));
    }

    #[test]
    fn the_device_namespace_is_refused_whatever_the_policy_says() {
        let dir = scratch("device-ns");
        let p = policy_over(&dir);
        for target in [r"\\.\PhysicalDrive0", r"\\?\C:\out\x.img", r"\??\C:\x"] {
            let d = authorize(&p, target, None, "r+", &Env::Process, None);
            assert!(!d.allowed, "{target} was allowed");
            assert_eq!(d.code, DENY_DEVICE_PLATFORM, "{target}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_policy_that_arms_devices_is_refused_at_construction() {
        let dir = scratch("arm-devices");
        let err = Policy::build(PolicySpec {
            roots: vec![dir.to_str().unwrap().to_string()],
            allow_device_targets: true,
            ..PolicySpec::default()
        })
        .unwrap_err();
        assert!(err.0.contains("device targets are not supported"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_shallow_or_system_root_is_refused() {
        let shallow = Policy::build(PolicySpec::with_roots([r"C:\"]));
        assert!(shallow.is_err(), "a drive root must never be a write root");
        let users = Policy::build(PolicySpec::with_roots([r"C:\Users"]));
        assert!(users.is_err(), "C:\\Users must never be a write root");
    }

    #[test]
    fn confirmation_is_checked_after_containment_and_never_instead_of_it() {
        let dir = scratch("confirm");
        let inside = dir.join("image.img");
        std::fs::write(&inside, vec![0u8; 4096]).unwrap();
        let p = Policy::build(PolicySpec {
            roots: vec![dir.to_str().unwrap().to_string()],
            require_confirmation: true,
            ..PolicySpec::default()
        })
        .unwrap();

        let absent = authorize(&p, inside.to_str().unwrap(), None, "r+", &Env::Process, None);
        assert_eq!(absent.code, DENY_CONFIRMATION_ABSENT);

        let wrong = authorize(
            &p,
            inside.to_str().unwrap(),
            Some("nope"),
            "r+",
            &Env::Process,
            None,
        );
        assert_eq!(wrong.code, DENY_CONFIRMATION);

        let right = authorize(
            &p,
            inside.to_str().unwrap(),
            Some(&realpath(inside.to_str().unwrap())),
            "r+",
            &Env::Process,
            None,
        );
        assert!(right.allowed, "{right:?}");

        let other = scratch("confirm-other");
        let outside = other.join("image.img");
        std::fs::write(&outside, vec![0u8; 4096]).unwrap();
        let d = authorize(
            &p,
            outside.to_str().unwrap(),
            Some(&realpath(outside.to_str().unwrap())),
            "r+",
            &Env::Process,
            None,
        );
        assert_eq!(
            d.code, DENY_NOT_ALLOWLISTED,
            "confirmation must grant nothing on its own"
        );

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&other).ok();
    }

    #[test]
    fn open_authorized_writes_only_inside_the_root() {
        use std::io::{Read, Seek, SeekFrom, Write};
        let dir = scratch("open-auth");
        let inside = dir.join("image.img");
        std::fs::write(&inside, vec![0u8; 4096]).unwrap();
        let p = policy_over(&dir);

        let mut f = open_authorized(&p, inside.to_str().unwrap(), "r+", None, &Env::Process).unwrap();
        f.write_all(&[0x5A; 512]).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut back = [0u8; 512];
        f.read_exact(&mut back).unwrap();
        assert!(back.iter().all(|b| *b == 0x5A));
        drop(f);

        let other = scratch("open-auth-other");
        let outside = other.join("image.img");
        std::fs::write(&outside, vec![0u8; 4096]).unwrap();
        let err =
            open_authorized(&p, outside.to_str().unwrap(), "r+", None, &Env::Process).unwrap_err();
        match err {
            GuardError::Refused(d) => assert_eq!(d.code, DENY_NOT_ALLOWLISTED),
            GuardError::Io(e) => panic!("expected a refusal, got io {e}"),
        }
        assert!(std::fs::read(&outside).unwrap().iter().all(|b| *b == 0));

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&other).ok();
    }

    #[test]
    fn a_missing_target_creates_in_write_mode_and_refuses_in_update_mode() {
        let dir = scratch("create-vs-update");
        let p = policy_over(&dir);
        let absent = dir.join("not-yet.img");

        let d = authorize(&p, absent.to_str().unwrap(), None, "w", &Env::Process, None);
        assert!(d.allowed, "{d:?}");
        assert_eq!(d.code, ALLOW_CREATE);

        let d2 = authorize(&p, absent.to_str().unwrap(), None, "r+", &Env::Process, None);
        assert!(!d2.allowed);
        assert_eq!(d2.code, DENY_MISSING);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let dir = scratch("not-regular");
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let p = policy_over(&dir);
        let d = authorize(&p, sub.to_str().unwrap(), None, "r+", &Env::Process, None);
        assert_eq!(d.code, DENY_NOT_REGULAR);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn size_bounds_are_enforced_on_the_resolved_file() {
        let dir = scratch("size-bounds");
        let f = dir.join("big.img");
        std::fs::write(&f, vec![0u8; 4096]).unwrap();
        let p = Policy::build(PolicySpec {
            roots: vec![dir.to_str().unwrap().to_string()],
            max_file_bytes: 1024,
            ..PolicySpec::default()
        })
        .unwrap();
        let d = authorize(&p, f.to_str().unwrap(), None, "r+", &Env::Process, None);
        assert_eq!(d.code, DENY_SIZE);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_digest_payload_is_stable_and_sorted() {
        let dir = scratch("digest");
        let p = policy_over(&dir);
        let a = p.digest_payload();
        let b = p.digest_payload();
        assert_eq!(a, b, "the payload must not depend on iteration order");
        assert!(a.starts_with("{\"allow_device_targets\":false,\"devices\":[],"));
        assert!(a.contains("\"require_confirmation\":false"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_or_nul_target_is_refused_before_anything_touches_the_disk() {
        let dir = scratch("empty-nul");
        let p = policy_over(&dir);
        assert_eq!(
            authorize(&p, "", None, "r+", &Env::Process, None).code,
            DENY_EMPTY
        );
        assert_eq!(
            authorize(&p, "C:\\out\\a\0b.img", None, "r+", &Env::Process, None).code,
            DENY_NUL
        );
        assert_eq!(
            authorize(&p, "C:\\out\\a.img", None, "nonsense", &Env::Process, None).code,
            DENY_MODE
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
