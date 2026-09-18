from __future__ import annotations

import hashlib
import json
import os
import stat as statmod
from dataclasses import asdict, dataclass, field
from typing import Optional, Sequence, Tuple

BACKEND = "windows"

ALLOW_FILE = "ALLOW_FILE"
ALLOW_CREATE = "ALLOW_CREATE"
ALLOW_DEVICE = "ALLOW_DEVICE"

DENY_EMPTY = "DENY_EMPTY_TARGET"
DENY_NUL = "DENY_NUL_IN_PATH"
DENY_RELATIVE = "DENY_RELATIVE_PATH"
DENY_SYNTHETIC = "DENY_SYNTHETIC_NAMESPACE_PATH"
DENY_MODE = "DENY_UNSUPPORTED_MODE"
DENY_MISSING = "DENY_TARGET_MISSING"
DENY_EXISTS = "DENY_TARGET_ALREADY_EXISTS"
DENY_NOT_REGULAR = "DENY_NOT_A_REGULAR_FILE"
DENY_HARDLINK = "DENY_MULTIPLE_HARDLINKS"
DENY_SIZE = "DENY_SIZE_OUT_OF_BOUNDS"
DENY_NOT_ALLOWLISTED = "DENY_NOT_ALLOWLISTED"
DENY_CROSSED_MOUNT = "DENY_CROSSED_MOUNT_POINT"
DENY_BAD_LEAF = "DENY_INVALID_LEAF_NAME"
DENY_PARENT_MISSING = "DENY_PARENT_DIRECTORY_MISSING"
DENY_CONFIRMATION = "DENY_CONFIRMATION_MISMATCH"
DENY_CONFIRMATION_ABSENT = "DENY_CONFIRMATION_ABSENT"

DENY_DEVICE_MODE_OFF = "DENY_DEVICE_MODE_NOT_ENABLED"
DENY_DEVICE_ENV_OFF = "DENY_DEVICE_ENV_NOT_SET"
DENY_DEVICE_NOT_ALLOWLISTED = "DENY_DEVICE_NOT_ALLOWLISTED"
DENY_DEVICE_ALIAS = "DENY_DEVICE_NAME_IS_AN_ALIAS"
DENY_DEVICE_NOT_A_DEVICE = "DENY_NOT_A_DEVICE_NODE"
DENY_DEVICE_IS_SYSTEM = "DENY_DEVICE_BACKS_RUNNING_SYSTEM"
DENY_DEVICE_PLATFORM = "DENY_DEVICE_TARGETS_UNSUPPORTED_ON_THIS_PLATFORM"

DENY_RACE = "DENY_RACE_DETECTED_AT_OPEN"
DENY_SYMLINK_AT_OPEN = "DENY_SYMLINK_COMPONENT_AT_OPEN"

ALL_CODES = (
    ALLOW_FILE, ALLOW_CREATE, ALLOW_DEVICE,
    DENY_EMPTY, DENY_NUL, DENY_RELATIVE, DENY_SYNTHETIC, DENY_MODE, DENY_MISSING,
    DENY_EXISTS, DENY_NOT_REGULAR, DENY_HARDLINK, DENY_SIZE, DENY_NOT_ALLOWLISTED,
    DENY_CROSSED_MOUNT, DENY_BAD_LEAF, DENY_PARENT_MISSING, DENY_CONFIRMATION,
    DENY_CONFIRMATION_ABSENT, DENY_DEVICE_MODE_OFF, DENY_DEVICE_ENV_OFF,
    DENY_DEVICE_NOT_ALLOWLISTED, DENY_DEVICE_ALIAS, DENY_DEVICE_NOT_A_DEVICE,
    DENY_DEVICE_IS_SYSTEM, DENY_DEVICE_PLATFORM, DENY_RACE, DENY_SYMLINK_AT_OPEN,
)

DEVICE_MODE_ENV = "SENTINELWIPE_DEVICE_MODE"

MIN_ROOT_DEPTH = 2

DEFAULT_MAX_FILE_BYTES = 8 * (1 << 30)

FORBIDDEN_TOP = frozenset([
    "WINDOWS",
    "PROGRAM FILES",
    "PROGRAM FILES (X86)",
    "PROGRAMDATA",
    "USERS",
    "$RECYCLE.BIN",
    "SYSTEM VOLUME INFORMATION",
    "RECOVERY",
    "PERFLOGS",
])

FORBIDDEN_UNDER = FORBIDDEN_TOP - {"USERS"}

RESERVED_LEAFS = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + ["COM%d" % i for i in range(1, 10)]
    + ["LPT%d" % i for i in range(1, 10)]
)

MODES = ("r", "r+", "w", "x")

_MODE_ALIASES = {
    "r": "r", "rb": "r",
    "r+": "r+", "rb+": "r+", "r+b": "r+", "+r": "r+",
    "w": "w", "wb": "w", "w+": "w", "wb+": "w", "w+b": "w",
    "x": "x", "xb": "x", "x+": "x", "xb+": "x", "x+b": "x",
}

TOCTOU_NOTE = (
    "windows backend: containment was checked on the resolved path and re-checked "
    "on the open descriptor, not held across the open. Unlike the posix backend "
    "there is no openat(O_NOFOLLOW) descent, so a directory on this path that an "
    "attacker can write to is a race this guard does not close"
)


class GuardError(Exception):
    def __init__(self, decision: "Decision"):
        super().__init__(f"{decision.code}: {decision.detail}")
        self.decision = decision


class PolicyError(Exception):
    pass


def native_platform() -> str:
    return "windows"


def _norm_mode(mode: str) -> Optional[str]:
    return _MODE_ALIASES.get(mode)


def _ids(path: str) -> Optional[Tuple[int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def contained_by_inode(resolved: str, root_ids: Sequence[Tuple[int, int]]
                       ) -> Optional[Tuple[int, int]]:
    if not root_ids:
        return None
    wanted = set(root_ids)
    cur = os.path.dirname(os.path.abspath(resolved))
    seen = set()
    while True:
        if cur in seen:
            return None
        seen.add(cur)
        got = _ids(cur)
        if got is not None and got in wanted:
            return got
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def _is_reparse(path: str) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if statmod.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & getattr(statmod, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _reparse_on_path(root_real: str, resolved: str) -> Optional[str]:
    try:
        rest = os.path.relpath(resolved, root_real)
    except ValueError:
        return None
    if rest.startswith(".."):
        return None
    cur = root_real
    for part in rest.split(os.sep):
        if not part or part == ".":
            continue
        cur = os.path.join(cur, part)
        if _is_reparse(cur):
            return cur
    return None


def _is_absolute_windows(path: str) -> bool:
    drive, rest = os.path.splitdrive(path)
    if not drive:
        return False
    return rest.startswith("\\") or rest.startswith("/")


def _body_components(real: str) -> list:
    _drive, rest = os.path.splitdrive(real)
    return [p for p in rest.replace("/", "\\").split("\\") if p]


def realpath(path: str) -> str:
    if not _is_absolute_windows(path):
        return path
    try:
        return os.path.realpath(path)
    except OSError:
        return os.path.normpath(path)


def _is_synthetic_namespace(path: str) -> bool:
    p = path.replace("/", "\\")
    return p.startswith("\\\\.\\") or p.startswith("\\\\?\\") or p.startswith("\\??\\")


def _is_reserved_leaf(name: str) -> bool:
    return name.split(".")[0].upper() in RESERVED_LEAFS


@dataclass(frozen=True)
class Policy:
    roots: Tuple[str, ...]
    devices: Tuple[str, ...] = ()
    allow_device_targets: bool = False
    require_confirmation: bool = False
    min_file_bytes: int = 0
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    root_ids: Tuple[Tuple[int, int], ...] = field(default=(), repr=False, compare=False)
    root_reals: Tuple[str, ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        if isinstance(self.roots, str):
            raise PolicyError("roots must be a sequence of paths, not a single string")
        object.__setattr__(self, "roots", tuple(self.roots))
        object.__setattr__(self, "devices", tuple(self.devices))

        if self.allow_device_targets or self.devices:
            raise PolicyError(
                "device targets are not supported on windows: this build has no "
                "Windows block-device layer, so a policy that armed one would "
                "authorise an operation nothing can carry out. Remove "
                "allow_device_targets and devices, or run the device path on Linux."
            )
        if self.min_file_bytes > self.max_file_bytes:
            raise PolicyError(
                f"min_file_bytes {self.min_file_bytes} exceeds max_file_bytes "
                f"{self.max_file_bytes}"
            )
        if not self.roots:
            raise PolicyError(
                "no write roots: a policy with no root allows nothing and is refused "
                "at construction rather than silently denying every target later"
            )

        ids = []
        reals = []
        profile = os.environ.get("USERPROFILE", "")
        profile_real = os.path.realpath(profile).upper() if profile else None
        for r in self.roots:
            if not r:
                raise PolicyError("empty write root")
            if not _is_absolute_windows(r):
                raise PolicyError(
                    f"write root {r!r} is relative; a root is resolved against nothing "
                    f"and must name a drive or a UNC share"
                )
            if not os.path.isdir(r):
                raise PolicyError(
                    f"write root {r!r} is not an existing directory. The root must "
                    f"exist before the policy is built: creating it here would make "
                    f"the guard the thing that widened its own allowlist."
                )
            real = os.path.realpath(r)
            comps = [c.upper() for c in _body_components(real)]
            depth = len(comps)
            if depth < MIN_ROOT_DEPTH:
                raise PolicyError(f"root is too shallow ({depth} components): {real!r}")
            if depth == 1 and comps[0] in FORBIDDEN_TOP:
                raise PolicyError(
                    f"refusing system directory as a write root: {r!r} -> {real!r}"
                )
            if depth > 1 and comps[0] in FORBIDDEN_UNDER:
                raise PolicyError(
                    f"refusing write root {real!r}: it lies under the system "
                    f"directory {comps[0]}"
                )
            upper = real.upper()
            if profile_real is not None and upper == profile_real:
                raise PolicyError(
                    f"refusing the user profile directory as a write root: {real!r}"
                )
            got = _ids(real)
            if got is None:
                raise PolicyError(f"write root {real!r} could not be stat'd")
            ids.append(got)
            reals.append(real)
        object.__setattr__(self, "root_ids", tuple(ids))
        object.__setattr__(self, "root_reals", tuple(reals))

    def digest(self) -> str:
        payload = json.dumps(
            {
                "roots": sorted(os.path.realpath(r) for r in self.roots),
                "devices": list(self.devices),
                "allow_device_targets": self.allow_device_targets,
                "require_confirmation": self.require_confirmation,
                "min_file_bytes": self.min_file_bytes,
                "max_file_bytes": self.max_file_bytes,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    resolved: str
    detail: str = ""
    target: str = ""
    st_dev: Optional[int] = None
    st_ino: Optional[int] = None
    kind: str = "file"
    policy_digest: str = ""

    def as_record(self) -> dict:
        return asdict(self)


def _deny(code: str, detail: str, target: str, policy: Policy, *,
          kind: str = "file", resolved: str = "") -> Decision:
    return Decision(False, code, resolved, detail, target, None, None, kind,
                    policy.digest())


def _allow(code: str, detail: str, target: str, resolved: str, policy: Policy,
           ids: Optional[Tuple[int, int]]) -> Decision:
    return Decision(True, code, resolved, detail, target,
                    ids[0] if ids else None, ids[1] if ids else None,
                    "file", policy.digest())


def authorize(policy: Policy, path: str, confirmation: Optional[str] = None,
              *, mode: str = "r+", env: Optional[dict] = None,
              _platform: Optional[str] = None) -> Decision:
    del env

    if _platform is not None and _platform != native_platform():
        return _deny(
            DENY_DEVICE_PLATFORM,
            f"this backend answers for {native_platform()!r} only; a decision was "
            f"requested for {_platform!r} and is refused rather than guessed",
            path, policy)

    norm = _norm_mode(mode)
    if norm is None:
        return _deny(DENY_MODE, f"mode {mode!r} is not one of {list(MODES)!r}",
                     path, policy)

    if not path:
        return _deny(DENY_EMPTY, "empty target", path, policy)
    if "\0" in path:
        return _deny(DENY_NUL, "NUL byte in path", path, policy)
    if _is_synthetic_namespace(path):
        return _deny(
            DENY_DEVICE_PLATFORM,
            f"{path!r} names the Windows device or verbatim namespace. This build "
            f"has no Windows block-device layer, so there is nothing here to "
            f"authorise; the device path is Linux-gated and never demoed.",
            path, policy, kind="device")
    if not _is_absolute_windows(path):
        return _deny(
            DENY_RELATIVE,
            f"{path!r} is not absolute. A POSIX-style path such as '/tmp/x' has a "
            f"root but no drive and is relative on this platform; name a drive or a "
            f"UNC share.",
            path, policy)

    leaf = os.path.basename(path.replace("/", "\\").rstrip("\\"))
    if not leaf or leaf in (".", ".."):
        return _deny(DENY_BAD_LEAF, f"leaf {leaf!r} does not name a file", path, policy)
    if _is_reserved_leaf(leaf):
        return _deny(
            DENY_SYNTHETIC,
            f"leaf {leaf!r} is a reserved DOS device name; it resolves to a device "
            f"in every directory and at any extension",
            path, policy, kind="device")

    resolved = realpath(path)

    if contained_by_inode(resolved, policy.root_ids) is None:
        return _deny(
            DENY_NOT_ALLOWLISTED,
            f"{resolved!r} is not inside any allowed root {list(policy.root_reals)!r}",
            path, policy, resolved=resolved)

    root_real = None
    for cand in policy.root_reals:
        try:
            rel = os.path.relpath(resolved, cand)
        except ValueError:
            continue
        if not rel.startswith(".."):
            root_real = cand
            break
    if root_real is None:
        return _deny(
            DENY_NOT_ALLOWLISTED,
            f"{resolved!r} passed the identity walk but names no allowed root by "
            f"path; the two checks must agree and they do not",
            path, policy, resolved=resolved)

    link = _reparse_on_path(root_real, resolved)
    if link is not None:
        return _deny(
            DENY_SYMLINK_AT_OPEN,
            f"{link!r} on the path from the allowed root is a symlink or junction; a "
            f"reparse point can redirect outside the root after this check",
            path, policy, resolved=resolved)

    exists = os.path.lexists(resolved)

    if norm == "x":
        if exists:
            return _deny(DENY_EXISTS,
                         f"{resolved!r} already exists and mode 'x' requires it not to",
                         path, policy, resolved=resolved)
        return _confirm_then(policy, confirmation, path, resolved, ALLOW_CREATE,
                             f"create under {root_real!r}. {TOCTOU_NOTE}", None)

    if not exists:
        if norm == "w":
            parent = os.path.dirname(resolved)
            if not os.path.isdir(parent):
                return _deny(DENY_PARENT_MISSING,
                             f"the parent directory of {resolved!r} does not exist",
                             path, policy, resolved=resolved)
            return _confirm_then(policy, confirmation, path, resolved, ALLOW_CREATE,
                                 f"create under {root_real!r}. {TOCTOU_NOTE}", None)
        return _deny(DENY_MISSING, f"{resolved!r} does not exist",
                     path, policy, resolved=resolved)

    if _is_reparse(resolved):
        return _deny(DENY_SYMLINK_AT_OPEN, f"{resolved!r} is itself a reparse point",
                     path, policy, resolved=resolved)

    try:
        st = os.stat(resolved)
    except OSError as e:
        return _deny(DENY_MISSING, f"{resolved!r} could not be examined: {e}",
                     path, policy, resolved=resolved)

    if not statmod.S_ISREG(st.st_mode):
        return _deny(DENY_NOT_REGULAR, f"{resolved!r} is not a regular file",
                     path, policy, resolved=resolved)

    if st.st_size < policy.min_file_bytes or st.st_size > policy.max_file_bytes:
        return _deny(
            DENY_SIZE,
            f"{resolved!r} is {st.st_size} bytes, outside the allowed "
            f"[{policy.min_file_bytes}, {policy.max_file_bytes}]",
            path, policy, resolved=resolved)

    return _confirm_then(
        policy, confirmation, path, resolved, ALLOW_FILE,
        f"regular file of {st.st_size} bytes under {root_real!r}. {TOCTOU_NOTE}",
        (st.st_dev, st.st_ino))


def _confirm_then(policy: Policy, confirmation: Optional[str], path: str,
                  resolved: str, code: str, detail: str,
                  ids: Optional[Tuple[int, int]]) -> Decision:
    if not policy.require_confirmation:
        return _allow(code, detail, path, resolved, policy, ids)
    if confirmation is None:
        return _deny(
            DENY_CONFIRMATION_ABSENT,
            f"this policy requires a typed confirmation and none was given. It must "
            f"byte-equal the guard's own resolution of the target: {resolved!r}",
            path, policy, resolved=resolved)
    if confirmation != resolved:
        return _deny(
            DENY_CONFIRMATION,
            f"confirmation {confirmation!r} does not byte-equal the guard's "
            f"resolution of the target {resolved!r}",
            path, policy, resolved=resolved)
    return _allow(code, detail, path, resolved, policy, ids)


def open_authorized(policy: Policy, path: str, mode: str,
                    confirmation: Optional[str] = None,
                    *, env: Optional[dict] = None) -> int:
    d = authorize(policy, path, confirmation, mode=mode, env=env)
    if not d.allowed:
        raise GuardError(d)

    norm = _norm_mode(mode)
    flags = {
        "r": os.O_RDONLY,
        "r+": os.O_RDWR,
        "w": os.O_RDWR | os.O_CREAT,
        "x": os.O_RDWR | os.O_CREAT | os.O_EXCL,
    }[norm]
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)

    try:
        fd = os.open(d.resolved, flags, 0o600)
    except OSError as e:
        raise GuardError(_deny(DENY_RACE,
                               f"{d.resolved!r} was authorised and could not be "
                               f"opened: {e}",
                               path, policy, resolved=d.resolved)) from e

    try:
        st = os.fstat(fd)
        if not statmod.S_ISREG(st.st_mode):
            raise GuardError(_deny(
                DENY_RACE,
                f"{d.resolved!r} was a regular file when it was authorised and is "
                f"not one on the descriptor that was opened",
                path, policy, resolved=d.resolved))
        if d.st_ino is not None and (st.st_dev, st.st_ino) != (d.st_dev, d.st_ino):
            raise GuardError(_deny(
                DENY_RACE,
                f"{d.resolved!r} is a different object on the descriptor "
                f"({st.st_dev}, {st.st_ino}) than the one authorised "
                f"({d.st_dev}, {d.st_ino}); it was replaced between the check and "
                f"the open",
                path, policy, resolved=d.resolved))
        if contained_by_inode(d.resolved, policy.root_ids) is None:
            raise GuardError(_deny(
                DENY_RACE,
                f"{d.resolved!r} is no longer inside any allowed root; the path "
                f"moved between the decision and the open",
                path, policy, resolved=d.resolved))
    except GuardError:
        os.close(fd)
        raise
    except OSError as e:
        os.close(fd)
        raise GuardError(_deny(DENY_RACE,
                               f"{d.resolved!r} could not be re-checked on the "
                               f"descriptor: {e}",
                               path, policy, resolved=d.resolved)) from e
    return fd


def root_backing_device() -> Optional[str]:
    return None


def _whole_disk(dev_name: str) -> str:
    return dev_name


def audit_append(log_path: str, decision: Decision, *, stamp: str = "") -> None:
    rec = decision.as_record()
    rec["stamp"] = stamp
    rec["backend"] = BACKEND
    line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
    with open(log_path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line)


def collect_confirmation(resolved: str, flag_value: Optional[str],
                         *, stdin_isatty: Optional[bool] = None) -> Optional[str]:
    if flag_value is not None:
        return flag_value
    import sys
    isatty = sys.stdin.isatty() if stdin_isatty is None else stdin_isatty
    if not isatty:
        return None
    sys.stderr.write(
        f"Type the target path exactly to confirm destruction:\n  {resolved}\n> ")
    sys.stderr.flush()
    try:
        return sys.stdin.readline().rstrip("\r\n")
    except (EOFError, KeyboardInterrupt):
        return None
