from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import stat as statmod
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional, Sequence, Tuple

__all__ = [
    "Policy",
    "Decision",
    "GuardError",
    "PolicyError",
    "authorize",
    "open_authorized",
    "contained_by_inode",
    "root_backing_device",
    "audit_append",
    "collect_confirmation",
    "MODES",
]

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

MODES = ("r", "r+", "w", "x")

_MODE_ALIASES = {
    "r": "r", "rb": "r",
    "r+": "r+", "rb+": "r+", "r+b": "r+", "+r": "r+",
    "w": "w", "wb": "w", "w+": "w", "wb+": "w", "w+b": "w",
    "x": "x", "xb": "x", "x+": "x", "xb+": "x", "x+b": "x",
}

MIN_ROOT_DEPTH = 2

FORBIDDEN_ROOTS = (
    "/", "/dev", "/.vol", "/System", "/System/Volumes/Data", "/Volumes", "/Library",
    "/Applications", "/bin", "/sbin", "/usr", "/etc", "/var", "/private",
    "/private/etc", "/private/var", "/private/var/db", "/private/tmp", "/tmp",
    "/Users", "/home", "/opt", "/net", "/cores", "/Network",
)


class GuardError(Exception):
    def __init__(self, decision: "Decision"):
        super().__init__(f"{decision.code}: {decision.detail}")
        self.decision = decision


class PolicyError(Exception):
    pass


def _ids(path: str) -> Optional[Tuple[int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def _forbidden_ids() -> dict:
    out: dict = {}
    for name in FORBIDDEN_ROOTS:
        for spelling in (name, os.path.realpath(name)):
            got = _ids(spelling)
            if got is not None:
                out.setdefault(got, spelling)
    return out


def _reachable_by_descent(policy, walk_from: str, resolved: str) -> bool:
    root_real = _matching_root_real(policy, walk_from)
    if root_real is None:
        return False
    parts = _rel_parts(resolved, root_real)
    return bool(parts)


def contained_by_inode(resolved: str, root_ids: Sequence[Tuple[int, int]]
                       ) -> Optional[Tuple[int, int]]:
    wanted = set(root_ids)
    if not wanted:
        return None
    cur = resolved
    steps = 0
    while True:
        got = _ids(cur)
        if got is not None and got in wanted:
            return got
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent
        steps += 1
        if steps > 256:
            return None


def root_backing_device() -> Optional[str]:
    try:
        rootdev = os.stat("/").st_dev
    except OSError:
        return None
    try:
        names = os.listdir("/dev")
    except OSError:
        return None
    for n in sorted(names):
        if not n.startswith("disk"):
            continue
        p = "/dev/" + n
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if statmod.S_ISBLK(st.st_mode) and st.st_rdev == rootdev:
            return p
    return None


def _whole_disk(dev_name: str) -> str:
    base = os.path.basename(dev_name)
    if base.startswith("r"):
        base = base[1:]
    out = []
    for ch in base:
        if ch == "s" and out and out[-1].isdigit():
            break
        out.append(ch)
    return "".join(out)


@dataclass(frozen=True)
class Policy:
    roots: Tuple[str, ...]
    devices: Tuple[str, ...] = ()
    allow_device_targets: bool = False
    require_confirmation: bool = False
    min_file_bytes: int = 0
    max_file_bytes: int = 8 * (1 << 30)
    root_ids: Tuple[Tuple[int, int], ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        if isinstance(self.roots, str):
            raise PolicyError("roots must be a sequence of paths, not a single string")
        object.__setattr__(self, "roots", tuple(self.roots))
        if isinstance(self.devices, str):
            raise PolicyError("devices must be a sequence of names, not a single string")
        object.__setattr__(self, "devices", tuple(self.devices))

        if not self.roots:
            raise PolicyError(
                "roots is empty; a guard with no allowed root is a bug, not a safe default")
        if self.min_file_bytes < 0 or self.max_file_bytes < self.min_file_bytes:
            raise PolicyError(
                f"nonsensical size bounds [{self.min_file_bytes}, {self.max_file_bytes}]")
        if self.allow_device_targets and not self.require_confirmation:
            raise PolicyError(
                "allow_device_targets=True requires require_confirmation=True; a device "
                "target is destructive by definition")

        forbidden = _forbidden_ids()
        home_real = os.path.realpath(os.path.expanduser("~"))
        home_ids = _ids(home_real)
        ids = []
        for r in self.roots:
            if not isinstance(r, str) or not r or "\x00" in r:
                raise PolicyError(f"invalid root {r!r}")
            if not os.path.isabs(r):
                raise PolicyError(f"root must be absolute: {r!r}")
            real = os.path.realpath(r)
            if not os.path.isdir(real):
                raise PolicyError(
                    f"root does not exist or is not a directory: {real!r} (create it "
                    f"before constructing the Policy; the guard never creates its own root)")
            got = _ids(real)
            if got is None:
                raise PolicyError(f"root vanished during validation: {real!r}")

            if got in forbidden:
                raise PolicyError(
                    f"refusing system directory as a write root: {r!r} -> {real!r} "
                    f"(matches {forbidden[got]})")
            for fname in forbidden.values():
                freal = os.path.realpath(fname)
                if contained_by_inode(freal, [got]) is not None:
                    raise PolicyError(
                        f"refusing write root {real!r}: it contains the system "
                        f"directory {freal!r}")
            depth = len([p for p in real.split("/") if p])
            if depth < MIN_ROOT_DEPTH:
                raise PolicyError(f"root is too shallow ({depth} components): {real!r}")
            if real == home_real or (home_ids is not None and got == home_ids):
                raise PolicyError(f"refusing $HOME as a write root: {real!r}")
            ids.append(got)
        object.__setattr__(self, "root_ids", tuple(ids))

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


def authorize(policy: Policy, path: str, confirmation: Optional[str] = None,
              *, mode: str = "r+", env: Optional[dict] = None,
              _platform: Optional[str] = None) -> Decision:
    try:
        return _authorize(policy, path, confirmation, mode=mode, env=env,
                          _platform=_platform)
    except OSError as e:
        return _deny(DENY_RACE,
                     f"path resolution failed while the filesystem changed "
                     f"underneath it: {e.strerror}",
                     path if isinstance(path, str) else str(path), policy)


def _authorize(policy: Policy, path: str, confirmation: Optional[str] = None,
               *, mode: str = "r+", env: Optional[dict] = None,
               _platform: Optional[str] = None) -> Decision:
    env = os.environ if env is None else env
    plat = sys.platform if _platform is None else _platform
    pdig = policy.digest()

    norm = _MODE_ALIASES.get(mode) if isinstance(mode, str) else None
    if norm is None:
        return _deny(DENY_MODE, f"mode {mode!r} is not one of {MODES}",
                     path if isinstance(path, str) else str(path), policy)

    if not isinstance(path, str) or path == "":
        return _deny(DENY_EMPTY, "target is empty", str(path), policy)
    if "\x00" in path:
        return _deny(DENY_NUL, "target contains NUL",
                     path.replace("\x00", "?"), policy)
    if not os.path.isabs(path):
        return _deny(DENY_RELATIVE,
                     "target must be an absolute path; the working directory is "
                     "attacker-influenced", path, policy)

    resolved = os.path.realpath(path)

    if sys.platform == "darwin" and (resolved == "/.vol"
                                     or resolved.startswith("/.vol/")):
        return _deny(DENY_SYNTHETIC,
                     f"{resolved}: /.vol addresses files by inode number and is "
                     f"refused whole. A fixture is named by its path, and the "
                     f"operator must be able to read the target being confirmed.",
                     path, policy, resolved=resolved)

    try:
        st = os.stat(resolved)
    except OSError as e:
        if norm in ("w", "x") and e.errno == errno.ENOENT:
            return _authorize_create(policy, path, resolved, confirmation, pdig)
        return _deny(DENY_MISSING, f"cannot stat {resolved}: {e.strerror}",
                     path, policy, resolved=resolved)

    if statmod.S_ISBLK(st.st_mode) or statmod.S_ISCHR(st.st_mode):
        return _authorize_device(policy, path, resolved, st, confirmation, env, pdig,
                                 plat)

    if norm == "x":
        return _deny(DENY_EXISTS,
                     f"{resolved} already exists and mode 'x' refuses to replace it",
                     path, policy, resolved=resolved)

    matched = contained_by_inode(resolved, policy.root_ids)
    if matched is None:
        return _deny(DENY_NOT_ALLOWLISTED,
                     f"{resolved} is not inside any allowed root",
                     path, policy, resolved=resolved)

    if not statmod.S_ISREG(st.st_mode):
        return _deny(DENY_NOT_REGULAR,
                     f"{resolved} is not a regular file "
                     f"(mode {statmod.filemode(st.st_mode)})",
                     path, policy, resolved=resolved)

    if not _reachable_by_descent(policy, resolved, resolved):
        return _deny(DENY_NOT_ALLOWLISTED,
                     f"{resolved} is inside an allowed root by inode but is not "
                     f"reachable from that root's own spelling by name; the open "
                     f"would refuse it",
                     path, policy, resolved=resolved)

    if st.st_nlink != 1:
        return _deny(DENY_HARDLINK,
                     f"{resolved} has {st.st_nlink} links; a hardlink can place an "
                     f"inode from outside the allowed root inside it",
                     path, policy, resolved=resolved)

    if norm in ("r", "r+") and not (
            policy.min_file_bytes <= st.st_size <= policy.max_file_bytes):
        return _deny(DENY_SIZE,
                     f"{st.st_size} bytes is outside "
                     f"[{policy.min_file_bytes}, {policy.max_file_bytes}]",
                     path, policy, resolved=resolved)

    if st.st_dev != matched[0]:
        return _deny(DENY_CROSSED_MOUNT,
                     f"{resolved} is on device {st.st_dev} but its allowed root is on "
                     f"{matched[0]}; a filesystem was mounted inside the root",
                     path, policy, resolved=resolved)

    bad = _confirm(policy, path, resolved, confirmation)
    if bad is not None:
        return bad

    return Decision(True, ALLOW_FILE, resolved,
                    "regular file inside an allowed root", path,
                    st.st_dev, st.st_ino, "file", pdig)


def _confirm(policy: Policy, path: str, resolved: str,
             confirmation: Optional[str]) -> Optional[Decision]:
    if not policy.require_confirmation:
        return None
    if confirmation is None:
        return _deny(DENY_CONFIRMATION_ABSENT,
                     f"destructive operation needs --i-understand '{resolved}'",
                     path, policy, resolved=resolved)
    if not hmac.compare_digest(confirmation.encode("utf-8"), resolved.encode("utf-8")):
        return _deny(DENY_CONFIRMATION,
                     "typed confirmation does not name the resolved target",
                     path, policy, resolved=resolved)
    return None


def _authorize_create(policy: Policy, path: str, resolved: str,
                      confirmation: Optional[str], pdig: str) -> Decision:
    parent_arg = os.path.dirname(resolved)
    leaf = os.path.basename(resolved)
    if leaf in ("", ".", "..") or "/" in leaf:
        return _deny(DENY_BAD_LEAF,
                     f"{path!r} does not name a single file below a directory",
                     path, policy, resolved=resolved)

    parent = os.path.realpath(parent_arg)
    if not os.path.isdir(parent):
        return _deny(DENY_PARENT_MISSING,
                     f"parent directory {parent} does not exist; the guard creates "
                     f"no directories",
                     path, policy, resolved=resolved)

    matched = contained_by_inode(parent, policy.root_ids)
    if matched is None:
        return _deny(DENY_NOT_ALLOWLISTED,
                     f"{parent} is not inside any allowed root",
                     path, policy, resolved=os.path.join(parent, leaf))

    resolved = os.path.join(parent, leaf)
    if not _reachable_by_descent(policy, parent, resolved):
        return _deny(DENY_NOT_ALLOWLISTED,
                     f"{parent} is inside an allowed root by inode but is not "
                     f"reachable from that root's own spelling by name; the open "
                     f"would refuse it",
                     path, policy, resolved=resolved)

    pst = _ids(parent)
    if pst is None:
        return _deny(DENY_PARENT_MISSING, f"parent {parent} vanished",
                     path, policy, resolved=resolved)
    if pst[0] != matched[0]:
        return _deny(DENY_CROSSED_MOUNT,
                     f"{parent} is on device {pst[0]} but its allowed root is on "
                     f"{matched[0]}; a filesystem was mounted inside the root",
                     path, policy, resolved=resolved)

    bad = _confirm(policy, path, resolved, confirmation)
    if bad is not None:
        return bad

    return Decision(True, ALLOW_CREATE, resolved,
                    "new file in a directory inside an allowed root", path,
                    None, None, "file", pdig)


def _authorize_device(policy: Policy, path: str, resolved: str,
                      st: os.stat_result, confirmation: Optional[str],
                      env: dict, pdig: str, plat: Optional[str] = None) -> Decision:
    plat = sys.platform if plat is None else plat
    if plat == "darwin":
        return _deny(DENY_DEVICE_PLATFORM,
                     f"{resolved}: raw device targets are refused on macOS. APFS "
                     f"containers are synthesized, so a device name cannot be shown "
                     f"unrelated to the boot volume without trusting an external "
                     f"tool. The device layer is Linux-only.",
                     path, policy, kind="device", resolved=resolved)
    if not policy.allow_device_targets:
        return _deny(DENY_DEVICE_MODE_OFF,
                     "device targets are disabled in the policy",
                     path, policy, kind="device", resolved=resolved)
    if env.get("SENTINELWIPE_DEVICE_MODE") != "1":
        return _deny(DENY_DEVICE_ENV_OFF,
                     "SENTINELWIPE_DEVICE_MODE is not set to 1",
                     path, policy, kind="device", resolved=resolved)
    if path not in policy.devices:
        return _deny(DENY_DEVICE_NOT_ALLOWLISTED,
                     f"{path} is not in the device allowlist",
                     path, policy, kind="device", resolved=resolved)
    if resolved != path:
        return _deny(DENY_DEVICE_ALIAS,
                     f"{path} resolves to {resolved}; device names are compared "
                     f"literally and may not be reached through a link or alias",
                     path, policy, kind="device", resolved=resolved)
    if not (statmod.S_ISBLK(st.st_mode) or statmod.S_ISCHR(st.st_mode)):
        return _deny(DENY_DEVICE_NOT_A_DEVICE, "not a device node",
                     path, policy, kind="device", resolved=resolved)

    rootdev = root_backing_device()
    if rootdev is not None and _whole_disk(resolved) == _whole_disk(rootdev):
        return _deny(DENY_DEVICE_IS_SYSTEM,
                     f"{resolved} is on {_whole_disk(rootdev)}, the disk backing the "
                     f"running system ({rootdev})",
                     path, policy, kind="device", resolved=resolved)

    if confirmation is None:
        return _deny(DENY_CONFIRMATION_ABSENT,
                     f"destructive operation needs --i-understand '{resolved}'",
                     path, policy, kind="device", resolved=resolved)
    if not hmac.compare_digest(confirmation.encode("utf-8"), resolved.encode("utf-8")):
        return _deny(DENY_CONFIRMATION, "typed confirmation does not name the device",
                     path, policy, kind="device", resolved=resolved)

    return Decision(True, ALLOW_DEVICE, resolved,
                    "allowlisted device, three factors present", path,
                    st.st_dev, st.st_ino, "device", pdig)


def _rel_parts(resolved: str, root_real: str) -> Optional[list]:
    rel = os.path.relpath(resolved, root_real)
    parts = [p for p in rel.split(os.sep) if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return parts


def _matching_root_real(policy: Policy, resolved: str) -> Optional[str]:
    for r in policy.roots:
        rr = os.path.realpath(r)
        got = _ids(rr)
        if got is None:
            continue
        if contained_by_inode(resolved, [got]) is not None:
            return rr
    return None


def open_authorized(policy: Policy, path: str, mode: str,
                    confirmation: Optional[str] = None,
                    *, env: Optional[dict] = None) -> int:
    try:
        return _open_authorized(policy, path, mode, confirmation, env=env)
    except OSError as e:
        raise GuardError(_deny(
            DENY_RACE,
            f"open failed while the filesystem changed underneath it: "
            f"{e.strerror}", path, policy)) from None


def _open_authorized(policy: Policy, path: str, mode: str,
                     confirmation: Optional[str] = None,
                     *, env: Optional[dict] = None) -> int:
    env = os.environ if env is None else env
    d = authorize(policy, path, confirmation, mode=mode, env=env)
    if not d.allowed:
        raise GuardError(d)

    norm = _MODE_ALIASES[mode]
    creating = d.code == ALLOW_CREATE

    if d.kind == "device":
        flags = (os.O_RDONLY if norm == "r" else os.O_RDWR) | os.O_NOFOLLOW
        return os.open(d.resolved, flags)

    resolved = d.resolved
    walk_from = os.path.dirname(resolved) if creating else resolved
    root_real = _matching_root_real(policy, walk_from)
    if root_real is None:
        raise GuardError(_deny(DENY_NOT_ALLOWLISTED,
                               "root disappeared between decision and open",
                               path, policy, resolved=resolved))

    parts = _rel_parts(resolved, root_real)
    if not parts:
        raise GuardError(_deny(DENY_NOT_ALLOWLISTED,
                               "target does not sit strictly below its root",
                               path, policy, resolved=resolved))

    try:
        dirfd = os.open(root_real,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
            raise GuardError(_deny(
                DENY_SYMLINK_AT_OPEN,
                "allowed root is a symlink or not a directory at open time",
                path, policy, resolved=resolved)) from None
        raise GuardError(_deny(
            DENY_RACE, f"allowed root could not be opened: {e.strerror}",
            path, policy, resolved=resolved)) from None
    try:
        for comp in parts[:-1]:
            try:
                nxt = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=dirfd)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
                    raise GuardError(_deny(
                        DENY_SYMLINK_AT_OPEN,
                        f"component {comp!r} is a symlink or not a directory at "
                        f"open time", path, policy, resolved=resolved)) from None
                raise GuardError(_deny(
                    DENY_RACE, f"descend failed at {comp!r}: {e.strerror}",
                    path, policy, resolved=resolved)) from None
            os.close(dirfd)
            dirfd = nxt

        if norm == "r":
            flags = os.O_RDONLY | os.O_NOFOLLOW
        elif norm == "r+":
            flags = os.O_RDWR | os.O_NOFOLLOW
        elif norm == "x":
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        else:
            flags = os.O_RDWR | os.O_NOFOLLOW
            flags |= (os.O_CREAT | os.O_EXCL) if creating else 0
        try:
            fd = os.open(parts[-1], flags, 0o600, dir_fd=dirfd)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise GuardError(_deny(DENY_SYMLINK_AT_OPEN,
                                       "leaf became a symlink at open time",
                                       path, policy, resolved=resolved)) from None
            if e.errno == errno.EEXIST:
                raise GuardError(_deny(
                    DENY_RACE,
                    "target appeared between the decision and the create; refusing "
                    "rather than replacing it",
                    path, policy, resolved=resolved)) from None
            raise GuardError(_deny(DENY_RACE, f"open failed: {e.strerror}",
                                   path, policy, resolved=resolved)) from None
    finally:
        os.close(dirfd)

    try:
        fst = os.fstat(fd)
        if not statmod.S_ISREG(fst.st_mode):
            raise GuardError(_deny(DENY_NOT_REGULAR, "fd is not a regular file",
                                   path, policy, resolved=resolved))
        if fst.st_nlink != 1:
            raise GuardError(_deny(DENY_HARDLINK, f"fd has {fst.st_nlink} links",
                                   path, policy, resolved=resolved))
        if not creating:
            if (fst.st_dev, fst.st_ino) != (d.st_dev, d.st_ino):
                raise GuardError(_deny(
                    DENY_RACE,
                    f"target changed identity between decision "
                    f"({d.st_dev},{d.st_ino}) and open ({fst.st_dev},{fst.st_ino})",
                    path, policy, resolved=resolved))
            if norm in ("r", "r+") and not (policy.min_file_bytes <= fst.st_size
                                            <= policy.max_file_bytes):
                raise GuardError(_deny(DENY_SIZE, f"fd size {fst.st_size} out of bounds",
                                       path, policy, resolved=resolved))
    except GuardError:
        os.close(fd)
        raise
    if norm == "w" and not creating:
        os.ftruncate(fd, 0)
    return fd


def audit_append(log_path: str, decision: Decision, *, stamp: str = "") -> None:
    rec = decision.as_record()
    if stamp:
        rec["stamp"] = stamp
    line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def collect_confirmation(resolved: str, flag_value: Optional[str],
                         *, stdin_isatty: Optional[bool] = None) -> Optional[str]:
    if flag_value is not None:
        return flag_value.rstrip("\n")
    if stdin_isatty is None:
        stdin_isatty = sys.stdin.isatty()
    if not stdin_isatty:
        return None
    sys.stderr.write(
        f"DESTRUCTIVE. This overwrites:\n  {resolved}\n"
        f"Type the path exactly to proceed: "
    )
    sys.stderr.flush()
    try:
        return sys.stdin.readline().rstrip("\n")
    except (EOFError, KeyboardInterrupt):
        return None
