"""The **Windows** backend of the fixture write guard.

What this module guarantees, and the one thing it does not
----------------------------------------------------------
It answers the same question ``posix.py`` answers: *may this process open this
path for writing?* It refuses on the same grounds -- the target is not under an
allowlisted root, the root is a system directory, the path is relative, the leaf
is not a regular file, the size is outside bounds, the typed confirmation does
not match the guard's own resolution of the target -- and it returns the same
``Decision`` shape with the same code strings, so an audit line written on
Windows is read by the same reader.

**It is not TOCTOU-hardened, and that is the difference.** ``posix.py`` descends
from the allowlisted root one component at a time with
``openat(O_NOFOLLOW | O_DIRECTORY)`` and re-checks type, identity, link count and
size on the descriptor it will actually write through, so the path it checked and
the path it opened are provably the same object. ``os.supports_dir_fd`` is empty
on Windows and there is no ``O_NOFOLLOW``, so that descent cannot be reproduced.
This module resolves, checks, opens, and then **re-checks on the open
descriptor**. That narrows the window; it does not close it. An attacker who can
write to a directory on the path, racing the guard between the check and the
open, is not defeated here and is defeated on POSIX.

That sentence is reproduced in the ``detail`` of every allow this module issues,
in ``docs/architecture.md`` D7, and in the certificate's limitations block. It is
not a footnote: CLAUDE.md rule 1 says the tool never claims more than it
verified, and a guard that quietly implied the POSIX guarantee on Windows would
be exactly that claim.

What IS parity
--------------
The containment check is the same one, not a weaker substitute. CPython on
Windows reports the volume serial number in ``st_dev`` and the 64-bit file index
in ``st_ino``, so ``contained_by_inode`` walks the resolved path upward comparing
identity pairs exactly as the POSIX backend does. A junction that points outside
an allowed root fails that walk for the same reason a symlink does there.

What is strictly stricter here
------------------------------
* **Device targets are always refused.** ``DENY_DEVICE_PLATFORM`` is returned for
  every ``\\\\.\\PhysicalDriveN``, ``\\\\?\\`` and legacy DOS device name,
  whether or not the policy arms devices and whether or not the environment sets
  ``SENTINELWIPE_DEVICE_MODE``. Arming devices is refused at policy construction.
  There is no Windows block-device layer in this build, so there is nothing for a
  device decision to authorise and the honest answer is no.
* **Reserved DOS names are refused.** ``CON``, ``NUL``, ``AUX``, ``PRN``,
  ``COM1``..``COM9`` and ``LPT1``..``LPT9`` resolve to devices in any directory
  and at any extension, so ``out\\NUL.img`` is a device and not a file. POSIX has
  no counterpart to this rule.

What cannot be enforced here, stated rather than skipped
--------------------------------------------------------
``DENY_HARDLINK`` is in ``ALL_CODES`` and this backend never returns it.
``os.stat().st_nlink`` is reported as 1 for every file on Windows regardless of
how many hard links exist, so the multiple-hardlink refusal cannot be performed.
A hard link from outside an allowlisted root into it is **not** detected here.
The code is kept in the table so the two platforms share one vocabulary, and so
this paragraph has something to name.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat as statmod
from dataclasses import asdict, dataclass, field
from typing import Optional, Sequence, Tuple

#: Which implementation answered.
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

#: The same 28 codes ``posix.py`` publishes, in the same order, so a reader of a
#: decision never has to know which platform produced it. Two are unreachable
#: here and it is better to say which than to let a reader assume coverage:
#: ``DENY_HARDLINK`` (no link count on Windows) and ``ALLOW_DEVICE`` (device
#: targets are always refused).
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

#: A root must name at least two components below its drive: ``C:\\a\\b``.
#: ``C:\\`` and ``C:\\Users`` are refused by depth before the forbidden table is
#: consulted.
MIN_ROOT_DEPTH = 2

DEFAULT_MAX_FILE_BYTES = 8 * (1 << 30)

#: Top-level directories that may never *be* a write root.
#:
#: Spelled without a drive letter and compared component-wise, because the system
#: volume is not always ``C:`` and a rule that assumed so would silently stop
#: protecting anyone who installed Windows elsewhere.
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

#: Top-level directories that may never be an *ancestor* of a write root.
#:
#: This is deliberately ``FORBIDDEN_TOP`` minus ``USERS``, and the difference is
#: the whole point. Being under ``C:\\Windows`` or ``C:\\Program Files`` is
#: dangerous and is refused. Being under ``C:\\Users`` is where every developer's
#: checkout lives on this platform -- there is no ``/home`` -- so refusing it
#: would refuse the repository itself and the guard would protect nothing by
#: making itself unusable. ``C:\\Users`` as the root, and the operator's own
#: profile directory as the root, are both still refused.
FORBIDDEN_UNDER = FORBIDDEN_TOP - {"USERS"}

#: Legacy DOS device names. These resolve to devices in every directory and with
#: any extension.
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

#: The sentence every allow carries. Written once so it cannot drift between the
#: allow paths.
TOCTOU_NOTE = (
    "windows backend: containment was checked on the resolved path and re-checked "
    "on the open descriptor, not held across the open. Unlike the posix backend "
    "there is no openat(O_NOFOLLOW) descent, so a directory on this path that an "
    "attacker can write to is a race this guard does not close"
)


class GuardError(Exception):
    """A target was refused. Carries the Decision that refused it."""

    def __init__(self, decision: "Decision"):
        super().__init__(f"{decision.code}: {decision.detail}")
        self.decision = decision


class PolicyError(Exception):
    """The policy itself is unsafe. Raised at construction, never at use."""


def native_platform() -> str:
    return "windows"


def _norm_mode(mode: str) -> Optional[str]:
    return _MODE_ALIASES.get(mode)


def _ids(path: str) -> Optional[Tuple[int, int]]:
    """``(st_dev, st_ino)`` for ``path``, or None if it cannot be stat'd.

    On Windows CPython fills ``st_dev`` with the volume serial number and
    ``st_ino`` with the 64-bit file index, so this pair is a genuine identity and
    the containment walk below is the same algorithm the POSIX backend runs.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def contained_by_inode(resolved: str, root_ids: Sequence[Tuple[int, int]]
                       ) -> Optional[Tuple[int, int]]:
    """Walk `resolved` upward comparing identity against `root_ids`.

    Returns the matching root's identity pair, or None. A path is *inside* a
    root, never equal to it: the loop starts at the parent of `resolved`, so a
    root does not contain itself and cannot be overwritten as though it were a
    target.
    """
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
    """True if `path` is a symlink, junction or any other reparse point.

    ``os.path.islink`` misses directory junctions on some CPython versions, so
    the reparse attribute is consulted directly as well.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if statmod.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & getattr(statmod, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _reparse_on_path(root_real: str, resolved: str) -> Optional[str]:
    """The first reparse point on the path from `root_real` down to `resolved`.

    This is the Windows stand-in for the POSIX backend's ``O_NOFOLLOW`` descent.
    It is a check and not an open, so it establishes what was true when it ran
    and not what is true at the moment of the write.
    """
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
    """True for ``C:\\x`` and ``\\\\server\\share\\x``; false for ``C:x``,
    ``\\x`` and ``x``.

    Deliberately not ``os.path.isabs``, which on Windows accepts a bare leading
    separator. A POSIX-style path such as ``/tmp/x`` names no drive here and must
    be refused rather than silently resolved against the current one.
    """
    drive, rest = os.path.splitdrive(path)
    if not drive:
        return False
    return rest.startswith("\\") or rest.startswith("/")


def _body_components(real: str) -> list:
    """Components below the drive or share: ``C:\\a\\b\\c.img`` -> [a, b, c.img]."""
    _drive, rest = os.path.splitdrive(real)
    return [p for p in rest.replace("/", "\\").split("\\") if p]


def realpath(path: str) -> str:
    """Fully resolve `path`, following symlinks and junctions.

    A relative path is returned unchanged, exactly as the POSIX backend does:
    resolving one against the working directory would import state the caller did
    not state, and every caller rejects relative targets before this point.
    """
    if not _is_absolute_windows(path):
        return path
    try:
        return os.path.realpath(path)
    except OSError:
        return os.path.normpath(path)


def _is_synthetic_namespace(path: str) -> bool:
    """True for the Windows device and namespace prefixes.

    ``\\\\?\\`` is included because it bypasses path normalisation, which is
    precisely the normalisation this guard's containment check depends on.
    """
    p = path.replace("/", "\\")
    return p.startswith("\\\\.\\") or p.startswith("\\\\?\\") or p.startswith("\\??\\")


def _is_reserved_leaf(name: str) -> bool:
    return name.split(".")[0].upper() in RESERVED_LEAFS


@dataclass(frozen=True)
class Policy:
    """The allowlist. Constructed once, validated loudly at construction,
    hashed into the certificate so a reader can see which policy was in force.

    roots must already exist: a root that is not a directory is a PolicyError, so
    callers mkdir -p before constructing. A guard that creates its own allowed
    root has no allowlist.
    """

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
        """Stable over spelling. Byte-for-byte the same construction the POSIX
        backend uses, so the certificate field means the same thing on both."""
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
    """The verdict. No timestamp, no random, no host state: two identical calls
    produce equal Decisions, which is what makes the audit line reproducible
    alongside the image it authorised."""

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
    """Decide whether `path` may be opened under `policy`.

    TOTAL: returns a Decision for every input and never raises OSError.

    `env` is accepted for signature parity with the POSIX backend, which reads
    ``SENTINELWIPE_DEVICE_MODE`` through it. Device targets are refused here
    before any environment is consulted, so nothing reads it.
    """
    del env  # parity surface; see docstring

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
    """The typed confirmation is checked **last**, after containment, so it can
    never be the thing that lets a target through. It grants nothing on its own."""
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
    """The only way to obtain a descriptor on a fixture target.

    TOTAL over refusals: raises GuardError and never a bare OSError, so every
    exit is a Decision an audit line can carry. Returns a raw int fd; the caller
    closes it.

    After the open, the descriptor is re-checked with ``os.fstat`` against the
    identity the decision recorded. That is what stands in for the POSIX
    backend's ``openat`` descent. It narrows the race; it does not remove it, and
    no line in this module claims otherwise.
    """
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
    """Present for signature parity with the POSIX backend, which uses it to
    refuse a device that backs the running system. There is no Windows device
    path in this build, so there is nothing to report and nothing is invented."""
    return None


def _whole_disk(dev_name: str) -> str:
    """Present for signature parity. See :func:`root_backing_device`."""
    return dev_name


def audit_append(log_path: str, decision: Decision, *, stamp: str = "") -> None:
    """Append one decision as JSONL. Every allow and every refusal is recorded.

    `stamp` is supplied by the caller, never read from the clock here, so a build
    that wants a byte-identical audit log can pass "" and get one.
    """
    rec = decision.as_record()
    rec["stamp"] = stamp
    rec["backend"] = BACKEND
    line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
    with open(log_path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line)


def collect_confirmation(resolved: str, flag_value: Optional[str],
                         *, stdin_isatty: Optional[bool] = None) -> Optional[str]:
    """--i-understand composition.

    The flag TAKES A VALUE. A bare --i-understand is a bug, not a convenience.
    When absent and stdin is a TTY we prompt; when absent and stdin is not a TTY
    we return None, which denies. There is deliberately no environment variable,
    config key, --force or --yes that stands in for this.
    """
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
