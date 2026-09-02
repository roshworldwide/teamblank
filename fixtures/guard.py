"""SENTINELWIPE write guard. CLAUDE.md rule 4. Phase 0 gate.

Nothing in this project obtains a writable descriptor on a fixture or wipe
target except through open_authorized(). Python 3.11, standard library only,
no subprocess: nothing on PATH may influence a refusal.

THE PREDICATE, in evaluation order. Every clause is a conjunct. There is no
disjunction anywhere on the allow path.

  Target is an EXISTING FILE (modes "r", "r+", "w" on a file that is there):
    F1  path is a non-empty str, contains no NUL, and is absolute
    F2  resolved = os.path.realpath(path) -- resolves every symlink component
        and the macOS /tmp -> /private/tmp alias
    F3  on macOS, resolved is not under /.vol -- the volfs namespace that
        addresses any file by inode number. See authorize() for the measurement
    F4  resolved exists; a block or character device is handed to the DEVICE
        path, which is default-deny
    F5  containment: some ancestor of resolved is inode-identical
        ((st_dev, st_ino)) to an allowed root. Checked BEFORE any property of
        the file itself, so a refusal names the control that refused it
    F6  stat() says S_ISREG -- a directory, FIFO or socket is refused
    F7  st_nlink == 1 -- a hardlink inside an allowed root whose inode lives
        outside it is the one escape realpath cannot see
    F8  min_file_bytes <= st_size <= max_file_bytes  (modes "r" and "r+")
    F9  st_dev equals the matched root's st_dev (nothing was mounted inside
        the root). DESIGNED BUT UNVERIFIED: exercising it needs a filesystem
        mounted inside an allowed root, which needs privilege and which the
        no-mount decision in docs/architecture.md forbids
    F10 if policy.require_confirmation: confirmation byte-equals resolved
  Target does NOT exist (modes "w" and "x"):
    C1  F1 and F3
    C2  the leaf is one component and is not "", "." or ".."
    C3  the parent directory exists and is a directory
    C4  containment on the PARENT, by inode ancestry (F5)
    C5  parent st_dev equals the matched root's st_dev
    C6  F10, against resolved = realpath(parent) + "/" + leaf
        Size bounds do not apply: there is no file yet to be out of bounds.
        The create is O_CREAT|O_EXCL|O_NOFOLLOW relative to a descended
        directory descriptor, so it can neither follow a symlink nor clobber
        a file that appeared after the decision.
  Target is a DEVICE:
    D0  the platform is not macOS. See _authorize_device: this is a measured
        defect fix, not caution
    D1  policy.allow_device_targets is True         (config-file factor)
    D2  env SENTINELWIPE_DEVICE_MODE == "1"         (environment factor)
    D3  path byte-equals an entry in policy.devices AND realpath(path)
        byte-equals that same entry
    D4  stat() says S_ISBLK or S_ISCHR
    D5  the device is not the one backing "/" nor a slice of the same whole
        disk (Linux; DESIGNED BUT UNVERIFIED, no Linux host was available)
    D6  confirmation byte-equals the device name, unconditionally
  policy.devices is EMPTY by default, so D3 refuses every device until a human
  edits a config file on purpose, and D0 refuses it again on this platform.

WHY INODE CONTAINMENT AND NOT A STRING PREFIX. Measured on the dev machine,
macOS 26.6.2 arm64, Python 3.11.15:
  * /Users and /System/Volumes/Data/Users report the same (st_dev, st_ino) --
    one directory -- but os.path.realpath returns each unchanged. realpath
    does not resolve firmlinks, so one directory has two irreducible path
    strings. A string prefix test denies a legitimate target reached by the
    other name.
  * The working volume is case-insensitive: '/x/FIXTURES/a.img' and
    '/x/fixtures/a.img' are the same file. A case-sensitive prefix test denies
    one of them; a case-insensitive one is wrong on a case-sensitive volume.
Inode identity is exact under both, and being identity rather than a string
relation it can never widen the allowed set.

WHY THE SYSTEM DENYLIST LIVES IN POLICY CONSTRUCTION, NOT IN THE PER-TARGET
CHECK. A per-target "refuse anything under /System" clause would refuse a
legitimate fixture reached through the /System/Volumes/Data firmlink. Roots
are validated once, loudly, at construction; after that containment is exact
and needs no second opinion. The device denylist is separate and per-target.

TOCTOU. authorize() is a decision about a path and is inherently racy.
open_authorized() re-establishes every fact against descriptors: it descends
from the allowed root one component at a time with O_NOFOLLOW|O_DIRECTORY
(measured: ELOOP on macOS when a component is swapped for a symlink), opens
the leaf O_NOFOLLOW, and re-checks type, identity, nlink and size on the fd.
The returned fd, not the path, is what callers write through.
"""

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

# ---------------------------------------------------------------- reason codes

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

# ------------------------------------------------------------------- modes
#
# The third argument of open_authorized. Deliberately Python's open() spelling
# so a reader does not have to learn a second vocabulary, and deliberately a
# closed set: an unrecognised mode is DENY_UNSUPPORTED_MODE, never a guess.
#
#   "r"   read an existing file
#   "r+"  read/write an existing file, no truncation
#   "w"   read/write, create if absent, truncate if present
#   "x"   create; refuse if the target already exists
#
# A trailing or embedded "b" is accepted and ignored: every descriptor this
# module returns is binary, because it is a raw file descriptor.

MODES = ("r", "r+", "w", "x")

_MODE_ALIASES = {
    "r": "r", "rb": "r",
    "r+": "r+", "rb+": "r+", "r+b": "r+", "+r": "r+",
    "w": "w", "wb": "w", "w+": "w", "wb+": "w", "w+b": "w",
    "x": "x", "xb": "x", "x+": "x", "xb+": "x", "x+b": "x",
}

MIN_ROOT_DEPTH = 2  # a root must be at least /a/b; "/" and "/Users" are refused

FORBIDDEN_ROOTS = (
    "/", "/dev", "/.vol", "/System", "/System/Volumes/Data", "/Volumes", "/Library",
    "/Applications", "/bin", "/sbin", "/usr", "/etc", "/var", "/private",
    "/private/etc", "/private/var", "/private/var/db", "/private/tmp", "/tmp",
    "/Users", "/home", "/opt", "/net", "/cores", "/Network",
)


class GuardError(Exception):
    """A target was refused. Carries the Decision that refused it."""

    def __init__(self, decision: "Decision"):
        super().__init__(f"{decision.code}: {decision.detail}")
        self.decision = decision


class PolicyError(Exception):
    """The policy itself is unsafe. Raised at construction, never at use."""


# --------------------------------------------------------------------- helpers


def _ids(path: str) -> Optional[Tuple[int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def _forbidden_ids() -> dict:
    """(st_dev, st_ino) -> the spelling it was listed as.

    Built from the REALPATH of each entry as well as the literal string,
    because the string list alone is a trap: realpath('/etc') is
    '/private/etc', which no string test for '/etc' catches. Found by
    test_ATTACK_symlinked_root_itself, which passed a root symlinked to /etc
    through an earlier string-only version of this check.
    """
    out: dict = {}
    for name in FORBIDDEN_ROOTS:
        for spelling in (name, os.path.realpath(name)):
            got = _ids(spelling)
            if got is not None:
                out.setdefault(got, spelling)
    return out


def contained_by_inode(resolved: str, root_ids: Sequence[Tuple[int, int]]
                       ) -> Optional[Tuple[int, int]]:
    """Walk `resolved` upward comparing (st_dev, st_ino) against root_ids.

    `resolved` must already be a realpath, so every component is symlink-free
    and walking by string is sound. Identity comparison at each step is what
    makes this correct across macOS firmlinks (two path strings, one inode)
    and case-insensitive volumes (two spellings, one inode). Returns the
    matched root's id, or None.
    """
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
        if steps > 256:          # pathological depth; refuse rather than spin
            return None


def root_backing_device() -> Optional[str]:
    """The /dev/diskNsM whose st_rdev equals st_dev of '/'.

    Measured on the dev machine: /dev/disk3s5. Computed with stat only; the
    guard shells out to nothing.
    """
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
    """/dev/disk3s5 -> disk3 ; /dev/rdisk3s5 -> disk3."""
    base = os.path.basename(dev_name)
    if base.startswith("r"):
        base = base[1:]
    out = []
    for ch in base:
        if ch == "s" and out and out[-1].isdigit():
            break
        out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------- policy


@dataclass(frozen=True)
class Policy:
    """The allowlist. Constructed once, validated loudly at construction,
    hashed into the certificate so a reader can see which policy was in force.

    roots must already exist: a root that is not a directory is a PolicyError,
    so callers mkdir -p before constructing. A guard that creates its own
    allowed root has no allowlist.

    require_confirmation is False by default because building a fixture into a
    scratch directory is not a destructive operation on anyone's data. Every
    destructive caller -- the wipe path -- constructs its Policy with
    require_confirmation=True, and arming devices forces it True.
    """

    roots: Tuple[str, ...]
    devices: Tuple[str, ...] = ()
    allow_device_targets: bool = False
    require_confirmation: bool = False
    min_file_bytes: int = 0
    max_file_bytes: int = 8 * (1 << 30)          # 8 GiB
    root_ids: Tuple[Tuple[int, int], ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        # Accept any sequence (the contract spells it list[str]); store a tuple
        # so the frozen dataclass stays hashable and comparable.
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

            # (a) the root IS a system directory, under any spelling.
            # MEASURED redundant: containment is reflexive, so clause (b)
            # below already fires when the root IS the forbidden directory
            # (a negative control that removes only (a) changes no test).
            # Kept because it produces the message a reader can act on --
            # "matches /tmp" rather than "contains /private/tmp".
            if got in forbidden:
                raise PolicyError(
                    f"refusing system directory as a write root: {r!r} -> {real!r} "
                    f"(matches {forbidden[got]})")
            # (b) the root CONTAINS a system directory, so writing under it
            #     could reach one. Catches /private, /System/Volumes, and every
            #     ancestor of the running system.
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
        """Stable over spelling: two teammates who name the same root as
        /tmp/x and /private/tmp/x produce the same digest."""
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
    """The verdict. No timestamp, no random, no host state: two identical
    calls produce equal Decisions, which is what makes the audit line
    reproducible alongside the image it authorised."""

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


# ------------------------------------------------------------------ authorize


def authorize(policy: Policy, path: str, confirmation: Optional[str] = None,
              *, mode: str = "r+", env: Optional[dict] = None,
              _platform: Optional[str] = None) -> Decision:
    """Decide whether `path` may be opened under `policy`. Pure: no fd, no
    side effect, no mutation of anything on disk.

    mode is keyword-only and defaults to "r+", the existing-file write
    predicate, so the two-argument form authorize(policy, path) reads as
    "may I write this file". Pass mode="w" or "x" to ask about a create.

    confirmation is checked LAST, and only after the allowlist has already
    said yes, so a refused target never reveals that typing something would
    have helped. It carries no authority of its own: the value it must equal
    is the guard's own resolution of the target, not the string the operator
    passed.

    _platform is a TEST SEAM and nothing else. Clause D0 refuses every device
    target on macOS before any other factor is consulted, which on this host
    makes D1..D6 -- the allowlist, the environment factor, the alias rule, the
    root-backing-disk rule and the typed confirmation -- unreachable and
    therefore untested, and those are precisely the clauses CLAUDE.md rule 4
    calls a disqualifying defect area. Passing _platform="linux" bypasses D0
    ONLY, so each remaining clause has a test that can fail. It defaults to the
    real sys.platform, it is never passed anywhere in the fixture build path,
    and it does not reach the file rules: the /.vol refusal below still keys on
    the real platform.
    """
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

    # macOS volfs. MEASURED on this machine, unprivileged: /.vol/<st_dev>/<st_ino>
    # addresses any file on the volume by inode; os.path.realpath leaves the
    # string untouched, os.stat reports the underlying regular file (S_ISREG,
    # st_nlink 1, true size), and os.open(..., O_RDWR) succeeds. So F5, F6 and
    # F7 all pass and inode containment is the only clause left standing.
    #
    # Containment does hold -- /.vol/<dev>/<ino-of-a-file-outside> walks up
    # through /.vol to / and matches no root. But /.vol/<dev>/<ino-of-the-root>/
    # disk.img DOES match, because the walk hits the allowed root's own inode,
    # and authorize() returned ALLOW_FILE for it while open_authorized() refused
    # it (relpath against the root produces "..", so the descent will not start).
    # Two defects in that: the two halves of the guard disagreed, and the
    # confirmation string put in front of the operator was an inode number
    # rather than a path a human can read before authorising a destructive act.
    #
    # Nothing in this project ever legitimately produces a /.vol path, so the
    # namespace is refused whole. This is a string test, and soundly so: it is
    # applied to the REALPATH, which has already collapsed ".", "..", repeated
    # separators and every symlink, and no real file under an allowed root ever
    # resolves back into /.vol.
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
        # Checked before containment on purpose: "x" asserts the target does
        # not exist, and an existing file is a failure of the caller's own
        # premise, not a policy question.
        return _deny(DENY_EXISTS,
                     f"{resolved} already exists and mode 'x' refuses to replace it",
                     path, policy, resolved=resolved)

    # Containment is evaluated FIRST, before any property of the file itself.
    # Ordering is not cosmetic: with the size check first, /dev/stdout was
    # refused as DENY_SIZE_OUT_OF_BOUNDS rather than DENY_NOT_ALLOWLISTED
    # (measured). Both refuse, but the audit line then records an incidental
    # reason instead of the controlling one, and the certificate quotes that
    # line. The allowlist is the control; everything after it is hygiene.
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

    if st.st_nlink != 1:
        return _deny(DENY_HARDLINK,
                     f"{resolved} has {st.st_nlink} links; a hardlink can place an "
                     f"inode from outside the allowed root inside it",
                     path, policy, resolved=resolved)

    # Size bounds apply to the modes that READ existing content. "w"
    # truncates and "x" creates, so the size the file happens to have now is
    # not a policy question -- and a rule that denied "w" on a 10-byte file
    # while allowing "w" on no file at all would be incoherent.
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
    """The last conjunct. Returns a denial, or None if the clause is satisfied
    (including the case where the policy does not require it)."""
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
    """The target does not exist and the caller asked for "w" or "x".

    Containment moves to the parent directory. The leaf never participates in
    a path walk: it is a single component opened relative to a descended
    directory descriptor with O_CREAT|O_EXCL|O_NOFOLLOW, so no symlink can be
    followed and no file that appeared after this decision can be clobbered.
    """
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
    # macOS: refuse every device target, unconditionally, before any factor is
    # consulted. Not conservatism -- a MEASURED defect in the earlier version
    # of this function.
    #
    #   "/" is on /dev/disk3s5. /dev/disk3 is a SYNTHESIZED APFS container
    #   whose "APFS Physical Store" is /dev/disk0s2, a partition of the
    #   internal 500 GB drive /dev/disk0 (diskutil list, this machine).
    #
    # The whole-disk rule below derives "disk3" from "disk3s5" and never
    # reaches disk0, so an operator who allowlisted /dev/disk0 and set both
    # other factors got ALLOW_DEVICE for the boot drive. It failed only with
    # EPERM because the process was not root -- the guard had already said
    # yes. That is the disqualifying defect in CLAUDE.md rule 4, reached
    # through the documented escape hatch, and it is why the red-team table
    # asserts on the DECISION and never on whether an fd came back.
    #
    # Walking the synthesis chain correctly needs `diskutil info -plist` or
    # IOKit. The guard spawns no subprocess, on purpose: nothing on PATH may
    # influence a refusal. So on darwin the honest predicate is "no". The
    # device layer is Linux-only per the scope rules and is never demoed.
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

    # Devices always require the typed confirmation, whatever the policy says.
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


# -------------------------------------------------------------- hardened open


def _rel_parts(resolved: str, root_real: str) -> Optional[list]:
    rel = os.path.relpath(resolved, root_real)
    parts = [p for p in rel.split(os.sep) if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return parts


def _matching_root_real(policy: Policy, resolved: str) -> Optional[str]:
    """The realpath spelling of the allowed root that contains `resolved`.

    Containment matched an inode; the descent needs a string to start from.
    Firmlinks mean the two are not interchangeable, so the root that matched
    is re-identified here rather than assumed.
    """
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
    """The only way to obtain a descriptor on a fixture or wipe target.

    Returns a raw file descriptor. The CALLER owns it and must close it.
    Raises GuardError, whose .decision carries the refusing clause, on any
    refusal -- including a refusal discovered only at open time.

    Runs authorize(), then re-establishes every fact against descriptors:
    descends from the allowed root one component at a time with
    O_NOFOLLOW|O_DIRECTORY and opens the leaf with O_NOFOLLOW, so a component
    swapped for a symlink between decision and open fails with ELOOP instead
    of escaping. The fd, not the path, is what callers write through.
    """
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

    dirfd = os.open(root_real, os.O_RDONLY | os.O_DIRECTORY)
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
        else:                                   # "w"
            flags = os.O_RDWR | os.O_NOFOLLOW
            flags |= (os.O_CREAT | os.O_EXCL) if creating else os.O_TRUNC
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
    return fd


# ----------------------------------------------------------------- audit trail


def audit_append(log_path: str, decision: Decision, *, stamp: str = "") -> None:
    """Append one decision as JSONL. Every allow and every refusal is
    recorded; the certificate cites this file for "what we verified".

    `stamp` is supplied by the caller, never read from the clock here, so a
    build that wants a byte-identical audit log can pass "" and get one.
    This is the one writable open in the project outside open_authorized: the
    log is an append-only record chosen by the operator, not a wipe target,
    and routing it through the guard would make the guard depend on its own
    allowlist to explain a refusal.
    """
    rec = decision.as_record()
    if stamp:
        rec["stamp"] = stamp
    line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


# ----------------------------------------------------- confirmation collection


def collect_confirmation(resolved: str, flag_value: Optional[str],
                         *, stdin_isatty: Optional[bool] = None) -> Optional[str]:
    """--i-understand composition.

    The flag TAKES A VALUE. A bare --i-understand is a bug, not a convenience.
    When absent and stdin is a TTY we prompt; when absent and stdin is not a
    TTY we return None, which denies. There is deliberately no environment
    variable, config key, --force or --yes that stands in for this.
    """
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
