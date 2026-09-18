from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from fixtures import guard as G  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason=(
        "Windows guard backend: this file tests drive-rooted containment, reparse "
        "points and DOS device names. The POSIX backend is covered by "
        "tests/test_guard.py."
    ),
)


@pytest.fixture()
def lab(tmp_path):
    root = tmp_path / "work" / "out"
    root.mkdir(parents=True)
    img = root / "fixture.img"
    img.write_bytes(b"\0" * 4096)
    policy = G.Policy(roots=[str(root)])
    return policy, str(root), str(img)


def test_a_file_inside_the_root_is_allowed(lab):
    policy, _root, img = lab
    d = G.authorize(policy, img, mode="r+")
    assert d.allowed, d.detail
    assert d.code == G.ALLOW_FILE
    assert d.st_ino is not None, "the identity pair must be recorded on an allow"


def test_every_allow_publishes_its_own_limit(lab):
    policy, _root, img = lab
    d = G.authorize(policy, img, mode="r+")
    assert d.allowed
    assert "openat" in d.detail, d.detail
    assert "does not close" in d.detail, d.detail


def test_open_authorized_returns_a_usable_fd_and_writes_land(lab):
    policy, _root, img = lab
    fd = G.open_authorized(policy, img, "r+")
    try:
        os.write(fd, b"\x5a" * 512)
        os.fsync(fd)
    finally:
        os.close(fd)
    assert Path(img).read_bytes()[:512] == b"\x5a" * 512


def test_a_missing_target_creates_in_w_and_refuses_in_r_plus(lab):
    policy, root, _img = lab
    absent = str(Path(root) / "not-yet.img")
    assert G.authorize(policy, absent, mode="w").code == G.ALLOW_CREATE
    assert G.authorize(policy, absent, mode="r+").code == G.DENY_MISSING


def test_a_target_outside_every_root_is_refused(lab, tmp_path):
    policy, _root, _img = lab
    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    outside = outside_dir / "fixture.img"
    outside.write_bytes(b"\0" * 4096)
    d = G.authorize(policy, str(outside), mode="r+")
    assert not d.allowed
    assert d.code == G.DENY_NOT_ALLOWLISTED


def test_a_sibling_sharing_a_name_prefix_is_not_inside(lab, tmp_path):
    policy, root, _img = lab
    sibling = Path(root + "2")
    sibling.mkdir(parents=True)
    victim = sibling / "fixture.img"
    victim.write_bytes(b"\0" * 4096)
    d = G.authorize(policy, str(victim), mode="r+")
    assert d.code == G.DENY_NOT_ALLOWLISTED, d.detail


def test_a_posix_absolute_path_is_relative_here_and_is_refused(lab):
    policy, _root, _img = lab
    d = G.authorize(policy, "/private/tmp/somewhere/fixture.img", mode="r+")
    assert d.code == G.DENY_RELATIVE, d.detail


def test_the_device_and_verbatim_namespaces_are_refused(lab):
    policy, _root, _img = lab
    for target in ("\\\\.\\PhysicalDrive0", "\\\\?\\C:\\out\\x.img", "\\??\\C:\\x"):
        d = G.authorize(policy, target, mode="r+")
        assert not d.allowed, target
        assert d.code == G.DENY_DEVICE_PLATFORM, (target, d.detail)


def test_reserved_dos_names_are_devices_in_any_directory(lab):
    policy, root, _img = lab
    for leaf in ("NUL", "nul.img", "COM1.txt", "aux"):
        d = G.authorize(policy, str(Path(root) / leaf), mode="w")
        assert d.code == G.DENY_SYNTHETIC, (leaf, d.code)
    ok = G.authorize(policy, str(Path(root) / "NULL.img"), mode="w")
    assert ok.allowed, ok.detail


def test_a_directory_is_not_a_regular_file(lab):
    policy, root, _img = lab
    sub = Path(root) / "sub"
    sub.mkdir()
    assert G.authorize(policy, str(sub), mode="r+").code == G.DENY_NOT_REGULAR


def test_size_bounds_are_enforced(lab, tmp_path):
    _policy, root, img = lab
    tight = G.Policy(roots=[root], max_file_bytes=1024)
    assert G.authorize(tight, img, mode="r+").code == G.DENY_SIZE


def test_empty_nul_and_bad_mode_are_refused_before_any_disk_access(lab):
    policy, root, _img = lab
    assert G.authorize(policy, "", mode="r+").code == G.DENY_EMPTY
    assert G.authorize(policy, str(Path(root) / "a\0b.img"), mode="r+").code == G.DENY_NUL
    assert G.authorize(policy, str(Path(root) / "a.img"), mode="nonsense").code == G.DENY_MODE


def test_a_shallow_or_system_root_is_refused():
    for bad in ("C:\\", "C:\\Users", "C:\\Windows", "C:\\Windows\\Temp"):
        with pytest.raises(G.PolicyError):
            G.Policy(roots=[bad])


def test_a_root_under_the_user_profile_is_allowed(tmp_path):
    root = tmp_path / "work" / "out"
    root.mkdir(parents=True)
    assert G.Policy(roots=[str(root)]).root_reals

    profile = os.environ.get("USERPROFILE")
    if profile:
        with pytest.raises(G.PolicyError):
            G.Policy(roots=[profile])


def test_a_policy_that_arms_devices_is_refused_at_construction(tmp_path):
    root = tmp_path / "work" / "out"
    root.mkdir(parents=True)
    with pytest.raises(G.PolicyError, match="device targets are not supported"):
        G.Policy(roots=[str(root)], allow_device_targets=True)
    with pytest.raises(G.PolicyError, match="device targets are not supported"):
        G.Policy(roots=[str(root)], devices=["\\\\.\\PhysicalDrive0"])


def test_a_root_that_does_not_exist_is_refused(tmp_path):
    with pytest.raises(G.PolicyError, match="not an existing directory"):
        G.Policy(roots=[str(tmp_path / "work" / "never-made")])


def test_no_roots_is_refused(tmp_path):
    with pytest.raises(G.PolicyError, match="no write roots"):
        G.Policy(roots=[])


def test_the_policy_digest_is_stable_and_spelling_independent(tmp_path):
    root = tmp_path / "work" / "out"
    root.mkdir(parents=True)
    a = G.Policy(roots=[str(root)])
    b = G.Policy(roots=[str(root) + os.sep])
    assert a.digest() == b.digest(), "a trailing separator is not a different policy"
    assert a.digest() == a.digest()


def test_confirmation_is_required_when_the_policy_says_so(lab):
    _policy, root, img = lab
    strict = G.Policy(roots=[root], require_confirmation=True)
    assert G.authorize(strict, img, None, mode="r+").code == G.DENY_CONFIRMATION_ABSENT
    assert G.authorize(strict, img, "nope", mode="r+").code == G.DENY_CONFIRMATION
    good = G.authorize(strict, img, G.realpath(img), mode="r+")
    assert good.allowed, good.detail


def test_confirmation_grants_nothing_on_its_own(lab, tmp_path):
    _policy, root, _img = lab
    strict = G.Policy(roots=[root], require_confirmation=True)
    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    outside = outside_dir / "fixture.img"
    outside.write_bytes(b"\0" * 4096)
    d = G.authorize(strict, str(outside), G.realpath(str(outside)), mode="r+")
    assert d.code == G.DENY_NOT_ALLOWLISTED, d.detail


def _make_junction(link: Path, target: Path) -> bool:
    try:
        r = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and link.exists()


def test_a_junction_out_of_the_root_is_refused(lab, tmp_path):
    policy, root, _img = lab
    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    (outside_dir / "fixture.img").write_bytes(b"\0" * 4096)

    link = Path(root) / "escape"
    if not _make_junction(link, outside_dir):
        pytest.skip(
            "NOT VERIFIED: this host would not create a directory junction "
            "(mklink /J failed), so the reparse-point refusal was not exercised"
        )

    d = G.authorize(policy, str(link / "fixture.img"), mode="r+")
    assert not d.allowed, d.detail
    assert d.code in (G.DENY_SYMLINK_AT_OPEN, G.DENY_NOT_ALLOWLISTED), d.code
    assert (outside_dir / "fixture.img").read_bytes() == b"\0" * 4096


def test_the_code_table_is_complete_and_distinct():
    assert len(G.ALL_CODES) == 28
    assert len(set(G.ALL_CODES)) == 28, "a code string is duplicated"


def test_the_backend_names_itself():
    assert G.BACKEND == "windows"


def test_the_codes_this_backend_cannot_reach_are_named_not_hidden():
    assert G.DENY_HARDLINK in G.ALL_CODES
    probe = Path(os.environ.get("TEMP", ".")) / "sentinelwipe-nlink-probe.txt"
    probe.write_bytes(b"x")
    try:
        assert os.stat(probe).st_nlink == 1
    finally:
        probe.unlink(missing_ok=True)
