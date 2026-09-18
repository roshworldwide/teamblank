from __future__ import annotations

import errno
import json
import os
import shutil
import sys
import tempfile
import unicodedata
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from fixtures import guard as G  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "POSIX guard backend: this file tests O_NOFOLLOW descent, symlink and "
        "hardlink refusal and /dev device aliases, none of which exist on Windows. "
        "The Windows backend is covered by tests/test_guard_windows.py."
    ),
)


IMG = 4 * 1024 * 1024
MIB = 1 << 20


@pytest.fixture()
def lab(tmp_path):
    root = tmp_path / "fixtures"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    img = root / "disk.img"
    img.write_bytes(b"\x00" * IMG)
    victim = outside / "victim.img"
    victim.write_bytes(b"\xaa" * IMG)
    return {
        "tmp": tmp_path,
        "root": root,
        "outside": outside,
        "img": img,
        "victim": victim,
        "policy": G.Policy(roots=[str(root)]),
        "confirming": G.Policy(roots=[str(root)], require_confirmation=True),
        "sized": G.Policy(roots=[str(root)], min_file_bytes=MIB,
                          max_file_bytes=8 * (1 << 30)),
        "conf": os.path.realpath(str(img)),
    }


def auth(pol, target, conf=None, **kw):
    return G.authorize(pol, str(target), conf, **kw)


def test_contract_signatures():
    import inspect
    p = list(inspect.signature(G.Policy).parameters)
    assert p[0] == "roots"
    d = list(inspect.signature(G.Decision).parameters)
    assert d[:3] == ["allowed", "code", "resolved"]
    a = list(inspect.signature(G.authorize).parameters)
    assert a[:2] == ["policy", "path"]
    o = list(inspect.signature(G.open_authorized).parameters)
    assert o[:3] == ["policy", "path", "mode"]


def test_policy_accepts_a_plain_list(lab):
    pol = G.Policy(roots=[str(lab["root"])])
    assert pol.roots == (str(lab["root"]),)
    assert hash(pol) == hash(G.Policy(roots=[str(lab["root"])]))


def test_open_authorized_returns_an_int_fd(lab):
    fd = G.open_authorized(lab["policy"], str(lab["img"]), "r+")
    try:
        assert isinstance(fd, int)
        os.pwrite(fd, b"SENTINELWIPE", 0)
        assert os.pread(fd, 12, 0) == b"SENTINELWIPE"
    finally:
        os.close(fd)


def test_ALLOW_plain_image_in_root(lab):
    d = auth(lab["policy"], lab["img"])
    assert d.allowed, d.code
    assert d.code == G.ALLOW_FILE
    assert d.resolved == lab["conf"]


def test_ALLOW_two_argument_form_is_usable(lab):
    assert G.authorize(lab["policy"], str(lab["img"])).allowed


def test_ALLOW_create_new_file_in_root(lab):
    new = lab["root"] / "fresh.img"
    d = auth(lab["policy"], new, mode="x")
    assert d.allowed and d.code == G.ALLOW_CREATE
    fd = G.open_authorized(lab["policy"], str(new), "x")
    try:
        os.write(fd, b"NEW")
    finally:
        os.close(fd)
    assert new.read_bytes() == b"NEW"
    assert os.stat(new).st_nlink == 1


def test_ALLOW_w_truncates_an_existing_file(lab):
    fd = G.open_authorized(lab["policy"], str(lab["img"]), "w")
    try:
        os.write(fd, b"TRUNCATED")
    finally:
        os.close(fd)
    assert lab["img"].read_bytes() == b"TRUNCATED"


def test_ALLOW_read_mode_gives_a_read_only_fd(lab):
    fd = G.open_authorized(lab["policy"], str(lab["img"]), "r")
    try:
        assert os.pread(fd, 4, 0) == b"\x00\x00\x00\x00"
        with pytest.raises(OSError):
            os.pwrite(fd, b"x", 0)
    finally:
        os.close(fd)


def test_decision_is_deterministic(lab):
    a = auth(lab["policy"], lab["img"])
    b = auth(lab["policy"], lab["img"])
    assert a == b
    assert "ts" not in a.as_record() and "time" not in a.as_record()


def test_ATTACK_symlink_leaf_to_outside_file(lab):
    link = lab["root"] / "innocent.img"
    os.symlink(str(lab["victim"]), str(link))
    d = auth(lab["confirming"], link, str(link))
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED
    assert d.resolved == os.path.realpath(str(lab["victim"]))


def test_ATTACK_symlink_leaf_to_dev_disk0(lab):
    link = lab["root"] / "fixture.img"
    os.symlink("/dev/disk0", str(link))
    d = auth(lab["policy"], link, "/dev/disk0")
    assert not d.allowed
    assert d.kind == "device"
    assert d.code in (G.DENY_DEVICE_PLATFORM, G.DENY_DEVICE_MODE_OFF)
    assert d.resolved == "/dev/disk0"


def test_ATTACK_symlink_leaf_to_rdisk0(lab):
    link = lab["root"] / "raw.img"
    os.symlink("/dev/rdisk0", str(link))
    d = auth(lab["policy"], link, "/dev/rdisk0")
    assert not d.allowed and d.kind == "device"


def test_ATTACK_symlinked_directory_component(lab):
    (lab["root"] / "sub").symlink_to("/etc")
    d = auth(lab["policy"], lab["root"] / "sub" / "hosts",
             os.path.realpath("/etc/hosts"))
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED


def test_ATTACK_symlinked_root_itself(tmp_path):
    r = tmp_path / "fixtures"
    r.symlink_to("/etc")
    with pytest.raises(G.PolicyError):
        G.Policy(roots=[str(r)])


def test_ATTACK_dotdot_escape(lab):
    t = str(lab["root"] / ".." / "outside" / "victim.img")
    d = auth(lab["policy"], t, os.path.realpath(t))
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED


def test_ATTACK_dotdot_that_returns_inside_is_allowed(lab):
    (lab["root"] / "sub").mkdir()
    t = str(lab["root"] / "sub" / ".." / "disk.img")
    d = auth(lab["policy"], t)
    assert d.allowed, d.code
    assert d.resolved == lab["conf"]


def test_ATTACK_sibling_prefix_confusion(tmp_path):
    root = tmp_path / "fixtures"
    root.mkdir()
    evil = tmp_path / "fixtures-evil"
    evil.mkdir()
    img = evil / "disk.img"
    img.write_bytes(b"\x00" * IMG)
    pol = G.Policy(roots=[str(root)])
    d = G.authorize(pol, str(img), os.path.realpath(str(img)))
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED


def test_ATTACK_relative_path_refused(lab):
    d = G.authorize(lab["policy"], "disk.img", "disk.img")
    assert not d.allowed and d.code == G.DENY_RELATIVE


def test_ATTACK_nul_byte(lab):
    d = G.authorize(lab["policy"], str(lab["img"]) + "\x00/dev/disk0", "x")
    assert not d.allowed and d.code == G.DENY_NUL


def test_ATTACK_empty_target(lab):
    assert G.authorize(lab["policy"], "").code == G.DENY_EMPTY


def test_ATTACK_hardlink_from_outside_into_root(lab):
    link = lab["root"] / "planted.img"
    os.link(str(lab["victim"]), str(link))
    assert os.stat(str(link)).st_nlink == 2
    d = auth(lab["policy"], link, os.path.realpath(str(link)))
    assert not d.allowed and d.code == G.DENY_HARDLINK


def test_ATTACK_hardlink_also_refused_at_open(lab):
    link = lab["root"] / "planted2.img"
    os.link(str(lab["victim"]), str(link))
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], str(link), "r+")
    assert ei.value.decision.code == G.DENY_HARDLINK
    assert lab["victim"].read_bytes()[:4] == b"\xaa\xaa\xaa\xaa"


def test_ALLOW_tmp_alias_resolves():
    if not os.path.islink("/tmp"):
        pytest.skip("/tmp is not a symlink on this host")
    base = tempfile.mkdtemp(dir="/tmp")
    try:
        root = os.path.join(base, "fixtures")
        os.mkdir(root)
        img = os.path.join(root, "d.img")
        with open(img, "wb") as fh:
            fh.write(b"\x00" * IMG)
        pol = G.Policy(roots=[root])
        via_private = os.path.join(os.path.realpath(root), "d.img")
        assert G.authorize(pol, via_private).allowed
        assert G.authorize(pol, img).allowed
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_tmp_and_private_tmp_roots_are_one_policy():
    if not os.path.islink("/tmp"):
        pytest.skip("/tmp is not a symlink")
    base = tempfile.mkdtemp(dir="/tmp")
    try:
        r_tmp = os.path.join(base, "fx")
        os.mkdir(r_tmp)
        r_priv = os.path.join(os.path.realpath(base), "fx")
        assert G.Policy(roots=[r_tmp]).digest() == G.Policy(roots=[r_priv]).digest()
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_case_variant_spelling_of_the_root_is_refused_by_the_decision_itself(lab):
    upper = str(lab["root"]).replace("/fixtures", "/FIXTURES")
    if not os.path.exists(upper):
        pytest.skip("volume is case-sensitive")
    target = os.path.join(upper, "disk.img")
    d = G.authorize(lab["policy"], target)
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED, d.code
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], target, "r+")
    assert ei.value.decision.code == d.code, (
        "the decision and the open must now give the SAME code for this target")
    ok = G.authorize(lab["policy"], str(lab["img"]))
    assert ok.allowed and ok.code == G.ALLOW_FILE, ok.code
    fd = G.open_authorized(lab["policy"], str(lab["img"]), "r+")
    os.close(fd)


def test_case_variant_is_not_a_widening(lab):
    upper = str(lab["outside"]).replace("/outside", "/OUTSIDE")
    if not os.path.exists(upper):
        pytest.skip("volume is case-sensitive")
    d = G.authorize(lab["policy"], os.path.join(upper, "victim.img"))
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED


def _vol(path):
    st = os.stat(str(path))
    return "/.vol/%d/%d" % (st.st_dev, st.st_ino)


def test_volfs_is_a_real_bypass_surface():
    if sys.platform != "darwin" or not os.path.isdir("/.vol"):
        pytest.skip("no /.vol on this host")
    d = tempfile.mkdtemp(dir="/private/tmp")
    try:
        f = os.path.join(d, "victim.img")
        with open(f, "wb") as fh:
            fh.write(b"\xaa" * 4096)
        st = os.stat(f)
        v = _vol(f)
        assert os.path.realpath(v) == v, "realpath rewrote the volfs path"
        st2 = os.stat(v)
        assert (st2.st_dev, st2.st_ino) == (st.st_dev, st.st_ino)
        assert st2.st_nlink == 1 and st2.st_size == 4096
        fd = os.open(v, os.O_RDWR)
        os.close(fd)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_ATTACK_volfs_reaches_a_file_outside_the_root(lab):
    if sys.platform != "darwin" or not os.path.isdir("/.vol"):
        pytest.skip("no /.vol on this host")
    d = G.authorize(lab["policy"], _vol(lab["victim"]))
    assert not d.allowed
    assert d.code in (G.DENY_SYNTHETIC, G.DENY_NOT_ALLOWLISTED)


def test_ATTACK_volfs_composed_under_the_allowed_root(lab):
    if sys.platform != "darwin" or not os.path.isdir("/.vol"):
        pytest.skip("no /.vol on this host")
    t = _vol(lab["root"]) + "/disk.img"
    d = G.authorize(lab["policy"], t)
    assert not d.allowed and d.code == G.DENY_SYNTHETIC
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], t, "r+")
    assert ei.value.decision.code == d.code, \
        "authorize() and open_authorized() disagree about the same target"


def test_ATTACK_volfs_create(lab):
    if sys.platform != "darwin" or not os.path.isdir("/.vol"):
        pytest.skip("no /.vol on this host")
    d = G.authorize(lab["policy"], _vol(lab["root"]) + "/new.img", mode="x")
    assert not d.allowed and d.code == G.DENY_SYNTHETIC


def test_ATTACK_volfs_as_a_policy_root():
    if sys.platform != "darwin" or not os.path.isdir("/.vol"):
        pytest.skip("no /.vol on this host")
    with pytest.raises(G.PolicyError):
        G.Policy(roots=["/.vol"])


def test_ATTACK_depth_one_root_refused():
    import fixtures.guard as _g
    cands = [n for n in sorted(os.listdir("/"))
             if os.path.isdir("/" + n) and "/" + n not in _g.FORBIDDEN_ROOTS
             and not os.path.islink("/" + n)]
    if not cands:
        pytest.skip("every top-level directory is already on the denylist")
    for n in cands:
        with pytest.raises(G.PolicyError) as ei:
            G.Policy(roots=["/" + n])
        msg = str(ei.value)
        assert any(k in msg for k in ("shallow", "system", "HOME")), msg


def test_firmlink_two_strings_one_inode():
    a, b = "/Users", "/System/Volumes/Data/Users"
    if not (os.path.isdir(a) and os.path.isdir(b)):
        pytest.skip("no firmlink on this host")
    sa, sb = os.stat(a), os.stat(b)
    assert (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)
    assert os.path.realpath(a) != os.path.realpath(b)
    assert G.contained_by_inode(b, [(sa.st_dev, sa.st_ino)]) is not None


def test_ATTACK_dev_disk0_direct(lab):
    d = G.authorize(lab["policy"], "/dev/disk0", "/dev/disk0")
    assert not d.allowed
    if sys.platform == "darwin":
        assert d.code == G.DENY_DEVICE_PLATFORM


def test_ATTACK_dev_rdisk0_direct(lab):
    d = G.authorize(lab["policy"], "/dev/rdisk0", "/dev/rdisk0")
    assert not d.allowed and d.kind == "device"


def test_ATTACK_dev_stdout(lab):
    d = G.authorize(lab["policy"], "/dev/stdout", "/dev/stdout")
    assert not d.allowed
    assert d.code in (G.DENY_DEVICE_PLATFORM, G.DENY_DEVICE_MODE_OFF,
                      G.DENY_NOT_ALLOWLISTED, G.DENY_MISSING), d.code


def test_ATTACK_dev_null(lab):
    d = G.authorize(lab["policy"], "/dev/null", "/dev/null")
    assert not d.allowed and d.kind == "device"


def test_ATTACK_dev_fd_reference_to_outside_file(lab):
    fd = os.open(str(lab["victim"]), os.O_RDONLY)
    try:
        t = f"/dev/fd/{fd}"
        d = G.authorize(lab["policy"], t, os.path.realpath(t))
        assert not d.allowed, f"{t} resolved to {d.resolved} and was ALLOWED"
        assert d.code in (G.DENY_NOT_ALLOWLISTED, G.DENY_DEVICE_MODE_OFF,
                          G.DENY_DEVICE_PLATFORM, G.DENY_NOT_REGULAR,
                          G.DENY_MISSING), d.code
    finally:
        os.close(fd)


def test_ATTACK_device_mode_on_but_not_allowlisted(lab):
    pol = G.Policy(roots=[str(lab["root"])], devices=["/dev/disk99"],
                   allow_device_targets=True, require_confirmation=True)
    d = G.authorize(pol, "/dev/disk0", "/dev/disk0",
                    env={"SENTINELWIPE_DEVICE_MODE": "1"})
    assert not d.allowed
    assert d.code in (G.DENY_DEVICE_PLATFORM, G.DENY_DEVICE_NOT_ALLOWLISTED)


def test_ATTACK_device_allowlisted_but_env_off(lab):
    pol = G.Policy(roots=[str(lab["root"])], devices=["/dev/disk0"],
                   allow_device_targets=True, require_confirmation=True)
    d = G.authorize(pol, "/dev/disk0", "/dev/disk0", env={})
    assert not d.allowed
    assert d.code in (G.DENY_DEVICE_PLATFORM, G.DENY_DEVICE_ENV_OFF)


def test_ATTACK_the_measured_defect_disk0_fully_armed(lab):
    if not os.path.exists("/dev/disk0"):
        pytest.skip("/dev/disk0 absent on this host")
    pol = G.Policy(roots=[str(lab["root"])], devices=["/dev/disk0"],
                   allow_device_targets=True, require_confirmation=True)
    env = {"SENTINELWIPE_DEVICE_MODE": "1"}
    d = G.authorize(pol, "/dev/disk0", "/dev/disk0", env=env)
    assert d.allowed is False, "the guard PERMITTED the internal disk"
    assert d.code.startswith("DENY_"), d.code
    if sys.platform == "darwin":
        assert d.code == G.DENY_DEVICE_PLATFORM
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(pol, "/dev/disk0", "r+", "/dev/disk0", env=env)
    assert ei.value.decision.code == d.code
    assert not isinstance(ei.value, OSError)


def test_ATTACK_boot_disk_refused_even_when_fully_allowlisted(lab):
    rootdev = G.root_backing_device()
    if rootdev is None:
        pytest.skip("cannot identify the root-backing device")
    pol = G.Policy(roots=[str(lab["root"])], devices=[rootdev],
                   allow_device_targets=True, require_confirmation=True)
    d = G.authorize(pol, rootdev, rootdev, env={"SENTINELWIPE_DEVICE_MODE": "1"})
    assert not d.allowed
    assert d.code in (G.DENY_DEVICE_PLATFORM, G.DENY_DEVICE_IS_SYSTEM)


def test_ATTACK_whole_disk_of_boot_volume_refused(lab):
    rootdev = G.root_backing_device()
    if rootdev is None:
        pytest.skip("cannot identify the root-backing device")
    whole = "/dev/" + G._whole_disk(rootdev)
    if not os.path.exists(whole):
        pytest.skip(f"{whole} absent")
    pol = G.Policy(roots=[str(lab["root"])], devices=[whole],
                   allow_device_targets=True, require_confirmation=True)
    d = G.authorize(pol, whole, whole, env={"SENTINELWIPE_DEVICE_MODE": "1"})
    assert not d.allowed
    assert d.code in (G.DENY_DEVICE_PLATFORM, G.DENY_DEVICE_IS_SYSTEM)


def test_ATTACK_device_reached_through_an_alias(lab):
    pol = G.Policy(roots=[str(lab["root"])], devices=["/dev/disk0"],
                   allow_device_targets=True, require_confirmation=True)
    d = G.authorize(pol, "/dev/./disk0", "/dev/disk0",
                    env={"SENTINELWIPE_DEVICE_MODE": "1"})
    assert not d.allowed
    assert d.code in (G.DENY_DEVICE_PLATFORM, G.DENY_DEVICE_NOT_ALLOWLISTED)


def test_arming_devices_without_confirmation_is_a_policy_error(lab):
    with pytest.raises(G.PolicyError):
        G.Policy(roots=[str(lab["root"])], devices=["/dev/disk9"],
                 allow_device_targets=True)


def _armed(root, devices):
    return G.Policy(roots=[str(root)], devices=list(devices),
                    allow_device_targets=True, require_confirmation=True)


LINUX = {"_platform": "linux"}
DEV_ON = {"SENTINELWIPE_DEVICE_MODE": "1"}


def test_the_seam_only_bypasses_D0(lab):
    if sys.platform != "darwin":
        pytest.skip("D0 is the macOS clause")
    pol = G.Policy(roots=[str(lab["root"])])
    assert G.authorize(pol, "/dev/null").code == G.DENY_DEVICE_PLATFORM
    assert G.authorize(pol, "/dev/null", **LINUX).code == G.DENY_DEVICE_MODE_OFF


def test_D1_devices_disabled_in_the_policy(lab):
    pol = G.Policy(roots=[str(lab["root"])])
    d = G.authorize(pol, "/dev/null", "/dev/null", env=DEV_ON, **LINUX)
    assert not d.allowed and d.code == G.DENY_DEVICE_MODE_OFF


def test_D2_environment_factor_absent(lab):
    pol = _armed(lab["root"], ["/dev/null"])
    d = G.authorize(pol, "/dev/null", "/dev/null", env={}, **LINUX)
    assert not d.allowed and d.code == G.DENY_DEVICE_ENV_OFF
    d = G.authorize(pol, "/dev/null", "/dev/null",
                    env={"SENTINELWIPE_DEVICE_MODE": "0"}, **LINUX)
    assert not d.allowed and d.code == G.DENY_DEVICE_ENV_OFF
    d = G.authorize(pol, "/dev/null", "/dev/null",
                    env={"SENTINELWIPE_DEVICE_MODE": "true"}, **LINUX)
    assert not d.allowed and d.code == G.DENY_DEVICE_ENV_OFF


def test_D3_device_not_on_the_allowlist(lab):
    if not os.path.exists("/dev/zero"):
        pytest.skip("/dev/zero absent")
    pol = _armed(lab["root"], ["/dev/null"])
    d = G.authorize(pol, "/dev/zero", "/dev/zero", env=DEV_ON, **LINUX)
    assert not d.allowed and d.code == G.DENY_DEVICE_NOT_ALLOWLISTED


def test_D4_an_allowlisted_alias_is_still_an_alias(lab):
    pol = _armed(lab["root"], ["/dev/./null"])
    d = G.authorize(pol, "/dev/./null", "/dev/null", env=DEV_ON, **LINUX)
    assert not d.allowed and d.code == G.DENY_DEVICE_ALIAS


def test_D5_the_running_systems_disk_is_refused_with_all_factors_present(lab):
    rootdev = G.root_backing_device()
    if rootdev is None:
        pytest.skip("cannot identify the root-backing device")
    pol = _armed(lab["root"], [rootdev])
    d = G.authorize(pol, rootdev, rootdev, env=DEV_ON, **LINUX)
    assert not d.allowed and d.code == G.DENY_DEVICE_IS_SYSTEM


def test_D5_covers_the_whole_disk_and_its_slices(lab):
    rootdev = G.root_backing_device()
    if rootdev is None:
        pytest.skip("cannot identify the root-backing device")
    whole = "/dev/" + G._whole_disk(rootdev)
    if not os.path.exists(whole):
        pytest.skip(f"{whole} absent")
    pol = _armed(lab["root"], [whole])
    d = G.authorize(pol, whole, whole, env=DEV_ON, **LINUX)
    assert not d.allowed and d.code == G.DENY_DEVICE_IS_SYSTEM


def test_D6_confirmation_is_unconditional_for_devices(lab):
    pol = _armed(lab["root"], ["/dev/null"])
    d = G.authorize(pol, "/dev/null", None, env=DEV_ON, **LINUX)
    assert not d.allowed and d.code == G.DENY_CONFIRMATION_ABSENT
    for bad in ("", "dev/null", "/dev/nul", "/dev/null ", "yes"):
        d = G.authorize(pol, "/dev/null", bad, env=DEV_ON, **LINUX)
        assert not d.allowed, bad
        assert d.code in (G.DENY_CONFIRMATION_ABSENT, G.DENY_CONFIRMATION), bad


def test_the_device_path_can_actually_say_yes(lab):
    pol = _armed(lab["root"], ["/dev/null"])
    d = G.authorize(pol, "/dev/null", "/dev/null", env=DEV_ON, **LINUX)
    assert d.allowed is True
    assert d.code == G.ALLOW_DEVICE
    assert d.kind == "device"
    assert d.resolved == "/dev/null"


def test_the_seam_does_not_reach_the_file_rules(lab):
    if sys.platform != "darwin":
        pytest.skip("/.vol is macOS")
    st = os.stat(str(lab["img"]))
    volpath = f"/.vol/{st.st_dev}/{st.st_ino}"
    d = G.authorize(lab["policy"], volpath, **LINUX)
    assert not d.allowed and d.code == G.DENY_SYNTHETIC
    assert G.authorize(lab["policy"], str(lab["victim"]), **LINUX).allowed is False


def test_the_seam_defaults_to_the_real_platform(lab):
    a = G.authorize(lab["policy"], "/dev/null")
    b = G.authorize(lab["policy"], "/dev/null", _platform=sys.platform)
    assert a.code == b.code


def test_no_confirmation_clause_for_a_refused_target(lab):
    d = auth(lab["confirming"], lab["victim"], None)
    assert d.code == G.DENY_NOT_ALLOWLISTED
    assert d.code != G.DENY_CONFIRMATION_ABSENT


def test_no_confirmation_clause_for_a_refused_hardlink(lab):
    link = lab["root"] / "planted3.img"
    os.link(str(lab["victim"]), str(link))
    d = auth(lab["confirming"], link, None)
    assert d.code == G.DENY_HARDLINK


def test_ATTACK_confirmation_cannot_add_to_allowlist(lab):
    v = str(lab["victim"])
    d = G.authorize(lab["confirming"], v, os.path.realpath(v))
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED


def test_ATTACK_absent_confirmation_denies(lab):
    d = auth(lab["confirming"], lab["img"], None)
    assert not d.allowed and d.code == G.DENY_CONFIRMATION_ABSENT


def test_ATTACK_empty_confirmation_denies(lab):
    d = auth(lab["confirming"], lab["img"], "")
    assert not d.allowed and d.code == G.DENY_CONFIRMATION


def test_ATTACK_confirmation_prefix_denies(lab):
    d = auth(lab["confirming"], lab["img"], lab["conf"][:-1])
    assert not d.allowed and d.code == G.DENY_CONFIRMATION


def test_ATTACK_confirmation_matching_the_arg_not_the_resolved(lab):
    (lab["root"] / "sub").mkdir()
    t = str(lab["root"] / "sub" / ".." / "disk.img")
    d = G.authorize(lab["confirming"], t, t)
    assert not d.allowed and d.code == G.DENY_CONFIRMATION
    assert G.authorize(lab["confirming"], t, os.path.realpath(t)).allowed


def test_confirmation_required_on_create_too(lab):
    new = lab["root"] / "fresh.img"
    assert auth(lab["confirming"], new, None, mode="x").code == \
        G.DENY_CONFIRMATION_ABSENT
    assert auth(lab["confirming"], new, str(new), mode="x").allowed


def test_non_tty_never_auto_confirms():
    assert G.collect_confirmation("/x/y.img", None, stdin_isatty=False) is None


def test_flag_value_is_used_verbatim():
    assert G.collect_confirmation("/x/y.img", "/x/y.img\n",
                                  stdin_isatty=False) == "/x/y.img"


def test_ATTACK_directory_target(lab):
    d = auth(lab["policy"], lab["root"])
    assert not d.allowed and d.code == G.DENY_NOT_REGULAR


def test_ATTACK_fifo_target(lab):
    p = lab["root"] / "pipe"
    os.mkfifo(str(p))
    d = auth(lab["policy"], p)
    assert not d.allowed and d.code == G.DENY_NOT_REGULAR


def test_ATTACK_undersized_file_refused(lab):
    small = lab["root"] / "tiny.img"
    small.write_bytes(b"x" * 10)
    d = auth(lab["sized"], small)
    assert not d.allowed and d.code == G.DENY_SIZE


def test_ATTACK_oversized_file_refused(lab):
    big = lab["root"] / "huge.img"
    with open(big, "wb") as fh:
        fh.truncate(16 * (1 << 30))
    d = auth(lab["sized"], big)
    assert not d.allowed and d.code == G.DENY_SIZE


def test_ATTACK_missing_target(lab):
    d = auth(lab["policy"], lab["root"] / "nope.img")
    assert not d.allowed and d.code == G.DENY_MISSING


def test_ATTACK_unsupported_mode(lab):
    d = auth(lab["policy"], lab["img"], mode="a")
    assert not d.allowed and d.code == G.DENY_MODE
    assert auth(lab["policy"], lab["img"], mode=None).code == G.DENY_MODE


def test_ATTACK_create_through_a_dangling_symlink_out_of_the_root(lab):
    link = lab["root"] / "new.img"
    os.symlink(str(lab["outside"] / "planted.img"), str(link))
    d = auth(lab["policy"], link, mode="x")
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED
    assert not (lab["outside"] / "planted.img").exists()


def test_ATTACK_create_under_a_symlinked_directory_component(lab):
    (lab["root"] / "sub").symlink_to(str(lab["outside"]))
    d = auth(lab["policy"], lab["root"] / "sub" / "new.img", mode="x")
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED


def test_ATTACK_create_outside_the_root(lab):
    d = auth(lab["policy"], lab["outside"] / "new.img", mode="x")
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED


def test_ATTACK_create_with_a_missing_parent(lab):
    d = auth(lab["policy"], lab["root"] / "nodir" / "new.img", mode="x")
    assert not d.allowed and d.code == G.DENY_PARENT_MISSING


def test_ATTACK_x_mode_refuses_to_replace(lab):
    d = auth(lab["policy"], lab["img"], mode="x")
    assert not d.allowed and d.code == G.DENY_EXISTS
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], str(lab["img"]), "x")
    assert ei.value.decision.code == G.DENY_EXISTS
    assert lab["img"].stat().st_size == IMG


def test_create_uses_O_EXCL_so_a_planted_leaf_cannot_be_followed(lab):
    os.symlink(str(lab["victim"]), str(lab["root"] / "n.img"))
    d0 = os.open(str(lab["root"]), os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError) as ei:
            os.open("n.img", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=d0)
        assert ei.value.errno == errno.EEXIST
    finally:
        os.close(d0)
    assert lab["victim"].read_bytes()[:4] == b"\xaa\xaa\xaa\xaa"


@pytest.mark.parametrize("bad", ["/", "/dev", "/Volumes", "/tmp", "/etc",
                                 "/System", "/private", "/usr", "/var",
                                 "/Library", "/Applications"])
def test_ATTACK_system_root_refused(bad):
    if not os.path.exists(bad):
        pytest.skip(f"{bad} absent")
    with pytest.raises(G.PolicyError):
        G.Policy(roots=[bad])


def test_ATTACK_root_home_refused():
    with pytest.raises(G.PolicyError):
        G.Policy(roots=[os.path.expanduser("~")])


def test_ATTACK_empty_policy_refused():
    with pytest.raises(G.PolicyError):
        G.Policy(roots=[])


def test_ATTACK_relative_root_refused():
    with pytest.raises(G.PolicyError):
        G.Policy(roots=["fixtures"])


def test_ATTACK_nonexistent_root_refused(tmp_path):
    with pytest.raises(G.PolicyError):
        G.Policy(roots=[str(tmp_path / "not-created-yet")])


def test_ATTACK_root_given_as_a_bare_string_refused(tmp_path):
    r = tmp_path / "fixtures"
    r.mkdir()
    with pytest.raises(G.PolicyError):
        G.Policy(roots=str(r))


def test_ATTACK_root_that_is_a_file_refused(lab):
    with pytest.raises(G.PolicyError):
        G.Policy(roots=[str(lab["img"])])


def test_ATTACK_nonsensical_size_bounds(lab):
    with pytest.raises(G.PolicyError):
        G.Policy(roots=[str(lab["root"])], min_file_bytes=10, max_file_bytes=5)


def test_ATTACK_root_deleted_and_recreated_after_policy(lab):
    root = str(lab["root"])
    pol = lab["policy"]
    assert auth(pol, lab["img"]).allowed
    shutil.rmtree(root)
    os.mkdir(root)
    newimg = os.path.join(root, "disk.img")
    with open(newimg, "wb") as fh:
        fh.write(b"\x00" * IMG)
    d = G.authorize(pol, newimg)
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED


def test_ATTACK_root_replaced_by_symlink_to_outside(lab):
    root = str(lab["root"])
    shutil.rmtree(root)
    os.symlink(str(lab["outside"]), root)
    d = G.authorize(lab["policy"], os.path.join(root, "victim.img"))
    assert not d.allowed and d.code == G.DENY_NOT_ALLOWLISTED


def test_policy_digest_is_stable_and_binding(lab):
    p1 = G.Policy(roots=[str(lab["root"])])
    p2 = G.Policy(roots=[str(lab["root"])])
    assert p1.digest() == p2.digest()
    p3 = G.Policy(roots=[str(lab["root"])], devices=["/dev/disk9"],
                  allow_device_targets=True, require_confirmation=True)
    assert p3.digest() != p1.digest()
    assert auth(p1, lab["img"]).policy_digest == p1.digest()

    other = lab["tmp"] / "second-root"
    other.mkdir()
    assert G.Policy(roots=[str(other)]).digest() != p1.digest()
    assert G.Policy(roots=[str(lab["root"]), str(other)]).digest() != p1.digest()
    assert G.Policy(roots=[str(lab["root"])],
                    require_confirmation=True).digest() != p1.digest()
    assert G.Policy(roots=[str(lab["root"])],
                    min_file_bytes=1).digest() != p1.digest()
    assert G.Policy(roots=[str(lab["root"])],
                    max_file_bytes=1 << 40).digest() != p1.digest()
    assert G.Policy(roots=[str(lab["root"]), str(other)]).digest() == \
        G.Policy(roots=[str(other), str(lab["root"])]).digest()


@pytest.mark.parametrize("mangle", [
    lambda p: p + "/",
    lambda p: p.replace("/fixtures/", "//fixtures//"),
    lambda p: p.replace("/fixtures/", "/fixtures/./"),
    lambda p: p.replace("/fixtures/", "/fixtures/./././"),
    lambda p: "/" + p.lstrip("/"),
    lambda p: p.replace("/fixtures/", "/fixtures/sub/../"),
])
def test_syntax_variants_of_a_legitimate_target(lab, mangle):
    (lab["root"] / "sub").mkdir(exist_ok=True)
    t = mangle(str(lab["img"]))
    d = G.authorize(lab["policy"], t)
    assert d.resolved == lab["conf"], f"{t} -> {d.resolved}"
    assert d.allowed, f"{t}: {d.code}"


@pytest.mark.parametrize("mangle", [
    lambda p: p.replace("/fixtures/disk.img", "/outside/victim.img"),
    lambda p: p.replace("/fixtures/", "/fixtures/../outside/").replace("disk.img", "victim.img"),
    lambda p: p.replace("/fixtures/", "//fixtures/../outside//").replace("disk.img", "victim.img"),
    lambda p: p.replace("/fixtures/", "/fixtures/./../outside/").replace("disk.img", "victim.img"),
])
def test_syntax_variants_that_escape_are_all_refused(lab, mangle):
    t = mangle(str(lab["img"]))
    d = G.authorize(lab["policy"], t, os.path.realpath(t))
    assert not d.allowed, f"{t} -> {d.resolved} was ALLOWED"
    assert d.code == G.DENY_NOT_ALLOWLISTED


def test_unicode_nfc_nfd_spellings_agree(lab):
    nfc = unicodedata.normalize("NFC", "café.img")
    nfd = unicodedata.normalize("NFD", "café.img")
    (lab["root"] / nfc).write_bytes(b"\x00" * IMG)
    for spelling in (nfc, nfd):
        t = os.path.join(str(lab["root"]), spelling)
        if not os.path.exists(t):
            continue
        d = G.authorize(lab["confirming"], t, os.path.realpath(t))
        assert d.allowed, f"{spelling!r}: {d.code}"
        d2 = G.authorize(lab["confirming"], t, t)
        assert d2.allowed or d2.code == G.DENY_CONFIRMATION


def test_ATTACK_symlink_cycle(lab):
    a, b = lab["root"] / "a", lab["root"] / "b"
    os.symlink(str(b), str(a))
    os.symlink(str(a), str(b))
    d = auth(lab["policy"], a)
    assert not d.allowed and d.code == G.DENY_MISSING


def test_ATTACK_deep_nesting_terminates(lab):
    p = lab["root"]
    for i in range(40):
        p = p / f"d{i}"
    p.mkdir(parents=True)
    img = p / "deep.img"
    img.write_bytes(b"\x00" * IMG)
    assert auth(lab["policy"], img).allowed
    fd = G.open_authorized(lab["policy"], str(img), "r+")
    os.close(fd)


def test_ATTACK_swap_leaf_for_symlink_after_decision(lab):
    assert auth(lab["policy"], lab["img"]).allowed
    os.unlink(str(lab["img"]))
    os.symlink(str(lab["victim"]), str(lab["img"]))
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], str(lab["img"]), "r+")
    assert ei.value.decision.code in (G.DENY_NOT_ALLOWLISTED,
                                      G.DENY_SYMLINK_AT_OPEN)
    assert lab["victim"].stat().st_size == IMG
    assert lab["victim"].read_bytes()[:4] == b"\xaa\xaa\xaa\xaa"


def test_ATTACK_swap_intermediate_dir_for_symlink(lab):
    sub = lab["root"] / "sub"
    sub.mkdir()
    img = sub / "d.img"
    img.write_bytes(b"\x00" * IMG)
    assert auth(lab["policy"], img).allowed
    evil = lab["outside"] / "sub"
    evil.mkdir()
    (evil / "d.img").write_bytes(b"\xaa" * IMG)
    shutil.rmtree(str(sub))
    os.symlink(str(evil), str(sub))
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], str(img), "r+")
    assert ei.value.decision.code in (G.DENY_NOT_ALLOWLISTED,
                                      G.DENY_SYMLINK_AT_OPEN)
    assert (evil / "d.img").read_bytes()[:4] == b"\xaa\xaa\xaa\xaa"


def _racing_authorize(swap):
    real = G.authorize

    def racing(policy, path, confirmation=None, *, mode="r+", env=None):
        d = real(policy, path, confirmation, mode=mode, env=env)
        if d.allowed:
            swap()
        return d
    return racing


def test_ATTACK_true_race_leaf_swapped_inside_the_window(lab, monkeypatch):
    def swap():
        os.unlink(str(lab["img"]))
        os.symlink(str(lab["victim"]), str(lab["img"]))
    monkeypatch.setattr(G, "authorize", _racing_authorize(swap))
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], str(lab["img"]), "r+")
    assert ei.value.decision.code == G.DENY_SYMLINK_AT_OPEN
    assert lab["victim"].read_bytes() == b"\xaa" * IMG


def test_ATTACK_true_race_on_w_would_truncate_the_victim(lab, monkeypatch):
    def swap():
        os.unlink(str(lab["img"]))
        os.symlink(str(lab["victim"]), str(lab["img"]))
    monkeypatch.setattr(G, "authorize", _racing_authorize(swap))
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], str(lab["img"]), "w")
    assert ei.value.decision.code == G.DENY_SYMLINK_AT_OPEN
    assert lab["victim"].stat().st_size == IMG
    assert lab["victim"].read_bytes() == b"\xaa" * IMG


def test_ATTACK_true_race_leaf_replaced_by_another_regular_file(lab, monkeypatch):
    other = lab["root"] / "other.img"
    other.write_bytes(b"\xbb" * IMG)

    def swap():
        os.unlink(str(lab["img"]))
        os.link(str(other), str(lab["img"]))
        os.unlink(str(other))
    monkeypatch.setattr(G, "authorize", _racing_authorize(swap))
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], str(lab["img"]), "r+")
    assert ei.value.decision.code == G.DENY_RACE
    assert lab["img"].read_bytes()[:4] == b"\xbb\xbb\xbb\xbb"


def test_ATTACK_true_race_intermediate_dir_swapped_inside_the_window(lab, monkeypatch):
    sub = lab["root"] / "sub"
    sub.mkdir()
    img = sub / "d.img"
    img.write_bytes(b"\x00" * IMG)
    evil = lab["outside"] / "sub"
    evil.mkdir()
    (evil / "d.img").write_bytes(b"\xaa" * IMG)

    def swap():
        shutil.rmtree(str(sub))
        os.symlink(str(evil), str(sub))
    monkeypatch.setattr(G, "authorize", _racing_authorize(swap))
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], str(img), "r+")
    assert ei.value.decision.code == G.DENY_SYMLINK_AT_OPEN
    assert (evil / "d.img").read_bytes() == b"\xaa" * IMG


def test_ATTACK_true_race_target_appears_before_a_create(lab, monkeypatch):
    new = lab["root"] / "fresh.img"

    def swap():
        new.write_bytes(b"\xcc" * 32)
    monkeypatch.setattr(G, "authorize", _racing_authorize(swap))
    with pytest.raises(G.GuardError) as ei:
        G.open_authorized(lab["policy"], str(new), "x")
    assert ei.value.decision.code == G.DENY_RACE
    assert new.read_bytes() == b"\xcc" * 32


def test_open_authorized_uses_nofollow_at_the_leaf(lab):
    os.symlink(str(lab["victim"]), str(lab["root"] / "l.img"))
    d0 = os.open(str(lab["root"]), os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError) as ei:
            os.open("l.img", os.O_RDWR | os.O_NOFOLLOW, dir_fd=d0)
        assert ei.value.errno == errno.ELOOP
    finally:
        os.close(d0)


def test_every_decision_is_auditable(lab, tmp_path):
    log = tmp_path / "guard-audit.jsonl"
    G.audit_append(str(log), auth(lab["policy"], lab["img"]))
    G.audit_append(str(log), G.authorize(lab["policy"], "/dev/disk0", "/dev/disk0"))
    rows = [json.loads(l) for l in log.read_text().splitlines()]
    assert len(rows) == 2
    assert rows[0]["allowed"] is True and rows[0]["code"] == G.ALLOW_FILE
    assert rows[1]["allowed"] is False and rows[1]["resolved"] == "/dev/disk0"
    assert all(r["policy_digest"] for r in rows)


def test_audit_log_is_byte_identical_across_runs(lab, tmp_path):
    import hashlib
    hashes = []
    for i in range(2):
        log = tmp_path / f"a{i}.jsonl"
        G.audit_append(str(log), auth(lab["policy"], lab["img"]))
        hashes.append(hashlib.sha256(log.read_bytes()).hexdigest())
    assert hashes[0] == hashes[1]


_WRITE_MODE_LITERALS = ('"w', "'w", '"a', "'a", '"x', "'x", '"r+', "'r+",
                        "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

_WRITE_CALLS = ("os.open(", "os.fdopen(", "io.open(", "mmap.mmap(",
                "os.replace(", "os.rename(", "os.truncate(",
                "shutil.copy", "shutil.move")

_IMAGE_PATH_MODULES = ("fixtures/build_image.py", "fixtures/fat32.py",
                       "fixtures/plan.py", "py/sentinelwipe")

_DECLARED_UNGUARDED = {
    "fixtures/corpus.py":
        "_main() dumps the generated corpus to an operator-supplied directory "
        "so external decoders can be pointed at it. Not a fixture or wipe "
        "target: it writes source material, never the image or the manifest.",
}


def _raw_writes(paths, exempt=("posix.py", "windows.py")):
    found = []
    for p in paths:
        if p.name in exempt:
            continue
        for i, line in enumerate(
                p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            t = line.strip()
            if t.startswith("#") or "open_authorized" in t:
                continue
            if (any(c in t for c in _WRITE_CALLS)
                    or ("open(" in t and any(m in t for m in _WRITE_MODE_LITERALS))
                    or ".write_bytes(" in t or ".write_text(" in t):
                found.append((p.relative_to(_REPO).as_posix(), i, t))
    return found


def _watched(*rels):
    out = []
    for rel in rels:
        base = _REPO / rel
        if base.is_dir():
            out.extend(sorted(base.rglob("*.py")))
        elif base.is_file():
            out.append(base)
    return out


def test_no_raw_writable_open_on_the_image_path():
    bad = _raw_writes(_watched(*_IMAGE_PATH_MODULES))
    assert not bad, (
        "writable open on the image path. Obtain the descriptor from "
        'fixtures.guard.open_authorized(policy, path, "x") instead:\n  '
        + "\n  ".join(f"{f}:{i}: {t}" for f, i, t in bad))


def test_unguarded_writes_elsewhere_are_declared():
    bad = _raw_writes(_watched("fixtures", "py/sentinelwipe"))
    undeclared = [(f, i, t) for f, i, t in bad if f not in _DECLARED_UNGUARDED]
    assert not undeclared, (
        "undeclared writable open outside the guard:\n  "
        + "\n  ".join(f"{f}:{i}: {t}" for f, i, t in undeclared))
    assert all(_DECLARED_UNGUARDED[f].strip() for f, _, _ in bad)


def test_the_write_detector_is_not_vacuous():
    hits = _raw_writes([_REPO / "fixtures" / "guard" / "posix.py"], exempt=())
    assert hits, "the detector found no writable open in guard/posix.py itself"
    assert any("os.open(" in t for _, _, t in hits), \
        "the detector cannot see os.open with a computed flags argument"
    assert any('"a"' in t or "'a'" in t for _, _, t in hits), \
        "the detector cannot see a string write mode"


def _redteam_rows(tmp: str):
    rows = []
    root = os.path.join(tmp, "fixtures")
    os.mkdir(root)
    out = os.path.join(tmp, "outside")
    os.mkdir(out)
    img = os.path.join(root, "disk.img")
    with open(img, "wb") as fh:
        fh.write(b"\x00" * IMG)
    vic = os.path.join(out, "victim.img")
    with open(vic, "wb") as fh:
        fh.write(b"\xaa" * IMG)
    vic_before = open(vic, "rb").read(16)
    pol = G.Policy(roots=[root])
    conf_pol = G.Policy(roots=[root], require_confirmation=True)
    sized = G.Policy(roots=[root], min_file_bytes=MIB)
    real = os.path.realpath

    def attempt(label, target, p, conf, *, env=None, mode="r+", expect_deny=True):
        got_fd = False
        code = ""
        errno_code = ""
        try:
            d = G.authorize(p, target, conf, mode=mode,
                            env=env if env is not None else {})
            code = d.code
            allowed = d.allowed
        except Exception as e:
            code, allowed = f"RAISED/{type(e).__name__}", True
        try:
            fd = G.open_authorized(p, target, mode, conf,
                                   env=env if env is not None else {})
            got_fd = True
            os.close(fd)
        except G.GuardError as e:
            code = e.decision.code
        except OSError as e:
            errno_code = f"OSERROR/{e.errno}"
        if expect_deny:
            ok = (not got_fd) and (not allowed) and code.startswith("DENY_") \
                and not errno_code
        else:
            ok = got_fd and allowed
        rows.append((label, "FD OBTAINED" if got_fd else "refused",
                     errno_code or code, ok))

    attempt("CONTROL legitimate fixture image", img, pol, None, expect_deny=False)
    attempt("CONTROL create a new file in the root",
            os.path.join(root, "created.img"), pol, None, mode="x",
            expect_deny=False)

    l1 = os.path.join(root, "s_victim.img"); os.symlink(vic, l1)
    attempt("symlink under root -> file outside root", l1, pol, real(l1))
    l2 = os.path.join(root, "s_disk0.img"); os.symlink("/dev/disk0", l2)
    attempt("symlink under root -> /dev/disk0", l2, pol, "/dev/disk0")
    l3 = os.path.join(root, "s_rdisk0.img"); os.symlink("/dev/rdisk0", l3)
    attempt("symlink under root -> /dev/rdisk0", l3, pol, "/dev/rdisk0")
    d1 = os.path.join(root, "s_etc"); os.symlink("/etc", d1)
    attempt("symlinked DIRECTORY component -> /etc",
            os.path.join(d1, "hosts"), pol, real("/etc/hosts"))
    l4 = os.path.join(root, "s_new.img")
    os.symlink(os.path.join(out, "planted.img"), l4)
    attempt("CREATE through a dangling symlink out of the root", l4, pol,
            None, mode="x")

    h = os.path.join(root, "h_victim.img"); os.link(vic, h)
    attempt("hardlink under root, inode outside root", h, pol, real(h))

    attempt("dotdot escape", os.path.join(root, "..", "outside", "victim.img"),
            pol, real(vic))
    os.makedirs(root + "-evil", exist_ok=True)
    with open(root + "-evil/disk.img", "wb") as fh:
        fh.write(b"\x00" * IMG)
    attempt("sibling prefix confusion (fixtures-evil)",
            root + "-evil/disk.img", pol, real(root + "-evil/disk.img"))
    attempt("relative path", "disk.img", pol, "disk.img")
    attempt("NUL smuggling", img + "\x00/dev/disk0", pol, real(img))
    attempt("create outside the root", os.path.join(out, "new.img"), pol,
            None, mode="x")
    attempt("create with a missing parent",
            os.path.join(root, "nodir", "new.img"), pol, None, mode="x")

    attempt("raw /dev/disk0, default policy", "/dev/disk0", pol, "/dev/disk0")
    attempt("raw /dev/rdisk0, default policy", "/dev/rdisk0", pol, "/dev/rdisk0")
    attempt("/dev/stdout", "/dev/stdout", pol, "/dev/stdout")
    attempt("/dev/null", "/dev/null", pol, "/dev/null")
    if sys.platform == "darwin" and os.path.isdir("/.vol"):
        sv = os.stat(vic)
        attempt("/.vol/<dev>/<ino> of a file outside the root",
                "/.vol/%d/%d" % (sv.st_dev, sv.st_ino), pol, None)
        sr_ = os.stat(root)
        attempt("/.vol/<dev>/<ino-of-root>/disk.img composed under the root",
                "/.vol/%d/%d/disk.img" % (sr_.st_dev, sr_.st_ino), pol, None)
    fd = os.open(vic, os.O_RDONLY)
    attempt("/dev/fd/N pointing at a file outside the root",
            f"/dev/fd/{fd}", pol, real(f"/dev/fd/{fd}"))
    os.close(fd)
    pol_d = G.Policy(roots=[root], devices=["/dev/disk0"],
                     allow_device_targets=True, require_confirmation=True)
    attempt("/dev/disk0 allowlisted, env unset", "/dev/disk0", pol_d,
            "/dev/disk0", env={})
    attempt("/dev/disk0 allowlisted + env set  [THE MEASURED DEFECT]",
            "/dev/disk0", pol_d, "/dev/disk0",
            env={"SENTINELWIPE_DEVICE_MODE": "1"})
    attempt("/dev/./disk0 alias of an allowlisted device", "/dev/./disk0",
            pol_d, "/dev/disk0", env={"SENTINELWIPE_DEVICE_MODE": "1"})
    bootdev = G.root_backing_device()
    if bootdev:
        pol_b = G.Policy(roots=[root], devices=[bootdev],
                         allow_device_targets=True, require_confirmation=True)
        attempt(f"BOOT DISK {bootdev}, allowlisted, all 3 factors",
                bootdev, pol_b, bootdev, env={"SENTINELWIPE_DEVICE_MODE": "1"})
        whole = "/dev/" + G._whole_disk(bootdev)
        if os.path.exists(whole):
            pol_w = G.Policy(roots=[root], devices=[whole],
                             allow_device_targets=True, require_confirmation=True)
            attempt(f"WHOLE BOOT DISK {whole}, allowlisted",
                    whole, pol_w, whole, env={"SENTINELWIPE_DEVICE_MODE": "1"})

    attempt("no confirmation at all", img, conf_pol, None)
    attempt("empty confirmation", img, conf_pol, "")
    attempt("confirmation naming an off-allowlist file", vic, conf_pol, real(vic))
    attempt("confirmation one char short", img, conf_pol, real(img)[:-1])
    attempt("confirmation for a DIFFERENT allowed file", img, conf_pol,
            real(img) + ".other")

    attempt("target is a directory", root, pol, real(root))
    fifo = os.path.join(root, "p"); os.mkfifo(fifo)
    attempt("target is a FIFO", fifo, pol, real(fifo))
    tiny = os.path.join(root, "tiny.img")
    with open(tiny, "wb") as fh:
        fh.write(b"x" * 10)
    attempt("target below size floor", tiny, sized, real(tiny))
    attempt("mode 'x' over an existing file", img, pol, None, mode="x")
    attempt("unsupported mode 'a'", img, pol, None, mode="a")

    assert G.authorize(pol, img).allowed
    os.unlink(img); os.symlink(vic, img)
    attempt("leaf swapped for a symlink AFTER the decision", img, pol, real(img))
    os.unlink(img)
    with open(img, "wb") as fh:
        fh.write(b"\x00" * IMG)

    sub = os.path.join(root, "sub"); os.mkdir(sub)
    simg = os.path.join(sub, "d.img")
    with open(simg, "wb") as fh:
        fh.write(b"\x00" * IMG)
    assert G.authorize(pol, simg).allowed
    evil = os.path.join(out, "sub"); os.makedirs(evil, exist_ok=True)
    with open(os.path.join(evil, "d.img"), "wb") as fh:
        fh.write(b"\xaa" * IMG)
    shutil.rmtree(sub); os.symlink(evil, sub)
    attempt("intermediate dir swapped for a symlink after the decision",
            simg, pol, real(simg))

    for bad in ("/", "/dev", "/Volumes", "/tmp", "/etc", os.path.expanduser("~"),
                "/System", "/private", "/usr", "/var", "/.vol",
                os.path.join(tmp, "does-not-exist")):
        if not os.path.exists(bad):
            continue
        try:
            G.Policy(roots=[bad])
            rows.append((f"POLICY root={bad}", "ACCEPTED", "-", False))
        except G.PolicyError:
            rows.append((f"POLICY root={bad}", "refused", "PolicyError", True))
    try:
        G.Policy(roots=[root], devices=["/dev/disk0"], allow_device_targets=True)
        rows.append(("POLICY devices armed without confirmation", "ACCEPTED",
                     "-", False))
    except G.PolicyError:
        rows.append(("POLICY devices armed without confirmation", "refused",
                     "PolicyError", True))

    unchanged = open(vic, "rb").read(16) == vic_before
    return rows, unchanged


def _race_lab(tmp_path, tag):
    base = tmp_path / tag
    (base / "fixtures" / "sub").mkdir(parents=True)
    (base / "outside" / "sub").mkdir(parents=True)
    victim = base / "outside" / "sub" / "disk.img"
    victim.write_bytes(b"\xaa" * 4096)
    target = base / "fixtures" / "sub" / "disk.img"
    target.write_bytes(b"\xbb" * 4096)
    return base, target, victim


def test_ATTACK_a_racing_thread_flipping_the_allowed_root_never_costs_a_victim(tmp_path):
    import threading
    import time

    base, target, victim = _race_lab(tmp_path, "race-root")
    root = base / "fixtures"
    outside = base / "outside"
    hidden = base / "fixtures.real"
    victim_ids = os.stat(victim).st_ino, os.stat(victim).st_dev
    victim_before = victim.read_bytes()

    policy = G.Policy(roots=[str(root)])
    conf = os.path.realpath(str(target))

    stop = threading.Event()

    def flipper():
        while not stop.is_set():
            try:
                os.rename(str(root), str(hidden))
                os.symlink(str(outside), str(root))
                os.unlink(str(root))
                os.rename(str(hidden), str(root))
            except OSError:
                pass

    t = threading.Thread(target=flipper, daemon=True)
    t.start()
    census: dict[str, int] = {}
    kernel_errors = []
    attempts = 0
    deadline = time.monotonic() + 30.0
    try:
        while attempts < 20000 and time.monotonic() < deadline:
            attempts += 1
            try:
                fd = G.open_authorized(policy, str(target), "w", conf)
                os.close(fd)
                census["ALLOW"] = census.get("ALLOW", 0) + 1
            except G.GuardError as e:
                census[e.decision.code] = census.get(e.decision.code, 0) + 1
            except OSError as e:
                kernel_errors.append(e.errno)
                census["OSERROR:%s" % e.errno] = census.get("OSERROR:%s" % e.errno, 0) + 1
            if victim.exists():
                assert victim.stat().st_size == 4096, (
                    "THE GUARD TRUNCATED A FILE OUTSIDE EVERY ALLOWED ROOT on "
                    "attempt %d. census: %r" % (attempts, census))
            if census.get(G.DENY_RACE, 0) > 0 and attempts >= 2000:
                break
    finally:
        stop.set()
        t.join(timeout=5)
        if os.path.islink(str(root)):
            os.unlink(str(root))
        if hidden.exists() and not root.exists():
            os.rename(str(hidden), str(root))

    assert victim.read_bytes() == victim_before, (
        "a file outside the allowlist changed. census: %r" % census)
    assert (os.stat(victim).st_ino, os.stat(victim).st_dev) == victim_ids
    assert not kernel_errors, (
        "open_authorized exited by errno rather than by policy %d times (%r). A "
        "guard stopped by the kernel is not a guard. census: %r"
        % (len(kernel_errors), sorted(set(kernel_errors)), census))
    assert census.get(G.DENY_RACE, 0) > 0, (
        "DENY_RACE_DETECTED_AT_OPEN was never reached in %d attempts, so this "
        "test proved nothing about it. census: %r" % (attempts, census))
    print("\nrace/root: %d attempts, victim intact, census: %r" % (attempts, census))


def test_ATTACK_a_racing_thread_swapping_a_mid_path_component_hits_the_symlink_clause(
    tmp_path,
):
    import threading
    import time

    base, target, victim = _race_lab(tmp_path, "race-mid")
    root = base / "fixtures"
    sub = root / "sub"
    outside = base / "outside" / "sub"
    hidden = root / "sub.real"
    victim_before = victim.read_bytes()
    policy = G.Policy(roots=[str(root)])
    conf = os.path.realpath(str(target))

    stop = threading.Event()

    def flipper():
        while not stop.is_set():
            try:
                os.rename(str(sub), str(hidden))
                os.symlink(str(outside), str(sub))
                os.unlink(str(sub))
                os.rename(str(hidden), str(sub))
            except OSError:
                pass

    t = threading.Thread(target=flipper, daemon=True)
    t.start()
    census: dict[str, int] = {}
    kernel_errors = []
    attempts = 0
    deadline = time.monotonic() + 30.0
    try:
        while attempts < 20000 and time.monotonic() < deadline:
            attempts += 1
            try:
                fd = G.open_authorized(policy, str(target), "w", conf)
                os.close(fd)
                census["ALLOW"] = census.get("ALLOW", 0) + 1
            except G.GuardError as e:
                census[e.decision.code] = census.get(e.decision.code, 0) + 1
            except OSError as e:
                kernel_errors.append(e.errno)
            if victim.exists():
                assert victim.stat().st_size == 4096, (
                    "THE GUARD TRUNCATED A FILE OUTSIDE EVERY ALLOWED ROOT on "
                    "attempt %d. census: %r" % (attempts, census))
            if census.get(G.DENY_SYMLINK_AT_OPEN, 0) > 0 and attempts >= 500:
                break
    finally:
        stop.set()
        t.join(timeout=5)
        if os.path.islink(str(sub)):
            os.unlink(str(sub))
        if hidden.exists() and not sub.exists():
            os.rename(str(hidden), str(sub))

    assert victim.read_bytes() == victim_before
    assert not kernel_errors, (
        "open_authorized exited by errno rather than by policy: %r. census: %r"
        % (sorted(set(kernel_errors)), census))
    assert census.get(G.DENY_SYMLINK_AT_OPEN, 0) > 0, (
        "DENY_SYMLINK_COMPONENT_AT_OPEN was never reached in %d attempts. "
        "census: %r" % (attempts, census))
    print("\nrace/mid: %d attempts, victim intact, census: %r" % (attempts, census))


def test_redteam_table(capsys, tmp_path):
    tmp = str(tmp_path / "redteam")
    os.mkdir(tmp)
    rows, unchanged = _redteam_rows(tmp)
    w = max(len(r[0]) for r in rows)
    lines = ["", "SENTINELWIPE guard - red team", "=" * (w + 52),
             f"{'attack':<{w}}  {'result':<12} {'clause':<34} ok",
             "-" * (w + 52)]
    for label, res, code, ok in rows:
        lines.append(f"{label:<{w}}  {res:<12} {code:<34} {'.' if ok else 'FAIL'}")
    failed = [r for r in rows if not r[3]]
    lines.append("-" * (w + 52))
    lines.append(f"{len(rows) - len(failed)} of {len(rows)} as expected")
    lines.append(f"victim file outside the root unchanged: {unchanged}")
    print("\n".join(lines))
    assert unchanged, "a file outside the allowed root was modified"
    assert not failed, "\n".join(f"{r[0]}: {r[1]} {r[2]}" for r in failed)
    assert len(rows) >= 50, f"only {len(rows)} attacks exercised"
