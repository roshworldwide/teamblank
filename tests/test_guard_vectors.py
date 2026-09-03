"""The Python half of the shared guard conformance table.

READY TO COMMIT AS tests/test_guard_vectors.py. It is written here rather than
under tests/ because tests/ was not this task's to write; see the Phase 3 report.

fixtures/guard_vectors.json is the committed contract between the two write-guard
implementations. `core/device/src/guard.rs` runs every row in its own
`conformance` module; this file runs the same rows against `fixtures/guard.py`.
Neither implementation may drift from the table without a test going red.

The expectations in the table were MEASURED from fixtures/guard.py. That is not
circular: the point of this file is that they stay measured from it. If someone
edits guard.py, this goes red. If someone edits guard.rs, the Rust test goes red.
If someone edits the table to make either pass, the OTHER one goes red.

Run: uv run pytest -q tests/test_guard_vectors.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from fixtures import guard as G  # noqa: E402

VECTORS = _REPO / "fixtures" / "guard_vectors.json"


def _subst(s: str, sub: dict) -> str:
    for k, v in sub.items():
        if v is not None:
            s = s.replace(k, v)
    return s


def _build_lab(spec: dict, base: str) -> None:
    for d in spec["dirs"]:
        os.makedirs(os.path.join(base, d), exist_ok=True)
    for f in spec["files"]:
        with open(os.path.join(base, f["path"]), "wb") as fh:
            fh.write(bytes([f["fill"]]) * f["bytes"])
    real = os.path.realpath(base)
    sub = {"{lab_real}": real, "{lab}": base}
    for s in spec["symlinks"]:
        os.symlink(_subst(s["to"], sub), os.path.join(base, s["link"]))
    for h in spec["hardlinks"]:
        os.link(_subst(h["to"], sub), os.path.join(base, h["link"]))
    for p in spec["fifos"]:
        os.mkfifo(os.path.join(base, p))


def _policy(spec: dict, sub: dict) -> G.Policy:
    kw = {"roots": [_subst(r, sub) for r in spec.get("roots", [])]}
    if "devices" in spec:
        kw["devices"] = [_subst(d, sub) for d in spec["devices"]]
    for k in ("allow_device_targets", "require_confirmation", "min_file_bytes",
              "max_file_bytes"):
        if k in spec:
            kw[k] = spec[k]
    return G.Policy(**kw)


def _target(t: dict, sub: dict):
    kind = t["kind"]
    if kind == "path":
        return _subst(t["tpl"], sub), None
    if kind == "volfs":
        st = os.stat(_subst(t["of"], sub))
        return "/.vol/%d/%d%s" % (st.st_dev, st.st_ino, t.get("suffix", "")), None
    if kind == "devfd":
        fd = os.open(_subst(t["of"], sub), os.O_RDONLY)
        return "/dev/fd/%d" % fd, fd
    raise AssertionError(kind)


def _conf(c, target, sub):
    if c is None:
        return None
    k = c["kind"]
    if k == "literal":
        return _subst(c["tpl"], sub)
    if k == "resolved":
        return os.path.realpath(target)
    if k == "resolved_drop_last":
        return os.path.realpath(target)[:-1]
    if k == "resolved_plus":
        return os.path.realpath(target) + c["suffix"]
    raise AssertionError(k)


def _met(req: str, sub: dict) -> bool:
    if req == "darwin":
        return sys.platform == "darwin"
    if req == "volfs":
        return os.path.isdir("/.vol")
    if req == "boot_device":
        return sub.get("{boot_device}") is not None
    if req == "boot_whole_disk":
        w = sub.get("{boot_whole_disk}")
        return w is not None and os.path.exists(w)
    if req.startswith("path_exists:"):
        return os.path.exists(_subst(req[len("path_exists:"):], sub))
    raise AssertionError(req)


@pytest.fixture(scope="module")
def table():
    return json.loads(VECTORS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def lab(table, tmp_path_factory):
    # tmp_path_factory sits under the system temp directory, which on macOS is
    # reached through a symlinked ancestor -- which is what makes the two
    # aliasing control rows real rather than decorative.
    base = str(tmp_path_factory.mktemp("sw-guard-vectors"))
    _build_lab(table["lab"], base)
    real = os.path.realpath(base)
    boot = G.root_backing_device()
    return {
        "{lab_real_first_component}": "/" + [p for p in real.split("/") if p][0],
        "{lab_real}": real,
        "{lab}": base,
        "{home}": os.path.realpath(os.path.expanduser("~")),
        "{boot_whole_disk}": ("/dev/" + G._whole_disk(boot)) if boot else None,
        "{boot_device}": boot,
    }


def test_the_table_is_present_and_not_vacuous(table):
    """Guard the guard: a truncated table would make every assertion below pass
    while measuring nothing."""
    assert table["schema"] == "sentinelwipe.guard_vectors/1"
    rows, pol = table["rows"], table["policy_rows"]
    assert len(rows) >= 80, len(rows)
    assert len(pol) >= 18, len(pol)
    allows = [r for r in rows if r["expect_allowed"]]
    denies = [r for r in rows if not r["expect_allowed"]]
    assert len(allows) >= 15, "a table of only refusals proves nothing"
    assert len(denies) >= 60
    assert any(r.get("expect_code") == G.ALLOW_DEVICE for r in rows), \
        "no ALLOW_DEVICE row: the device path could be refusing everything"
    assert any("MEASURED DEFECT" in r["name"] for r in rows), \
        "the regression row for the boot-disk defect is missing"


def test_every_code_the_python_guard_can_produce_is_accounted_for(table):
    """The other half of the Rust `every_code_is_accounted_for` check.

    A code is accounted for in exactly one of three ways: a row exercises it,
    `codes_not_exercised` states why it is unreachable on this host, or
    `codes_exercised_by_race_test` names a RACING test in each language that
    reaches it, with the measured census from both.

    The third bucket exists because the second one used to hold
    DENY_RACE_DETECTED_AT_OPEN and DENY_SYMLINK_COMPONENT_AT_OPEN -- the two
    clauses guarding the window between the decision and the open -- excused as
    "not expressible in a static table in either language".  While that excuse
    stood, all 85 rows passed in both languages against two guards that would
    truncate a file outside every allowed root under a racing rename.  A clause
    no test reaches is not a guard, and an excuse is not a measurement.
    """
    codes = {v for k, v in vars(G).items()
             if k.startswith(("DENY_", "ALLOW_")) and isinstance(v, str)}
    assert len(codes) >= 25, codes

    seen = set()
    for row in table["rows"]:
        if "expect_code" in row:
            seen.add(row["expect_code"])
        seen.update(row.get("expect_code_any", []))
        if row.get("expect_open_code"):
            seen.add(row["expect_open_code"])

    excused = {k: v for k, v in table["codes_not_exercised"].items()
               if not k.startswith("_")}
    for k, v in excused.items():
        assert isinstance(v, str) and v.strip(), "%s is excused without a reason" % k

    raced = {k: v for k, v in table["codes_exercised_by_race_test"].items()
             if not k.startswith("_")}
    guard_py_tests = (_REPO / "tests" / "test_guard.py").read_text(encoding="utf-8")
    guard_rs = (_REPO / "core" / "device" / "src" / "guard.rs").read_text(encoding="utf-8")
    for code, entry in raced.items():
        for field in ("rust_test", "python_test", "measured_rust", "measured_python"):
            assert entry.get(field, "").strip(), "%s.%s is empty" % (code, field)
        # The named tests must EXIST.  A table naming a test nobody wrote is the
        # same paper excuse wearing a different field name.
        pleaf = entry["python_test"].rsplit("::", 1)[-1]
        assert ("def %s(" % pleaf) in guard_py_tests, \
            "%s.python_test names %s, which is not in tests/test_guard.py" % (code, pleaf)
        rleaf = entry["rust_test"].rsplit("::", 1)[-1]
        assert ("fn %s(" % rleaf) in guard_rs, \
            "%s.rust_test names %s, which is not in core/device/src/guard.rs" % (code, rleaf)
    assert {G.DENY_RACE, G.DENY_SYMLINK_AT_OPEN} <= set(raced), \
        "the two open-time race clauses must be accounted for by a race test"

    unaccounted = codes - seen - set(excused) - set(raced)
    assert not unaccounted, \
        "codes neither exercised, excused, nor raced: %r" % sorted(unaccounted)
    named = (seen | set(excused) | set(raced)) - codes
    assert not named, "the table names codes guard.py cannot produce: %r" % sorted(named)


def test_every_row_agrees_with_guard_py(table, lab, capsys):
    checked = 0
    skipped = []
    failures = []
    refusals = 0
    allows = 0

    for row in table["rows"]:
        name = row["name"]
        if not all(_met(q, lab) for q in row["requires"]):
            skipped.append(name)
            continue
        pol = _policy(table["policies"][row["policy"]], lab)
        target, fd = _target(row["target"], lab)
        conf = _conf(row["confirmation"], target, lab)
        kw = {} if row["platform"] == "native" else {"_platform": row["platform"]}
        try:
            d = G.authorize(pol, target, conf, mode=row["mode"], env=row["env"], **kw)
        except Exception as e:                    # authorize must never raise
            failures.append(f"{name}: authorize RAISED {type(e).__name__}: {e}")
            if fd is not None:
                os.close(fd)
            continue

        if d.allowed != row["expect_allowed"]:
            failures.append(f"{name}: allowed={d.allowed} want {row['expect_allowed']} "
                            f"(code {d.code})")
        if "expect_code_any" in row:
            if d.code not in row["expect_code_any"]:
                failures.append(f"{name}: code {d.code} not in the admitted set")
        elif d.code != row["expect_code"]:
            failures.append(f"{name}: code {d.code} want {row['expect_code']}")
        if d.kind != row["expect_kind"]:
            failures.append(f"{name}: kind {d.kind} want {row['expect_kind']}")
        if d.allowed:
            allows += 1
        else:
            refusals += 1
            if not d.code.startswith("DENY_"):
                failures.append(f"{name}: refusal code {d.code} is not a DENY_")

        if row["open"]:
            got_fd = False
            try:
                ofd = G.open_authorized(pol, target, row["mode"], conf, env=row["env"])
                got_fd = True
                os.close(ofd)
                if not row["expect_fd"]:
                    failures.append(f"{name}: DESCRIPTOR OBTAINED on a refused row")
            except G.GuardError as e:
                if row["expect_fd"]:
                    failures.append(f"{name}: open refused with {e.decision.code}")
                elif e.decision.code != row["expect_open_code"]:
                    failures.append(f"{name}: open code {e.decision.code} want "
                                    f"{row['expect_open_code']}")
            except OSError as e:
                failures.append(
                    f"{name}: open refused by errno {e.errno}, NOT by policy. A guard "
                    f"stopped by the kernel is not a guard.")
            del got_fd
        if fd is not None:
            os.close(fd)
        checked += 1

    pol_checked = 0
    for row in table["policy_rows"]:
        if not all(_met(q, lab) for q in row.get("requires", [])):
            skipped.append(row["name"])
            continue
        try:
            _policy(row, lab)
            got = "OK"
        except G.PolicyError:
            got = "POLICY_ERROR"
        if got != row["expect"]:
            failures.append(f"{row['name']}: policy {got} want {row['expect']}")
        pol_checked += 1

    victim = os.path.join(lab["{lab_real}"], "outside", "victim.img")
    with open(victim, "rb") as fh:
        body = fh.read()
    assert set(body) == {0xAA}, "a file OUTSIDE the allowed root was modified"

    print(f"\nSENTINELWIPE guard - Python conformance against fixtures/"
          f"guard_vectors.json\n{checked} target rows + {pol_checked} policy rows "
          f"executed, {len(skipped)} skipped\n{refusals} refusals, {allows} allows, "
          f"{len(failures)} failures\nskipped: {skipped}")

    assert checked >= 80, f"only {checked} rows executed; the table is skipping itself"
    assert not failures, "guard.py disagrees with the committed table:\n  " + \
        "\n  ".join(failures)


def test_the_policy_digest_payload_is_what_the_table_records(table, lab):
    """The Rust guard cannot compute SHA-256 without a new dependency, so the
    table records the canonical PAYLOAD both implementations must produce. This
    asserts guard.py's end of that; core/device/src/guard.rs asserts the other."""
    import hashlib
    checked = 0
    for name, spec in table["policies"].items():
        tpl = spec.get("digest_payload_tpl")
        if tpl is None:
            continue
        if "{boot_" in tpl and any(
                lab.get(k) is None for k in ("{boot_device}", "{boot_whole_disk}")):
            continue
        pol = _policy(spec, lab)
        payload = json.dumps(
            {"roots": sorted(os.path.realpath(r) for r in pol.roots),
             "devices": list(pol.devices),
             "allow_device_targets": pol.allow_device_targets,
             "require_confirmation": pol.require_confirmation,
             "min_file_bytes": pol.min_file_bytes,
             "max_file_bytes": pol.max_file_bytes},
            sort_keys=True, separators=(",", ":"))
        assert payload == _subst(tpl, lab), name
        assert hashlib.sha256(payload.encode()).hexdigest() == pol.digest(), name
        checked += 1
    assert checked >= 8, f"only {checked} policy payloads checked"
