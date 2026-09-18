from __future__ import annotations

import re
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[1] / "core"

DECL = re.compile(r"^\s*(?:pub\s*(?:\([^)]*\)\s*)?)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
                  re.MULTILINE)

ROOTS = {"lib.rs", "main.rs", "mod.rs"}


def declared_in(path: Path) -> set[str]:
    return set(DECL.findall(path.read_text(encoding="utf-8"))) if path.exists() else set()


def module_files() -> list[tuple[Path, Path, str]]:
    out = []
    for src in sorted(CORE.glob("*/src")):
        for rs in sorted(src.rglob("*.rs")):
            if rs.name in ROOTS:
                continue
            parent = rs.parent
            owner = (parent / "mod.rs") if parent != src else (src / "lib.rs")
            out.append((rs, owner, rs.stem))
        for moddir in sorted(p for p in src.rglob("*") if p.is_dir()):
            if (moddir / "mod.rs").exists():
                owner = ((moddir.parent / "mod.rs") if moddir.parent != src
                         else (src / "lib.rs"))
                out.append((moddir / "mod.rs", owner, moddir.name))
    return out


def test_the_workspace_has_rust_modules_to_check():
    mods = module_files()
    assert len(mods) >= 8, "found only %d module files; the walk is broken" % len(mods)


@pytest.mark.parametrize("rs,owner,name",
                         module_files(),
                         ids=lambda v: v.name if isinstance(v, Path) else str(v))
def test_every_module_file_is_declared(rs: Path, owner: Path, name: str):
    rel = rs.relative_to(CORE.parent)
    assert owner.exists(), "%s has no owning root at %s" % (rel, owner)
    assert name in declared_in(owner), (
        "%s is NOT declared in %s.\n"
        "  It will not compile, its tests will not run, and the suite will still\n"
        "  look green -- exactly how confidence.rs hid for a session.\n"
        "  Add `pub mod %s;` to %s."
        % (rel, owner.relative_to(CORE.parent), name, owner.relative_to(CORE.parent)))
