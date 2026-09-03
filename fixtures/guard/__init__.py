"""The fixture write guard, in two platform backends behind one API.

Why this is a package and not one module
----------------------------------------
CLAUDE.md rule 4 says a destructive operation refuses to run against any target
that is not on an allowlist. This package is where that rule is enforced for the
Python side, so it is the last place in the tree that should grow ``if os.name``
branches through its decision path. Each platform gets its own implementation and
this file picks one, so neither backend can weaken the other by accident and the
POSIX module -- the one ``fixtures/guard_vectors.json`` was measured against --
stays byte-for-byte what it was.

The two backends are NOT equivalent, and that is published
----------------------------------------------------------
=================  ==================================  =================================
                   posix.py                            windows.py
=================  ==================================  =================================
containment        ``(st_dev, st_ino)`` identity walk   ``(st_dev, st_ino)`` identity walk
link refusal       ``O_NOFOLLOW`` on every component    reparse-point check per component
descent            ``openat`` from the root, per        resolve, then open, then re-check
                   component, re-checked on the fd      on the handle
TOCTOU             hardened                             **not hardened**
device targets     gated, allowlisted, arming required  **always refused**
=================  ==================================  =================================

Windows keeps the inode-identity containment check -- CPython reports a real
volume serial in ``st_dev`` and a real file index in ``st_ino`` there -- so that
row is genuine parity rather than a weaker substitute. The row that is not parity
is the descent: ``os.supports_dir_fd`` is empty on Windows and there is no
``O_NOFOLLOW``, so the path that was checked cannot be proven to be the path that
was opened. See ``windows.py`` and ``docs/architecture.md`` D7.

Nothing here narrows to the weaker backend: the Windows module refuses several
things the POSIX one permits, never the reverse.
"""

from __future__ import annotations

import os

# The package IS the chosen backend -- an alias in sys.modules, not a copy.
# Two façade designs failed before this one, each invisibly:
#   a curated star-import dropped the 28 decision-code constants (77 tests red),
#   and a vars() hoist made COPIES, so monkeypatching fixtures.guard.authorize
#   patched the façade while open_authorized kept calling the backend's own
#   global -- the race-attack tests could no longer install their probe and
#   "DID NOT RAISE" was the symptom. Before the split, fixtures.guard WAS the
#   module; aliasing is the only façade that preserves those semantics exactly.
import sys

if os.name == "nt":
    from fixtures.guard import windows as _backend
    if not hasattr(_backend, "BACKEND"):
        _backend.BACKEND = "windows"
else:
    from fixtures.guard import posix as _backend
    if not hasattr(_backend, "BACKEND"):
        #: Which implementation answered. On the module so a caller, a test or a
        #: certificate can record it rather than infer it from the host.
        _backend.BACKEND = "posix"

_backend.__path__ = __path__          # keep `import fixtures.guard.windows` working
sys.modules[__name__] = _backend      # fixtures.guard is now the backend itself
