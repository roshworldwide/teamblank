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

if os.name == "nt":
    from fixtures.guard.windows import *  # noqa: F401,F403
    from fixtures.guard.windows import (  # noqa: F401
        _whole_disk,
        BACKEND,
        Decision,
        GuardError,
        Policy,
        PolicyError,
    )
else:
    from fixtures.guard.posix import *  # noqa: F401,F403
    from fixtures.guard.posix import (  # noqa: F401
        _whole_disk,
        Decision,
        GuardError,
        Policy,
        PolicyError,
    )

    #: Which implementation answered. Present on both backends so a caller, a
    #: test or a certificate can record it rather than infer it from the host.
    BACKEND = "posix"
