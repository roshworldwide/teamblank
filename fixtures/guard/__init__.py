from __future__ import annotations

import os
import sys

if os.name == "nt":
    from fixtures.guard import windows as _backend
    if not hasattr(_backend, "BACKEND"):
        _backend.BACKEND = "windows"
else:
    from fixtures.guard import posix as _backend
    if not hasattr(_backend, "BACKEND"):
        _backend.BACKEND = "posix"

_backend.__path__ = __path__
sys.modules[__name__] = _backend
