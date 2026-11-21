"""Where a case lives on disk.

Order of preference, per the XDG base directory spec:

1. ``$OSINT_RAIL_HOME``            (explicit override, used by tests and CI)
2. ``$XDG_STATE_HOME/osint-rail``
3. ``~/.local/state/osint-rail``

Read at call time, not import time, so an environment change in a test is seen.
"""

from __future__ import annotations

import os
from pathlib import Path

APP = "osint-rail"


def state_dir() -> Path:
    explicit = os.environ.get("OSINT_RAIL_HOME", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    xdg = os.environ.get("XDG_STATE_HOME", "").strip()
    if xdg:
        return Path(xdg).expanduser() / APP
    return Path.home() / ".local" / "state" / APP


def default_db() -> Path:
    return state_dir() / "cases.db"


def default_out() -> Path:
    return state_dir() / "cases"
