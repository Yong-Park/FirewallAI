"""Read-only privilege check (SB-02: FirewallAI must not run elevated)."""

import sys


def is_elevated() -> bool | None:
    """True if the current process is elevated, False if not, None if it cannot be determined."""
    if sys.platform != "win32":
        return None
    import ctypes  # Windows-only API access

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return None
