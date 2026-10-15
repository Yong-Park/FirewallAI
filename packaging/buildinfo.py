"""Build metadata for the packaged app (M1.5): single-sourced version, source commit, names.

No subprocesses: the git commit is read from the ``.git`` directory files directly.
"""

import re
import tomllib
from pathlib import Path

from packaging.version import Version

APP_NAME = "FirewallAI"
GUI_EXE = "FirewallAI"  # FirewallAI.exe: GUI, no console
CLI_EXE = "firewallai-cli"  # firewallai-cli.exe: console (distinct even case-insensitively)
COMPANY = "FirewallAI project (open source, MIT)"
_VERSION_LINE = re.compile(r'^__version__\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_SHA = re.compile(r"^[0-9a-f]{40}$")


def project_version(root: Path) -> str:
    """The single version source (``pyproject.toml``); must equal ``firewallai.__version__``."""
    declared = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    init = (root / "src" / "firewallai" / "__init__.py").read_text(encoding="utf-8")
    match = _VERSION_LINE.search(init)
    if match is None or match.group(1) != declared:
        raise ValueError("pyproject.toml version and firewallai.__version__ differ")
    Version(declared)  # must be a valid PEP 440 version
    return str(declared)


def file_version(version: str) -> tuple[int, int, int, int]:
    """Windows FILEVERSION (4 integers) from a PEP 440 version: 0.1.0.dev0 -> (0, 1, 0, 0)."""
    release = list(Version(version).release)[:4]
    while len(release) < 4:
        release.append(0)
    return (release[0], release[1], release[2], release[3])


def git_commit(root: Path) -> str | None:
    """The checked-out commit, read from ``.git`` files; None if it cannot be determined."""
    git = root / ".git"
    if not git.is_dir():
        return None
    head = (git / "HEAD").read_text(encoding="utf-8").strip()
    if _SHA.match(head):
        return head
    if not head.startswith("ref: "):
        return None
    ref = head[5:].strip()
    loose = git / ref
    if loose.is_file():
        value = loose.read_text(encoding="utf-8").strip()
        return value if _SHA.match(value) else None
    packed = git / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            parts = line.split(" ")
            if len(parts) == 2 and parts[1] == ref and _SHA.match(parts[0]):
                return parts[0]
    return None


def artifact_stem(version: str, commit: str | None) -> str:
    suffix = f"-g{commit[:8]}" if commit else ""
    return f"{APP_NAME}-{version}{suffix}-win64-portable"
