"""Smoke tests against a FROZEN bundle (M1.5). Not part of the default test run.

Run explicitly after building (see packaging/BUILD.md):

    uv run --frozen pytest packaging/smoke -p no:cacheprovider --bundle dist/FirewallAI

They execute the real executables, read-only and non-elevated, and print only counts and timings.
"""

import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

CLI = "firewallai-cli.exe"
GUI = "FirewallAI.exe"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--bundle", default="dist/FirewallAI", help="Path to the built FirewallAI folder."
    )


@pytest.fixture(scope="session")
def bundle(pytestconfig: pytest.Config) -> Path:
    path = Path(str(pytestconfig.getoption("--bundle"))).resolve()
    if not (path / CLI).is_file() or not (path / GUI).is_file():
        raise pytest.UsageError(f"no FirewallAI bundle at {path}; build it first")
    return path


def run_cli(
    bundle: Path, *args: str, timeout: float = 180, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(bundle / CLI), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        check=False,
        cwd=cwd or bundle.parent,
    )


def gui_env() -> dict[str, str]:
    return dict(os.environ, QT_QPA_PLATFORM="offscreen")


@pytest.fixture(scope="session")
def spaced_copy(bundle: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """The bundle copied to a path with spaces and non-ASCII characters."""
    target = tmp_path_factory.mktemp("smoke") / "Carpeta con espacios Ñandú" / "FirewallAI"
    shutil.copytree(bundle, target)
    yield target
