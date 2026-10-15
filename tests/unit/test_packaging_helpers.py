"""M1.5 packaging helpers (packaging/buildinfo.py, packaging/make_icon.py), run from source."""

import importlib.util
import struct
from pathlib import Path
from types import ModuleType

import pytest

import firewallai

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "packaging" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


buildinfo = _load("buildinfo")


def test_version_is_single_sourced() -> None:
    assert buildinfo.project_version(ROOT) == firewallai.__version__


def test_version_mismatch_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "src" / "firewallai").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0"\n', encoding="utf-8")
    (tmp_path / "src" / "firewallai" / "__init__.py").write_text(
        '__version__ = "0.1.0"\n', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="differ"):
        buildinfo.project_version(tmp_path)


@pytest.mark.parametrize(
    ("version", "expected"),
    [("0.1.0.dev0", (0, 1, 0, 0)), ("1.2", (1, 2, 0, 0)), ("1.2.3.4", (1, 2, 3, 4))],
)
def test_windows_file_version(version: str, expected: tuple[int, ...]) -> None:
    assert buildinfo.file_version(version) == expected


SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(
    ("layout", "expected"),
    [
        ({"HEAD": "ref: refs/heads/main\n", "refs/heads/main": SHA + "\n"}, SHA),
        ({"HEAD": SHA + "\n"}, SHA),  # detached
        ({"HEAD": "ref: refs/heads/x\n", "packed-refs": f"# pack\n{SHA} refs/heads/x\n"}, SHA),
        ({"HEAD": "ref: refs/heads/missing\n"}, None),
        ({"HEAD": "ref: refs/heads/main\n", "refs/heads/main": "not-a-sha\n"}, None),
    ],
    ids=["loose-ref", "detached", "packed-ref", "missing-ref", "invalid"],
)
def test_git_commit_without_subprocess(
    tmp_path: Path, layout: dict[str, str], expected: str | None
) -> None:
    for rel, text in layout.items():
        path = tmp_path / ".git" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert buildinfo.git_commit(tmp_path) == expected
    assert buildinfo.git_commit(tmp_path / "no-repo") is None


def test_artifact_names_and_executable_names() -> None:
    assert buildinfo.artifact_stem("0.1.0.dev0", SHA) == (
        "FirewallAI-0.1.0.dev0-g01234567-win64-portable"
    )
    assert buildinfo.artifact_stem("0.1.0", None) == "FirewallAI-0.1.0-win64-portable"
    assert buildinfo.GUI_EXE.lower() != buildinfo.CLI_EXE.lower()  # no case-insensitive clash


def test_icon_is_a_valid_deterministic_multi_size_ico() -> None:
    make_icon = _load("make_icon")
    data = make_icon.build_ico()
    assert data == make_icon.build_ico()  # deterministic
    reserved, kind, count = struct.unpack_from("<HHH", data)
    assert (reserved, kind, count) == (0, 1, len(make_icon.SIZES))
    for i, size in enumerate(make_icon.SIZES):
        w, h, _, _, planes, bits, length, offset = struct.unpack_from("<BBBBHHII", data, 6 + 16 * i)
        assert (w or 256, h or 256) == (size, size) and planes == 1 and bits == 32
        assert data[offset : offset + 8] == b"\x89PNG\r\n\x1a\n" and length > 0
