"""Frozen-bundle smoke tests (M1.5): CLI, privacy, N-04 reporting, GUI launch, child environment,
standard-user execution, read-only install directory, and paths with spaces/non-ASCII."""

import json
import re
import subprocess
import time
from pathlib import Path

import psutil
import pytest

from conftest import CLI, GUI, gui_env, run_cli

PRIVACY = "do not share it publicly"
HOSTILE = "evil\u202egnp.exe\x1b[2J"


def _tree_state(root: Path) -> dict[str, tuple[int, int]]:
    return {
        p.relative_to(root).as_posix(): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in root.rglob("*")
        if p.is_file()
    }


@pytest.fixture(scope="module")
def install_state(bundle: Path) -> dict[str, tuple[int, int]]:
    return _tree_state(bundle)


def test_cli_version_without_python(bundle: Path) -> None:
    result = run_cli(bundle, "--version")
    assert result.returncode == 0
    assert result.stdout.strip() == "firewallai 0.1.0.dev0"


def test_profiles_json_standard_user(bundle: Path) -> None:
    result = run_cli(bundle, "profiles", "--json")
    assert result.returncode == 0, result.stderr[-500:]
    doc = json.loads(result.stdout)
    assert doc["elevated"] is False  # the frozen app itself reports non-elevated execution
    assert {p["name"] for p in doc["profiles"]} == {"domain", "private", "public"}


def test_rules_scan_reports_n04_unchanged(bundle: Path) -> None:
    started = time.perf_counter()
    result = run_cli(bundle, "rules", "--summary", timeout=300)
    elapsed = time.perf_counter() - started
    assert result.returncode in (0, 3), result.stderr[-500:]
    n04 = [line for line in result.stdout.splitlines() if "N-04" in line]
    assert n04, "the N-04 status must always be reported"
    assert "Verdicts: none" in result.stdout
    print(f"\n[frozen] rules --summary: {elapsed:.1f} s; {n04[0].strip()}")


def test_endpoints_text_hides_remote_addresses(bundle: Path) -> None:
    result = run_cli(bundle, "endpoints")
    assert result.returncode in (0, 3), result.stderr[-500:]
    out = result.stdout
    assert "not an exposure, reachability, or firewall assessment" in out
    rows = [line for line in out.splitlines() if re.match(r"^(tcp|udp)\s", line)]
    connections = [r for r in rows if " connection " in r]
    assert all("<hidden>" in r for r in connections)
    target = [line for line in out.splitlines() if "Endpoint snapshot target" in line]
    assert target
    print(f"\n[frozen] endpoints: {len(rows)} rows; {target[0].strip()}")


def test_endpoints_json_is_marked_sensitive(bundle: Path) -> None:
    plain = run_cli(bundle, "endpoints", "--json")
    flagged = run_cli(bundle, "endpoints", "--json", "--show-remote")
    for result in (plain, flagged):
        assert result.returncode in (0, 3)
        assert PRIVACY in result.stderr
        doc = json.loads(result.stdout)
        assert doc["sensitivity"]["share_publicly"] is False
        assert doc["sensitivity"]["remote_addresses_included"] is True
        assert "process command lines" in doc["sensitivity"]["not_collected"]


def test_untrusted_names_are_escaped_in_frozen_text(bundle: Path, tmp_path: Path) -> None:
    sock = {
        "protocol": "tcp",
        "family": "ipv4",
        "local_address": "192.0.2.10",
        "local_port": 8080,
        "remote_address": None,
        "remote_port": None,
        "status": "LISTEN",
        "pid": 1000,
    }
    raw = {
        "first": [sock],
        "second": [sock],
        "processes": [
            {
                "pid": 1000,
                "exited": False,
                "name": {"value": HOSTILE, "error": None},
                "exe": {"value": "C:\\Synthetic\\a.exe", "error": None},
            }
        ],
        "services": [],
        "services_error": None,
    }
    fixture = tmp_path / "endpoints.json"
    fixture.write_text(json.dumps(raw), encoding="utf-8")
    result = run_cli(bundle, "endpoints", "--fixture", str(fixture))
    assert result.returncode == 0
    assert "\u202e" not in result.stdout and "\x1b" not in result.stdout
    assert "\\u202e" in result.stdout


def _find_powershell_child(parent: psutil.Process, deadline: float) -> psutil.Process | None:
    while time.monotonic() < deadline:
        try:
            for child in parent.children(recursive=True):
                if child.name().lower() == "powershell.exe":
                    return child
        except psutil.NoSuchProcess:
            return None
        time.sleep(0.02)
    return None


def test_gui_launches_and_powershell_child_gets_a_sanitized_environment(bundle: Path) -> None:
    """GUI start (offscreen): it refreshes profiles at start-up, which spawns PowerShell. The
    child's environment must not contain PyInstaller values (human decision Q7)."""
    proc = subprocess.Popen([str(bundle / GUI)], env=gui_env())
    try:
        parent = psutil.Process(proc.pid)
        child = _find_powershell_child(parent, time.monotonic() + 15)
        assert child is not None, "no PowerShell child observed"
        env = child.environ()
        internal = str(bundle / "_internal").lower()
        assert not any(k.upper().startswith("_PYI_") for k in env)
        assert not any(e.lower().startswith(internal) for e in env.get("PATH", "").split(";"))
        assert "QT_PLUGIN_PATH" not in env or internal not in env["QT_PLUGIN_PATH"].lower()
        # PSModulePath is not asserted here: PowerShell 5.1 rewrites it at start-up (it inserts
        # %ProgramFiles%\WindowsPowerShell\Modules), and reading another process's environment
        # block after that is unreliable (M1.5 finding; see HANDOFF.md). What the runner PASSES is
        # covered by tests/security/test_powershell_runner.py.
        assert internal not in env.get("PSModulePath", "").lower()
        time.sleep(3)
        assert proc.poll() is None, "GUI exited unexpectedly"
    finally:
        proc.terminate()
        proc.wait(15)


def test_gui_starts_quickly(bundle: Path) -> None:
    """Time until the GUI process has created its first PowerShell child (start-up + first
    collection request): an upper bound for window start-up. Printed, not asserted strictly."""
    started = time.perf_counter()
    proc = subprocess.Popen([str(bundle / GUI)], env=gui_env())
    try:
        child = _find_powershell_child(psutil.Process(proc.pid), time.monotonic() + 30)
        elapsed = time.perf_counter() - started
        assert child is not None
        print(f"\n[frozen] GUI start to first collection: {elapsed:.2f} s")
        assert elapsed < 15
    finally:
        proc.terminate()
        proc.wait(15)


def test_install_directory_is_not_written(
    bundle: Path, install_state: dict[str, tuple[int, int]]
) -> None:
    run_cli(bundle, "--version")
    run_cli(bundle, "profiles")
    proc = subprocess.Popen([str(bundle / GUI)], env=gui_env())
    time.sleep(4)
    proc.terminate()
    proc.wait(15)
    assert _tree_state(bundle) == install_state  # no new, changed, or removed files


def test_runs_from_a_path_with_spaces_and_non_ascii(spaced_copy: Path) -> None:
    assert run_cli(spaced_copy, "--version").returncode == 0
    result = run_cli(spaced_copy, "profiles", "--json")
    assert result.returncode == 0, result.stderr[-500:]
    assert json.loads(result.stdout)["elevated"] is False


def test_both_executables_present_without_collision(bundle: Path) -> None:
    names = {p.name.lower() for p in bundle.iterdir() if p.suffix.lower() == ".exe"}
    assert names == {GUI.lower(), CLI.lower()}
