"""SB-01/SB-02/SB-05/SB-20 and Q4 privacy for M1.4 (endpoint collection and correlation).

- Only read-only psutil APIs are used, only in the Windows endpoint collector; no command lines,
  process owners, environment, or process control (kill/suspend/priority/affinity).
- The service script is local, read-only, and requests only service names and PIDs.
- No logging, printing, elevation, or firewall/network writes in the M1.4 modules.
- No output claims reachability, exposure, or permission (SB-20).
"""

import ast
import io
import json
import re
from pathlib import Path

import pytest

from endpoint_builders import proc, snapshot, sock
from firewallai.cli.main import main
from firewallai.collectors.windows.scripts import REGISTERED_SCRIPTS, WIN32_SERVICES
from firewallai.core.correlation import CORRELATION_DISCLAIMER

pytestmark = pytest.mark.security

SRC = Path(__file__).resolve().parents[2] / "src" / "firewallai"
COLLECTOR = SRC / "collectors" / "windows" / "network_endpoints.py"
M14_MODULES = [
    SRC / "core" / "endpoints.py",
    SRC / "core" / "correlation.py",
    SRC / "collectors" / "endpoint_assembly.py",
    SRC / "collectors" / "fake" / "network_endpoints.py",
    COLLECTOR,
    SRC / "app" / "endpoint_service.py",
]

PSUTIL_ALLOWED = frozenset({"net_connections", "Process", "NoSuchProcess", "AccessDenied", "Error"})
PROCESS_METHODS_ALLOWED = frozenset({"name", "exe", "oneshot"})
FORBIDDEN_PROCESS_API = (
    "cmdline",
    "username",
    "environ",
    "open_files",
    "memory_maps",
    "kill",
    "terminate",
    "suspend",
    "resume",
    "send_signal",
    "nice",
    "ionice",
    "cpu_affinity",
    "rlimit",
    "children",
    "connections",
)
FORBIDDEN_CLAIMS = (
    "is reachable",
    "is exposed",
    "exposed to",
    "is allowed",
    "is blocked",
    "allows traffic",
    "blocks traffic",
    "open to the internet",
    "vulnerable",
)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def test_psutil_is_imported_only_by_the_windows_endpoint_collector() -> None:
    importers = set()
    for path in SRC.rglob("*.py"):
        for node in ast.walk(_tree(path)):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(n == "psutil" or n.startswith("psutil.") for n in names):
                importers.add(path)
    assert importers == {COLLECTOR}


def test_only_read_only_psutil_apis_are_used() -> None:
    tree = _tree(COLLECTOR)
    used = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "psutil"
    }
    assert used <= PSUTIL_ALLOWED, used - PSUTIL_ALLOWED
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "proc"
    }
    assert called <= PROCESS_METHODS_ALLOWED, called - PROCESS_METHODS_ALLOWED
    text = COLLECTOR.read_text(encoding="utf-8")
    for api in FORBIDDEN_PROCESS_API:
        assert not re.search(rf"\.{api}\b", text), api


def test_service_script_is_local_read_only_and_minimal() -> None:
    assert WIN32_SERVICES in REGISTERED_SCRIPTS
    assert WIN32_SERVICES.allowed_commands == frozenset({"Get-CimInstance"})
    body = WIN32_SERVICES.body.lower()
    assert "-computername" not in body and "-cimsession" not in body  # local machine only
    assert "win32_service" in body and "invoke-cimmethod" not in body
    requested = re.search(r"\$fwaiprops = @\(([^)]*)\)", body)
    assert requested is not None
    assert {p.strip(" '") for p in requested.group(1).split(",")} == {"name", "processid"}
    for private in ("pathname", "startname", "commandline", "description"):
        assert private not in body
    assert WIN32_SERVICES.timeout_s <= 15 and WIN32_SERVICES.max_output_bytes <= 1024 * 1024


@pytest.mark.parametrize("path", M14_MODULES, ids=lambda p: p.name)
def test_m14_modules_do_not_log_print_elevate_or_write(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    lowered = text.lower()
    for token in ("import logging", "print(", "runas", "shellexecute", "netsh", "subprocess"):
        assert token not in lowered, token
    for verb in ("Set-", "New-", "Remove-", "Enable-", "Disable-", "Invoke-"):
        assert not re.search(rf"\b{verb}Net", text), verb


def test_cli_output_never_claims_reachability_or_permission(tmp_path: Path) -> None:
    raw = snapshot(
        [
            sock(lport=8080, pid=1000),
            sock(lport=50000, raddr="198.51.100.9", rport=443, pid=1000),
        ],
        processes=[proc(1000)],
    )
    path = tmp_path / "f.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    texts = [CORRELATION_DISCLAIMER]
    for args in ([], ["--show-remote"], ["--summary"], ["--json"]):
        out, err = io.StringIO(), io.StringIO()
        main(["endpoints", "--fixture", str(path), *args], out=out, err=err)
        texts += [out.getvalue(), err.getvalue()]
    blob = " ".join(texts).lower()
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in blob, claim
