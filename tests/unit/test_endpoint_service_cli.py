"""M1.4 endpoint service and CLI: target evaluation, privacy defaults, safe output, exit codes."""

import io
import json
from pathlib import Path
from typing import Any

import pytest

from endpoint_builders import proc, snapshot, sock
from firewallai.app.endpoint_service import (
    ENDPOINTS_PRIVACY_NOTE,
    ENDPOINTS_REPORT_SCHEMA,
    SNAPSHOT_TARGET_S,
    EndpointScanService,
    TargetStatus,
    endpoints_report_to_dict,
    program_path_environment,
)
from firewallai.cli.main import main
from firewallai.collectors.fake.network_endpoints import FixtureEndpointCollector
from firewallai.core.results import CollectorErrorCode

REMOTE = "198.51.100.77"
HOSTILE = "evil\u202egnp.exe\x1b[2J"


def _fixture(tmp_path: Path, **kw: Any) -> Path:
    raw = snapshot(
        [
            sock(lport=8080, pid=1000),
            sock("udp", "ipv6", "2001:db8::10", 5353, pid=1000),
            sock(lport=50000, raddr=REMOTE, rport=443, pid=1000),
        ],
        processes=[proc(1000, name=HOSTILE)],
        **kw,
    )
    path = tmp_path / "endpoints.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _cli(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(["endpoints", *args], out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def _service(raw: Any, times: list[float], **kw: Any) -> EndpointScanService:
    ticks = iter(times)
    return EndpointScanService(
        FixtureEndpointCollector(raw, **kw),
        clock=lambda: next(ticks),
        elevation_check=lambda: False,
    )


def test_target_met_exceeded_and_not_evaluated() -> None:
    raw = snapshot([sock()])
    assert _service(raw, [0.0, 0.4]).scan().target.status is TargetStatus.MET
    exceeded = _service(raw, [0.0, 1.3]).scan().target
    assert exceeded.status is TargetStatus.EXCEEDED and "EXCEEDED" in exceeded.describe()
    assert exceeded.target_s == SNAPSHOT_TARGET_S == 1.0
    no_svc = _service(snapshot([sock()], no_services=True), [0.0, 0.1]).scan().target
    assert no_svc.status is TargetStatus.NOT_EVALUATED  # incomplete snapshot never counts
    failed = _service(raw, [0.0, 0.1], fail_code=CollectorErrorCode.TIMEOUT).scan().target
    assert failed.status is TargetStatus.NOT_EVALUATED
    cancelled = dict(raw, process_lookup_complete=False)
    assert _service(cancelled, [0.0, 0.1]).scan().target.status is TargetStatus.NOT_EVALUATED


def test_target_is_separate_from_n04() -> None:
    report = _service(snapshot([sock()]), [0.0, 0.2]).scan()
    exported = endpoints_report_to_dict(report)
    assert "n04" not in exported
    assert "separate from N-04" in exported["snapshot_target"]["note"]


def test_default_text_hides_remote_addresses(tmp_path: Path) -> None:
    code, out, _ = _cli("--fixture", str(_fixture(tmp_path)))
    assert code == 0
    assert REMOTE not in out
    assert "<hidden>" in out and "--show-remote" in out
    assert "not an exposure, reachability, or firewall assessment" in out


def test_show_remote_is_explicit(tmp_path: Path) -> None:
    _, out, _ = _cli("--fixture", str(_fixture(tmp_path)), "--show-remote")
    assert f"{REMOTE}:443" in out


def test_listening_filter_and_summary(tmp_path: Path) -> None:
    _, out, _ = _cli("--fixture", str(_fixture(tmp_path)), "--listening", "--show-remote")
    assert REMOTE not in out and ":8080" in out and ":5353" in out
    _, summary, _ = _cli("--fixture", str(_fixture(tmp_path)), "--summary")
    assert "Endpoints: 3 (listening TCP 1, bound UDP 1, TCP connections 1" in summary
    assert ":8080" not in summary


def test_untrusted_process_name_is_escaped_in_text(tmp_path: Path) -> None:
    _, out, _ = _cli("--fixture", str(_fixture(tmp_path)))
    assert "\u202e" not in out and "\x1b" not in out
    assert "\\u202e" in out


def test_json_contains_sensitive_data_with_a_privacy_note(tmp_path: Path) -> None:
    code, out, err = _cli("--fixture", str(_fixture(tmp_path)), "--json")
    assert code == 0
    doc = json.loads(out)
    assert doc["schema"] == ENDPOINTS_REPORT_SCHEMA and doc["read_only"] is True
    assert doc["scope"] == "local_socket_facts_only"
    assert doc["note"] == ENDPOINTS_PRIVACY_NOTE and "do not share it publicly" in err
    assert any(e["remote_address"] == REMOTE for e in doc["endpoints"])
    assert doc["endpoints"][0]["process"]["name"]["value"] == HOSTILE  # JSON escapes; data intact


def test_show_remote_applies_only_to_text_output(tmp_path: Path) -> None:
    path = str(_fixture(tmp_path))
    _, plain, err1 = _cli("--fixture", path, "--json")
    _, flagged, err2 = _cli("--fixture", path, "--json", "--show-remote")
    a, b = json.loads(plain), json.loads(flagged)
    assert a["endpoints"] == b["endpoints"]  # JSON always contains remote addresses
    assert err1 == err2 and "do not share it publicly" in err1
    sens = a["sensitivity"]
    assert sens["data_class"] == "host_sensitive" and sens["share_publicly"] is False
    assert sens["remote_addresses_included"] is True
    assert "process command lines" in sens["not_collected"]
    assert "process owners" in sens["not_collected"]


def test_partial_snapshot_exit_code_and_limitation(tmp_path: Path) -> None:
    path = _fixture(tmp_path, no_services=True, services_error="lookup failed")
    code, out, _ = _cli("--fixture", str(path))
    assert code == 0  # fixture snapshot without services is data, not a collector error
    assert "service_lookup_failed" in out and "not evaluated" in out


def test_failed_collection_exit_code(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"first": "nope"}), encoding="utf-8")
    code, out, _ = _cli("--fixture", str(path))
    assert code == 1 and "parse_error" in out


def test_program_path_environment_has_no_user_specific_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\someone")
    env = program_path_environment()
    assert env["SystemRoot"] == "C:\\Windows"
    assert "USERPROFILE" not in env and "APPDATA" not in env
