"""RuleScanService (N-04 evaluation, evidence summary, report) and the ``rules`` CLI."""

import io
import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from firewallai.app.rule_service import (
    N04Status,
    RuleScanService,
    rules_report_to_dict,
)
from firewallai.cli.main import EXIT_FAILED, EXIT_OK, EXIT_PARTIAL, main
from firewallai.collectors.fake.firewall_rules import FixtureFirewallRuleCollector
from rule_builders import complete_fixture


def _service(fixture: dict[str, Any], durations: list[float], **kw: Any) -> RuleScanService:
    ticks = itertools.chain([0.0], durations, itertools.repeat(durations[-1]))
    return RuleScanService(
        FixtureFirewallRuleCollector(fixture, **kw),
        clock=lambda: next(ticks),
        elevation_check=lambda: False,
    )


def test_n04_exceeded_is_reported_with_measured_time() -> None:
    # clock: start=0, inventory=3.0, end=26.6
    report = _service(complete_fixture(), [3.0, 26.6]).scan()
    assert report.n04.status is N04Status.EXCEEDED
    assert report.n04.measured_s == pytest.approx(26.6)
    assert "EXCEEDED" in report.n04.describe()
    assert "over by 16.6 s" in report.n04.describe()
    assert report.inventory_s == pytest.approx(3.0)


def test_n04_met_only_for_complete_full_scan() -> None:
    report = _service(complete_fixture(), [1.0, 8.0]).scan()
    assert report.n04.status is N04Status.MET


def test_n04_not_evaluated_for_inventory_only_cancelled_or_failed() -> None:
    assert _service(complete_fixture(), [1.0, 2.0]).scan(detail=False).n04.status is (
        N04Status.NOT_EVALUATED
    )
    timed_out = _service(complete_fixture(), [1.0, 2.0], fail_after_events=1).scan()
    assert timed_out.n04.status is N04Status.NOT_EVALUATED
    failed = _service({"events": [], "final_error": {"code": "timeout"}}, [1.0]).scan()
    assert failed.n04.status is N04Status.NOT_EVALUATED


def test_report_dict_schema_and_sensitive_note() -> None:
    report = _service(complete_fixture(n=3), [1.0, 2.0]).scan()
    doc = rules_report_to_dict(report)
    assert doc["schema"] == "firewallai.rules/1"
    assert doc["read_only"] is True and doc["scope"] == "local_policy_only"
    assert "host-sensitive" in doc["note"]
    assert doc["n04"]["status"] == "met"
    assert doc["evidence"]["complete"] == 3
    assert "none" in doc["evidence"]["verdicts"]
    assert len(doc["rules"]) == 3
    assert doc["collection"]["detail_complete"] is True
    json.dumps(doc)  # serializable


# --- CLI -----------------------------------------------------------------------------------------


def _write(tmp_path: Path, fixture: dict[str, Any]) -> Path:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def test_cli_rules_json_complete(tmp_path: Path) -> None:
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["rules", "--json", "--fixture", str(_write(tmp_path, complete_fixture()))],
        out=out,
        err=err,
    )
    assert code == EXIT_OK
    doc = json.loads(out.getvalue())
    assert doc["schema"] == "firewallai.rules/1"
    assert "host-sensitive" in err.getvalue()  # warning on stderr for JSON exports
    assert "details" in err.getvalue()  # progress on stderr, not stdout


def test_cli_rules_summary_text(tmp_path: Path) -> None:
    out = io.StringIO()
    code = main(
        ["rules", "--summary", "--fixture", str(_write(tmp_path, complete_fixture()))],
        out=out,
        err=io.StringIO(),
    )
    text = out.getvalue()
    assert code == EXIT_OK
    assert "N-04" in text and "Verdicts: none" in text and "Limitations:" in text
    assert "fw_rule:" not in text  # --summary omits the table


def test_cli_rules_partial_and_failed_exit_codes(tmp_path: Path) -> None:
    partial = complete_fixture()
    partial["final_error"] = {"code": "timeout", "detail": "x"}
    assert (
        main(
            ["rules", "--fixture", str(_write(tmp_path, partial))],
            out=io.StringIO(),
            err=io.StringIO(),
        )
        == EXIT_PARTIAL
    )
    failed = {"events": [], "final_error": {"code": "access_denied"}}
    assert (
        main(
            ["rules", "--fixture", str(_write(tmp_path, failed))],
            out=io.StringIO(),
            err=io.StringIO(),
        )
        == EXIT_FAILED
    )


def test_cli_inventory_only_is_partial_and_not_evaluated(tmp_path: Path) -> None:
    out = io.StringIO()
    code = main(
        [
            "rules",
            "--inventory-only",
            "--json",
            "--fixture",
            str(_write(tmp_path, complete_fixture())),
        ],
        out=out,
        err=io.StringIO(),
    )
    doc = json.loads(out.getvalue())
    assert code == EXIT_PARTIAL
    assert doc["n04"]["status"] == "not_evaluated"
    assert doc["mode"] == "inventory_only"
