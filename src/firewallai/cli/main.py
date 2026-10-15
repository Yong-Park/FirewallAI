"""``firewallai`` CLI. Read-only; no network access.

Exit codes: 0 = complete, 1 = collection failed, 2 = usage error, 3 = partial/incomplete data.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from firewallai import __version__
from firewallai.app.endpoint_service import (
    ENDPOINT_SCOPE_NOTE,
    ENDPOINTS_PRIVACY_NOTE,
    EndpointScanReport,
    create_endpoint_scan_service,
    endpoints_report_to_dict,
    summarize,
)
from firewallai.app.profile_service import (
    SCOPE_NOTE,
    ProfileReport,
    create_profile_service,
    report_to_dict,
)
from firewallai.app.rule_service import (
    SENSITIVE_EXPORT_NOTE,
    RuleScanReport,
    create_rule_scan_service,
    rules_report_to_dict,
)
from firewallai.core.endpoints import Endpoint, EndpointKind, display_safe
from firewallai.core.rules import FilterResult, FilterState, FirewallRule

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_PARTIAL = 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firewallai", description="Read-only Windows Firewall auditor."
    )
    parser.add_argument("--version", action="version", version=f"firewallai {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    profiles = sub.add_parser("profiles", help="Show effective firewall profile settings.")
    profiles.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    profiles.add_argument(
        "--fixture",
        type=Path,
        default=None,
        help="Read a recorded raw payload instead of the live system (testing/development).",
    )
    rules = sub.add_parser(
        "rules", help="Collect ActiveStore firewall rules (read-only; may take tens of seconds)."
    )
    rules.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    rules.add_argument("--summary", action="store_true", help="Print only the summary.")
    rules.add_argument(
        "--inventory-only",
        action="store_true",
        help="Skip per-rule port/address/interface filters (faster; evidence stays incomplete).",
    )
    rules.add_argument(
        "--fixture", type=Path, default=None, help="Replay a recorded/synthetic event fixture."
    )
    endpoints = sub.add_parser(
        "endpoints",
        help="Show local listening/bound sockets and TCP connections with owning processes "
        "(read-only; not a reachability assessment).",
    )
    endpoints.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON. It includes remote addresses: do not share it publicly.",
    )
    endpoints.add_argument("--summary", action="store_true", help="Print only the summary.")
    endpoints.add_argument(
        "--listening", action="store_true", help="Only listening TCP and bound UDP endpoints."
    )
    endpoints.add_argument(
        "--show-remote",
        action="store_true",
        help="Show remote addresses of TCP connections (hidden by default; host-sensitive).",
    )
    endpoints.add_argument(
        "--fixture", type=Path, default=None, help="Read a synthetic snapshot fixture."
    )
    return parser


def _exit_code(report: ProfileReport) -> int:
    if report.result.data is None:
        return EXIT_FAILED
    return EXIT_PARTIAL if report.result.partial else EXIT_OK


def _print_text(report: ProfileReport, out: TextIO) -> None:
    out.write(f"{SCOPE_NOTE}\n\n")
    header = (
        f"{'Profile':<9} {'Enabled':<15} {'Inbound':<15} {'Outbound':<15} {'Inbound rules':<15}"
    )
    out.write(header + "\n" + "-" * len(header) + "\n")
    for p in report.result.data or ():
        out.write(
            f"{p.name.value:<9} {p.enabled.value:<15} {p.default_inbound_action.value:<15} "
            f"{p.default_outbound_action.value:<15} {p.allow_inbound_rules.value:<15}\n"
        )
    for error in report.result.errors:
        out.write(f"\nLimitation: {error.code.value} ({error.source}): {error.detail}\n")


# --- rules ---------------------------------------------------------------------------------------


class _StderrProgress:
    def __init__(self, err: TextIO) -> None:
        self._err = err

    def inventory_ready(self, rules: tuple[FirewallRule, ...]) -> None:
        self._err.write(f"Inventory: {len(rules)} rules. Collecting per-rule filters...\n")

    def detail_progress(self, done: int, total: int, updated: tuple[FirewallRule, ...]) -> None:
        self._err.write(f"  details {done}/{total}\n")


def _cell(result: FilterResult[Any], text: str) -> str:
    """Never render a missing filter as a value: show its evidence state instead."""
    if result.state is FilterState.NOT_COLLECTED:
        return f"<not collected: {result.reason.value if result.reason else '?'}>"
    if result.state is FilterState.UNREADABLE:
        return "<unreadable>"
    return text


def _rule_line(rule: FirewallRule) -> str:
    port = rule.port.value
    addr = rule.address.value
    proto = _cell(rule.port, port.protocol if port else "")
    lports = _cell(rule.port, ",".join(t.value for t in port.local_ports) if port else "")
    raddr = _cell(
        rule.address, ",".join(t.value for t in addr.remote_addresses)[:40] if addr else ""
    )
    return (
        f"{rule.id:<28} {rule.direction.value:<8} {rule.action.value:<6} "
        f"{'yes' if rule.enabled else 'no':<4} {proto:<8} {lports[:24]:<24} {raddr}"
    )


def _print_rules_text(report: RuleScanReport, out: TextIO, *, summary_only: bool) -> None:
    data = report.result.data
    out.write(f"{SCOPE_NOTE}\n\n")
    if data is not None:
        rules = data.rules
        inbound = sum(r.direction.value == "inbound" for r in rules)
        enabled = sum(r.enabled for r in rules)
        out.write(
            f"Rules: {len(rules)} of {data.total_in_source} in ActiveStore "
            f"(inbound {inbound}, outbound {len(rules) - inbound}; enabled {enabled})\n"
        )
        out.write(
            f"Detail: {'complete' if data.detail_complete else 'NOT complete'} "
            f"(mode: {report.mode})\n"
        )
    ev = report.evidence
    out.write(f"Evidence: complete {ev.complete}, incomplete {ev.incomplete}")
    if ev.reasons:
        out.write(" (" + ", ".join(f"{k}: {v}" for k, v in ev.reasons.items()) + ")")
    out.write("\nVerdicts: none (evidence collection only)\n")
    inv = "n/a" if report.inventory_s is None else f"{report.inventory_s:.1f} s"
    out.write(f"Timing: inventory {inv}, total {report.total_s:.1f} s\n")
    out.write(report.n04.describe() + "\n")
    if data is not None:
        out.write("\nLimitations:\n")
        for lim in data.limitations:
            out.write(f"  - {lim.code.value}: {lim.detail}\n")
    for error in report.result.errors[:20]:
        out.write(f"Error: {error.code.value} ({error.source}): {error.detail}\n")
    if len(report.result.errors) > 20:
        out.write(f"... {len(report.result.errors) - 20} more errors (see --json)\n")
    if data is not None and not summary_only:
        out.write(
            f"\n{'id':<28} {'dir':<8} {'action':<6} {'on':<4} {'proto':<8} "
            f"{'local ports':<24} remote addresses\n"
        )
        for rule in data.rules:
            out.write(_rule_line(rule) + "\n")


def _rules_exit_code(report: RuleScanReport) -> int:
    data = report.result.data
    if data is None:
        return EXIT_FAILED
    if report.result.partial or not data.detail_complete:
        return EXIT_PARTIAL
    return EXIT_OK


# --- endpoints -----------------------------------------------------------------------------------

HIDDEN = "<hidden>"


def _process_cell(ep: Endpoint) -> str:
    p = ep.process
    if p.reason is not None:
        return f"<{p.reason.value}>"
    if p.name.value is not None:
        return display_safe(p.name.value, 40)
    return f"<{p.name.reason.value if p.name.reason else 'unavailable'}>"


def _endpoint_line(ep: Endpoint, *, show_remote: bool) -> str:
    if ep.remote_address is None:
        remote = "-"
    elif show_remote:
        remote = f"{display_safe(ep.remote_address, 46)}:{ep.remote_port}"
    else:
        remote = HIDDEN
    state = ep.tcp_state.value if ep.tcp_state is not None else "-"
    pid = "-" if ep.process.pid is None else str(ep.process.pid)
    local = f"{display_safe(ep.local_address, 46)}:{ep.local_port}"
    return (
        f"{ep.protocol.value:<4} {ep.family.value:<5} {ep.kind.value:<10} {state:<12} "
        f"{local:<48} {remote:<48} {pid:>7} {_process_cell(ep)}"
    )


def _print_endpoints_text(
    report: EndpointScanReport, out: TextIO, *, summary_only: bool, listening: bool, remote: bool
) -> None:
    data = report.result.data
    out.write(f"{ENDPOINT_SCOPE_NOTE}\n\n")
    if data is not None:
        s = summarize(data)
        out.write(
            f"Endpoints: {s['total']} (listening TCP {s['listening_tcp']}, bound UDP "
            f"{s['bound_udp']}, TCP connections {s['tcp_connections']}; "
            + ", ".join(f"{k} {v}" for k, v in s["families"].items())
            + ")\n"
        )
        out.write(
            "Process attribution: "
            + ", ".join(f"{k} {v}" for k, v in s["process_attribution"].items())
            + "\n"
        )
        t = data.timings
        services = "n/a" if t.services_s is None else f"{t.services_s:.2f} s (parallel)"
        out.write(
            f"Timing: sockets {t.sockets_s:.2f} s, processes {t.processes_s:.2f} s, "
            f"services {services}; total {report.total_s:.2f} s\n"
        )
    out.write(report.target.describe() + "\n")
    if data is not None:
        out.write("\nLimitations:\n")
        for lim in data.limitations:
            out.write(f"  - {lim.code.value}: {lim.detail}\n")
    for error in report.result.errors:
        out.write(f"Error: {error.code.value} ({error.source}): {error.detail}\n")
    if data is None or summary_only:
        return
    if not remote:
        out.write("\nRemote addresses are hidden (use --show-remote to display them).\n")
    out.write(
        f"\n{'prot':<4} {'fam':<5} {'kind':<10} {'state':<12} {'local':<48} {'remote':<48} "
        f"{'pid':>7} process\n"
    )
    for ep in data.endpoints:
        if listening and ep.kind is EndpointKind.CONNECTION:
            continue
        out.write(_endpoint_line(ep, show_remote=remote) + "\n")


def _endpoints_exit_code(report: EndpointScanReport) -> int:
    if report.result.data is None:
        return EXIT_FAILED
    return EXIT_PARTIAL if report.result.partial else EXIT_OK


def main(
    argv: Sequence[str] | None = None, *, out: TextIO | None = None, err: TextIO | None = None
) -> int:
    stream = out if out is not None else sys.stdout
    err_stream = err if err is not None else sys.stderr
    args = _build_parser().parse_args(argv)
    if args.command == "profiles":
        report = create_profile_service(fixture=args.fixture).get_profiles()
        if report.elevated:
            err_stream.write(
                "Warning: running elevated is not needed; FirewallAI is designed to run as a "
                "standard user.\n"
            )
        if args.json:
            stream.write(json.dumps(report_to_dict(report), indent=2, ensure_ascii=False) + "\n")
        else:
            _print_text(report, stream)
        return _exit_code(report)
    if args.command == "rules":
        service = create_rule_scan_service(fixture=args.fixture)
        rule_report = service.scan(
            detail=not args.inventory_only, observer=_StderrProgress(err_stream)
        )
        if rule_report.elevated:
            err_stream.write("Warning: running elevated is not needed.\n")
        if args.json:
            err_stream.write(f"Note: {SENSITIVE_EXPORT_NOTE}\n")
            stream.write(
                json.dumps(rules_report_to_dict(rule_report), indent=2, ensure_ascii=False) + "\n"
            )
        else:
            _print_rules_text(rule_report, stream, summary_only=args.summary)
        return _rules_exit_code(rule_report)
    if args.command == "endpoints":
        ep_report = create_endpoint_scan_service(fixture=args.fixture).scan()
        if ep_report.elevated:
            err_stream.write("Warning: running elevated is not needed.\n")
        if args.json:
            err_stream.write(f"Note: {ENDPOINTS_PRIVACY_NOTE}\n")
            stream.write(
                json.dumps(endpoints_report_to_dict(ep_report), indent=2, ensure_ascii=False) + "\n"
            )
        else:
            _print_endpoints_text(
                ep_report,
                stream,
                summary_only=args.summary,
                listening=args.listening,
                remote=args.show_remote,
            )
        return _endpoints_exit_code(ep_report)
    return 2  # pragma: no cover - argparse enforces a known command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
