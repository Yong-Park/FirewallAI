"""``firewallai`` CLI. Read-only; no network access.

Exit codes: 0 = complete, 1 = collection failed, 2 = usage error, 3 = partial data.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from firewallai import __version__
from firewallai.app.profile_service import (
    SCOPE_NOTE,
    ProfileReport,
    create_profile_service,
    report_to_dict,
)

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


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    stream = out if out is not None else sys.stdout
    args = _build_parser().parse_args(argv)
    if args.command == "profiles":
        report = create_profile_service(fixture=args.fixture).get_profiles()
        if report.elevated:
            sys.stderr.write(
                "Warning: running elevated is not needed; FirewallAI is designed to run as a "
                "standard user.\n"
            )
        if args.json:
            stream.write(json.dumps(report_to_dict(report), indent=2, ensure_ascii=False) + "\n")
        else:
            _print_text(report, stream)
        return _exit_code(report)
    return 2  # pragma: no cover - argparse enforces a known command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
