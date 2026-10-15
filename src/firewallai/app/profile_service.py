"""Profile collection service and report serialization (read-only, local-policy scope)."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from firewallai import __version__
from firewallai.collectors.fake.firewall_profiles import FixtureFirewallProfileCollector
from firewallai.collectors.protocols import FirewallProfileCollector, ProfilesResult
from firewallai.collectors.windows.firewall_profiles import WindowsFirewallProfileCollector
from firewallai.collectors.windows.privilege import is_elevated

REPORT_SCHEMA = "firewallai.profiles/1"
SCOPE_NOTE = (
    "Read-only. Shows the local Windows Firewall policy only; it cannot show whether anything "
    "is reachable from other networks."
)


@dataclass(frozen=True, slots=True)
class ProfileReport:
    result: ProfilesResult
    source_id: str
    collected_at: datetime
    elevated: bool | None


class ProfileService:
    """Collects firewall profiles through a ``FirewallProfileCollector``."""

    def __init__(
        self,
        collector: FirewallProfileCollector,
        *,
        clock: Callable[[], datetime] | None = None,
        elevation_check: Callable[[], bool | None] = is_elevated,
    ) -> None:
        self._collector = collector
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._elevation_check = elevation_check

    def get_profiles(self) -> ProfileReport:
        result = self._collector.collect_profiles()
        return ProfileReport(
            result=result,
            source_id=self._collector.source_id,
            collected_at=self._clock(),
            elevated=self._elevation_check(),
        )


def create_profile_service(fixture: Path | None = None) -> ProfileService:
    """Real Windows collector by default; a fixture-backed collector when ``fixture`` is given."""
    collector: FirewallProfileCollector
    if fixture is not None:
        collector = FixtureFirewallProfileCollector.from_file(fixture)
    else:
        collector = WindowsFirewallProfileCollector()
    return ProfileService(collector)


def report_to_dict(report: ProfileReport) -> dict[str, Any]:
    """Machine-readable, schema-versioned representation of a profile report."""
    return {
        "schema": REPORT_SCHEMA,
        "app_version": __version__,
        "collected_at": report.collected_at.isoformat(),
        "source": report.source_id,
        "scope": "local_policy_only",
        "read_only": True,
        "elevated": report.elevated,
        "ok": report.result.ok,
        "partial": report.result.partial,
        "profiles": [p.model_dump(mode="json") for p in (report.result.data or ())],
        "errors": [e.model_dump(mode="json") for e in report.result.errors],
    }
