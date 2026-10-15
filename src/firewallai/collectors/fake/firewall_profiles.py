"""Fake profile collector backed by a recorded/sanitized raw payload."""

import json
import time
from pathlib import Path
from typing import Any

from firewallai.collectors.protocols import ProfilesResult
from firewallai.collectors.windows.profile_mapping import parse_profiles_payload

_MAX_FIXTURE_BYTES = 1024 * 1024


class FixtureFirewallProfileCollector:
    """Profiles parsed from a raw ``{"profiles": [...]}`` payload, as emitted by PowerShell."""

    SOURCE_ID = "fixture.firewall_profiles"

    def __init__(self, payload: Any, *, delay_s: float = 0.0) -> None:
        self._payload = payload
        self._delay_s = delay_s

    @classmethod
    def from_file(cls, path: Path, *, delay_s: float = 0.0) -> "FixtureFirewallProfileCollector":
        if path.stat().st_size > _MAX_FIXTURE_BYTES:
            raise ValueError("fixture file too large")
        return cls(json.loads(path.read_text(encoding="utf-8")), delay_s=delay_s)

    @property
    def source_id(self) -> str:
        return self.SOURCE_ID

    def collect_profiles(self) -> ProfilesResult:
        if self._delay_s > 0:
            time.sleep(self._delay_s)  # lets UI tests prove collection runs off the GUI thread
        return parse_profiles_payload(self._payload, self.SOURCE_ID)
