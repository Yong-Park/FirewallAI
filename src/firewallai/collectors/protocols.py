"""Collector interfaces.

Implementations: ``collectors.windows`` (real, read-only) and ``collectors.fake`` (fixtures).
"""

from typing import Protocol

from firewallai.core.models import FirewallProfile
from firewallai.core.results import CollectorResult

ProfilesResult = CollectorResult[tuple[FirewallProfile, ...]]


class FirewallProfileCollector(Protocol):
    """Reads the effective firewall profile settings. Must never modify system state."""

    @property
    def source_id(self) -> str: ...

    def collect_profiles(self) -> ProfilesResult: ...
