"""Collector interfaces.

Implementations: ``collectors.windows`` (real, read-only) and ``collectors.fake`` (fixtures).
"""

import threading
from typing import Protocol

from firewallai.core.models import FirewallProfile
from firewallai.core.results import CollectorResult
from firewallai.core.rules import FirewallRule, RuleCollection

ProfilesResult = CollectorResult[tuple[FirewallProfile, ...]]
RulesResult = CollectorResult[RuleCollection]


class FirewallProfileCollector(Protocol):
    """Reads the effective firewall profile settings. Must never modify system state."""

    @property
    def source_id(self) -> str: ...

    def collect_profiles(self) -> ProfilesResult: ...


class RuleCollectionObserver(Protocol):
    """Progress callbacks. They run on the collecting (background) thread."""

    def inventory_ready(self, rules: tuple[FirewallRule, ...]) -> None: ...

    def detail_progress(self, done: int, total: int, updated: tuple[FirewallRule, ...]) -> None: ...


class FirewallRuleCollector(Protocol):
    """Reads ActiveStore rules progressively (ADR 0009). Must never modify system state."""

    @property
    def source_id(self) -> str: ...

    def collect_rules(
        self,
        *,
        detail: bool = True,
        observer: RuleCollectionObserver | None = None,
        cancel: threading.Event | None = None,
    ) -> RulesResult: ...
