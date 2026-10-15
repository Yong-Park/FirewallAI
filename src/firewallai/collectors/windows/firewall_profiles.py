"""Real, read-only collector for Windows Firewall profile settings (ActiveStore)."""

from firewallai.collectors.protocols import ProfilesResult
from firewallai.collectors.windows.powershell_runner import (
    PowerShellRunner,
    UnsupportedPlatformError,
)
from firewallai.collectors.windows.profile_mapping import parse_profiles_payload
from firewallai.collectors.windows.scripts import FIREWALL_PROFILES
from firewallai.core.results import CollectorError, CollectorErrorCode, CollectorResult


class WindowsFirewallProfileCollector:
    """Reads ``Get-NetFirewallProfile -PolicyStore ActiveStore`` as a standard user."""

    SOURCE_ID = "windows.netsecurity.firewall_profiles"

    def __init__(self, runner: PowerShellRunner | None = None) -> None:
        self._runner = runner

    @property
    def source_id(self) -> str:
        return self.SOURCE_ID

    def collect_profiles(self) -> ProfilesResult:
        try:
            runner = self._runner if self._runner is not None else PowerShellRunner()
        except UnsupportedPlatformError:
            return CollectorResult(
                errors=(
                    CollectorError(
                        code=CollectorErrorCode.UNSUPPORTED_PLATFORM,
                        source=self.SOURCE_ID,
                        detail="Windows PowerShell is not available on this platform",
                    ),
                )
            )
        outcome = runner.run(FIREWALL_PROFILES, source=self.SOURCE_ID)
        if outcome.error is not None:
            return CollectorResult(errors=(outcome.error,))
        return parse_profiles_payload(outcome.data, self.SOURCE_ID)
