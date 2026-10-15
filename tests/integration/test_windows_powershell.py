"""Read-only integration tests against the real Windows PowerShell and NetSecurity module.

These run only on Windows, as a standard user, and never modify system state.
"""

import time

import pytest

from firewallai.collectors.windows.firewall_profiles import WindowsFirewallProfileCollector
from firewallai.collectors.windows.powershell_runner import PowerShellRunner, PowerShellScript
from firewallai.collectors.windows.privilege import is_elevated
from firewallai.core.models import ProfileName
from firewallai.core.results import CollectorErrorCode

pytestmark = [pytest.mark.windows, pytest.mark.integration]

# Test-only scripts (not registered for production). They use only read-only/data cmdlets.
_ECHO = PowerShellScript(
    name="test_echo_params",
    body="        $FwaiParams",
    allowed_commands=frozenset(),
)
_NOT_FOUND = PowerShellScript(
    name="test_not_found",
    body=(
        "        Get-NetFirewallProfile -PolicyStore ActiveStore"
        " -Name FwaiNoSuchProfile -ErrorAction Stop"
    ),
    allowed_commands=frozenset({"Get-NetFirewallProfile"}),
)


def test_tests_run_unelevated() -> None:
    assert is_elevated() is False, "integration tests must run as a standard user (SB-02)"


def test_real_profiles_are_collected_read_only() -> None:
    started = time.perf_counter()
    result = WindowsFirewallProfileCollector().collect_profiles()
    elapsed = time.perf_counter() - started
    assert result.ok, result.errors
    assert result.data is not None
    assert {p.name for p in result.data} == set(ProfileName)
    print(f"\n[measurement] live profile collection: {elapsed:.2f}s")


@pytest.mark.security
def test_injection_payloads_round_trip_as_data() -> None:
    payload = {
        "a": "$(Write-Output pwned)",
        "b": "'; Remove-Item C:\\nonexistent; '",
        "c": '"; whoami; "',
        "d": "` & | ; \u00f1",
    }
    outcome = PowerShellRunner().run(_ECHO, payload, source="test")
    assert outcome.error is None
    assert outcome.data == payload  # returned unchanged: parsed as JSON, never executed


def test_real_error_is_structured_not_localized() -> None:
    outcome = PowerShellRunner().run(_NOT_FOUND, source="test")
    assert outcome.error is not None
    assert outcome.error.code in {CollectorErrorCode.NOT_FOUND, CollectorErrorCode.EXECUTION_FAILED}
    assert "category=" in outcome.error.detail
    assert "error_id=" in outcome.error.detail
