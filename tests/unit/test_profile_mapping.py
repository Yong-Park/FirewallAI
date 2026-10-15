import json
from pathlib import Path

import pytest

from firewallai.collectors.fake.firewall_profiles import FixtureFirewallProfileCollector
from firewallai.collectors.windows.profile_mapping import (
    ACTION,
    GPO_BOOLEAN,
    parse_profiles_payload,
)
from firewallai.core.models import FirewallAction, ProfileName, TriState
from firewallai.core.results import CollectorErrorCode


def _load(fixtures_dir: Path, name: str) -> object:
    return json.loads((fixtures_dir / "profiles" / name).read_text(encoding="utf-8"))


def test_enum_maps_match_verified_netsecurity_values() -> None:
    # Values verified read-only on TE-1 (2026-10-14) via [Enum]::GetNames/GetValues.
    assert dict(GPO_BOOLEAN) == {0: TriState.FALSE, 1: TriState.TRUE, 2: TriState.NOT_CONFIGURED}
    assert dict(ACTION) == {
        0: FirewallAction.NOT_CONFIGURED,
        2: FirewallAction.ALLOW,
        4: FirewallAction.BLOCK,
    }


def test_default_fixture_maps_all_profiles(fixtures_dir: Path) -> None:
    result = parse_profiles_payload(_load(fixtures_dir, "win11_default.json"), "test")
    assert result.ok
    assert result.data is not None
    assert [p.name for p in result.data] == [
        ProfileName.DOMAIN,
        ProfileName.PRIVATE,
        ProfileName.PUBLIC,
    ]
    public = result.data[2]
    assert public.id == "fw_profile:public"
    assert public.enabled is TriState.TRUE
    assert public.default_inbound_action is FirewallAction.BLOCK
    assert public.default_outbound_action is FirewallAction.ALLOW
    assert public.disabled_interface_aliases == ()  # [""] means "none configured"
    assert public.log_max_size_kb == 4096


def test_invalid_values_produce_partial_result_with_safe_errors(fixtures_dir: Path) -> None:
    result = parse_profiles_payload(_load(fixtures_dir, "invalid_values.json"), "test")
    assert result.partial
    assert result.data is not None
    assert [p.name for p in result.data] == [ProfileName.DOMAIN]
    domain = result.data[0]
    assert domain.log_file_name is None  # "NotConfigured" sentinel normalized
    assert domain.disabled_interface_aliases == ()
    codes = sorted(e.code for e in result.errors)
    assert codes == [CollectorErrorCode.INVALID_VALUE, CollectorErrorCode.PARSE_ERROR]
    invalid = next(e for e in result.errors if e.code is CollectorErrorCode.INVALID_VALUE)
    assert "field=Enabled" in invalid.detail
    assert "value=7" in invalid.detail


@pytest.mark.parametrize(
    "payload",
    [None, [], "text", {"profiles": "x"}, {"other": []}, {"profiles": []}],
)
def test_malformed_payloads_fail_without_data(payload: object) -> None:
    result = parse_profiles_payload(payload, "test")
    assert result.data is None
    assert result.errors
    assert result.errors[0].code is CollectorErrorCode.PARSE_ERROR


def test_unexpected_profile_name_is_not_echoed() -> None:
    item = {
        "Name": "C:\\Users\\someone\\secret",
        "Enabled": 1,
        "DefaultInboundAction": 4,
        "DefaultOutboundAction": 2,
        "AllowInboundRules": 1,
        "AllowLocalFirewallRules": 1,
        "AllowLocalIPsecRules": 1,
        "NotifyOnListen": 1,
        "LogAllowed": 0,
        "LogBlocked": 0,
        "LogMaxSizeKilobytes": 1,
        "LogFileName": "",
        "DisabledInterfaceAliases": [],
    }
    result = parse_profiles_payload({"profiles": [item]}, "test")
    assert result.data is None
    assert "someone" not in result.errors[0].detail


def test_duplicate_profiles_are_flagged(fixtures_dir: Path) -> None:
    payload = _load(fixtures_dir, "win11_default.json")
    assert isinstance(payload, dict)
    payload["profiles"].append(payload["profiles"][0])
    result = parse_profiles_payload(payload, "test")
    assert result.partial
    assert any("duplicate" in e.detail for e in result.errors)


def test_fake_collector_uses_same_parsing_path(fixtures_dir: Path) -> None:
    collector = FixtureFirewallProfileCollector.from_file(
        fixtures_dir / "profiles" / "win11_default.json"
    )
    result = collector.collect_profiles()
    assert result.ok
    assert collector.source_id == "fixture.firewall_profiles"
