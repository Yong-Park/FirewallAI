import pytest
from pydantic import ValidationError

from firewallai.collectors.windows import rule_mapping
from firewallai.collectors.windows.rule_mapping import (
    allocate_rule_ids,
    parse_address_token,
    parse_icmp_token,
    parse_port_token,
)
from firewallai.core.results import CollectorError, CollectorErrorCode
from firewallai.core.rules import (
    AddressFilter,
    AddressToken,
    ApplicationFilter,
    FilterResult,
    FilterState,
    FirewallRule,
    InterfaceFilter,
    InterfaceTypeFilter,
    NotCollectedReason,
    PortFilter,
    PortToken,
    RuleCollection,
    ScanLimitation,
    SecurityFilter,
    ServiceFilter,
    TokenKind,
    rule_id,
    rule_id_digest,
)
from firewallai.core.sensitivity import DataClass, field_sensitivity, unclassified_fields

# --- FilterResult --------------------------------------------------------------------------------


def test_filter_result_states_are_exclusive() -> None:
    err = CollectorError(code=CollectorErrorCode.ACCESS_DENIED, source="t", detail="")
    assert FilterResult[ServiceFilter].collected(ServiceFilter()).is_collected
    assert FilterResult[ServiceFilter].not_collected(NotCollectedReason.PENDING).value is None
    assert FilterResult[ServiceFilter].unreadable(err).state is FilterState.UNREADABLE
    with pytest.raises(ValidationError):
        FilterResult[ServiceFilter](state=FilterState.COLLECTED)  # no value
    with pytest.raises(ValidationError):
        FilterResult[ServiceFilter](
            state=FilterState.NOT_COLLECTED,
            value=ServiceFilter(),
            reason=NotCollectedReason.PENDING,
        )
    with pytest.raises(ValidationError):
        FilterResult[ServiceFilter](state=FilterState.UNREADABLE)  # no error


# --- rule IDs ------------------------------------------------------------------------------------


def test_rule_id_scheme_is_versioned_stable_and_hashed() -> None:
    raw = "TCP Query User{12345678-aaaa}C:\\users\\someone\\app.exe"
    rid = rule_id(raw)
    assert rid == rule_id(raw)  # deterministic
    assert rid.startswith("fw_rule:h1-")
    assert rid.removeprefix("fw_rule:h1-") == rule_id_digest(raw)[:16]
    assert "someone" not in rid and "\\" not in rid
    assert rule_id(raw, extended=True).removeprefix("fw_rule:h1-") == rule_id_digest(raw)


def test_prefix_collision_uses_full_digest_and_never_merges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = rule_mapping.rule_id

    def colliding(raw: str, *, extended: bool = False) -> str:
        return real(raw, extended=True) if extended else "fw_rule:h1-0000000000000000"

    monkeypatch.setattr(rule_mapping, "rule_id", colliding)
    alloc = allocate_rule_ids(["a", "b", "c"])
    assert alloc.extended == {"a", "b", "c"}
    assert len(set(alloc.public_ids.values())) == 3


def test_duplicate_raw_ids_are_reported_not_merged() -> None:
    alloc = allocate_rule_ids(["x", "y", "x"])
    assert alloc.duplicates == {"x"}
    assert set(alloc.public_ids) == {"y"}


# --- tokens: unknown values are never ANY --------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "kind", "value"),
    [
        ("Any", TokenKind.ANY, "any"),
        ("443", TokenKind.NUMBER, "443"),
        ("5000-5020", TokenKind.RANGE, "5000-5020"),
        ("RPC", TokenKind.KEYWORD, "rpc"),
        ("RPCEPMap", TokenKind.KEYWORD, "rpcepmap"),
        ("IPHTTPSIn", TokenKind.KEYWORD, "iphttpsin"),
        ("70000", TokenKind.UNKNOWN, "70000"),
        ("20-10", TokenKind.UNKNOWN, "20-10"),
        ("SomethingNew", TokenKind.UNKNOWN, "SomethingNew"),
        ("*", TokenKind.UNKNOWN, "*"),
    ],
)
def test_port_tokens(raw: str, kind: TokenKind, value: str) -> None:
    token = parse_port_token(raw)
    assert (token.kind, token.value) == (kind, value)


@pytest.mark.parametrize(
    ("raw", "kind"),
    [
        ("Any", TokenKind.ANY),
        ("LocalSubnet", TokenKind.KEYWORD),
        ("LocalSubnet6", TokenKind.KEYWORD),
        ("PlayToDevice", TokenKind.KEYWORD),
        ("192.0.2.10", TokenKind.ADDRESS),
        ("192.0.2.0/24", TokenKind.ADDRESS),
        ("192.0.2.0/255.255.255.0", TokenKind.ADDRESS),
        ("192.0.2.1-192.0.2.9", TokenKind.ADDRESS),
        ("2001:db8::1", TokenKind.ADDRESS),
        ("2001:db8::/32", TokenKind.ADDRESS),
        ("192.0.2.9-192.0.2.1", TokenKind.UNKNOWN),
        ("NewKeyword", TokenKind.UNKNOWN),
        ("999.1.1.1", TokenKind.UNKNOWN),
    ],
)
def test_address_tokens(raw: str, kind: TokenKind) -> None:
    assert parse_address_token(raw).kind is kind


@pytest.mark.parametrize(
    ("raw", "kind"),
    [
        ("Any", TokenKind.ANY),
        ("8", TokenKind.NUMBER),
        ("3:4", TokenKind.NUMBER),
        ("300", TokenKind.UNKNOWN),
        ("x:1", TokenKind.UNKNOWN),
    ],
)
def test_icmp_tokens(raw: str, kind: TokenKind) -> None:
    assert parse_icmp_token(raw).kind is kind


# --- sensitivity metadata ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model",
    [
        FirewallRule,
        PortToken,
        AddressToken,
        ApplicationFilter,
        ServiceFilter,
        SecurityFilter,
        PortFilter,
        AddressFilter,
        InterfaceTypeFilter,
        InterfaceFilter,
        ScanLimitation,
        RuleCollection,
    ],
)
def test_every_new_field_declares_sensitivity(model: type) -> None:
    assert unclassified_fields(model) == frozenset()


def test_host_identifying_rule_fields_are_host_sensitive() -> None:
    for name in (
        "instance_id",
        "display_name",
        "description",
        "group",
        "application",
        "address",
        "interface",
        "remote_dynamic_keyword_addresses",
    ):
        assert field_sensitivity(FirewallRule, name) is DataClass.HOST_SENSITIVE, name
    assert field_sensitivity(AddressToken, "value") is DataClass.HOST_SENSITIVE
    assert field_sensitivity(InterfaceFilter, "aliases") is DataClass.HOST_SENSITIVE
    assert field_sensitivity(FirewallRule, "id") is DataClass.DERIVED_ABSTRACT
