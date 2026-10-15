"""M1.4 descriptive correlation (SB-20): truth table over real parsed rules and endpoints.

RELATED only when EVERY endpoint-identity filter matches; known contradictions -> NOT_RELATED;
missing/ambiguous data or incomplete rule evidence -> CANNOT_EVALUATE; network-condition
restrictions are listed, never dropped. No verdict words are produced.
"""

from typing import Any

import pytest

from endpoint_builders import ALL_IPV4, APP_PATH, proc, snapshot, sock
from firewallai.collectors.fake.firewall_rules import FixtureFirewallRuleCollector
from firewallai.collectors.fake.network_endpoints import FixtureEndpointCollector
from firewallai.core.correlation import (
    CORRELATION_DISCLAIMER,
    CorrelationStatus,
    RelationStatus,
    RuleIndex,
    normalize_program_path,
    relate,
)
from firewallai.core.endpoints import Endpoint
from firewallai.core.evidence import IncompleteEvidence, evidence_for_verdict
from firewallai.core.rules import FirewallRule, RuleCollection
from rule_builders import address, detail, inventory, port, raw_rule

ENV = {"SystemRoot": "C:\\Windows", "ProgramFiles": "C:\\Program Files"}


def _collection(
    *,
    rule: dict[str, Any] | None = None,
    program: str = "Any",
    package: str = "Any",
    service: str = "Any",
    ports: dict[str, Any] | None = None,
    addrs: dict[str, Any] | None = None,
    iftype: str = "Any",
    aliases: list[str] | None = None,
    security: dict[str, Any] | None = None,
    with_detail: bool = True,
) -> RuleCollection:
    inv = inventory([raw_rule("R", **(rule or {}))])
    inv["apps"] = [{"id": "R", "program": program, "package": package}]
    inv["services"] = [{"id": "R", "service": service}]
    inv["security"][0].update(security or {})
    events = [inv]
    if with_detail:
        events.append(
            detail(
                ["R"],
                done=1,
                total=1,
                ports=[port("R", **(ports or {}))],
                addresses=[address("R", **(addrs or {}))],
                iftypes=[{"id": "R", "type": iftype}],
                ifaliases=[{"id": "R", "aliases": aliases or ["Any"]}],
            )
        )
    result = FixtureFirewallRuleCollector({"events": events, "final_error": None}).collect_rules(
        detail=with_detail
    )
    assert result.data is not None
    return result.data


def _rule(**kw: Any) -> FirewallRule:
    return _collection(**kw).rules[0]


def _endpoint(
    s: dict[str, Any] | None = None, *, services: list[dict[str, Any]] | None = None, **kw: Any
) -> Endpoint:
    raw = snapshot([s or sock(lport=443, pid=1000)], services=services, **kw)
    result = FixtureEndpointCollector(raw).collect_endpoints()
    assert result.data is not None
    return result.data.endpoints[0]


def _status(rule: FirewallRule, ep: Endpoint) -> RelationStatus:
    ev = evidence_for_verdict(rule)
    return relate(rule, ep, ENV, ev if isinstance(ev, IncompleteEvidence) else None).status


R, C, N = RelationStatus.RELATED, RelationStatus.CANNOT_EVALUATE, RelationStatus.NOT_RELATED
RC = RelationStatus.RELATED_WITH_UNEVALUATED_CONDITIONS


@pytest.mark.parametrize(
    ("rule_kw", "expected"),
    [
        ({}, R),  # TCP 443, any program/service/address
        ({"ports": {"local": ["400-500"]}}, R),
        ({"ports": {"local": ["80", "443"]}}, R),
        ({"ports": {"local": ["8443"]}}, N),
        ({"ports": {"protocol": "UDP"}}, N),
        ({"ports": {"protocol": "ICMPv4", "local": ["Any"]}}, N),
        ({"ports": {"protocol": "47", "local": ["Any"]}}, N),
        ({"ports": {"protocol": "6"}}, R),
        ({"ports": {"protocol": "Any", "local": ["Any"]}}, R),
        ({"ports": {"local": ["RPC"]}}, C),  # keyword: not resolved
        ({"ports": {"local": ["RPC", "443"]}}, R),  # an explicit match exists
        ({"ports": {"local": ["weird"]}}, C),
        ({"ports": {"dynamic_target": "ProximitySharing"}}, C),
        ({"program": APP_PATH}, R),
        ({"program": APP_PATH.upper()}, R),  # Windows paths are case-insensitive
        ({"program": "C:\\Other\\other.exe"}, N),
        ({"program": "%ProgramFiles%\\x.exe"}, N),  # expanded, then compared
        ({"program": "%UNKNOWNVAR%\\synthetic.exe"}, C),
        ({"program": "C:\\SYNTHE~1\\App\\synthetic.exe"}, C),  # 8.3 short name
        ({"program": "System"}, N),  # System (PID 4) vs. an attributed user process
        ({"package": "S-1-15-2-1"}, C),
        ({"package": "*"}, C),
        ({"rule": {"has_owner": True}}, C),
        ({"addrs": {"local": ["192.0.2.0/24"]}}, R),
        ({"addrs": {"local": ["192.0.2.1-192.0.2.20"]}}, R),
        ({"addrs": {"local": ["198.51.100.0/24"]}}, N),
        ({"addrs": {"local": ["2001:db8::/32"]}}, N),  # other family
        ({"addrs": {"local": ["LocalSubnet"]}}, C),
        ({"with_detail": False}, C),  # filters not collected: never "Any"
        ({"with_detail": False, "program": "C:\\Other\\other.exe"}, N),  # known contradiction
    ],
)
def test_truth_table_for_a_specific_bound_tcp_listener(
    rule_kw: dict[str, Any], expected: RelationStatus
) -> None:
    ep = _endpoint(sock(laddr="192.0.2.10", lport=443, pid=1000))
    assert _status(_rule(**rule_kw), ep) is expected


def test_a_matching_port_alone_is_never_enough() -> None:
    ep = _endpoint()
    rule = _rule(program="C:\\Other\\other.exe")  # port and protocol match, program does not
    relation = relate(rule, ep, ENV)
    assert relation.status is N
    assert any(c.dimension == "local_port" and c.outcome.value == "match" for c in relation.checks)


def test_all_interfaces_listener_against_local_address_restriction() -> None:
    ep = _endpoint(sock(laddr=ALL_IPV4, lport=443, pid=1000))
    relation = relate(_rule(addrs={"local": ["192.0.2.10"]}), ep, ENV)
    assert relation.status is C
    assert any("all local addresses" in r for r in relation.reasons)


@pytest.mark.parametrize(
    ("process", "rule_program", "expected"),
    [
        (proc(1000, exe_error="access_denied"), APP_PATH, C),
        (proc(1000, exe_error="access_denied"), "Any", R),
        (proc(1000, exited=True), APP_PATH, C),
    ],
)
def test_unavailable_process_details(
    process: dict[str, Any], rule_program: str, expected: RelationStatus
) -> None:
    ep = _endpoint(processes=[process])
    assert _status(_rule(program=rule_program), ep) is expected


def test_unverified_attribution_never_matches_a_program() -> None:
    ep = _endpoint(second=[])  # socket gone in the second snapshot
    assert _status(_rule(program=APP_PATH), ep) is C
    assert _status(_rule(), ep) is R  # an any-program rule needs no process identity


def test_system_program_rule_and_pid_4() -> None:
    ep = _endpoint(sock(lport=443, pid=4))
    assert _status(_rule(program="System"), ep) is R
    assert _status(_rule(program=APP_PATH), ep) is C  # PID 4 has no image path


def test_service_wildcard_is_preserved_as_a_restriction() -> None:
    """M1.3 mapped "*" to None ("any"); "*" means "services only" (SB-18 regression)."""
    rule = _rule(service="*")
    assert rule.service.value is not None and rule.service.value.service == "*"
    assert _rule(package="*").application.value.package == "*"
    hosts_none = _endpoint()
    hosts_one = _endpoint(services=[{"name": "SynthSvc", "pid": 1000}])
    lookup_failed = _endpoint(no_services=True, services_error="x")
    assert _status(rule, hosts_none) is N
    assert _status(rule, hosts_one) is R
    assert _status(rule, lookup_failed) is C


@pytest.mark.parametrize(
    ("services", "expected"),
    [
        ([{"name": "SynthSvc", "pid": 1000}], R),
        ([{"name": "synthsvc", "pid": 1000}], R),  # service names are case-insensitive
        ([{"name": "SynthSvc", "pid": 1000}, {"name": "Other", "pid": 1000}], C),  # shared host
        ([{"name": "Other", "pid": 1000}], N),
        ([], N),
    ],
)
def test_named_service_rules(services: list[dict[str, Any]], expected: RelationStatus) -> None:
    assert _status(_rule(service="SynthSvc"), _endpoint(services=services)) is expected


def test_network_conditions_are_listed_never_silently_dropped() -> None:
    rule = _rule(
        rule={"profile": "Public", "edge": "Allow"},
        addrs={"remote": ["198.51.100.0/24"]},
        ports={"remote": ["5000"]},
        iftype="Wireless",
        aliases=["Synthetic vSwitch"],
        security={"authentication": "Required"},
    )
    relation = relate(rule, _endpoint(), ENV)
    assert relation.status is RC  # never a plain "related" while conditions are unevaluated
    text = " | ".join(relation.conditions)
    for fragment in (
        "profiles: public",
        "interface type: wireless",
        "named interface",
        "remote addresses restricted",
        "remote ports restricted",
        "edge traversal",
        "IPsec",
    ):
        assert fragment in text, fragment
    assert all("not evaluated" in c or "not mapped" in c for c in relation.conditions)


@pytest.mark.parametrize(
    "rule_kw",
    [
        {"rule": {"profile": "Public"}},
        {"rule": {"profile": "Domain, Private"}},
        {"iftype": "Wireless"},
        {"aliases": ["Synthetic vSwitch"]},
        {"addrs": {"remote": ["198.51.100.0/24"]}},
        {"addrs": {"remote": ["LocalSubnet"]}},
        {"ports": {"remote": ["5000"]}},
        {"rule": {"edge": "DeferToUser"}},
        {"security": {"authentication": "Required"}},
        {"security": {"encryption": "Required"}},
        {"security": {"override_block": "True"}},
        {"security": {"remote_user": "O:LSD:(A;;CC;;;S-1-5-21-0-0-0-1001)"}},
    ],
    ids=[
        "profile-public",
        "profile-two",
        "interface-type",
        "interface-alias",
        "remote-address",
        "remote-keyword",
        "remote-port",
        "edge-traversal",
        "ipsec-auth",
        "ipsec-encryption",
        "auth-bypass",
        "remote-user",
    ],
)
def test_each_unevaluated_condition_alone_prevents_a_plain_related(rule_kw: dict[str, Any]) -> None:
    """Profile, interface, remote-peer, edge, and IPsec/authorization restrictions are never
    treated as satisfied: the relation is RELATED_WITH_UNEVALUATED_CONDITIONS (or
    CANNOT_EVALUATE when the rule evidence is incomplete), never RELATED."""
    status = _status(_rule(**rule_kw), _endpoint())
    assert status in (RC, C)
    assert status is not R


def test_service_hosting_and_app_container_scopes_are_never_related() -> None:
    shared = _endpoint(services=[{"name": "SynthSvc", "pid": 1000}, {"name": "Other", "pid": 1000}])
    assert _status(_rule(service="SynthSvc"), shared) is C
    for kw in ({"package": "S-1-15-2-1"}, {"package": "*"}, {"rule": {"has_owner": True}}):
        assert _status(_rule(**kw), _endpoint()) is C


@pytest.mark.parametrize(
    ("field", "raw", "stored"),
    [
        ("service", "Any", None),
        ("service", "any", None),
        ("service", "", None),
        ("service", "*", "*"),  # "services only": a restriction, never "any"
        ("service", "SynthSvc", "SynthSvc"),
        ("package", "Any", None),
        ("package", "", None),
        ("package", "*", "*"),  # "app packages only": a restriction, never "any"
        ("package", "S-1-15-2-1", "S-1-15-2-1"),
        ("program", "Any", None),
        ("program", APP_PATH, APP_PATH),
    ],
)
def test_wildcard_mapping_regression(field: str, raw: str, stored: str | None) -> None:
    """M1.3 mapped "*" to None ("any") for service and package filters (SB-18 defect)."""
    rule = _rule(**{field: raw})
    if field == "service":
        assert rule.service.value is not None
        assert rule.service.value.service == stored
    else:
        app = rule.application.value
        assert app is not None
        assert getattr(app, field) == stored


def test_index_skips_outbound_and_disabled_and_reports_completeness() -> None:
    inbound = _collection()
    index = RuleIndex(inbound, ENV)
    result = index.correlate(_endpoint())
    assert result.status is CorrelationStatus.EVALUATED
    assert len(result.related) == 1 and result.rules_considered == 1 and result.rule_set_complete
    for over in ({"direction": "Outbound"}, {"enabled": "False"}):
        skipped = RuleIndex(_collection(rule=over), ENV).correlate(_endpoint())
        assert skipped.related == () and skipped.rules_skipped == 1
    partial = RuleIndex(_collection(with_detail=False), ENV).correlate(_endpoint())
    assert not partial.rule_set_complete and partial.note


def test_connections_and_loopback_are_not_correlated() -> None:
    index = RuleIndex(_collection(), ENV)
    conn = _endpoint(sock(raddr="198.51.100.7", rport=50000, lport=443))
    assert index.correlate(conn).status is CorrelationStatus.NOT_APPLICABLE
    loop = _endpoint(sock(laddr="127.0.0.1", lport=443))
    assert index.correlate(loop).status is CorrelationStatus.CANNOT_EVALUATE
    assert index.correlate(loop).related == ()


def test_udp_bound_endpoint_against_udp_rule() -> None:
    ep = _endpoint(sock("udp", laddr="192.0.2.10", lport=5353))
    assert _status(_rule(ports={"protocol": "UDP", "local": ["5353"]}), ep) is R
    assert _status(_rule(ports={"protocol": "TCP", "local": ["5353"]}), ep) is N


def test_normalize_program_path() -> None:
    assert normalize_program_path("%SystemRoot%\\System32\\a.exe", ENV) == (
        "c:\\windows\\system32\\a.exe"
    )
    assert normalize_program_path('"C:/Tools/a.exe"', {}) == "c:\\tools\\a.exe"
    assert normalize_program_path("%USERPROFILE%\\a.exe", ENV) is None
    assert normalize_program_path("\\\\server\\share\\a.exe", {}) is None
    assert normalize_program_path("\\Device\\HarddiskVolume3\\a.exe", {}) is None


FORBIDDEN_CLAIMS = (
    "is reachable",
    "is exposed",
    "exposed to",
    "is allowed",
    "is blocked",
    "allows traffic",
    "blocks traffic",
    "open to the internet",
    "vulnerable",
)


def test_correlation_text_never_claims_reachability_or_permission() -> None:
    index = RuleIndex(_collection(rule={"profile": "Public"}), ENV)
    result = index.correlate(_endpoint())
    texts = [CORRELATION_DISCLAIMER, result.note]
    for relation in (*result.related, *result.cannot_evaluate):
        texts += [*relation.conditions, *relation.reasons, *(c.detail for c in relation.checks)]
    blob = " ".join(texts).lower()
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in blob, claim
