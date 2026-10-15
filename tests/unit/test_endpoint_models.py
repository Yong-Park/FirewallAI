"""M1.4 endpoint models: bind classification, explicit states, sensitivity, safe display."""

import pytest
from pydantic import BaseModel, ValidationError

from endpoint_builders import ALL_IPV4
from firewallai.core.endpoints import (
    BindScope,
    Endpoint,
    EndpointKind,
    EndpointSnapshot,
    IpFamily,
    Observed,
    ProcessInfo,
    TcpState,
    TransportProtocol,
    UnavailableReason,
    classify_bind,
    display_safe,
    endpoint_id,
)
from firewallai.core.sensitivity import DataClass, field_sensitivity, unclassified_fields


@pytest.mark.parametrize(
    ("address", "scope", "dual"),
    [
        ("127.0.0.1", BindScope.LOOPBACK, False),
        ("127.42.0.9", BindScope.LOOPBACK, False),
        ("::1", BindScope.LOOPBACK, False),
        ("::ffff:127.0.0.1", BindScope.LOOPBACK, False),  # IPv4-mapped loopback
        (ALL_IPV4, BindScope.ALL_INTERFACES, False),
        ("::", BindScope.ALL_INTERFACES, True),  # may also accept IPv4: unknown
        ("169.254.10.20", BindScope.LINK_LOCAL, False),
        ("fe80::1%12", BindScope.LINK_LOCAL, False),  # zone ID ignored
        ("192.0.2.10", BindScope.SPECIFIC, False),
        ("2001:db8::10", BindScope.SPECIFIC, False),
        ("not-an-address", BindScope.UNPARSEABLE, False),
        ("", BindScope.UNPARSEABLE, False),
    ],
)
def test_bind_scope_is_descriptive_and_explicit(address: str, scope: BindScope, dual: bool) -> None:
    assert classify_bind(address) == (scope, dual)


def test_observed_has_no_defaults() -> None:
    with pytest.raises(ValidationError):
        Observed[str](availability="collected")
    with pytest.raises(ValidationError):
        Observed[str](availability="unavailable", value="x")
    assert Observed[str].missing(UnavailableReason.ACCESS_DENIED).value is None


def test_unattributed_process_never_carries_details() -> None:
    with pytest.raises(ValidationError, match="no details"):
        ProcessInfo(
            pid=1000,
            attribution="unavailable",
            reason=UnavailableReason.ATTRIBUTION_UNVERIFIED,
            name=Observed.of("someone-else.exe"),
            image_path=Observed.missing(UnavailableReason.ATTRIBUTION_UNVERIFIED),
            services=Observed.missing(UnavailableReason.ATTRIBUTION_UNVERIFIED),
        )


def _ep(**over: object) -> Endpoint:
    base: dict[str, object] = {
        "id": endpoint_id(TransportProtocol.UDP, IpFamily.IPV4, "192.0.2.10", 53, None, None, 1),
        "protocol": TransportProtocol.UDP,
        "family": IpFamily.IPV4,
        "kind": EndpointKind.BOUND,
        "tcp_state": None,
        "local_address": "192.0.2.10",
        "local_port": 53,
        "bind_scope": BindScope.SPECIFIC,
        "dual_stack_unknown": False,
        "process": ProcessInfo.unattributed(None, UnavailableReason.NO_PID),
    }
    base.update(over)
    return Endpoint.model_validate(base)


def test_udp_is_bound_never_listening() -> None:
    assert _ep().kind is EndpointKind.BOUND
    with pytest.raises(ValidationError):
        _ep(kind=EndpointKind.LISTENING)
    with pytest.raises(ValidationError):
        _ep(tcp_state=TcpState.LISTEN)
    with pytest.raises(ValidationError):
        _ep(remote_address="198.51.100.1", remote_port=5000)


def test_tcp_kind_follows_reported_state() -> None:
    tcp = {"protocol": TransportProtocol.TCP}
    assert _ep(**tcp, kind=EndpointKind.LISTENING, tcp_state=TcpState.LISTEN).kind
    with pytest.raises(ValidationError):
        _ep(**tcp, kind=EndpointKind.CONNECTION, tcp_state=TcpState.LISTEN)
    with pytest.raises(ValidationError):
        _ep(**tcp, kind=EndpointKind.LISTENING, tcp_state=TcpState.ESTABLISHED)
    with pytest.raises(ValidationError):
        _ep(**tcp, kind=EndpointKind.CONNECTION, tcp_state=None)


@pytest.mark.parametrize("model", [Endpoint, ProcessInfo, EndpointSnapshot])
def test_every_field_declares_sensitivity(model: type[BaseModel]) -> None:
    assert unclassified_fields(model) == frozenset()


def test_addresses_and_process_identity_are_host_sensitive() -> None:
    for name in ("local_address", "remote_address", "process"):
        assert field_sensitivity(Endpoint, name) is DataClass.HOST_SENSITIVE
    for name in ("name", "image_path", "services"):
        assert field_sensitivity(ProcessInfo, name) is DataClass.HOST_SENSITIVE
    assert field_sensitivity(Endpoint, "local_port") is DataClass.DERIVED_ABSTRACT


@pytest.mark.parametrize(
    ("raw", "must_not_contain"),
    [
        ("evil‮exe.txt", "‮"),  # right-to-left override
        ("a​b", "​"),  # zero-width space
        ("line1\nline2\x1b[31m", "\x1b"),  # newline / terminal escape
        ("x" + chr(0x2028) + "y", chr(0x2028)),  # line separator
    ],
)
def test_display_safe_neutralizes_control_and_bidi(raw: str, must_not_contain: str) -> None:
    shown = display_safe(raw)
    assert must_not_contain not in shown
    assert "\\u" in shown


def test_display_safe_truncates_and_keeps_normal_text() -> None:
    assert display_safe("svchost.exe") == "svchost.exe"
    assert display_safe("ñandú.exe") == "ñandú.exe"
    long = display_safe("x" * 5000, max_len=50)
    assert len(long) == 50 and long.endswith("…")
