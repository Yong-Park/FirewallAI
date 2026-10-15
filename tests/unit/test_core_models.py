import pytest
from pydantic import ValidationError

from firewallai.core.models import (
    FirewallAction,
    FirewallProfile,
    ProfileName,
    TriState,
    profile_id,
)
from firewallai.core.results import CollectorError, CollectorErrorCode, CollectorResult
from firewallai.core.sensitivity import (
    DataClass,
    field_sensitivity,
    fields_of_class,
    unclassified_fields,
)


def _profile(**overrides: object) -> FirewallProfile:
    values: dict[str, object] = {
        "id": "fw_profile:public",
        "name": ProfileName.PUBLIC,
        "enabled": TriState.TRUE,
        "default_inbound_action": FirewallAction.BLOCK,
        "default_outbound_action": FirewallAction.ALLOW,
        "allow_inbound_rules": TriState.TRUE,
        "allow_local_firewall_rules": TriState.TRUE,
        "allow_local_ipsec_rules": TriState.TRUE,
        "notify_on_listen": TriState.TRUE,
        "log_allowed": TriState.FALSE,
        "log_blocked": TriState.FALSE,
    }
    values.update(overrides)
    return FirewallProfile.model_validate(values)


def test_profile_ids_are_stable_and_typed() -> None:
    assert profile_id(ProfileName.DOMAIN) == "fw_profile:domain"
    assert _profile().id == "fw_profile:public"


def test_profile_id_must_match_name() -> None:
    with pytest.raises(ValidationError):
        _profile(id="fw_profile:domain")


def test_profile_rejects_malformed_id_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _profile(id="Public Profile")
    with pytest.raises(ValidationError):
        _profile(unexpected="x")


def test_profile_is_immutable() -> None:
    profile = _profile()
    with pytest.raises(ValidationError):
        profile.enabled = TriState.FALSE  # type: ignore[misc]


def test_every_domain_field_declares_sensitivity() -> None:
    for model in (FirewallProfile, CollectorError):
        assert unclassified_fields(model) == frozenset(), model.__name__


def test_host_identifying_fields_are_host_sensitive() -> None:
    sensitive = fields_of_class(FirewallProfile, DataClass.HOST_SENSITIVE)
    assert sensitive == {"log_file_name", "disabled_interface_aliases"}
    assert (
        field_sensitivity(FirewallProfile, "default_inbound_action") is DataClass.DERIVED_ABSTRACT
    )


def test_collector_result_invariants() -> None:
    error = CollectorError(code=CollectorErrorCode.TIMEOUT, source="t", detail="")
    assert CollectorResult[int](data=1).ok
    assert not CollectorResult[int](errors=(error,)).ok
    assert CollectorResult[int](data=1, errors=(error,), partial=True).partial
    with pytest.raises(ValidationError):
        CollectorResult[int]()  # neither data nor errors
    with pytest.raises(ValidationError):
        CollectorResult[int](data=1, errors=(error,))  # must be marked partial
    with pytest.raises(ValidationError):
        CollectorResult[int](data=1, partial=True)  # partial without errors


def test_collector_error_detail_is_bounded() -> None:
    with pytest.raises(ValidationError):
        CollectorError(code=CollectorErrorCode.PARSE_ERROR, source="t", detail="x" * 301)
