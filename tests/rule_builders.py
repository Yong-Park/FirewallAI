"""Builders for SYNTHETIC rule-stream events (no real host data).

Addresses use documentation ranges (192.0.2.0/24, 2001:db8::/32). Names and paths are invented.
"""

from typing import Any


def raw_rule(rid: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": rid,
        "display": f"Synthetic rule {rid}",
        "description": "",
        "group": "",
        "direction": "Inbound",
        "action": "Allow",
        "enabled": "True",
        "profile": "Any",
        "source_type": "Local",
        "enforcement": "Enforced",
        "primary_status": "OK",
        "edge": "Block",
        "has_owner": False,
        "dynamic_keywords": [],
        "local_only_mapping": False,
        "loose_source_mapping": False,
    }
    base.update(over)
    return base


def inventory(rules: list[dict[str, Any]], **over: Any) -> dict[str, Any]:
    ids = [r["id"] for r in rules]
    event: dict[str, Any] = {
        "stage": "inventory",
        "rules": rules,
        "apps": [{"id": i, "program": "Any", "package": "Any"} for i in ids],
        "services": [{"id": i, "service": "Any"} for i in ids],
        "security": [
            {
                "id": i,
                "authentication": "NotRequired",
                "encryption": "NotRequired",
                "override_block": "False",
                "local_user": "Any",
                "remote_user": "Any",
                "remote_machine": "Any",
            }
            for i in ids
        ],
    }
    event.update(over)
    return event


def port(rid: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": rid,
        "protocol": "TCP",
        "local": ["443"],
        "remote": ["Any"],
        "icmp": ["Any"],
        "dynamic_target": "Any",
        "dynamic_transport": "Any",
    }
    base.update(over)
    return base


def address(rid: str, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"id": rid, "local": ["Any"], "remote": ["Any"]}
    base.update(over)
    return base


def detail(
    ids: list[str],
    *,
    done: int,
    total: int,
    ports: list[dict[str, Any]] | None = None,
    addresses: list[dict[str, Any]] | None = None,
    iftypes: list[dict[str, Any]] | None = None,
    ifaliases: list[dict[str, Any]] | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "stage": "detail",
        "done": done,
        "total": total,
        "ids": ids,
        "port": ports if ports is not None else [port(i) for i in ids],
        "address": addresses if addresses is not None else [address(i) for i in ids],
        "iftype": iftypes if iftypes is not None else [{"id": i, "type": "Any"} for i in ids],
        "ifalias": ifaliases
        if ifaliases is not None
        else [{"id": i, "aliases": ["Any"]} for i in ids],
        "errors": errors or [],
    }


def complete_fixture(n: int = 4, chunk: int = 2) -> dict[str, Any]:
    ids = [f"Rule-{i}" for i in range(n)]
    events: list[dict[str, Any]] = [inventory([raw_rule(i) for i in ids])]
    for start in range(0, n, chunk):
        part = ids[start : start + chunk]
        events.append(detail(part, done=start + len(part), total=n))
    return {"events": events, "final_error": None}
