"""Builders for SYNTHETIC endpoint snapshots (no real host data).

Addresses use documentation ranges (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32). Process names,
paths, and service names are invented.
"""

import ipaddress
from types import SimpleNamespace
from typing import Any

APP_PATH = "C:\\Synthetic\\App\\synthetic.exe"
ALL_IPV4 = str(ipaddress.IPv4Address(0))  # the unspecified address, as data (not a bind)


def sock(
    protocol: str = "tcp",
    family: str = "ipv4",
    laddr: str = "192.0.2.10",
    lport: int = 8080,
    raddr: str | None = None,
    rport: int | None = None,
    status: str | None = None,
    pid: int | None = 1000,
) -> dict[str, Any]:
    if status is None:
        status = "NONE" if protocol == "udp" else ("LISTEN" if raddr is None else "ESTABLISHED")
    return {
        "protocol": protocol,
        "family": family,
        "local_address": laddr,
        "local_port": lport,
        "remote_address": raddr,
        "remote_port": rport,
        "status": status,
        "pid": pid,
    }


def proc(
    pid: int,
    name: str | None = "synthetic.exe",
    exe: str | None = APP_PATH,
    *,
    exited: bool = False,
    name_error: str | None = None,
    exe_error: str | None = None,
) -> dict[str, Any]:
    return {
        "pid": pid,
        "exited": exited,
        "name": {"value": None if name_error else name, "error": name_error},
        "exe": {"value": None if exe_error else exe, "error": exe_error},
    }


def snapshot(
    first: list[dict[str, Any]],
    *,
    second: list[dict[str, Any]] | None = None,
    processes: list[dict[str, Any]] | None = None,
    services: list[dict[str, Any]] | None = None,
    services_error: str | None = None,
    no_services: bool = False,
    **over: Any,
) -> dict[str, Any]:
    if processes is None:
        pids = sorted({s["pid"] for s in first if s["pid"] not in (None, 0, 4)})
        processes = [proc(p) for p in pids]
    raw: dict[str, Any] = {
        "first": first,
        "second": first if second is None else second,
        "processes": processes,
        "services": None if no_services else (services or []),
        "services_error": services_error,
    }
    raw.update(over)
    return raw


def psutil_conn(
    *,
    family: str = "AF_INET",
    kind: str = "SOCK_STREAM",
    laddr: tuple[Any, ...] = ("192.0.2.10", 8080),
    raddr: tuple[Any, ...] = (),
    status: str = "LISTEN",
    pid: int | None = 1000,
) -> SimpleNamespace:
    """A stand-in for a psutil ``sconn`` record."""
    return SimpleNamespace(
        family=SimpleNamespace(name=family),
        type=SimpleNamespace(name=kind),
        laddr=laddr,
        raddr=raddr,
        status=status,
        pid=pid,
    )
