"""Shared test configuration.

- Qt runs offscreen, so UI tests need no visible desktop.
- SB-05 guard: any attempt to open a network connection fails the test (v0.1 has zero egress).
"""

import os
import socket
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

FIXTURES = Path(__file__).parent / "fixtures"


class NetworkAccessError(AssertionError):
    pass


def _deny(*_args: Any, **_kwargs: Any) -> Any:
    raise NetworkAccessError("network access is forbidden in FirewallAI v0.1 tests (SB-05)")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    yield


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if sys.platform == "win32":
        return
    skip = pytest.mark.skip(reason="requires a real Windows host")
    for item in items:
        if "windows" in item.keywords:
            item.add_marker(skip)
