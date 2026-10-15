"""SB-01/SB-03: every registered PowerShell script is constant, read-only, and argument-safe."""

import re

import pytest

from firewallai.collectors.windows.powershell_runner import (
    WRAPPER_TEMPLATE,
    PowerShellScript,
    render_script,
)
from firewallai.collectors.windows.scripts import REGISTERED_SCRIPTS

pytestmark = pytest.mark.security

# Commands the constant wrapper itself may use.
WRAPPER_COMMANDS = frozenset({"ConvertTo-Json", "ConvertFrom-Json"})
# Verb-Noun tokens anywhere in the text (cmdlets and functions).
COMMAND_PATTERN = re.compile(r"\b([A-Za-z]+-[A-Za-z][A-Za-z0-9]*)\b")
# Read-only verbs only. Anything else (Set/New/Remove/Enable/Disable/Invoke/Start/...) is rejected.
READ_ONLY_VERBS = frozenset({"Get", "ConvertTo", "ConvertFrom", "ForEach", "Where", "Select"})
FORBIDDEN_SUBSTRINGS = (
    "netsh",
    "invoke-expression",
    "iex ",
    "start-process",
    "add-type",
    "encodedcommand",
    "executionpolicy",
    "bypass",
    "downloadstring",
    "net.webclient",
    "invoke-webrequest",
    "invoke-restmethod",
    "[system.reflection",
    "-verb runas",
)


def _commands(text: str) -> set[str]:
    # Ignore PowerShell parameters like -PolicyStore / -ErrorAction (they start with a dash).
    return {m.group(1) for m in COMMAND_PATTERN.finditer(text) if text[m.start() - 1] != "-"}


def test_registered_scripts_exist() -> None:
    assert REGISTERED_SCRIPTS
    assert len({s.name for s in REGISTERED_SCRIPTS}) == len(REGISTERED_SCRIPTS)


@pytest.mark.parametrize("script", REGISTERED_SCRIPTS, ids=lambda s: s.name)
def test_script_uses_only_allowlisted_read_only_commands(script: PowerShellScript) -> None:
    used = _commands(script.body)
    assert used <= script.allowed_commands, used - script.allowed_commands
    for command in script.allowed_commands:
        assert command.split("-")[0] in READ_ONLY_VERBS, command


@pytest.mark.parametrize("script", REGISTERED_SCRIPTS, ids=lambda s: s.name)
def test_rendered_script_has_no_forbidden_constructs(script: PowerShellScript) -> None:
    rendered = render_script(script)
    lowered = rendered.lower()
    for token in FORBIDDEN_SUBSTRINGS:
        assert token not in lowered, token
    # One -Command argument: double quotes would be re-parsed by the Windows command line.
    assert '"' not in rendered
    assert _commands(WRAPPER_TEMPLATE) <= WRAPPER_COMMANDS


@pytest.mark.parametrize("script", REGISTERED_SCRIPTS, ids=lambda s: s.name)
def test_scripts_have_bounded_resources(script: PowerShellScript) -> None:
    assert 0 < script.timeout_s <= 120
    assert 0 < script.max_output_bytes <= 16 * 1024 * 1024


def test_wrapper_token_cannot_be_smuggled() -> None:
    with pytest.raises(ValueError, match="wrapper token"):
        render_script(
            PowerShellScript(
                name="x", body="__FIREWALLAI_SCRIPT_BODY__", allowed_commands=frozenset()
            )
        )
