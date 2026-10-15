import io
import json
from pathlib import Path

import pytest

from firewallai.cli.main import EXIT_FAILED, EXIT_OK, EXIT_PARTIAL, main


def test_profiles_json_from_fixture(fixtures_dir: Path) -> None:
    out = io.StringIO()
    code = main(
        ["profiles", "--json", "--fixture", str(fixtures_dir / "profiles" / "win11_default.json")],
        out=out,
    )
    assert code == EXIT_OK
    doc = json.loads(out.getvalue())
    assert doc["schema"] == "firewallai.profiles/1"
    assert doc["read_only"] is True
    assert doc["scope"] == "local_policy_only"
    assert [p["name"] for p in doc["profiles"]] == ["domain", "private", "public"]
    assert doc["errors"] == []


def test_partial_data_exit_code(fixtures_dir: Path) -> None:
    out = io.StringIO()
    code = main(
        ["profiles", "--fixture", str(fixtures_dir / "profiles" / "invalid_values.json")],
        out=out,
    )
    assert code == EXIT_PARTIAL
    assert "Limitation:" in out.getvalue()
    assert "Read-only" in out.getvalue()


def test_failed_collection_exit_code(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"profiles": []}', encoding="utf-8")
    assert main(["profiles", "--json", "--fixture", str(bad)], out=io.StringIO()) == EXIT_FAILED


def test_unknown_command_is_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["delete-rules"])
    assert exc.value.code == 2
