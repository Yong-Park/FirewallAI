"""M1.5 CI finding: local-data scan of the bundle (packaging/privacy_scan.py).

Regression for PR #8's first CI failure: on a GitHub-hosted Windows runner the build user is
``runneradmin``, and pydantic-core's published wheel embeds its OWN upstream build paths
(``C:\\Users\\runneradmin\\.cargo\\registry\\...``). Data below is synthetic.
"""

import base64
import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
BS = chr(92)
SOURCE = f"D:{BS}a{BS}FirewallAI{BS}FirewallAI"
UPSTREAM = f"C:{BS}Users{BS}runneradmin{BS}.cargo{BS}registry{BS}src{BS}index.crates.io-x{BS}a.rs"
PYD = "pydantic_core/_pydantic_core.cp312-win_amd64.pyd"
RUNTIME = ("pydantic-core", "psutil")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "privacy_scan", ROOT / "packaging" / "privacy_scan.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ps = _load()


def _record_line(path: str, data: bytes) -> str:
    b64 = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
    return f"{path},sha256={b64},{len(data)}"


def _index(*entries: tuple[str, bytes], dist: str = "pydantic-core") -> object:
    record = "\n".join([_record_line(p, d) for p, d in entries] + ["x.dist-info/RECORD,,"])
    return ps.wheel_index({dist: record}, allowed=RUNTIME)


UPSTREAM_PYD = b"\x00MZ" + UPSTREAM.encode() + b"\x00panic"


def _scan(files: list[tuple[str, bytes]], index: object, user: str = "runneradmin") -> object:
    return ps.scan(files, source_needles=[SOURCE], identity_needles=[user, ""], index=index)


def test_ci_scenario_upstream_wheel_file_is_attributed_not_failed() -> None:
    files = [(f"_internal/{PYD}", UPSTREAM_PYD)]
    result = _scan(files, _index((PYD, UPSTREAM_PYD)))
    assert result.ok
    assert result.attributed_upstream == [(f"_internal/{PYD}", "pydantic-core")]


def test_original_failure_without_provenance_still_fails() -> None:
    """Without a matching RECORD entry the same bytes are a failure (the old behaviour)."""
    result = _scan([(f"_internal/{PYD}", UPSTREAM_PYD)], ps.wheel_index({}, allowed=()))
    assert not result.ok and result.identity_hits == [f"_internal/{PYD}"]


def test_modified_upstream_file_loses_the_exception() -> None:
    tampered = UPSTREAM_PYD + b"x"
    result = _scan([(f"_internal/{PYD}", tampered)], _index((PYD, UPSTREAM_PYD)))
    assert not result.ok and result.identity_hits == [f"_internal/{PYD}"]


def test_source_path_is_never_exempt_even_in_upstream_identical_files() -> None:
    data = UPSTREAM_PYD + SOURCE.encode()
    result = _scan([(f"_internal/{PYD}", data)], _index((PYD, data)))
    assert result.source_path_hits == [f"_internal/{PYD}"] and not result.ok


@pytest.mark.parametrize(
    "relpath",
    [
        "firewallai-cli.exe",  # our executables are never upstream content
        "build-info.json",
        "_internal/base_library.zip",
        "_internal/planted.txt",
        "pydantic_core/_pydantic_core.cp312-win_amd64.pyd",  # outside _internal
    ],
)
def test_no_exception_outside_recorded_wheel_files(relpath: str) -> None:
    result = _scan([(relpath, UPSTREAM_PYD)], _index((PYD, UPSTREAM_PYD)))
    assert result.identity_hits == [relpath]


@pytest.mark.parametrize(
    "encoded",
    [
        b"built by RUNNERADMIN",
        "user=runneradmin".encode("utf-16-le"),
        "RunnerAdmin".encode("utf-16-le"),
    ],
    ids=["upper-utf8", "utf16", "mixed-utf16"],
)
def test_identity_matching_is_case_insensitive_utf8_and_utf16(encoded: bytes) -> None:
    result = _scan([("_internal/x.dat", encoded)], ps.wheel_index({}, allowed=()))
    assert result.identity_hits == ["_internal/x.dat"]


def test_source_path_matching_both_slash_styles_and_utf16() -> None:
    files = [
        ("a.txt", SOURCE.lower().encode()),
        ("b.txt", SOURCE.replace(BS, "/").encode("utf-16-le")),
    ]
    result = ps.scan(
        files,
        source_needles=[SOURCE, SOURCE.replace(BS, "/")],
        identity_needles=[],
        index=ps.wheel_index({}, allowed=()),
    )
    assert result.source_path_hits == ["a.txt", "b.txt"]


def test_short_identity_values_are_ignored_but_real_ones_kept() -> None:
    result = ps.scan(
        [("a.txt", b"abc"), ("b.txt", b"name=ci-host-01")],
        source_needles=[],
        identity_needles=["abc", "ci-host-01"],
        index=ps.wheel_index({}, allowed=()),
    )
    assert result.identity_hits == ["b.txt"]


def test_record_parsing() -> None:
    data = b"hello"
    parsed = ps.parse_record(
        "\n".join(
            [
                _record_line("pkg/a.py", data),
                "pkg/b.py,,",  # unhashed: ignored
                "pkg/c.py,sha256=!!!,3",  # invalid: ignored
                "pkg\\d.py," + _record_line("x", data).split(",", 1)[1],  # backslashes normalised
            ]
        )
    )
    assert parsed == {
        "pkg/a.py": hashlib.sha256(data).hexdigest(),
        "pkg/d.py": hashlib.sha256(data).hexdigest(),
    }


# --- final review (human, 2026-10-15): path + hash binding, runtime-only, explicit reporting ------

OTHER = "pydantic_core/other.pyd"
OTHER_BYTES = b"other upstream file " + UPSTREAM.encode()


def test_a_hash_recorded_for_another_file_cannot_authorize_a_different_path() -> None:
    """The bundled PYD path is recorded, but its bytes are those of OTHER: no exemption."""
    index = _index((PYD, UPSTREAM_PYD), (OTHER, OTHER_BYTES))
    result = _scan([(f"_internal/{PYD}", OTHER_BYTES)], index)
    assert result.identity_hits == [f"_internal/{PYD}"] and result.attributed_upstream == []


def test_an_unrecorded_path_with_bytes_of_a_recorded_file_is_not_authorized() -> None:
    index = _index((OTHER, OTHER_BYTES))
    result = _scan([("_internal/pydantic_core/copied.pyd", OTHER_BYTES)], index)
    assert result.identity_hits == ["_internal/pydantic_core/copied.pyd"]


def test_only_runtime_distributions_can_vouch_for_files() -> None:
    record = _record_line(PYD, UPSTREAM_PYD)
    index = ps.wheel_index({"pyinstaller": record, "Some_Dev_Tool": record}, allowed=RUNTIME)
    result = _scan([(f"_internal/{PYD}", UPSTREAM_PYD)], index)
    assert result.identity_hits == [f"_internal/{PYD}"]


def test_distribution_names_are_normalized() -> None:
    index = ps.wheel_index({"Pydantic_Core": _record_line(PYD, UPSTREAM_PYD)}, allowed=RUNTIME)
    assert _scan([(f"_internal/{PYD}", UPSTREAM_PYD)], index).ok


def test_ambiguous_path_recorded_by_two_distributions_is_dropped() -> None:
    clash = {
        "pydantic-core": _record_line(PYD, UPSTREAM_PYD),
        "psutil": _record_line(PYD, UPSTREAM_PYD + b"different"),
    }
    index = ps.wheel_index(clash, allowed=RUNTIME)
    assert PYD not in index
    assert _scan([(f"_internal/{PYD}", UPSTREAM_PYD)], index).identity_hits == [f"_internal/{PYD}"]
    same = {
        "pydantic-core": _record_line(PYD, UPSTREAM_PYD),
        "psutil": _record_line(PYD, UPSTREAM_PYD),
    }
    assert PYD in ps.wheel_index(same, allowed=RUNTIME)  # identical hashes are not ambiguous


def test_every_attributed_match_is_reported() -> None:
    index = _index((PYD, UPSTREAM_PYD), (OTHER, OTHER_BYTES))
    files = [(f"_internal/{PYD}", UPSTREAM_PYD), (f"_internal/{OTHER}", OTHER_BYTES)]
    result = _scan(files, index)
    assert result.ok
    assert result.attributed_upstream == [
        (f"_internal/{PYD}", "pydantic-core"),
        (f"_internal/{OTHER}", "pydantic-core"),
    ]


@pytest.mark.parametrize(
    "relpath",
    ["FirewallAI.exe", "firewallai-cli.exe", "_internal/base_library.zip", "README.txt"],
)
def test_own_build_outputs_never_exempt_even_with_a_forged_record(relpath: str) -> None:
    """Our executables/archives fail even if a RECORD (wrongly) listed their exact bytes."""
    data = b"MZ built by runneradmin"
    index = ps.wheel_index({"pydantic-core": _record_line(relpath, data)}, allowed=RUNTIME)
    assert _scan([(relpath, data)], index).identity_hits == [relpath]


@pytest.mark.parametrize("inner", ["base_library.zip", "python312.dll", "pydantic_core.pyd"])
def test_top_level_internal_files_are_never_exempt_even_with_a_forged_record(inner: str) -> None:
    """A RECORD entry naming a top-level _internal file (build output, not wheel content) is
    ignored: wheel files always live inside a package directory."""
    data = b"PK built by runneradmin"
    index = ps.wheel_index({"pydantic-core": _record_line(inner, data)}, allowed=RUNTIME)
    relpath = f"_internal/{inner}"
    assert _scan([(relpath, data)], index).identity_hits == [relpath]
