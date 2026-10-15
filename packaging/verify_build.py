"""Verify a built FirewallAI bundle (M1.5) before anyone runs or shares it. Exit 1 on any failure.

Run from the isolated build environment (needs PyInstaller's archive reader and pefile):

    .venv-build\\Scripts\\python.exe -I packaging\\verify_build.py dist

Checks:
1. Layout: only the expected top-level entries; no sources, tests, VCS, or env files.
2. Both executables: asInvoker manifest (uiAccess false), GUI/console subsystem, version resource
   matching the project version, an icon, and no UPX packing.
3. Code integrity: every ``firewallai`` module inside each executable is structurally identical to
   the reviewed source (bytecode, constants including the PowerShell script bodies, names, line
   tables), and the registered PowerShell scripts are present.
4. Attack surface: network-client, async, multiprocessing, and dev-tool modules are absent.
5. No embedded local data: no absolute source paths in code objects, and neither the build user
   name, the computer name, nor the source directory appears in any bundled file.
6. Licenses, notices, README, build info (unsigned), SBOM, and SHA-256 sums are present and valid.
Prints a JSON report; prints no host data.
"""

import hashlib
import json
import os
import re
import sys
import zipfile
from pathlib import Path
from types import CodeType
from typing import Any

import pefile
from PyInstaller.archive.readers import CArchiveReader

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOP_LEVEL = {
    "FirewallAI.exe",
    "firewallai-cli.exe",
    "_internal",
    "licenses",
    "README.txt",
    "THIRD_PARTY_NOTICES.txt",
    "build-info.json",
    "sbom.cdx.json",
}
FORBIDDEN_MODULES = (
    "ssl",
    "_ssl",
    "http",
    "urllib.request",
    "ftplib",
    "smtplib",
    "xmlrpc",
    "socketserver",
    "asyncio",
    "multiprocessing",
    "webbrowser",
    "setuptools",
    "pkg_resources",
    "mypy",
    "pytest",
    "_pytest",
    "hypothesis",
    "rich",
    "pygments",
    "tkinter",
    "unittest",
    "pydoc",
)
FORBIDDEN_PATH_PARTS = {".git", ".env", ".venv", "tests", "scratchpad", "__pycache__", ".claude"}
REQUIRED_MODULES = (
    "firewallai.collectors.windows.scripts",
    "firewallai.collectors.windows.powershell_runner",
    "firewallai.collectors.windows.network_endpoints",
    "firewallai.core.evidence",
    "firewallai.core.correlation",
)
RUNTIME_SBOM_COMPONENTS = {
    "annotated-types",
    "psutil",
    "pydantic",
    "pydantic-core",
    "pyside6-essentials",
    "shiboken6",
    "typing-extensions",
    "typing-inspection",
}
RT_MANIFEST, RT_GROUP_ICON = 24, 14


class Report:
    def __init__(self) -> None:
        self.checks: dict[str, Any] = {}
        self.failures: list[str] = []

    def check(self, name: str, ok: bool, detail: Any = None) -> None:
        self.checks[name] = {"ok": ok, **({"detail": detail} if detail is not None else {})}
        if not ok:
            self.failures.append(name)


def _project_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    if match is None:
        raise SystemExit("cannot read project version")
    return match.group(1)


def _resource(pe: pefile.PE, type_id: int) -> bytes | None:
    resources = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    for entry in resources.entries if resources is not None else ():
        if entry.id == type_id:
            leaf = entry.directory.entries[0].directory.entries[0].data.struct
            return bytes(pe.get_data(leaf.OffsetToData, leaf.Size))
    return None


def _version_strings(pe: pefile.PE) -> dict[str, str]:
    out: dict[str, str] = {}
    for info in getattr(pe, "FileInfo", []) or []:
        for item in info:
            for table in getattr(item, "StringTable", []) or []:
                out.update({k.decode(): v.decode() for k, v in table.entries.items()})
    return out


def check_executable(report: Report, path: Path, gui: bool, version: str) -> None:
    pe = pefile.PE(str(path))
    name = path.name
    manifest = (_resource(pe, RT_MANIFEST) or b"").decode("utf-8", "replace")
    level = re.findall(r'requestedExecutionLevel\s+level="([^"]+)"\s+uiAccess="([^"]+)"', manifest)
    report.check(f"{name}: asInvoker manifest", level == [("asInvoker", "false")], level)
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    report.check(f"{name}: subsystem", subsystem == (2 if gui else 3), subsystem)
    strings = _version_strings(pe)
    report.check(
        f"{name}: version resource",
        strings.get("FileVersion") == version
        and strings.get("ProductVersion", "").startswith(version)
        and strings.get("OriginalFilename") == name,
        {k: strings.get(k) for k in ("FileVersion", "ProductVersion", "OriginalFilename")},
    )
    report.check(f"{name}: icon", _resource(pe, RT_GROUP_ICON) is not None)
    sections = [s.Name.rstrip(b"\0").decode("ascii", "replace") for s in pe.sections]
    report.check(f"{name}: not UPX-packed", not any(s.startswith("UPX") for s in sections))
    pe.close()


def _all_code(co: CodeType) -> list[CodeType]:
    out = [co]
    for const in co.co_consts:
        if isinstance(const, CodeType):
            out += _all_code(const)
    return out


def check_archive(report: Report, path: Path) -> None:
    name = path.name
    pyz = CArchiveReader(str(path)).open_embedded_archive("PYZ.pyz")
    modules = list(pyz.toc)
    present = [
        m for m in FORBIDDEN_MODULES if any(n == m or n.startswith(m + ".") for n in modules)
    ]
    report.check(f"{name}: forbidden modules absent", not present, present)
    missing = [m for m in REQUIRED_MODULES if m not in modules]
    report.check(f"{name}: required modules present", not missing, missing)
    mismatched, absolute = [], 0
    for module in sorted(n for n in modules if n == "firewallai" or n.startswith("firewallai.")):
        bundled = pyz.extract(module)
        if not isinstance(bundled, CodeType):
            mismatched.append(module)
            continue
        parts = module.split(".")
        candidates = [SRC.joinpath(*parts).with_suffix(".py"), SRC.joinpath(*parts, "__init__.py")]
        source = next((c for c in candidates if c.is_file()), None)
        if source is None:
            mismatched.append(module)
            continue
        compiled = compile(source.read_bytes(), bundled.co_filename, "exec", optimize=0)
        if compiled != bundled:
            mismatched.append(module)
        absolute += sum(
            1 for co in _all_code(bundled) if re.match(r"^([A-Za-z]:|\\\\|/)", co.co_filename)
        )
    report.check(f"{name}: firewallai modules identical to source", not mismatched, mismatched)
    report.check(f"{name}: no absolute source paths in code", absolute == 0, absolute)


def check_layout(report: Report, bundle: Path) -> None:
    top = {p.name for p in bundle.iterdir()}
    report.check("layout: top-level entries", top == TOP_LEVEL, sorted(top ^ TOP_LEVEL))
    bad = [
        p.relative_to(bundle).as_posix()
        for p in bundle.rglob("*")
        if FORBIDDEN_PATH_PARTS & {part.lower() for part in p.relative_to(bundle).parts}
        or (p.is_file() and p.suffix in (".py", ".pyc") and "_internal" not in p.parts)
    ]
    report.check("layout: no sources, tests, VCS, env, or scratch files", not bad, bad[:10])


def check_no_local_data(report: Report, bundle: Path) -> None:
    needles = [str(ROOT), str(ROOT).replace("\\", "/")]
    for var in ("USERNAME", "COMPUTERNAME"):
        value = os.environ.get(var, "")
        if len(value) >= 4:
            needles.append(value)
    patterns = [n.encode("utf-8") for n in needles] + [n.encode("utf-16-le") for n in needles]
    patterns += [p.lower() for p in patterns]
    hits = []
    for path in bundle.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            low = data.lower()
            if any(p in data or p in low for p in patterns):
                hits.append(path.relative_to(bundle).as_posix())
    # Only counts and file names are reported, never the matched values.
    report.check("no build user, computer name, or source path in any file", not hits, hits[:10])


def check_metadata(report: Report, bundle: Path, version: str) -> None:
    info = json.loads((bundle / "build-info.json").read_text(encoding="utf-8"))
    report.check(
        "build-info: version and unsigned",
        info.get("version") == version and info.get("signed") is False,
        {"version": info.get("version"), "signed": info.get("signed")},
    )
    readme = (bundle / "README.txt").read_text(encoding="utf-8")
    report.check(
        "README: unsigned development build and limitations",
        "UNSIGNED DEVELOPMENT BUILD" in readme and "N-04" in readme and "cold start" in readme,
    )
    sbom = json.loads((bundle / "sbom.cdx.json").read_text(encoding="utf-8"))
    names = {c.get("name") for c in sbom.get("components", [])}
    report.check(
        "SBOM: CycloneDX runtime components",
        sbom.get("bomFormat") == "CycloneDX" and names == RUNTIME_SBOM_COMPONENTS,
        sorted(names ^ RUNTIME_SBOM_COMPONENTS),
    )
    lic = bundle / "licenses"
    empty = [d.name for d in lic.iterdir() if d.is_dir() and not any(d.iterdir())]
    report.check("licenses: present for every bundled component", len(empty) == 0, empty)
    notices = (bundle / "THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
    report.check("notices: LGPL replaceability statement", "LGPL" in notices)


def check_release_files(report: Report, dist: Path, bundle: Path) -> None:
    sums = dist / "SHA256SUMS.txt"
    ok = sums.is_file()
    if ok:
        for line in sums.read_text(encoding="utf-8").splitlines():
            digest, _, name = line.partition("  ")
            target = dist / name
            ok = (
                ok
                and target.is_file()
                and hashlib.sha256(target.read_bytes()).hexdigest() == digest
            )
    report.check("SHA256SUMS: matches artifacts", ok)
    archives = sorted(dist.glob("*-win64-portable.zip"))
    zip_ok = len(archives) == 1
    if zip_ok:
        with zipfile.ZipFile(archives[0]) as zf:
            names = {n.split("/", 1)[1] for n in zf.namelist()}
        files = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file()}
        zip_ok = names == files
    report.check("ZIP: contains exactly the bundle", zip_ok)


def main() -> int:
    dist = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist"
    bundle = dist / "FirewallAI"
    version = _project_version()
    report = Report()
    check_layout(report, bundle)
    for exe, gui in (("FirewallAI.exe", True), ("firewallai-cli.exe", False)):
        check_executable(report, bundle / exe, gui, version)
        check_archive(report, bundle / exe)
    check_no_local_data(report, bundle)
    check_metadata(report, bundle, version)
    check_release_files(report, dist, bundle)
    size = sum(p.stat().st_size for p in bundle.rglob("*") if p.is_file())
    files = sum(1 for p in bundle.rglob("*") if p.is_file())
    print(
        json.dumps(
            {
                "bundle_mib": round(size / 2**20, 1),
                "files": files,
                "checks": report.checks,
                "failures": report.failures,
            },
            indent=2,
        )
    )
    return 1 if report.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
