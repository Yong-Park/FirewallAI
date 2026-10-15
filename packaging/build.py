"""Build the FirewallAI one-folder Windows x64 development bundle (M1.5). See packaging/BUILD.md.

Run from the isolated build environment (runtime dependencies + the "build" group only), with a
fixed hash seed and timestamp so that the build is reproducible (PowerShell):

    uv export --frozen --no-default-groups --format cyclonedx1.5 -o build/sbom.cdx.json
    $env:PYTHONHASHSEED = "0"; $env:SOURCE_DATE_EPOCH = "315532800"
    .venv-build\\Scripts\\python.exe -s -P packaging\\build.py --sbom build\\sbom.cdx.json

(``-s -P`` instead of ``-I``: ``-I`` would ignore PYTHONHASHSEED. PYTHONPATH must not be set.)

Steps: PyInstaller (packaging/firewallai.spec) -> third-party licenses -> README and build info ->
SBOM copy -> deterministic ZIP -> SHA256SUMS. No subprocesses, no network access, no uploads.
The output is an UNSIGNED DEVELOPMENT BUILD. It is never published by this script.
"""

import argparse
import hashlib
import importlib.metadata as md
import importlib.util
import json
import os
import platform
import shutil
import sys
import zipfile
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load_buildinfo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("buildinfo", ROOT / "packaging" / "buildinfo.py")
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load packaging/buildinfo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_info = _load_buildinfo()
APP_NAME: str = _info.APP_NAME
artifact_stem = _info.artifact_stem
git_commit = _info.git_commit
project_version = _info.project_version

# Distributions whose code ships inside the bundle (runtime dependencies + the bootloader).
BUNDLED_DISTRIBUTIONS = (
    "pydantic",
    "pydantic-core",
    "annotated-types",
    "typing-extensions",
    "typing-inspection",
    "psutil",
    "PySide6-Essentials",
    "shiboken6",
    "pyinstaller",  # bootloader only (GPLv2-or-later with the bootloader exception)
)
DEV_ONLY_MODULES = ("mypy", "pytest", "ruff", "hypothesis", "rich", "pygments")
LICENSE_HINTS = ("license", "licence", "copying", "notice", "authors")
ZIP_DATE = (1980, 1, 1, 0, 0, 0)

README = """FirewallAI {version} ({commit}) - UNSIGNED DEVELOPMENT BUILD

This is a portable, unsigned development build. It is NOT a public release, it is not code-signed,
and Windows SmartScreen or antivirus software may warn about it. Verify the SHA-256 checksum that
came with the ZIP before running it.

- FirewallAI.exe       desktop window (Profiles, Rules, Network)
- firewallai-cli.exe   command line: profiles | rules | endpoints  (--help for options)

FirewallAI is read-only and runs as a standard user. It never changes firewall settings, never
requests administrator rights, and sends nothing over the network. It does not write into this
folder.

Known limitations (not waived):
- N-04: a complete firewall rule scan takes about 27-35 s on the development machine, against a
  10 s target.
- The local endpoint snapshot takes about 0.7-0.9 s when warm but 1.2-1.7 s on a cold start
  (target 1 s).
- Results are local facts only: they do not show whether anything is reachable from other
  networks, and "related rules" are descriptive, not a statement that traffic is permitted.
- `firewallai-cli endpoints --json` output contains host-sensitive data (addresses, process
  paths). Do not share it publicly.

Third-party licenses: see the licenses folder and THIRD_PARTY_NOTICES.txt.
"""


def _require_build_environment() -> None:
    present = [m for m in DEV_ONLY_MODULES if importlib.util.find_spec(m) is not None]
    if present:
        raise SystemExit(
            f"refusing to build: dev tools are importable ({', '.join(present)}). "
            "Use the isolated build environment (.venv-build); see packaging/BUILD.md."
        )
    if os.environ.get("PYTHONPATH"):
        raise SystemExit("refusing to build: PYTHONPATH is set (the build must be isolated)")
    # Measured on TE-1 (M1.5): without these, two builds differed in 3 of 223 files; with them,
    # two builds (including the ZIP) were byte-identical.
    if sys.flags.hash_randomization or not os.environ.get("SOURCE_DATE_EPOCH", "").isdigit():
        raise SystemExit(
            "refusing to build: set PYTHONHASHSEED=0 and SOURCE_DATE_EPOCH for a reproducible "
            "build; see packaging/BUILD.md"
        )


def _license_files(dist: md.Distribution) -> list[tuple[str, bytes]]:
    out = []
    for f in dist.files or ():
        name = f.name.lower()
        parts = [p.lower() for p in f.parts]
        if any(h in name for h in LICENSE_HINTS) or "licenses" in parts:
            path = Path(str(dist.locate_file(f)))
            if path.is_file() and path.stat().st_size < 2_000_000:
                out.append((f.name, path.read_bytes()))
    return out


def write_licenses(bundle: Path) -> list[dict[str, str]]:
    lic_dir = bundle / "licenses"
    lic_dir.mkdir()
    (lic_dir / APP_NAME).mkdir()
    shutil.copyfile(ROOT / "LICENSE", lic_dir / APP_NAME / "LICENSE")
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    entries = [{"name": APP_NAME, "version": project_version(ROOT), "license": "MIT"}]
    if python_license.is_file():
        (lic_dir / "Python").mkdir()
        shutil.copyfile(python_license, lic_dir / "Python" / "LICENSE.txt")
    entries.append({"name": "CPython", "version": platform.python_version(), "license": "PSF-2.0"})
    for name in BUNDLED_DISTRIBUTIONS:
        dist = md.distribution(name)
        meta = dist.metadata
        expression = (
            meta.get("License-Expression")
            or ((meta.get("License") or "").strip().splitlines() or ["see license files"])[0]
        )
        target = lic_dir / f"{meta['Name']}-{dist.version}"
        target.mkdir()
        files = _license_files(dist)
        if not files:
            raise SystemExit(f"no license file found for {name}")
        for index, (fname, data) in enumerate(sorted(files)):
            (target / f"{index:02d}-{fname}").write_bytes(data)
        entries.append({"name": meta["Name"], "version": dist.version, "license": expression[:120]})
    notices = ["Third-party software bundled with FirewallAI", ""]
    notices += [f"- {e['name']} {e['version']}: {e['license']}" for e in entries]
    notices += [
        "",
        "Qt / PySide6 (LGPLv3) are dynamically linked: the Qt and PySide6 libraries in _internal",
        "can be replaced with compatible builds. Full license texts are in the licenses folder.",
    ]
    (bundle / "THIRD_PARTY_NOTICES.txt").write_text("\n".join(notices) + "\n", encoding="utf-8")
    return entries


def write_metadata(bundle: Path, version: str, commit: str | None, sbom: Path) -> None:
    import PyInstaller

    (bundle / "README.txt").write_text(
        README.format(version=version, commit=commit[:8] if commit else "unknown commit"),
        encoding="utf-8",
    )
    info = {
        "app": APP_NAME,
        "version": version,
        "source_commit": commit,
        "signed": False,
        "kind": "unsigned development build (not a public release)",
        "python": platform.python_version(),
        "pyinstaller": PyInstaller.__version__,
        "bundled_distributions": {
            md.distribution(n).metadata["Name"]: md.distribution(n).version
            for n in BUNDLED_DISTRIBUTIONS
        },
    }
    (bundle / "build-info.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(sbom, bundle / "sbom.cdx.json")


def deterministic_zip(bundle: Path, target: Path) -> None:
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(p for p in bundle.rglob("*") if p.is_file()):
            arcname = f"{APP_NAME}/{path.relative_to(bundle).as_posix()}"
            info = zipfile.ZipInfo(arcname, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes())


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sbom", type=Path, required=True, help="CycloneDX SBOM from uv export")
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--work", type=Path, default=ROOT / "build" / "pyinstaller")
    args = parser.parse_args()
    _require_build_environment()
    if not args.sbom.is_file():
        raise SystemExit("SBOM file not found; see packaging/BUILD.md")
    version = project_version(ROOT)
    commit = git_commit(ROOT)

    import PyInstaller.__main__

    PyInstaller.__main__.run(
        [
            str(ROOT / "packaging" / "firewallai.spec"),
            "--noconfirm",
            "--clean",
            "--log-level",
            "WARN",
            "--distpath",
            str(args.dist),
            "--workpath",
            str(args.work),
        ]
    )
    bundle = args.dist / APP_NAME
    write_licenses(bundle)
    write_metadata(bundle, version, commit, args.sbom)
    stem = artifact_stem(version, commit)
    archive = args.dist / f"{stem}.zip"
    deterministic_zip(bundle, archive)
    sbom_out = args.dist / f"{stem}.sbom.cdx.json"
    shutil.copyfile(args.sbom, sbom_out)
    sums = "".join(f"{sha256(p)}  {p.name}\n" for p in (archive, sbom_out))
    (args.dist / "SHA256SUMS.txt").write_text(sums, encoding="utf-8")
    size = sum(p.stat().st_size for p in bundle.rglob("*") if p.is_file())
    print(f"bundle: {bundle.name} ({size / 2**20:.1f} MiB)")
    print(f"archive: {archive.name} ({archive.stat().st_size / 2**20:.1f} MiB)")
    print(sums, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
