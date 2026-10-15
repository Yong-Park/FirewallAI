# PyInstaller spec for the FirewallAI one-folder Windows x64 development build (M1.5).
#
# Build with packaging/build.py from the isolated build environment (.venv-build: runtime
# dependencies + the "build" group only); see packaging/BUILD.md. Two executables share one
# _internal directory:
#   FirewallAI.exe      GUI, windowed (no console)
#   firewallai-cli.exe  CLI, console
# Both: asInvoker manifest (standard user; never elevated), no UPX, version resource, icon.
import sys
from pathlib import Path

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VarFileInfo,
    VarStruct,
    VSVersionInfo,
)

SPEC_DIR = Path(SPECPATH)  # SPECPATH is provided by PyInstaller
ROOT = SPEC_DIR.parent
sys.path.insert(0, str(SPEC_DIR))

from buildinfo import (
    APP_NAME,
    CLI_EXE,
    COMPANY,
    GUI_EXE,
    file_version,
    git_commit,
    project_version,
)
from make_icon import write_icon

VERSION = project_version(ROOT)
COMMIT = git_commit(ROOT)
ICON = write_icon(Path(workpath) / "firewallai.ico")  # workpath: PyInstaller

# Never bundle dev/build tooling or network-client modules the app does not use. A missing module
# fails loudly at runtime and is caught by the frozen smoke tests (packaging/smoke).
EXCLUDES = [
    # build tooling pulled in by the build environment
    "setuptools",
    "_distutils_hack",
    "pkg_resources",
    "distutils",
    # optional plug-ins of runtime packages that would drag in dev tools
    "pydantic.mypy",
    "pydantic.v1",
    "pydantic._hypothesis_plugin",
    "mypy",
    "hypothesis",
    # unused standard-library network clients/servers and UI toolkits
    "ssl",
    "_ssl",
    "http",
    "urllib.request",
    "ftplib",
    "smtplib",
    "imaplib",
    "poplib",
    "xmlrpc",
    "socketserver",
    "webbrowser",
    "asyncio",
    "multiprocessing",
    "tkinter",
    "unittest",
    "doctest",
    "pydoc",
    "pdb",
    "lib2to3",
]


def analysis(script: str):
    return Analysis(
        [str(SPEC_DIR / script)],
        pathex=[str(ROOT / "src")],
        excludes=EXCLUDES,
        noarchive=False,
        optimize=0,
    )


def version_info(internal_name: str, description: str) -> VSVersionInfo:
    fv = file_version(VERSION)
    product = VERSION + (f"+g{COMMIT[:8]}" if COMMIT else "")
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=fv, prodvers=fv, mask=0x3F, flags=0x0, OS=0x40004,
                          fileType=0x1, subtype=0x0, date=(0, 0)),
        kids=[
            StringFileInfo([
                StringTable("040904B0", [
                    StringStruct("CompanyName", COMPANY),
                    StringStruct("FileDescription", description),
                    StringStruct("FileVersion", VERSION),
                    StringStruct("InternalName", internal_name),
                    StringStruct("LegalCopyright", "MIT License. See licenses\\FirewallAI\\LICENSE."),
                    StringStruct("OriginalFilename", internal_name + ".exe"),
                    StringStruct("ProductName", APP_NAME + " (unsigned development build)"),
                    StringStruct("ProductVersion", product),
                ])
            ]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )


a_gui = analysis("entry_gui.py")
a_cli = analysis("entry_cli.py")
pyz_gui = PYZ(a_gui.pure)
pyz_cli = PYZ(a_cli.pure)

common_exe = dict(
    exclude_binaries=True,
    icon=str(ICON),
    upx=False,
    uac_admin=False,
    uac_uiaccess=False,
    debug=False,
    strip=False,
)
exe_gui = EXE(
    pyz_gui, a_gui.scripts, [], name=GUI_EXE, console=False,
    version=version_info(GUI_EXE, "FirewallAI read-only Windows Firewall auditor (GUI)"),
    **common_exe,
)
exe_cli = EXE(
    pyz_cli, a_cli.scripts, [], name=CLI_EXE, console=True,
    version=version_info(CLI_EXE, "FirewallAI read-only Windows Firewall auditor (CLI)"),
    **common_exe,
)
coll = COLLECT(
    exe_gui, a_gui.binaries, a_gui.datas,
    exe_cli, a_cli.binaries, a_cli.datas,
    upx=False,
    name=APP_NAME,
)
