# ADR 0001: Application language and UI, Python 3.12 + PySide6

- **Status:** Accepted. The human accepted D1 on 2026-10-14: "Python 3.12 as the project's pinned Python version". The PySide6 GUI was an earlier explicit human requirement ("Prioritize a professional PySide6 GUI").
- **Decision ID:** D1 · **Date:** 2026-10-14 · **Proposed by:** claude-code · **Decided by:** human, 2026-10-14
- **Implementation notes (M1.1):**
  - `requires-python = "==3.12.*"`, using the locally installed CPython 3.12.6 (uv `python-downloads = "never"`).
  - GUI dependency: `pyside6-essentials` 6.11.2. This is the official core subset of PySide6 (QtCore/QtGui/QtWidgets, without the Addons/WebEngine modules), giving a smaller install and attack surface.
  - Moving to 3.13+ requires a new ADR once PySide6, PyInstaller, and Nuitka support it [VERIFY then].

## 1. Problem
FirewallAI needs a maintainable Windows desktop application. It has to read firewall and network state, show complex tables, integrate local AI later, and be packaged as an installable EXE. The developer's learning goals and their existing Python/Ollama experience (P_proyect) matter.

## 2. Decision (recommended)
Python **3.12** (pinned) with **PySide6** (Qt for Python, LGPL-3.0). Move to 3.13 or later only once PySide6, PyInstaller, and Nuitka all officially support that version [VERIFY at Sprint 1].

## 3. Alternatives considered
- **C#/.NET 8+ with WPF or WinUI 3.** Technically the **stronger option for deep Windows integration**: native COM, WFP P/Invoke, Windows Services, MSIX, mature code signing. Not chosen for the main app because of learning goals, AI-ecosystem fit, and reuse of the Python/Ollama experience. Reconsidered for the privileged component ([ADR 0012](0012-native-component-language.md)).
- **PyQt6.** Same Qt, but GPL or commercial licensing. PySide6 is LGPL.
- **Tauri or Electron.** A web UI plus IPC to a backend means two stacks, and Electron is heavy.
- **Python 3.14** (installed as the system default). Too new for the packaging toolchain [VERIFY].

## 4. Advantages and disadvantages
- **Advantages:** fast iteration, rich data and AI libraries, Qt's mature model/view tables, accessibility support, and light/dark theming.
- **Disadvantages:** frozen Python apps are large, start slower, and trigger more antivirus false positives. The GIL means long work has to run in worker threads or processes. Windows API access goes through pywin32 or ctypes.

## 5. Security implications
- The bundled interpreter and its dependencies widen the attack surface. This is managed with a lockfile, pip-audit, and an SBOM.
- The frozen app is exposed to DLL search-order hijacking (CWE-427); see [14-packaging-distribution.md](../planning/14-packaging-distribution.md).
- LGPL obligations: PySide6 must stay dynamically linked and replaceable, and the license notice must ship.

## 6. Performance implications
Adequate for snapshot auditing: thousands of rules and endpoints. **Not** suitable for any per-packet path, which is out of scope anyway.

## 7. Validation
Sprint 1 spike:
1. Freeze a minimal PySide6 window that shows collector data from a background worker, using PyInstaller one-dir.
2. Install it on a clean Windows 11 VM.
3. Record startup time and bundle size.

Exit criterion: it runs on a clean VM without a Python install.

## 8. What to learn
- Qt signals and slots, model/view (`QAbstractTableModel`), and `QThreadPool`/`QRunnable`.
- Python packaging (src layout, `pyproject.toml`) and uv.
- LGPL obligations.
