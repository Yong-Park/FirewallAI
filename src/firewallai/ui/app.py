"""GUI entry point: ``firewallai-gui [--fixture PATH] [--rules-fixture PATH]``."""

import argparse
import gc
import sys
from collections.abc import Sequence
from pathlib import Path

from PySide6.QtWidgets import QApplication

from firewallai.app.endpoint_service import create_endpoint_scan_service
from firewallai.app.profile_service import create_profile_service
from firewallai.app.rule_service import create_rule_scan_service
from firewallai.ui.main_window import MainWindow


def prepare_gc_for_gui() -> None:
    """Move objects alive at startup (modules, Qt bindings, models) out of the GC's scan set.

    Full (generation-2) collections then scan only objects created later. During rule
    collection, full collections triggered on the worker thread took 35-90 ms each and held the
    GIL, stalling the GUI (measured, M1.3). ``gc.freeze`` is a standard technique for
    long-running Python GUI processes; frozen startup objects are simply never collected.

    Memory implications: frozen objects are still freed by reference counting; only *cyclic*
    garbage among them is never reclaimed, so it runs once, after a full collection, before any
    scan. Scan data is created later and stays collectable. Call it once per process only:
    repeated calls would pin each scan's results. Repeated scans showed no growth in the frozen
    or tracked object counts (probe recorded in docs/development/HANDOFF.md).
    """
    gc.collect()
    gc.freeze()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="firewallai-gui")
    parser.add_argument("--fixture", type=Path, default=None)
    parser.add_argument("--rules-fixture", type=Path, default=None)
    parser.add_argument("--endpoints-fixture", type=Path, default=None)
    args, qt_args = parser.parse_known_args(argv)
    app = QApplication([sys.argv[0], *qt_args])
    window = MainWindow(
        create_profile_service(fixture=args.fixture),
        rule_service=create_rule_scan_service(fixture=args.rules_fixture),
        endpoint_service=create_endpoint_scan_service(fixture=args.endpoints_fixture),
    )
    prepare_gc_for_gui()
    window.show()
    window.refresh()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
