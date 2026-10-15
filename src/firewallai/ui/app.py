"""GUI entry point: ``firewallai-gui [--fixture PATH]``."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from PySide6.QtWidgets import QApplication

from firewallai.app.profile_service import create_profile_service
from firewallai.ui.main_window import MainWindow


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="firewallai-gui")
    parser.add_argument("--fixture", type=Path, default=None)
    args, qt_args = parser.parse_known_args(argv)
    app = QApplication([sys.argv[0], *qt_args])
    window = MainWindow(create_profile_service(fixture=args.fixture))
    window.show()
    window.refresh()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
