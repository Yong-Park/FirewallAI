"""PyInstaller entry point for firewallai-cli.exe (console). See packaging/firewallai.spec."""

import sys

from firewallai.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
