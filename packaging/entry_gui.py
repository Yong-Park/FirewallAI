"""PyInstaller entry point for FirewallAI.exe (GUI, no console). See packaging/firewallai.spec."""

import sys

from firewallai.ui.app import main

if __name__ == "__main__":
    sys.exit(main())
