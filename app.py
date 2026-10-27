"""BLOODSKY NET — Windows LAN/Wi-Fi diagnostics application."""
import os
import sys
from pathlib import Path


def main():
    if os.name != "nt" and not os.environ.get("BLOODSKY_ALLOW_NONWINDOWS"):
        print("BLOODSKY NET предназначен для Windows 10/11. Для запуска демо на Linux установите BLOODSKY_ALLOW_NONWINDOWS=1.")
        return 1
    from bloodsky_net.ui import NetApp
    app = NetApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
