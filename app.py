"""BLOODSKY NET — Windows LAN/Wi-Fi diagnostics application."""
import os
import sys


def main():
    # Safe, headless packaging smoke test for installed one-file EXEs and CI.
    # Never opens the GUI, scans the network or creates a real user database.
    if "--self-check" in sys.argv[1:]:
        try:
            from bloodsky_net.selfcheck import run_self_check
            if run_self_check():
                print("BLOODSKY NET self-check OK")
                return 0
        except Exception:
            pass  # Do not print internal paths or diagnostic command arguments.
        print("BLOODSKY NET self-check FAILED", file=sys.stderr)
        return 2
    if os.name != "nt" and not os.environ.get("BLOODSKY_ALLOW_NONWINDOWS"):
        print("BLOODSKY NET предназначен для Windows 10/11. Для запуска демо на Linux установите BLOODSKY_ALLOW_NONWINDOWS=1.")
        return 1
    from bloodsky_net.ui import NetApp
    app = NetApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
