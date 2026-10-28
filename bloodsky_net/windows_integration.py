"""Optional Windows user-session integration; no admin rights, credentials or services."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "BLOODSKY NET"


def startup_command(executable: str | None = None, script: str | None = None,
                    frozen: bool | None = None) -> str:
    """Quote every argument, support PyInstaller EXE and source-mode pythonw."""
    exe = executable or sys.executable
    is_frozen = getattr(sys, "frozen", False) if frozen is None else frozen
    if is_frozen:
        arguments = [exe, "--minimized"]
    else:
        path = Path(exe)
        gui_exe = path.with_name("pythonw.exe")
        if path.name.lower() == "python.exe" and gui_exe.exists():
            exe = str(gui_exe)
        arguments = [exe, str(Path(script or sys.argv[0]).resolve()), "--minimized"]
    return subprocess.list2cmdline(arguments)


def is_autostart_enabled() -> bool:
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, kind = winreg.QueryValueEx(key, RUN_NAME)
            return kind == winreg.REG_SZ and bool(value)
    except FileNotFoundError:
        return False


def set_autostart(enabled: bool) -> bool:
    """Only the current user's HKCU entry, never HKLM or elevation."""
    if os.name != "nt":
        raise OSError("Автозапуск поддерживается только в Windows")
    import winreg
    if enabled:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, RUN_NAME, 0, winreg.REG_SZ, startup_command())
    else:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, RUN_NAME)
        except FileNotFoundError:
            pass
    return is_autostart_enabled()
