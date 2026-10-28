"""Best-effort opt-in native Windows notifications. Never blocks UI or scans."""
from __future__ import annotations

import os
import threading


def send_windows_alert(title: str, detail: str) -> bool:
    """Display a Windows toast when supported. Never include SNMP secrets."""
    if os.name != 'nt':
        return False
    try:
        from winotify import Notification
        toast = Notification(app_id='BLOODSKY NET', title=str(title)[:90], msg=str(detail)[:200])
        toast.show()
        return True
    except Exception:
        # Some Windows sessions disable Action Center or lack notification permission.
        return False


def alert_async(title: str, detail: str) -> None:
    threading.Thread(target=send_windows_alert, args=(title, detail), daemon=True).start()
