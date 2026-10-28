"""Windows notification-area icon; all Tk actions must execute on Tk's main thread."""
from __future__ import annotations

import os
import threading
from typing import Callable


class TrayController:
    def __init__(self, on_show: Callable[[], None], on_exit: Callable[[], None]):
        self.on_show = on_show
        self.on_exit = on_exit
        self.icon = None
        self.thread: threading.Thread | None = None
        self._ready = threading.Event()

    @property
    def active(self) -> bool:
        return self.icon is not None and self._ready.is_set() and self.thread is not None and self.thread.is_alive()

    def start(self) -> bool:
        if os.name != "nt":
            return False
        if self.active:
            return True
        try:
            import pystray
            from PIL import Image, ImageDraw
            picture = Image.new("RGBA", (64, 64), "#101b2d")
            canvas = ImageDraw.Draw(picture)
            canvas.ellipse((12, 12, 52, 52), outline="#4abef1", width=6)
            canvas.ellipse((27, 27, 37, 37), fill="#4cd4a5")
            menu = pystray.Menu(
                pystray.MenuItem("Показать BLOODSKY NET", lambda *_: self.on_show(), default=True),
                pystray.MenuItem("Выйти", lambda *_: self.on_exit()),
            )
            self.icon = pystray.Icon("BLOODSKY-NET", picture, "BLOODSKY NET", menu)
            self._ready.clear()
            self.thread = threading.Thread(target=self._run, daemon=True, name="BloodskyTray")
            self.thread.start()
            # Failure to initialize must not hide the only UI window.
            self._ready.wait(timeout=3)
            return self.active
        except Exception:
            self.icon = None
            return False

    def _run(self) -> None:
        try:
            # pystray marks its Win32 message loop active before _ready becomes set.
            self.icon.run(setup=lambda _: self._ready.set())
        except Exception:
            pass
        finally:
            self._ready.clear()

    def stop(self) -> None:
        icon, self.icon = self.icon, None
        self._ready.clear()
        if icon is not None:
            try:
                icon.stop()
            except Exception:
                pass
