"""Apply the BLOODSKY radar icon to the Windows/Tk main window."""
from __future__ import annotations
import base64
from io import BytesIO
from PIL import Image, ImageTk
from .icon_source import WEBP_BASE64


def set_window_icon(app) -> bool:
    """Set a window icon; unusual Tk installations may decline it harmlessly."""
    try:
        artwork = Image.open(BytesIO(base64.b64decode(WEBP_BASE64, validate=True))).convert('RGB')
        image = ImageTk.PhotoImage(artwork, master=app)
        app.iconphoto(True, image)
        app._bloodsky_icon_ref = image
        return True
    except (OSError, ValueError, RuntimeError):
        return False
