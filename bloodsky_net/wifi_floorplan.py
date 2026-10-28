"""Offline, explicit floorplan images and precise coordinate mapping for Wi-Fi surveys.

Only user-selected PNG/JPEG inputs; normalized coordinates refer to the *image*,
not canvas letterboxing. No automatic room boundaries or signal interpolation.
"""
from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from math import isfinite
import warnings

MAX_SOURCE_BYTES = 12 * 1024 * 1024
MAX_STORED_BYTES = 4 * 1024 * 1024
MAX_SOURCE_PIXELS = 16_000_000
MAX_PLAN_SIDE = 8192
MAX_DISPLAY_SIDE = 1800


@dataclass(frozen=True)
class Floorplan:
    jpeg: bytes  # Local SQLite BLOB; re-encoded without source metadata/EXIF.
    width: int
    height: int


def sanitize_floorplan(content: bytes) -> Floorplan:
    """Decode only a bounded image into a safe, metadata-free JPEG.

    Pillow handles parsing in-process; user must trust images they explicitly open.
    """
    if not isinstance(content, bytes) or not 0 < len(content) <= MAX_SOURCE_BYTES:
        raise ValueError('Размер плана должен быть от 1 байта до 12 МБ')
    try:
        from PIL import Image, ImageOps, UnidentifiedImageError
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(BytesIO(content)) as original:
                if original.format not in ('PNG', 'JPEG'):
                    raise ValueError('Поддерживаются только PNG и JPEG')
                w, h = original.size
                if not (0 < w <= MAX_PLAN_SIDE and 0 < h <= MAX_PLAN_SIDE and w*h <= MAX_SOURCE_PIXELS):
                    raise ValueError('План слишком большой: максимум 16 Мпикс, сторона до 8192')
                original.load()
                image = ImageOps.exif_transpose(original)
                if image.mode in ('RGBA', 'LA') or 'transparency' in image.info:
                    rgba = image.convert('RGBA')
                    bg = Image.new('RGB', rgba.size, 'white')
                    bg.paste(rgba, mask=rgba.getchannel('A'))
                    image = bg
                else:
                    image = image.convert('RGB')
                image.thumbnail((MAX_DISPLAY_SIDE, MAX_DISPLAY_SIDE), Image.Resampling.LANCZOS)
                buf = BytesIO()
                image.save(buf, 'JPEG', quality=85, optimize=True)
                data = buf.getvalue()
                if not data or len(data) > MAX_STORED_BYTES:
                    raise ValueError('План не удалось безопасно сжать до 4 МБ')
                return Floorplan(data, *image.size)
    except (OSError, Image.DecompressionBombError, Image.DecompressionBombWarning,
            UnidentifiedImageError) as exc:
        raise ValueError('Невозможно прочитать план помещения') from exc


def image_bounds(canvas_width: int, canvas_height: int, image_width: int,
                 image_height: int) -> tuple[float, float, float, float]:
    """Aspect-fit rectangle (x0, y0, displayed_width, displayed_height)."""
    if min(canvas_width, canvas_height, image_width, image_height) <= 0:
        raise ValueError('Недопустимый размер изображения или холста')
    scale = min(canvas_width / image_width, canvas_height / image_height)
    w, h = image_width * scale, image_height * scale
    return ((canvas_width-w)/2, (canvas_height-h)/2, w, h)


def canvas_to_percent(x: float, y: float, bounds: tuple[float, float, float, float]
                      ) -> tuple[float, float] | None:
    if not (isfinite(x) and isfinite(y)):
        return None
    left, top, width, height = bounds
    if width <= 0 or height <= 0:
        return None
    if not (left <= x <= left + width and top <= y <= top + height):
        return None  # Letterboxing is not a room or physical observation.
    return (round((x-left)*100/width, 3), round((y-top)*100/height, 3))


def percent_to_canvas(x: float, y: float, bounds: tuple[float, float, float, float]
                      ) -> tuple[float, float]:
    left, top, width, height = bounds
    if not all(isfinite(v) for v in (x, y, left, top, width, height)) or not (0 <= x <= 100 and 0 <= y <= 100):
        raise ValueError('Недопустимые координаты точки')
    return left + width*x/100, top + height*y/100


def zoomed_bounds(canvas_width: int, canvas_height: int, image_width: int,
                  image_height: int, zoom: int = 100,
                  pan_x: float = 0, pan_y: float = 0) -> tuple[float, float, float, float]:
    """Aspect-fit zoomed around canvas center; pan in canvas pixels for Shift-drag.

    This is a view transform only; points remain at source-image coordinates.
    """
    if type(zoom) is not int or zoom not in (75, 100, 125, 150, 200):
        raise ValueError('Масштаб должен быть 75, 100, 125, 150 или 200%')
    if not all(isfinite(v) and abs(v) <= 100000 for v in (pan_x, pan_y)):
        raise ValueError('Недопустимое смещение плана')
    _, _, w, h = image_bounds(canvas_width, canvas_height, image_width, image_height)
    w, h = w * zoom/100, h * zoom/100
    # Avoid hiding the entire image outside the canvas on extreme drag.
    max_x = (canvas_width + w)/2 - min(w, 30)
    max_y = (canvas_height + h)/2 - min(h, 30)
    return ((canvas_width-w)/2 + max(-max_x, min(max_x, pan_x)),
            (canvas_height-h)/2 + max(-max_y, min(max_y, pan_y)), w, h)
