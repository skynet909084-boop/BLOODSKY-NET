"""Generate release-grade ICO and PNG assets from the user-approved embedded icon."""
from __future__ import annotations
from pathlib import Path
import base64
import sys
from io import BytesIO
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bloodsky_net.icon_source import WEBP_BASE64


def generate_assets(destination: Path | None = None) -> tuple[Path, Path]:
    folder = Path(destination) if destination is not None else ROOT / 'assets'
    folder.mkdir(parents=True, exist_ok=True)
    artwork = Image.open(BytesIO(base64.b64decode(WEBP_BASE64, validate=True))).convert('RGB')
    if artwork.size != (128, 128):
        raise ValueError('Unexpected source icon dimensions')
    png = folder / 'BLOODSKY-NET-window.png'
    ico = folder / 'BLOODSKY-NET.ico'
    artwork.resize((256, 256), Image.Resampling.LANCZOS).save(png, optimize=True)
    artwork.resize((256, 256), Image.Resampling.LANCZOS).save(
        ico, format='ICO', sizes=[(16,16), (24,24), (32,32), (48,48), (64,64), (128,128), (256,256)])
    return ico, png


if __name__ == '__main__':
    a, b = generate_assets()
    print(f'BLOODSKY NET icon prepared: {a.name}, {b.name}')
