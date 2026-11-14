"""Genera las imágenes de la demo con Pillow (solo si faltan)."""
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from test_server.payloads import EXFIL_PLAIN

STATIC_DIR = Path(__file__).parent / "static"
SIZE = (900, 260)


def _draw_wrapped(img: Image.Image, text: str, color: tuple, font: ImageFont.ImageFont, width_chars: int) -> None:
    draw = ImageDraw.Draw(img)
    draw.multiline_text((20, 20), "\n".join(textwrap.wrap(text, width_chars)), fill=color, font=font, spacing=6)


def _make_diagram(path: Path) -> None:
    img = Image.new("RGB", SIZE, (255, 255, 255))
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    for i, label in enumerate(("client", "retry policy", "server")):
        x = 40 + i * 290
        draw.rectangle((x, 90, x + 200, 170), outline=(40, 40, 40), width=2)
        draw.text((x + 60, 125), label, fill=(40, 40, 40), font=font)
        if i < 2:
            draw.line((x + 200, 130, x + 290, 130), fill=(40, 40, 40), width=2)
            draw.polygon([(x + 290, 130), (x + 278, 123), (x + 278, 137)], fill=(40, 40, 40))
    img.save(path)


def _make_lowcontrast(path: Path) -> None:
    img = Image.new("RGB", SIZE, (250, 250, 250))
    _draw_wrapped(img, EXFIL_PLAIN, (242, 242, 242), ImageFont.load_default(), 130)
    img.save(path)


def _make_typographic(path: Path) -> None:
    img = Image.new("RGB", SIZE, (255, 255, 255))
    try:
        font = ImageFont.load_default(size=22)
    except TypeError:  # Pillow antiguo sin parámetro size
        font = ImageFont.load_default()
    _draw_wrapped(img, EXFIL_PLAIN, (0, 0, 0), font, 62)
    img.save(path)


def ensure_images(static_dir: Path = STATIC_DIR) -> list[Path]:
    """Crea los PNG que falten y devuelve sus rutas."""
    static_dir.mkdir(parents=True, exist_ok=True)
    builders = {
        "diagram.png": _make_diagram,
        "trap_lowcontrast.png": _make_lowcontrast,
        "trap_typographic.png": _make_typographic,
    }
    paths = []
    for name, build in builders.items():
        path = static_dir / name
        if not path.exists():
            build(path)
        paths.append(path)
    return paths


if __name__ == "__main__":
    for generated in ensure_images():
        print(generated)
