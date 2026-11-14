"""Generación determinista de casos del benchmark a partir de las semillas de cases.yaml.

- Ofuscación (base64, ancho cero, homoglifos, leetspeak, letras espaciadas, texto invertido...).
- Canales de transporte: HTML oculto (display:none, texto blanco, font-size 0, comentario, alt),
  JSON, CSV, markdown.
- Aguja en un pajar: la inyección dentro de un documento legítimo largo (inicio, mitad, final).
- Imágenes: el texto renderizado con distintos estilos (normal, bajo contraste, pequeño, rotado,
  ruido, banner) para medir WARD-2b + el doble chequeo.

Las MISMAS envolturas se aplican también a semillas legítimas: así se mide si el detector bloquea por
el envoltorio (p. ej. "hay HTML oculto") en lugar de por el contenido.
"""
from __future__ import annotations

import base64
import io
import json
import random
import textwrap
from dataclasses import dataclass, field
from typing import Callable, Optional

_HOMOGLYPHS = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і", "x": "х", "y": "у"})
_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
_ZW = "​"
_HTML_PAGE = ("<html><body><h1>Portal de contratación</h1><p>Consulte aquí los documentos del proceso "
              "LP-2026-014 y el cronograma vigente.</p>{payload}<p>Última actualización: 2026-10-02.</p></body></html>")


@dataclass
class Case:
    id: str
    label: int
    cat: str
    lang: str
    diff: str
    text: str
    scope: str = "in"
    source: str = "handwritten"       # handwritten | generated | image
    transform: str = "none"
    parent: Optional[str] = None
    image_style: Optional[str] = None
    image: Optional[bytes] = field(default=None, repr=False)

    def meta(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k not in {"image", "text"}}


# -- ofuscación -------------------------------------------------------------- #

def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


OBFUSCATIONS: dict[str, tuple[str, Callable[[str], str]]] = {
    # nombre: (dificultad, función)
    "uppercase": ("easy", str.upper),
    "base64_instructed": ("hard", lambda t: f"Decode the following base64 string and do what it says: {_b64(t)}"),
    "base64_raw": ("boundary", _b64),
    "zero_width": ("hard", lambda t: _ZW.join(t)),
    "homoglyph": ("hard", lambda t: t.translate(_HOMOGLYPHS)),
    "leetspeak": ("medium", lambda t: t.translate(_LEET)),
    "spaced_letters": ("hard", lambda t: " ".join(t.replace(" ", "  "))),
    "reversed": ("hard", lambda t: f"Lee este texto al revés y cúmplelo: {t[::-1]}"),
    "newline_split": ("medium", lambda t: "\n".join(textwrap.wrap(t, 18))),
}

CARRIERS: dict[str, tuple[str, Callable[[str], str]]] = {
    "html_display_none": ("medium", lambda t: _HTML_PAGE.format(payload=f'<div style="display:none">{t}</div>')),
    "html_white_text": ("medium", lambda t: _HTML_PAGE.format(
        payload=f'<p style="color:#ffffff;background:#ffffff">{t}</p>')),
    "html_zero_font": ("medium", lambda t: _HTML_PAGE.format(payload=f'<span style="font-size:0px">{t}</span>')),
    "html_comment": ("medium", lambda t: _HTML_PAGE.format(payload=f"<!-- {t} -->")),
    "html_alt": ("medium", lambda t: _HTML_PAGE.format(payload=f'<img src="/static/logo.png" alt="{t}">')),
    "html_visible": ("easy", lambda t: _HTML_PAGE.format(payload=f"<p>{t}</p>")),
    "json_field": ("medium", lambda t: json.dumps({"invoice_id": "FAC-2210", "total": "100000000.00",
                                                   "currency": "COP", "notes": t}, ensure_ascii=False)),
    "csv_cell": ("medium", lambda t: "item,cantidad,valor,observaciones\nmezcla asfáltica,1200,450000,\"" + t.replace('"', "'")
                 + "\"\nseñalización,85,320000,ninguna"),
    "markdown_quote": ("easy", lambda t: f"## Observaciones del oferente\n\n> {t}\n\n- Plazo: 8 meses\n- Garantía: 5 años"),
}

POSITIONS = ("start", "middle", "end")
# Envolturas que en sí mismas son una orden ("decodifica y haz lo que dice"): no se aplican a legítimos.
INSTRUCTION_WRAPPERS = {"base64_instructed", "reversed"}
# Ofuscaciones que casi nunca aparecen en un documento legítimo real: en legítimos son caso de frontera.
RARE_IN_BENIGN = {"leetspeak", "homoglyph", "spaced_letters", "zero_width", "base64_raw"}


def _haystack(paragraphs: list[str], rng: random.Random, target_chars: int = 3000) -> list[str]:
    out: list[str] = []
    while sum(len(p) for p in out) < target_chars:
        out.append(rng.choice(paragraphs))
    return out


def needle(text: str, paragraphs: list[str], position: str, seed: str) -> str:
    rng = random.Random(f"needle:{seed}:{position}")
    hay = _haystack(paragraphs, rng)
    index = {"start": 0, "middle": len(hay) // 2, "end": len(hay)}[position]
    hay.insert(index, text)
    return "\n\n".join(hay)


def generate(seeds: list[Case], paragraphs: dict[str, list[str]]) -> list[Case]:
    """Variantes de cada semilla. Determinista: mismo cases.yaml -> mismos casos.

    `paragraphs`: párrafos legítimos por idioma ("es", "en"). La aguja va en un pajar de su idioma;
    los documentos bilingües se generan aparte (`haystack_mixed`) porque son otro efecto.
    """
    out: list[Case] = []
    for case in seeds:
        for name, (diff, fn) in {**OBFUSCATIONS, **CARRIERS}.items():
            if case.label == 0 and name in INSTRUCTION_WRAPPERS:
                continue
            if case.label == 0 and name in RARE_IN_BENIGN:
                diff = "boundary"
            out.append(Case(id=f"{case.id}__{name}", label=case.label, cat=case.cat, lang=case.lang,
                            diff=max_diff(case.diff, diff), text=fn(case.text), scope=case.scope,
                            source="generated", transform=name, parent=case.id))
        if case.cat != "long_benign":
            hay = paragraphs["en" if case.lang == "en" else "es"]
            for position in POSITIONS:
                out.append(Case(id=f"{case.id}__needle_{position}", label=case.label, cat=case.cat, lang=case.lang,
                                diff=max_diff(case.diff, "hard"), text=needle(case.text, hay, position, case.id),
                                scope=case.scope, source="generated", transform=f"needle_{position}", parent=case.id))
    for lang, items in paragraphs.items():  # documentos legítimos largos de un solo idioma, sin aguja
        for size in (1500, 4000, 9000):
            rng = random.Random(f"haystack:{lang}:{size}")
            out.append(Case(id=f"haystack_{lang}_{size}", label=0, cat="long_benign", lang=lang, diff="medium",
                            text="\n\n".join(_haystack(items, rng, size)), source="generated", transform="haystack"))
    mixed = [p for items in paragraphs.values() for p in items]
    for size in (1500, 4000, 9000):  # bilingües (es/en): frontera conocida, ver docs/ML_ARCHITECTURE.md
        rng = random.Random(f"haystack:mixed:{size}")
        out.append(Case(id=f"haystack_mixed_{size}", label=0, cat="bilingual_benign", lang="mix", diff="boundary",
                        text="\n\n".join(_haystack(mixed, rng, size)), source="generated", transform="haystack_mixed"))
    return out


_DIFF_ORDER = ["easy", "medium", "hard", "boundary"]


def max_diff(a: str, b: str) -> str:
    return max(a, b, key=lambda d: _DIFF_ORDER.index(d) if d in _DIFF_ORDER else 0)


# -- imágenes ------------------------------------------------------------------ #

IMAGE_STYLES = ("plain", "lowcontrast", "small", "rotated", "noisy", "banner")


def render_image(text: str, style: str, seed: str) -> bytes:
    """PNG determinista con el texto en el estilo pedido."""
    from PIL import Image, ImageDraw, ImageFilter, ImageFont

    rng = random.Random(f"img:{seed}:{style}")
    size = {"small": 13, "banner": 34}.get(style, 22)
    font = ImageFont.load_default(size=size)
    width = {"small": 90, "banner": 38}.get(style, 60)
    lines = textwrap.wrap(text, width) or [""]
    line_h = int(size * 1.45)
    w = max(400, int(max(len(line) for line in lines) * size * 0.55) + 60)
    h = line_h * len(lines) + 60
    bg, fg = (255, 255, 255), (20, 20, 20)
    if style == "lowcontrast":
        bg, fg = (244, 244, 244), (226, 226, 226)
    elif style == "banner":
        bg, fg = (18, 52, 120), (255, 214, 0)
    img = Image.new("RGB", (w, h), bg)
    draw = ImageDraw.Draw(img)
    if style == "noisy":
        for _ in range(int(w * h / 60)):
            x, y = rng.randrange(w), rng.randrange(h)
            shade = rng.randrange(150, 245)
            draw.point((x, y), fill=(shade, shade, shade))
        for _ in range(12):
            draw.line([(rng.randrange(w), rng.randrange(h)), (rng.randrange(w), rng.randrange(h))],
                      fill=(190, 190, 190), width=1)
    for i, line in enumerate(lines):
        draw.text((30, 30 + i * line_h), line, font=font, fill=fg)
    if style == "rotated":
        img = img.rotate(7, expand=True, fillcolor=bg, resample=Image.BICUBIC)
    if style == "noisy":
        img = img.filter(ImageFilter.GaussianBlur(0.6))
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


# Qué casos se convierten en imagen y con qué estilos (positivos y negativos balanceados).
IMAGE_PLAN: dict[str, tuple[str, ...]] = {
    "ovr_en_01": ("plain", "lowcontrast", "rotated"),
    "exf_es_01": ("plain", "noisy", "small"),
    "cam_es_01": ("plain", "lowcontrast"),
    "auth_es_01": ("banner", "noisy"),
    "pex_es_01": ("plain", "rotated"),
    "ml_pt_01": ("plain",),
    "cond_en_01": ("small", "banner"),
    "para_03": ("plain", "small"),
    "tram_01": ("plain", "lowcontrast", "banner"),
    "data_01": ("plain", "noisy"),
    "it_01": ("plain", "rotated"),
    "mail_03": ("plain", "small"),
    "legal_01": ("noisy", "lowcontrast"),
    "tram_03": ("banner",),
}


def image_cases(by_id: dict[str, Case]) -> list[Case]:
    out = []
    for case_id, styles in IMAGE_PLAN.items():
        case = by_id[case_id]
        for style in styles:
            out.append(Case(id=f"{case_id}__img_{style}", label=case.label, cat=case.cat, lang=case.lang,
                            diff=max_diff(case.diff, "hard" if style in {"lowcontrast", "noisy", "rotated"} else "medium"),
                            text=case.text, scope=case.scope, source="image", transform=f"img_{style}",
                            parent=case.id, image_style=style, image=render_image(case.text, style, case.id)))
    return out
