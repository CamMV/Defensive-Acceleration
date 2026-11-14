"""Utilidades de texto deterministas: HTML -> texto visible y extracción por regex.

Módulo añadido a la estructura objetivo porque lo comparten la Aduana (fallback),
el verificador de procedencia y el MockLLM; así ninguno importa a otro.
"""
from __future__ import annotations

import html
import re
from html.parser import HTMLParser

_VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"})
_SKIP_TAGS = frozenset({"script", "style", "noscript", "template"})
_BLOCK_TAGS = frozenset({"p", "div", "tr", "li", "br", "h1", "h2", "h3", "h4", "table", "pre", "ol", "ul", "title"})
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*[01](?:px|pt|em)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)",
    re.IGNORECASE,
)
_COLOR = re.compile(r"(?<![-\w])color\s*:\s*([^;]+)", re.IGNORECASE)
_BACKGROUND = re.compile(r"background(?:-color)?\s*:\s*([^;]+)", re.IGNORECASE)


def _is_hidden(attrs: list[tuple[str, str | None]]) -> bool:
    attributes = {name.lower(): (value or "") for name, value in attrs}
    if "hidden" in attributes or attributes.get("aria-hidden", "").lower() == "true":
        return True
    style = attributes.get("style", "")
    if _HIDDEN_STYLE.search(style):
        return True
    color, background = _COLOR.search(style), _BACKGROUND.search(style)
    # Texto del mismo color que su fondo (blanco sobre blanco).
    return bool(color and background and color.group(1).strip().lower() == background.group(1).strip().lower())


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.images: list[str] = []
        self._stack: list[bool] = []  # True = este elemento (o un ancestro) está oculto

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "img":
            source = dict(attrs).get("src")
            if source:
                self.images.append(source)
        if tag in _VOID_TAGS:
            if tag == "br":
                self.parts.append("\n")
            return
        parent_hidden = bool(self._stack and self._stack[-1])
        self._stack.append(parent_hidden or tag in _SKIP_TAGS or _is_hidden(attrs))

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID_TAGS:
            return
        if self._stack:
            self._stack.pop()
        self.parts.append("\n" if tag in _BLOCK_TAGS else " ")

    def handle_data(self, data: str) -> None:
        if not (self._stack and self._stack[-1]):
            self.parts.append(data)

    # Los comentarios HTML se descartan: HTMLParser no los envía a handle_data.


def _parse(document: str) -> _VisibleTextParser:
    parser = _VisibleTextParser()
    parser.feed(document)
    parser.close()
    return parser


def visible_text(document: str) -> str:
    """Texto que vería un humano: sin elementos ocultos, comentarios ni atributos."""
    text = "".join(_parse(document).parts)
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def image_sources(document: str) -> list[str]:
    return _parse(document).images


def naive_text(document: str) -> str:
    """Conversión ingenua (la de un agente sin defensas): conserva comentarios, alt y texto oculto."""
    text = re.sub(r"<!--(.*?)-->", r" \1 ", document, flags=re.DOTALL)
    text = re.sub(r'<img[^>]*?alt="([^"]*)"[^>]*>', r" \1 ", text)
    text = re.sub(r"</(?:p|div|tr|li|h\d|table|title)>", "\n", text)
    text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


_FIELD_PATTERNS: dict[str, re.Pattern[str]] = {
    "invoice_id": re.compile(r"Invoice ID\W{0,3}([A-Z]{2,6}-\d{1,8})\b"),
    "total_amount": re.compile(r"\bTotal\W{0,3}(\d[\d,]*\.\d{2})(?!\d)"),
    "currency": re.compile(r"\bTotal\W{0,3}\d[\d,]*\.\d{2}\s*(USD|COP|EUR)\b"),
    "issue_date": re.compile(r"Issue date\W{0,3}(\d{4}-\d{2}-\d{2})\b"),
    "version": re.compile(r"\bversion\s+(?:is\s+)?(\d{1,4}\.\d{1,4}\.\d{1,4})\b", re.IGNORECASE),
}


def regex_fields(text: str) -> dict[str, str]:
    """Extractor determinista de respaldo. Devuelve solo los campos que encuentra."""
    found: dict[str, str] = {}
    for name, pattern in _FIELD_PATTERNS.items():
        match = pattern.search(text)
        if match:
            value = match.group(1)
            found[name] = value.replace(",", "") if name == "total_amount" else value
    return found
