"""Separa un documento HTML en texto VISIBLE y canales OCULTOS (determinista, stdlib).

Canales ocultos que se detectan (clásicos de indirect prompt injection):
- `css`: display:none, visibility:hidden, opacity:0, font-size <= 2px, atributo `hidden`,
  aria-hidden="true", color de texto igual al fondo (blanco sobre blanco).
- `comment`: comentarios HTML.
- `attribute`: alt, title y aria-label (el humano casi nunca los ve; un LLM sí).
- `script`: <script>, <style>, <template>, <noscript>.

El texto visible es lo único contra lo que se verifica la procedencia de los datos.
Los canales ocultos NO se pasan a ningún modelo: solo se cuentan para la telemetría.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin

_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
                   "param", "source", "track", "wbr"})
_SKIP = frozenset({"script", "style", "template", "noscript", "head"})
_BLOCK = frozenset({"p", "div", "li", "tr", "br", "h1", "h2", "h3", "h4", "h5", "h6", "pre",
                    "table", "ul", "ol", "section", "article", "header", "footer", "blockquote"})
_CELL = frozenset({"td", "th"})
_HIDDEN_ATTRS = ("alt", "title", "aria-label")
_FONT_PX = re.compile(r"^(\d+(?:\.\d+)?)px$")


@dataclass
class SplitDocument:
    visible_text: str
    hidden: dict[str, list[str]] = field(default_factory=dict)  # canal -> fragmentos
    image_srcs: list[str] = field(default_factory=list)

    @property
    def hidden_chars(self) -> int:
        return sum(len(s) for chunks in self.hidden.values() for s in chunks)

    @property
    def hidden_ratio(self) -> float:
        total = self.hidden_chars + len(self.visible_text)
        return self.hidden_chars / total if total else 0.0


def _parse_style(style: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for decl in style.split(";"):
        if ":" in decl:
            key, value = decl.split(":", 1)
            props[key.strip().casefold()] = value.strip().casefold().replace(" ", "")
    return props


def _norm_color(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    named = {"white": "#ffffff", "black": "#000000"}
    value = named.get(value, value)
    if re.fullmatch(r"#[0-9a-f]{3}", value):
        value = "#" + "".join(ch * 2 for ch in value[1:])
    return value


def is_hidden_element(attrs: dict[str, Optional[str]]) -> bool:
    if "hidden" in attrs or (attrs.get("aria-hidden") or "").casefold() == "true":
        return True
    style = _parse_style(attrs.get("style") or "")
    if style.get("display") == "none" or style.get("visibility") == "hidden":
        return True
    if style.get("opacity") in {"0", "0.0"}:
        return True
    size = _FONT_PX.match(style.get("font-size", ""))
    if size and float(size.group(1)) <= 2:
        return True
    color = _norm_color(style.get("color"))
    background = _norm_color(style.get("background-color") or style.get("background"))
    return color is not None and color == background


class _Splitter(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible: list[str] = []
        self.hidden: dict[str, list[str]] = {}
        self.image_srcs: list[str] = []
        self._stack: list[tuple[str, Optional[str]]] = []  # (tag, canal oculto o None)

    def _channel(self) -> Optional[str]:
        for _, channel in reversed(self._stack):
            if channel:
                return channel
        return None

    def _add_hidden(self, channel: str, text: str) -> None:
        text = " ".join(text.split())
        if text:
            self.hidden.setdefault(channel, []).append(text)

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, Optional[str]]]) -> None:
        attrs = {k.casefold(): v for k, v in attrs_list}
        for name in _HIDDEN_ATTRS:
            if attrs.get(name):
                self._add_hidden("attribute", attrs[name] or "")
        if tag == "img" and attrs.get("src") and self._channel() is None:
            self.image_srcs.append(attrs["src"] or "")
        if tag in _BLOCK or tag in _CELL:
            self.visible.append("\n" if tag in _BLOCK else " ")
        if tag in _VOID:
            return
        channel = "script" if tag in _SKIP else ("css" if is_hidden_element(attrs) else None)
        self._stack.append((tag, channel))

    def handle_startendtag(self, tag: str, attrs_list: list[tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs_list)
        if tag not in _VOID and self._stack and self._stack[-1][0] == tag:
            self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break
        if tag in _BLOCK:
            self.visible.append("\n")

    def handle_data(self, data: str) -> None:
        channel = self._channel()
        if channel:
            self._add_hidden(channel, data)
        else:
            self.visible.append(data)

    def handle_comment(self, data: str) -> None:
        self._add_hidden("comment", data)


def split_html(html: str, base_url: str = "") -> SplitDocument:
    parser = _Splitter()
    parser.feed(html)
    parser.close()
    lines = (" ".join(line.split()) for line in "".join(parser.visible).splitlines())
    visible = "\n".join(line for line in lines if line)
    srcs = [urljoin(base_url, s) if base_url else s for s in parser.image_srcs]
    return SplitDocument(visible_text=visible, hidden=parser.hidden, image_srcs=srcs)
