"""Utilidades de texto deterministas: HTML -> texto visible y extracción por regex.

Módulo añadido a la estructura objetivo porque lo comparten la Aduana (fallback),
el verificador de procedencia y el MockLLM; así ninguno importa a otro.

También normaliza documentos de oficina (.pdf, .docx, .pptx, .csv) a texto (`read_document`).
Lo que un humano NO ve al abrir el documento (metadatos, notas del orador, comentarios, texto
blanco/oculto/diminuto) sale en canales `<office-channel name="...">` separados del cuerpo:
`visible_text` los descarta (no cuentan como fuente de procedencia) y `naive_text` los conserva,
igual que con el HTML oculto.
"""
from __future__ import annotations

import csv
import html
import re
import zipfile
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable

_VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "wbr"})
OFFICE_CHANNEL_TAG = "office-channel"
_SKIP_TAGS = frozenset({"script", "style", "noscript", "template", OFFICE_CHANNEL_TAG})
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


# --------------------------------------------------------------------------- #
# Documentos de oficina: .pdf / .docx / .pptx / .csv -> texto
# --------------------------------------------------------------------------- #

OFFICE_SUFFIXES = frozenset({".pdf", ".docx", ".pptx", ".csv"})
MAX_DOCUMENT_BYTES = 10_000_000  # un binario mayor se rechaza sin abrirlo
MAX_PDF_PAGES = 50
MAX_CSV_ROWS = 500
MAX_ZIP_MEMBER_BYTES = 1_000_000  # tope de lectura de partes XML internas (anti zip-bomb)
TINY_FONT_PT = 2.0  # texto <= 2 pt se considera oculto
# Canales que un lector humano no ve en la vista normal del documento.
HIDDEN_CHANNELS = ("metadata", "speaker_notes", "comments", "hidden_text")


@dataclass(frozen=True)
class DocumentText:
    """Resultado de la extracción: texto normalizado y los canales no visibles que se encontraron."""

    kind: str                 # pdf | docx | pptx | csv
    text: str
    flags: frozenset[str]     # subconjunto de HIDDEN_CHANNELS presente en el documento


def _esc(text: str) -> str:
    return html.escape(text, quote=False)


def _channel(name: str, content: str, attrs: str = "", hidden_style: bool = False) -> str:
    """Bloque etiquetado. `hidden_text` además lleva display:none (lo que ya detectan los escáneres de HTML)."""
    style = ' style="display:none"' if hidden_style else ""
    return f'<{OFFICE_CHANNEL_TAG} name="{name}"{attrs}{style}>{_esc(content)}</{OFFICE_CHANNEL_TAG}>'


def _metadata_lines(pairs: list[tuple[str, Any]]) -> str:
    return "\n".join(f"{key}: {' '.join(str(value).split())}" for key, value in pairs if value and str(value).strip())


def _zip_xml_texts(path: Path, member_filter: Callable[[str], bool], text_tag: str) -> list[str]:
    """Texto de las partes XML internas de un OOXML (comentarios). Sin entidades, sin red, con tope de lectura."""
    from lxml import etree  # dependencia de python-docx / python-pptx

    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    found: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for name in sorted(archive.namelist()):
            if not member_filter(name) or not name.endswith(".xml"):
                continue
            with archive.open(name) as member:
                data = member.read(MAX_ZIP_MEMBER_BYTES)
            for element in etree.fromstring(data, parser).iter():
                if isinstance(element.tag, str) and etree.QName(element).localname == text_tag and element.text:
                    found.append(element.text)
    return found


def _finish(kind: str, parts: list[str], flags: set[str]) -> DocumentText:
    return DocumentText(kind, "\n".join(parts), frozenset(flags))


# -- docx -------------------------------------------------------------------- #


def _docx_run_hidden(run: Any) -> bool:
    from docx.shared import RGBColor

    font = run.font
    if font.hidden:  # w:vanish
        return True
    if font.size is not None and font.size.pt <= TINY_FONT_PT:
        return True
    try:
        return font.color is not None and font.color.rgb == RGBColor(0xFF, 0xFF, 0xFF)  # blanco sobre blanco
    except (AttributeError, ValueError):
        return False


def _docx_paragraph(paragraph: Any, hidden: list[str]) -> str:
    """Texto visible del párrafo; los runs ocultos van a `hidden`."""
    from docx.oxml.ns import qn
    from docx.text.run import Run

    visible: list[str] = []
    for element in paragraph._p.iter(qn("w:r")):
        run = Run(element, paragraph)
        (hidden if _docx_run_hidden(run) else visible).append(run.text)
    return "".join(visible).strip()


def _extract_docx(path: Path) -> DocumentText:
    import docx
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    document = docx.Document(str(path))
    hidden: list[str] = []
    parts: list[str] = []
    for child in document.element.body.iterchildren():  # orden real del documento
        tag = child.tag.rsplit("}", 1)[-1]
        if tag == "p":
            line = _docx_paragraph(Paragraph(child, document), hidden)
            if line:
                parts.append(_esc(line))
        elif tag == "tbl":
            for row in Table(child, document).rows:
                cells = [" ".join(_docx_paragraph(p, hidden) for p in cell.paragraphs).strip() for cell in row.cells]
                parts.append(_esc(" | ".join(cells)))
    furniture: list[str] = []
    for section in document.sections:  # encabezados y pies: son visibles al imprimir
        for part in (section.header, section.footer):
            for paragraph in part.paragraphs:
                line = _docx_paragraph(paragraph, hidden)
                if line and line not in furniture:
                    furniture.append(line)
    parts.extend(_esc(f"[encabezado/pie] {line}") for line in furniture)
    props = document.core_properties
    metadata = _metadata_lines([("author", props.author), ("title", props.title), ("subject", props.subject),
                                ("keywords", props.keywords), ("comments", props.comments),
                                ("last_modified_by", props.last_modified_by), ("category", props.category)])
    channels = (("hidden_text", "\n".join(h for h in hidden if h.strip()), True),
                ("comments", "\n".join(_zip_xml_texts(path, lambda n: n.startswith("word/comments"), "t")), False),
                ("metadata", metadata, False))
    flags: set[str] = set()
    for name, content, hidden_style in channels:
        if content.strip():
            flags.add(name)
            parts.append(_channel(name, content, hidden_style=hidden_style))
    return _finish("docx", parts, flags)


# -- pptx -------------------------------------------------------------------- #


def _pptx_shapes(shapes: Any) -> list[Any]:
    from pptx.enum.shapes import MSO_SHAPE_TYPE

    flat: list[Any] = []
    for shape in shapes:
        if shape.shape_type == MSO_SHAPE_TYPE.GROUP:
            flat.extend(_pptx_shapes(shape.shapes))
        else:
            flat.append(shape)
    return flat


def _extract_pptx(path: Path) -> DocumentText:
    from pptx import Presentation

    presentation = Presentation(str(path))
    parts: list[str] = []
    flags: set[str] = set()
    for number, slide in enumerate(presentation.slides, start=1):
        parts.append(_esc(f"--- Diapositiva {number} ---"))
        tiny: list[str] = []
        for shape in _pptx_shapes(slide.shapes):
            if shape.has_text_frame:
                for paragraph in shape.text_frame.paragraphs:
                    visible: list[str] = []
                    for run in paragraph.runs:
                        small = run.font.size is not None and run.font.size.pt <= TINY_FONT_PT
                        (tiny if small else visible).append(run.text)
                    if "".join(visible).strip():
                        parts.append(_esc("".join(visible).strip()))
            elif getattr(shape, "has_table", False) and shape.has_table:
                parts.extend(_esc(" | ".join(cell.text.strip() for cell in row.cells)) for row in shape.table.rows)
        if "".join(tiny).strip():
            flags.add("hidden_text")
            parts.append(_channel("hidden_text", "".join(tiny), f' slide="{number}"', hidden_style=True))
        if slide.has_notes_slide and slide.notes_slide.notes_text_frame is not None:
            notes = slide.notes_slide.notes_text_frame.text
            if notes.strip():  # vector clásico: las notas del orador no se ven al proyectar
                flags.add("speaker_notes")
                parts.append(_channel("speaker_notes", notes, f' slide="{number}"'))
    props = presentation.core_properties
    metadata = _metadata_lines([("author", props.author), ("title", props.title), ("subject", props.subject),
                                ("keywords", props.keywords), ("comments", props.comments),
                                ("last_modified_by", props.last_modified_by), ("category", props.category)])
    comments = "\n".join(_zip_xml_texts(path, lambda n: n.startswith("ppt/comments/"), "text"))
    for name, content in (("comments", comments), ("metadata", metadata)):
        if content.strip():
            flags.add(name)
            parts.append(_channel(name, content))
    return _finish("pptx", parts, flags)


# -- pdf --------------------------------------------------------------------- #


def _extract_pdf(path: Path) -> DocumentText:
    from pypdf import PdfReader

    reader = PdfReader(str(path), strict=False)
    if reader.is_encrypted and not reader.decrypt(""):
        raise ValueError("encrypted pdf")
    parts: list[str] = []
    flags: set[str] = set()
    for number, page in enumerate(reader.pages[:MAX_PDF_PAGES], start=1):
        visible: list[str] = []
        tiny: list[str] = []

        def visit(text: str, _cm: Any, _tm: Any, _font: Any, size: Any) -> None:
            small = isinstance(size, (int, float)) and 0 < size <= TINY_FONT_PT
            (tiny if small else visible).append(text)

        page.extract_text(visitor_text=visit)
        parts.append(_esc(f"--- Página {number} ---"))
        parts.extend(_esc(line.strip()) for line in "".join(visible).splitlines() if line.strip())
        if "".join(tiny).strip():  # texto diminuto: invisible a simple vista
            flags.add("hidden_text")
            parts.append(_channel("hidden_text", "".join(tiny), f' page="{number}"', hidden_style=True))
    info = reader.metadata
    if info is not None:
        metadata = _metadata_lines([(label, info.get(key)) for label, key in (
            ("title", "/Title"), ("author", "/Author"), ("subject", "/Subject"),
            ("keywords", "/Keywords"), ("creator", "/Creator"))])
        if metadata.strip():
            flags.add("metadata")
            parts.append(_channel("metadata", metadata))
    return _finish("pdf", parts, flags)


# -- csv --------------------------------------------------------------------- #


def _extract_csv(path: Path) -> DocumentText:
    """Fila por fila: `fila N: columna=valor | ...`."""
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        rows = [row for _, row in zip(range(MAX_CSV_ROWS + 1), csv.reader(handle))]
    if not rows:
        return DocumentText("csv", "", frozenset())
    header = [cell.strip() or f"col{i}" for i, cell in enumerate(rows[0], start=1)]
    lines = ["columnas: " + " | ".join(header)]
    for number, row in enumerate(rows[1:], start=1):
        pairs = [f"{header[i] if i < len(header) else f'col{i + 1}'}={cell.strip()}" for i, cell in enumerate(row)]
        lines.append(f"fila {number}: " + " | ".join(pairs))
    return DocumentText("csv", _esc("\n".join(lines)), frozenset())


_EXTRACTORS: dict[str, Callable[[Path], DocumentText]] = {
    ".pdf": _extract_pdf, ".docx": _extract_docx, ".pptx": _extract_pptx, ".csv": _extract_csv,
}


def extract_document(path: Path) -> DocumentText:
    """Extrae un documento de oficina. Lanza si el archivo no es del formato que dice su extensión."""
    extractor = _EXTRACTORS[path.suffix.lower()]
    if path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("document too large")
    return extractor(path)


def read_document(path: Path, strict: bool = True) -> str:
    """Texto de cualquier archivo de la bóveda: .txt/.md tal cual y .pdf/.docx/.pptx/.csv extraídos.

    Con `strict=False` un binario ilegible cae a bytes decodificados (útil para descubrir canaries).
    """
    if path.suffix.lower() in OFFICE_SUFFIXES:
        try:
            return extract_document(path).text
        except Exception:
            if strict:
                raise
            return path.read_bytes()[:MAX_DOCUMENT_BYTES].decode("utf-8", errors="replace")
    return path.read_text(encoding="utf-8", errors="replace")
