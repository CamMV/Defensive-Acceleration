"""QuarantineStore (handles opacos) + verificador de procedencia.

Patrón dual-LLM / CaMeL:
- Todo texto libre de una fuente no confiable se guarda aquí y sale como un handle opaco
  `q_xxxxxxxx`. El Orquestador puede mover el handle (a otro enclave, al reporte), pero
  NO puede leerlo: `get` solo acepta lectores autorizados (el renderer del reporte, que
  es código, no un LLM).
- `render_safe` convierte el texto en un bloque citado e inerte para el humano: sin HTML,
  sin links ni imágenes Markdown (canal clásico de exfiltración) y con URLs desactivadas.

Verificador de procedencia (determinista):
- Un valor tipado propuesto por un extractor (regex o LLM) solo se acepta si aparece,
  normalizado, en el texto VISIBLE del documento fuente. Si no aparece, se descarta y se
  registra el NOMBRE del campo (nunca el valor).
- Limitación (P4): un valor que sí está en el texto visible pero es engañoso (p. ej. una
  factura legítima con un monto fraudulento) pasa. Eso es data poisoning semántico.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, Mapping, Optional

from .contracts import AuditKind, Label, TextField
from .ml.vectors import normalize_text

if TYPE_CHECKING:
    from .broker import AuditLog

HANDLE_PREFIX = "q_"
DEFAULT_READERS = frozenset({"report_renderer"})
MAX_RENDER_CHARS = 2000


class QuarantineError(Exception):
    """Handle desconocido o mal formado."""


class QuarantineAccessDenied(QuarantineError):
    """Un lector no autorizado intentó leer texto en cuarentena."""


@dataclass(frozen=True)
class QuarantineEntry:
    handle: str
    text: str
    label: Label
    step_id: str
    field: TextField
    sha256: str


@dataclass(frozen=True)
class HandleMeta:
    """Lo único que se puede saber de un handle sin leerlo."""

    handle: str
    label: Label
    step_id: str
    field: TextField
    length: int
    sha256_prefix: str


class QuarantineStore:
    def __init__(self, session_id: str, audit: Optional["AuditLog"] = None,
                 readers: frozenset[str] = DEFAULT_READERS) -> None:
        self.session_id = session_id
        self.audit = audit
        self.readers = readers
        self._entries: dict[str, QuarantineEntry] = {}

    def _log(self, kind: AuditKind, **detail: Any) -> None:
        if self.audit is not None:
            self.audit.write(self.session_id, kind, enclave="quarantine", **detail)

    def put(self, text: str, *, step_id: str, field: TextField, label: Label = Label.L0) -> str:
        handle = HANDLE_PREFIX + secrets.token_hex(4)
        while handle in self._entries:
            handle = HANDLE_PREFIX + secrets.token_hex(4)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        self._entries[handle] = QuarantineEntry(handle, text, label, step_id, field, digest)
        self._log(AuditKind.HANDLE_CREATED, handle=handle, step_id=step_id, field=field.value,
                  label=label.name, length=len(text), sha256_prefix=digest[:12])
        return handle

    def _entry(self, handle: str) -> QuarantineEntry:
        try:
            return self._entries[handle]
        except KeyError:
            raise QuarantineError(f"unknown handle {handle!r}") from None

    def meta(self, handle: str) -> HandleMeta:
        e = self._entry(handle)
        return HandleMeta(e.handle, e.label, e.step_id, e.field, len(e.text), e.sha256[:12])

    def get(self, handle: str, reader: str) -> str:
        """Lectura del texto crudo. Solo lectores autorizados; cada intento queda en el log."""
        entry = self._entry(handle)
        allowed = reader in self.readers
        self._log(AuditKind.HANDLE_READ, handle=handle, reader=reader, allowed=allowed,
                  rule="authorized_reader" if allowed else "reader_not_authorized")
        if not allowed:
            raise QuarantineAccessDenied(f"{reader!r} may not read quarantined text")
        return entry.text

    def render_safe(self, handle: str, reader: str = "report_renderer",
                    max_chars: int = MAX_RENDER_CHARS) -> str:
        """Bloque Markdown citado e inerte para que lo lea un humano."""
        entry = self._entry(handle)
        text = defang(self.get(handle, reader))
        if len(text) > max_chars:
            text = text[:max_chars] + f" ...(+{len(text) - max_chars} chars)"
        quoted = "\n".join("> " + line for line in text.splitlines() or [""])
        header = f"> **Contenido externo no verificado** ({handle}, {entry.field.value}, paso {entry.step_id})"
        return header + "\n>\n" + quoted

    def __len__(self) -> int:
        return len(self._entries)


_MD_SPECIAL = re.compile(r"([\\`*_\[\]()!#|])")
_URL_SCHEME = re.compile(r"\b(h)(ttps?)(://)", re.IGNORECASE)


def defang(text: str) -> str:
    """Neutraliza HTML, Markdown activo (links, imágenes, código) y URLs."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = _MD_SPECIAL.sub(r"\\\1", text)
    return _URL_SCHEME.sub(lambda m: m.group(1) + "xx" + m.group(2)[2:] + "[:]//", text)


# --------------------------------------------------------------------------- #
# Normalizadores
# --------------------------------------------------------------------------- #

_NUMBER_TOKEN = re.compile(r"\d[\d.,]*\d|\d")
_CENT = Decimal("0.01")


def parse_amount(token: str) -> Optional[Decimal]:
    """`1,234.50`, `1.234,50`, `1250`, `1310.00`, `1 250,00` -> Decimal con 2 decimales."""
    token = token.strip().replace(" ", "").replace(" ", "")
    if not token or not token[0].isdigit() or not token[-1].isdigit():
        return None
    has_dot, has_comma = "." in token, "," in token
    if has_dot and has_comma:
        decimal_sep = "." if token.rfind(".") > token.rfind(",") else ","
        thousands = "," if decimal_sep == "." else "."
        token = token.replace(thousands, "").replace(decimal_sep, ".")
    elif has_dot or has_comma:
        sep = "." if has_dot else ","
        head, _, tail = token.rpartition(sep)
        if token.count(sep) == 1 and len(tail) in (1, 2):
            token = head + "." + tail          # separador decimal
        elif all(len(g) == 3 for g in token.split(sep)[1:]):
            token = token.replace(sep, "")     # separador de miles
        else:
            return None
    try:
        return Decimal(token).quantize(_CENT)
    except InvalidOperation:
        return None


def amounts_in(text: str) -> set[Decimal]:
    found = set()
    for token in _NUMBER_TOKEN.findall(text):
        value = parse_amount(token)
        if value is not None:
            found.add(value)
    return found


_MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6, "july": 7,
    "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
    "enero": 1, "febrero": 2, "marzo": 3, "abril": 4, "mayo": 5, "junio": 6, "julio": 7,
    "agosto": 8, "septiembre": 9, "setiembre": 9, "octubre": 10, "noviembre": 11, "diciembre": 12,
}
_MONTH_ALT = "|".join(sorted(_MONTHS, key=len, reverse=True))
_ISO_DATE = re.compile(r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b")
_NUM_DATE = re.compile(r"\b(\d{1,2})[/.](\d{1,2})[/.](\d{4})\b")
_DMY_NAME = re.compile(rf"\b(\d{{1,2}})\s+(?:de\s+)?({_MONTH_ALT})\s+(?:de\s+|del\s+)?(\d{{4}})\b")
_MDY_NAME = re.compile(rf"\b({_MONTH_ALT})\s+(\d{{1,2}}),?\s+(\d{{4}})\b")


def _safe_date(y: int, m: int, d: int) -> Optional[dt.date]:
    try:
        return dt.date(y, m, d)
    except ValueError:
        return None


def dates_in(text: str) -> set[dt.date]:
    """Fechas ISO, d/m/y (y m/d/y si es ambigua) y con nombre de mes en inglés o español."""
    norm = normalize_text(text)
    candidates: list[Optional[dt.date]] = []
    for y, m, d in _ISO_DATE.findall(norm):
        candidates.append(_safe_date(int(y), int(m), int(d)))
    for a, b, y in _NUM_DATE.findall(norm):
        candidates += [_safe_date(int(y), int(b), int(a)), _safe_date(int(y), int(a), int(b))]
    for d, mon, y in _DMY_NAME.findall(norm):
        candidates.append(_safe_date(int(y), _MONTHS[mon], int(d)))
    for mon, d, y in _MDY_NAME.findall(norm):
        candidates.append(_safe_date(int(y), _MONTHS[mon], int(d)))
    return {c for c in candidates if c is not None}


def contains_token(text: str, value: str) -> bool:
    """`value` aparece en `text` como token completo (sin tildes ni mayúsculas)."""
    needle = normalize_text(value)
    if not needle:
        return False
    return re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", normalize_text(text)) is not None


# --------------------------------------------------------------------------- #
# Verificador de procedencia
# --------------------------------------------------------------------------- #

AMOUNT_FIELDS = frozenset({"total_amount"})
DATE_FIELDS = frozenset({"issue_date"})


@dataclass
class ProvenanceResult:
    accepted: dict[str, Any] = field(default_factory=dict)
    dropped: list[str] = field(default_factory=list)


class ProvenanceVerifier:
    """Acepta un valor solo si aparece (normalizado) en el texto visible de la fuente."""

    def __init__(self, session_id: str = "", audit: Optional["AuditLog"] = None) -> None:
        self.session_id = session_id
        self.audit = audit

    def verify(self, candidates: Mapping[str, Any], visible_text: str, step_id: str = "") -> ProvenanceResult:
        result = ProvenanceResult()
        amounts: Optional[set[Decimal]] = None
        dates: Optional[set[dt.date]] = None
        for name, value in candidates.items():
            if value is None:
                continue
            if name in AMOUNT_FIELDS:
                amounts = amounts_in(visible_text) if amounts is None else amounts
                ok = _as_amount(value) in amounts
            elif name in DATE_FIELDS:
                dates = dates_in(visible_text) if dates is None else dates
                ok = _as_date(value) in dates
            else:
                ok = contains_token(visible_text, str(value))
            if ok:
                result.accepted[name] = value
            else:
                result.dropped.append(name)
        if result.dropped and self.audit is not None:
            self.audit.write(self.session_id, AuditKind.PROVENANCE_DROP, enclave="customs",
                             step_id=step_id, fields=list(result.dropped))
        return result


def _as_amount(value: Any) -> Optional[Decimal]:
    if isinstance(value, Decimal):
        return value.quantize(_CENT)
    if isinstance(value, (int, float)):
        return Decimal(str(value)).quantize(_CENT)
    return parse_amount(str(value))


def _as_date(value: Any) -> Optional[dt.date]:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    found = dates_in(str(value))
    return next(iter(found)) if len(found) == 1 else None
