"""QuarantineStore (handles opacos) y verificador de procedencia.

Patrón dual-LLM / CaMeL: el texto libre no confiable nunca entra al contexto del
Orquestador. Se guarda aquí y viaja como `q_xxxxxxxx`. El Orquestador solo puede
mover el handle; leerlo le está prohibido y el intento queda auditado.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
import unicodedata
from decimal import Decimal
from enum import Enum
from typing import Any

from .broker import AuditLog
from .contracts import AuditKind, EnclaveId, Label

MAX_QUARANTINED_CHARS = 8_000


class QuarantineStore:
    # Enclaves cuyo CÓDIGO (no su LLM de control) puede desreferenciar handles.
    READERS = frozenset({EnclaveId.VAULT_WORKER, EnclaveId.CUSTOMS})

    def __init__(self, session_id: str, audit: AuditLog) -> None:
        self._session_id = session_id
        self._audit = audit
        self._items: dict[str, tuple[str, Label]] = {}

    def put(self, text: str, label: Label, source: str, field: str) -> str:
        handle = "q_" + secrets.token_hex(4)
        while handle in self._items:
            handle = "q_" + secrets.token_hex(4)
        stored = text[:MAX_QUARANTINED_CHARS]
        self._items[handle] = (stored, label)
        # Se audita huella y tamaño, nunca el contenido.
        self._audit.write(self._session_id, AuditKind.HANDLE_CREATED, handle=handle, label=label.name,
                          source=source[:200], field=field, chars=len(stored),
                          sha256=hashlib.sha256(stored.encode("utf-8")).hexdigest())
        return handle

    def read(self, handle: str, reader: EnclaveId) -> str:
        allowed = reader in self.READERS and handle in self._items
        self._audit.write(self._session_id, AuditKind.HANDLE_READ, enclave=reader.value, allowed=allowed,
                          rule="allow" if allowed else "handle_read_denied", handle=handle)
        if not allowed:
            raise PermissionError(f"{reader.value} may not read {handle}")
        return self._items[handle][0]

    def label(self, handle: str) -> Label:
        return self._items[handle][1]

    def __contains__(self, handle: object) -> bool:
        return handle in self._items


# --------------------------------------------------------------------------- #
# Procedencia
# --------------------------------------------------------------------------- #


def normalize(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def renderings(value: Any) -> list[str]:
    """Formas en que un valor tipado puede aparecer escrito en el documento fuente."""
    if isinstance(value, Enum):
        return [str(value.value)]
    if isinstance(value, Decimal):
        plain = f"{value:.2f}"
        grouped = f"{value:,.2f}"
        european = grouped.replace(",", "\x00").replace(".", ",").replace("\x00", ".")
        return [plain, grouped, european]
    if isinstance(value, dt.date):
        return [value.isoformat(), value.strftime("%d/%m/%Y"), value.strftime("%m/%d/%Y"),
                value.strftime("%B %d, %Y").replace(" 0", " ")]
    return [str(value)]


class ProvenanceVerifier:
    """Un valor extraído solo sobrevive si aparece (normalizado) en el texto fuente.

    El texto fuente debe ser el VISIBLE (más OCR), no el HTML crudo: así un valor
    que solo existe en una instrucción oculta no pasa.
    """

    def verify(self, fields: dict[str, Any], source_text: str) -> tuple[dict[str, Any], list[str]]:
        source = normalize(source_text)
        kept: dict[str, Any] = {}
        dropped: list[str] = []
        for name, value in fields.items():
            if any(self._appears(candidate, source) for candidate in renderings(value)):
                kept[name] = value
            else:
                dropped.append(name)
        return kept, dropped

    @staticmethod
    def _appears(candidate: str, source: str) -> bool:
        needle = normalize(candidate)
        if not needle:
            return False
        # Límites de token: "250.00" no debe validar contra "1250.00".
        return re.search(r"(?<![\w.,])" + re.escape(needle) + r"(?![\w])", source) is not None
