"""Herramientas locales. Reciben rutas YA resueltas y validadas por el broker.

Nunca resuelven rutas por su cuenta: quien las llame sin pasar por el broker
(solo el baseline sin defensas) asume la validación.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from ..textutil import read_document
from .web_tools import IMAGE_DATA_PREFIX, MAX_IMAGE_BYTES

MAX_FILE_CHARS = 20_000


def read_file(path: Path) -> str:
    """Texto del archivo: .txt/.md tal cual; .pdf/.docx/.pptx/.csv extraídos (ver `textutil.read_document`).

    Un binario corrupto lanza: el broker lo registra como `tool_error` y no entrega nada.
    """
    return read_document(path)[:MAX_FILE_CHARS]


_IMAGE_MAGIC = {".png": (b"\x89PNG\r\n\x1a\n",), ".jpg": (b"\xff\xd8\xff",), ".jpeg": (b"\xff\xd8\xff",)}


def read_inbox(path: Path) -> str:
    """Archivo L0. Las imágenes (.png/.jpg) salen como data URI, igual que las imágenes web.

    Así la Aduana las distingue del texto y las pasa por el mismo OCR/VLM. Falla cerrado si la
    extensión no coincide con los bytes (p. ej. un ejecutable renombrado a .png) o si excede el tope.
    """
    suffix = path.suffix.lower()
    if suffix not in _IMAGE_MAGIC:
        return read_file(path)
    if path.stat().st_size > MAX_IMAGE_BYTES:
        raise ValueError("image too large")
    data = path.read_bytes()
    if not data.startswith(_IMAGE_MAGIC[suffix]):
        raise ValueError("file content does not match its image extension")
    return IMAGE_DATA_PREFIX + base64.b64encode(data).decode("ascii")


def write_diff(path: Path, old: str, new: str) -> str:
    """Diff mínimo auditable: `old` vacío = agregar al final; si no, reemplazo único exacto."""
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    if old == "":
        separator = "" if current.endswith("\n") or not current else "\n"
        updated = f"{current}{separator}{new}\n"
    else:
        occurrences = current.count(old)
        if occurrences != 1:
            raise ValueError(f"diff anchor must match exactly once, matched {occurrences}")
        updated = current.replace(old, new, 1)
    path.write_text(updated, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(updated.encode("utf-8")).hexdigest()
    return json.dumps({"bytes_written": len(new.encode("utf-8")), "sha256": digest})
