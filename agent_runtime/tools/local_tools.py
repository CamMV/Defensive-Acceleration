"""Herramientas locales. Reciben rutas YA resueltas y validadas por el broker.

Nunca resuelven rutas por su cuenta: quien las llame sin pasar por el broker
(solo el baseline sin defensas) asume la validación.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

MAX_FILE_CHARS = 20_000


def read_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")[:MAX_FILE_CHARS]


def read_inbox(path: Path) -> str:
    return read_file(path)


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
