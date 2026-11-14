"""Extractores deterministas (regex + normalizadores) de `EXTRACTABLE_FIELDS`.

Proponen CANDIDATOS. Ninguno se acepta sin pasar después por el verificador de
procedencia y por la validación pydantic de `ExtractedRecord`.

ML-TEAM: un extractor LLM/VLM (si algún día se usa) debe implementar la misma firma
`extract(visible_text) -> dict[str, Any]` con claves de EXTRACTABLE_FIELDS. Sus valores
pasan por el mismo verificador, así que un extractor secuestrado no puede inventar datos.
"""
from __future__ import annotations

import re
from typing import Any

from ..ml_d.quarantine import dates_in, parse_amount

_INVOICE_HINT = re.compile(r"\b(invoice|factura)\b", re.IGNORECASE)
_INVOICE_ID = re.compile(r"(?:invoice|factura)\s*(?:id|no\.?|number|n[uú]mero|#)?\s*[:#]?\s*([A-Z]{2,6}-\d{1,8})\b",
                         re.IGNORECASE)
_TOTAL = re.compile(r"\btotal(?:\s+(?:amount|due|a\s+pagar))?\s*[:\-]?\s*(USD|COP|EUR|\$|€)?\s*(\d[\d.,]*\d|\d)\s*(USD|COP|EUR)?",
                    re.IGNORECASE)
_DATE_LABEL = re.compile(r"(?:issue\s+date|invoice\s+date|fecha(?:\s+de\s+emisi[oó]n)?)\s*:?\s*([^\n]{0,40})",
                         re.IGNORECASE)
_VERSION = re.compile(r"(?:version|release|versi[oó]n)\D{0,40}?(\d{1,4}\.\d{1,4}\.\d{1,4})\b", re.IGNORECASE)
_SYMBOL_CURRENCY = {"$": "USD", "€": "EUR"}


def looks_like_invoice(visible_text: str) -> bool:
    return bool(_INVOICE_HINT.search(visible_text) and _TOTAL.search(visible_text))


class RegexExtractor:
    """Extractor baseline. Solo extrae campos de factura si el documento parece factura."""

    def extract(self, visible_text: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if looks_like_invoice(visible_text):
            if m := _INVOICE_ID.search(visible_text):
                out["invoice_id"] = m.group(1).upper()
            if m := _TOTAL.search(visible_text):
                amount = parse_amount(m.group(2))
                if amount is not None:
                    out["total_amount"] = amount
                code = (m.group(3) or m.group(1) or "").upper()
                code = _SYMBOL_CURRENCY.get(code, code)
                if code in {"USD", "COP", "EUR"}:
                    out["currency"] = code
            if m := _DATE_LABEL.search(visible_text):
                found = sorted(dates_in(m.group(1)))
                if found:
                    out["issue_date"] = found[0]
        if m := _VERSION.search(visible_text):
            out["version"] = m.group(1)
        return out
