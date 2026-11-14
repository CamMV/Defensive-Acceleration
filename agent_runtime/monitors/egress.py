"""Monitor de egreso: detecta canaries que salen por sumideros de red.

Segunda línea de defensa, independiente del taint tracking. Es determinista:
construye "vistas" del texto (plano, URL-decodificado, base64, hex, invertido)
y busca cada canary en ellas. Además acumula cobertura por fragmentos entre
llamadas de una misma sesión (`observe`).

Regla de oro: el valor del canary NUNCA aparece en hallazgos, excepciones ni logs;
solo su `canary_id` (sha256[:12]).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Iterable
from urllib.parse import unquote_plus

from agent_runtime.contracts import CANARY_PATTERN, EgressFinding

_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX_RUN = re.compile(r"[0-9a-fA-F]{12,}")
# Separadores entre pares de bytes hex ("43:41-4e 41").
_HEX_SEPARATOR = re.compile(r"(?<=[0-9a-fA-F]{2})[:\- ](?=[0-9a-fA-F]{2})")
_MAX_URL_DECODES = 3
_PREFIX = "CANARY-"

View = tuple[str, str]  # (encoding, texto en minúsculas)


def canary_id(canary: str) -> str:
    """Identificador no reversible del canary: sha256(canary)[:12]."""
    return hashlib.sha256(canary.encode("utf-8")).hexdigest()[:12]


def find_canaries(text: str) -> list[str]:
    """Canaries con el formato del contrato, sin duplicados y en orden de aparición."""
    return list(dict.fromkeys(re.findall(CANARY_PATTERN, text)))


def _url_decode(text: str) -> str:
    """unquote_plus iterado (hasta 3 veces) para cubrir doble codificación."""
    for _ in range(_MAX_URL_DECODES):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def _decode_hex_views(text: str) -> list[str]:
    """Decodifica cada tramo hexadecimal (con o sin separadores, 2 alineaciones)."""
    decoded: list[str] = []
    for source in (text, _HEX_SEPARATOR.sub("", text)):
        for run in _HEX_RUN.findall(source):
            for offset in (0, 1):  # un carácter hex pegado delante desalinea los pares
                body = run[offset:]
                body = body[: len(body) - len(body) % 2]
                if len(body) >= 12:
                    decoded.append(bytes.fromhex(body).decode("latin-1"))
    return decoded


def _decode_b64_views(text: str) -> list[str]:
    """Decodifica cada tramo base64 (estándar y urlsafe) con los 4 offsets de inicio.

    Un prefijo pegado delante del blob o un canary a mitad de un blob largo
    desalinean los grupos de 4 caracteres; probar offsets 0..3 los realinea.
    """
    decoded: list[str] = []
    for run in _B64_RUN.findall(text):
        run = run.rstrip("=").translate(str.maketrans("-_", "+/"))
        for offset in range(4):
            body = run[offset:]
            if len(body) % 4 == 1:
                body = body[:-1]
            if len(body) < 8:
                continue
            body += "=" * (-len(body) % 4)
            try:
                decoded.append(base64.b64decode(body).decode("latin-1"))
            except (binascii.Error, ValueError):
                continue
    return decoded


def _build_views(text: str) -> list[View]:
    """Vistas en orden de prioridad: plain > url > base64 > hex > reversed."""
    unquoted = _url_decode(text)
    bases = [text] if unquoted == text else [text, unquoted]
    views: list[View] = [("plain", text)]
    if unquoted != text:
        views.append(("url", unquoted))
    views += [("base64", v) for base in bases for v in _decode_b64_views(base)]
    views += [("hex", v) for base in bases for v in _decode_hex_views(base)]
    views += [("reversed", base[::-1]) for base in bases]
    return [(encoding, view.lower()) for encoding, view in views]


class _FragmentState:
    """Máscara de cobertura de los caracteres aleatorios de un canary."""

    def __init__(self, canary: str) -> None:
        self.text = canary.lower()
        self.start = len(_PREFIX) if canary.startswith(_PREFIX) else 0
        self.mask = [False] * len(canary)
        self.reported = 0  # posiciones cubiertas ya notificadas

    @property
    def total(self) -> int:
        return len(self.text) - self.start

    @property
    def covered(self) -> int:
        return sum(self.mask[self.start:])

    def absorb(self, view: str, min_fragment: int) -> None:
        """Marca las posiciones cubiertas por subcadenas comunes >= min_fragment."""
        size = len(self.text)
        for i in range(size - min_fragment + 1):
            end = i + min_fragment
            if self.text[i:end] not in view:
                continue
            while end < size and self.text[i:end + 1] in view:
                end += 1
            for pos in range(i, end):
                self.mask[pos] = True

    def mark_all(self) -> None:
        self.mask = [True] * len(self.text)
        self.reported = self.total


class EgressMonitor:
    """Detector de canaries en texto que sale por la red."""

    def __init__(self, canaries: Iterable[str], min_fragment: int = 4,
                 coverage_threshold: float = 0.85) -> None:
        self._canaries = {canary_id(c): c for c in dict.fromkeys(canaries)}
        self._lowered = {cid: c.lower() for cid, c in self._canaries.items()}
        self._min_fragment = min_fragment
        self._threshold = coverage_threshold
        self._state: dict[str, _FragmentState] = {}
        self.reset()

    def reset(self) -> None:
        """Olvida la cobertura acumulada (nueva sesión)."""
        self._state = {cid: _FragmentState(c) for cid, c in self._canaries.items()}

    def scan(self, text: str) -> list[EgressFinding]:
        """Sin estado: busca canarios completos solo en este texto."""
        return self._scan_views(_build_views(text))

    def observe(self, text: str) -> list[EgressFinding]:
        """Con estado: `scan` + acumulación de fragmentos entre llamadas."""
        views = _build_views(text)
        findings = self._scan_views(views)
        whole = {f.canary_id for f in findings}
        for cid, state in self._state.items():
            for _, view in views:
                state.absorb(view, self._min_fragment)
            if cid in whole:
                state.mark_all()
                continue
            covered = state.covered
            if state.total <= 0 or covered <= state.reported:
                continue
            fraction = covered / state.total
            if fraction >= self._threshold:
                state.reported = covered
                findings.append(EgressFinding(canary_id=cid, encoding="fragmented",
                                              coverage=fraction))
        return findings

    def _scan_views(self, views: list[View]) -> list[EgressFinding]:
        findings: list[EgressFinding] = []
        pending = dict(self._lowered)
        for encoding, view in views:
            for cid, needle in list(pending.items()):
                if needle in view:
                    findings.append(EgressFinding(canary_id=cid, encoding=encoding,
                                                  coverage=1.0))
                    del pending[cid]
        return findings
