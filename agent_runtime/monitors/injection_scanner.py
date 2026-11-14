"""Escáner de inyección de prompts para documentos no confiables.

La Aduana (enclave en cuarentena) lee documentos externos. Antes de exponer su
LLM, este módulo puntúa el documento. Veredicto ``malicious`` => el LLM no ve el
documento y los spans marcados se enmascaran; ``suspicious`` => se procesa pero
se audita. Es UNA capa entre varias (las garantías duras están en otro lado),
por eso se prioriza un bajo índice de falsos positivos sobre documentos
oficiales legítimos: términos como SECOP o "expediente" nunca bastan por sí solos.

Los spans solo llevan offsets y el nombre de la regla, jamás el texto coincidente.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Callable, Iterable, Optional

from agent_runtime.contracts import ScanResult, ScanSpan

SUSPICIOUS_THRESHOLD = 0.3
MALICIOUS_THRESHOLD = 0.6

DEFAULT_REPLACEMENT = "[REDACTED_BY_SCANNER]"

# Peso por familia; la puntuación es la suma de las familias que dispararon (tope 1.0).
FAMILY_WEIGHTS: dict[str, float] = {
    "ai_addressed": 0.35,
    "override": 0.35,
    "imperative_action": 0.35,
    "exfil_sink": 0.2,
    "sensitive_ref": 0.1,  # un solo disparo de la familia; nunca suma más de 0.1
    "hidden_html": 0.3,
}

_FLAGS = re.IGNORECASE | re.DOTALL
_MIN_COMMENT_WORDS = 5
_MAX_ALT_LENGTH = 80

# Estilos que ocultan texto al lector humano. El color == fondo usa grupo con nombre.
_HIDDEN_STYLE = (
    r"(?:display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|font-size\s*:\s*(?:0(?:px|pt|em|rem|%)?|1px)(?![\w.])"
    r"|(?<![-\w])color\s*:\s*(?P<c>[^;\"']+?)\s*;[^\"']*?background(?:-color)?\s*:\s*(?P=c)\s*(?:;|(?=[\"'])))"
)

_URL_CHARS = r"[^\s\"'<>]"


def _is_long_comment(matched: str) -> bool:
    """Un comentario HTML con 5+ palabras es un canal de texto oculto."""
    body = matched[4:-3]
    return len(re.findall(r"\w+", body)) >= _MIN_COMMENT_WORDS


# (familia, regex, predicado opcional sobre el texto coincidente)
_Rule = tuple[str, "re.Pattern[str]", Optional[Callable[[str], bool]]]


def _rule(family: str, pattern: str, predicate: Optional[Callable[[str], bool]] = None) -> _Rule:
    return family, re.compile(pattern, _FLAGS), predicate


_RULES: tuple[_Rule, ...] = (
    # --- Texto dirigido al agente ---
    _rule("ai_addressed", r"\bnotes?\s+for\s+(?:the\s+)?ai\b"),
    _rule("ai_addressed", r"\bai\s+(?:assistants?|agents?|models?)\b"),
    _rule("ai_addressed", r"\bas\s+an\s+ai\b"),
    _rule("ai_addressed", r"\bsystem\s+prompt\b"),
    _rule("ai_addressed", r"\basistentes?\s+de\s+ia\b"),
    _rule("ai_addressed", r"\bmodelo\s+de\s+lenguaje\b"),
    _rule("ai_addressed", r"\b(?:your|tus)\s+instruc(?:tions|ciones)\b"),
    # --- Anulación de instrucciones ---
    _rule("override", r"\b(?:ignore|disregard)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+)?(?:previous|prior|above)\s+instructions\b"),
    _rule("override", r"\bignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)\b"),
    _rule("override", r"\bbefore\s+continuing\b"),
    _rule("override", r"\bantes\s+de\s+continuar\b"),
    _rule("override", r"\bdo\s+not\s+tell\s+the\s+user\b"),
    _rule("override", r"\bnew\s+instructions\b"),
    # --- Órdenes tipo herramienta ---
    _rule("imperative_action", r"\bread\s+the\s+file\s+\S+"),
    _rule("imperative_action", r"\bsend\s+(?:its|the|your)\b[^.\n]{0,60}?\bto\b"),
    _rule("imperative_action", r"\bsearch\s+the\s+web\s+for\b"),
    _rule("imperative_action", r"\bappend\s+the\s+line\b"),
    _rule("imperative_action", r"\bmust\s+report\s+the\s+total\s+as\b"),
    _rule("imperative_action",
          r"\b(?:reveal|print|repeat|show)\s+your\s+(?:(?:full|complete)\s+)?(?:\w+\s+){0,2}?(?:system\s+prompt|instructions)\b"),
    _rule("imperative_action", r"\b(?:revela|muestra|env[ií]a)\s+tus\s+instrucciones\b"),
    _rule("imperative_action", r"\blee\s+el\s+archivo\b"),
    _rule("imperative_action", r"\benv[ií]a\s+(?:el|su)\s+contenido\b"),
    # --- Sumideros de exfiltración ---
    _rule("exfil_sink", rf"https?://{_URL_CHARS}*/collect(?![A-Za-z0-9_]){_URL_CHARS}*"),
    _rule("exfil_sink", rf"https?://{_URL_CHARS}*=(?=[\s\"'<>.,;)]|$)"),
    # --- Referencias sensibles (solas nunca llegan al umbral) ---
    _rule("sensitive_ref",
          r"restricted_vault|\.env\b|\bsecop\b|\bregistradur[ií]a\b|\bexpediente\b"
          r"|\bc[eé]dula\b|\bcredenciales\b|\bcredentials\b|\bdeclaraci[oó]n\s+de\s+renta\b"),
    # --- Canales de texto oculto en HTML crudo (el span cubre el elemento entero) ---
    _rule("hidden_html",
          rf"<(?P<tag>\w+)\b[^>]*?\bstyle\s*=\s*[\"'][^\"']*{_HIDDEN_STYLE}[^\"']*[\"'][^>]*>(?:.*?</(?P=tag)\s*>)?"),
    _rule("hidden_html", r"<!--.*?-->", _is_long_comment),
    _rule("hidden_html", rf"\b(?:alt|aria-label)\s*=\s*(?:\"[^\"]{{{_MAX_ALT_LENGTH + 1},}}\"|'[^']{{{_MAX_ALT_LENGTH + 1},}}')"),
)


def _verdict(score: float) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "malicious"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


class InjectionScanner(ABC):
    """Interfaz del escáner; la Aduana depende solo de esta abstracción."""

    @abstractmethod
    def scan_document(self, text: str, source: str) -> ScanResult:
        """Puntúa un documento no confiable. ``source`` es la URL o ruta de bóveda."""


# ML-TEAM: Insert Model here
# Contrato para el equipo de ML: reemplazar esta clase por un modelo propio que
# implemente InjectionScanner.
#   - Entrada: texto crudo no confiable (HTML, texto plano o markdown) y ``source``.
#   - Salida: ScanResult con ``score`` en [0, 1], ``spans`` como offsets (start, end)
#     sobre el texto recibido más el nombre de la regla (nunca el texto), y ``verdict``
#     derivado con SUSPICIOUS_THRESHOLD y MALICIOUS_THRESHOLD.
#   - Debe ser determinista, funcionar sin red y responder en < 200 ms.
#   - Se inyecta mediante el argumento ``scanner=`` de ``Customs``.
class HeuristicInjectionScanner(InjectionScanner):
    """Línea base heurística (regex, ES/EN). ``source`` se acepta pero se ignora."""

    def scan_document(self, text: str, source: str) -> ScanResult:
        spans: list[ScanSpan] = []
        fired: set[str] = set()
        for family, pattern, predicate in _RULES:
            for match in pattern.finditer(text):
                if predicate is not None and not predicate(match.group(0)):
                    continue
                spans.append(ScanSpan(start=match.start(), end=match.end(), rule=family))
                fired.add(family)
        spans.sort(key=lambda s: (s.start, s.end, s.rule))
        score = min(1.0, sum(FAMILY_WEIGHTS[family] for family in fired))
        return ScanResult(score=round(score, 4), spans=tuple(spans), verdict=_verdict(score))


_DEFAULT_SCANNER = HeuristicInjectionScanner()


def scan_document(text: str, source: str) -> ScanResult:
    """Atajo con el escáner heurístico por defecto."""
    return _DEFAULT_SCANNER.scan_document(text, source)


def mask_spans(text: str, spans: Iterable[ScanSpan], replacement: str = DEFAULT_REPLACEMENT) -> str:
    """Reemplaza cada span marcado; fusiona solapes y procesa de derecha a izquierda."""
    bounds = sorted((min(s.start, len(text)), min(s.end, len(text))) for s in spans)
    merged: list[list[int]] = []
    for start, end in bounds:
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in reversed(merged):
        text = text[:start] + replacement + text[end:]
    return text
