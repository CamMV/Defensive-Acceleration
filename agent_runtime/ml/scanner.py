"""Escáner de inyección de doble chequeo para el punto `# ML-TEAM: Insert Model here` de main.

Un documento (o el texto transcrito de una imagen) continúa solo si AMBOS dicen que no hay inyección:
1. Determinista: la heurística regex de main (`HeuristicInjectionScanner`) no da "malicious".
2. Modelo: Galvanize-3 da P(inyección) < umbral (0.9802 por defecto) en todos los trozos.

Si cualquiera marca, el veredicto es "malicious": el LLM de la Aduana no ve el documento y los trozos
marcados se enmascaran (comportamiento de main). Score = máximo entre el score de la regex y la
P(inyección) más alta. Spans = unión (offsets + nombre de regla, nunca el texto).
"""
from __future__ import annotations

import re
from typing import Optional

from ..contracts import ScanResult, ScanSpan
from ..monitors.injection_scanner import HeuristicInjectionScanner, InjectionScanner
from .galvanize import InjectionScorer

MODEL_RULE = "galvanize3"
MAX_SEGMENTS = 400       # tope de costo por documento
MAX_CHUNK_CHARS = 1500   # ~ 400 tokens: un trozo cabe casi siempre en una sola ventana de 512
_SEGMENT = re.compile(r"[^<>\n.!?]{12,}")  # texto entre etiquetas o dentro de ellas (atributos, comentarios)


def chunks_with_offsets(text: str, max_chars: int = MAX_CHUNK_CHARS) -> list[tuple[int, int, str]]:
    """Agrupa segmentos contiguos (texto entre etiquetas, atributos, comentarios) en trozos acotados.

    Cada trozo se clasifica por separado: una orden escondida en una línea no se diluye en un
    documento largo, y el span marca dónde está.
    """
    out: list[tuple[int, int, str]] = []
    start = end = -1
    parts: list[str] = []
    for match in list(_SEGMENT.finditer(text))[:MAX_SEGMENTS]:
        piece = match.group(0).strip()
        if len(piece.split()) < 3:
            continue
        if parts and (sum(len(p) for p in parts) + len(piece) > max_chars):
            out.append((start, end, " ".join(parts)))
            parts = []
        if not parts:
            start = match.start()
        parts.append(piece)
        end = match.end()
    if parts:
        out.append((start, end, " ".join(parts)))
    return out


class DualCheckInjectionScanner(InjectionScanner):
    def __init__(self, scorer: InjectionScorer, deterministic: Optional[InjectionScanner] = None,
                 threshold: Optional[float] = None) -> None:
        from .galvanize import threshold as default_threshold
        self.deterministic = deterministic or HeuristicInjectionScanner()
        self.scorer = scorer
        self.threshold = default_threshold() if threshold is None else threshold

    def scan_document(self, text: str, source: str) -> ScanResult:
        rules = self.deterministic.scan_document(text, source)
        chunks = chunks_with_offsets(text)
        probs = self.scorer.injection_probs([c for _, _, c in chunks]) if chunks else []
        highest = max(probs, default=0.0)
        flagged = tuple(ScanSpan(start=s, end=e, rule=MODEL_RULE) for (s, e, _), p in zip(chunks, probs)
                        if p >= self.threshold)
        model_says_injection = highest >= self.threshold
        verdict = "malicious" if model_says_injection else rules.verdict
        score = min(1.0, max(rules.score, highest))
        spans = tuple(sorted(set(rules.spans) | set(flagged), key=lambda s: (s.start, s.end, s.rule)))
        return ScanResult(score=round(score, 4), spans=spans, verdict=verdict)


def default_scanner() -> InjectionScanner:
    """Regex + Galvanize-3 si el modelo carga; si no, solo la regex.

    `GALVANIZE_MODE=required` hace que un Galvanize ausente sea un error (el sistema no arranca sin él);
    `GALVANIZE_MODE=off` usa solo la regex.
    """
    from .galvanize import PREFIX, load_galvanize
    from .hf_common import ModelUnavailable, model_mode
    if model_mode(PREFIX) == "off":
        return HeuristicInjectionScanner()
    try:
        return DualCheckInjectionScanner(load_galvanize())
    except ModelUnavailable:
        if model_mode(PREFIX) == "required":
            raise
        return HeuristicInjectionScanner()
