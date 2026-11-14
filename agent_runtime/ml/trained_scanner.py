"""Escáneres de inyección para el punto `# ML-TEAM: Insert Model here` de main.

- `MLInjectionScanner`: divide el documento crudo en segmentos (texto entre etiquetas HTML,
  saltos de línea y fin de oración, incluidos atributos y comentarios) y puntúa cada uno con
  el clasificador entrenado. Score del documento = máximo de los segmentos.
- `HybridInjectionScanner`: combina el escáner heurístico de main (regex por familias) con el
  clasificador: score = máximo de ambos y unión de spans. Es el que se usa por defecto.

Cumple el contrato de `InjectionScanner`: determinista, sin red, < 200 ms, spans como offsets
+ nombre de regla (nunca el texto), veredicto con los umbrales de main.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from ..contracts import ScanResult, ScanSpan
from ..monitors.injection_scanner import (
    HeuristicInjectionScanner, InjectionScanner, MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD,
)
from .classifier import MODEL_PATH, LogisticModel

ML_RULE = "ml_classifier"
SPAN_THRESHOLD = 0.5   # probabilidad mínima para marcar un segmento como span
MAX_SEGMENTS = 400     # tope de costo por documento
_SEGMENT = re.compile(r"[^<>\n.!?]{12,}")  # texto entre etiquetas o dentro de ellas (atributos, comentarios)


def _verdict(score: float) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "malicious"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


@lru_cache(maxsize=4)
def load_model(path: str = str(MODEL_PATH)) -> LogisticModel:
    return LogisticModel.load(Path(path))


class MLInjectionScanner(InjectionScanner):
    def __init__(self, model: Optional[LogisticModel] = None) -> None:
        self.model = model or load_model()

    def segment_scores(self, text: str) -> list[tuple[int, int, float]]:
        out = []
        for match in list(_SEGMENT.finditer(text))[:MAX_SEGMENTS]:
            if len(match.group(0).split()) < 3:
                continue
            out.append((match.start(), match.end(), self.model.predict_proba(match.group(0))))
        return out

    def scan_document(self, text: str, source: str) -> ScanResult:
        scored = self.segment_scores(text)
        score = max((p for _, _, p in scored), default=0.0)
        spans = tuple(ScanSpan(start=s, end=e, rule=ML_RULE) for s, e, p in scored if p >= SPAN_THRESHOLD)
        return ScanResult(score=round(score, 4), spans=spans, verdict=_verdict(score))


class HybridInjectionScanner(InjectionScanner):
    """Heurística de main + clasificador entrenado. Score = máximo; spans = unión.

    El clasificador solo aporta cuando clasifica un segmento como inyección (p >= 0.5, su umbral de
    decisión). Por debajo no suma: así no vuelve "sospechoso" un documento oficial legítimo.
    """

    def __init__(self, heuristic: Optional[InjectionScanner] = None, ml: Optional[MLInjectionScanner] = None) -> None:
        self.heuristic = heuristic or HeuristicInjectionScanner()
        self.ml = ml or MLInjectionScanner()

    def scan_document(self, text: str, source: str) -> ScanResult:
        h = self.heuristic.scan_document(text, source)
        m = self.ml.scan_document(text, source)
        ml_score = m.score if m.score >= SPAN_THRESHOLD else 0.0
        score = max(h.score, ml_score)
        spans = tuple(sorted(set(h.spans) | set(m.spans), key=lambda s: (s.start, s.end, s.rule)))
        return ScanResult(score=round(score, 4), spans=spans, verdict=_verdict(score))


def default_scanner() -> InjectionScanner:
    """Híbrido si existe el modelo entrenado; si no, la heurística de main."""
    try:
        return HybridInjectionScanner()
    except (FileNotFoundError, ValueError):
        return HeuristicInjectionScanner()
