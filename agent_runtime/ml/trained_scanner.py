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
from typing import TYPE_CHECKING, Optional

from ..contracts import ScanResult, ScanSpan
from ..monitors.injection_scanner import (
    HeuristicInjectionScanner, InjectionScanner, MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD,
)
from .classifier import MODEL_PATH, LogisticModel

if TYPE_CHECKING:
    from .sentinel import BenignScorer

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


HF_RULE = "hf_sentinel"
MAX_CHUNK_CHARS = 1500


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


class TwoStageInjectionScanner(InjectionScanner):
    """Dos etapas que el documento debe pasar AMBAS:

    1. Determinista + clasificador propio (`HybridInjectionScanner`): no debe dar "malicious".
    2. Clasificador de Hugging Face (Sentinel v2): cada trozo debe ser "benigno" con
       confianza >= `min_benign` (0.75 por defecto).

    Si cualquiera falla, el veredicto es "malicious": el LLM de la Aduana no ve el documento y
    los trozos marcados se enmascaran (comportamiento de main). Score = máximo entre el score de
    la etapa 1 y el riesgo de la etapa 2 (1 - P(benigno) mínima).
    """

    def __init__(self, scorer: "BenignScorer", stage1: Optional[InjectionScanner] = None,
                 min_benign: Optional[float] = None) -> None:
        from .sentinel import min_benign as default_min_benign
        self.stage1 = stage1 or HybridInjectionScanner()
        self.scorer = scorer
        self.min_benign = default_min_benign() if min_benign is None else min_benign

    def scan_document(self, text: str, source: str) -> ScanResult:
        first = self.stage1.scan_document(text, source)
        chunks = chunks_with_offsets(text)
        probs = self.scorer.benign_probs([c for _, _, c in chunks]) if chunks else []
        lowest = min(probs, default=1.0)
        flagged = tuple(ScanSpan(start=s, end=e, rule=HF_RULE) for (s, e, _), p in zip(chunks, probs)
                        if p < self.min_benign)
        passed = first.verdict != "malicious" and lowest >= self.min_benign
        score = max(first.score, round(1.0 - lowest, 4))
        verdict = first.verdict if passed else "malicious"
        spans = tuple(sorted(set(first.spans) | set(flagged), key=lambda s: (s.start, s.end, s.rule)))
        return ScanResult(score=round(min(1.0, score), 4), spans=spans, verdict=verdict)


def default_scanner() -> InjectionScanner:
    """Dos etapas si Sentinel está disponible; si no, híbrido; si tampoco hay modelo propio, la heurística.

    `SENTINEL_MODE=required` hace que un Sentinel ausente sea un error (el sistema no arranca sin él).
    """
    from .sentinel import SentinelUnavailable, load_sentinel, mode
    try:
        base: InjectionScanner = HybridInjectionScanner()
    except (FileNotFoundError, ValueError):
        base = HeuristicInjectionScanner()
    if mode() == "off":
        return base
    try:
        return TwoStageInjectionScanner(load_sentinel(), stage1=base)
    except SentinelUnavailable:
        if mode() == "required":
            raise
        return base
