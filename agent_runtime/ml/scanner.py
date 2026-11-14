"""Escáner de inyección de doble chequeo para el punto `# ML-TEAM: Insert Model here` de main.

Dos señales sobre cada documento (o el texto transcrito de una imagen):
1. Determinista: la heurística regex de main (`HeuristicInjectionScanner`).
2. Modelo: Galvanize-3, P(inyección) por trozo (umbral 0.99 por defecto, `GALVANIZE_THRESHOLD`).

Política (calibrada con eval/benchmark, ver docs/ML_ARCHITECTURE.md §5d):
- Bloquea ("malicious") cuando el modelo supera el umbral. El LLM de la Aduana no ve el documento.
- La regex sola NO bloquea: su "malicious" baja a "suspicious" (se audita y sus reglas quedan en los
  spans). En el benchmark no atrapó ningún ataque que el modelo no atrapara y sí sumaba falsas
  alarmas. `INJECTION_REGEX_BLOCKS=1` restaura "bloquea si cualquiera de los dos marca".
- Si el modelo no está disponible, `default_scanner()` devuelve la regex sola y ahí SÍ bloquea
  (comportamiento original de main).

Spans (offsets + regla, nunca el texto): se marcan las ORACIONES que el modelo señala dentro de cada
trozo bloqueado, no el trozo entero; así enmascarar no borra completo un documento legítimo largo. Si
ninguna oración supera el umbral por sí sola (la orden solo existe en contexto), se marca el trozo.
"""
from __future__ import annotations

import os
import re
from typing import Optional

from ..contracts import ScanResult, ScanSpan
from ..monitors.injection_scanner import HeuristicInjectionScanner, InjectionScanner
from .galvanize import InjectionScorer

MODEL_RULE = "galvanize3"
MAX_SEGMENTS = 400       # tope de costo por documento
MAX_CHUNK_CHARS = 1500   # ~ 400 tokens: un trozo cabe casi siempre en una sola ventana de 512
_SEGMENT = re.compile(r"[^<>\n.!?]{12,}")  # texto entre etiquetas o dentro de ellas (atributos, comentarios)
# Entre dos segmentos hay frontera de párrafo si media una línea en blanco o una etiqueta de bloque.
_PARAGRAPH_BREAK = re.compile(
    r"\n\s*\n|<\s*/?\s*(?:p|div|li|ul|ol|h[1-6]|tr|table|section|article|br|pre|blockquote)\b", re.IGNORECASE)


def regex_blocks() -> bool:
    return os.environ.get("INJECTION_REGEX_BLOCKS", "0").strip().lower() in {"1", "true", "yes", "on"}


def _segments(text: str) -> list[tuple[int, int, str, bool]]:
    """(inicio, fin, texto, empieza_párrafo) de cada segmento con al menos 3 palabras."""
    out: list[tuple[int, int, str, bool]] = []
    prev_end = 0
    for match in list(_SEGMENT.finditer(text))[:MAX_SEGMENTS]:
        piece = match.group(0).strip()
        if len(piece.split()) < 3:
            continue
        new_paragraph = not out or bool(_PARAGRAPH_BREAK.search(text, prev_end, match.start()))
        out.append((match.start(), match.end(), piece, new_paragraph))
        prev_end = match.end()
    return out


def chunks_with_offsets(text: str, max_chars: int = MAX_CHUNK_CHARS) -> list[tuple[int, int, str]]:
    """Agrupa segmentos en trozos acotados SIN partir párrafos (salvo uno más largo que el tope).

    Cada trozo se clasifica por separado: una orden escondida en una línea no se diluye en un documento
    largo. Cortar a mitad de párrafo producía falsos positivos (un trozo en español que terminaba con el
    fragmento de un párrafo en inglés daba P = 1.0), por eso las fronteras caen entre párrafos.
    """
    paragraphs: list[list[tuple[int, int, str]]] = []
    for start, end, piece, new_paragraph in _segments(text):
        if new_paragraph or not paragraphs:
            paragraphs.append([])
        paragraphs[-1].append((start, end, piece))

    out: list[tuple[int, int, str]] = []
    current: list[tuple[int, int, str]] = []

    def size(items: list[tuple[int, int, str]]) -> int:
        return sum(len(p) + 1 for _, _, p in items)

    def flush() -> None:
        if current:
            out.append((current[0][0], current[-1][1], " ".join(p for _, _, p in current)))
            current.clear()

    for paragraph in paragraphs:
        if current and size(current) + size(paragraph) > max_chars:
            flush()
        if size(paragraph) <= max_chars:
            current.extend(paragraph)
            continue
        for segment in paragraph:  # párrafo más largo que el tope: se parte por oraciones
            if current and size(current) + len(segment[2]) > max_chars:
                flush()
            current.append(segment)
        flush()
    flush()
    return out


class DualCheckInjectionScanner(InjectionScanner):
    def __init__(self, scorer: InjectionScorer, deterministic: Optional[InjectionScanner] = None,
                 threshold: Optional[float] = None, regex_can_block: Optional[bool] = None) -> None:
        from .galvanize import threshold as default_threshold
        self.deterministic = deterministic or HeuristicInjectionScanner()
        self.scorer = scorer
        self.threshold = default_threshold() if threshold is None else threshold
        self.regex_can_block = regex_blocks() if regex_can_block is None else regex_can_block

    def _sentence_spans(self, text: str, start: int, end: int) -> tuple[ScanSpan, ...]:
        """Oraciones del trozo [start, end) que el modelo marca por sí solas; si ninguna, el trozo entero."""
        sentences = [(s, e, p) for s, e, p, _ in _segments(text) if start <= s and e <= end]
        if len(sentences) > 1:
            probs = self.scorer.injection_probs([p for _, _, p in sentences])
            flagged = tuple(ScanSpan(start=s, end=e, rule=MODEL_RULE)
                            for (s, e, _), p in zip(sentences, probs) if p >= self.threshold)
            if flagged:
                return flagged
        return (ScanSpan(start=start, end=end, rule=MODEL_RULE),)

    def scan_document(self, text: str, source: str) -> ScanResult:
        rules = self.deterministic.scan_document(text, source)
        chunks = chunks_with_offsets(text)
        probs = self.scorer.injection_probs([c for _, _, c in chunks]) if chunks else []
        highest = max(probs, default=0.0)
        flagged: tuple[ScanSpan, ...] = ()
        for (start, end, _), p in zip(chunks, probs):
            if p >= self.threshold:
                flagged += self._sentence_spans(text, start, end)
        if highest >= self.threshold:
            verdict = "malicious"
        elif rules.verdict == "malicious":
            verdict = "malicious" if self.regex_can_block else "suspicious"
        else:
            verdict = rules.verdict
        score = min(1.0, max(rules.score, highest))
        spans = tuple(sorted(set(rules.spans) | set(flagged), key=lambda s: (s.start, s.end, s.rule)))
        return ScanResult(score=round(score, 4), spans=spans, verdict=verdict)


def default_scanner() -> InjectionScanner:
    """Regex + Galvanize-3 si el modelo carga; si no, solo la regex (que entonces sí bloquea sola).

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
