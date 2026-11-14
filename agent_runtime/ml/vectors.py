"""Vectores dispersos de n-gramas de caracteres + similitud coseno.

Por qué así (sector público / defensa):
- Determinista: mismo texto -> mismo vector en cualquier máquina y ejecución. El hash es
  `zlib.crc32`, no `hash()` de Python (que cambia por proceso).
- Rápido y offline: Python puro, sin numpy/torch ni modelos que descargar.
- Auditable: cada dimensión es un n-grama concreto.

Límite (documentar en P4): mide similitud LÉXICA. Una paráfrasis lejana la evade, así que
se usa como SEÑAL, nunca como barrera de seguridad.

ML-TEAM: para similitud semántica, implementa otro `Vectorizer` (p. ej. embeddings ONNX
locales) con la misma firma `embed(text) -> SparseVector`; `cosine` sigue sirviendo si
devuelves un dict índice->valor normalizado en L2.
"""
from __future__ import annotations

import math
import re
import unicodedata
import zlib
from typing import Iterable, Protocol, Sequence

SparseVector = dict[int, float]

_WS = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """NFKC + sin tildes + minúsculas + espacios colapsados."""
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = unicodedata.normalize("NFKC", text).casefold()
    return _WS.sub(" ", text).strip()


class Vectorizer(Protocol):
    def embed(self, text: str) -> SparseVector: ...


class HashedNgramVectorizer:
    """Bolsa de n-gramas de caracteres con hashing trick, tf sublineal y norma L2."""

    def __init__(self, ngram_min: int = 3, ngram_max: int = 5, n_buckets: int = 2 ** 18) -> None:
        if not 1 <= ngram_min <= ngram_max:
            raise ValueError("invalid n-gram range")
        if n_buckets < 2:
            raise ValueError("n_buckets must be >= 2")
        self.ngram_min = ngram_min
        self.ngram_max = ngram_max
        self.n_buckets = n_buckets

    def _ngrams(self, text: str) -> Iterable[str]:
        padded = f" {text} "
        for n in range(self.ngram_min, self.ngram_max + 1):
            for i in range(len(padded) - n + 1):
                yield padded[i:i + n]

    def embed(self, text: str) -> SparseVector:
        norm = normalize_text(text)
        if not norm:
            return {}
        counts: dict[int, int] = {}
        for gram in self._ngrams(norm):
            idx = zlib.crc32(gram.encode("utf-8")) % self.n_buckets
            counts[idx] = counts.get(idx, 0) + 1
        weights = {idx: 1.0 + math.log(c) for idx, c in counts.items()}
        length = math.sqrt(sum(w * w for w in weights.values()))
        return {idx: w / length for idx, w in weights.items()}


def cosine(a: SparseVector, b: SparseVector) -> float:
    """Coseno entre vectores ya normalizados en L2 (= producto punto). 0 si alguno es vacío."""
    if not a or not b:
        return 0.0
    if len(a) > len(b):
        a, b = b, a
    dot = sum(w * b.get(idx, 0.0) for idx, w in a.items())
    return max(0.0, min(1.0, dot))


def max_similarity(vec: SparseVector, bank: Sequence[SparseVector]) -> tuple[float, int]:
    """Mayor coseno contra un banco de prototipos: (score, índice). (0.0, -1) si no hay banco."""
    best, best_idx = 0.0, -1
    for i, proto in enumerate(bank):
        score = cosine(vec, proto)
        if score > best:
            best, best_idx = score, i
    return best, best_idx
