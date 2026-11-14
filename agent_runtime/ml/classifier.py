"""Clasificador de inyección entrenado: regresión logística sobre n-gramas con hashing.

- Features: n-gramas de caracteres (3-5) + n-gramas de palabras (1-2), hasheados con crc32 en
  2^18 posiciones, tf sublineal y normalización L2. Determinista y sin dependencias.
- Modelo: regresión logística entrenada con SGD (Python puro), regularización L2, clases
  balanceadas y semilla fija. Se guarda como JSON versionado (pesos podados).
- Inferencia: microsegundos por frase; sin red; misma entrada -> misma salida.

Este modelo es UNA capa de detección. No es la barrera de seguridad: la arquitectura
(plan congelado, cuarentena, broker) protege aunque el clasificador falle.
"""
from __future__ import annotations

import json
import math
import random
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from .vectors import normalize_text

N_BUCKETS = 2 ** 18
MODEL_PATH = Path(__file__).with_name("models") / "injection_lr.json"
_WORD = re.compile(r"[a-z0-9_]+")

SparseVector = dict[int, float]


def _hash(token: str) -> int:
    return zlib.crc32(token.encode("utf-8")) % N_BUCKETS


def featurize(text: str) -> SparseVector:
    norm = normalize_text(text)
    if not norm:
        return {}
    counts: dict[int, float] = {}
    padded = f" {norm} "
    for n in (3, 4, 5):
        for i in range(len(padded) - n + 1):
            k = _hash("c:" + padded[i:i + n])
            counts[k] = counts.get(k, 0.0) + 1.0
    words = _WORD.findall(norm)
    for i, w in enumerate(words):
        k = _hash("w:" + w)
        counts[k] = counts.get(k, 0.0) + 1.0
        if i + 1 < len(words):
            k = _hash("b:" + w + " " + words[i + 1])
            counts[k] = counts.get(k, 0.0) + 1.0
    weights = {k: 1.0 + math.log(c) for k, c in counts.items()}
    length = math.sqrt(sum(v * v for v in weights.values()))
    return {k: v / length for k, v in weights.items()}


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@dataclass
class LogisticModel:
    weights: dict[int, float] = field(default_factory=dict)
    bias: float = 0.0
    meta: dict = field(default_factory=dict)

    def score_vector(self, x: SparseVector) -> float:
        return _sigmoid(self.bias + sum(v * self.weights.get(k, 0.0) for k, v in x.items()))

    def predict_proba(self, text: str) -> float:
        return self.score_vector(featurize(text))

    # -- persistencia ------------------------------------------------------- #

    def save(self, path: Path = MODEL_PATH, prune: float = 1e-4) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        kept = {str(k): round(w, 5) for k, w in sorted(self.weights.items()) if abs(w) >= prune}
        payload = {"format": "hashed-ngram-logreg/v1", "n_buckets": N_BUCKETS, "bias": round(self.bias, 6),
                   "meta": self.meta, "weights": kept}
        path.write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "LogisticModel":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("format") != "hashed-ngram-logreg/v1" or payload.get("n_buckets") != N_BUCKETS:
            raise ValueError("incompatible model file")
        return cls({int(k): float(w) for k, w in payload["weights"].items()}, float(payload["bias"]),
                   payload.get("meta", {}))


def train(data: Sequence[tuple[str, int]], epochs: int = 12, lr: float = 0.4, l2: float = 1e-5,
          seed: int = 13) -> LogisticModel:
    """SGD con clases balanceadas y tasa de aprendizaje decreciente. Determinista."""
    rng = random.Random(seed)
    xs = [(featurize(t), y) for t, y in data]
    n_pos = sum(y for _, y in xs) or 1
    n_neg = (len(xs) - n_pos) or 1
    class_w = {1: len(xs) / (2 * n_pos), 0: len(xs) / (2 * n_neg)}
    model = LogisticModel()
    w = model.weights
    order = list(range(len(xs)))
    step = 0
    for epoch in range(epochs):
        rng.shuffle(order)
        for i in order:
            x, y = xs[i]
            step += 1
            eta = lr / (1.0 + 0.0005 * step)
            p = _sigmoid(model.bias + sum(v * w.get(k, 0.0) for k, v in x.items()))
            g = (p - y) * class_w[y]
            for k, v in x.items():
                w[k] = w.get(k, 0.0) * (1.0 - eta * l2) - eta * g * v
            model.bias -= eta * g
    model.meta = {"epochs": epochs, "lr": lr, "l2": l2, "seed": seed, "n_train": len(xs),
                  "n_pos": n_pos, "n_neg": n_neg}
    return model


# --------------------------------------------------------------------------- #
# Métricas (sin dependencias)
# --------------------------------------------------------------------------- #


def auroc(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Probabilidad de que un positivo puntúe más que un negativo (empates = 0.5)."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return float("nan")
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def rates(scores: Iterable[float], labels: Iterable[int], threshold: float) -> dict[str, float]:
    tp = fp = tn = fn = 0
    for s, y in zip(scores, labels):
        hit = s >= threshold
        if y == 1:
            tp, fn = tp + hit, fn + (not hit)
        else:
            fp, tn = fp + hit, tn + (not hit)
    return {"tpr": tp / (tp + fn) if tp + fn else float("nan"), "fpr": fp / (fp + tn) if fp + tn else float("nan"),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}
