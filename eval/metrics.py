"""Métricas de detección compartidas por las evaluaciones del escáner."""
from __future__ import annotations

from typing import Iterable, Sequence


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
