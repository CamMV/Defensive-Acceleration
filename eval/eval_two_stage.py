"""Evalúa el reconocimiento en dos etapas con el modelo Sentinel REAL en los sets reservados.

    python -m eval.eval_two_stage            # requiere el modelo descargado (condiciones aceptadas en HF)

Compara: heurística de main | híbrido (etapa 1) | Sentinel solo | dos etapas (umbral configurable).
Mide falsas alarmas en documentos oficiales legítimos (el test de main exige que salgan limpios),
latencia por documento y muestra la curva de umbrales de P(benigno).
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

from agent_runtime.contracts import ScanResult
from agent_runtime.ml.classifier import auroc, rates
from agent_runtime.ml.sentinel import load_sentinel, min_benign
from agent_runtime.ml.trained_scanner import HybridInjectionScanner, TwoStageInjectionScanner, chunks_with_offsets
from agent_runtime.monitors.injection_scanner import HeuristicInjectionScanner, InjectionScanner
from eval.injection_eval import load_docs_a, load_heldout_b

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "two_stage_metrics.json"


class SentinelOnly(InjectionScanner):
    def __init__(self, scorer, threshold: float) -> None:
        self.scorer, self.threshold = scorer, threshold

    def scan_document(self, text: str, source: str) -> ScanResult:
        chunks = chunks_with_offsets(text)
        lowest = min(self.scorer.benign_probs([c for _, _, c in chunks]), default=1.0) if chunks else 1.0
        return ScanResult(score=round(1 - lowest, 4), verdict="malicious" if lowest < self.threshold else "clean")


def blocked(scanner: InjectionScanner, items: list[tuple[str, str, int]]) -> tuple[list[int], list[float], float]:
    flags, scores, started = [], [], time.perf_counter()
    for source, text, _ in items:
        r = scanner.scan_document(text, source)
        flags.append(int(r.verdict == "malicious"))
        scores.append(r.score)
    return flags, scores, (time.perf_counter() - started) / max(1, len(items))


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sentinel = load_sentinel()
    print(f"Sentinel: {sentinel.model_id} en {sentinel.device}; etiqueta benigna = "
          f"{sentinel.model.config.id2label[sentinel.benign_index]!r}")
    with tempfile.TemporaryDirectory() as tmp:
        docs = load_docs_a(Path(tmp) / "atk.jsonl")
    sentences = [("B", text, y) for text, y in load_heldout_b()]
    threshold = min_benign()
    scanners = {
        "heuristica_main": HeuristicInjectionScanner(),
        "hibrido_etapa1": HybridInjectionScanner(),
        f"sentinel_solo@{threshold}": SentinelOnly(sentinel, threshold),
        f"dos_etapas@{threshold}": TwoStageInjectionScanner(sentinel, min_benign=threshold),
    }
    report: dict = {"threshold": threshold, "scanners": {}}
    print(f"\n{'escáner':<22} | {'A bloqueo TPR':>13} {'FPR':>5} {'AUROC':>6} {'ms/doc':>7} | {'B bloqueo TPR':>13} {'FPR':>5} {'AUROC':>6}")
    for name, scanner in scanners.items():
        fa, sa, lat = blocked(scanner, docs)
        fb, sb, _ = blocked(scanner, sentences)
        ya, yb = [y for *_, y in docs], [y for *_, y in sentences]
        ra, rb = rates(fa, ya, 0.5), rates(fb, yb, 0.5)
        report["scanners"][name] = {"A": {**ra, "auroc": auroc(sa, ya), "ms_per_doc": lat * 1000},
                                    "B": {**rb, "auroc": auroc(sb, yb)},
                                    "A_benign_blocked": [s for (s, _, y), f in zip(docs, fa) if not y and f]}
        print(f"{name:<22} | {ra['tpr']:>13.2f} {ra['fpr']:>5.2f} {auroc(sa, ya):>6.2f} {lat * 1000:>7.1f} |"
              f" {rb['tpr']:>13.2f} {rb['fpr']:>5.2f} {auroc(sb, yb):>6.2f}")

    print("\nCurva de umbral de P(benigno) para Sentinel solo (A docs / B frases):")
    curve = []
    for t in (0.5, 0.6, 0.75, 0.9, 0.95):
        fa, _, _ = blocked(SentinelOnly(sentinel, t), docs)
        fb, _, _ = blocked(SentinelOnly(sentinel, t), sentences)
        ra, rb = rates(fa, [y for *_, y in docs], 0.5), rates(fb, [y for *_, y in sentences], 0.5)
        curve.append({"min_benign": t, "A": ra, "B": rb})
        print(f"  min_benign={t:<4}  A: TPR={ra['tpr']:.2f} FPR={ra['fpr']:.2f}   B: TPR={rb['tpr']:.2f} FPR={rb['fpr']:.2f}")
    report["curve"] = curve

    print("\nP(benigno) mínima por documento (A):")
    for source, text, y in docs:
        chunks = chunks_with_offsets(text)
        low = min(sentinel.benign_probs([c for _, _, c in chunks]), default=1.0) if chunks else 1.0
        print(f"  {'INY' if y else 'ben'}  {low:.3f}  {source}")
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nMétricas: {RESULTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
