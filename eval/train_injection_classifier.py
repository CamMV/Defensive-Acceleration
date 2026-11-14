"""Entrena el clasificador de inyección, lo guarda y lo evalúa en los sets reservados.

    python -m eval.train_injection_classifier

1. Genera el dataset sintético (agent_runtime/ml/injection_dataset.py).
2. Validación cruzada de 5 particiones sobre ese dataset (rendimiento dentro de la distribución).
3. Entrena con todo el dataset y guarda agent_runtime/ml/models/injection_lr.json.
4. Ablación en los sets reservados A (documentos del repo) y B (frases a mano):
   heurística de main vs. clasificador vs. híbrido.
5. Escribe results/injection_classifier_metrics.json e imprime la tabla.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

from agent_runtime.ml.classifier import MODEL_PATH, auroc, rates, train
from agent_runtime.ml.injection_dataset import generate
from agent_runtime.ml.trained_scanner import HybridInjectionScanner, MLInjectionScanner
from agent_runtime.monitors.injection_scanner import HeuristicInjectionScanner
from eval.injection_eval import IMAGE_ONLY, ablation

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "injection_classifier_metrics.json"


def cross_validate(data: list[tuple[str, int]], k: int = 5) -> dict:
    scores, labels = [], []
    for fold in range(k):
        test = [d for i, d in enumerate(data) if i % k == fold]
        model = train([d for i, d in enumerate(data) if i % k != fold])
        scores += [model.predict_proba(t) for t, _ in test]
        labels += [y for _, y in test]
    return {"auroc": auroc(scores, labels), "at_0.5": rates(scores, labels, 0.5)}


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    data = generate()
    print(f"Dataset sintético: {len(data)} frases ({sum(y for _, y in data)} inyecciones)")
    t0 = time.perf_counter()
    cv = cross_validate(data)
    print(f"CV 5 particiones (misma distribución): AUROC={cv['auroc']:.3f} "
          f"TPR={cv['at_0.5']['tpr']:.2f} FPR={cv['at_0.5']['fpr']:.2f}")
    model = train(data)
    model.save(MODEL_PATH)
    print(f"Modelo guardado en {MODEL_PATH.relative_to(ROOT)} ({MODEL_PATH.stat().st_size // 1024} KB, "
          f"entrenamiento total {time.perf_counter() - t0:.1f} s)")

    with tempfile.TemporaryDirectory() as tmp:
        results = ablation({"heuristica_main": HeuristicInjectionScanner,
                            "clasificador": lambda: MLInjectionScanner(model),
                            "hibrido": lambda: HybridInjectionScanner(ml=MLInjectionScanner(model))},
                           Path(tmp) / "atk.jsonl")
    print("\nSets reservados (nunca vistos en entrenamiento)")
    print(f"{'escáner':<16} | {'A docs AUROC':>12} {'TPR@0.6':>8} {'FPR@0.6':>8} {'TPR@0.3':>8} {'FPR@0.3':>8}"
          f" | {'B frases AUROC':>14} {'TPR@0.6':>8} {'FPR@0.6':>8}")
    for name, r in results.items():
        a, b = r["A_docs"], r["B_sentences"]
        print(f"{name:<16} | {a['auroc']:>12.3f} {a['malicious']['tpr']:>8.2f} {a['malicious']['fpr']:>8.2f}"
              f" {a['suspicious']['tpr']:>8.2f} {a['suspicious']['fpr']:>8.2f} | {b['auroc']:>14.3f}"
              f" {b['malicious']['tpr']:>8.2f} {b['malicious']['fpr']:>8.2f}")
    print(f"\nNo evaluable por un escáner de texto (payload solo en imagen): {', '.join(IMAGE_ONLY)}")
    print("\nPor documento (A), score heurística / clasificador / híbrido:")
    for i, row in enumerate(results["hibrido"]["A_docs"]["per_doc"]):
        h = results["heuristica_main"]["A_docs"]["per_doc"][i]["score"]
        m = results["clasificador"]["A_docs"]["per_doc"][i]["score"]
        print(f"  {'INY' if row['label'] else 'ben'}  {h:.2f} / {m:.2f} / {row['score']:.2f}  {row['source']}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({"dataset": {"n": len(data), "n_pos": sum(y for _, y in data)},
                                   "cv": cv, "model": model.meta, "heldout": results}, indent=2, ensure_ascii=False),
                       encoding="utf-8")
    print(f"\nMétricas: {RESULTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
