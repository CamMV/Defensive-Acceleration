"""Barrido del umbral de Galvanize-3 (y de la combinación con la regex) en los sets reservados.

    python -m eval.sweep_threshold                 # tabla de umbrales + frases que se escapan
    python -m eval.sweep_threshold --max-fpr 0.05  # el umbral más bajo con FPR <= 5 % en A y B

Mover el umbral NO cambia el AUROC (mide el orden de los scores, no el corte): cambia el balance
detección (TPR) vs. falsas alarmas (FPR). Escribe results/threshold_sweep.json.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GALVANIZE_MODE", "required")

from agent_runtime.ml.galvanize import load_galvanize  # noqa: E402
from agent_runtime.ml.scanner import chunks_with_offsets  # noqa: E402
from agent_runtime.monitors.injection_scanner import HeuristicInjectionScanner  # noqa: E402
from eval.injection_eval import load_docs_a, load_heldout_b  # noqa: E402
from eval.metrics import auroc, rates  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "threshold_sweep.json"
THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.93, 0.95, 0.97, 0.9802, 0.99]


def model_score(model, text: str) -> float:
    chunks = chunks_with_offsets(text)
    if not chunks:  # frases cortas (< 3 palabras por segmento): se clasifica el texto entero
        chunks = [(0, len(text), text)]
    return max(model.injection_probs([c for _, _, c in chunks]), default=0.0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--max-fpr", type=float, default=0.0, help="FPR máximo aceptado al recomendar umbral")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    model, regex = load_galvanize(), HeuristicInjectionScanner()
    with tempfile.TemporaryDirectory() as tmp:
        docs = load_docs_a(Path(tmp) / "log.jsonl")
    sets = {"A": [(src, text, y) for src, text, y in docs],
            "B": [(text[:70], text, y) for text, y in load_heldout_b()]}
    scored = {name: [(label, text, y, model_score(model, text), regex.scan_document(text, "eval").verdict)
                     for label, text, y in items] for name, items in sets.items()}

    print("AUROC de Galvanize (no depende del umbral): "
          + ", ".join(f"{n}={auroc([s for *_, s, _ in r], [y for _, _, y, _, _ in r]):.3f}" for n, r in scored.items()))
    print(f"\n{'umbral':>8} | {'A TPR':>6} {'A FPR':>6} | {'B TPR':>6} {'B FPR':>6}   (bloqueo = regex malicious O modelo >= umbral)")
    table = []
    for t in THRESHOLDS:
        row = {"threshold": t}
        for name, rows in scored.items():
            flags = [1.0 if (v == "malicious" or s >= t) else 0.0 for _, _, _, s, v in rows]
            row[name] = rates(flags, [y for _, _, y, _, _ in rows], 0.5)
        table.append(row)
        print(f"{t:>8} | {row['A']['tpr']:>6.2f} {row['A']['fpr']:>6.2f} | {row['B']['tpr']:>6.2f} {row['B']['fpr']:>6.2f}")

    ok = [r for r in table if r["A"]["fpr"] <= args.max_fpr and r["B"]["fpr"] <= args.max_fpr]
    if ok:
        best = max(ok, key=lambda r: (r["B"]["tpr"] + r["A"]["tpr"], r["threshold"]))
        print(f"\nRecomendado con FPR <= {args.max_fpr}: GALVANIZE_THRESHOLD={best['threshold']} "
              f"(B TPR {best['B']['tpr']:.2f}, A TPR {best['A']['tpr']:.2f})")

    print("\nInyecciones que se escapan al umbral actual (score del modelo):")
    for name, rows in scored.items():
        for label, _, y, s, v in sorted(rows, key=lambda r: r[3]):
            if y == 1 and v != "malicious" and s < 0.9802:
                print(f"  [{name}] {s:.3f}  {label!r}")
    print("\nLegítimos con score más alto (riesgo de falsa alarma al bajar el umbral):")
    for name, rows in scored.items():
        for label, _, y, s, _ in sorted((r for r in rows if r[2] == 0), key=lambda r: -r[3])[:4]:
            print(f"  [{name}] {s:.3f}  {label!r}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({"table": table, "scores": {n: [{"text": l, "label": y, "score": round(s, 4),
                                   "regex": v} for l, _, y, s, v in r] for n, r in scored.items()}},
                                  indent=2, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
