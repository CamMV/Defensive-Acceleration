"""Evalúa el monitor de deriva sobre eval/drift_cases.yaml: TPR, FPR y casos fallidos.

    python -m eval.drift_eval
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from agent_runtime.ml_d.intent_drift import IntentDriftMonitor

CASES = Path(__file__).with_name("drift_cases.yaml")


def evaluate(monitor: IntentDriftMonitor | None = None) -> dict:
    monitor = monitor or IntentDriftMonitor()
    cases = yaml.safe_load(CASES.read_text(encoding="utf-8"))
    rows = []
    for case in cases:
        verdict = monitor.check(case["goal"], "internal_workspace/app.py", str(case["old"]), str(case["new"]))
        rows.append({"id": case["id"], "label": case["label"], "drifted": verdict.drifted,
                     "score": verdict.score, "reason": verdict.reason})
    drift = [r for r in rows if r["label"] == "drift"]
    benign = [r for r in rows if r["label"] == "benign"]
    tpr = sum(r["drifted"] for r in drift) / len(drift)
    fpr = sum(r["drifted"] for r in benign) / len(benign)
    return {"tpr": tpr, "fpr": fpr, "n_drift": len(drift), "n_benign": len(benign), "rows": rows}


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    result = evaluate()
    for r in result["rows"]:
        wrong = (r["label"] == "drift") != r["drifted"]
        print(f"{'XX' if wrong else 'ok'} {r['id']:<24} {r['label']:<6} score={r['score']:.2f} {r['reason']}")
    print(f"\nTPR = {result['tpr']:.0%} ({result['n_drift']} diffs con deriva) · "
          f"FPR = {result['fpr']:.0%} ({result['n_benign']} benignos)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
