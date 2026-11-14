"""Evalúa el doble chequeo (regex de main + Galvanize-3) y la transcripción de WARD-2b con los modelos REALES.

    python -m eval.eval_galvanize

Texto (sets reservados de eval/injection_eval.py): regex sola | Galvanize-3 solo | doble chequeo.
Mide bloqueo (TPR/FPR), falsas alarmas en documentos oficiales legítimos y latencia por documento.
Imágenes (test_server/static): texto transcrito por WARD-2b, veredicto del doble chequeo y latencia.
Escribe results/galvanize_metrics.json.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("GALVANIZE_MODE", "required")
os.environ.setdefault("WARD_MODE", "required")

from agent_runtime.contracts import ScanResult  # noqa: E402
from agent_runtime.ml.galvanize import load_galvanize, threshold  # noqa: E402
from agent_runtime.ml.scanner import DualCheckInjectionScanner, chunks_with_offsets  # noqa: E402
from agent_runtime.ml.ward import load_ward  # noqa: E402
from agent_runtime.monitors.injection_scanner import HeuristicInjectionScanner, InjectionScanner  # noqa: E402
from eval.injection_eval import load_docs_a, load_heldout_b  # noqa: E402
from eval.metrics import auroc, rates  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "galvanize_metrics.json"
IMAGES = {"trap_lowcontrast.png": 1, "trap_typographic.png": 1, "diagram.png": 0}


class GalvanizeOnly(InjectionScanner):
    def __init__(self, scorer, cut: float) -> None:
        self.scorer, self.cut = scorer, cut

    def scan_document(self, text: str, source: str) -> ScanResult:
        chunks = chunks_with_offsets(text)
        p = max(self.scorer.injection_probs([c for _, _, c in chunks]), default=0.0) if chunks else 0.0
        return ScanResult(score=round(p, 4), spans=(), verdict="malicious" if p >= self.cut else "clean")


def blocked(scanner: InjectionScanner, items: list[tuple[str, int]]) -> tuple[dict, list[float], float]:
    flags, scores, started = [], [], time.perf_counter()
    for text, _ in items:
        result = scanner.scan_document(text, "eval")
        flags.append(1.0 if result.verdict == "malicious" else 0.0)
        scores.append(result.score)
    ms = (time.perf_counter() - started) * 1000 / max(1, len(items))
    labels = [y for _, y in items]
    return rates(flags, labels, 0.5), scores, ms


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    started = time.perf_counter()
    galvanize = load_galvanize()
    print(f"Galvanize-3: {galvanize.model_id} en {galvanize.device} ({time.perf_counter() - started:.1f} s de carga)")
    cut = threshold()
    galvanize.injection_probs(["warmup text for the classifier"])

    with tempfile.TemporaryDirectory() as tmp:
        loaded = load_docs_a(Path(tmp) / "log.jsonl")
    docs = [(text, y) for _, text, y in loaded]
    sources = [s for s, _, _ in loaded]
    sentences = load_heldout_b()
    scanners = {"regex_main": HeuristicInjectionScanner(), f"galvanize_solo@{cut}": GalvanizeOnly(galvanize, cut),
                f"doble_chequeo@{cut}": DualCheckInjectionScanner(galvanize, threshold=cut)}
    report: dict = {"threshold": cut, "device": galvanize.device, "text": {}, "images": {}}
    print(f"\n{'escáner':26}{'A bloqueo TPR/FPR':>20}{'A ms/doc':>10}{'B AUROC':>9}{'B bloqueo TPR/FPR':>20}")
    for name, scanner in scanners.items():
        ra, sa, ms = blocked(scanner, docs)
        rb, sb, _ = blocked(scanner, sentences)
        report["text"][name] = {
            "A_block": ra, "A_ms_per_doc": round(ms, 1), "B_auroc": auroc(sb, [y for _, y in sentences]), "B_block": rb,
            "A_false_alarms": [src for src, (_, y), s in zip(sources, docs, sa) if y == 0 and s >= cut],
            "A_per_doc": [{"source": src, "label": y, "score": s} for src, (_, y), s in zip(sources, docs, sa)]}
        print(f"{name:26}{ra['tpr']:>11.2f} / {ra['fpr']:<6.2f}{ms:>10.1f}{report['text'][name]['B_auroc']:>9.2f}"
              f"{rb['tpr']:>11.2f} / {rb['fpr']:<6.2f}")

    started = time.perf_counter()
    ward = load_ward()
    print(f"\nWARD-2b: {ward.model_id} en {ward.device} ({time.perf_counter() - started:.1f} s de carga)")
    dual = scanners[f"doble_chequeo@{cut}"]
    ward.read((ROOT / "test_server" / "static" / "diagram.png").read_bytes())  # warmup
    for name, label in IMAGES.items():
        data = (ROOT / "test_server" / "static" / name).read_bytes()
        t0 = time.perf_counter()
        text = ward.read(data)
        ward_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        result = dual.scan_document(text, name)
        scan_ms = (time.perf_counter() - t0) * 1000
        report["images"][name] = {"label": label, "transcript": text, "ward_s": round(ward_s, 2),
                                  "scan_ms": round(scan_ms, 1), "verdict": result.verdict, "score": result.score}
        print(f"  {name:24} etiqueta={label} veredicto={result.verdict:10} score={result.score:.3f} "
              f"WARD={ward_s:.2f}s scan={scan_ms:.0f}ms\n    transcripción: {text[:300]!r}")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nEscrito {RESULTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
