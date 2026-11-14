"""Benchmark de reconocimiento de prompt injection: regex de main vs. Galvanize-3 vs. doble chequeo.

    python -m eval.benchmark.run                          # todo (texto + variantes + imágenes con WARD-2b)
    python -m eval.benchmark.run --no-images              # sin WARD (más rápido, ~1 min)
    python -m eval.benchmark.run --threshold 0.9          # otro umbral de Galvanize
    python -m eval.benchmark.run --scanners regex         # solo la línea base (no necesita GPU)
    python -m eval.benchmark.run --only handwritten       # handwritten | generated | image
    python -m eval.benchmark.run --compare results/benchmark/latest/report.json

Casos: eval/benchmark/cases.yaml (a mano) + variantes deterministas (eval/benchmark/transforms.py).
Salida: results/benchmark/<fecha-hora>/ y una copia en results/benchmark/latest/:
  report.md (tablas), report.json (métricas), cases.jsonl (score de cada caso y escáner),
  failures.csv (errores del escáner principal), images/ (las imágenes generadas y su transcripción).

Bloquear = veredicto "malicious" (el mismo criterio que usa la Aduana).
"""
from __future__ import annotations

import argparse
import csv
import difflib
import json
import os
import shutil
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

import yaml

from agent_runtime.contracts import ScanResult
from agent_runtime.monitors.injection_scanner import HeuristicInjectionScanner, InjectionScanner
from eval.benchmark.transforms import Case, generate, image_cases
from eval.metrics import auroc

ROOT = Path(__file__).resolve().parents[2]
CASES = Path(__file__).with_name("cases.yaml")
OUT = ROOT / "results" / "benchmark"
PRIMARY = "dual"


# -- casos ---------------------------------------------------------------------- #

def load_cases(with_generated: bool = True, with_images: bool = True,
               rewrite: Optional[Callable[[Case], str]] = None) -> list[Case]:
    """`rewrite` (opcional) cambia el texto de cada caso escrito a mano ANTES de generar variantes."""
    rows = yaml.safe_load(CASES.read_text(encoding="utf-8"))
    hand = [Case(id=r["id"], label=int(r["label"]), cat=r["cat"], lang=r["lang"], diff=r["diff"], text=r["text"],
                 scope=r.get("scope", "in")) for r in rows]
    if rewrite is not None:
        for case in hand:
            case.text = rewrite(case)
    by_id = {c.id: c for c in hand}
    seeds = [by_id[r["id"]] for r in rows if r.get("seed")]
    paragraphs = {lang: [c.text for c in hand if c.cat == "long_benign" and c.lang == lang] for lang in ("es", "en")}
    cases = list(hand)
    if with_generated:
        cases += generate(seeds, paragraphs)
    if with_images:
        cases += image_cases(by_id)
    ids = [c.id for c in cases]
    duplicated = {i for i in ids if ids.count(i) > 1}
    if duplicated:
        raise ValueError(f"ids duplicados: {sorted(duplicated)[:5]}")
    return cases


# -- escáneres --------------------------------------------------------------------- #

class GalvanizeOnly(InjectionScanner):
    """Solo el modelo, con los mismos trozos que usa el doble chequeo en producción."""

    def __init__(self, scorer, cut: float) -> None:
        from agent_runtime.ml.scanner import chunks_with_offsets
        self.scorer, self.cut, self._chunks = scorer, cut, chunks_with_offsets

    def scan_document(self, text: str, source: str) -> ScanResult:
        chunks = self._chunks(text)
        p = max(self.scorer.injection_probs([c for _, _, c in chunks]), default=0.0) if chunks else 0.0
        return ScanResult(score=round(p, 4), spans=(), verdict="malicious" if p >= self.cut else "clean")


def build_scanners(names: list[str], threshold: Optional[float]) -> tuple[dict[str, InjectionScanner], dict]:
    info: dict = {}
    scanners: dict[str, InjectionScanner] = {}
    if "regex" in names:
        scanners["regex"] = HeuristicInjectionScanner()
    if {"galvanize", "dual"} & set(names):
        os.environ.setdefault("GALVANIZE_MODE", "required")
        from agent_runtime.ml.galvanize import load_galvanize, threshold as default_threshold
        from agent_runtime.ml.scanner import DualCheckInjectionScanner
        model = load_galvanize()
        cut = default_threshold() if threshold is None else threshold
        model.injection_probs(["warmup"])
        info.update(galvanize_model=model.model_id, device=model.device, threshold=cut)
        if "galvanize" in names:
            scanners["galvanize"] = GalvanizeOnly(model, cut)
        if "dual" in names:
            scanners["dual"] = DualCheckInjectionScanner(model, threshold=cut)
    return scanners, info


# -- métricas ---------------------------------------------------------------------- #

def summarize(rows: list[dict], scanner: str) -> dict:
    pos = [r for r in rows if r["label"] == 1]
    neg = [r for r in rows if r["label"] == 0]
    tp = sum(r[scanner]["blocked"] for r in pos)
    fp = sum(r[scanner]["blocked"] for r in neg)
    lat = [r[scanner]["ms"] for r in rows]
    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / len(pos) if pos else float("nan")
    return {
        "n": len(rows), "pos": len(pos), "neg": len(neg), "tp": tp, "fp": fp,
        "tpr": round(recall, 4) if pos else None, "fpr": round(fp / len(neg), 4) if neg else None,
        "precision": round(precision, 4) if tp + fp else None,
        "f1": round(2 * precision * recall / (precision + recall), 4) if tp and pos else (0.0 if pos else None),
        "auroc": round(auroc([r[scanner]["score"] for r in rows], [r["label"] for r in rows]), 4) if pos and neg else None,
        "ms_p50": round(statistics.median(lat), 2) if lat else None,
        "ms_p95": round(sorted(lat)[int(0.95 * (len(lat) - 1))], 2) if lat else None,
    }


def breakdown(rows: list[dict], scanners: list[str], key: str) -> dict[str, dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[str(r[key])].append(r)
    return {g: {s: summarize(items, s) for s in scanners} for g, items in sorted(groups.items())}


# -- ejecución -------------------------------------------------------------------- #

def transcribe(cases: list[Case], out_dir: Path) -> dict[str, dict]:
    os.environ.setdefault("WARD_MODE", "required")
    from agent_runtime.ml.ward import load_ward
    ward = load_ward()
    image_dir = out_dir / "images"
    image_dir.mkdir(parents=True, exist_ok=True)
    ward.read(cases[0].image)  # warmup
    result = {}
    for i, case in enumerate(cases, 1):
        (image_dir / f"{case.id}.png").write_bytes(case.image)
        started = time.perf_counter()
        text = ward.read(case.image)
        seconds = time.perf_counter() - started
        similarity = difflib.SequenceMatcher(None, " ".join(case.text.lower().split()), " ".join(text.lower().split())).ratio()
        result[case.id] = {"transcript": text, "ward_s": round(seconds, 3), "ocr_similarity": round(similarity, 3)}
        print(f"\r  WARD-2b {i}/{len(cases)}", end="", flush=True)
    print()
    (image_dir / "transcripts.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def run(cases: list[Case], scanners: dict[str, InjectionScanner], out_dir: Path) -> list[dict]:
    images = [c for c in cases if c.image is not None]
    transcripts = transcribe(images, out_dir) if images else {}
    rows = []
    for i, case in enumerate(cases, 1):
        text = transcripts[case.id]["transcript"] if case.id in transcripts else case.text
        row = {**case.meta(), **transcripts.get(case.id, {})}
        for name, scanner in scanners.items():
            started = time.perf_counter()
            result = scanner.scan_document(text, case.id)
            row[name] = {"blocked": result.verdict == "malicious", "verdict": result.verdict,
                         "score": result.score, "ms": round((time.perf_counter() - started) * 1000, 2)}
        rows.append(row)
        if i % 50 == 0 or i == len(cases):
            print(f"\r  escaneados {i}/{len(cases)}", end="", flush=True)
    print()
    return rows


# -- reportes ---------------------------------------------------------------------- #

def _fmt(v) -> str:
    if v is None:
        return "–"
    return f"{v:.2f}" if isinstance(v, float) else str(v)


def md_table(title: str, groups: dict[str, dict], scanners: list[str], cols=("tpr", "fpr", "auroc")) -> list[str]:
    head = "| " + title + " | n (+/−) | " + " | ".join(f"{s} {c.upper()}" for s in scanners for c in cols) + " |"
    lines = [head, "|" + "---|" * (2 + len(scanners) * len(cols))]
    for g, by_scanner in groups.items():
        first = next(iter(by_scanner.values()))
        cells = [_fmt(by_scanner[s][c]) for s in scanners for c in cols]
        lines.append(f"| {g} | {first['n']} ({first['pos']}/{first['neg']}) | " + " | ".join(cells) + " |")
    return lines


def write_reports(rows: list[dict], scanners: list[str], info: dict, out_dir: Path,
                  compare: Optional[Path]) -> dict:
    main_rows = [r for r in rows if r["scope"] == "in"]
    out_rows = [r for r in rows if r["scope"] == "out"]
    primary = PRIMARY if PRIMARY in scanners else scanners[-1]
    report = {
        "info": {**info, "cases": len(rows), "primary": primary, "date": time.strftime("%Y-%m-%d %H:%M:%S")},
        "overall": {s: summarize(main_rows, s) for s in scanners},
        "overall_no_boundary": {s: summarize([r for r in main_rows if r["diff"] != "boundary"], s) for s in scanners},
        "by_source": breakdown(main_rows, scanners, "source"),
        "by_category": breakdown(main_rows, scanners, "cat"),
        "by_transform": breakdown(main_rows, scanners, "transform"),
        "by_difficulty": breakdown(main_rows, scanners, "diff"),
        "by_language": breakdown(main_rows, scanners, "lang"),
        "out_of_scope": {s: summarize(out_rows, s) for s in scanners} if out_rows else {},
    }
    images = [r for r in rows if r["source"] == "image"]
    if images:
        report["images"] = {
            "n": len(images), "ward_s_p50": round(statistics.median(r["ward_s"] for r in images), 3),
            "ward_s_max": round(max(r["ward_s"] for r in images), 3),
            "ocr_similarity_mean": round(statistics.mean(r["ocr_similarity"] for r in images), 3),
            "by_style": {style: {"n": len(items), "ocr_similarity": round(statistics.mean(r["ocr_similarity"] for r in items), 3),
                                 **{s: summarize(items, s) for s in scanners}}
                         for style, items in sorted(_group(images, "image_style").items())}}

    (out_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    with (out_dir / "cases.jsonl").open("w", encoding="utf-8") as handle:
        for r in rows:
            handle.write(json.dumps(r, ensure_ascii=False) + "\n")
    texts = {c.id: c.text for c in load_cases(with_images=False)}
    failures = [r for r in rows if r[primary]["blocked"] != bool(r["label"])]
    with (out_dir / "failures.csv").open("w", encoding="utf-8", newline="") as handle:
        w = csv.writer(handle)
        w.writerow(["id", "error", "label", "cat", "transform", "diff", "scope", "score", "regex_verdict", "text_or_transcript"])
        for r in failures:
            w.writerow([r["id"], "FN" if r["label"] else "FP", r["label"], r["cat"], r["transform"], r["diff"], r["scope"],
                        r[primary]["score"], r.get("regex", {}).get("verdict", ""),
                        (r.get("transcript") or texts.get(r["id"], ""))[:400]])

    md = [f"# Benchmark de prompt injection — {report['info']['date']}", "",
          f"Casos: {len(rows)} ({len(main_rows)} en alcance, {len(out_rows)} fuera de alcance). "
          f"Umbral Galvanize: {info.get('threshold', '–')}. Escáner principal: `{primary}`.", "",
          "TPR = inyecciones bloqueadas / inyecciones (más alto mejor). FPR = legítimos bloqueados / legítimos "
          "(más bajo mejor). AUROC = separación por score, independiente del umbral.", "", "## General", "",
          "| escáner | TPR | FPR | precisión | F1 | AUROC | ms p50 | ms p95 |", "|---|---|---|---|---|---|---|---|"]
    for s, m in report["overall"].items():
        md.append(f"| {s} | {_fmt(m['tpr'])} | {_fmt(m['fpr'])} | {_fmt(m['precision'])} | {_fmt(m['f1'])} | "
                  f"{_fmt(m['auroc'])} | {_fmt(m['ms_p50'])} | {_fmt(m['ms_p95'])} |")
    md += ["", "Sin casos de frontera (diff = boundary):", "", "| escáner | TPR | FPR | F1 | AUROC |", "|---|---|---|---|---|"]
    for s, m in report["overall_no_boundary"].items():
        md.append(f"| {s} | {_fmt(m['tpr'])} | {_fmt(m['fpr'])} | {_fmt(m['f1'])} | {_fmt(m['auroc'])} |")
    for title, key in (("Por origen", "by_source"), ("Por categoría", "by_category"),
                       ("Por transformación", "by_transform"), ("Por dificultad", "by_difficulty"),
                       ("Por idioma", "by_language")):
        md += ["", f"## {title}", ""] + md_table(title.split()[-1], report[key], scanners, cols=("tpr", "fpr"))
    if report.get("images"):
        im = report["images"]
        md += ["", "## Imágenes (WARD-2b → doble chequeo)", "",
               f"{im['n']} imágenes. WARD p50 {im['ward_s_p50']} s, máx {im['ward_s_max']} s. "
               f"Similitud media transcripción/texto real: {im['ocr_similarity_mean']}.", "",
               "| estilo | n | similitud OCR | " + " | ".join(f"{s} TPR | {s} FPR" for s in scanners) + " |",
               "|" + "---|" * (3 + 2 * len(scanners))]
        for style, m in im["by_style"].items():
            md.append(f"| {style} | {m['n']} | {m['ocr_similarity']} | "
                      + " | ".join(f"{_fmt(m[s]['tpr'])} | {_fmt(m[s]['fpr'])}" for s in scanners) + " |")
    if report["out_of_scope"]:
        md += ["", "## Fuera de alcance (data poisoning sin imperativos; no entra en las métricas)", ""]
        md += [f"- {s}: bloqueó {m['tp']}/{m['pos']}" for s, m in report["out_of_scope"].items()]
    fn = [r for r in failures if r["label"] == 1 and r["scope"] == "in"]
    fp = [r for r in failures if r["label"] == 0]
    md += ["", f"## Errores de `{primary}`: {len(fn)} falsos negativos, {len(fp)} falsos positivos (detalle en failures.csv)", ""]
    for r in sorted(fp, key=lambda r: -r[primary]["score"])[:15]:
        md.append(f"- FP `{r['id']}` score {r[primary]['score']:.3f}: {texts.get(r['id'], r.get('transcript', ''))[:120]!r}")
    for r in sorted(fn, key=lambda r: r[primary]["score"])[:25]:
        md.append(f"- FN `{r['id']}` score {r[primary]['score']:.3f}")

    if compare and compare.is_file():
        md += ["", f"## Comparación con {compare}", ""] + compare_lines(json.loads(compare.read_text(encoding="utf-8")),
                                                                        report, compare.parent / "cases.jsonl", rows, primary)
    (out_dir / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return report


def _group(rows: list[dict], key: str) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[str(r[key])].append(r)
    return groups


def compare_lines(old: dict, new: dict, old_cases: Path, rows: list[dict], primary: str) -> list[str]:
    lines = ["| escáner | TPR antes → ahora | FPR antes → ahora | AUROC antes → ahora |", "|---|---|---|---|"]
    for s, m in new["overall"].items():
        o = old.get("overall", {}).get(s)
        if o:
            lines.append(f"| {s} | {_fmt(o['tpr'])} → {_fmt(m['tpr'])} | {_fmt(o['fpr'])} → {_fmt(m['fpr'])} | "
                         f"{_fmt(o['auroc'])} → {_fmt(m['auroc'])} |")
    if old_cases.is_file():
        before = {}
        for line in old_cases.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            if primary in r:
                before[r["id"]] = r[primary]["blocked"]
        flips = [(r["id"], before[r["id"]], r[primary]["blocked"], r["label"]) for r in rows
                 if r["id"] in before and before[r["id"]] != r[primary]["blocked"]]
        lines += ["", f"Casos que cambiaron de veredicto en `{primary}`: {len(flips)}"]
        for cid, was, now, label in flips[:40]:
            good = now == bool(label)
            lines.append(f"- {'mejora' if good else 'EMPEORA'} `{cid}`: {'bloqueado' if was else 'pasaba'} → "
                         f"{'bloqueado' if now else 'pasa'} (label {label})")
    return lines


def print_summary(report: dict, scanners: list[str]) -> None:
    for title, key in (("Todos los casos en alcance", "overall"), ("Sin casos de frontera", "overall_no_boundary")):
        print(f"\n{title}\n{'escáner':12}{'TPR':>7}{'FPR':>7}{'F1':>7}{'AUROC':>8}{'ms p50':>9}{'ms p95':>9}")
        for s, m in report[key].items():
            print(f"{s:12}{_fmt(m['tpr']):>7}{_fmt(m['fpr']):>7}{_fmt(m['f1']):>7}{_fmt(m['auroc']):>8}"
                  f"{_fmt(m['ms_p50']):>9}{_fmt(m['ms_p95']):>9}")
    primary = report["info"]["primary"]
    print(f"\nPeores categorías para `{primary}` (TPR en positivos / FPR en negativos):")
    worst = sorted(report["by_category"].items(),
                   key=lambda kv: -((1 - (kv[1][primary]["tpr"] or 1)) + (kv[1][primary]["fpr"] or 0)))[:8]
    for cat, m in worst:
        p = m[primary]
        print(f"  {cat:22} n={p['n']:<4} TPR={_fmt(p['tpr']):>5} FPR={_fmt(p['fpr']):>5}")
    print(f"\nPeores transformaciones para `{primary}`:")
    worst = sorted(report["by_transform"].items(),
                   key=lambda kv: -((1 - (kv[1][primary]["tpr"] or 1)) + (kv[1][primary]["fpr"] or 0)))[:8]
    for name, m in worst:
        p = m[primary]
        print(f"  {name:22} n={p['n']:<4} TPR={_fmt(p['tpr']):>5} FPR={_fmt(p['fpr']):>5}")
    if report.get("images"):
        im = report["images"]
        print(f"\nImágenes: {im['n']}, WARD p50 {im['ward_s_p50']} s, similitud OCR media {im['ocr_similarity_mean']}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scanners", default="regex,galvanize,dual", help="lista separada por comas")
    parser.add_argument("--threshold", type=float, default=None, help="umbral de Galvanize (por defecto GALVANIZE_THRESHOLD o 0.95)")
    parser.add_argument("--no-images", action="store_true", help="no generar ni transcribir imágenes")
    parser.add_argument("--no-generated", action="store_true", help="solo los casos escritos a mano")
    parser.add_argument("--only", choices=["handwritten", "generated", "image"], help="filtrar por origen")
    parser.add_argument("--cat", help="filtrar por categoría (cat de cases.yaml)")
    parser.add_argument("--compare", type=Path, help="report.json de una corrida anterior")
    parser.add_argument("--out", type=Path, default=OUT, help="directorio de resultados")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    names = [n.strip() for n in args.scanners.split(",") if n.strip()]
    if args.only == "image" and args.no_images:
        parser.error("--only image y --no-images se excluyen")
    cases = load_cases(with_generated=not args.no_generated, with_images=not args.no_images)
    if args.only:
        cases = [c for c in cases if c.source == args.only]
    if args.cat:
        cases = [c for c in cases if c.cat == args.cat]
    if not cases:
        parser.error("no quedan casos con esos filtros")
    print(f"Casos: {len(cases)} ({sum(c.label for c in cases)} inyecciones, {sum(1 - c.label for c in cases)} legítimos, "
          f"{sum(c.image is not None for c in cases)} imágenes)")
    scanners, info = build_scanners(names, args.threshold)
    if info:
        print(f"Galvanize: {info['galvanize_model']} en {info['device']}, umbral {info['threshold']}")

    out_dir = args.out / time.strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = run(cases, scanners, out_dir)
    report = write_reports(rows, list(scanners), info, out_dir, args.compare)
    latest = args.out / "latest"
    if latest.exists():
        shutil.rmtree(latest)
    shutil.copytree(out_dir, latest)
    print_summary(report, list(scanners))
    print(f"\nReporte: {out_dir.relative_to(ROOT) if out_dir.is_relative_to(ROOT) else out_dir}/report.md "
          f"(copia en {latest.relative_to(ROOT) if latest.is_relative_to(ROOT) else latest}/)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
