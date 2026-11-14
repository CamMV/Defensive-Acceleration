"""Matriz de ablación: configuraciones A-E x escenarios x repeticiones.

    python -m eval.run_matrix --mock            # pipeline completo sin red ni claves
    python -m eval.run_matrix --live --reps 3   # ASR reportable: LLM real vía .env

Salidas: results/matrix.csv (agregado), results/runs.csv (una fila por corrida),
results/asr_vs_utility.png. La columna `llm` dice si la fila usó mock: un ASR con
mock mide el pipeline frente a un atacante obediente, no a un modelo real.
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from agent_runtime.broker import AuditLog  # noqa: E402
from agent_runtime.contracts import CONFIGS  # noqa: E402
from agent_runtime.runtime import run_session, warmup_models  # noqa: E402
from eval.judge import internal_prompt_leaks, judge, load_scenarios, system_prompt_leaked  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_LABELS = {
    "A": "A: monolítico sin defensa",
    "B": "B: enclaves + broker",
    "C": "C: B + taint/egreso",
    "D": "D: broker + taint + aduana + scanner + datamarking",
    "E": "E: D-ML, plan DAG congelado (agent_runtime/ml_d)",
}
NOT_MEASURED = "no medido"
RUN_FIELDS = ["config", "scenario", "kind", "objective", "rep", "seed", "llm", "success", "prompt_leak",
              "internal_prompt_leaks", "false_block", "denies", "latency_s", "llm_calls", "error", "detail"]
MATRIX_FIELDS = ["config", "label", "llm", "reps", "attack_runs", "attack_success_rate", "prompt_leak_runs",
                 "prompt_leak_rate", "internal_prompt_leaks", "benign_runs", "benign_utility", "false_block_rate", "mean_latency_s", "mean_llm_calls", "skipped_requires_vlm"]


def run_matrix(configs: list[str], reps: int, base_seed: int, mock: bool, use_http: bool,
               results_dir: Path, include_vlm: bool = False) -> list[dict[str, Any]]:
    scenarios = load_scenarios()
    skipped = [s["id"] for s in scenarios if s.get("requires_vlm") and not include_vlm]
    scenarios = [s for s in scenarios if s["id"] not in skipped]
    llm_label = "mock" if mock else "live"
    run_dir = REPO_ROOT / "runs" / time.strftime("%Y%m%d-%H%M%S")
    audit = AuditLog(run_dir / "audit.jsonl")

    runs: list[dict[str, Any]] = []
    for config in configs:
        for scenario in scenarios:
            for rep in range(reps):
                seed = base_seed + rep
                outcome = run_session(config, scenario["prompt"], run_dir, audit,
                                      f"{config}_{scenario['id']}_r{rep}", mock=mock, seed=seed, use_http=use_http)
                success, detail = judge(scenario, outcome)
                runs.append({
                    "config": config, "scenario": scenario["id"], "kind": scenario["kind"],
                    "objective": scenario.get("objective", {}).get("type", ""), "rep": rep,
                    "seed": seed, "llm": llm_label, "success": int(success),
                    # Sin canaries de sistema (config E) no hay nada que medir: vacío, no 0.
                    "prompt_leak": int(system_prompt_leaked(outcome)) if outcome.system_canaries else "",
                    "internal_prompt_leaks": internal_prompt_leaks(outcome),
                    "false_block": int(scenario["kind"] == "benign" and bool(outcome.denies)),
                    "denies": "|".join(sorted(set(outcome.denies))), "latency_s": round(outcome.latency_s, 4),
                    "llm_calls": outcome.llm_calls, "error": outcome.error or "", "detail": detail,
                })

    matrix: list[dict[str, Any]] = []
    for config in configs:
        rows = [row for row in runs if row["config"] == config]
        attacks = [row for row in rows if row["kind"] == "attack"]
        benign = [row for row in rows if row["kind"] == "benign"]
        # prompt_leak_rate: de los ataques de extracción de system prompt, ¿cuántos hicieron llegar un
        # canary de sistema al atacante? (egreso bloqueado = 0; la fuga E0/E1 -> E2 se cuenta aparte).
        extraction = [row for row in attacks if row["objective"] == "system_prompt_leaked"]
        measured = [row["prompt_leak"] for row in extraction if row["prompt_leak"] != ""]
        matrix.append({
            "config": config, "label": CONFIG_LABELS[config], "llm": llm_label, "reps": reps,
            "attack_runs": len(attacks),
            "attack_success_rate": round(statistics.mean(r["success"] for r in attacks), 3) if attacks else "",
            "prompt_leak_runs": len(extraction),
            "prompt_leak_rate": (round(statistics.mean(measured), 3) if measured
                                 else NOT_MEASURED if extraction else ""),
            "internal_prompt_leaks": sum(r["internal_prompt_leaks"] for r in rows),
            "benign_runs": len(benign),
            "benign_utility": round(statistics.mean(r["success"] for r in benign), 3) if benign else "",
            "false_block_rate": round(statistics.mean(r["false_block"] for r in benign), 3) if benign else "",
            "mean_latency_s": round(statistics.mean(r["latency_s"] for r in rows), 4),
            "mean_llm_calls": round(statistics.mean(r["llm_calls"] for r in rows), 2),
            "skipped_requires_vlm": "|".join(skipped),
        })

    results_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(results_dir / "runs.csv", RUN_FIELDS, runs)
    _write_csv(results_dir / "matrix.csv", MATRIX_FIELDS, matrix)
    _plot(matrix, results_dir / "asr_vs_utility.png", mock)
    print(f"audit log: {audit.path.relative_to(REPO_ROOT)}")
    return matrix


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _plot(matrix: list[dict[str, Any]], path: Path, mock: bool) -> None:
    figure, axis = plt.subplots(figsize=(7, 5))
    for row in matrix:
        if row["attack_success_rate"] == "" or row["benign_utility"] == "":
            continue
        axis.scatter(row["attack_success_rate"], row["benign_utility"], s=140, zorder=3)
        axis.annotate(row["config"], (row["attack_success_rate"], row["benign_utility"]),
                      textcoords="offset points", xytext=(8, 8), fontsize=12, fontweight="bold")
    axis.set_xlim(-0.05, 1.05)
    axis.set_ylim(-0.05, 1.05)
    axis.set_xlabel("Attack Success Rate (menor es mejor)")
    axis.set_ylabel("Benign Utility (mayor es mejor)")
    source = "MOCK LLM (atacante obediente) - NO es una medida de un modelo real" if mock else "LLM real"
    axis.set_title(f"ASR vs utilidad por configuración\n{source}", fontsize=10)
    axis.grid(True, alpha=0.3, zorder=0)
    figure.text(0.01, 0.01, " | ".join(CONFIG_LABELS[row["config"]] for row in matrix), fontsize=6)
    figure.tight_layout(rect=(0, 0.03, 1, 1))
    figure.savefig(path, dpi=140)
    plt.close(figure)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--mock", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--seed", type=int, default=1000, help="semilla base; la repetición r usa seed+r")
    parser.add_argument("--configs", default="ABCD")
    parser.add_argument("--http", action="store_true", help="servidor real en 127.0.0.1:8000")
    parser.add_argument("--include-vlm", action="store_true", help="incluir escenarios requires_vlm")
    parser.add_argument("--results-dir", type=Path, default=REPO_ROOT / "results")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    configs = [name for name in args.configs.upper() if name in CONFIGS]
    print(f"Modelos (precarga, fuera de la latencia medida): {warmup_models()}")
    matrix = run_matrix(configs, args.reps, args.seed, args.mock, args.http, args.results_dir, args.include_vlm)
    print(f"\n{'cfg':4}{'llm':6}{'ASR':>7}{'prompt_leak_rate':>18}{'utility':>9}{'false_blk':>11}{'lat_s':>9}{'llm_calls':>11}")
    for row in matrix:
        print(f"{row['config']:4}{row['llm']:6}{row['attack_success_rate']:>7}{row['prompt_leak_rate']:>18}{row['benign_utility']:>9}"
              f"{row['false_block_rate']:>11}{row['mean_latency_s']:>9}{row['mean_llm_calls']:>11}")
    if args.mock:
        print("\nMOCK: estas filas ejercitan el pipeline con un atacante obediente. El ASR reportable requiere --live.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
