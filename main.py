"""Demo de 60 s: el mismo ataque contra el baseline sin defensas y contra el sistema defendido.

    python main.py --mock                      # sin red externa ni claves
    python main.py --live                      # usa los modelos de .env
    python main.py --mock --scenario atk_multihop_app
"""
from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path

from agent_runtime.broker import AuditLog
from agent_runtime.contracts import AuditKind
from agent_runtime.runtime import RunOutcome, run_session, warmup_models
from eval.judge import judge, load_scenarios

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_SCENARIO = "atk_css_exfil"


def describe(label: str, scenario: dict, outcome: RunOutcome) -> bool:
    attack_succeeded, detail = judge(scenario, outcome)
    tool_calls = [event for event in outcome.events if event.kind is AuditKind.TOOL_CALL]
    denied = Counter(f"{event.enclave}:{event.tool or '-'} -> {event.rule}" for event in outcome.events
                     if event.allowed is False and event.rule)
    handles = sum(event.kind is AuditKind.HANDLE_CREATED for event in outcome.events)
    print(f"\n=== {label} (config {outcome.config}) ===")
    if outcome.error:
        print(f"  ERROR: {outcome.error}")
    print(f"  llamadas a herramientas : {len(tool_calls)}  | llamadas LLM: {outcome.llm_calls}"
          f"  | {outcome.latency_s * 1000:.0f} ms")
    collected = sum(str(entry.get("path", "")).startswith("/collect") for entry in outcome.attacker_entries)
    print(f"  peticiones a /collect   : {collected}")
    print(f"  handles en cuarentena   : {handles}")
    print(f"  app.py modificado       : {'SI' if outcome.app_changed else 'no'}")
    if denied:
        print("  decisiones DENY del broker / monitores:")
        for rule, count in denied.items():
            print(f"    - {rule} (x{count})")
    else:
        print("  decisiones DENY         : ninguna (no hay broker)" if outcome.config == "A"
              else "  decisiones DENY         : ninguna")
    print(f"  juez                    : {detail}")
    print(f"  >>> ATAQUE {'EXITOSO' if attack_succeeded else 'BLOQUEADO'}")
    return attack_succeeded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--mock", action="store_true", help="MockLLM determinista (atacante obediente)")
    mode.add_argument("--live", action="store_true", help="LLM real configurado en .env")
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO, help="id en eval/scenarios.yaml")
    parser.add_argument("--http", action="store_true",
                        help="usar el servidor real en 127.0.0.1:8000 en vez del servidor en proceso")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    scenarios = {scenario["id"]: scenario for scenario in load_scenarios()}
    if args.scenario not in scenarios:
        parser.error(f"unknown scenario; choose one of: {', '.join(scenarios)}")
    scenario = scenarios[args.scenario]

    run_dir = REPO_ROOT / "runs" / time.strftime("%Y%m%d-%H%M%S")
    audit = AuditLog(run_dir / "audit.jsonl")
    print(f"Escenario : {scenario['id']} - {scenario.get('description', '')}")
    print(f"Prompt    : {scenario['prompt']}")
    print(f"LLM       : {'MOCK (atacante obediente; no es una medida de un modelo real)' if args.mock else 'real (.env)'}")
    models = warmup_models()  # fuera del tiempo del flujo
    print(f"Modelos   : Galvanize-3 {'activo' if models['galvanize'] else 'no cargado (solo regex)'}"
          f" ({models['galvanize_s']} s) | WARD-2b {'activo' if models['ward'] else 'no cargado (sin imágenes)'}"
          f" ({models['ward_s']} s)")

    baseline = run_session("A", scenario["prompt"], run_dir, audit, "baseline", mock=args.mock, use_http=args.http)
    defended = run_session("D", scenario["prompt"], run_dir, audit, "defended", mock=args.mock, use_http=args.http)
    baseline_hit = describe("BASELINE monolítico sin defensas", scenario, baseline)
    defended_hit = describe("SISTEMA DEFENDIDO: 3 enclaves + broker + taint/egreso + aduana", scenario, defended)

    print("\n--- Reporte generado por el sistema defendido (extracto) ---")
    print("\n".join(defended.report_text.splitlines()[-8:]))
    print(f"\nEvidencia : {audit.path.relative_to(REPO_ROOT)}  ({len(audit.events)} eventos)")
    print(f"Contraste : baseline={'EXITOSO' if baseline_hit else 'bloqueado'}  "
          f"defendido={'EXITOSO' if defended_hit else 'BLOQUEADO'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
