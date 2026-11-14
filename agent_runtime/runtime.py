"""Ensamblado de una sesión: copia de bóveda, servidor de pruebas, agente y resultado.

Módulo añadido a la estructura objetivo: `main.py` y `eval/run_matrix.py`
comparten este único punto de entrada en vez de duplicar el cableado.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx

from baselines.monolithic_agent import MonolithicAgent
from test_server.app import DEFAULT_LOG, create_app, inprocess_client

from .broker import AuditLog, CapabilityBroker
from .contracts import CONFIGS, AuditEvent, DefenseConfig, ToolName
from .enclaves.customs import Customs, OcrFn, no_ocr
from .enclaves.orchestrator import Orchestrator
from .enclaves.vault_worker import VaultWorker
from .llm import LLMClient, make_llm
from .monitors.egress import find_canaries
from .monitors.intent_drift import BaselineDriftMonitor, IntentDriftMonitor
from .quarantine import QuarantineStore
from .tools import local_tools
from .tools.web_tools import WebTools, http_client

REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_TEMPLATE = REPO_ROOT / "vault"
REPORT_PATH = "internal_workspace/acta_auditoria.md"
APP_PATH = "internal_workspace/app.py"


@dataclass
class RunOutcome:
    session_id: str
    config: str
    vault_dir: Path
    report_text: str
    app_text: str
    app_changed: bool
    attacker_entries: list[dict[str, Any]]
    canaries: list[str]
    system_canaries: list[str]
    events: list[AuditEvent]
    llm_calls: int
    latency_s: float
    used_mock: bool
    error: Optional[str] = None
    denies: list[str] = field(default_factory=list)  # reglas que negaron algo, en orden


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_jsonl(path: Path, skip: int = 0) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[skip:]
    return [json.loads(line) for line in lines if line.strip()]


def build_defended_system(config: DefenseConfig, session_id: str, vault_dir: Path, audit: AuditLog,
                          web: WebTools, user_prompt: str, mock: bool, seed: int,
                          drift_monitor: Optional[IntentDriftMonitor] = None,
                          ocr: OcrFn = no_ocr) -> tuple[Orchestrator, list[LLMClient]]:
    """Cablea broker + 3 enclaves. Cada enclave recibe su propia instancia de LLM."""
    broker = CapabilityBroker(session_id, vault_dir, audit, config)
    broker.register_tool(ToolName.READ_FILE, local_tools.read_file)
    broker.register_tool(ToolName.WRITE_DIFF, local_tools.write_diff)
    broker.register_tool(ToolName.READ_INBOX, local_tools.read_inbox)
    broker.register_tool(ToolName.FETCH_URL, web.fetch_url)
    broker.register_tool(ToolName.WEB_SEARCH, web.web_search)
    quarantine = QuarantineStore(session_id, audit)
    drift = (drift_monitor or BaselineDriftMonitor()) if config.customs_ml else None
    llms = [make_llm(role, mock, seed) for role in ("orchestrator", "customs", "vault_worker")]
    customs = Customs(broker, llms[1], quarantine, config, user_prompt, drift, ocr)
    worker = VaultWorker(broker, llms[2], quarantine, config, user_prompt, drift)
    return Orchestrator(broker, llms[0], config, customs, worker), llms


def run_session(config_name: "str | DefenseConfig", prompt: str, run_dir: Path, audit: AuditLog, session_id: str,
                mock: bool = True, seed: int = 0, use_http: bool = False) -> RunOutcome:
    """Ejecuta un prompt bajo una configuración (A-D) sobre una copia fresca de la bóveda."""
    config = CONFIGS[config_name] if isinstance(config_name, str) else config_name
    session_dir = run_dir / session_id
    vault_dir = session_dir / "vault"
    shutil.copytree(VAULT_TEMPLATE, vault_dir)
    app_before = _sha(vault_dir / APP_PATH)
    canaries = [canary for path in sorted((vault_dir / "restricted_vault").rglob("*")) if path.is_file()
                for canary in find_canaries(path.read_text(encoding="utf-8", errors="replace"))]

    if use_http:  # servidor real ya levantado en 127.0.0.1:8000
        attacker_log, skip = DEFAULT_LOG, len(_read_jsonl(DEFAULT_LOG))
        client: httpx.Client = http_client()
    else:  # en proceso: sin sockets
        attacker_log, skip = session_dir / "attacker_log.jsonl", 0
        client = inprocess_client(create_app(attacker_log))
    web = WebTools(client)

    error: Optional[str] = None
    llms: list[LLMClient] = []
    system_canaries: list[str] = []
    started = time.perf_counter()
    try:
        if config.privilege_separation:
            orchestrator, llms = build_defended_system(config, session_id, vault_dir, audit, web, prompt, mock, seed)
            system_canaries = [orchestrator.system_canary, orchestrator._customs.system_canary,
                               orchestrator._worker.system_canary]
            orchestrator.run(prompt)
        else:
            llms = [make_llm("baseline", mock, seed)]
            agent = MonolithicAgent(llms[0], vault_dir, web, audit, session_id)
            system_canaries = [agent.system_canary]
            agent.run(prompt)
    except Exception as exc:  # una corrida rota cuenta como fallo, no detiene la matriz
        error = f"{type(exc).__name__}: {exc}"
    finally:
        client.close()
    latency = time.perf_counter() - started

    events = audit.for_session(session_id)
    denies = [event.rule for event in events if event.allowed is False and event.rule]
    return RunOutcome(
        session_id=session_id, config=config.name, vault_dir=vault_dir,
        report_text=(vault_dir / REPORT_PATH).read_text(encoding="utf-8"),
        app_text=(vault_dir / APP_PATH).read_text(encoding="utf-8"),
        app_changed=_sha(vault_dir / APP_PATH) != app_before,
        attacker_entries=_read_jsonl(attacker_log, skip), canaries=list(dict.fromkeys(canaries)),
        system_canaries=system_canaries,
        events=events, llm_calls=sum(llm.calls for llm in llms), latency_s=latency,
        used_mock=mock, error=error, denies=denies,
    )
