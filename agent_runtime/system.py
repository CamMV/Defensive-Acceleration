"""Ensamblado del sistema defendido (configuración D) para `main.py`, la evaluación y tests.

Cada sesión recibe su propio broker (clave HMAC efímera), su propio QuarantineStore y una
instancia nueva de cada enclave. Nada se comparte entre sesiones salvo el AuditLog.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from .broker import AuditLog, CapabilityBroker
from .contracts import CONFIGS, ToolName
from .enclaves.customs import CustomsEnclave
from .enclaves.orchestrator import Orchestrator
from .enclaves.planner import LLMPlanner, PlanValidator, RulePlanner
from .enclaves.vault_worker import DriftCheck, VaultWorker
from .llm import BaseLLM
from .ml.summarizer import ExtractiveSummarizer, LLMSummarizer
from .monitors.intent_drift import IntentDriftMonitor
from .quarantine import QuarantineStore
from .tools import local_tools
from .tools.web_tools import WebTools


@dataclass
class DefendedSystem:
    session_id: str
    broker: CapabilityBroker
    store: QuarantineStore
    customs: CustomsEnclave
    worker: VaultWorker
    orchestrator: Orchestrator


def build_defended_system(vault_root: Path, audit: AuditLog, web_client: httpx.Client,
                          planner_llm: Optional[BaseLLM] = None, patch_llm: Optional[BaseLLM] = None,
                          drift_check: Optional[DriftCheck] = None, summarizer_llm: Optional[BaseLLM] = None,
                          session_id: Optional[str] = None) -> DefendedSystem:
    session_id = session_id or "d_" + secrets.token_hex(4)
    broker = CapabilityBroker(session_id, vault_root, audit, CONFIGS["D"])
    web = WebTools(web_client)
    broker.register_tool(ToolName.FETCH_URL, web.fetch_url)
    broker.register_tool(ToolName.WEB_SEARCH, web.web_search)
    broker.register_tool(ToolName.READ_INBOX, local_tools.read_inbox)
    broker.register_tool(ToolName.READ_FILE, local_tools.read_file)
    broker.register_tool(ToolName.WRITE_DIFF, local_tools.write_diff)
    store = QuarantineStore(session_id, audit)
    summarizer = LLMSummarizer(summarizer_llm) if summarizer_llm is not None else ExtractiveSummarizer()
    customs = CustomsEnclave(broker, store, summarizer=summarizer)
    worker = VaultWorker(broker, store, patch_llm=patch_llm,
                         drift_check=drift_check if drift_check is not None else IntentDriftMonitor())
    planner = LLMPlanner(planner_llm, audit, session_id) if planner_llm is not None else RulePlanner()
    orchestrator = Orchestrator(broker, customs, worker, planner, PlanValidator(audit))
    return DefendedSystem(session_id, broker, store, customs, worker, orchestrator)
