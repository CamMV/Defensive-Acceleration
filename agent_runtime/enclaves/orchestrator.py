"""Enclave 0 — Orquestador (control plane) e intérprete del DAG.

Flujo (configuración D):
  1. Planner -> borrador (ve solo el prompt).
  2. PlanValidator -> Plan congelado; `broker.register_plan` lo fija.
  3. Intérprete: recorre los pasos en orden (las entradas solo apuntan hacia atrás, así
     que el orden del plan ya es topológico). Para cada paso: token del broker -> enclave.
  4. El Orquestador solo guarda `ExtractedRecord` (tipados + handles) y `WorkerReceipt`.
     Nunca lee texto de páginas, de la bóveda ni de handles.

Si un paso falla, los pasos que dependen de él se saltan (`input_failed`).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional, Union

from ..broker import CapabilityBroker
from ..contracts import ACTION_ROUTING, ActionType, EnclaveId, ExtractedRecord, Plan, PlanStep, WorkerReceipt
from .customs import CustomsEnclave, StepDenied
from .planner import LLMPlanner, PlanValidator, RulePlanner
from .vault_worker import VaultWorker

Planner = Union[RulePlanner, LLMPlanner]


@dataclass
class StepOutcome:
    step_id: str
    action: ActionType
    target: str
    ok: bool
    rule: str = "ok"
    record: Optional[ExtractedRecord] = None
    receipt: Optional[WorkerReceipt] = None


@dataclass
class RunResult:
    plan: Plan
    outcomes: list[StepOutcome] = field(default_factory=list)
    latency_s: float = 0.0
    llm_calls: int = 0
    used_mock_llm: bool = False

    def outcome(self, step_id: str) -> Optional[StepOutcome]:
        return next((o for o in self.outcomes if o.step_id == step_id), None)


class Orchestrator:
    enclave = EnclaveId.ORCHESTRATOR

    def __init__(self, broker: CapabilityBroker, customs: CustomsEnclave, worker: VaultWorker,
                 planner: Planner, validator: PlanValidator) -> None:
        self.broker = broker
        self.customs = customs
        self.worker = worker
        self.planner = planner
        self.validator = validator

    def run(self, prompt: str) -> RunResult:
        started = time.perf_counter()
        draft = self.planner.draft(prompt)
        plan = self.validator.validate(self.broker.session_id, prompt, draft)
        self.broker.register_plan(plan)
        result = RunResult(plan=plan)
        done: dict[str, StepOutcome] = {}
        for step in plan.steps:
            outcome = self._run_step(step, prompt, done)
            done[step.step_id] = outcome
            result.outcomes.append(outcome)
        llm = getattr(self.planner, "llm", None)
        result.llm_calls = llm.stats.calls if llm is not None else 0
        result.used_mock_llm = bool(llm is not None and llm.is_mock)
        result.latency_s = time.perf_counter() - started
        return result

    def _run_step(self, step: PlanStep, prompt: str, done: dict[str, StepOutcome]) -> StepOutcome:
        base = {"step_id": step.step_id, "action": step.action, "target": step.target}
        if any(not done[i].ok for i in step.inputs):
            return StepOutcome(**base, ok=False, rule="input_failed")
        token = self.broker.mint_for_step(step)
        if token is None:
            return StepOutcome(**base, ok=False, rule="token_denied")
        enclave = ACTION_ROUTING[step.action][0]
        try:
            if enclave is EnclaveId.CUSTOMS:
                return StepOutcome(**base, ok=True, record=self.customs.run_step(step, token))
            inputs = [done[i] for i in step.inputs]
            records = [o.record for o in inputs if o.record is not None]
            vault_reads = [o.step_id for o in inputs if o.action is ActionType.READ_VAULT]
            if step.action is ActionType.READ_VAULT:
                receipt = self.worker.read(step, token)
            elif step.action is ActionType.WRITE_REPORT:
                flagged = frozenset(r.step_id for r in records
                                    if r.step_id in self.customs.signals and self.customs.signals[r.step_id].flagged)
                receipt = self.worker.write_report(step, token, prompt, records, vault_reads, flagged)
            else:  # PATCH_CODE
                read_step = next((s for s in vault_reads if done[s].target == step.target), None)
                receipt = self.worker.patch_code(step, token, prompt, records, read_step)
            return StepOutcome(**base, ok=True, receipt=receipt)
        except StepDenied as denied:
            return StepOutcome(**base, ok=False, rule=denied.rule)
