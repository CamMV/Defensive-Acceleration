"""Base común de los enclaves.

Cada enclave tiene su propia instancia de LLM, su propio historial y solo puede
actuar llamando al broker. El LLM nunca recibe tokens: los tokens los entrega el
runtime para un paso concreto del plan. Una llamada pedida por el LLM por su
cuenta va sin token y el broker la niega.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from ..broker import CapabilityBroker
from ..contracts import (
    ENCLAVE_TOOLS, AuditKind, BrokerDecision, CapabilityToken, EnclaveId, PlanStep, ToolCall, ToolResult,
)
from ..llm import LLMClient, parse_json
from ..monitors.intent_drift import IntentDriftMonitor

MAX_UNSOLICITED_CALLS = 6


class Enclave:
    enclave_id: EnclaveId

    def __init__(self, broker: CapabilityBroker, llm: LLMClient, user_prompt: str = "",
                 drift: Optional[IntentDriftMonitor] = None) -> None:
        self.broker = broker
        self.llm = llm
        self.tools = ENCLAVE_TOOLS[self.enclave_id]  # registro disjunto, derivado del contrato
        self.history: list[dict[str, str]] = []
        self._user_prompt = user_prompt
        self._drift = drift

    def _ask(self, task: str, system: str, payload: dict[str, Any]) -> dict[str, Any]:
        user = json.dumps(payload, ensure_ascii=False, default=str)
        reply = self.llm.complete(task, system, user)
        self.history.append({"task": task, "user": user, "reply": reply})
        return parse_json(reply)

    def _call(self, tool: str, args: dict[str, str], token: Optional[CapabilityToken] = None,
              step: Optional[PlanStep] = None) -> ToolResult:
        call = ToolCall(call_id=self.broker.new_call_id(), session_id=self.broker.session_id,
                        enclave=self.enclave_id, tool=tool, args=args, token=token)
        if self._drift is not None and step is not None:
            verdict = self._drift.check(self._user_prompt, step, call)
            self.broker.audit.write(self.broker.session_id, AuditKind.DRIFT_CHECK, enclave=self.enclave_id.value,
                                    tool=tool, allowed=not verdict.drifted, rule="intent_drift" if verdict.drifted else "allow",
                                    call_id=call.call_id, step_id=step.step_id, score=verdict.score, reason=verdict.reason)
            if verdict.drifted:
                return ToolResult(call_id=call.call_id,
                                  decision=BrokerDecision(allowed=False, rule="intent_drift", reason=verdict.reason))
        return self.broker.execute(call)

    def _attempt_unsolicited(self, tool_calls: Any) -> list[ToolResult]:
        """Llamadas que el LLM pidió por iniciativa propia (posible secuestro). Van SIN token."""
        results: list[ToolResult] = []
        if not isinstance(tool_calls, list):
            return results
        for item in tool_calls[:MAX_UNSOLICITED_CALLS]:
            if not isinstance(item, dict) or not isinstance(item.get("args"), dict):
                continue
            args = {str(key): str(value) for key, value in item["args"].items()}
            results.append(self._call(str(item.get("tool", ""))[:64], args, token=None))
        return results
