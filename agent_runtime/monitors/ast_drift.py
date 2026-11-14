"""Adaptador: el monitor de deriva por AST de `ml_d` detrás de la interfaz de `monitors.intent_drift`.

Las dos interfaces no coinciden:
  monitors.intent_drift.IntentDriftMonitor.check(user_prompt, step, call)
  ml_d.intent_drift.IntentDriftMonitor.check(goal, path, old, new)

Este adaptador no cambia ninguna de las dos. Las comprobaciones estructurales (herramienta y destino
iguales a los del paso del plan) siguen siendo las del baseline; solo el juicio sobre un cambio de
código pasa al monitor por AST. Así la configuración D puede usarlo:
`runtime.build_defended_system(drift_monitor=AstDriftMonitor())`.
"""
from __future__ import annotations

from typing import Optional

from ..contracts import ACTION_ROUTING, DriftVerdict, PlanStep, ToolCall, ToolName
from ..ml_d.intent_drift import IntentDriftMonitor as MlDriftMonitor
from .intent_drift import CODE_SUFFIXES, BaselineDriftMonitor


class AstDriftMonitor(BaselineDriftMonitor):
    def __init__(self, inner: Optional[MlDriftMonitor] = None) -> None:
        self._inner = inner or MlDriftMonitor()

    def check(self, user_prompt: str, step: PlanStep, call: ToolCall) -> DriftVerdict:
        is_planned_code_patch = (
            call.tool == ToolName.WRITE_DIFF.value
            and ACTION_ROUTING[step.action][1] is ToolName.WRITE_DIFF
            and step.target.casefold().endswith(CODE_SUFFIXES)
            and self._same_target(step, call)
        )
        if not is_planned_code_patch:
            return super().check(user_prompt, step, call)
        return self._inner.check(user_prompt, call.args.get("path", ""), call.args.get("old", ""),
                                 call.args.get("new", ""))
