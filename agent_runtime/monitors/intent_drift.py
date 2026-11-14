"""Validador de deriva intención-acción.

Pregunta que responde: ¿esta llamada concreta sigue sirviendo a lo que pidió el
usuario en el paso del plan que se está ejecutando? Corre fuera del LLM, antes
del broker. La implementación baseline es léxica; el equipo ML la reemplaza.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

from ..contracts import ACTION_ROUTING, ActionType, DriftVerdict, PlanStep, ToolCall, ToolName
from ..broker import SUBRESOURCE_TARGET, normalize_scope_path
from ..tools.web_tools import UrlNotAllowed, net_target, search_target

DRIFT_THRESHOLD = 0.5
# Única forma de cambio de código que el baseline considera alineada: fijar una constante.
SAFE_ASSIGNMENT = re.compile(r'^[A-Z][A-Z0-9_]{1,40} = "[\w.\-]{1,40}"$')
CODE_SUFFIXES = (".py", ".js", ".ts", ".sh", ".ps1", ".bat", ".yaml", ".yml", ".toml", ".json")


class IntentDriftMonitor(ABC):
    @abstractmethod
    def check(self, user_prompt: str, step: PlanStep, call: ToolCall) -> DriftVerdict:
        """Compara la llamada propuesta con la intención del usuario para ese paso."""


class BaselineDriftMonitor(IntentDriftMonitor):
    """Reglas léxicas deterministas. Score 0 = alineado, 1 = deriva segura."""

    # ML-TEAM: reemplazar esta clase por un modelo (embeddings o NLI).
    #   Entrada: user_prompt (str, confiable), step (PlanStep: acción + destino fijados
    #            antes de ver datos no confiables), call (ToolCall: herramienta + args
    #            propuestos; `args["new"]` puede venir de un LLM que leyó L2).
    #   Salida:  DriftVerdict(drifted: bool, score: float en [0,1], reason: str corto
    #            sin copiar contenido de `call.args`, porque va al log de auditoría).
    #   Contrato: determinista para la misma entrada, sin red, < 200 ms por llamada.
    #   Se inyecta en `runtime.build_defended_system(drift_monitor=...)`.
    def check(self, user_prompt: str, step: PlanStep, call: ToolCall) -> DriftVerdict:
        _, expected_tool, _ = ACTION_ROUTING[step.action]
        allowed_tools = {expected_tool.value}
        if step.action is ActionType.PATCH_CODE:
            allowed_tools.add(ToolName.READ_FILE.value)
        if call.tool not in allowed_tools:
            return DriftVerdict(drifted=True, score=1.0, reason="tool differs from planned step")
        if not self._same_target(step, call):
            return DriftVerdict(drifted=True, score=1.0, reason="target differs from planned step")
        if call.tool == ToolName.WRITE_DIFF.value and step.target.casefold().endswith(CODE_SUFFIXES):
            return self._check_code_patch(call)
        return DriftVerdict(drifted=False, score=0.0, reason="matches planned step")

    @staticmethod
    def _same_target(step: PlanStep, call: ToolCall) -> bool:
        try:
            if call.tool == ToolName.FETCH_URL.value:
                target = net_target(call.args.get("url", ""))
                return target == net_target(step.target) or bool(SUBRESOURCE_TARGET.match(target))
            if call.tool == ToolName.WEB_SEARCH.value:
                return search_target(call.args.get("query", "")) == search_target(step.target)
        except UrlNotAllowed:
            return False
        return normalize_scope_path(call.args.get("path", "")) == normalize_scope_path(step.target)

    @staticmethod
    def _check_code_patch(call: ToolCall) -> DriftVerdict:
        old, new = call.args.get("old", ""), call.args.get("new", "")
        if not SAFE_ASSIGNMENT.match(new):
            return DriftVerdict(drifted=True, score=0.9, reason="code change is not a plain constant assignment")
        if not old or old.split(" = ")[0] != new.split(" = ")[0]:
            return DriftVerdict(drifted=True, score=0.8, reason="code change adds a line instead of updating a constant")
        return DriftVerdict(drifted=False, score=0.1, reason="constant update on planned file")
