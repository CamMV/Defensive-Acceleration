"""Enclave 1 — Trabajador de Bóveda (lee L1/L2, escribe L1; SIN herramientas de red).

- Lo que lee de la bóveda se queda en su memoria privada (`_memory`). Al Orquestador solo
  le devuelve un `WorkerReceipt` (ok/regla/bytes/sha256): nunca contenido.
- Nunca recibe texto libre no confiable: de la Aduana solo le llegan `ExtractedRecord`
  (campos tipados + handles). Los handles se citan por referencia en el reporte.
- El reporte se arma con una plantilla determinista (sin LLM). Minimización de datos: del
  contrato solo sale el veredicto del cruce (COINCIDE / NO COINCIDE), no su contenido.
- `patch_code`: estrategia determinista para constantes de versión a partir de un campo
  `version` validado como semver. Si no aplica y hay un LLM de parches configurado, este
  solo ve el prompt del usuario y el archivo L1 (nunca datos L0). Toda propuesta pasa por
  `drift_check` antes de escribir.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import PurePosixPath
from typing import Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..broker import CapabilityBroker
from ..contracts import (
    ActionType, AuditKind, CapabilityToken, DocType, DriftVerdict, EnclaveId, ExtractedRecord, PlanStep,
    TextField, ToolCall, ToolName, WorkerReceipt,
)
from .llm import BaseLLM, LLMError, dumps_schema
from .quarantine import QuarantineStore, amounts_in, defang
from .customs import StepDenied

DriftCheck = Callable[[str, str, str, str], DriftVerdict]  # (goal, path, old, new) -> veredicto
_VERSION_CONST = re.compile(
    r'^(?P<lhs>[ \t]*(?P<name>[A-Z_]*VERSION[A-Z_]*)[ \t]*=[ \t]*)(?P<q>["\'])(?P<v>\d{1,4}\.\d{1,4}\.\d{1,4})(?P=q)',
    re.MULTILINE)


class PatchDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    old: str = Field(min_length=1, max_length=2000)
    new: str = Field(max_length=2000)


class VaultWorker:
    enclave = EnclaveId.VAULT_WORKER

    def __init__(self, broker: CapabilityBroker, store: QuarantineStore, patch_llm: Optional[BaseLLM] = None,
                 drift_check: Optional[DriftCheck] = None) -> None:
        self.broker = broker
        self.store = store
        self.patch_llm = patch_llm
        self.drift_check = drift_check
        self._memory: dict[str, tuple[str, str]] = {}  # step_id -> (ruta, contenido); nunca sale

    # -- broker ------------------------------------------------------------- #

    def _call(self, tool: ToolName, args: dict[str, str], token: Optional[CapabilityToken], step_id: str) -> str:
        result = self.broker.execute(ToolCall(call_id=self.broker.new_call_id(), session_id=self.broker.session_id,
                                              enclave=self.enclave, tool=tool.value, args=args, token=token))
        if not result.decision.allowed or result.output is None:
            raise StepDenied(step_id, result.decision.rule)
        return result.output

    def _receipt(self, step: PlanStep, output: str) -> WorkerReceipt:
        meta = json.loads(output)
        return WorkerReceipt(step_id=step.step_id, ok=True, bytes_written=meta["bytes_written"], sha256=meta["sha256"])

    # -- acciones ----------------------------------------------------------- #

    def read(self, step: PlanStep, token: Optional[CapabilityToken]) -> WorkerReceipt:
        content = self._call(ToolName.READ_FILE, {"path": step.target}, token, step.step_id)
        self._memory[step.step_id] = (step.target, content)
        return WorkerReceipt(step_id=step.step_id, ok=True)

    def write_report(self, step: PlanStep, token: Optional[CapabilityToken], prompt: str,
                     records: list[ExtractedRecord], vault_steps: list[str],
                     flagged_steps: frozenset[str] = frozenset()) -> WorkerReceipt:
        section = self.render_report(prompt, records, vault_steps, flagged_steps)
        out = self._call(ToolName.WRITE_DIFF, {"path": step.target, "old": "", "new": section}, token, step.step_id)
        return self._receipt(step, out)

    def render_report(self, prompt: str, records: list[ExtractedRecord], vault_steps: list[str],
                      flagged_steps: frozenset[str] = frozenset()) -> str:
        lines = [f"\n### Hallazgo {self.broker.session_id} · {dt.date.today().isoformat()}",
                 f"Solicitud: {defang(' '.join(prompt.split()))[:300]}", ""]
        vault_docs = [self._memory[s] for s in vault_steps if s in self._memory]
        for rec in records:
            lines.append(f"- {rec.step_id} · {rec.doc_type.value}" + _fields(rec))
            if rec.doc_type is DocType.INVOICE and rec.total_amount is not None:
                for path, content in vault_docs:
                    verdict = "COINCIDE" if rec.total_amount in amounts_in(content) else "NO COINCIDE"
                    lines.append(f"  - Cruce con {PurePosixPath(path).name}: {verdict}")
            if rec.dropped_fields:
                lines.append(f"  - Campos descartados (procedencia/esquema): {', '.join(rec.dropped_fields)}")
            if rec.step_id in flagged_steps:
                lines.append("  - Alerta: posible prompt injection en la fuente (contenido en cuarentena)")
            summary = rec.text_handles.get(TextField.SUMMARY)
            if summary is not None:
                lines.append("  - Resumen del lector en cuarentena (no verificado, ningún LLM con permisos lo leyó):")
                lines += ["    " + line for line in self.store.render_safe(summary).splitlines()]
            for field, handle in rec.text_handles.items():
                if field is TextField.SUMMARY:
                    continue
                meta = self.store.meta(handle)
                lines.append(f"  - Contenido externo en cuarentena, no leído por ningún LLM: "
                             f"{handle} ({field.value}, {meta.length} caracteres)")
        if not records:
            lines.append("- Sin datos externos en esta solicitud.")
        return "\n".join(lines)

    def patch_code(self, step: PlanStep, token: Optional[CapabilityToken], prompt: str,
                   records: list[ExtractedRecord], read_step: Optional[str]) -> WorkerReceipt:
        if read_step is None or read_step not in self._memory or self._memory[read_step][0] != step.target:
            raise StepDenied(step.step_id, "patch_requires_read")
        current = self._memory[read_step][1]
        draft = self._version_patch(prompt, current, records) or self._llm_patch(prompt, step.target, current)
        if draft is None:
            raise StepDenied(step.step_id, "no_patch_strategy")
        if self.drift_check is not None:
            verdict = self.drift_check(prompt, step.target, draft.old, draft.new)
            self.broker.audit.write(self.broker.session_id, AuditKind.DRIFT_CHECK, enclave=self.enclave.value,
                                    step_id=step.step_id, allowed=not verdict.drifted, rule="intent_drift",
                                    score=verdict.score, reason=verdict.reason)
            if verdict.drifted:
                raise StepDenied(step.step_id, "intent_drift")
        out = self._call(ToolName.WRITE_DIFF, {"path": step.target, "old": draft.old, "new": draft.new},
                         token, step.step_id)
        return self._receipt(step, out)

    @staticmethod
    def _version_patch(prompt: str, current: str, records: list[ExtractedRecord]) -> Optional[PatchDraft]:
        versions = [r.version for r in records if r.version]
        if not versions:
            return None
        matches = list(_VERSION_CONST.finditer(current))
        named = [m for m in matches if m.group("name").casefold() in prompt.casefold()]
        target = (named or matches or [None])[0]
        if target is None or target.group("v") == versions[0]:
            return None
        old = target.group(0)
        return PatchDraft(old=old, new=f'{target.group("lhs")}{target.group("q")}{versions[0]}{target.group("q")}')

    def _llm_patch(self, prompt: str, path: str, current: str) -> Optional[PatchDraft]:
        if self.patch_llm is None:
            return None
        system = ("You edit one Python file. Return ONE JSON object " + dumps_schema(PatchDraft) +
                  ": `old` must be an exact unique snippet of the file, `new` its replacement. "
                  "Make only the change the user asked for.")
        try:
            return self.patch_llm.complete_json([
                {"role": "system", "content": system},
                {"role": "user", "content": f"Request: {prompt}\n\nFile {path}:\n{current}"}], PatchDraft)
        except LLMError:
            return None


def _fields(rec: ExtractedRecord) -> str:
    parts = []
    if rec.invoice_id:
        parts.append(rec.invoice_id)
    if rec.issue_date:
        parts.append(rec.issue_date.isoformat())
    if rec.total_amount is not None:
        parts.append(f"{rec.total_amount} {rec.currency.value if rec.currency else ''}".strip())
    if rec.version:
        parts.append(f"versión {rec.version}")
    if rec.image_count:
        parts.append(f"{rec.image_count} imagen(es)")
    return (" · " + " · ".join(parts)) if parts else ""
