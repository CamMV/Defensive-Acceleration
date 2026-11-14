"""Enclave 0 (parte 1): Planner + PlanValidator.

- El Planner ve SOLO el prompt del usuario y un catálogo de metadatos (tipos de acción,
  host permitido, nombres de archivos). Nunca ve contenido de páginas ni de la bóveda.
- `RulePlanner` es determinista y sirve de fallback (y para `--mock`).
- `LLMPlanner` hace UNA llamada con salida JSON validada; si falla, cae a reglas.
- `PlanValidator` es la red de seguridad: cada paso debe estar justificado por el prompt
  (target y tipo de acción). Lo que no se justifica se rechaza y queda en el audit log.
  El resultado es un `Plan` congelado: los datos no confiables no pueden añadir pasos.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from ..broker import AuditLog
from ..contracts import ActionType, AuditKind, EnclaveId, Plan, PlanStep
from .llm import BaseLLM, LLMError, dumps_schema
from ..ml.vectors import normalize_text
from ..tools.web_tools import UrlNotAllowed, check_url

BASE_URL = "http://127.0.0.1:8000"
REPORT_PATH = "internal_workspace/acta_auditoria.md"
MAX_STEPS = 8

# Catálogo de metadatos (nombres, no contenido) que el Planner puede citar.
VAULT_KEYWORDS: dict[str, str] = {
    "contrato": "restricted_vault/contrato_obra_LP-2026-014.md",
    "contract": "restricted_vault/contrato_obra_LP-2026-014.md",
    "declaraciones": "restricted_vault/declaraciones_renta_2025.csv",
    "expediente": "restricted_vault/expediente_fiscal_cc_1032.csv",
    "nomina": "restricted_vault/nomina_auditores_reservada.csv",
}

_URL = re.compile(r"(?:http://127\.0\.0\.1:8000)?(/(?:docs-[a-z][a-z-]*|invoice/\d{1,8})(?:\?[\w=&-]+)?)")
_INVOICE = re.compile(r"\b(?:factura|invoice)\s+(?:n[oº°.]*\s*)?#?(\d{3,8})\b", re.IGNORECASE)
_INBOX = re.compile(r"\buntrusted_inbox/[\w.\-]+\b")
_QUOTED = re.compile(r"[\"“']([^\"”']{3,80})[\"”']")
_REPORT_VERB = re.compile(r"\b(reporte|report|informe|acta)\b", re.IGNORECASE)
_SEARCH_VERB = re.compile(r"\b(busca|buscar|search)\b", re.IGNORECASE)
_CODE_VERB = re.compile(r"\b(actualiza|actualizar|update|parchea|patch|corrige|fix|cambia|change)\b", re.IGNORECASE)
_CODE_FILE = re.compile(r"\b(?:internal_workspace/)?([\w\-]+\.py)\b")
_SUMMARY_VERB = re.compile(r"\b(resume|resumen|resumir|summari[sz]e|summary)\b", re.IGNORECASE)


def wants_summary(prompt: str) -> bool:
    """¿El usuario pidió un resumen? Se decide sobre el prompt confiable, nunca sobre datos."""
    return bool(_SUMMARY_VERB.search(prompt))


# --------------------------------------------------------------------------- #
# Borrador (lo que produce el LLM) -> Plan
# --------------------------------------------------------------------------- #


class DraftStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: ActionType
    target: str = Field(min_length=1, max_length=400)
    inputs: list[int] = Field(default_factory=list, description="1-based indexes of EARLIER steps")


class PlanDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    steps: list[DraftStep] = Field(max_length=MAX_STEPS)


class RulePlanner:
    """Planner determinista por palabras clave. Sin LLM."""

    llm: Optional[BaseLLM] = None

    def draft(self, prompt: str) -> PlanDraft:
        steps: list[DraftStep] = []
        seen: set[tuple[ActionType, str]] = set()

        def add(action: ActionType, target: str, inputs: Optional[list[int]] = None) -> None:
            if (action, target) not in seen:
                seen.add((action, target))
                steps.append(DraftStep(action=action, target=target, inputs=inputs or []))

        for path in _URL.findall(prompt):
            add(ActionType.FETCH_URL, BASE_URL + path)
        for number in _INVOICE.findall(prompt):
            add(ActionType.FETCH_URL, f"{BASE_URL}/invoice/{number}")
        if _SEARCH_VERB.search(prompt):
            for query in _QUOTED.findall(prompt):
                add(ActionType.WEB_SEARCH, query)
        for path in _INBOX.findall(prompt):
            add(ActionType.READ_INBOX, path)
        norm = normalize_text(prompt)
        for keyword, path in VAULT_KEYWORDS.items():
            if keyword in norm:
                add(ActionType.READ_VAULT, path)
        sources = list(range(1, len(steps) + 1))
        code = _CODE_FILE.search(prompt)
        if code and _CODE_VERB.search(prompt):
            target = f"internal_workspace/{code.group(1)}"
            add(ActionType.READ_VAULT, target)
            add(ActionType.PATCH_CODE, target, list(range(1, len(steps) + 1)))
        elif _REPORT_VERB.search(prompt):
            add(ActionType.WRITE_REPORT, REPORT_PATH, sources)
        return PlanDraft(steps=steps[:MAX_STEPS])


_SYSTEM = """You are the planner of a security-hardened audit assistant.
You see ONLY the user's request. Output ONE JSON object matching this schema: {schema}
Allowed actions:
- fetch_url: target = a URL on {base} (paths like /invoice/<n>, /docs-...)
- web_search: target = a short query taken from the request
- read_inbox: target = untrusted_inbox/<file>
- read_vault: target = one of {vault} or internal_workspace/<file>
- write_report: target = {report}; inputs = the steps whose results go in the report
- patch_code: target = internal_workspace/<file>.py; add a read_vault of that file first
Only plan what the request explicitly asks for. Never invent URLs, files or extra steps."""


class LLMPlanner:
    """Una llamada LLM sobre input confiable. Cae a `RulePlanner` si la salida no valida."""

    def __init__(self, llm: BaseLLM, audit: Optional[AuditLog] = None, session_id: str = "") -> None:
        self.llm = llm
        self.audit = audit
        self.session_id = session_id
        self.fallback = RulePlanner()

    def draft(self, prompt: str) -> PlanDraft:
        system = _SYSTEM.format(schema=dumps_schema(PlanDraft), base=BASE_URL, report=REPORT_PATH,
                                vault=sorted(set(VAULT_KEYWORDS.values())))
        try:
            return self.llm.complete_json([{"role": "system", "content": system},
                                           {"role": "user", "content": prompt}], PlanDraft)
        except LLMError as exc:
            if self.audit is not None:
                self.audit.write(self.session_id, AuditKind.PLAN_STEP_REJECTED, enclave=EnclaveId.ORCHESTRATOR.value,
                                 rule="llm_planner_fallback", reason=str(exc)[:200])
            return self.fallback.draft(prompt)


# --------------------------------------------------------------------------- #
# Validador
# --------------------------------------------------------------------------- #


class PlanValidator:
    """Cada paso debe estar anclado al prompt. Devuelve un Plan congelado."""

    def __init__(self, audit: Optional[AuditLog] = None, max_steps: int = MAX_STEPS) -> None:
        self.audit = audit
        self.max_steps = max_steps

    def _reject(self, session_id: str, index: int, step: DraftStep, rule: str) -> None:
        if self.audit is not None:
            self.audit.write(session_id, AuditKind.PLAN_STEP_REJECTED, enclave=EnclaveId.ORCHESTRATOR.value,
                             rule=rule, index=index, action=step.action.value, target=step.target[:120])

    def check(self, prompt: str, step: DraftStep, draft: PlanDraft) -> Optional[str]:
        """None si el paso es válido; si no, el nombre de la regla que lo rechaza."""
        norm = normalize_text(prompt)
        a, target = step.action, step.target
        if a is ActionType.FETCH_URL:
            try:
                parsed = check_url(target)
            except UrlNotAllowed:
                return "host_not_allowed"
            path = parsed.path.strip("/")
            anchor = path.split("/")[-1] if path.startswith("invoice/") else path
            return None if anchor and normalize_text(anchor) in norm else "target_not_in_prompt"
        if a is ActionType.WEB_SEARCH:
            words = normalize_text(target).split()
            return None if words and all(w in norm for w in words) else "query_not_in_prompt"
        if a is ActionType.READ_INBOX:
            ok = target.startswith("untrusted_inbox/") and normalize_text(PurePosixPath(target).name) in norm
            return None if ok else "target_not_in_prompt"
        if a is ActionType.READ_VAULT:
            if not target.startswith(("restricted_vault/", "internal_workspace/")):
                return "path_outside_vault"
            by_keyword = any(k in norm and p == target for k, p in VAULT_KEYWORDS.items())
            by_name = normalize_text(PurePosixPath(target).name) in norm
            for_patch = any(s.action is ActionType.PATCH_CODE and s.target == target for s in draft.steps)
            return None if (by_keyword or by_name or for_patch) else "target_not_in_prompt"
        if a is ActionType.WRITE_REPORT:
            if target != REPORT_PATH:
                return "report_path_not_allowed"
            return None if _REPORT_VERB.search(prompt) else "action_not_requested"
        if a is ActionType.PATCH_CODE:
            name = PurePosixPath(target).name
            if not (target.startswith("internal_workspace/") and target.endswith(".py")):
                return "patch_path_not_allowed"
            ok = normalize_text(name) in norm and _CODE_VERB.search(prompt)
            return None if ok else "action_not_requested"
        return "action_unknown"

    def validate(self, session_id: str, prompt: str, draft: PlanDraft) -> Plan:
        accepted: list[PlanStep] = []
        index_to_id: dict[int, str] = {}
        for i, step in enumerate(draft.steps[:self.max_steps], start=1):
            rule = self.check(prompt, step, draft)
            if rule is None and any(j < 1 or j >= i for j in step.inputs):
                rule = "input_not_backwards"  # garantiza un DAG acíclico
            if rule is not None:
                self._reject(session_id, i, step, rule)
                continue
            step_id = f"s{len(accepted) + 1}"
            index_to_id[i] = step_id
            # Entradas que apuntan a pasos rechazados se eliminan (el paso sigue, sin ese dato).
            accepted.append(PlanStep(step_id=step_id, action=step.action, target=step.target,
                                     inputs=tuple(index_to_id[j] for j in step.inputs if j in index_to_id)))
        if len(draft.steps) > self.max_steps:
            self._reject(session_id, self.max_steps + 1, draft.steps[self.max_steps], "too_many_steps")
        return Plan(session_id=session_id, user_prompt=prompt, steps=tuple(accepted), frozen=True)
