"""CapabilityBroker: único camino para ejecutar herramientas.

Determinista, sin LLM. Orden de comprobación en `execute`:
  1. herramienta en el registro del enclave
  2. argumentos esperados
  3. token: presente, firma HMAC, sesión, enclave/herramienta, TTL, uso único
  4. destino: ruta (resolve + symlink + contención + nivel) o host (allowlist) y scope del token
  5. taint: contexto L2 -/-> sumidero de red
  6. monitor de egreso (canaries codificados o fragmentados)
Un canary de system prompt en un sumidero de red se corta antes que todo lo demás: se audita
la decisión y `execute` lanza `SystemPromptLeakageError`. Si el canary de E0/E1 viaja hacia E2
(`transfer` / argumentos de la Aduana) solo se registra `internal_prompt_leakage`, sin bloquear.
Cada llamada y cada decisión se escriben en el log de auditoría JSONL.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .contracts import (
    ACTION_ROUTING, CANARY_PATTERN, ENCLAVE_TOOLS, SYSTEM_CANARY_PATTERN, NETWORK_SINKS, TOOL_OPERATION, VAULT_LEVELS,
    ActionType, AuditEvent, AuditKind, BrokerDecision, CapabilityToken, DefenseConfig, EnclaveId,
    Label, Operation, Plan, PlanStep, ToolCall, ToolName, ToolResult,
)
from .monitors.egress import EgressMonitor, canary_id, find_canaries
from .textutil import read_document
from .tools.web_tools import UrlNotAllowed, net_target, search_target

DEFAULT_TTL_SECONDS = 60.0
TOOL_ARGS: dict[ToolName, frozenset[str]] = {
    ToolName.READ_FILE: frozenset({"path"}),
    ToolName.READ_INBOX: frozenset({"path"}),
    ToolName.WRITE_DIFF: frozenset({"path", "old", "new"}),
    ToolName.FETCH_URL: frozenset({"url"}),
    ToolName.WEB_SEARCH: frozenset({"query"}),
}
# Niveles de bóveda que cada enclave puede tocar por operación.
PATH_POLICY: dict[tuple[EnclaveId, Operation], frozenset[Label]] = {
    (EnclaveId.VAULT_WORKER, Operation.READ): frozenset({Label.L1, Label.L2}),
    (EnclaveId.VAULT_WORKER, Operation.WRITE): frozenset({Label.L1}),
    (EnclaveId.CUSTOMS, Operation.READ): frozenset({Label.L0}),
}
# Herramientas adicionales que un tipo de paso habilita sobre su mismo destino.
STEP_EXTRA_TOOLS: dict[ActionType, frozenset[ToolName]] = {
    ActionType.PATCH_CODE: frozenset({ToolName.READ_FILE}),  # leer el archivo antes de parchearlo
}
SUBRESOURCE_TARGET = re.compile(r"^127\.0\.0\.1:8000/static/[\w.\-]{1,80}$")
_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$", re.IGNORECASE)
_CANARY_RE = re.compile(CANARY_PATTERN)
_SYSTEM_CANARY_RE = re.compile(SYSTEM_CANARY_PATTERN)
# Enclaves cuyo system prompt no debe aparecer en lo que se entrega a la Aduana.
INTERNAL_LEAK_SOURCES = frozenset({EnclaveId.ORCHESTRATOR, EnclaveId.VAULT_WORKER})


class SecurityViolation(Exception):
    """Violación de seguridad que aborta la sesión (fail-closed). Nunca incluye valores de canaries."""

    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(reason)
        self.rule = rule
        self.reason = reason


class SystemPromptLeakageError(SecurityViolation):
    """Un canary de system prompt intentó salir por un sumidero de red (`web_search`, `fetch_url`)."""


def redact(text: str, limit: int = 300) -> str:
    """Trunca y enmascara canaries en claro antes de escribir en el log."""
    masked = _CANARY_RE.sub(lambda m: f"CANARY-<{canary_id(m.group(0))}>", text)
    masked = _SYSTEM_CANARY_RE.sub(lambda m: f"SYS-CANARY-<{canary_id(m.group(0))}>", masked)
    return masked if len(masked) <= limit else masked[:limit] + f"...(+{len(masked) - limit})"


# --------------------------------------------------------------------------- #
# Auditoría
# --------------------------------------------------------------------------- #


class AuditLog:
    """Log JSONL de solo-agregar. Compartible entre sesiones de una misma corrida."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def write(self, session_id: str, kind: AuditKind, *, enclave: Optional[str] = None,
              tool: Optional[str] = None, allowed: Optional[bool] = None,
              rule: Optional[str] = None, **detail: Any) -> AuditEvent:
        with self._lock:
            event = AuditEvent(ts=time.time(), seq=len(self.events), session_id=session_id, kind=kind,
                               enclave=enclave, tool=tool, allowed=allowed, rule=rule, detail=detail)
            self.events.append(event)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(event.model_dump_json() + "\n")
            return event

    def for_session(self, session_id: str) -> list[AuditEvent]:
        return [event for event in self.events if event.session_id == session_id]


# --------------------------------------------------------------------------- #
# Rutas
# --------------------------------------------------------------------------- #


class PathViolation(Exception):
    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(reason)
        self.rule = rule
        self.reason = reason


def _is_reparse_point(path: Path) -> bool:
    """Symlink o junction de Windows (los junctions no siempre reportan is_symlink)."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _normcase(path: Path) -> str:
    return os.path.normcase(str(path))


def _within(child: Path, parent: Path) -> bool:
    child_s, parent_s = _normcase(child), _normcase(parent)
    return child_s == parent_s or child_s.startswith(parent_s.rstrip("\\/") + os.sep)


def resolve_vault_path(raw: str, vault_root: Path) -> tuple[Path, str, Label]:
    """Devuelve (ruta absoluta, relativa posix en minúsculas, etiqueta) o lanza PathViolation.

    No es un filtro de strings: la autoridad es `resolve()` + contención en la raíz.
    """
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise PathViolation("path_invalid", "empty path or NUL byte")
    candidate = raw.strip().replace("\\", "/")
    if candidate.startswith("//"):
        raise PathViolation("path_unc", "UNC or device prefix")
    if candidate.startswith("/") or re.match(r"^[A-Za-z]:", candidate):
        raise PathViolation("path_absolute", "absolute path or drive letter")
    if ":" in candidate:
        raise PathViolation("path_invalid", "alternate data stream or drive reference")
    for part in candidate.split("/"):
        if part in ("", ".", ".."):
            continue
        if part != part.rstrip(". ") or _WINDOWS_RESERVED.match(part):
            raise PathViolation("path_invalid", "trailing dot/space or reserved device name")

    root = vault_root.resolve(strict=True)
    lexical = Path(os.path.normpath(root / candidate))
    if not _within(lexical, root):
        raise PathViolation("path_escape", "path leaves the vault root")
    current = root
    for part in lexical.relative_to(root).parts:
        current = current / part
        if _is_reparse_point(current):
            raise PathViolation("path_symlink", "symlink or junction in path")
    resolved = lexical.resolve()
    if not _within(resolved, root):
        raise PathViolation("path_escape", "resolved path leaves the vault root")
    if _normcase(resolved) != _normcase(lexical):
        raise PathViolation("path_symlink", "resolved path differs from lexical path")
    relative = resolved.relative_to(root).as_posix().casefold()
    label = VAULT_LEVELS.get(relative.split("/", 1)[0])
    if label is None or "/" not in relative:
        raise PathViolation("path_outside_levels", "path is not inside a vault level folder")
    return resolved, relative, label


def normalize_scope_path(raw: str) -> str:
    """Normalización léxica para el scope del token (la validación real ocurre en execute)."""
    return os.path.normpath(raw.strip().replace("\\", "/")).replace("\\", "/").casefold()


# --------------------------------------------------------------------------- #
# Broker
# --------------------------------------------------------------------------- #


class CapabilityBroker:
    def __init__(self, session_id: str, vault_root: Path, audit: AuditLog, config: DefenseConfig,
                 clock: Callable[[], float] = time.time) -> None:
        self.session_id = session_id
        self.vault_root = vault_root
        self.audit = audit
        self.config = config
        self._clock = clock
        self._key = secrets.token_bytes(32)  # clave efímera por sesión; nunca sale del broker
        self._tools: dict[ToolName, Callable[..., str]] = {}
        self._minted: set[str] = set()
        self._used: set[str] = set()
        self._plan: Optional[Plan] = None
        self._context: dict[EnclaveId, Label] = {enclave: Label.L0 for enclave in EnclaveId}
        self._file_labels: dict[str, Label] = {}
        self._call_seq = 0
        self._last_target: Optional[str] = None
        self._system_canaries: dict[str, EnclaveId] = {}  # canary_id -> enclave dueño
        self.canaries = self._load_canaries()
        self.egress = EgressMonitor(self.canaries, coverage_threshold=0.75)
        audit.write(session_id, AuditKind.SESSION_START, config=config.model_dump(),
                    canary_ids=[canary_id(c) for c in self.canaries])

    def _load_canaries(self) -> list[str]:
        found: list[str] = []
        restricted = self.vault_root / "restricted_vault"
        for path in sorted(restricted.rglob("*")) if restricted.is_dir() else []:
            if path.is_file() and not _is_reparse_point(path):
                for canary in find_canaries(read_document(path, strict=False)):
                    if canary not in found:
                        found.append(canary)
        return found

    # -- registro ---------------------------------------------------------- #

    def register_tool(self, tool: ToolName, fn: Callable[..., str]) -> None:
        self._tools[tool] = fn

    def register_system_canary(self, enclave: EnclaveId, canary: str) -> None:
        """Canary del system prompt de un enclave. El monitor de egreso lo vigila en todo sumidero."""
        self._system_canaries[canary_id(canary)] = enclave
        self.egress.add_canary(canary, kind="system")

    def check_internal_leak(self, destination: EnclaveId, text: str, channel: str) -> None:
        """Registra (sin bloquear) si el system prompt de E0/E1 aparece en lo que llega a la Aduana."""
        if destination is not EnclaveId.CUSTOMS or not text:
            return
        for finding in self.egress.scan(text):
            owner = self._system_canaries.get(finding.canary_id)
            if finding.kind == "system" and owner in INTERNAL_LEAK_SOURCES:
                self.audit.write(self.session_id, AuditKind.INTERNAL_PROMPT_LEAKAGE, enclave=owner.value,
                                 allowed=True, rule="internal_prompt_leakage", destination=destination.value,
                                 channel=channel, canary_id=finding.canary_id, encoding=finding.encoding)

    def new_call_id(self) -> str:
        self._call_seq += 1
        return f"c{self._call_seq:04d}"

    # -- plan y tokens ----------------------------------------------------- #

    def register_plan(self, plan: Plan) -> None:
        """Fija el plan. Con `frozen`, no se puede volver a registrar ni ampliar."""
        if self._plan is not None and self._plan.frozen:
            raise PermissionError("plan is frozen")
        self._plan = plan
        self.audit.write(self.session_id, AuditKind.PLAN_FIXED, enclave=EnclaveId.ORCHESTRATOR.value,
                         frozen=plan.frozen,
                         steps=[{"step_id": s.step_id, "action": s.action.value,
                                 "target": redact(s.target), "origin": s.origin} for s in plan.steps])

    def _sign(self, token: CapabilityToken) -> str:
        return hmac.new(self._key, token.signing_payload(), hashlib.sha256).hexdigest()

    def _mint(self, enclave: EnclaveId, tool: ToolName, scope: str, step_id: Optional[str],
              ttl: float, single_use: bool) -> CapabilityToken:
        unsigned = CapabilityToken(token_id="t_" + secrets.token_hex(6), session_id=self.session_id,
                                   enclave=enclave, tool=tool, operation=TOOL_OPERATION[tool], scope=scope,
                                   expires_at=self._clock() + ttl, single_use=single_use, step_id=step_id)
        token = unsigned.model_copy(update={"signature": self._sign(unsigned)})
        self._minted.add(token.token_id)
        self.audit.write(self.session_id, AuditKind.TOKEN_MINTED, enclave=enclave.value, tool=tool.value,
                         token_id=token.token_id, scope=redact(scope), step_id=step_id,
                         single_use=single_use, ttl=ttl)
        return token

    def mint_for_step(self, step: PlanStep, ttl: float = DEFAULT_TTL_SECONDS,
                      tool: Optional[ToolName] = None) -> Optional[CapabilityToken]:
        """Emite el token de un paso. Con plan congelado, el paso debe ser idéntico al registrado."""
        enclave, default_tool, _ = ACTION_ROUTING[step.action]
        tool = tool or default_tool
        if tool is not default_tool and tool not in STEP_EXTRA_TOOLS.get(step.action, frozenset()):
            self.audit.write(self.session_id, AuditKind.BROKER_DECISION, enclave=enclave.value,
                             tool=tool.value, allowed=False, rule="tool_not_in_step", step_id=step.step_id)
            return None
        if self._plan is not None and self._plan.frozen and step not in self._plan.steps:
            self.audit.write(self.session_id, AuditKind.BROKER_DECISION, enclave=enclave.value,
                             tool=tool.value, allowed=False, rule="step_not_in_plan",
                             step_id=step.step_id, target=redact(step.target))
            return None
        try:
            scope = self._scope_for(step.action, step.target)
        except UrlNotAllowed as exc:
            self.audit.write(self.session_id, AuditKind.BROKER_DECISION, enclave=enclave.value,
                             tool=tool.value, allowed=False, rule="host_not_allowed",
                             step_id=step.step_id, target=redact(step.target), reason=str(exc))
            return None
        return self._mint(enclave, tool, scope, step.step_id, ttl, single_use=True)

    def mint_subresource(self, step: PlanStep, url: str, ttl: float = 15.0) -> Optional[CapabilityToken]:
        """Token para un sub-recurso estático (imagen) de una página ya planeada. Solo /static/."""
        if step.action is not ActionType.FETCH_URL:
            return None
        try:
            target = net_target(url)
        except UrlNotAllowed:
            target = ""
        if not SUBRESOURCE_TARGET.match(target):
            self.audit.write(self.session_id, AuditKind.BROKER_DECISION, enclave=EnclaveId.CUSTOMS.value,
                             tool=ToolName.FETCH_URL.value, allowed=False, rule="subresource_not_static",
                             step_id=step.step_id, target=redact(url))
            return None
        return self._mint(EnclaveId.CUSTOMS, ToolName.FETCH_URL, target, step.step_id, ttl, single_use=True)

    @staticmethod
    def _scope_for(action: ActionType, target: str) -> str:
        if action is ActionType.FETCH_URL:
            return net_target(target)
        if action is ActionType.WEB_SEARCH:
            return search_target(target)
        return normalize_scope_path(target)

    # -- taint ------------------------------------------------------------- #

    def context_label(self, enclave: EnclaveId) -> Label:
        return self._context[enclave]

    def note_exposure(self, enclave: EnclaveId, label: Label, reason: str) -> None:
        """El contexto de un enclave sube a `label` (nunca baja en la sesión)."""
        if label > self._context[enclave]:
            self._context[enclave] = label
            self.audit.write(self.session_id, AuditKind.EXPOSURE, enclave=enclave.value,
                             label=label.name, reason=reason)

    def transfer(self, source: EnclaveId, destination: EnclaveId, reason: str, content: str = "") -> None:
        """Mensaje entre enclaves: el destino hereda la etiqueta del origen.

        `content` es lo que viaja en el mensaje; se revisa por fuga interna de system prompt.
        """
        self.check_internal_leak(destination, content, f"dispatch: {reason}")
        self.note_exposure(destination, self._context[source], f"message from {source.value}: {reason}")

    # -- ejecución --------------------------------------------------------- #

    def execute(self, call: ToolCall) -> ToolResult:
        enclave = call.enclave
        self.audit.write(self.session_id, AuditKind.TOOL_CALL, enclave=enclave.value, tool=call.tool,
                         call_id=call.call_id, token_id=call.token.token_id if call.token else None,
                         args={key: redact(value) for key, value in call.args.items()},
                         args_sha256=hashlib.sha256(json.dumps(call.args, sort_keys=True).encode()).hexdigest())
        self._last_target = None
        for value in call.args.values():
            self.check_internal_leak(enclave, value, f"tool_call {call.tool}")
        decision, runner, label = self._decide(call)
        output: Optional[str] = None
        if decision.allowed and runner is not None:
            try:
                output = runner()
            except Exception as exc:  # la herramienta falló; no es una decisión de seguridad
                decision = BrokerDecision(allowed=False, rule="tool_error", reason=f"{type(exc).__name__}: {exc}")
                label = None
        if decision.allowed and label is not None:
            self.note_exposure(enclave, label, f"result of {call.tool}")
        self.audit.write(self.session_id, AuditKind.BROKER_DECISION, enclave=enclave.value, tool=call.tool,
                         allowed=decision.allowed, rule=decision.rule, call_id=call.call_id,
                         reason=decision.reason, step_id=call.token.step_id if call.token else None,
                         target=redact(self._last_target) if self._last_target else None,
                         label=label.name if decision.allowed and label is not None else None)
        if decision.rule == "system_canary_egress":
            raise SystemPromptLeakageError(decision.rule, f"{enclave.value}: {decision.reason} via {call.tool}")
        return ToolResult(call_id=call.call_id, decision=decision, output=output,
                          label=label if decision.allowed else None)

    def _deny(self, rule: str, reason: str) -> tuple[BrokerDecision, None, None]:
        return BrokerDecision(allowed=False, rule=rule, reason=reason), None, None

    def _decide(self, call: ToolCall) -> tuple[BrokerDecision, Optional[Callable[[], str]], Optional[Label]]:
        enclave = call.enclave
        # 1. registro disjunto por enclave
        try:
            tool = ToolName(call.tool)
        except ValueError:
            return self._deny("tool_unknown", "tool does not exist")
        is_sink = tool in NETWORK_SINKS
        # El monitor de egreso observa SIEMPRE los sumideros, aunque otra regla niegue antes:
        # así los fragmentos de intentos fallidos también cuentan.
        findings = []
        if self.config.egress_monitor and is_sink:
            for value in call.args.values():
                findings.extend(self.egress.observe(value))
            if findings:
                self.audit.write(self.session_id, AuditKind.EGRESS_ALERT, enclave=enclave.value, tool=tool.value,
                                 call_id=call.call_id, findings=[f.model_dump() for f in findings])
            # Un canary de system prompt en un sumidero es una fuga confirmada: se bloquea antes de
            # cualquier otra regla (aunque el token o el host también fallen) y `execute` lanza la excepción.
            if any(finding.kind == "system" for finding in findings):
                return self._deny("system_canary_egress", "system prompt canary in network sink")
        if tool not in ENCLAVE_TOOLS[enclave] or tool not in self._tools:
            return self._deny("tool_not_in_registry", f"{tool.value} is not registered for {enclave.value}")
        # 2. argumentos
        if set(call.args) != TOOL_ARGS[tool]:
            return self._deny("bad_arguments", f"expected {sorted(TOOL_ARGS[tool])}")
        # 3. token
        token = call.token
        if token is None:
            return self._deny("token_missing", "no capability token")
        if token.token_id not in self._minted or not hmac.compare_digest(self._sign(token), token.signature):
            return self._deny("token_bad_signature", "signature does not verify")
        if token.session_id != self.session_id or call.session_id != self.session_id:
            return self._deny("token_wrong_session", "token belongs to another session")
        if token.enclave is not enclave or token.tool is not tool or token.operation is not TOOL_OPERATION[tool]:
            return self._deny("token_scope_mismatch", "token was issued for another enclave or tool")
        if self._clock() >= token.expires_at:
            return self._deny("token_expired", "TTL elapsed")
        if token.single_use and token.token_id in self._used:
            return self._deny("token_reused", "single-use token already spent")
        # 4. destino
        fn = self._tools[tool]
        if is_sink:
            try:
                target = net_target(call.args["url"]) if tool is ToolName.FETCH_URL else search_target(call.args["query"])
            except UrlNotAllowed as exc:
                return self._deny("host_not_allowed", str(exc))
            self._last_target = target
            if not _scope_matches(target, token.scope):
                return self._deny("token_scope_mismatch", "network target outside token scope")
            self._used.add(token.token_id)
            # 5. taint
            if self.config.taint and self._context[enclave] >= Label.L2:
                return self._deny("taint_l2_to_network", "enclave context carries L2 data")
            # 6. egreso (los canaries de system prompt ya se cortaron arriba)
            if findings:
                return self._deny("egress_canary_detected", f"{len(findings)} canary finding(s)")
            return BrokerDecision(allowed=True, rule="allow"), (lambda: fn(**call.args)), Label.L0

        try:
            resolved, relative, dir_label = resolve_vault_path(call.args["path"], self.vault_root)
        except PathViolation as violation:
            return self._deny(violation.rule, violation.reason)
        operation = TOOL_OPERATION[tool]
        self._last_target = relative
        if dir_label not in PATH_POLICY.get((enclave, operation), frozenset()):
            return self._deny("path_level_not_allowed",
                              f"{enclave.value} may not {operation.value} {dir_label.name}")
        if not _scope_matches(relative, token.scope):
            return self._deny("token_scope_mismatch", "path outside token scope")
        self._used.add(token.token_id)
        if operation is Operation.WRITE:
            written_label = max(dir_label, self._context[enclave])
            extra = {key: value for key, value in call.args.items() if key != "path"}

            def run_write() -> str:
                result = fn(path=resolved, **extra)
                self._file_labels[relative] = Label(written_label)
                return result

            return BrokerDecision(allowed=True, rule="allow"), run_write, None
        if not resolved.is_file():
            return self._deny("path_not_found", "file does not exist")
        label = Label(max(dir_label, self._file_labels.get(relative, Label.L0)))
        return BrokerDecision(allowed=True, rule="allow"), (lambda: fn(path=resolved)), label


def _scope_matches(target: str, scope: str) -> bool:
    return target == scope or fnmatch.fnmatchcase(target, scope)
