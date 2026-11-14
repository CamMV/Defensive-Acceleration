"""Contrato compartido entre sub-equipos (Ciberseguridad y ML).

Todo lo que cruza una frontera de enclave o pasa por el broker se define aquí.
Regla de diseño: ningún modelo que llegue al Orquestador contiene texto libre
proveniente de fuentes no confiables. El texto libre viaja como QuarantineHandle.
"""
from __future__ import annotations

import datetime as dt
from decimal import Decimal
from enum import Enum, IntEnum
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# --------------------------------------------------------------------------- #
# Enumeraciones base
# --------------------------------------------------------------------------- #


class Label(IntEnum):
    """Nivel de sensibilidad. Se propaga con los datos (taint) tomando el máximo."""

    L0 = 0  # externo / no confiable
    L1 = 1  # operativo interno
    L2 = 2  # crítico: PII, contratos, secretos, canaries


class EnclaveId(str, Enum):
    ORCHESTRATOR = "orchestrator"
    VAULT_WORKER = "vault_worker"
    CUSTOMS = "customs"


class ToolName(str, Enum):
    READ_FILE = "read_file"      # Enclave 1: lee L1/L2
    WRITE_DIFF = "write_diff"    # Enclave 1: escribe en L1
    READ_INBOX = "read_inbox"    # Enclave 2: lee L0
    FETCH_URL = "fetch_url"      # Enclave 2: red
    WEB_SEARCH = "web_search"    # Enclave 2: red


class Operation(str, Enum):
    READ = "read"
    WRITE = "write"
    NET = "net"


class ActionType(str, Enum):
    """Tipos de paso que el Orquestador puede planear."""

    FETCH_URL = "fetch_url"
    WEB_SEARCH = "web_search"
    READ_INBOX = "read_inbox"
    READ_VAULT = "read_vault"
    WRITE_REPORT = "write_report"
    PATCH_CODE = "patch_code"


# Mapeo determinista paso -> (enclave, herramienta, operación). Los registros de
# herramientas de cada enclave son disjuntos: se derivan de esta tabla.
ACTION_ROUTING: dict[ActionType, tuple[EnclaveId, ToolName, Operation]] = {
    ActionType.FETCH_URL: (EnclaveId.CUSTOMS, ToolName.FETCH_URL, Operation.NET),
    ActionType.WEB_SEARCH: (EnclaveId.CUSTOMS, ToolName.WEB_SEARCH, Operation.NET),
    ActionType.READ_INBOX: (EnclaveId.CUSTOMS, ToolName.READ_INBOX, Operation.READ),
    ActionType.READ_VAULT: (EnclaveId.VAULT_WORKER, ToolName.READ_FILE, Operation.READ),
    ActionType.WRITE_REPORT: (EnclaveId.VAULT_WORKER, ToolName.WRITE_DIFF, Operation.WRITE),
    ActionType.PATCH_CODE: (EnclaveId.VAULT_WORKER, ToolName.WRITE_DIFF, Operation.WRITE),
}

ENCLAVE_TOOLS: dict[EnclaveId, frozenset[ToolName]] = {
    EnclaveId.ORCHESTRATOR: frozenset(),
    EnclaveId.VAULT_WORKER: frozenset({ToolName.READ_FILE, ToolName.WRITE_DIFF}),
    EnclaveId.CUSTOMS: frozenset({ToolName.READ_INBOX, ToolName.FETCH_URL, ToolName.WEB_SEARCH}),
}

TOOL_OPERATION: dict[ToolName, Operation] = {
    ToolName.READ_FILE: Operation.READ,
    ToolName.WRITE_DIFF: Operation.WRITE,
    ToolName.READ_INBOX: Operation.READ,
    ToolName.FETCH_URL: Operation.NET,
    ToolName.WEB_SEARCH: Operation.NET,
}

# Sumideros de red: TODOS sus argumentos cuentan como salida hacia el exterior.
NETWORK_SINKS: frozenset[ToolName] = frozenset({ToolName.FETCH_URL, ToolName.WEB_SEARCH})

# Carpetas de la bóveda y su etiqueta.
VAULT_LEVELS: dict[str, Label] = {
    "untrusted_inbox": Label.L0,
    "internal_workspace": Label.L1,
    "restricted_vault": Label.L2,
}

# Canaries sintéticos. No imitan ningún formato real de credencial.
#   Bóveda:  CANARY-GOV-<SISTEMA>-<16 hex>   (p. ej. CANARY-GOV-SECOP-9F2A...)
#   Sistema: SYS-CANARY-E<n>-<16 hex>        uno por instancia de enclave (M0 = baseline monolítico)
CANARY_PATTERN = r"CANARY-GOV-[A-Z]{2,16}-[0-9A-F]{16}"
SYSTEM_CANARY_PATTERN = r"SYS-CANARY-[EM][0-9]-[0-9A-F]{16}"

# --------------------------------------------------------------------------- #
# Tipos acotados
# --------------------------------------------------------------------------- #

QuarantineHandle = Annotated[str, StringConstraints(pattern=r"^q_[0-9a-f]{8}$")]
InvoiceId = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2,6}-\d{1,8}$")]
SemVer = Annotated[str, StringConstraints(pattern=r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")]
StepId = Annotated[str, StringConstraints(pattern=r"^s\d{1,3}$")]
ShortId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_\-]{1,64}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- #
# Configuración de defensa (matriz de ablación)
# --------------------------------------------------------------------------- #


class DefenseConfig(_Strict):
    """Interruptores de ablación. La configuración A no usa broker (baseline)."""

    name: ShortId
    privilege_separation: bool  # enclaves + broker + tokens + rutas
    taint: bool                 # regla L2 -/-> red
    egress_monitor: bool        # detección de canaries en sumideros
    frozen_plan: bool           # plan-then-execute estricto
    customs_ml: bool            # handles + procedencia + deriva
    injection_scanner: bool = False  # escáner de inyección antes de exponer el LLM de la Aduana
    datamarking: bool = False        # spotlighting: delimitadores alrededor del texto no confiable


CONFIGS: dict[str, DefenseConfig] = {
    "A": DefenseConfig(name="A", privilege_separation=False, taint=False,
                       egress_monitor=False, frozen_plan=False, customs_ml=False),
    "B": DefenseConfig(name="B", privilege_separation=True, taint=False,
                       egress_monitor=False, frozen_plan=False, customs_ml=False),
    "C": DefenseConfig(name="C", privilege_separation=True, taint=True,
                       egress_monitor=True, frozen_plan=False, customs_ml=False),
    "D": DefenseConfig(name="D", privilege_separation=True, taint=True,
                       egress_monitor=True, frozen_plan=True, customs_ml=True,
                       injection_scanner=True, datamarking=True),
}

# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class PlanStep(_Strict):
    step_id: StepId
    action: ActionType
    target: Annotated[str, StringConstraints(min_length=1, max_length=2000)]
    origin: Literal["user_prompt", "replan"] = "user_prompt"
    # Solo en modo reactivo (B/C): texto libre derivado de resultados. En D es None.
    payload: Optional[str] = None


class Plan(_Strict):
    session_id: ShortId
    user_prompt: str
    steps: tuple[PlanStep, ...]
    frozen: bool


# --------------------------------------------------------------------------- #
# Capacidades, llamadas y decisiones
# --------------------------------------------------------------------------- #


class CapabilityToken(_Strict):
    """Token de capacidad firmado con HMAC-SHA256 (clave efímera por sesión)."""

    token_id: ShortId
    session_id: ShortId
    enclave: EnclaveId
    tool: ToolName
    operation: Operation
    # Glob sobre ruta relativa a la bóveda (posix, minúsculas) o sobre "host:port/path?query".
    scope: Annotated[str, StringConstraints(min_length=1, max_length=2400)]
    expires_at: float
    single_use: bool = True
    step_id: Optional[StepId] = None
    signature: str = ""

    def signing_payload(self) -> bytes:
        parts = [self.token_id, self.session_id, self.enclave.value, self.tool.value,
                 self.operation.value, self.scope, repr(self.expires_at),
                 str(self.single_use), self.step_id or ""]
        return "\x1f".join(parts).encode("utf-8")


class ToolCall(_Strict):
    call_id: ShortId
    session_id: ShortId
    enclave: EnclaveId
    tool: str  # str y no ToolName: un enclave secuestrado puede pedir cualquier cosa
    args: dict[str, str]
    token: Optional[CapabilityToken] = None


class BrokerDecision(_Strict):
    allowed: bool
    rule: ShortId       # nombre estable de la regla que decidió
    reason: str = ""


class ToolResult(_Strict):
    call_id: ShortId
    decision: BrokerDecision
    output: Optional[str] = None
    label: Optional[Label] = None


# --------------------------------------------------------------------------- #
# Salida de la Aduana (Enclave 2)
# --------------------------------------------------------------------------- #


class DocType(str, Enum):
    INVOICE = "invoice"
    TECH_DOC = "tech_doc"
    SEARCH_RESULTS = "search_results"
    INBOX_FILE = "inbox_file"
    UNKNOWN = "unknown"


class Currency(str, Enum):
    USD = "USD"
    COP = "COP"
    EUR = "EUR"


class TextField(str, Enum):
    """Nombres permitidos para texto libre en cuarentena."""

    BODY = "body"
    NOTES = "notes"
    IMAGE_TEXT = "image_text"


class ExtractedRecord(_Strict):
    """Único tipo que la Aduana puede devolver al Orquestador en modo D.

    Solo campos tipados y acotados. Texto libre = handle opaco.
    """

    step_id: StepId
    doc_type: DocType
    invoice_id: Optional[InvoiceId] = None
    total_amount: Optional[Annotated[Decimal, Field(ge=0, max_digits=14, decimal_places=2)]] = None
    currency: Optional[Currency] = None
    issue_date: Optional[dt.date] = None
    version: Optional[SemVer] = None
    image_count: Annotated[int, Field(ge=0, le=50)] = 0
    text_handles: dict[TextField, QuarantineHandle] = Field(default_factory=dict)
    dropped_fields: tuple[ShortId, ...] = ()  # solo nombres de campo, nunca valores


# Campos tipados que un extractor (regex, LLM, VLM) puede proponer.
EXTRACTABLE_FIELDS: tuple[str, ...] = ("invoice_id", "total_amount", "currency", "issue_date", "version")


class FreeTextResult(_Strict):
    """Salida heredada (B/C): texto libre que el Orquestador lee. Canal de inyección."""

    step_id: StepId
    text: str
    label: Label


class WorkerReceipt(_Strict):
    """Lo único que el Trabajador devuelve al Orquestador en modo D: metadatos."""

    step_id: StepId
    ok: bool
    rule: ShortId = "ok"
    bytes_written: int = 0
    sha256: Optional[Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]] = None


# --------------------------------------------------------------------------- #
# Monitores
# --------------------------------------------------------------------------- #


class EgressFinding(_Strict):
    canary_id: ShortId  # sha256(canary)[:12]; el canary nunca se escribe en logs
    encoding: Literal["plain", "base64", "url", "hex", "reversed", "fragmented"]
    coverage: Annotated[float, Field(ge=0, le=1)] = 1.0
    kind: Literal["vault", "system"] = "vault"  # system = canary de system prompt de un enclave


class ScanSpan(_Strict):
    start: Annotated[int, Field(ge=0)]
    end: Annotated[int, Field(ge=0)]
    rule: ShortId  # regla que disparó; nunca el texto del span


class ScanResult(_Strict):
    """Salida del escáner de inyección sobre un documento no confiable."""

    score: Annotated[float, Field(ge=0, le=1)]
    spans: tuple[ScanSpan, ...] = ()
    verdict: Literal["clean", "suspicious", "malicious"]


class DriftVerdict(_Strict):
    drifted: bool
    score: Annotated[float, Field(ge=0, le=1)]
    reason: str = ""


# --------------------------------------------------------------------------- #
# Auditoría
# --------------------------------------------------------------------------- #


class AuditKind(str, Enum):
    SESSION_START = "session_start"
    PLAN_FIXED = "plan_fixed"
    PLAN_STEP_REJECTED = "plan_step_rejected"
    TOKEN_MINTED = "token_minted"
    TOOL_CALL = "tool_call"
    BROKER_DECISION = "broker_decision"
    HANDLE_CREATED = "handle_created"
    HANDLE_READ = "handle_read"
    PROVENANCE_DROP = "provenance_drop"
    SCHEMA_DROP = "schema_drop"
    DRIFT_CHECK = "drift_check"
    EGRESS_ALERT = "egress_alert"
    EXPOSURE = "exposure"
    INJECTION_SCAN = "injection_scan"
    INTERNAL_PROMPT_LEAKAGE = "internal_prompt_leakage"


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: float
    seq: int
    session_id: str
    kind: AuditKind
    enclave: Optional[str] = None
    tool: Optional[str] = None
    allowed: Optional[bool] = None
    rule: Optional[str] = None
    detail: dict[str, Any] = Field(default_factory=dict)
