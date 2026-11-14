"""Enclave 2 — Aduana en cuarentena (red y L0; sin ruta alguna hacia L1/L2).

Por cada paso del plan:
  1. Ejecuta la herramienta SOLO vía broker, con el token emitido para ese paso.
  2. Separa el documento en texto visible y canales ocultos (`ml/html_split.py`).
  3. Extrae candidatos tipados con regex (`ml/extractors.py`).
  4. Verificador de procedencia: solo sobreviven valores presentes en el texto visible.
  5. Valida con `ExtractedRecord` (extra=forbid); un campo inválido se descarta.
  6. Texto libre visible -> QuarantineStore -> handle opaco. Lo oculto NO se guarda ni se
     pasa a ningún modelo: solo se cuenta.
  7. Señal de inyección (telemetría) -> audit log.

Lo que devuelve al Orquestador es SOLO un `ExtractedRecord`: campos tipados + handles.
No hay LLM en este enclave por defecto, así que no hay nada que una inyección pueda
secuestrar aquí.
"""
from __future__ import annotations

import base64
from typing import Any, Optional, Protocol

from pydantic import ValidationError

from ..broker import CapabilityBroker
from ..contracts import (
    ACTION_ROUTING, ActionType, AuditKind, CapabilityToken, DocType, EnclaveId, ExtractedRecord,
    PlanStep, TextField, ToolCall, ToolName,
)
from ..ml.extractors import RegexExtractor, looks_like_invoice
from ..ml.html_split import SplitDocument, split_html
from ..ml.injection_signal import InjectionScorer, InjectionSignal
from ..ml.summarizer import Summarizer
from .quarantine import ProvenanceVerifier, QuarantineStore
from ..tools.web_tools import IMAGE_DATA_PREFIX

MAX_IMAGES_PER_STEP = 5
_TOOL_ARG = {ToolName.FETCH_URL: "url", ToolName.WEB_SEARCH: "query", ToolName.READ_INBOX: "path"}


class StepDenied(Exception):
    """El broker negó la llamada o la herramienta falló. `rule` es la regla del broker."""

    def __init__(self, step_id: str, rule: str) -> None:
        super().__init__(f"{step_id}: {rule}")
        self.step_id = step_id
        self.rule = rule


class ImageReader(Protocol):
    def read(self, image_bytes: bytes) -> str: ...


class NullImageReader:
    """Baseline: no lee imágenes. La instrucción que solo vive en una imagen nunca entra.

    ML-TEAM: implementa `read(image_bytes) -> str` con OCR local o un VLM (sin
    herramientas). Su salida va SIEMPRE a un handle `image_text`, nunca al Orquestador.
    """

    def read(self, image_bytes: bytes) -> str:
        return ""


class CustomsEnclave:
    enclave = EnclaveId.CUSTOMS

    def __init__(self, broker: CapabilityBroker, store: QuarantineStore,
                 verifier: Optional[ProvenanceVerifier] = None, extractor: Optional[RegexExtractor] = None,
                 scorer: Optional[InjectionScorer] = None, image_reader: Optional[ImageReader] = None,
                 summarizer: Optional[Summarizer] = None) -> None:
        self.broker = broker
        self.store = store
        self.verifier = verifier or ProvenanceVerifier(broker.session_id, broker.audit)
        self.extractor = extractor or RegexExtractor()
        self.scorer = scorer or InjectionScorer()
        self.image_reader = image_reader or NullImageReader()
        self.summarizer = summarizer  # lector en cuarentena (Dual-LLM); None = no resume
        self.signals: dict[str, InjectionSignal] = {}  # telemetría por paso (para métricas)

    # -- herramientas ------------------------------------------------------- #

    def _call(self, tool: ToolName, value: str, token: Optional[CapabilityToken], step_id: str) -> str:
        call = ToolCall(call_id=self.broker.new_call_id(), session_id=self.broker.session_id,
                        enclave=self.enclave, tool=tool.value, args={_TOOL_ARG[tool]: value}, token=token)
        result = self.broker.execute(call)
        if not result.decision.allowed or result.output is None:
            raise StepDenied(step_id, result.decision.rule)
        return result.output

    @staticmethod
    def _strip_http(output: str, step_id: str) -> str:
        head, _, body = output.partition("\n")
        if not head.startswith("HTTP "):
            return output
        if head.strip() != "HTTP 200":
            raise StepDenied(step_id, "http_error")
        return body

    # -- paso ---------------------------------------------------------------- #

    def run_step(self, step: PlanStep, token: Optional[CapabilityToken], summarize: bool = False) -> ExtractedRecord:
        enclave, tool, _ = ACTION_ROUTING[step.action]
        if enclave is not self.enclave:
            raise StepDenied(step.step_id, "action_not_for_customs")
        raw = self._call(tool, step.target, token, step.step_id)

        if raw.startswith(IMAGE_DATA_PREFIX):
            return self._image_only(step, raw)

        if tool is ToolName.READ_INBOX:
            doc = split_html(raw)  # Markdown/texto: el parser solo quita comentarios y HTML embebido
            doc_type = DocType.INBOX_FILE
        else:
            doc = split_html(self._strip_http(raw, step.step_id), base_url=step.target if tool is ToolName.FETCH_URL else "")
            doc_type = DocType.SEARCH_RESULTS if tool is ToolName.WEB_SEARCH else (
                DocType.INVOICE if looks_like_invoice(doc.visible_text) else DocType.TECH_DOC)

        candidates = self.extractor.extract(doc.visible_text)
        proven = self.verifier.verify(candidates, doc.visible_text, step_id=step.step_id)
        handles: dict[TextField, str] = {}
        if doc.visible_text:
            handles[TextField.BODY] = self.store.put(doc.visible_text, step_id=step.step_id, field=TextField.BODY)
        if summarize and self.summarizer is not None and doc.visible_text:
            # Dual-LLM: el lector en cuarentena ve el texto visible; su salida es otro handle.
            summary = self.summarizer.summarize(doc.visible_text)
            if summary:
                handles[TextField.SUMMARY] = self.store.put(summary, step_id=step.step_id, field=TextField.SUMMARY)
        image_count = len(doc.image_srcs)
        if tool is ToolName.FETCH_URL and doc.image_srcs:
            image_text = self._read_images(step, doc)
            if image_text:
                handles[TextField.IMAGE_TEXT] = self.store.put(image_text, step_id=step.step_id,
                                                               field=TextField.IMAGE_TEXT)
        self._signal(step, doc)
        return self._build(step, doc_type, proven.accepted, list(proven.dropped), handles, image_count)

    def _image_only(self, step: PlanStep, raw: str) -> ExtractedRecord:
        text = self.image_reader.read(base64.b64decode(raw[len(IMAGE_DATA_PREFIX):]))
        handles = {TextField.IMAGE_TEXT: self.store.put(text, step_id=step.step_id, field=TextField.IMAGE_TEXT)} if text else {}
        return self._build(step, DocType.UNKNOWN, {}, [], handles, 1)

    def _read_images(self, step: PlanStep, doc: SplitDocument) -> str:
        if isinstance(self.image_reader, NullImageReader):
            return ""  # sin lector no se descarga nada: menos superficie
        texts = []
        for src in doc.image_srcs[:MAX_IMAGES_PER_STEP]:
            token = self.broker.mint_subresource(step, src)
            if token is None:
                continue
            try:
                raw = self._call(ToolName.FETCH_URL, src, token, step.step_id)
            except StepDenied:
                continue
            if raw.startswith(IMAGE_DATA_PREFIX):
                text = self.image_reader.read(base64.b64decode(raw[len(IMAGE_DATA_PREFIX):]))
                if text:
                    texts.append(text)
        return "\n".join(texts)

    def _signal(self, step: PlanStep, doc: SplitDocument) -> None:
        signal = self.scorer.score(doc.visible_text, doc.hidden)
        self.signals[step.step_id] = signal
        self.broker.audit.write(self.broker.session_id, AuditKind.INJECTION_SIGNAL, enclave=self.enclave.value,
                                step_id=step.step_id, score=signal.score, channel=signal.channel,
                                flagged=signal.flagged, hidden_chars=signal.hidden_chars,
                                hidden_channels=sorted(doc.hidden))

    def _build(self, step: PlanStep, doc_type: DocType, fields: dict[str, Any], dropped: list[str],
               handles: dict[TextField, str], image_count: int) -> ExtractedRecord:
        """Valida campo por campo: uno inválido se descarta sin tumbar el registro."""
        base = {"step_id": step.step_id, "doc_type": doc_type, "text_handles": handles,
                "image_count": min(image_count, 50)}
        accepted: dict[str, Any] = {}
        for name, value in fields.items():
            try:
                ExtractedRecord(**base, **accepted, **{name: value})
                accepted[name] = value
            except ValidationError:
                dropped.append(name)
                self.broker.audit.write(self.broker.session_id, AuditKind.SCHEMA_DROP, enclave=self.enclave.value,
                                        step_id=step.step_id, field=name)
        return ExtractedRecord(**base, **accepted, dropped_fields=tuple(dropped))
