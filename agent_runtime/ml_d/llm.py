"""Cliente LLM compatible con OpenAI + MockLLM determinista para tests.

Diseño:
- Una instancia por enclave (historial y estadísticas separados). Nada global.
- Configuración solo por variables de entorno (`LLM_BASE_URL`, `LLM_API_KEY`,
  `LLM_MODEL_<ROL>`); nunca se hardcodean modelos ni claves.
- `complete_json` valida la salida contra un modelo pydantic y reintenta un número
  acotado de veces. Al modelo solo se le devuelve el *tipo* de error de validación,
  nunca el contenido de un dato no confiable.
- Los prompts y respuestas NO se registran (pueden contener datos sensibles); solo
  métricas: llamadas, fallos, latencia y tokens.
- `MockLLM` existe solo para tests y para `--mock`. Toda salida de evaluación debe
  consultar `is_mock` y marcar las filas que lo usaron.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Optional, Sequence, TypeVar, Union

from pydantic import BaseModel, ValidationError

Role = Literal["orchestrator", "vault_worker", "customs", "baseline"]
Message = dict[str, str]
T = TypeVar("T", bound=BaseModel)

DEFAULT_TIMEOUT_S = 60.0
DEFAULT_SEED = 1234
_FENCE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)


class LLMError(RuntimeError):
    """El modelo no produjo una salida válida tras los reintentos."""


class LLMNotConfigured(LLMError):
    """Faltan variables de entorno para el rol pedido."""


@dataclass
class LLMStats:
    calls: int = 0
    failures: int = 0
    latency_s: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def as_dict(self) -> dict[str, Union[int, float]]:
        return {"calls": self.calls, "failures": self.failures, "latency_s": round(self.latency_s, 4),
                "prompt_tokens": self.prompt_tokens, "completion_tokens": self.completion_tokens}


def extract_json_text(text: str) -> str:
    """Quita cercas ```json``` y texto alrededor del primer objeto JSON."""
    fenced = _FENCE.match(text)
    if fenced:
        text = fenced.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end < start:
        return text.strip()
    return text[start:end + 1]


class BaseLLM:
    """Interfaz común. Las subclases implementan `_complete`."""

    is_mock: bool = False

    def __init__(self, role: Role) -> None:
        self.role = role
        self.stats = LLMStats()

    def _complete(self, messages: Sequence[Message], json_mode: bool) -> tuple[str, int, int]:
        raise NotImplementedError

    def complete(self, messages: Sequence[Message], json_mode: bool = False) -> str:
        started = time.perf_counter()
        self.stats.calls += 1
        try:
            text, p_tokens, c_tokens = self._complete(list(messages), json_mode)
        except Exception:
            self.stats.failures += 1
            raise
        finally:
            self.stats.latency_s += time.perf_counter() - started
        self.stats.prompt_tokens += p_tokens
        self.stats.completion_tokens += c_tokens
        return text

    def complete_json(self, messages: Sequence[Message], schema: type[T], max_retries: int = 2) -> T:
        """Pide JSON y lo valida con `schema`. Reintenta como máximo `max_retries` veces."""
        history = list(messages)
        last_error = "no attempt"
        for _ in range(max_retries + 1):
            raw = self.complete(history, json_mode=True)
            try:
                return schema.model_validate_json(extract_json_text(raw))
            except (ValidationError, ValueError) as exc:
                last_error = _error_summary(exc)
                history = list(messages) + [
                    {"role": "assistant", "content": raw},
                    {"role": "user", "content": "Invalid output (" + last_error + "). "
                     "Reply with ONLY one JSON object matching the schema."},
                ]
        self.stats.failures += 1
        raise LLMError(f"{self.role}: invalid JSON after {max_retries + 1} attempts ({last_error})")


def _error_summary(exc: Exception) -> str:
    """Resumen sin valores: solo ubicación y tipo de cada error."""
    if isinstance(exc, ValidationError):
        parts = [".".join(str(p) for p in err["loc"]) + ":" + err["type"] for err in exc.errors()[:5]]
        return "; ".join(parts) or "validation_error"
    return type(exc).__name__


class OpenAICompatLLM(BaseLLM):
    """Cualquier endpoint compatible con OpenAI (Ollama local, vLLM, OpenRouter...)."""

    def __init__(self, role: Role, base_url: str, api_key: str, model: str,
                 timeout_s: float = DEFAULT_TIMEOUT_S, seed: int = DEFAULT_SEED) -> None:
        super().__init__(role)
        from openai import OpenAI  # import diferido: los tests no lo necesitan

        self.model = model
        self.seed = seed
        self._client = OpenAI(base_url=base_url, api_key=api_key or "unused", timeout=timeout_s,
                              max_retries=0)

    def _complete(self, messages: Sequence[Message], json_mode: bool) -> tuple[str, int, int]:
        kwargs: dict = {"model": self.model, "messages": messages, "temperature": 0, "seed": self.seed}
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        resp = self._client.chat.completions.create(**kwargs)
        text = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        return text, getattr(usage, "prompt_tokens", 0) or 0, getattr(usage, "completion_tokens", 0) or 0


Responder = Callable[[Sequence[Message]], str]


class MockLLM(BaseLLM):
    """LLM determinista para tests. Respuestas de una cola o de una función.

    Nunca usar sus resultados como ASR: `is_mock` es True y la evaluación lo marca.
    """

    is_mock = True

    def __init__(self, role: Role, responses: Optional[Union[Sequence[str], Responder]] = None) -> None:
        super().__init__(role)
        self._queue: list[str] = []
        self._responder: Optional[Responder] = None
        if callable(responses):
            self._responder = responses
        elif responses is not None:
            self._queue = list(responses)
        self.seen: list[list[Message]] = []  # solo en memoria, para asserts en tests

    def _complete(self, messages: Sequence[Message], json_mode: bool) -> tuple[str, int, int]:
        self.seen.append([dict(m) for m in messages])
        if self._responder is not None:
            return self._responder(messages), 0, 0
        if not self._queue:
            raise LLMError(f"MockLLM({self.role}): no scripted responses left")
        return self._queue.pop(0), 0, 0


# --------------------------------------------------------------------------- #
# Configuración
# --------------------------------------------------------------------------- #


def load_env(path: Union[str, Path] = ".env") -> None:
    """Carga `KEY=VALUE` de un archivo .env sin pisar variables ya definidas."""
    env_path = Path(path)
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def is_configured(role: Role) -> bool:
    return bool(os.environ.get("LLM_BASE_URL") and os.environ.get(f"LLM_MODEL_{role.upper()}"))


def make_llm(role: Role, mock: bool = False,
             responses: Optional[Union[Sequence[str], Responder]] = None) -> BaseLLM:
    """Fábrica: una instancia nueva por llamada (nunca compartir entre enclaves)."""
    if mock:
        return MockLLM(role, responses)
    base_url = os.environ.get("LLM_BASE_URL", "")
    model = os.environ.get(f"LLM_MODEL_{role.upper()}", "")
    if not base_url or not model:
        raise LLMNotConfigured(f"set LLM_BASE_URL and LLM_MODEL_{role.upper()} in .env")
    return OpenAICompatLLM(role, base_url, os.environ.get("LLM_API_KEY", ""), model)


def dumps_schema(schema: type[BaseModel]) -> str:
    """JSON Schema compacto para incluir en el prompt del sistema."""
    return json.dumps(schema.model_json_schema(), separators=(",", ":"), ensure_ascii=False)
