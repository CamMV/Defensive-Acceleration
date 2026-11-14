"""Segunda etapa de reconocimiento: clasificador preentrenado de Hugging Face (Sentinel v2).

Modelo: `prompt-injection-jailbreak-sentinel-v2` (fine-tune de Qwen3-0.6B, ~1.2 GB en fp16,
clasificación binaria). Su model card indica:
- Licencia "other": dice que es de uso comercial bajo la licencia Elastic. El repositorio es
  "gated": cada persona debe iniciar sesión en Hugging Face y aceptar las condiciones antes de
  descargarlo. Los pesos NO se versionan en este repo.
- Solo inglés: "Not evaluated on non-English data". Nuestros documentos están en español, así
  que sus falsas alarmas se miden antes de confiar en él (eval/eval_two_stage.py).

Configuración por variables de entorno (nada fijo en el código):
- `SENTINEL_MODEL`: id o ruta local del modelo.
- `SENTINEL_MODE`: `auto` (por defecto: se usa si está instalado y descargado), `required`
  (si no carga, el sistema no arranca) u `off`.
- `SENTINEL_MIN_BENIGN`: confianza mínima de "benigno" para pasar (por defecto 0.75).
"""
from __future__ import annotations

import os
from typing import Optional, Protocol, Sequence

DEFAULT_MODEL = "rogue-security/prompt-injection-jailbreak-sentinel-v2"  # la URL de qualifire/ resuelve aquí
DEFAULT_MIN_BENIGN = 0.75
MAX_TOKENS = 2048
_MALICIOUS_WORDS = ("jailbreak", "injection", "malicious", "unsafe", "attack")


class BenignScorer(Protocol):
    """Devuelve P(benigno) en [0, 1] para cada texto. Determinista para la misma entrada."""

    def benign_probs(self, texts: Sequence[str]) -> list[float]: ...


class SentinelUnavailable(RuntimeError):
    """Faltan dependencias, el modelo no está descargado o no se aceptaron sus condiciones."""


def mode() -> str:
    value = os.environ.get("SENTINEL_MODE", "auto").strip().lower()
    return value if value in {"auto", "required", "off"} else "auto"


def min_benign() -> float:
    try:
        return min(1.0, max(0.0, float(os.environ.get("SENTINEL_MIN_BENIGN", DEFAULT_MIN_BENIGN))))
    except ValueError:
        return DEFAULT_MIN_BENIGN


class SentinelClassifier:
    """Envoltura de transformers. Carga perezosa, GPU si hay (fp16), inferencia por lotes sin gradientes."""

    def __init__(self, model_id: Optional[str] = None, batch_size: int = 8) -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:  # dependencias opcionales
            raise SentinelUnavailable("install torch and transformers>=4.51") from exc
        self._torch = torch
        self.model_id = model_id or os.environ.get("SENTINEL_MODEL", DEFAULT_MODEL)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        dtype = torch.float16 if self.device == "cuda" else torch.float32
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            try:  # transformers >= 4.56 / 5.x usa `dtype`; versiones anteriores, `torch_dtype`
                self.model = AutoModelForSequenceClassification.from_pretrained(self.model_id, dtype=dtype)
            except TypeError:
                self.model = AutoModelForSequenceClassification.from_pretrained(self.model_id, torch_dtype=dtype)
        except Exception as exc:  # repo gated sin aceptar, sin red y sin caché, id incorrecto...
            raise SentinelUnavailable(f"cannot load {self.model_id}: {type(exc).__name__}") from exc
        self.model.to(self.device).eval()
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        if getattr(self.model.config, "pad_token_id", None) is None:
            self.model.config.pad_token_id = self.tokenizer.pad_token_id
        self.batch_size = batch_size
        self.benign_index = self._benign_index()

    def _benign_index(self) -> int:
        labels = {int(i): str(name).lower() for i, name in self.model.config.id2label.items()}
        if len(labels) != 2:
            raise SentinelUnavailable(f"expected a binary classifier, got labels {sorted(labels.values())}")
        benign = [i for i, name in labels.items() if not any(w in name for w in _MALICIOUS_WORDS)]
        if len(benign) != 1:
            raise SentinelUnavailable(f"cannot tell the benign label apart: {sorted(labels.values())}")
        return benign[0]

    def benign_probs(self, texts: Sequence[str]) -> list[float]:
        torch = self._torch
        out: list[float] = []
        for start in range(0, len(texts), self.batch_size):
            batch = list(texts[start:start + self.batch_size])
            enc = self.tokenizer(batch, truncation=True, max_length=MAX_TOKENS, padding=True, return_tensors="pt")
            enc = {k: v.to(self.device) for k, v in enc.items()}
            with torch.inference_mode():
                logits = self.model(**enc).logits.float()
            out += torch.softmax(logits, dim=-1)[:, self.benign_index].tolist()
        return out


_LOADED: dict[str, object] = {}


def load_sentinel() -> SentinelClassifier:
    """Una sola instancia por proceso. También memoriza el fallo: no reintenta la descarga en cada sesión."""
    if "model" not in _LOADED:
        try:
            _LOADED["model"] = SentinelClassifier()
        except SentinelUnavailable as exc:
            _LOADED["model"] = exc
    value = _LOADED["model"]
    if isinstance(value, SentinelUnavailable):
        raise value
    return value  # type: ignore[return-value]
