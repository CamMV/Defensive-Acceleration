"""Clasificador de inyección de Hugging Face: Galvanize-3 (`usezn/Galvanize-3`).

- ModernBERT (~140 M parámetros), fine-tune de Horizon-Labs/prompt-injection-guard-small sobre
  mmBERT-small. Licencia Apache-2.0, sin acceso restringido.
- Binario: `{0: SAFE, 1: INJECTION}`. P(inyección) = sigmoid(logit[INJECTION] - logit[SAFE]).
- Lee hasta 512 tokens. Los textos más largos se parten en ventanas solapadas (stride de 256) y se
  toma el máximo, como recomienda su model card.
- Umbral de servicio de la model card: P >= 0.9802. El umbral 0.5 por defecto del pipeline marca
  demasiado texto legítimo.
- Multilingüe según su ficha, pero el set de evaluación es privado: sus falsas alarmas sobre
  nuestros documentos en español se miden en `eval/eval_galvanize.py`.

Variables de entorno: `GALVANIZE_MODE` (auto|required|off), `GALVANIZE_MODEL`, `GALVANIZE_THRESHOLD`.
"""
from __future__ import annotations

import os
from typing import Optional, Protocol, Sequence

from .hf_common import ModelUnavailable, device_and_dtype, env_float, from_pretrained, import_torch, load_once

PREFIX = "GALVANIZE"
DEFAULT_MODEL = "usezn/Galvanize-3"
DEFAULT_THRESHOLD = 0.9802
MAX_TOKENS = 512
STRIDE = 256


class InjectionScorer(Protocol):
    """Devuelve P(inyección) en [0, 1] para cada texto. Determinista para la misma entrada."""

    def injection_probs(self, texts: Sequence[str]) -> list[float]: ...


def threshold() -> float:
    return env_float(f"{PREFIX}_THRESHOLD", DEFAULT_THRESHOLD)


def normalize(text: str) -> str:
    """Preproceso de la model card: espacios aplanados."""
    return " ".join(text.split())


class GalvanizeClassifier:
    """Envoltura de transformers. GPU si hay (fp16), inferencia por lotes de ventanas sin gradientes."""

    def __init__(self, model_id: Optional[str] = None, batch_size: int = 16) -> None:
        torch = import_torch()
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise ModelUnavailable("install transformers (requirements-ml.txt)") from exc
        self._torch = torch
        self.model_id = model_id or os.environ.get(f"{PREFIX}_MODEL", DEFAULT_MODEL)
        self.device, dtype = device_and_dtype(torch, torch.float16)
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
            self.model = from_pretrained(AutoModelForSequenceClassification, self.model_id, dtype)
        except Exception as exc:  # sin red y sin caché, id incorrecto...
            raise ModelUnavailable(f"cannot load {self.model_id}: {type(exc).__name__}: {exc}") from exc
        self.model.to(self.device).eval()
        self.batch_size = batch_size
        self.safe_index, self.injection_index = self._label_indices()

    def _label_indices(self) -> tuple[int, int]:
        labels = {int(i): str(name).upper() for i, name in self.model.config.id2label.items()}
        injection = [i for i, name in labels.items() if "INJECTION" in name]
        if len(labels) != 2 or len(injection) != 1:
            raise ModelUnavailable(f"expected labels SAFE/INJECTION, got {sorted(labels.values())}")
        return (1 - injection[0]), injection[0]

    def _windows(self, texts: Sequence[str]) -> tuple[list[list[int]], list[int]]:
        """Ventanas de <= 512 tokens por texto (con CLS/SEP) y el índice del texto de cada una."""
        enc = self.tokenizer([normalize(t) for t in texts], truncation=True, max_length=MAX_TOKENS,
                             stride=STRIDE, return_overflowing_tokens=True, padding=False)
        owners = enc.get("overflow_to_sample_mapping") or list(range(len(enc["input_ids"])))
        return enc["input_ids"], list(owners)

    def injection_probs(self, texts: Sequence[str]) -> list[float]:
        if not texts:
            return []
        torch = self._torch
        windows, owners = self._windows(texts)
        best = [0.0] * len(texts)
        pad = self.tokenizer.pad_token_id or 0
        for start in range(0, len(windows), self.batch_size):
            batch = windows[start:start + self.batch_size]
            width = max(len(w) for w in batch)
            ids = torch.full((len(batch), width), pad, dtype=torch.long)
            mask = torch.zeros((len(batch), width), dtype=torch.long)
            for row, window in enumerate(batch):
                ids[row, :len(window)] = torch.tensor(window, dtype=torch.long)
                mask[row, :len(window)] = 1
            with torch.inference_mode():
                logits = self.model(input_ids=ids.to(self.device), attention_mask=mask.to(self.device)).logits.float()
            margin = logits[:, self.injection_index] - logits[:, self.safe_index]
            for owner, p in zip(owners[start:start + self.batch_size], torch.sigmoid(margin).tolist()):
                best[owner] = max(best[owner], p)
        return best


def load_galvanize() -> GalvanizeClassifier:
    return load_once(PREFIX, GalvanizeClassifier)
