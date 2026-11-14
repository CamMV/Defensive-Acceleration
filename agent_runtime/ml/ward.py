"""Lector de imágenes: WARD-2b (`tricao1105/WARD-2b`) usado SOLO para transcribir.

WARD-2b es un VLM de 2B parámetros (familia Qwen, Apache-2.0) entrenado como guardián de prompt
injection para agentes web. Aquí no se usa su veredicto: se le pide que transcriba el texto visible
de la imagen, y ese texto pasa por el doble chequeo (regex + Galvanize-3) como cualquier documento.
Transcribir no es la tarea con la que se entrenó; su calidad se mide en `eval/eval_galvanize.py`.

Garantías que no dependen del modelo:
- Sin herramientas y sin HTML: solo la imagen y un prompt fijo.
- Su salida es texto NO confiable: la Aduana la escanea, la manda a cuarentena
  (`TextField.IMAGE_TEXT`) y nunca llega al Orquestador como texto.
- Decodificación greedy (determinista) y `max_new_tokens` acotado (latencia).

Variables de entorno: `WARD_MODE` (auto|required|off), `WARD_MODEL`, `WARD_MAX_NEW_TOKENS`, `WARD_MAX_SIDE`.
"""
from __future__ import annotations

import io
import os
import re
from typing import Any, Callable, Optional

from .hf_common import ModelUnavailable, device_and_dtype, env_int, from_pretrained, import_torch, load_once

PREFIX = "WARD"
DEFAULT_MODEL = "tricao1105/WARD-2b"
DEFAULT_MAX_NEW_TOKENS = 160
DEFAULT_MAX_SIDE = 1024
MAX_IMAGE_BYTES = 4_000_000

# Prompt medido en eval/eval_galvanize.py: los prompts largos hacen que el modelo los repita al final.
TRANSCRIBE_PROMPT = "OCR this image. Output only the exact text it contains, nothing else."
# WARD casi nunca emite fin de secuencia: tras la transcripción sigue con el JSON de su entrenamiento
# ({"content": ...}, {"reasoning": ...}). Se corta ahí, en la generación y en la limpieza.
STOP_STRINGS = ["\n{", "\n```"]
_THINK = re.compile(r"<think>.*?(?:</think>|$)", re.DOTALL)
_TRAILER = re.compile(r"\n\s*(?:\{|```)")


def prepare_image(image_bytes: bytes, max_side: int) -> Any:
    """RGB, contraste automático (texto de bajo contraste) y lado máximo acotado (latencia)."""
    from PIL import Image, ImageOps
    with Image.open(io.BytesIO(image_bytes)) as img:
        image = img.convert("RGB")
    image = ImageOps.autocontrast(image, cutoff=1)
    image.thumbnail((max_side, max_side))
    return image


def clean_output(text: str) -> str:
    """Quita razonamiento, cercas de código, el JSON que WARD añade después y el eco del prompt."""
    text = _THINK.sub("", text).strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
    text = _TRAILER.split(text, maxsplit=1)[0]
    return text.replace(TRANSCRIBE_PROMPT, "").strip()


class _TailStop:
    """Corta al aparecer un `STOP_STRINGS` decodificando solo los últimos tokens.

    `stop_strings` de transformers costaba ~1 s extra por imagen; esto, microsegundos por paso.
    """

    def __init__(self, tokenizer: Any, tail: int = 4) -> None:
        self.tokenizer, self.tail = tokenizer, tail

    def __call__(self, input_ids: Any, scores: Any, **kwargs: Any) -> Any:
        import torch
        text = self.tokenizer.decode(input_ids[0, -self.tail:].tolist(), skip_special_tokens=True)
        done = any(stop in text for stop in STOP_STRINGS)
        return torch.full((input_ids.shape[0],), done, dtype=torch.bool, device=input_ids.device)


class WardImageReader:
    """`__call__(bytes) -> str` (firma `OcrFn` de main) y `read(bytes) -> str` (protocolo de `ml_d`)."""

    def __init__(self, model_id: Optional[str] = None) -> None:
        torch = import_torch()
        try:
            from transformers import AutoModelForImageTextToText, AutoProcessor
        except ImportError as exc:
            raise ModelUnavailable("install transformers with image-text-to-text support") from exc
        self._torch = torch
        self.model_id = model_id or os.environ.get(f"{PREFIX}_MODEL", DEFAULT_MODEL)
        self.device, dtype = device_and_dtype(torch, torch.bfloat16)
        try:
            self.processor = AutoProcessor.from_pretrained(self.model_id, trust_remote_code=True)
            self.model = from_pretrained(AutoModelForImageTextToText, self.model_id, dtype, trust_remote_code=True)
            self.model.to(self.device).eval()
        except Exception as exc:  # incluye torch.OutOfMemoryError (GPU ocupada, p. ej. por un LLM local)
            raise ModelUnavailable(f"cannot load {self.model_id}: {type(exc).__name__}: {exc}") from exc
        self._tokenizer = getattr(self.processor, "tokenizer", self.processor)
        self._stop = _TailStop(self._tokenizer)
        self.max_new_tokens = env_int(f"{PREFIX}_MAX_NEW_TOKENS", DEFAULT_MAX_NEW_TOKENS)
        self.max_side = env_int(f"{PREFIX}_MAX_SIDE", DEFAULT_MAX_SIDE, low=64)

    def _inputs(self, image: Any) -> Any:
        messages = [{"role": "user", "content": [{"type": "image", "image": image},
                                                 {"type": "text", "text": TRANSCRIBE_PROMPT}]}]
        kwargs = dict(add_generation_prompt=True, tokenize=True, return_dict=True, return_tensors="pt")
        try:
            return self.processor.apply_chat_template(messages, enable_thinking=False, **kwargs)
        except TypeError:
            return self.processor.apply_chat_template(messages, **kwargs)

    def read(self, image_bytes: bytes) -> str:
        if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
            return ""
        try:
            image = prepare_image(image_bytes, self.max_side)
        except Exception:  # bytes que no son una imagen válida: no hay texto que leer
            return ""
        inputs = self._inputs(image).to(self.device)
        with self._torch.inference_mode():
            out = self.model.generate(**inputs, max_new_tokens=self.max_new_tokens, do_sample=False,
                                      stopping_criteria=[self._stop])
        new_tokens = out[:, inputs["input_ids"].shape[1]:]
        return clean_output(self.processor.batch_decode(new_tokens, skip_special_tokens=True)[0])

    __call__ = read


def load_ward() -> WardImageReader:
    return load_once(PREFIX, WardImageReader)


def default_image_reader() -> Optional[Callable[[bytes], str]]:
    """WARD-2b si carga; `None` si no (la Aduana no lee imágenes). `WARD_MODE=required` lo exige."""
    from .hf_common import model_mode
    if model_mode(PREFIX) == "off":
        return None
    try:
        return load_ward()
    except ModelUnavailable:
        if model_mode(PREFIX) == "required":
            raise
        return None
