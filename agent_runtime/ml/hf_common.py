"""Utilidades comunes para los modelos de Hugging Face que corren en proceso (Galvanize-3, WARD-2b).

Cada modelo se configura con variables de entorno de prefijo propio:
- `<PREFIX>_MODE`: `auto` (por defecto: se usa si está instalado y descargado), `required` (si no
  carga, el sistema no arranca) u `off`.
- `<PREFIX>_MODEL`: id del repo o ruta local.

Las dependencias (torch, transformers) son opcionales: sin ellas el sistema corre con la etapa
determinista. Los pesos NO se versionan en este repo.
"""
from __future__ import annotations

import os
from typing import Any, Callable, TypeVar

T = TypeVar("T")
_MODES = {"auto", "required", "off"}


class ModelUnavailable(RuntimeError):
    """Faltan dependencias, el modelo no está descargado o no carga."""


def model_mode(prefix: str) -> str:
    value = os.environ.get(f"{prefix}_MODE", "auto").strip().lower()
    return value if value in _MODES else "auto"


def env_float(name: str, default: float, low: float = 0.0, high: float = 1.0) -> float:
    try:
        return min(high, max(low, float(os.environ.get(name, default))))
    except ValueError:
        return default


def env_int(name: str, default: int, low: int = 1) -> int:
    try:
        return max(low, int(os.environ.get(name, default)))
    except ValueError:
        return default


def import_torch() -> Any:
    try:
        import torch
    except ImportError as exc:  # dependencia opcional
        raise ModelUnavailable("install torch and transformers (requirements-ml.txt)") from exc
    return torch


def device_and_dtype(torch: Any, gpu_dtype: Any) -> tuple[str, Any]:
    """GPU con el dtype pedido si hay CUDA; si no, CPU en float32."""
    if torch.cuda.is_available():
        return "cuda", gpu_dtype
    return "cpu", torch.float32


def from_pretrained(cls: Any, model_id: str, dtype: Any, **kwargs: Any) -> Any:
    """transformers >= 4.56 usa `dtype`; versiones anteriores, `torch_dtype`."""
    try:
        return cls.from_pretrained(model_id, dtype=dtype, **kwargs)
    except TypeError:
        return cls.from_pretrained(model_id, torch_dtype=dtype, **kwargs)


_LOADED: dict[str, object] = {}


def load_once(key: str, factory: Callable[[], T]) -> T:
    """Una sola instancia por proceso. También memoriza el fallo: no reintenta la descarga en cada sesión."""
    if key not in _LOADED:
        try:
            _LOADED[key] = factory()
        except ModelUnavailable as exc:
            _LOADED[key] = exc
    value = _LOADED[key]
    if isinstance(value, ModelUnavailable):
        raise value
    return value  # type: ignore[return-value]


def reset_cache() -> None:
    """Solo para tests."""
    _LOADED.clear()
