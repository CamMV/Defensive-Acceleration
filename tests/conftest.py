import os
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# La suite no carga los modelos de Hugging Face (Galvanize-3, WARD-2b: GPU y descarga): corre
# determinista y sin red. La integración real se prueba con HF_TEST=1 (ver tests/test_hf_models.py).
os.environ.setdefault("GALVANIZE_MODE", "off")
os.environ.setdefault("WARD_MODE", "off")


@pytest.fixture()
def vault(tmp_path: Path) -> Path:
    """Copia desechable de la bóveda sintética."""
    target = tmp_path / "vault"
    shutil.copytree(REPO_ROOT / "vault", target)
    return target
