import os
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# La suite no carga el modelo de Hugging Face (1.2 GB, GPU, descarga con condiciones): corre
# determinista y sin red. La integración real se prueba con SENTINEL_MODE=auto y SENTINEL_TEST=1.
os.environ.setdefault("SENTINEL_MODE", "off")


@pytest.fixture()
def vault(tmp_path: Path) -> Path:
    """Copia desechable de la bóveda sintética."""
    target = tmp_path / "vault"
    shutil.copytree(REPO_ROOT / "vault", target)
    return target
