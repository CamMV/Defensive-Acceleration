import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def vault(tmp_path: Path) -> Path:
    """Copia desechable de la bóveda sintética."""
    target = tmp_path / "vault"
    shutil.copytree(REPO_ROOT / "vault", target)
    return target
