from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = REPO_ROOT / "config" / "vigie.example.toml"


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Le shell de dev exporte VIGIE_ENV/VIGIE_CONFIG : les tests n'en dépendent pas."""
    for var in ("VIGIE_ENV", "VIGIE_CONFIG", "CREDENTIALS_DIRECTORY"):
        monkeypatch.delenv(var, raising=False)
