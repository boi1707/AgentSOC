"""Never runs without --live-provider. One paid request, synthetic evidence, no response executor."""

import pytest

from src.anon import Anon
from src.llm import LLM
from src.settings import Settings
from src.storage import Store


def test_opt_in_live_provider(request, tmp_path):
    if not request.config.getoption("--live-provider"):
        pytest.skip("Paid provider test disabled; requires explicit --live-provider")
    settings = Settings.from_env()
    if settings.llm_mode != "live":
        pytest.fail("Opt-in test requires LLM_MODE=live and explicit provider configuration")
    settings.validate()
    store = Store(tmp_path / "live-test.db")
    result = LLM(settings, store).ask(
        Anon(),
        "synthetic-connectivity-test",
        "net",
        "Return JSON keys finding, evidence_ids, suspicious, candidate. This is a synthetic connectivity test; do not infer an attack.",
        [{"id": "synthetic-1", "kind": "net", "description": "Synthetic schema connectivity check"}],
        ["synthetic-1"],
    )
    assert isinstance(result["finding"], str)
