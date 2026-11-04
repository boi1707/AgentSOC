import pytest

from src.settings import Settings


@pytest.mark.parametrize("missing", ["llm_url", "llm_key", "llm_model"])
def test_live_configuration_requires_all_credentials(settings, missing):
    settings.llm_mode = "live"
    settings.llm_url = "https://llm.example.org/v1/chat/completions"
    settings.llm_key = "test-only"
    settings.llm_model = "test-model"
    setattr(settings, missing, "")
    with pytest.raises(ValueError, match="Live mode requires"):
        settings.validate()


def test_startup_rejects_missing_approval_key(settings):
    from fastapi.testclient import TestClient

    from src.api.main import create_app

    settings.approve_key = ""
    with pytest.raises(ValueError, match="APPROVE_KEY"), TestClient(create_app(settings)):
        pass


def test_empty_host_ip_map_remains_empty():
    from src.incident import Grouper

    assert Grouper(host_ips={}).host_ips == {}


@pytest.mark.parametrize(
    "url", ["http://example.org", "https://user:password@example.org", "https://example.org?key=secret"]
)
def test_live_url_does_not_embed_credentials(settings, url):
    settings.llm_mode = "live"
    settings.llm_key, settings.llm_model = "test", "test"
    settings.llm_url = url
    with pytest.raises(ValueError):
        settings.validate()


def test_environment_configures_operational_limits(monkeypatch):
    monkeypatch.setenv("CAP", "20")
    monkeypatch.setenv("HI_LEVEL", "13")
    monkeypatch.setenv("LOG_LEVEL", "warning")
    settings = Settings.from_env()
    assert (settings.cap, settings.hi_level, settings.log_level) == (20, 13, "WARNING")
