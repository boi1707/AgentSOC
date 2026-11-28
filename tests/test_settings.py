import ipaddress

import pytest

from src.response import candidate
from src.response_adapters import PfSenseAdapter
from src.settings import Settings

BUILT_IN_NETWORKS = ("10.8.0.0/24", "192.168.10.0/24", "127.0.0.0/8", "169.254.0.0/16")
DEPLOYMENT_NETWORKS = ("192.168.119.0/24", "172.22.50.0/24", "10.100.27.254/32")
LAB_SOURCE = "10.100.27.10"


@pytest.fixture
def settings_env(monkeypatch, settings):
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.setenv("INGEST_KEY", settings.ingest_key)
    monkeypatch.setenv("APPROVE_KEY", settings.approve_key)
    monkeypatch.setenv("DB", settings.db)
    monkeypatch.setenv("LLM_MODE", "mock")
    monkeypatch.setenv("RESPONSE_MODE", "dry-run")
    monkeypatch.setenv("PFSENSE_LIVE_ENABLED", "0")
    return monkeypatch


@pytest.mark.parametrize("value", [None, "", " \t "])
def test_protected_network_defaults(settings_env, value):
    if value is None:
        settings_env.delenv("PROTECTED_NETWORKS", raising=False)
    else:
        settings_env.setenv("PROTECTED_NETWORKS", value)
    settings = Settings.from_env()
    settings.validate()
    assert settings.protected == BUILT_IN_NETWORKS


def test_protected_network_additions_are_trimmed_deduplicated_and_ordered(settings_env):
    settings_env.setenv(
        "PROTECTED_NETWORKS",
        " 192.168.119.0/24 , 10.8.0.0/24, 172.22.50.0/24, 192.168.119.0/24, 10.100.27.254/32 ",
    )
    settings = Settings.from_env()
    settings.validate()
    assert settings.protected == Settings.from_env().protected == BUILT_IN_NETWORKS + DEPLOYMENT_NETWORKS


@pytest.mark.parametrize(
    "value",
    [
        "300.168.119.0/24",
        "192.168.119.0/33",
        "192.168.119.0/-1",
        "2001:db8::/32",
        "192.168.119.158/24",
        "192.168.119.158",
        "192.168.119.0/255.255.255.0",
        "192.168.119.0/024",
        "192.168.119.0/24,",
        ",192.168.119.0/24",
        "192.168.119.0/24,,172.22.50.0/24",
    ],
)
def test_invalid_protected_networks_fail_validation(settings_env, value):
    settings_env.setenv("PROTECTED_NETWORKS", value)
    with pytest.raises(ValueError, match="PROTECTED_NETWORKS"):
        Settings.from_env().validate()


def test_explicit_constructor_keeps_its_own_protected_ranges(settings):
    settings.protected = ()
    settings.validate()
    assert settings.protected == ()
    settings.protected = ("203.0.113.0/24",)
    settings.validate()
    assert settings.protected == ("203.0.113.0/24",)


@pytest.mark.parametrize("mode", ["dry-run", "ssh"])
@pytest.mark.parametrize("gateway", ["invalid", "2001:db8::1", "192.0.2.1/32"])
def test_invalid_gateway_fails_validation(settings_env, mode, gateway):
    settings_env.setenv("RESPONSE_MODE", mode)
    settings_env.setenv("GATEWAY", gateway)
    if mode == "ssh":
        settings_env.setenv("LLM_MODE", "live")
        settings_env.setenv("LLM_URL", "https://llm.example.org/v1/chat/completions")
        settings_env.setenv("LLM_API_KEY", "fixture-api-key")
        settings_env.setenv("LLM_MODEL", "fixture-model")
    with pytest.raises(ValueError, match="GATEWAY must be an IPv4 address"):
        Settings.from_env().validate()


@pytest.mark.parametrize(
    ("variable", "value"),
    [("PROTECTED_NETWORKS", "192.168.119.158/24"), ("GATEWAY", "2001:db8::1")],
)
def test_invalid_network_policy_prevents_backend_and_worker_startup(settings_env, variable, value):
    from fastapi.testclient import TestClient

    from src import worker
    from src.api.main import create_app

    def refuse_service_start(_settings):
        pytest.fail("Worker initialized the service with invalid settings")

    settings_env.setenv(variable, value)
    settings_env.setattr(worker, "Service", refuse_service_start)
    with pytest.raises(ValueError, match=variable), TestClient(create_app()):
        pass
    with pytest.raises(ValueError, match=variable):
        worker.main()


@pytest.fixture
def deployment_policy(settings_env):
    settings_env.setenv("PROTECTED_NETWORKS", ",".join(DEPLOYMENT_NETWORKS))
    settings_env.setenv("GATEWAY", "198.51.100.254")
    settings_env.delenv("PFSENSE_ALLOWED_NETWORKS", raising=False)
    settings = Settings.from_env()
    settings.validate()
    return settings


def response_case(ip):
    return {
        "verdict": {
            "verdict": "attack",
            "confidence": 0.99,
            "grounded": 1,
            "block_ip": "INT_IP_0001",
            "evidence_ids": ["net-alert"],
        },
        "restore": {"INT_IP_0001": ip},
        "incident": {"alerts": [{"id": "net-alert", "kind": "net", "src_ip": ip}]},
    }


@pytest.mark.parametrize(
    "source",
    [
        "192.168.119.158",
        "192.168.119.134",
        "172.22.50.254",
        "172.22.50.10",
        "10.100.27.254",
        "10.8.0.3",
        "192.168.10.20",
        "127.0.0.1",
        "169.254.1.1",
        "198.51.100.254",  # Independently protected by GATEWAY.
    ],
)
def test_cited_protected_source_is_rejected_by_target_guard(deployment_policy, source):
    with pytest.raises(ValueError, match="Protected or invalid blocking target"):
        candidate(response_case(source), deployment_policy)


def test_lab_source_remains_eligible_only_when_cited(deployment_policy):
    case = response_case(LAB_SOURCE)
    assert candidate(case, deployment_policy) == LAB_SOURCE
    case["verdict"]["evidence_ids"] = ["different-alert"]
    with pytest.raises(ValueError, match="not a cited network source"):
        candidate(case, deployment_policy)


def test_pfsense_retains_its_narrow_allowlist_and_applies_additional_protection(
    deployment_policy, settings_env
):
    assert deployment_policy.pfsense_allowed_networks == (LAB_SOURCE + "/32",)
    adapter = PfSenseAdapter(deployment_policy)
    assert adapter.validate_target(LAB_SOURCE) == ipaddress.IPv4Address(LAB_SOURCE)
    with pytest.raises(ValueError, match="Protected or invalid source IP"):
        adapter.validate_target("192.168.119.158")
    with pytest.raises(ValueError, match="outside the authorized pfSense lab scope"):
        adapter.validate_target("10.100.27.11")

    # An explicit deny overrides even the allowed lab source.
    settings_env.setenv("PROTECTED_NETWORKS", LAB_SOURCE + "/32")
    protected_lab = Settings.from_env()
    protected_lab.validate()
    with pytest.raises(ValueError, match="Protected or invalid source IP"):
        PfSenseAdapter(protected_lab).validate_target(LAB_SOURCE)

    settings_env.setenv("PFSENSE_ALLOWED_NETWORKS", "10.100.27.0/24")
    with pytest.raises(ValueError, match="exceeds the initial authorized lab scope"):
        Settings.from_env().validate()


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
