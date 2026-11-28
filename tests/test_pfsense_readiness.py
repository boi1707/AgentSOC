import logging
import ssl
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from integrations.shuffle.agentsoc_bridge import query_text
from src import worker
from src.api.main import create_app
from src.response_adapters import BlockPlan, PfSenseAdapter, PfSenseObservation, PfSenseReadError
from src.settings import Settings
from tests.test_assistant_control import command, signed, telegram_settings

ALIAS = "AGENTSOC_BLOCKLIST"
TARGET = "10.100.27.10"
KEY = "disposable-read-test-key"


@pytest.fixture
def read_settings(tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_text(KEY + "\n", encoding="ascii")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    def make_context(*, cafile):
        assert cafile == "fixture-ca"
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        return context

    monkeypatch.setattr(ssl, "create_default_context", make_context)
    return Settings(
        pfsense_url="https://firewall.invalid",
        pfsense_hostname="Firewall.Invalid",
        pfsense_ca_file="fixture-ca",
        pfsense_api_key_file=str(key),
    )


def envelope(data):
    return httpx.Response(200, json={"code": 200, "status": "ok", "data": data})


def test_pfrest_read_contract_and_independent_verification_states(read_settings):
    observed_requests = []

    def serve(request):
        observed_requests.append(request)
        assert request.method == "GET"
        assert request.url.host == "firewall.invalid"
        assert request.headers["X-API-Key"] == KEY
        assert request.headers["Accept-Encoding"] == "identity"
        if request.url.path.endswith("/aliases"):
            assert request.url.params["name"] == ALIAS
            return envelope([{"id": 12, "name": ALIAS, "type": "host", "address": [TARGET, "10.100.27.20"]}])
        if request.url.path.endswith("/apply"):
            return envelope({"applied": False, "pending_subsystems": ["aliases"]})
        assert request.url.path == "/api/v2/diagnostics/table"
        assert request.url.params["id"] == ALIAS
        return envelope({"id": ALIAS, "name": ALIAS, "entries": [TARGET + "/32", "2001:db8::1"]})

    adapter = PfSenseAdapter(read_settings, transport=httpx.MockTransport(serve))
    assert adapter.observe(TARGET) == PfSenseObservation(12, True, True, False)
    for operation in (adapter.block, adapter.remove):
        with pytest.raises(RuntimeError, match="disabled"):
            operation(BlockPlan("proposal", TARGET, 86400, ()))
    assert len(observed_requests) == 3


@pytest.mark.parametrize("status", [301, 401, 403, 429, 500, 503])
def test_http_failure_never_redirects_or_reports_server_content(read_settings, status, caplog):
    calls = []

    def serve(request):
        calls.append(request)
        return httpx.Response(status, text=KEY, headers={"Location": "https://other.invalid"})

    with pytest.raises(PfSenseReadError, match=f"HTTP {status}") as caught:
        PfSenseAdapter(read_settings, transport=httpx.MockTransport(serve)).observe(TARGET)
    assert len(calls) == 1
    assert KEY not in str(caught.value) + caplog.text


def test_adapter_suppresses_wire_logs_and_restores_normal_logging(read_settings, caplog):
    trace = logging.getLogger("httpcore.http11")

    def serve(request):
        trace.debug("response echoed x-api-key: %s", request.headers["X-API-Key"])
        return httpx.Response(403)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(PfSenseReadError):
            PfSenseAdapter(read_settings, transport=httpx.MockTransport(serve)).observe(TARGET)
        trace.debug("diagnostics finished")
    assert KEY not in caplog.text
    assert "diagnostics finished" in caplog.text


@pytest.mark.parametrize("exception", [httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout])
def test_transport_failures_are_sanitized(read_settings, exception):
    def serve(request):
        raise exception(KEY, request=request)

    with pytest.raises(PfSenseReadError) as caught:
        PfSenseAdapter(read_settings, transport=httpx.MockTransport(serve)).observe(TARGET)
    assert KEY not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize(
    "options",
    [
        {"pfsense_api_key_file": "missing"},
        {"ingest_key": KEY},
        {"pfsense_url": "http://firewall.invalid"},
        {"pfsense_url": "https://different.invalid"},
        {"pfsense_allowed_networks": ("10.100.27.0/24",)},
        {"pfsense_alias": "SOME_OTHER_ALIAS"},
    ],
)
def test_invalid_configuration_denies_before_network(read_settings, options):
    def serve(_):
        pytest.fail("unexpected HTTP request")

    adapter = PfSenseAdapter(replace(read_settings, **options), transport=httpx.MockTransport(serve))
    with pytest.raises((ValueError, PfSenseReadError)) as caught:
        adapter.observe(TARGET)
    assert KEY not in str(caught.value)


@pytest.mark.parametrize(
    "source_ip",
    [
        "10.8.0.1",
        "172.22.50.10",
        "192.168.119.1",
        "10.100.27.254",
        "127.0.0.1",
        "169.254.1.2",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "10.100.27.11",
        "bad-ip",
    ],
)
def test_target_must_be_inside_authorized_lab_scope(read_settings, source_ip):
    with pytest.raises(ValueError):
        PfSenseAdapter(read_settings).validate_target(source_ip)
    with pytest.raises(ValueError, match="Protected"):
        PfSenseAdapter(read_settings).validate_target(TARGET, (TARGET + "/32",))


def test_invalid_alias_or_runtime_read_cannot_be_treated_as_verified(read_settings):
    valid_alias = {"id": 12, "name": ALIAS, "type": "host", "address": [TARGET]}
    valid_apply = {"applied": True, "pending_subsystems": []}
    for responses in (
        [envelope([valid_alias, valid_alias])],
        [envelope([{**valid_alias, "name": "OTHER"}])],
        [envelope([valid_alias]), envelope({"applied": True, "pending_subsystems": ["filter"]})],
        [
            envelope([valid_alias]),
            envelope(valid_apply),
            envelope({"name": ALIAS, "id": "OTHER", "entries": []}),
        ],
        [
            envelope([valid_alias]),
            envelope(valid_apply),
            envelope({"name": ALIAS, "id": ALIAS, "entries": ["oops"]}),
        ],
        [httpx.Response(200, text="not JSON")],
        [httpx.Response(200, json={"code": 403, "data": []})],
    ):
        pending = iter(responses)
        with pytest.raises(PfSenseReadError):
            PfSenseAdapter(read_settings, transport=httpx.MockTransport(lambda _: next(pending))).observe(
                TARGET
            )


def test_unapplied_membership_is_distinct_from_runtime_absence(read_settings):
    responses = iter(
        [
            envelope([{"id": 12, "name": ALIAS, "type": "host", "address": [TARGET]}]),
            envelope({"applied": False, "pending_subsystems": ["aliases"]}),
            envelope({"name": ALIAS, "id": ALIAS, "entries": []}),
        ]
    )
    adapter = PfSenseAdapter(read_settings, transport=httpx.MockTransport(lambda _: next(responses)))
    assert adapter.observe(TARGET) == PfSenseObservation(12, True, False, False)


def test_mutation_is_disabled_even_if_requested(settings):
    assert settings.response_mode == "dry-run"
    assert settings.pfsense_live_enabled is False
    settings.validate()
    for options in ({"response_mode": "pfsense"}, {"pfsense_live_enabled": True}):
        with pytest.raises(ValueError, match="mutation is unavailable"):
            replace(settings, **options).validate()


@pytest.mark.parametrize("options", [{"response_mode": "pfsense"}, {"pfsense_live_enabled": True}])
def test_backend_and_worker_reject_live_before_service_initialization(settings, monkeypatch, options):
    config = replace(settings, **options)

    def unexpected_initialization(*args, **kwargs):
        pytest.fail("Live configuration reached service initialization")

    monkeypatch.setattr("src.api.main.Service", unexpected_initialization)
    monkeypatch.setattr(worker, "Service", unexpected_initialization)
    monkeypatch.setattr(worker.Settings, "from_env", lambda: config)
    with pytest.raises(ValueError, match="no_verified_write_transport"):
        worker.main()
    with pytest.raises(ValueError, match="no_verified_write_transport"), TestClient(create_app(config)):
        pass


def test_status_separates_dry_run_from_pfrest_diagnostics(console, settings, monkeypatch):
    telegram_settings(settings)

    def unexpected_probe(*args):
        pytest.fail("Status must never contact the firewall")

    monkeypatch.setattr(PfSenseAdapter, "observe", unexpected_probe)
    expected = {"live_available": False, "reason": "no_verified_write_transport"}
    for path in ("/health", "/api/v1/system"):
        status = console.get(path).json()
        assert status["response_mode"] == "dry-run" and status["pfsense_enforcement"] == expected
    for language, message in (
        ("en", "Live pfSense enforcement unavailable."),
        ("vi", "Không thể chặn trực tiếp qua pfSense."),
    ):
        reply = signed(
            console, settings, {**command("/status", update=language), "language": language}
        ).json()
        assert reply["system"]["pfsense_enforcement"] == expected
        assert message in query_text(reply)
