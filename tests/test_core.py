import json

import httpx
import pytest

from src.agents import analyze
from src.anon import Anon
from src.incident import Grouper, norm
from src.llm import LLM, Blocked
from src.service import Service
from src.storage import Store
from tests.conftest import snort, windows


def test_anon_roundtrip():
    text = r"win-victim DESKTOP-HS8N3J7 C:\Users\vana\x admin@example.com 10.8.0.3 45.33.32.156"
    anon = Anon()
    safe = anon.clean(text)
    assert anon.restore(safe) == text
    assert "45.33.32.156" in safe and "10.8.0.3" not in safe
    assert not anon.leaks(safe)


@pytest.mark.parametrize(
    "value",
    [
        "169.254.1.5",
        "127.0.0.1",
        "172.31.1.2",
        "fd00::1",
        "fe80::1234",
        "::1",
        "sk-abcdefghijklmnop1234",
        "a@b.vn",
    ],
)
def test_guard_independent_of_mapping(value):
    assert Anon().leaks(value)
    assert value not in Anon().clean(value)


def test_structured_user_hostname_and_keys():
    anon = Anon()
    safe = anon.obj({"user": "CONTOSO\\alice", "hostname": "server-123", "10.8.0.3": "x"})
    assert "CONTOSO" not in json.dumps(safe) and "server-123" not in json.dumps(safe)
    assert "10.8.0.3" not in safe


def test_guard_prevents_network(settings, monkeypatch):
    settings.llm_mode = "live"
    llm = LLM(settings, Store(settings.db), post=lambda *a, **k: pytest.fail("Network called"))
    monkeypatch.setattr(Anon, "obj", lambda self, obj: obj)
    with pytest.raises(Blocked):
        llm.ask(Anon(), "c1", "net", "JSON", {"ip": "192.168.1.5"}, [])


def test_system_prompt_also_scanned(settings, monkeypatch):
    llm = LLM(settings, Store(settings.db))
    monkeypatch.setattr(Anon, "obj", lambda self, obj: obj)
    with pytest.raises(Blocked):
        llm.ask(Anon(), "c1", "net", "user admin@example.com", [], [])


def test_source_addresses_kept():
    row, ips = norm(snort())
    assert row["src_ip"] == "192.168.20.50" and "192.168.10.20" in ips


def test_merge_gap_quiet_and_high():
    group = Grouper()
    group.add(snort(), 0)
    group.add(windows(level=10), 10)
    assert len(group.inc) == 1 and group.ready(39) == []
    assert len(group.ready(40)) == 1
    group.add(snort("n2"), 50)
    group.add(snort("n3"), 700)
    assert len(group.inc) == 2
    group.add(windows(), 701)
    assert len(group.ready(702)) == 2


def test_dedupe_cap_preserves_high_evidence():
    group = Grouper()
    for n in range(5):
        group.add(snort(str(n)), 0)
    for n in range(60):
        alert = snort("x" + str(n))
        alert["rule"]["id"] = str(n)
        group.add(alert, 0)
    group.add(windows(), 0)
    incident = group.ready(31)[0]
    assert len(incident["alerts"]) == 40 and incident["dropped_rows"] == 22
    assert incident["alerts"][0]["kind"] == "host"
    assert any(a["count"] == 5 for a in incident["alerts"])


def test_different_sources_not_deduped():
    group = Grouper()
    group.add(snort("a"), 0)
    group.add(snort("b", src="192.168.20.51"), 0)
    assert len(group.ready(31)[0]["alerts"]) == 2


def test_bridge_merges_incidents():
    group = Grouper()
    group.add(snort("a", src="192.168.1.1", dst="192.168.1.2"), 0)
    group.add(snort("b", src="192.168.2.1", dst="192.168.2.2"), 1)
    group.add(snort("c", src="192.168.1.1", dst="192.168.2.2"), 2)
    assert len(group.inc) == 1


def test_sensor_management_ip_does_not_merge_unrelated_flows():
    group = Grouper()
    first = snort("a", src="192.168.1.1", dst="192.168.1.2")
    second = snort("b", src="192.168.2.1", dst="192.168.2.2")
    first["agent"] = second["agent"] = {"ip": "10.8.0.2"}
    group.add(first, 0)
    group.add(second, 1)
    assert len(group.inc) == 2


def test_restart_queue_and_ledger(settings):
    service = Service(settings)
    assert service.store.ingest(snort(), 0)
    assert not service.store.ingest(snort(), 1)
    service.store.ingest(windows(), 1)
    # New service instance reads persisted alerts and creates exactly one case.
    restarted = Service(settings)
    restarted.tick(40)
    restarted.tick(50)
    cases = restarted.store.cases()
    assert len(cases) == 1 and cases[0]["verdict"]["verdict"] == "attack"
    with restarted.store.connect() as db:
        ledger = db.execute("SELECT * FROM ledger").fetchall()
    assert len(ledger) == 6
    assert sum(r["agent"] == "tool" for r in ledger) == 3
    for row in ledger:
        assert row["mode"] == "mock" and not row["error"]
        assert "192.168." not in row["prompt"] and "vana" not in row["prompt"]


def test_malformed_live_output_is_audited(settings):
    settings.llm_mode = "live"

    def post(*args, **kwargs):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "not JSON"}}]},
            request=httpx.Request("POST", "https://example.com"),
        )

    store = Store(settings.db)
    llm = LLM(settings, store, post=post)
    with pytest.raises(ValueError):
        llm.ask(Anon(), "c1", "net", "JSON", [], [])
    with store.connect() as db:
        assert db.execute("SELECT error FROM ledger").fetchone()[0] == "JSONDecodeError"


def test_live_schema_failure_is_audited(settings):
    settings.llm_mode = "live"

    def post(*args, **kwargs):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"unexpected":"value"}'}}]},
            request=httpx.Request("POST", "https://example.com"),
        )

    store = Store(settings.db)
    with pytest.raises(ValueError):
        LLM(settings, store, post=post).ask(Anon(), "c1", "net", "JSON", [], [])
    with store.connect() as db:
        assert db.execute("SELECT error FROM ledger").fetchone()[0] == "ValidationError"


def test_runtime_secrets_are_masked_even_without_a_vendor_key_pattern(settings):
    secret = settings.ingest_key
    store = Store(settings.db)
    LLM(settings, store).ask(Anon(), "guarded", "net", "JSON", [{"id": "1", "description": secret}], ["1"])
    with store.connect() as db:
        prompt = db.execute("SELECT prompt FROM ledger").fetchone()[0]
    assert secret not in prompt and "SECRET_" in prompt


@pytest.mark.parametrize("confidence,ids", [(0.5, ["n1"]), (0.99, ["invented"]), (0.99, ["n1", "invented"])])
def test_downgrade_ungrounded_or_low_confidence(settings, confidence, ids):
    class Fake:
        def ask(self, anon, cid, role, system, payload, evidence):
            if role != "judge":
                return {"finding": "test", "evidence_ids": evidence}
            return {
                "verdict": "attack",
                "confidence": confidence,
                "evidence_ids": ids,
                "block_ip": "192.168.20.50",
            }

    fake = Fake()
    fake.settings = settings
    group = Grouper()
    group.add(snort(), 0)
    verdict = analyze(group.ready(31)[0], Anon(), "c", fake)
    assert verdict["verdict"] == "review" and verdict["block_ip"] is None


def test_live_failure_falls_back_to_review(settings):
    service = Service(settings)
    service.store.ingest(windows(), 0)
    service.llm.post = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("secret payload"))
    settings.llm_mode = "live"
    service.tick(1)
    verdict = service.store.cases()[0]["verdict"]
    assert verdict["verdict"] == "review" and "secret payload" not in verdict["reason"]
