import pytest

from src.settings import Settings


def pytest_addoption(parser):
    parser.addoption(
        "--live-provider",
        action="store_true",
        default=False,
        help="Explicitly allow a paid HTTPS LLM request in the opt-in live test",
    )


@pytest.fixture
def settings(tmp_path):
    return Settings(db=str(tmp_path / "test.db"), ingest_key="i" * 32, approve_key="r" * 32)


def snort(aid="n1", level=8, src="192.168.20.50", dst="192.168.10.20"):
    return {
        "id": aid,
        "rule": {"id": "100010", "level": level},
        "data": {"src_addr": src, "dst_addr": dst, "msg": "scan", "dst_port": 445},
    }


def windows(aid="h1", level=12):
    return {
        "id": aid,
        "rule": {"id": "100020", "level": level},
        "agent": {"ip": "10.8.0.3", "name": "win-victim"},
        "data": {
            "win": {
                "eventdata": {
                    "image": r"C:\Users\vana\x.exe",
                    "user": "CONTOSO\\vana",
                    "commandLine": "powershell -enc AAAA",
                }
            }
        },
    }
