import pytest

from scripts.gateway_block import target


@pytest.mark.parametrize(
    "command",
    [
        "id",
        "block 10.8.0.1",
        "block 192.168.10.20",
        "block 192.168.20.1",
        "block 192.168.20.255",
        "block 192.168.20.50; id",
        "block 192.168.20.50\nid",
    ],
)
def test_forced_command_rejects(command):
    with pytest.raises(ValueError):
        target(command)


def test_forced_command_accepts_lab_source():
    assert target("block 192.168.20.50") == "192.168.20.50"
