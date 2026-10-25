#!/usr/bin/env python3
"""Install as root-owned /usr/local/bin/agentsoc-block on the Linux lab gateway.

SSH forced command only. The fixed subnet is intentionally limited to the Kali lab.
"""

import ipaddress
import os
import re
import subprocess
import sys


def target(command):
    match = re.fullmatch(r"block ([0-9.]+)", command)
    if not match:
        raise ValueError("Only block IPv4 is allowed")
    ip = ipaddress.IPv4Address(match[1])
    network = ipaddress.ip_network("192.168.20.0/24")
    if ip not in network or ip in {
        network.network_address,
        network.broadcast_address,
        ipaddress.ip_address("192.168.20.1"),
    }:
        raise ValueError("Target outside allowed lab attacker range")
    return str(ip)


def main():
    try:
        ip = target(os.getenv("SSH_ORIGINAL_COMMAND", ""))
    except ValueError:
        return 2
    return subprocess.run(
        ["/usr/sbin/nft", "add", "element", "inet", "agentsoc", "block", "{ " + ip + " timeout 1h }"],
        check=False,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
