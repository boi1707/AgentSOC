import ipaddress
import subprocess

from .anon import Anon


def candidate(case, settings):
    verdict = case["verdict"]
    # Switching the service to live must not make old mock cases actionable.
    if settings.response_mode == "ssh" and verdict.get("mode") != "live":
        raise ValueError("Only live analysis cases can execute SSH blocking")
    if (
        verdict.get("verdict") != "attack"
        or verdict.get("confidence", 0) < settings.confidence
        or verdict.get("grounded", 0) != 1
    ):
        raise ValueError("Case is not eligible for blocking")
    anon = Anon(settings.hosts)
    anon.rev = case["restore"]
    ip = ipaddress.IPv4Address(anon.restore(verdict.get("block_ip") or ""))
    protected = (*settings.protected, settings.gateway + "/32")
    if (
        ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or any(ip in ipaddress.ip_network(n) for n in protected)
    ):
        raise ValueError("Protected or invalid blocking target")
    # Only a source address from a cited NETWORK alert, not just any incident IP.
    sources = {
        a.get("src_ip")
        for a in case["incident"]["alerts"]
        if a["kind"] == "net" and a["id"] in verdict.get("evidence_ids", [])
    }
    if str(ip) not in sources:
        raise ValueError("Target is not a cited network source")
    return str(ip)


def execute(ip, settings):
    if settings.response_mode == "dry-run":
        return "dry_run"
    process = subprocess.run(
        [
            "ssh",
            "-i",
            settings.ssh_key,
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + settings.known_hosts,
            "root@" + settings.gateway,
            "block " + ip,
        ],
        capture_output=True,
        timeout=15,
        check=False,
    )
    return "blocked" if process.returncode == 0 else "block_failed"
