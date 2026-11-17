"""Container-local real HTTP probe; no published ports or credentials on stdout."""

import argparse
import http.cookiejar
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


class SessionClient:
    def __init__(self, base="http://127.0.0.1:8000", *, opener=None):
        self.base = base
        self.csrf = ""
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(self, path, payload=None, *, headers=None, expected=200):
        request_headers = {"Content-Type": "application/json", "X-CSRF-Token": self.csrf, **(headers or {})}
        raw = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=raw, headers=request_headers)
        try:
            response = self.opener.open(req, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            assert response.code == expected, f"Unexpected HTTP status for {path}: {response.code}"
            return json.load(response)


def wait_for(check, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return check()
        except (AssertionError, urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(1)
    raise AssertionError("Container-local HTTP readiness deadline exceeded")


def health(client):
    assert client.request("/live")["status"] == "alive"
    assert client.request("/health")["response_mode"] == "dry-run"
    return True


def validate_api(client, dataset):
    assert os.environ.get("RESPONSE_MODE") == "dry-run"
    wait_for(lambda: health(client))
    wait_for(lambda: client.request("/ready"))
    client.request("/api/v1/incidents", expected=401)
    client.csrf = client.request(
        "/api/v1/auth/login",
        {
            "username": "admin",
            "password": "lab-review-" + "r" * 32,
        },
    )["csrf"]
    cases = client.request("/api/v1/incidents")["items"]
    assert len(cases) == 2
    pending = next(case for case in cases if case["status"] == "pending")
    question = {"message": "why", "incident_id": pending["id"]}
    # Demonstrate that the real HTTP session and CSRF checks remain enforced.
    client.request("/api/v1/assistant/query", question, headers={"X-CSRF-Token": "invalid"}, expected=403)
    assert client.request("/api/v1/assistant/query", question)["citations"]
    body = {"decision": "approve", "run_id": pending["latest_run_id"]}
    path = "/api/v1/incidents/" + pending["id"] + "/response"
    outcome = client.request(path, body)
    assert outcome["status"] == "dry_run" and outcome["blocked"] is False
    assert outcome["verification_status"] == "not_verified"
    client.request(path, body, expected=409)
    detail = client.request("/api/v1/incidents/" + pending["id"])
    assert len(detail["actions"]) == 1 and detail["actions"][0]["actor"] == "admin"
    assert detail["actions"][0]["mode"] == "dry-run"
    for line in Path(dataset).read_text(encoding="utf-8").splitlines():
        client.request(
            "/ingest",
            json.loads(line),
            headers={"Authorization": "Bearer " + os.environ["INGEST_KEY"]},
            expected=202,
        )

    def processed():
        rows = client.request("/api/v1/incidents")["items"]
        assert len(rows) >= 3 and any(case["status"] == "pending" for case in rows)
        return True

    wait_for(processed)
    return {
        "health": "PASS",
        "session_csrf": "PASS",
        "incident_assistant_api": "PASS",
        "dry_run_approval": "PASS",
        "ingestion_worker": "PASS",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--health-only", action="store_true")
    args = parser.parse_args()
    client = SessionClient()
    try:
        if args.health_only:
            wait_for(lambda: health(client), timeout=45)
            result = {"health": "PASS"}
        else:
            result = validate_api(client, "/app/datasets/demo.jsonl")
        print(json.dumps(result))
    except Exception as exc:
        # HTTP errors can contain session cookies/credentials; never dump exception values or locals.
        print(json.dumps({"status": "FAIL", "error_type": type(exc).__name__}))
        raise SystemExit(1) from None
