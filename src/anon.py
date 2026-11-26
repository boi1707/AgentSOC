"""Reversible pseudonymization; pattern matching is not a universal PII detector."""

import ipaddress
import json
import re

SECRET = re.compile(r"\b(?:sk[-_]|gh[pousr]_|github_pat_|xox[baprs]-|AIza)[A-Za-z0-9_-]{12,}")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])\[?(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9:.]*\]?(?![\w:])")
USER = re.compile(r"(?i)(?<=Users[\\/])[^\\/\s\"<>]+|(?<=/home/)[^/\s\"<>]+")
ACCOUNT = re.compile(
    r"(?<![\w:\\])(?!(?i:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR|HKCC)\\)(?:NT AUTHORITY|[A-Za-z][A-Za-z0-9_.-]{1,63})\\{1,2}[A-Za-z0-9$_.@-]+(?![\w\\])"
)
SID = re.compile(r"\bS-1-5-21-(?:\d+-){2,}\d+\b", re.I)
DNS = re.compile(r"\b(?:[a-z0-9_-]+\.)+(?:local|internal|intra|corp|lan|home|test)\.?\b", re.I)
UNC = re.compile(r"(?<!\\)\\{2,4}([^\\/\s\"<>]+)(?=[\\/])")
ARG_SECRET = re.compile(
    r"(?i)(?P<prefix>(?<!\w)(?:(?:--?|/)(?:password|passwd|pwd|token|api[_-]?key|secret|credential)(?:\s*[:=]\s*|\s+)"
    r"|(?:password|passwd|pwd|token|api[_-]?key|secret|credential)\s*[:=]\s*))"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
BEARER = re.compile(r"(?i)(\bBearer\s+)([A-Za-z0-9._~+/=-]+)")
ARG_USER = re.compile(r"(?i)(?<!\w)(?:--?|/)(?:user(?:name)?|account)(?:\s*[:=]\s*|\s+)([A-Za-z0-9@_.\\-]+)")
TOKEN = re.compile(r"\b(?:INT_IP|SECRET|MAIL|HOST|USER)_\d{4,}\b")
SENSITIVE_KEYS = {
    "user",
    "username",
    "user_name",
    "parentuser",
    "hostname",
    "computer",
    "computername",
    "password",
    "token",
    "apikey",
    "api_key",
    "authorization",
}
HOST_KEYS = {"hostname", "computer", "computername"}
USER_KEYS = {"user", "username", "user_name", "parentuser"}
# Schema names and message-role values are structure, not incident identities.
SCHEMA_KEYS = SENSITIVE_KEYS | {
    "role",
    "content",
    "id",
    "evidence_ids",
    "raw_ids",
    "run_id",
    "case_id",
    "incident_id",
    "source",
    "name",
    "items",
    "evidence",
    "alerts",
    "finding",
    "reason",
    "verdict",
    "mode",
}
STRUCTURE = {
    "role": {"system", "user", "assistant", "tool"},
    "kind": {"net", "host", "generic"},
    "verdict": {"attack", "benign", "review"},
    "mode": {"live", "mock", "dry-run", "ssh"},
    "status": {"queued", "running", "completed", "failed", "skipped", "pending", "review"},
}
RESERVED = (
    SCHEMA_KEYS
    | set(STRUCTURE)
    | set().union(*STRUCTURE.values())
    | {"judge", "sha256", "sha1", "md5", "imphash", "sha512"}
)


def structural(key, value):
    return isinstance(value, str) and value in STRUCTURE.get(key, ())


def internal(value):
    ip = ipaddress.ip_address(value.strip("[]"))
    return ip.version == 6 or not ip.is_global


class Anon:
    def __init__(self, hosts=("win-victim", "gateway", "kali"), *, secrets=()):
        self.fwd, self.rev, self.count = {}, {}, {}
        self.secrets = tuple(v for v in secrets if v)
        names = [re.escape(h) for h in hosts if h]
        self.host = re.compile(
            r"\b(?:DESKTOP-[A-Z0-9]{5,}" + ("|" + "|".join(names) if names else "") + r")\b", re.I
        )

    def tok(self, kind, value):
        if TOKEN.fullmatch(value):
            return value
        if value not in self.fwd:
            self.count[kind] = self.count.get(kind, 0) + 1
            token = f"{kind}_{self.count[kind]:04d}"
            self.fwd[value], self.rev[token] = token, value
        return self.fwd[value]

    def clean(self, text):
        for value in sorted(self.secrets, key=len, reverse=True):
            if value in text:
                text = text.replace(value, self.tok("SECRET", value))
        # Structured host/user fields may introduce names not in HOST_NAMES.
        # Reuse their existing token when the same entity appears in tool arguments or prose.
        for value in sorted(self.fwd, key=len, reverse=True):
            if value and value.lower() not in RESERVED:
                text = re.sub(r"(?<!\w)" + re.escape(value) + r"(?!\w)", lambda _: self.fwd[value], text)
        text = ARG_SECRET.sub(lambda m: m["prefix"] + self.tok("SECRET", m["value"]), text)
        text = BEARER.sub(lambda m: m[1] + self.tok("SECRET", m[2]), text)
        text = ARG_USER.sub(lambda m: m[0].replace(m[1], self.tok("USER", m[1])), text)
        text = UNC.sub(lambda m: m[0].replace(m[1], self.tok("HOST", m[1])), text)
        for kind, pattern in (
            ("SECRET", SECRET),
            ("MAIL", EMAIL),
            ("HOST", self.host),
            ("USER", USER),
            ("USER", ACCOUNT),
            ("USER", SID),
            ("HOST", DNS),
        ):
            text = pattern.sub(
                lambda m: m[0] if kind == "HOST" and m[0].lower() in RESERVED else self.tok(kind, m.group()),
                text,
            )

        def mask_ip(match):
            try:
                return self.tok("INT_IP", match.group()) if internal(match.group()) else match.group()
            except ValueError:
                return match.group()

        return IPV4.sub(mask_ip, IPV6.sub(mask_ip, text))

    def obj(self, value):
        # Discover all identities before rendering any field. Dictionary order must not
        # decide whether a name leaks in prose or which token a sibling field receives.
        discovered = set()

        def discover(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    if isinstance(child, str) and child and key.lower() in SENSITIVE_KEYS:
                        kind = (
                            "HOST"
                            if key.lower() in HOST_KEYS
                            else "USER"
                            if key.lower() in USER_KEYS
                            else "SECRET"
                        )
                        discovered.add((kind, child))
                        if kind == "USER":
                            part = re.split(r"[\\/]", child)[-1]
                            if (
                                len(part) >= 3
                                and not part.isdigit()
                                and part.upper() not in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
                            ):
                                discovered.add(("USER", part))
                    discover(child)
            elif isinstance(item, list):
                for child in item:
                    discover(child)
            elif isinstance(item, str):
                for kind, pattern in (
                    ("SECRET", SECRET),
                    ("MAIL", EMAIL),
                    ("HOST", self.host),
                    ("USER", USER),
                    ("USER", ACCOUNT),
                    ("USER", SID),
                    ("HOST", DNS),
                ):
                    discovered.update((kind, m[0]) for m in pattern.finditer(item))
                discovered.update(("HOST", m[1]) for m in UNC.finditer(item))
                discovered.update(("USER", m[1]) for m in ARG_USER.finditer(item))
                discovered.update(("SECRET", m["value"]) for m in ARG_SECRET.finditer(item))
                discovered.update(("SECRET", m[2]) for m in BEARER.finditer(item))

        discover(value)
        for secret in sorted(self.secrets, key=len, reverse=True):
            self.tok("SECRET", secret)
        for kind, item in sorted(discovered, key=lambda pair: (pair[0] != "SECRET", pair)):
            self.tok(kind, item)
        return self._obj(value)

    def _obj(self, value):
        if isinstance(value, str):
            return self.clean(value)
        if isinstance(value, list):
            return [self._obj(item) for item in value]
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                clean_key = key if key.lower() in RESERVED else self.clean(key)
                if structural(key, item):
                    out[clean_key] = item
                elif key.lower() in SENSITIVE_KEYS and isinstance(item, str) and item:
                    kind = (
                        "USER"
                        if key.lower() in USER_KEYS
                        else "HOST"
                        if key.lower() in {"hostname", "computer", "computername"}
                        else "SECRET"
                    )
                    out[clean_key] = self.tok(kind, item)
                else:
                    out[clean_key] = self._obj(item)
            return out
        return value

    def leaks(self, text):
        # Inspect actual string data, including serialized content, but not protocol
        # role labels/schema keys that may legitimately equal an account name.
        typed_leaks = []

        def strings(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key.lower() not in RESERVED and key not in STRUCTURE:
                        yield key
                    if (
                        key.lower() in SENSITIVE_KEYS
                        and isinstance(item, str)
                        and item
                        and not TOKEN.fullmatch(item)
                    ):
                        typed_leaks.append(item)
                    if not structural(key, item):
                        yield from strings(item)
            elif isinstance(value, list):
                for item in value:
                    yield from strings(item)
            elif isinstance(value, str):
                try:
                    parsed = json.loads(value)
                except (ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    yield from strings(parsed)
                else:
                    yield value

        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            parsed = text
        scanned = "\n".join(strings(parsed))
        found = typed_leaks + [v for v in self.secrets if v and (v in scanned or v in text)]
        text = TOKEN.sub("", scanned)
        found.extend(v for v in self.fwd if v and v.lower() not in RESERVED and v in text)
        for pattern in (SECRET, EMAIL, self.host, USER, ACCOUNT, SID, DNS):
            found.extend(
                m.group()
                for m in pattern.finditer(text)
                if not TOKEN.fullmatch(m.group()) and not (pattern is self.host and m[0].lower() in RESERVED)
            )
        found.extend(m[1] for m in UNC.finditer(scanned) if not TOKEN.fullmatch(m[1]))
        found.extend(m["value"] for m in ARG_SECRET.finditer(scanned) if not TOKEN.fullmatch(m["value"]))
        found.extend(m[2] for m in BEARER.finditer(scanned) if not TOKEN.fullmatch(m[2]))
        found.extend(m[1] for m in ARG_USER.finditer(scanned) if not TOKEN.fullmatch(m[1]))
        for pattern in (IPV4, IPV6):
            for match in pattern.finditer(text):
                try:
                    if internal(match.group()):
                        found.append(match.group())
                except ValueError:
                    pass
        return found

    def restore(self, text):
        return TOKEN.sub(lambda m: self.rev.get(m.group(), m.group()), text)
