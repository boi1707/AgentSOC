"""Reversible pseudonymization; pattern matching is not a universal PII detector."""

import ipaddress
import re

SECRET = re.compile(r"\b(?:sk[-_]|gh[pousr]_|github_pat_|xox[baprs]-|AIza)[A-Za-z0-9_-]{12,}")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])\[?(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9:.]*\]?(?![\w:])")
USER = re.compile(r"(?i)(?<=Users[\\/])[^\\/\s\"<>]+|(?<=/home/)[^/\s\"<>]+")
TOKEN = re.compile(r"\b(?:INT_IP|SECRET|MAIL|HOST|USER)_\d{4,}\b")
SENSITIVE_KEYS = {
    "user",
    "username",
    "user_name",
    "hostname",
    "computer",
    "computername",
    "password",
    "token",
    "apikey",
    "api_key",
    "authorization",
}


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
        for value in self.secrets:
            if value in text:
                text = text.replace(value, self.tok("SECRET", value))
        # Structured host/user fields may introduce names not in HOST_NAMES.
        # Reuse their existing token when the same entity appears in tool arguments or prose.
        for value in sorted(self.fwd, key=len, reverse=True):
            if value:
                text = re.sub(r"(?<!\w)" + re.escape(value) + r"(?!\w)", lambda _: self.fwd[value], text)
        for kind, pattern in (("SECRET", SECRET), ("MAIL", EMAIL), ("HOST", self.host), ("USER", USER)):
            text = pattern.sub(lambda m: self.tok(kind, m.group()), text)

        def mask_ip(match):
            try:
                return self.tok("INT_IP", match.group()) if internal(match.group()) else match.group()
            except ValueError:
                return match.group()

        return IPV4.sub(mask_ip, IPV6.sub(mask_ip, text))

    def obj(self, value):
        if isinstance(value, str):
            return self.clean(value)
        if isinstance(value, list):
            return [self.obj(item) for item in value]
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                if key.lower() in SENSITIVE_KEYS and isinstance(item, str) and item:
                    kind = (
                        "USER"
                        if "user" in key.lower()
                        else "HOST"
                        if key.lower() in {"hostname", "computer", "computername"}
                        else "SECRET"
                    )
                    out[self.clean(key)] = self.tok(kind, item)
                else:
                    out[self.clean(key)] = self.obj(item)
            return out
        return value

    def leaks(self, text):
        found = [v for v in (*self.fwd, *self.secrets) if v and v in text]
        for pattern in (SECRET, EMAIL, self.host, USER):
            found.extend(m.group() for m in pattern.finditer(text) if not TOKEN.fullmatch(m.group()))
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
