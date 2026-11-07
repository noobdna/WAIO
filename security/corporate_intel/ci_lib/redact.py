"""Secret redaction: the last filter on every line/report this module
emits. P1 runs keyless, so nothing secret should ever reach here -- this
is defense in depth, and tests/corporate_intel/test_secret_leak.py
proves it with a canary value."""

import os
import re

# env vars whose VALUES must never appear in output
_SECRET_ENV_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)", re.I)
_MIN_SECRET_LEN = 8
_PATTERNS = [
    re.compile(r"(?i)(apikey|api[_-]key|authorization|x-api-key)(\"?\s*[:=]\s*)(\"?)[^\s\",}&]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
]
MASK = "[REDACTED]"


def secret_values(environ=None):
    env = os.environ if environ is None else environ
    return sorted({v for k, v in env.items()
                   if _SECRET_ENV_RE.search(k) and isinstance(v, str) and len(v) >= _MIN_SECRET_LEN},
                  key=len, reverse=True)


def redact(text, environ=None):
    if not isinstance(text, str):
        text = str(text)
    for v in secret_values(environ):
        text = text.replace(v, MASK)
    # bearer first, so "Authorization: Bearer <tok>" masks the token, not just the scheme
    text = _PATTERNS[1].sub(lambda m: f"{m.group(1)}{MASK}", text)
    text = _PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{MASK}", text)
    return text
