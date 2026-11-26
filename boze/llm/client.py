"""boze/llm/client.py -- BOZE client for the local llama-server (U1).

Loopback only, by construction:
  * base_url must be exactly http://127.0.0.1:<port> -- no hostname
    (so no DNS), no https, no userinfo, no path, no query.
  * Requests go through http.client.HTTPConnection, which never reads
    HTTP(S)_PROXY / ALL_PROXY and never follows redirects.
  * Response bodies are read with a hard byte cap; prompts are capped too.
  * The API key is sent only as "Authorization: Bearer" and is never
    included in repr(), exceptions or return values.

Python 3.9 standard library only.
"""

import http.client
import json
import socket
import urllib.parse

from boze.llm import schema as _schema

DEFAULT_URL = "http://127.0.0.1:8081"
LOOPBACK = "127.0.0.1"


class LLMError(Exception):
    """Any failure talking to the local LLM."""


class LLMConfigError(LLMError):
    """Refused configuration (e.g. a non-loopback URL)."""


class LLMAuthError(LLMError):
    """The server rejected the API key (HTTP 401/403)."""


class LLMTimeout(LLMError):
    """The server did not answer within the timeout."""


class LLMResponseError(LLMError):
    """Malformed, oversized or schema-invalid response."""


def parse_loopback_url(url):
    """Return the port of a strict http://127.0.0.1:<port> URL or raise."""
    if not isinstance(url, str):
        raise LLMConfigError("base_url must be a string")
    u = urllib.parse.urlsplit(url)
    if u.scheme != "http":
        raise LLMConfigError("only http:// to 127.0.0.1 is allowed")
    if u.username is not None or u.password is not None or "@" in u.netloc:
        raise LLMConfigError("userinfo is not allowed in base_url")
    if u.path not in ("", "/") or u.query or u.fragment:
        raise LLMConfigError("base_url must not have a path, query or fragment")
    if u.hostname != LOOPBACK or not u.netloc.startswith(LOOPBACK + ":"):
        raise LLMConfigError("host must be the literal 127.0.0.1")
    try:
        port = u.port
    except ValueError:
        raise LLMConfigError("invalid port")
    if port is None or not 1 <= port <= 65535:
        raise LLMConfigError("an explicit port is required")
    return port


class LLMClient:
    def __init__(self, base_url=DEFAULT_URL, api_key=None, timeout=180.0,
                 max_response_bytes=2 * 1024 * 1024, max_prompt_chars=32000):
        self.port = parse_loopback_url(base_url)
        if api_key is not None:
            if not isinstance(api_key, str) or not api_key or any(
                    ord(c) < 33 or ord(c) == 127 for c in api_key):
                raise LLMConfigError("api_key must be a non-empty printable token")
        self._api_key = api_key
        self.timeout = float(timeout)
        self.max_response_bytes = int(max_response_bytes)
        self.max_prompt_chars = int(max_prompt_chars)

    def __repr__(self):
        return "LLMClient(port=%d, api_key=%s, timeout=%.0f)" % (
            self.port, "<set>" if self._api_key else "<none>", self.timeout)

    # -- transport ---------------------------------------------------------
    def _request(self, method, path, body=None):
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self._api_key:
            headers["Authorization"] = "Bearer " + self._api_key
        conn = http.client.HTTPConnection(LOOPBACK, self.port, timeout=self.timeout)
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(self.max_response_bytes + 1)
            status = resp.status
        except socket.timeout:
            raise LLMTimeout("no answer from 127.0.0.1:%d within %.0fs" % (self.port, self.timeout))
        except (OSError, http.client.HTTPException) as e:
            raise LLMError("request to 127.0.0.1:%d failed: %s" % (self.port, type(e).__name__))
        finally:
            conn.close()
        if len(raw) > self.max_response_bytes:
            raise LLMResponseError("response larger than %d bytes" % self.max_response_bytes)
        if status in (401, 403):
            raise LLMAuthError("server rejected the API key (HTTP %d)" % status)
        if status != 200:
            raise LLMError("HTTP %d from local LLM" % status)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise LLMResponseError("response is not valid JSON")

    # -- API ---------------------------------------------------------------
    def health(self):
        """True when llama-server reports ok."""
        try:
            r = self._request("GET", "/health")
        except LLMError:
            return False
        return isinstance(r, dict) and r.get("status") == "ok"

    def chat(self, messages, max_tokens=512, temperature=0.2, json_schema=None):
        """Return the assistant text, or the parsed+validated object when
        json_schema is given (validated locally even if the server enforced it)."""
        if not isinstance(messages, list) or not messages:
            raise LLMConfigError("messages must be a non-empty list")
        total = 0
        for m in messages:
            if not isinstance(m, dict) or m.get("role") not in ("system", "user", "assistant") \
                    or not isinstance(m.get("content"), str):
                raise LLMConfigError("each message needs role and string content")
            total += len(m["content"])
        if total > self.max_prompt_chars:
            raise LLMConfigError("prompt longer than %d chars" % self.max_prompt_chars)
        body = {"messages": messages, "max_tokens": int(max_tokens),
                "temperature": float(temperature), "stream": False}
        if json_schema is not None:
            _schema.validate({}, json_schema)  # raises SchemaError on unsupported schema
            body["response_format"] = {"type": "json_object", "schema": json_schema}
        r = self._request("POST", "/v1/chat/completions", body)
        try:
            text = r["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise LLMResponseError("unexpected response shape")
        if not isinstance(text, str):
            raise LLMResponseError("content is not a string")
        if json_schema is None:
            return text
        try:
            obj = json.loads(text)
        except ValueError:
            raise LLMResponseError("model output is not valid JSON")
        errs = _schema.validate(obj, json_schema)
        if errs:
            raise LLMResponseError("model output fails schema: " + "; ".join(errs[:5]))
        return obj
