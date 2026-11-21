"""HTTP client: polite, budgeted, audited, cache-backed (stdlib only).

One seam for all network I/O: a *transport* is a callable
``(url, headers, timeout) -> (status, body, error)``. The default is urllib.
Tests inject a fake transport, so the engine, every connector and the MCP server
all run offline through the same code path they use live.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

USER_AGENT = "osint-rail/2.0 (keyless research; +https://github.com/shattradingle/osint-rail)"
DEFAULT_TIMEOUT = 12.0
DEFAULT_HOST_INTERVAL = 1.0  # seconds between requests to the same host

# Statuses that mean "the source refused to answer", not "the subject is absent".
# 401/403 are the usual bot walls, 429 is a rate limit, 0 is DNS/TLS/timeout and
# the 5xx set is what a WAF or an overloaded origin returns instead of a page.
BLOCK_STATUSES = frozenset({0, 401, 403, 429, 500, 502, 503, 504})
# Retried only because they are transient server faults. 429 and 403 are never
# retried: a block is a stop, and retrying it turns a polite tool into a rude one.
RETRY_STATUSES = frozenset({0, 500, 502, 503, 504})

# transport(url, headers, timeout) -> (status, body, error)
Transport = Callable[[str, "dict[str, str]", float], "tuple[int, bytes, str]"]


class BudgetExceeded(Exception):
    """Raised when the per-case request/time budget is spent."""


@dataclass
class Response:
    url: str
    status: int
    body: bytes
    elapsed_ms: int
    error: str = ""
    from_cache: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def blocked(self) -> bool:
        """True when the answer says nothing about the subject either way."""
        return self.status in BLOCK_STATUSES

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.text())


def urllib_transport(url: str, headers: dict[str, str], timeout: float) -> tuple[int, bytes, str]:
    """Default transport. Returns (0, b'', reason) instead of raising."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(8_000_000), ""
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read() if exc.fp else b""
        except Exception:  # body already consumed or connection gone
            body = b""
        return exc.code, body, f"HTTP {exc.code}"
    except Exception as exc:  # timeouts, TLS, DNS, refused
        return 0, b"", str(exc)[:200]


class HttpClient:
    def __init__(
        self,
        max_requests: int = 120,
        max_seconds: float = 180.0,
        timeout: float = DEFAULT_TIMEOUT,
        host_interval: float = DEFAULT_HOST_INTERVAL,
        audit: Callable[[str, str, int, int], None] | None = None,
        connector: str = "",
        transport: Transport | None = None,
        retry_backoff: float = 0.6,
    ) -> None:
        self.max_requests = max_requests
        self.max_seconds = max_seconds
        self.timeout = timeout
        self.host_interval = host_interval
        self.audit = audit
        self.connector = connector
        self.transport: Transport = transport or urllib_transport
        self.retry_backoff = retry_backoff
        self.count = 0
        self.started = time.monotonic()
        self._host_last: dict[str, float] = {}
        self._host_count: dict[str, int] = {}
        self._host_locks: dict[str, threading.Lock] = {}
        self._cache: dict[str, Response] = {}
        self._lock = threading.Lock()

    # -- budget --------------------------------------------------------
    def _charge(self) -> None:
        with self._lock:
            if self.count >= self.max_requests:
                raise BudgetExceeded(f"request budget of {self.max_requests} spent")
            if time.monotonic() - self.started > self.max_seconds:
                raise BudgetExceeded(f"time budget of {self.max_seconds:.0f}s spent")
            self.count += 1

    def _throttle(self, host: str) -> None:
        lock = self._host_locks.setdefault(host, threading.Lock())
        with lock:
            last = self._host_last.get(host, 0.0)
            wait = self.host_interval - (time.monotonic() - last)
            if wait > 0:
                time.sleep(wait)
            self._host_last[host] = time.monotonic()
            self._host_count[host] = self._host_count.get(host, 0) + 1

    def host_stats(self) -> dict[str, dict[str, float]]:
        """Per-host request bookkeeping, for the audit trail and for tests."""
        with self._lock:
            return {
                host: {"requests": self._host_count.get(host, 0), "last": last}
                for host, last in self._host_last.items()
            }

    @property
    def elapsed_s(self) -> float:
        return round(time.monotonic() - self.started, 1)

    # -- fetch ---------------------------------------------------------
    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        connector: str | None = None,
        allow_404: bool = True,
        cache: bool = True,
        timeout: float | None = None,
        retries: int = 2,
    ) -> Response:
        if cache and url in self._cache:
            cached = self._cache[url]
            return Response(cached.url, cached.status, cached.body, cached.elapsed_ms,
                            cached.error, True)

        host = urllib.parse.urlsplit(url).netloc
        self._charge()
        self._throttle(host)

        req_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            req_headers.update(headers)

        started = time.monotonic()
        status, body, error = 0, b"", ""
        attempts = 0
        max_attempts = 1 + max(0, retries)
        while attempts < max_attempts:
            attempts += 1
            status, body, error = self.transport(url, req_headers, timeout or self.timeout)
            if status in RETRY_STATUSES and attempts < max_attempts:
                time.sleep(self.retry_backoff * attempts)
                continue
            break

        elapsed_ms = int((time.monotonic() - started) * 1000)
        resp_obj = Response(url, status, body, elapsed_ms, error)
        if resp_obj.ok and cache:
            with self._lock:
                self._cache[url] = resp_obj
        if self.audit:
            try:
                self.audit(connector or self.connector, url, status, elapsed_ms)
            except Exception:
                pass
        return resp_obj

    def get_json(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        connector: str | None = None,
    ) -> tuple[Any | None, Response]:
        resp = self.get(url, headers=headers, connector=connector)
        if not resp.ok:
            return None, resp
        try:
            return resp.json(), resp
        except json.JSONDecodeError:
            return None, resp


def excerpt(value: Any, limit: int = 220) -> str:
    """Compact, quotable excerpt for the evidence ledger."""
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1] + "…"
