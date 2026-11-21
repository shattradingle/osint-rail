"""HTTP layer: budget, cache, per-host bookkeeping, retry policy, tri-state flags."""

from __future__ import annotations

import time

import pytest

from osint_rail.net import BLOCK_STATUSES, BudgetExceeded, HttpClient, Response
from tests.helpers import FakeTransport, json_response, seq, text_response


def client(transport, **kw) -> HttpClient:
    kw.setdefault("host_interval", 0.0)
    kw.setdefault("retry_backoff", 0.0)
    return HttpClient(transport=transport, **kw)


def test_budget_is_enforced_and_charged_before_network():
    transport = FakeTransport(default=text_response("ok"))
    http = client(transport, max_requests=2)
    assert http.get("https://a.test/1").ok
    assert http.get("https://a.test/2").ok
    with pytest.raises(BudgetExceeded):
        http.get("https://a.test/3")
    assert transport.count == 2


def test_cache_hit_costs_no_request():
    transport = FakeTransport(default=json_response({"ok": True}))
    http = client(transport, max_requests=1)
    first = http.get("https://a.test/same")
    second = http.get("https://a.test/same")
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.body == first.body
    assert transport.count == 1
    assert http.count == 1


def test_cache_can_be_bypassed():
    transport = FakeTransport(default=text_response("ok"))
    http = client(transport)
    http.get("https://a.test/x")
    http.get("https://a.test/x", cache=False)
    assert transport.count == 2


def test_per_host_bookkeeping_is_separate():
    transport = FakeTransport(default=text_response("ok"))
    http = client(transport)
    http.get("https://a.test/1")
    http.get("https://a.test/2")
    http.get("https://b.test/1")
    stats = http.host_stats()
    assert stats["a.test"]["requests"] == 2
    assert stats["b.test"]["requests"] == 1
    assert "last" in stats["a.test"]


def test_rate_limit_waits_between_requests_to_one_host():
    transport = FakeTransport(default=text_response("ok"))
    http = client(transport, host_interval=0.04)
    started = time.monotonic()
    http.get("https://slow.test/1")
    http.get("https://slow.test/2")
    assert http.host_stats()["slow.test"]["requests"] == 2
    assert time.monotonic() - started >= 0.035


def test_429_is_not_retried():
    transport = FakeTransport(default=text_response("rate limited", 429))
    http = client(transport)
    response = http.get("https://a.test/x")
    assert response.status == 429
    assert transport.count == 1


def test_503_is_retried_then_succeeds():
    transport = FakeTransport(routes=[("a.test", seq(text_response("busy", 503),
                                                     json_response({"ok": 1})))])
    http = client(transport)
    response = http.get("https://a.test/x")
    assert response.ok
    assert transport.count == 2


def test_transport_failure_is_a_status_zero_not_an_exception():
    transport = FakeTransport(default=(0, b"", "timed out"))
    http = client(transport)
    response = http.get("https://dead.test/")
    assert response.status == 0
    assert response.error == "timed out"
    assert response.blocked is True


def test_block_statuses_are_the_documented_set():
    assert {0, 401, 403, 429} <= BLOCK_STATUSES
    assert 200 not in BLOCK_STATUSES and 404 not in BLOCK_STATUSES
    assert Response("u", 403, b"", 1).blocked is True
    assert Response("u", 404, b"", 1).blocked is False
    assert Response("u", 200, b"", 1).ok is True


def test_get_json_returns_none_on_non_json():
    transport = FakeTransport(default=text_response("<html>nope</html>"))
    http = client(transport)
    data, response = http.get_json("https://a.test/json")
    assert data is None
    assert response.ok


def test_audit_callback_sees_connector_url_status():
    seen = []
    transport = FakeTransport(default=text_response("ok"))
    http = client(transport, audit=lambda conn, url, status, ms: seen.append((conn, url, status)))
    http.get("https://a.test/x", connector="tester")
    assert seen == [("tester", "https://a.test/x", 200)]


def test_audit_failure_does_not_break_the_fetch():
    def explode(*args):
        raise RuntimeError("audit down")

    transport = FakeTransport(default=text_response("ok"))
    http = client(transport, audit=explode)
    assert http.get("https://a.test/x").ok
