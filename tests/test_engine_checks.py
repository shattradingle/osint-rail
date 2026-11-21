"""The tri-state rule: absent is a real answer, unknown is not, and neither is a crash."""

from __future__ import annotations

from unittest import mock

import pytest

from osint_rail.connectors import Connector, GitHub
from osint_rail.engine import Engine, RunOptions, derive_status
from osint_rail.model import Claim, Result, Seed, Store, coverage, now_iso
from osint_rail.net import HttpClient
from tests.helpers import FakeTransport, json_response, text_response


def make_claim(kind: str, value: str, confidence: float = 0.9, **extra) -> Claim:
    return Claim(kind=kind, predicate="full_name", value=value, source="fake",
                 source_url="https://example.test/x", excerpt=value, fetched_at=now_iso(),
                 confidence=confidence, subject_kind="username", subject_value="bob",
                 extra=extra.get("extra", {}))


def test_absence_row_means_absent():
    status, reason = derive_status(Result(claims=[make_claim("absence", "none")]))
    assert status == "absent"
    assert reason


def test_absence_row_marked_unknown_stays_unknown():
    result = Result(claims=[make_claim("absence", "unknown")])
    result.claims[0].excerpt = "anti-bot challenge page"
    status, reason = derive_status(result)
    assert status == "unknown"
    assert "challenge" in reason


def test_note_means_unknown_and_keeps_the_reason():
    status, reason = derive_status(Result(note="github HTTP 403: HTTP 403"))
    assert status == "unknown"
    assert "403" in reason


def test_real_claim_means_matched():
    assert derive_status(Result(claims=[make_claim("profile", "Linus")]))[0] == "matched"


def test_weak_only_claim_means_weak():
    weak = make_claim("account", "example", confidence=0.35, extra={"weak": True})
    assert derive_status(Result(claims=[weak]))[0] == "weak"


def test_silence_without_a_note_is_unknown_not_absent():
    status, reason = derive_status(Result())
    assert status == "unknown"
    assert "no claims" in reason


def test_403_from_a_real_connector_is_recorded_as_unknown(tmp_path):
    store = Store(tmp_path / "c.db")
    transport = FakeTransport(default=text_response("blocked by bot wall", 403))
    with mock.patch("osint_rail.engine.connectors_for", return_value=[GitHub()]):
        result = Engine(store, RunOptions(max_depth=0, max_requests=6),
                        transport=transport).run(Seed("username", "torvalds"))
    assert len(result.checks) == 1
    assert result.checks[0].connector == "github"
    assert result.checks[0].status == "unknown"
    assert "403" in result.checks[0].reason
    assert not [c for c in result.claims if c.kind == "absence"]
    assert result.coverage["unknown"] == 1
    assert result.coverage["matched"] == 0
    # the check survives the round-trip through SQLite
    assert store.checks(result.case.id)[0].status == "unknown"


class _Ok(Connector):
    name = "ok"
    accepts = frozenset({"username"})

    def run(self, seed, ctx):
        return Result(claims=[make_claim("profile", "found")], seeds=[Seed("email", "a@b.test")])


class _Absent(Connector):
    name = "absent"
    accepts = frozenset({"username"})

    def run(self, seed, ctx):
        return Result(claims=[make_claim("absence", "none")])


class _Boom(Connector):
    name = "boom"
    accepts = frozenset({"username"})

    def run(self, seed, ctx):
        raise RuntimeError("connector bug")


class _Chatty(Connector):
    name = "chatty"
    accepts = frozenset({"username"})

    def run(self, seed, ctx):
        for i in range(5):
            ctx.http.get(f"https://chatty.test/{i}", cache=False)
        return Result(claims=[make_claim("profile", "x")])


def test_every_connector_run_becomes_a_check_row(tmp_path):
    store = Store(tmp_path / "c.db")
    with mock.patch("osint_rail.engine.connectors_for", return_value=[_Ok(), _Absent()]):
        result = Engine(store, RunOptions(max_depth=0), transport=FakeTransport()).run(
            Seed("username", "bob"))
    assert len(result.checks) == 2
    assert coverage(result.checks) == {"matched": 1, "weak": 0, "absent": 1,
                                       "unknown": 0, "checks": 2}
    assert len(store.checks(result.case.id)) == 2
    assert result.coverage["matched"] == 1
    assert result.coverage["claims"] == 1


def test_connector_exception_is_unknown_with_the_exception_named(tmp_path):
    store = Store(tmp_path / "c.db")
    with mock.patch("osint_rail.engine.connectors_for", return_value=[_Boom()]):
        result = Engine(store, RunOptions(max_depth=0), transport=FakeTransport()).run(
            Seed("username", "bob"))
    assert result.checks[0].status == "unknown"
    assert "RuntimeError" in result.checks[0].reason
    assert "connector bug" in result.checks[0].reason


def test_budget_stops_the_case_and_reports_why(tmp_path):
    store = Store(tmp_path / "c.db")
    with mock.patch("osint_rail.engine.connectors_for", return_value=[_Chatty()]):
        result = Engine(store, RunOptions(max_depth=0, max_requests=2),
                        transport=FakeTransport(default=text_response("ok"))).run(
            Seed("username", "bob"))
    assert result.stop_reason.startswith("budget")
    assert result.stats["requests"] == 2
    assert result.coverage["checks"] == 1
    assert result.checks[0].status == "unknown"
    assert "budget" in result.checks[0].reason


def test_github_profile_and_commit_email_are_sourced(tmp_path):
    store = Store(tmp_path / "c.db")
    transport = FakeTransport(routes=[
        ("/events/public", json_response([])),
        ("api.github.com/users/torvalds", json_response({
            "login": "torvalds", "name": "Linus Torvalds", "html_url": "https://github.com/torvalds",
            "blog": "https://www.kernel.org",
        })),
    ])
    with mock.patch("osint_rail.engine.connectors_for", return_value=[GitHub()]):
        result = Engine(store, RunOptions(max_depth=0), transport=transport).run(
            Seed("username", "torvalds"))
    values = {c.value for c in result.claims}
    assert "Linus Torvalds" in values
    assert result.checks[0].status == "matched"
    assert all(c.source_url for c in result.claims)


def test_case_json_shape(tmp_path):
    store = Store(tmp_path / "c.db")
    from osint_rail.report import case_json

    with mock.patch("osint_rail.engine.connectors_for", return_value=[_Ok()]):
        result = Engine(store, RunOptions(max_depth=0), transport=FakeTransport()).run(
            Seed("username", "bob"))
    payload = case_json(result)
    assert set(payload) >= {"case", "coverage", "coverage_line", "stats", "checks",
                            "claims", "entities", "candidates"}
    assert payload["case"]["seed_value"] == "bob"
    assert payload["coverage"]["checks"] == 1
    assert payload["claims"][0]["url"] == "https://example.test/x"
    assert payload["coverage_line"].startswith("matched 1 / weak 0 / absent 0 / unknown 0 of 1")


@pytest.mark.parametrize("status,expected", [
    ("matched", 0), ("weak", 0), ("absent", 1), ("unknown", 2),
])
def test_exit_code_mapping(status, expected, tmp_path):
    from osint_rail.cli import exit_code_for
    from osint_rail.model import Check

    check = Check(connector="x", seed_kind="username", seed_value="bob", status=status)
    claims = []
    if status in ("matched", "weak"):
        claims = [make_claim("profile", "v")]
    if status == "absent":
        claims = [make_claim("absence", "none")]
    result = mock.Mock(claims=claims, coverage=coverage([check]), stop_reason="complete")
    assert exit_code_for(result) == expected


def test_budget_stop_is_empty_not_blocked():
    from osint_rail.cli import exit_code_for
    from osint_rail.model import Check

    check = Check(connector="x", seed_kind="username", seed_value="bob", status="unknown")
    result = mock.Mock(claims=[], coverage=coverage([check]), stop_reason="budget: 2 spent")
    assert exit_code_for(result) == 1


def test_http_client_seam_is_the_only_network_access():
    transport = FakeTransport(default=json_response({"hello": "world"}))
    http = HttpClient(transport=transport, host_interval=0)
    data, response = http.get_json("https://api.test/x")
    assert data == {"hello": "world"}
    assert response.ok and not response.from_cache
