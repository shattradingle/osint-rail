"""Connectors against canned responses: what they emit, and what they refuse to emit."""

from __future__ import annotations

import pytest

from osint_rail import connectors
from osint_rail.connectors import Connector, Context, GitHub, Gravatar, WhatsMyName
from osint_rail.connectors2 import PageFetch
from osint_rail.model import Seed
from osint_rail.net import HttpClient
from tests.helpers import (GITHUB_EVENTS, GITHUB_USER, GRAVATAR, WMN_DATA,
                           FakeTransport, json_response, text_response)

PAGE = (
    "<html><head><title>Jane's Site</title>"
    '<meta name="description" content="Portfolio and contact">'
    "</head><body>"
    '<a href="mailto:jane@example.org">mail</a>'
    '<a href="https://github.com/janedoe">gh</a>'
    '<a href="tel:+44 7700 900123">call</a>'
    "</body></html>"
)


def context(transport, **options) -> Context:
    opts = {"username_sites": 0, "username_weak_sites": 0}
    opts.update(options)
    http = HttpClient(transport=transport, max_requests=20, host_interval=0.0,
                      retry_backoff=0.0)
    return Context(case_id="test-case", options=opts, http=http)


def test_whatsmyname_with_zero_limits_does_not_download_datasets(monkeypatch):
    def explode(url, timeout=45):
        raise AssertionError("dataset download attempted with both limits at zero")

    monkeypatch.setattr(connectors, "_FETCH_JSON", explode)
    connectors.reset_datasets()
    result = WhatsMyName().run(Seed("username", "torvalds"),
                               context(FakeTransport(), username_sites=0,
                                       username_weak_sites=0))
    assert result.claims == []
    assert "datasets unavailable" in result.note


def test_gravatar_emits_a_verified_account_and_a_username_seed():
    transport = FakeTransport(routes=[("gravatar.com", json_response(GRAVATAR))])
    result = Gravatar().run(Seed("email", "torvalds@example.test"), context(transport))
    accounts = [c for c in result.claims if c.kind == "account"]
    assert accounts[0].value == "github.com:torvalds"
    assert accounts[0].extra["verified"] is True
    assert accounts[0].source_url.startswith("https://gravatar.com/")
    assert Seed("username", "torvalds") in result.seeds
    assert {c.predicate for c in result.claims} >= {"full_name", "profile_url", "bio"}


def test_github_pulls_commit_emails_and_drops_noreply():
    transport = FakeTransport(routes=[
        ("/events/public", json_response(GITHUB_EVENTS)),
        ("api.github.com/users/torvalds", json_response(GITHUB_USER)),
    ])
    result = GitHub().run(Seed("username", "torvalds"), context(transport))
    emails = [c.value for c in result.claims if c.predicate == "email"]
    assert emails == ["torvalds@linux-foundation.org"]
    assert Seed("email", "torvalds@linux-foundation.org") in result.seeds
    assert Seed("domain", "www.kernel.org") in result.seeds
    assert {c.predicate for c in result.claims} >= {"login", "full_name", "blog"}


def test_github_403_is_a_note_not_an_absence():
    transport = FakeTransport(default=text_response("blocked", 403))
    result = GitHub().run(Seed("username", "torvalds"), context(transport))
    assert result.claims == []
    assert "403" in result.note


def test_page_fetch_extracts_contacts_and_social_seeds():
    transport = FakeTransport(routes=[("jane.example", text_response(PAGE))])
    result = PageFetch().run(Seed("url", "https://jane.example"), context(transport))
    assert any(c.value == "jane@example.org" for c in result.claims)
    assert any(c.predicate == "page_title" for c in result.claims)
    assert any(c.value.startswith("github:") for c in result.claims)
    assert Seed("username", "janedoe") in result.seeds


def test_page_fetch_on_a_plain_text_page_says_so():
    transport = FakeTransport(routes=[("plain.example", text_response("just text"))])
    result = PageFetch().run(Seed("url", "https://plain.example"), context(transport))
    assert result.claims == []
    assert "not HTML" in result.note


def test_every_registered_connector_declares_a_name_and_seed_kind():
    from osint_rail.connectors import REGISTRY

    for connector in REGISTRY:
        assert isinstance(connector, Connector)
        assert connector.name and " " not in connector.name
        assert connector.accepts, f"{connector.name} accepts no seed kinds"
        assert connector.description, f"{connector.name} has no description"
        assert connector.state in ("live", "limited", "blocked")


@pytest.mark.parametrize("name", ["github", "gravatar", "gitlab", "domain", "ip", "page"])
def test_registry_lookup_is_by_name(name):
    from osint_rail.connectors import connectors_for

    assert any(c.name == name for c in connectors_for(
        {"github": "username", "gravatar": "email", "gitlab": "username",
         "domain": "domain", "ip": "ip", "page": "url"}[name]))


def test_domain_connector_never_reports_a_null_mx_as_a_host():
    from osint_rail.connectors import DomainIntel

    transport = FakeTransport(routes=[
        ("type=A", json_response({"Answer": [{"data": "93.184.216.34"}]})),
        ("type=MX", json_response({"Answer": [{"data": "0 ."},
                                              {"data": "10 mail.example.com."}]})),
        ("type=NS", json_response({"Answer": [{"data": "a.iana-servers.net."}]})),
        ("type=TXT", json_response({"Answer": []})),
        ("rdap.org", text_response("not found", 404)),
    ])
    result = DomainIntel().run(Seed("domain", "example.com"), context(transport))
    mx = [c.value for c in result.claims if c.predicate == "mx_host"]
    assert mx == ["mail.example.com"]


def test_websearch_can_be_switched_off_by_options():
    from osint_rail.connectors2 import WebSearch

    assert WebSearch().enabled({"websearch": True}) is True
    assert WebSearch().enabled({"websearch": False}) is False


def test_disabled_username_sweep_is_not_recorded_as_a_check(tmp_path):
    from unittest import mock

    from osint_rail.engine import Engine, RunOptions
    from osint_rail.model import Store

    store = Store(tmp_path / "c.db")
    with mock.patch("osint_rail.engine.connectors_for", return_value=[WhatsMyName()]):
        result = Engine(store, RunOptions(max_depth=0, username_sites=0,
                                          username_weak_sites=0)).run(
            Seed("username", "torvalds"))
    assert result.checks == []
    assert result.coverage["checks"] == 0


def test_blocked_websearch_is_a_note_not_an_absence_row():
    from osint_rail.connectors2 import WebSearch

    transport = FakeTransport(default=text_response("rate limited", 429))
    result = WebSearch().run(Seed("username", "torvalds"), context(transport))
    assert result.claims == []
    assert "429" in result.note


def test_pypi_challenge_page_is_unknown_not_absent():
    from osint_rail.connectors import PyPI

    transport = FakeTransport(routes=[("pypi.org/user", text_response(
        "<html><title>Just a moment</title>enable javascript</html>"))])
    result = PyPI().run(Seed("username", "torvalds"), context(transport))
    assert result.claims == []
    assert "challenge" in result.note.lower()


def test_username_sweep_survives_an_exhausted_budget(monkeypatch):
    """A spent budget inside the sweep is a partial result, not a NameError."""
    from osint_rail.model import coverage

    monkeypatch.setattr(
        connectors, "_FETCH_JSON",
        lambda url, timeout=45: WMN_DATA if "WhatsMyName" in url or "wmn" in url.lower() else {})
    connectors.reset_datasets()
    http = HttpClient(transport=FakeTransport(), max_requests=0, host_interval=0.0)
    ctx = Context(case_id="c", options={"username_sites": 1, "username_weak_sites": 0}, http=http)
    result = WhatsMyName().run(Seed("username", "torvalds"), ctx)
    kernels = [c for c in result.claims if c.predicate == "wmn_partial"]
    assert kernels, "expected a partial marker"
    assert kernels[0].kind == "coverage"
    assert coverage([])["checks"] == 0
