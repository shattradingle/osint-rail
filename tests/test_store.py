"""SQLite store: evidence rows, check rows, connector state, deletion."""

from __future__ import annotations

import pytest

from osint_rail.model import Check, Claim, Seed, Store, coverage, now_iso


def claim(value: str = "x", predicate: str = "full_name") -> Claim:
    return Claim(kind="profile", predicate=predicate, value=value, source="fake",
                 source_url="https://example.test/u", excerpt=value, fetched_at=now_iso(),
                 confidence=0.8, subject_kind="username", subject_value="bob")


def test_claims_round_trip(tmp_path):
    store = Store(tmp_path / "c.db")
    case = store.create_case(Seed("username", "bob"), {"depth": 1})
    assert store.add_claims(case.id, [claim("a"), claim("b")]) == 2
    rows = store.claims(case.id)
    assert [r.value for r in rows] == ["a", "b"]
    assert rows[0].as_row(case.id)[0] == case.id
    assert set(store.claim_values(case.id, "full_name")) == {"a", "b"}
    assert store.stats(case.id) == {"claims": 2, "requests": 0, "sources": 1}


def test_empty_claim_list_is_a_noop(tmp_path):
    store = Store(tmp_path / "c.db")
    case = store.create_case(Seed("username", "bob"), {})
    assert store.add_claims(case.id, []) == 0
    assert store.claims(case.id) == []


def test_checks_round_trip_and_coverage(tmp_path):
    store = Store(tmp_path / "c.db")
    case = store.create_case(Seed("username", "bob"), {})
    checks = [
        Check("github", "username", "bob", "matched"),
        Check("gitlab", "username", "bob", "absent", "[] (no user)"),
        Check("pypi", "username", "bob", "unknown", "anti-bot challenge page"),
    ]
    assert store.add_checks(case.id, checks) == 3
    back = store.checks(case.id)
    assert [c.status for c in back] == ["matched", "absent", "unknown"]
    assert back[2].reason.startswith("anti-bot")
    assert coverage(back) == {"matched": 1, "weak": 0, "absent": 1,
                              "unknown": 1, "checks": 3}


def test_check_rejects_an_unknown_state():
    with pytest.raises(ValueError):
        Check("github", "username", "bob", "maybe")


def test_last_connector_state_is_the_latest(tmp_path):
    store = Store(tmp_path / "c.db")
    one = store.create_case(Seed("username", "a"), {})
    two = store.create_case(Seed("username", "b"), {})
    store.add_checks(one.id, [Check("github", "username", "a", "unknown", "403")])
    store.add_checks(two.id, [Check("github", "username", "b", "matched")])
    assert store.last_connector_states()["github"]["status"] == "matched"


def test_delete_case_removes_every_table(tmp_path):
    store = Store(tmp_path / "c.db")
    case = store.create_case(Seed("username", "bob"), {})
    store.add_claims(case.id, [claim()])
    store.add_checks(case.id, [Check("github", "username", "bob", "matched")])
    store.log_request(case.id, "github", "https://api.github.com/x", 200, 5)
    store.mark_seed(case.id, Seed("email", "a@b.test"), 1, "github")
    assert store.delete_case(case.id) is True
    assert store.get_case(case.id) is None
    assert store.claims(case.id) == []
    assert store.checks(case.id) == []
    assert store.requests(case.id) == []
    assert store.delete_case(case.id) is False


def test_store_reopens_without_losing_or_duplicating_schema(tmp_path):
    path = tmp_path / "c.db"
    store = Store(path)
    case = store.create_case(Seed("domain", "example.com"), {})
    store.add_claims(case.id, [claim("example.com")])
    store.close()
    reopened = Store(path)
    assert reopened.get_case(case.id).seed.value == "example.com"
    assert len(reopened.claims(case.id)) == 1
