"""CLI: registry listing, store commands, machine-readable output, exit codes."""

from __future__ import annotations

import json

import pytest

from osint_rail.cli import EXIT_EMPTY, EXIT_OK, EXIT_USAGE, main, paint
from osint_rail.connectors import REGISTRY
from osint_rail.engine import RunResult
from osint_rail.model import Check, Claim, Seed, Store, coverage, now_iso
from osint_rail.paths import default_db, default_out, state_dir
from osint_rail.resolve import resolve


def make_case(tmp_path, seed_value: str = "bob"):
    store = Store(tmp_path / "cases.db")
    seed = Seed("username", seed_value)
    case = store.create_case(seed, {"max_depth": 0})
    claims = [
        Claim(kind="profile", predicate="full_name", value="Bob Smith", source="github",
              source_url="https://api.github.com/users/bob", excerpt="Bob Smith",
              fetched_at=now_iso(), confidence=0.9, subject_kind="username",
              subject_value=seed_value),
        Claim(kind="absence", predicate="gitlab_account", value="none", source="gitlab",
              source_url="https://gitlab.com/api/v4/users?username=bob", excerpt="[] (no user)",
              fetched_at=now_iso(), confidence=0.85, subject_kind="username",
              subject_value=seed_value),
    ]
    store.add_claims(case.id, claims)
    store.add_checks(case.id, [
        Check("github", "username", seed_value, "matched"),
        Check("gitlab", "username", seed_value, "absent", "[] (no user)"),
    ])
    store.log_request(case.id, "github", "https://api.github.com/users/bob", 200, 12)
    return store, case


def test_paths_honour_osint_rail_home(monkeypatch, tmp_path):
    monkeypatch.setenv("OSINT_RAIL_HOME", str(tmp_path))
    assert state_dir() == tmp_path
    assert default_db() == tmp_path / "cases.db"
    assert default_out() == tmp_path / "cases"


def test_paths_fall_back_to_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("OSINT_RAIL_HOME", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert state_dir() == tmp_path / "xdg" / "osint-rail"


def test_connectors_lists_the_registry(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("OSINT_RAIL_HOME", str(tmp_path))
    assert main(["connectors"]) == EXIT_OK
    out = capsys.readouterr().out
    assert f"{len(REGISTRY)} connectors" in out
    for connector in REGISTRY:
        assert connector.name in out


def test_connectors_json_matches_the_registry(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("OSINT_RAIL_HOME", str(tmp_path))
    assert main(["connectors", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == len(REGISTRY)
    names = {row["name"] for row in payload["connectors"]}
    assert names == {c.name for c in REGISTRY}
    row = next(r for r in payload["connectors"] if r["name"] == "whatsmyname")
    assert row["state"] == "limited"
    assert "registration" in row["sensitivity"]


def test_empty_list_is_exit_one(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("OSINT_RAIL_HOME", str(tmp_path))
    assert main(["list"]) == EXIT_EMPTY
    assert "no cases" in capsys.readouterr().out


def test_list_json(tmp_path, capsys):
    store, case = make_case(tmp_path)
    assert main(["list", "--json", "--db", str(tmp_path / "cases.db")]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["cases"][0]["id"] == case.id
    assert payload["cases"][0]["seed_value"] == "bob"


def test_show_json_is_one_object(tmp_path, capsys):
    store, case = make_case(tmp_path)
    assert main(["show", case.id, "--json", "--db", str(tmp_path / "cases.db")]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["case"]["id"] == case.id
    assert payload["coverage"]["matched"] == 1
    assert payload["claims"][0]["url"].startswith("https://api.github.com")


def test_show_missing_case_is_exit_one(tmp_path, capsys):
    assert main(["show", "nope", "--db", str(tmp_path / "c.db")]) == EXIT_EMPTY
    assert "no such case" in capsys.readouterr().err


def test_delete_removes_the_case(tmp_path, capsys):
    store, case = make_case(tmp_path)
    assert main(["delete", case.id, "--db", str(tmp_path / "cases.db")]) == EXIT_OK
    assert "deleted" in capsys.readouterr().out
    assert main(["delete", case.id, "--db", str(tmp_path / "cases.db")]) == EXIT_EMPTY


def test_unknown_command_is_usage_error(capsys):
    assert main(["frobnicate"]) == EXIT_USAGE
    assert "invalid choice" in capsys.readouterr().err


def test_bad_seed_kind_is_usage_error(tmp_path, capsys):
    assert main(["case", "bob", "--kind", "tea-leaves", "--db", str(tmp_path / "c.db")]) == EXIT_USAGE
    assert "unknown seed kind" in capsys.readouterr().err


def test_probe_unknown_connector_is_usage_error(tmp_path, capsys):
    assert main(["probe", "nope", "bob", "--db", str(tmp_path / "c.db")]) == EXIT_USAGE
    assert "unknown connector" in capsys.readouterr().err


def test_probe_wrong_seed_kind_is_usage_error(tmp_path, capsys):
    assert main(["probe", "github", "a@b.test", "--db", str(tmp_path / "c.db")]) == EXIT_USAGE
    assert "does not accept" in capsys.readouterr().err


class _StubEngine:
    result: RunResult | None = None

    def __init__(self, store, options):
        self.store = store

    def run(self, seed, title=""):
        return self.result


def test_case_json_prints_one_object_and_writes_reports(tmp_path, capsys, monkeypatch):
    from osint_rail import cli

    store, case = make_case(tmp_path)
    claims = store.claims(case.id)
    result = RunResult(
        case=case, claims=claims, resolution=resolve(case.seed, claims),
        stats={"claims": 2, "requests": 1, "sources": 2},
        checks=store.checks(case.id),
        coverage={**coverage(store.checks(case.id)), "requests": 1, "seconds": 0.1, "claims": 1},
        elapsed_s=0.1,
    )
    _StubEngine.result = result
    monkeypatch.setattr(cli, "Engine", _StubEngine)
    out_dir = tmp_path / "reports"
    code = main(["case", "bob", "--json", "--db", str(tmp_path / "cases.db"), "--out", str(out_dir)])
    assert code == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["case"]["id"] == case.id
    assert payload["exit_code"] == EXIT_OK
    assert payload["paths"]["markdown"].endswith(".md")
    assert (out_dir).exists()


def test_paint_is_plain_when_disabled():
    assert paint("x", "32", False) == "x"
    assert "\033[" in paint("x", "32", True)


@pytest.mark.parametrize("argv", [["--version"], ["--help"]])
def test_version_and_help_exit_zero(argv, capsys):
    assert main(argv) == EXIT_OK
    assert capsys.readouterr().out
