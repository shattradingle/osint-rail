"""CLI: run a case, inspect the store, probe one connector, serve MCP.

Exit codes are stable and documented:

* 0  ok
* 1  nothing found (no sourced claim) or the run could not complete
* 2  every connector failed or was blocked (all checks unknown)
* 64 usage error: bad flag, unknown command, unknown connector
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .connectors import REGISTRY, Context
from .engine import Engine, RunOptions, derive_status
from .model import Check, Seed, Store, coverage, detect_kind, normalise_seed_kind, sourced
from .net import HttpClient
from .paths import default_db, default_out
from .report import (case_json, coverage_line, render_markdown, render_stored,
                     stored_json, write_report)

EXIT_OK = 0
EXIT_EMPTY = 1
EXIT_BLOCKED = 2
EXIT_USAGE = 64

STATUS_COLOURS = {"matched": "32", "weak": "33", "absent": "2", "unknown": "31"}

GROUPED_HELP = """commands, by role:
  run       case        run a case from one seed
            probe       run one named connector against a seed
  store     show        re-render a stored case
            list        list recent cases
            delete      delete a case and its claims/checks/requests
  registry  connectors  list every connector, its seed kinds and its state
  server    mcp         serve MCP over stdio for Claude, Cursor or any MCP client

examples:
  osint-rail case torvalds --depth 2
  osint-rail case example.com --kind domain --json
  osint-rail connectors
  osint-rail probe github torvalds

exit codes: 0 ok | 1 nothing found | 2 every check blocked | 64 usage"""


class _Parser(argparse.ArgumentParser):
    """Usage errors exit 64, not argparse's 2 (which we use for 'all blocked')."""

    def error(self, message: str):  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _colour_enabled(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _common(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--db", default=None, help="SQLite case store (default: $OSINT_RAIL_HOME/cases.db)")
    parser.add_argument("--out", default=None, help="report directory (default: $OSINT_RAIL_HOME/cases)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--quiet", action="store_true", help="print nothing on success")
    return parser


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    _common(common)

    p = _Parser(
        prog="osint-rail",
        description="Keyless OSINT: one seed in, a sourced dossier out. "
                    "Every claim carries its source URL; a blocked source is UNKNOWN, not absence.",
        epilog=GROUPED_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
    )
    p.add_argument("--version", action="version", version=f"osint-rail {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="command")

    # -- run -----------------------------------------------------------
    run = sub.add_parser("case", description="Run a case: fan out over every connector that "
                                              "accepts this seed kind, follow the seeds they "
                                              "return, store the evidence and write a dossier.",
                         parents=[common])
    run.add_argument("seed", help="email, username, domain, ip, name, handle or url")
    run.add_argument("--kind", help="force the seed kind instead of guessing")
    run.add_argument("--depth", type=int, default=2, help="BFS depth (default 2)")
    run.add_argument("--max-requests", type=int, default=120, help="request budget (default 120)")
    run.add_argument("--max-seconds", type=float, default=180.0, help="wall-clock budget")
    run.add_argument("--username-sites", type=int, default=40,
                     help="strong username checks to probe (0 disables the dataset sweep)")
    run.add_argument("--weak-sites", type=int, default=20,
                     help="status-only username checks (confidence 0.35)")
    run.add_argument("--no-websearch", action="store_true", help="skip the DuckDuckGo sweep")
    run.add_argument("--no-registration", action="store_true",
                     help="skip account-existence probes (username site sweep)")
    run.add_argument("--allow-sensitive", action="store_true",
                     help="allow breach/intrusive connectors (none ship)")
    run.add_argument("--max", action="store_true",
                     help="max preset: depth 3, 480 requests, 150 strong + 120 weak checks")
    run.add_argument("--ai", action="store_true", help="run the optional AI summary layer")
    run.add_argument("--json", action="store_true", help="print one JSON object instead of the dossier")

    probe = sub.add_parser("probe", help="run one named connector against a seed",
                           description="Run a single connector, store the result as a case and "
                                       "print its check. The fastest way to test a new connector.",
                           parents=[common])
    probe.add_argument("connector", help="connector name (see `osint-rail connectors`)")
    probe.add_argument("seed")
    probe.add_argument("--kind", help="force the seed kind instead of guessing")
    probe.add_argument("--max-requests", type=int, default=6)
    probe.add_argument("--json", action="store_true")

    # -- store ---------------------------------------------------------
    show = sub.add_parser("show", help="re-render a stored case",
                          description="Re-render a stored case from the evidence ledger.",
                          parents=[common])
    show.add_argument("case_id")
    show.add_argument("--json", action="store_true")

    lst = sub.add_parser("list", help="list recent cases", parents=[common])
    lst.add_argument("--limit", type=int, default=20)
    lst.add_argument("--json", action="store_true")

    delete = sub.add_parser("delete", help="delete a case and its claims/checks/requests",
                            parents=[common])
    delete.add_argument("case_id")

    # -- registry / server --------------------------------------------
    conns = sub.add_parser("connectors", help="list every connector from the registry",
                           parents=[common])
    conns.add_argument("--json", action="store_true")

    mcp = sub.add_parser("mcp", help="serve MCP over stdio",
                         description="Line-delimited JSON-RPC 2.0 MCP server on stdin/stdout. "
                                     "Tools: osint_case, osint_show, osint_connectors.",
                         parents=[common])
    mcp.add_argument("--case-db", dest="mcp_db", default=None)

    # The grouped table in GROUPED_HELP is the command list; drop argparse's
    # auto-generated one so --help says it once, in role order.
    sub_action = p._subparsers._group_actions[0]
    for group in p._action_groups:
        if sub_action in group._group_actions:
            group._group_actions.remove(sub_action)
    return p


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _store(args: argparse.Namespace) -> Store:
    return Store(Path(args.db) if args.db else default_db())


def _out_dir(args: argparse.Namespace) -> Path:
    return Path(args.out) if args.out else default_out()


def exit_code_for(result) -> int:
    cov = result.coverage or {}
    checks = cov.get("checks", 0)
    ran_out = str(getattr(result, "stop_reason", "")).startswith("budget")
    if checks and not ran_out and cov.get("unknown", 0) == checks:
        return EXIT_BLOCKED
    if not sourced(result.claims):
        return EXIT_EMPTY
    return EXIT_OK


def _emit_json(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=False))


def _note(msg: str) -> None:
    print(msg, file=sys.stderr)


# ----------------------------------------------------------------------
# commands
# ----------------------------------------------------------------------
def cmd_case(args: argparse.Namespace) -> int:
    try:
        kind = normalise_seed_kind(args.kind) if args.kind else detect_kind(args.seed)
    except ValueError as exc:
        _note(f"osint-rail: {exc}")
        return EXIT_USAGE
    seed = Seed(kind, args.seed)

    depth, max_requests, max_seconds = args.depth, args.max_requests, args.max_seconds
    strong_sites, weak_sites, websearch = args.username_sites, args.weak_sites, not args.no_websearch
    if args.max:
        depth, max_requests, max_seconds = 3, 480, 360.0
        strong_sites, weak_sites, websearch = 150, 120, True

    options = RunOptions(
        max_depth=depth,
        max_requests=max_requests,
        max_seconds=max_seconds,
        username_sites=strong_sites,
        username_weak_sites=weak_sites,
        websearch=websearch,
        allow_registration=not args.no_registration,
        allow_sensitive=args.allow_sensitive,
        ai=args.ai,
    )
    store = _store(args)
    result = Engine(store, options).run(seed)
    paths = write_report(result, _out_dir(args))
    code = exit_code_for(result)
    colour = _colour_enabled(args)

    if args.json:
        payload = case_json(result)
        payload["paths"] = paths
        payload["exit_code"] = code
        _emit_json(payload)
    elif not args.quiet:
        print(render_markdown(result))
        print()
        print(paint("Coverage: " + coverage_line(result.coverage), "1", colour))
        print(f"report: {paths['markdown']}")
        print(f"graph:  {paths['graph']}")
        print(f"json:   {paths['json']}")
        unknown = [c for c in result.checks if c.status == "unknown"]
        for check in unknown[:5]:
            _note(paint(f"unknown: {check.connector} - {check.reason}", "33", colour))
        if len(unknown) > 5:
            _note(f"... and {len(unknown) - 5} more unknown checks (see the dossier)")
    return code


def cmd_probe(args: argparse.Namespace) -> int:
    connector = next((c for c in REGISTRY if c.name == args.connector), None)
    if connector is None:
        _note(f"unknown connector: {args.connector} (try: osint-rail connectors)")
        return EXIT_USAGE
    try:
        kind = normalise_seed_kind(args.kind) if args.kind else detect_kind(args.seed)
    except ValueError as exc:
        _note(f"osint-rail: {exc}")
        return EXIT_USAGE
    if kind not in connector.accepts:
        _note(f"{connector.name} does not accept {kind} seeds "
              f"(accepts: {', '.join(sorted(connector.accepts))})")
        return EXIT_USAGE

    seed = Seed(kind, args.seed)
    store = _store(args)
    case = store.create_case(seed, {"probe": connector.name, "max_requests": args.max_requests})
    store.mark_seed(case.id, seed, 0, "probe")
    started = time.monotonic()
    http = HttpClient(
        max_requests=args.max_requests,
        max_seconds=60.0,
        audit=lambda conn, url, status, ms: store.log_request(case.id, conn, url, status, ms),
    )
    ctx = Context(case_id=case.id, options={"username_sites": 5, "username_weak_sites": 2},
                  http=http)
    try:
        result = connector.run(seed, ctx)
        status, reason = derive_status(result)
        claims = result.claims
    except Exception as exc:  # a probe must not traceback
        status, reason, claims = "unknown", f"connector raised {type(exc).__name__}: {exc}", []

    check = Check(connector=connector.name, seed_kind=seed.kind, seed_value=seed.value,
                  status=status, reason=reason[:200])
    store.add_claims(case.id, claims)
    store.add_checks(case.id, [check])
    elapsed = round(time.monotonic() - started, 1)
    st = store.stats(case.id)
    cov = coverage([check])
    cov.update({"requests": st["requests"], "seconds": elapsed, "claims": len(sourced(claims))})

    if args.json:
        _emit_json({
            "case_id": case.id,
            "connector": connector.name,
            "coverage": cov,
            "coverage_line": coverage_line(cov),
            "check": check.as_dict(),
            "claims": [
                {"kind": c.kind, "predicate": c.predicate, "value": c.value,
                 "url": c.source_url, "excerpt": c.excerpt, "confidence": c.confidence}
                for c in claims
            ],
        })
    elif not args.quiet:
        colour = _colour_enabled(args)
        print(f"{connector.name} -> {paint(status, STATUS_COLOURS.get(status, '0'), colour)}"
              f" ({reason or 'no reason'})")
        print(f"`{coverage_line(cov)}`")
        for c in claims[:20]:
            print(f"  {c.kind:8} {c.predicate:20} {c.value[:70]}")
        print(f"case: {case.id}")

    if status == "unknown":
        return EXIT_BLOCKED
    return EXIT_OK if sourced(claims) else EXIT_EMPTY


def cmd_show(args: argparse.Namespace) -> int:
    store = _store(args)
    case = store.get_case(args.case_id)
    if not case:
        _note(f"no such case: {args.case_id}")
        return EXIT_EMPTY
    if args.json:
        _emit_json(stored_json(store, case))
    elif not args.quiet:
        print(render_stored(store, case))
    return EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    store = _store(args)
    rows = store.list_cases(limit=args.limit)
    if args.json:
        _emit_json({"cases": [
            {"id": r["id"], "seed_kind": r["seed_kind"], "seed_value": r["seed_value"],
             "created_at": r["created_at"], "title": r["title"]}
            for r in rows
        ]})
        return EXIT_OK if rows else EXIT_EMPTY
    if not rows:
        if not args.quiet:
            print("no cases")
        return EXIT_EMPTY
    if not args.quiet:
        for row in rows:
            print(f"{row['id']}  {row['seed_kind']}:{row['seed_value']}  {row['created_at']}")
    return EXIT_OK


def cmd_delete(args: argparse.Namespace) -> int:
    store = _store(args)
    if not store.delete_case(args.case_id):
        _note(f"no such case: {args.case_id}")
        return EXIT_EMPTY
    if not args.quiet:
        print(f"deleted {args.case_id}")
    return EXIT_OK


def connector_rows(observed: dict[str, dict[str, str]]) -> list[dict]:
    rows = []
    for connector in REGISTRY:
        state = connector.state
        note = connector.state_note
        last = observed.get(connector.name) or {}
        if last.get("status") == "unknown" and state == "live":
            state = "blocked"
            note = f"last attempt unknown ({last.get('fetched_at', '')})"
        rows.append({
            "name": connector.name,
            "accepts": ",".join(sorted(connector.accepts)),
            "pulls": connector.description,
            "sensitivity": connector.sensitivity,
            "state": state,
            "state_note": note,
            "observed": last.get("status", ""),
            "observed_at": last.get("fetched_at", ""),
        })
    return rows


def cmd_connectors(args: argparse.Namespace) -> int:
    observed: dict[str, dict[str, str]] = {}
    db_path = Path(args.db) if args.db else default_db()
    if db_path.exists():
        store = Store(db_path)
        observed = store.last_connector_states()
    rows = connector_rows(observed)
    if args.json:
        _emit_json({"count": len(rows), "connectors": rows})
        return EXIT_OK if rows else EXIT_EMPTY
    if not rows:
        _note("no connectors registered")
        return EXIT_EMPTY
    colour = _colour_enabled(args)
    codes = {"live": "32", "limited": "33", "blocked": "31"}
    name_width = max(len(r["name"]) for r in rows) + 2
    seeds_width = max(len(r["accepts"]) for r in rows) + 2
    print(f"{'connector'.ljust(name_width)}{'seeds'.ljust(seeds_width)}{'state'.ljust(9)}pulls")
    for row in rows:
        print(f"{row['name'].ljust(name_width)}{row['accepts'].ljust(seeds_width)}"
              f"{paint(row['state'].ljust(9), codes.get(row['state'], '0'), colour)}"
              f"{row['pulls']}")
    print(f"\n{len(rows)} connectors")
    return EXIT_OK


def cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import serve

    serve(args.mcp_db or args.db or str(default_db()))
    return EXIT_OK


_DISPATCH = {
    "case": cmd_case,
    "probe": cmd_probe,
    "show": cmd_show,
    "list": cmd_list,
    "delete": cmd_delete,
    "connectors": cmd_connectors,
    "mcp": cmd_mcp,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # `osint-rail max <seed>` stays as an alias for `case <seed> --max`.
    if argv and argv[0] == "max":
        argv = ["case", *argv[1:], "--max"]
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse exits 0 for --help/--version, 64 for errors
        return int(exc.code or 0)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return EXIT_USAGE

    try:
        return _DISPATCH[args.cmd](args)
    except KeyboardInterrupt:
        _note("interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 - never traceback at the user
        if os.environ.get("OSINT_RAIL_DEBUG"):
            import traceback
            traceback.print_exc()
        _note(f"osint-rail: {type(exc).__name__}: {exc}")
        return EXIT_EMPTY


if __name__ == "__main__":
    raise SystemExit(main())
