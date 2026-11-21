"""Stdio MCP server (JSON-RPC 2.0, one message per line).

Tools:
  osint_case        run a case from a seed, return the dossier
  osint_show        re-render a stored case
  osint_connectors  what this install can actually ask

The transport is injectable so the whole protocol can be tested offline.
"""

from __future__ import annotations

import json
import sys
import traceback

from . import __version__
from .connectors import REGISTRY
from .engine import Engine, RunOptions
from .model import Seed, Store, detect_kind, normalise_seed_kind
from .net import Transport
from .paths import default_db
from .report import case_json, coverage_line, render_markdown, render_stored

PROTOCOL_VERSION = "2025-06-18"
MAX_TEXT = 60_000

TOOLS = [
    {
        "name": "osint_case",
        "description": "Run an evidence-first OSINT case from one seed (email, username, domain, "
                       "ip, name, handle or url). Returns a markdown dossier; every claim carries "
                       "its source URL and a check row says which sources were blocked.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "seed": {"type": "string", "description": "The value to investigate"},
                "kind": {
                    "type": "string",
                    "enum": ["email", "username", "domain", "ip", "name", "handle", "url"],
                    "description": "Seed kind; guessed from the value when omitted",
                },
                "depth": {"type": "integer", "default": 2, "minimum": 0, "maximum": 4},
                "max_requests": {"type": "integer", "default": 60, "minimum": 5, "maximum": 300},
            },
            "required": ["seed"],
        },
    },
    {
        "name": "osint_show",
        "description": "Re-render a stored OSINT case by id, without any network requests.",
        "inputSchema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"],
        },
    },
    {
        "name": "osint_connectors",
        "description": "List the connectors installed here, the seed kinds each accepts and its "
                       "last observed state.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class McpServer:
    def __init__(self, db_path: str, transport: Transport | None = None) -> None:
        self.db_path = db_path
        self.transport = transport
        self.store = Store(db_path)

    def close(self) -> None:
        self.store.close()

    # -- jsonrpc -------------------------------------------------------
    def handle(self, request: dict) -> dict | None:
        method = request.get("method", "")
        req_id = request.get("id")

        def ok(result):
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        def err(code: int, message: str):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

        if method == "initialize":
            return ok({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "osint-rail", "version": __version__},
            })
        if method.startswith("notifications/"):
            return None
        if method == "ping":
            return ok({})
        if method == "tools/list":
            return ok({"tools": TOOLS})
        if method == "tools/call":
            params = request.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            try:
                if name == "osint_case":
                    return ok(self._call_case(arguments))
                if name == "osint_show":
                    return ok(self._call_show(arguments))
                if name == "osint_connectors":
                    return ok(self._call_connectors())
                return err(-32602, f"unknown tool: {name}")
            except Exception as exc:  # noqa: BLE001 - reported to the client, not a crash
                return ok({
                    "content": [{"type": "text", "text": f"error: {exc}"}],
                    "isError": True,
                })
        return err(-32601, f"method not found: {method}")

    # -- tools ---------------------------------------------------------
    def _call_case(self, args: dict) -> dict:
        seed_value = str(args.get("seed", "")).strip()
        if not seed_value:
            raise ValueError("seed is required")
        kind = args.get("kind")
        seed = Seed(normalise_seed_kind(kind) if kind else detect_kind(seed_value), seed_value)
        options = RunOptions(
            max_depth=int(args.get("depth", 2)),
            max_requests=int(args.get("max_requests", 60)),
            max_seconds=120.0,
            username_sites=30,
            username_weak_sites=20,
        )
        result = Engine(self.store, options, transport=self.transport).run(seed)
        text = render_markdown(result)
        if len(text) > MAX_TEXT:
            text = text[:MAX_TEXT] + "\n\n[truncated; full dossier stored]"
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": {
                "case_id": result.case.id,
                "coverage": result.coverage,
                "coverage_line": coverage_line(result.coverage),
                "claims": result.coverage.get("claims", 0),
                "requests": result.stats["requests"],
                "stop_reason": result.stop_reason,
            },
        }

    def _call_show(self, args: dict) -> dict:
        case_id = str(args.get("case_id", ""))
        case = self.store.get_case(case_id)
        if not case:
            raise ValueError(f"no such case: {case_id}")
        text = render_stored(self.store, case)
        if len(text) > MAX_TEXT:
            text = text[:MAX_TEXT] + "\n\n[truncated]"
        return {"content": [{"type": "text", "text": text}]}

    def _call_connectors(self) -> dict:
        observed = self.store.last_connector_states()
        rows = []
        for connector in REGISTRY:
            rows.append({
                "name": connector.name,
                "accepts": sorted(connector.accepts),
                "pulls": connector.description,
                "state": connector.state,
                "state_note": connector.state_note,
                "observed": (observed.get(connector.name) or {}).get("status", ""),
            })
        payload = {"count": len(rows), "connectors": rows}
        return {
            "content": [{"type": "text", "text": json.dumps(payload, indent=1)}],
            "structuredContent": payload,
        }

    # -- loop ----------------------------------------------------------
    def serve(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                self._write({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "parse error"}}, stdout)
                continue
            try:
                response = self.handle(request)
            except Exception:  # noqa: BLE001
                traceback.print_exc(file=sys.stderr)
                response = {"jsonrpc": "2.0", "id": request.get("id"),
                            "error": {"code": -32603, "message": "internal error"}}
            if response is not None:
                self._write(response, stdout)

    @staticmethod
    def _write(payload: dict, stdout=None) -> None:
        out = stdout or sys.stdout
        out.write(json.dumps(payload) + "\n")
        out.flush()


def serve(db_path: str | None = None) -> None:
    McpServer(str(db_path or default_db())).serve()


def case_payload(result) -> dict:  # re-exported for tests and future tools
    return case_json(result)
