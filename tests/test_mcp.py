"""MCP: tools/list, a real tools/call over the injected transport, and the stdio loop."""

from __future__ import annotations

import io
import json

import pytest

from osint_rail import connectors
from osint_rail.mcp_server import McpServer
from tests.helpers import GITHUB_USER, FakeTransport, json_response, text_response


@pytest.fixture()
def server(tmp_path, monkeypatch):
    # the username dataset is a network download; stub it so the test stays offline
    monkeypatch.setattr(connectors, "_FETCH_JSON", lambda url, timeout=45: {})
    connectors.reset_datasets()
    transport = FakeTransport(routes=[
        ("/events/public", json_response([])),
        ("api.github.com/users/torvalds", json_response(GITHUB_USER)),
    ], default=text_response("blocked", 403))
    return McpServer(str(tmp_path / "mcp.db"), transport=transport)


def call(server, tool: str, arguments: dict | None = None):
    return server.handle({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments or {}},
    })


def test_initialize_identifies_the_package(server):
    response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    info = response["result"]["serverInfo"]
    assert info["name"] == "osint-rail"
    assert info["version"] == "2.0.0"
    assert response["result"]["capabilities"]["tools"] == {}


def test_tools_list_exposes_three_tools(server):
    response = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = {t["name"]: t for t in response["result"]["tools"]}
    assert set(tools) == {"osint_case", "osint_show", "osint_connectors"}
    assert tools["osint_case"]["inputSchema"]["required"] == ["seed"]
    assert "url" in tools["osint_case"]["inputSchema"]["properties"]["kind"]["enum"]


def test_tools_call_case_runs_offline_and_returns_a_dossier(server):
    response = call(server, "osint_case", {"seed": "torvalds", "depth": 0, "max_requests": 30})
    result = response["result"]
    assert result["content"][0]["type"] == "text"
    assert "Evidence ledger" in result["content"][0]["text"]
    structured = result["structuredContent"]
    assert structured["coverage"]["matched"] >= 1
    assert structured["coverage"]["unknown"] >= 1          # the 403s were recorded
    assert structured["case_id"]
    assert structured["coverage_line"].startswith("matched ")

    case_id = structured["case_id"]
    shown = call(server, "osint_show", {"case_id": case_id})["result"]
    assert "Case " + case_id in shown["content"][0]["text"]

    listing = call(server, "osint_connectors")["result"]["structuredContent"]
    assert listing["count"] >= 20
    assert any(row["name"] == "github" for row in listing["connectors"])


def test_unknown_tool_is_a_jsonrpc_error(server):
    response = call(server, "teapot")
    assert response["error"]["code"] == -32602


def test_missing_seed_returns_an_error_result_not_a_crash(server):
    response = call(server, "osint_case", {})
    assert response["result"]["isError"] is True
    assert "seed is required" in response["result"]["content"][0]["text"]


def test_unknown_method_is_minus_32601(server):
    response = server.handle({"jsonrpc": "2.0", "id": 3, "method": "resources/list"})
    assert response["error"]["code"] == -32601


def test_notifications_get_no_response(server):
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_stdio_loop_skips_notifications_and_reports_parse_errors(server):
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        "{not json",
    ]
    out = io.StringIO()
    server.serve(stdin=io.StringIO("\n".join(lines) + "\n"), stdout=out)
    responses = [json.loads(line) for line in out.getvalue().splitlines()]
    assert len(responses) == 3            # initialize, tools/list, parse error
    assert responses[0]["result"]["serverInfo"]["name"] == "osint-rail"
    assert responses[2]["error"]["code"] == -32700


def test_ping(server):
    assert server.handle({"jsonrpc": "2.0", "id": 9, "method": "ping"})["result"] == {}
