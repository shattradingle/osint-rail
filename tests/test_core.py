import tempfile
import unittest
from pathlib import Path
from unittest import mock

from osint_rail.connectors import Connector, Context
from osint_rail.engine import Engine, RunOptions, suggest_pivots
from osint_rail.model import Claim, Result, Seed, Store, now_iso
from osint_rail.report import graph_json, render_markdown
from osint_rail.resolve import jaccard, resolve


def claim(**kw):
    base = dict(
        kind="profile", predicate="full_name", value="Jane Doe", source="fake",
        source_url="https://example.test/u", excerpt="Jane Doe", fetched_at=now_iso(),
        confidence=0.8, subject_kind="username", subject_value="janedoe",
    )
    base.update(kw)
    return Claim(**base)


class FakeConnector(Connector):
    name = "fake"
    accepts = frozenset({"username"})
    sensitivity = "public"

    def run(self, seed: Seed, ctx: Context) -> Result:
        return Result(
            claims=[
                claim(predicate="full_name", value="Jane Doe", extra={"profile_url": "https://example.test/u"}),
                claim(kind="contact", predicate="email", value="jane@example.test", confidence=0.6),
            ],
            seeds=[Seed("email", "jane@example.test")],
        )


class SeedTests(unittest.TestCase):
    def test_alias_and_validation(self):
        self.assertEqual(Seed("mail", "a@b.co").kind, "email")
        self.assertEqual(Seed(" USERNAME ", "Bob").value, "Bob")
        with self.assertRaises(ValueError):
            Seed("nonsense", "x")

    def test_key_is_lowercased(self):
        self.assertEqual(Seed("username", "Bob").key(), "username:bob")


class StoreTests(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "cases.db")
            case = store.create_case(Seed("username", "bob"), {"x": 1})
            self.assertIsNotNone(store.get_case(case.id))
            n = store.add_claims(case.id, [claim(), claim(predicate="bio", value="hi")])
            self.assertEqual(n, 2)
            self.assertEqual(len(store.claims(case.id)), 2)
            self.assertTrue(store.mark_seed(case.id, Seed("email", "bob@x.co"), 1, "test"))
            self.assertFalse(store.mark_seed(case.id, Seed("email", "bob@x.co"), 1, "test"))
            store.log_request(case.id, "fake", "https://x", 200, 10)
            self.assertEqual(store.stats(case.id)["requests"], 1)


class ResolveTests(unittest.TestCase):
    def test_deterministic_entities(self):
        claims = [
            claim(kind="account", predicate="account", value="bob@github",
                  extra={"domain": "github.com", "username": "bob", "profile_url": "https://github.com/bob"}),
            claim(kind="contact", predicate="email", value="Bob@Example.com"),
        ]
        res = resolve(Seed("username", "bob"), claims)
        kinds = {e.kind for e in res.entities}
        self.assertIn("account", kinds)
        self.assertIn("email", kinds)
        self.assertTrue(any(e.id == "email:bob@example.com" for e in res.entities))
        self.assertGreaterEqual(len(res.edges), 2)

    def test_candidate_needs_evidence(self):
        a = claim(source="github", extra={"profile_url": "https://github.com/bob"})
        b = claim(source="bluesky", value="Jane Doe", extra={"profile_url": "https://bsky.app/bob"})
        res = resolve(Seed("username", "bob"), [a, b])
        self.assertTrue(res.candidates)
        self.assertGreater(res.candidates[0].score, 0.45)

    def test_jaccard(self):
        self.assertAlmostEqual(jaccard("Jane Doe", "jane doe"), 1.0)
        self.assertEqual(jaccard("", "x"), 0.0)


class EngineTests(unittest.TestCase):
    def test_bfs_stores_claims_and_queues(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "c.db")
            with mock.patch("osint_rail.engine.connectors_for",
                            side_effect=lambda kind: [FakeConnector()] if kind == "username" else []):
                result = Engine(store, RunOptions(max_depth=1, max_requests=5)).run(Seed("username", "janedoe"))
            self.assertEqual(len(result.claims), 2)
            self.assertEqual(result.stats["requests"], 0)  # fake connector does no HTTP
            self.assertEqual([s.key() for s in result.queued], ["email:jane@example.test"])
            self.assertIn("https://example.test/u", render_markdown(result))

    def test_depth_zero_runs_only_root(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "c.db")
            with mock.patch("osint_rail.engine.connectors_for", return_value=[FakeConnector()]):
                result = Engine(store, RunOptions(max_depth=0)).run(Seed("username", "janedoe"))
            self.assertEqual(result.queued, [])

    def test_suggest_pivots_from_claims(self):
        claims = [claim(kind="contact", predicate="email", value="x@y.co", source="github")]
        seeds = [s for s, _ in suggest_pivots(Seed("username", "bob"), claims, [])]
        self.assertEqual(seeds[0].key(), "email:x@y.co")


class ReportTests(unittest.TestCase):
    def test_graph_and_table(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "c.db")
            with mock.patch("osint_rail.engine.connectors_for", return_value=[FakeConnector()]):
                result = Engine(store, RunOptions(max_depth=0)).run(Seed("username", "janedoe"))
            md = render_markdown(result)
            self.assertIn("Evidence ledger", md)
            self.assertIn("Jane Doe", md)
            graph = graph_json(result)
            self.assertTrue(graph["elements"]["nodes"])
            self.assertTrue(graph["elements"]["edges"])


class McpTests(unittest.TestCase):
    def test_initialize_and_tools(self):
        from osint_rail.mcp_server import McpServer

        with tempfile.TemporaryDirectory() as td:
            server = McpServer(str(Path(td) / "c.db"))
            init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            self.assertEqual(init["result"]["serverInfo"]["name"], "osint-rail")
            tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            names = {t["name"] for t in tools["result"]["tools"]}
            self.assertEqual(names, {"osint_case", "osint_show", "osint_connectors"})
            bad = server.handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})
            self.assertEqual(bad["error"]["code"], -32601)


class CliTests(unittest.TestCase):
    def test_detect_kind(self):
        from osint_rail.cli import detect_kind

        self.assertEqual(detect_kind("a@b.com"), "email")
        self.assertEqual(detect_kind("8.8.8.8"), "ip")
        self.assertEqual(detect_kind("example.com"), "domain")
        self.assertEqual(detect_kind("torvalds"), "username")


if __name__ == "__main__":
    unittest.main()


class ParserTests(unittest.TestCase):
    def test_ddg_lite_parser(self):
        from osint_rail.connectors2 import parse_ddg_lite

        page = (
            '<a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fx&amp;rut=1" '
            "class='result-link'>Example &amp; Co</a>"
            "<td class='result-snippet'>Hello <b>world</b></td>"
            '<a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fy" '
            "class='result-link'>Second</a>"
            "<td class='result-snippet'>Another snippet</td>"
        )
        rows = parse_ddg_lite(page)
        self.assertEqual(rows[0]["url"], "https://example.com/x")
        self.assertEqual(rows[0]["title"], "Example & Co")
        self.assertEqual(rows[0]["snippet"], "Hello world")
        self.assertEqual(len(rows), 2)

    def test_registry_has_extra_connectors(self):
        from osint_rail.connectors import REGISTRY
        import osint_rail.engine  # noqa: F401 - registers connectors2

        names = {c.name for c in REGISTRY}
        for required in ("gitlab", "telegram", "mojang", "websearch", "github_commits", "urlscan"):
            self.assertIn(required, names)
        self.assertGreaterEqual(len(names), 20)


class ParserTests2(unittest.TestCase):
    def test_ch_officer_filter(self):
        from osint_rail.connectors2 import parse_ch_officers

        page = (
            '<a href="/officers/ONE/appointments">Linus ADLER</a>'
            '<a href="/officers/TWO/appointments">Linus Torvalds</a>'
            '<a href="/officers/THREE/appointments">Torvalds, Linus B</a>'
        )
        rows = parse_ch_officers(page, "Linus Torvalds")
        names = [r["name"] for r in rows]
        self.assertIn("Linus Torvalds", names)
        self.assertIn("Torvalds, Linus B", names)
        self.assertNotIn("Linus ADLER", names)
        self.assertTrue(all(r["url"].startswith("https://find-and-update") for r in rows))


class PageExtractTests(unittest.TestCase):
    def test_extract(self):
        from osint_rail.connectors2 import extract_page

        page = (
            "<html><head><title>Jane's Site</title>"
            '<meta name="description" content="Portfolio and contact">'
            "</head><body>"
            '<a href="mailto:jane@example.org">mail</a>'
            '<a href="https://github.com/janedoe">gh</a>'
            '<a href="tel:+44 7700 900123">call</a>'
            '<img src="logo@2x.png">'
            "</body></html>"
        )
        found = extract_page(page, "https://jane.example.org")
        self.assertEqual(found["title"], "Jane's Site")
        self.assertEqual(found["description"], "Portfolio and contact")
        self.assertIn("jane@example.org", found["emails"])
        self.assertTrue(any(s["platform"] == "github" and s["handle"] == "janedoe" for s in found["socials"]))
        self.assertTrue(found["phones"])
