# How osint-rail works

One page. If you are adding a connector, read [CONTRIBUTING.md](../CONTRIBUTING.md) instead.

## The flow

```
 Seed(kind, value)
      │
      ▼
 Engine.run()                            engine.py:114
      │  create case, mark the root seed
      │
      ├──► connectors_for(kind)          connectors.py:59  (registry lookup)
      │        filters: sensitivity allowed (engine.py:78)
      │                 connector.enabled(options) (connectors.py:43)
      │
      ├──► ThreadPoolExecutor            engine.py:223
      │        each connector gets the same Context: case id, options, one HttpClient
      │
      ├──► Result(claims, seeds, note)   model.py:177
      │
      ├──► derive_status(result)         engine.py:87
      │        claims        -> matched | weak
      │        absence row   -> absent
      │        value unknown -> unknown
      │        note / crash / budget -> unknown
      │
      ├──► Store.add_claims / add_checks model.py:317, model.py:359
      │
      └──► new seeds queued at depth + 1, deduped by (kind, lower(value))
```

The BFS is breadth-first over seeds, not over pages. Depth 0 runs the connectors for the
seed you gave it; depth 1 also runs the connectors for each seed those connectors returned
(an A record becomes an IP seed, a Gravatar account becomes a username seed). Deduplication
happens in two places: `Store.mark_seed` uses a primary key on `(case_id, kind, value)`, and
`_claim_key` in `engine.py` drops duplicate claim rows before they are written.

## Where the evidence rule lives

Three lines of code do the work that the README claims:

1. **`_c()`** (`connectors.py:63`) is the only constructor used by the shipped connectors.
   It takes `source`, `url` and `excerpt_text` as required keyword arguments, so a connector
   cannot forget one and still return a claim.
2. **`Claim.as_row()`** (`model.py:111`) writes thirteen columns, and the `claims` table in
   `SCHEMA` (`model.py:208`) marks `source_url`, `excerpt` and `fetched_at` as `NOT NULL`.
3. **`render_markdown()`** (`report.py:83`) never prints a claim without its source column,
   and `case_json()` (`report.py:296`) emits `url` and `excerpt` on every claim object.

The excerpt is capped at 220 characters and whitespace-collapsed (`excerpt()`, `net.py:203`), so a
ledger stays readable; it is always a slice of the response, never a paraphrase.

## Where the tri-state rule lives

- `CHECK_STATES` (`model.py:34`) is the closed set. `Check.__post_init__` raises on anything
  else, so a typo cannot invent a state.
- `derive_status()` (`engine.py:87`) is the only mapping from connector output to state. An
  absence row is `absent`. A note is `unknown`, and a connector that returns neither is
  `unknown` too, because nobody can say why it was empty. (A 0.2 store can still hold
  absence rows whose value is `unknown`; that legacy branch stays for old databases.)
- Blocked statuses are defined once in `BLOCK_STATUSES` (`net.py:27`) and exposed as
  `Response.blocked`.
- The engine records a check even when the budget runs out mid-connector (`engine.py:153`)
  or a connector raises (`engine.py:159`), so "not checked" and "checked and blocked" both
  survive into the dossier as `unknown` with a reason.

## Where the budget and the politeness live

`HttpClient` (`net.py:81`) owns both. `_charge()` (`net.py:110`) raises `BudgetExceeded`
before the request leaves, so a connector cannot overspend by catching errors. `_throttle()`
(`net.py:118`) holds one lock per host and sleeps to keep at least one second between
requests to the same host. Every request goes through `self.transport(...)` (`net.py:170`):
the default is `urllib_transport` (`net.py:65`), and the tests pass a fake callable with the
same signature. That single indirection is why the whole suite runs with no sockets.

Per-host counts are kept in memory and readable through `host_stats()` (`net.py:128`); the
durable record is one row per request in the `requests` table, written by the audit callback
the engine passes in.

## Where identity is decided

`resolve()` (`resolve.py:103`) builds entities from deterministic keys only: an account on a
site, a profile URL, an email address, a domain record. Two profiles that look similar are
never merged. They become a `Candidate` with a score and a reason list, emitted only at
`score >= 0.45` (`resolve.py:163`). The report prints candidates under "Identity resolution"
and says they are guesses.

## Where the output goes

`write_report()` (`report.py:329`) writes three files per case into the state directory:

| file | contents |
|---|---|
| `<id>_<seed>.md` | the dossier: coverage, checks, claims, candidates, pivots |
| `<id>_<seed>.json` | the same content as one machine-readable object |
| `<id>_<seed>.graph.json` | nodes and edges for a graph view (deterministic merges plus candidate edges) |

`osint-rail show <id>` re-renders the markdown from SQLite without any network access, and
`osint-rail mcp` serves the same dossier over stdio (`mcp_server.py`).

## What is deliberately not here

No proxy rotation, no browser automation, no CAPTCHA handling, no login, no breach data, no
model in the fetch path. The AI layer (`ai.py`) is optional, off by default, and only ever
sees claims that already exist in the ledger.
