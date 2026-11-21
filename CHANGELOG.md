# Changelog

## 2.0.0 — 2026-11-21

First public release. The engine is the same one that ran privately since 2026-11-15;
this release is the packaging, the tri-state accounting and the tests.

- Renamed the package `osint_core` → `osint_rail`, entry point `osint-rail`.
- Every connector run now stores a check row with one of four outcomes
  (`matched`, `weak`, `absent`, `unknown`), so a dossier can print
  `matched / weak / absent / unknown of N checks` instead of implying silence is absence.
  A 403, a 429, a bot challenge, a crash and a spent budget are all `unknown`.
- New `osint-rail connectors` (from the registry, with the latest observed state) and
  `osint-rail probe <connector> <seed>`.
- `--json` on `case`, `show`, `list`, `connectors` and `probe`; `--quiet`; `--no-color`.
- Stable exit codes: `0` ok, `1` nothing found, `2` every check blocked, `64` usage.
- State moved to `$XDG_STATE_HOME/osint-rail` (or `~/.local/state/osint-rail`),
  overridable with `OSINT_RAIL_HOME`. No absolute paths anywhere.
- One HTTP seam (`transport`) for the whole engine, so the tests never open a socket.
  Per-host request bookkeeping is exposed through `HttpClient.host_stats()`.
- MCP server v2: `osint_case`, `osint_show`, `osint_connectors`; the case response
  carries the coverage counts in `structuredContent`.
- Bugs fixed that the old release lived with: a null MX record (`0 .`) was reported as the
  host `0`; `--no-websearch` / `--username-sites 0` did not switch those connectors off; a
  spent budget inside the username sweep raised `NameError` instead of reporting a partial
  result; and a blocked source was written to the ledger as an absence row.

## 0.2.0 — 2026-11-15

Private. 24 connectors, budgeted BFS, SQLite evidence ledger, markdown dossier, MCP.
17 tests.

## 0.1.0 — 2026-11-14

Private. Email → Gravatar → PGP chain, the `source_url + fetched_at + excerpt` rule.
