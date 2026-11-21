# Adding a connector

A connector is one class in `src/osint_rail/connectors.py` or `connectors2.py`.

1. Subclass `Connector`; set `name`, `accepts` (a frozenset of seed kinds), `description`
   and `sensitivity` (`public` or `registration`). Decorate with `@register`.
2. Fetch only through `ctx.http.get()` / `ctx.http.get_json()`. Never call `urllib`
   directly, or the request escapes the budget, the audit trail and the tests.
3. Return `Result(claims=[...])`. Every claim needs `source_url`, `fetched_at`, `excerpt`
   and a confidence. Use `_c(...)`; it fills the boilerplate.
4. Answered "no" → an `absence` claim. Blocked, challenged or timed out → `Result(note=...)`;
   the engine records that as `unknown`. Never turn a block into an absence.
5. Add a test in `tests/test_connectors.py` using `FakeTransport` and run `pytest -q`.
6. Probe it live: `osint-rail probe yourname <seed>`, then `osint-rail connectors`.
