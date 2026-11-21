"""Models, constants and the SQLite evidence store.

Three record types are stored per case:

* ``claims``   — sourced assertions (the evidence ledger).
* ``checks``   — the tri-state outcome of every connector run, so a dossier can
                 say "12 checks: 5 matched, 1 weak, 4 absent, 2 unknown" rather
                 than treating silence as absence.
* ``requests`` — one audit row per HTTP request, with status and elapsed ms.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Seed kinds the engine routes on.
SEED_KINDS = ("email", "username", "phone", "domain", "ip", "name", "handle", "url")

# Sensitivity ladder. Breach/intrusive connectors are refused unless explicitly enabled.
SENSITIVITY = ("public", "registration", "breach", "intrusive")

# Tri-state outcome of one connector run. "weak" is a hit we do not trust enough
# to call matched (a status-only probe); "unknown" is a source that refused to
# answer. Only "absent" is a genuine negative.
CHECK_STATES = ("matched", "weak", "absent", "unknown")

_SEED_KIND_ALIASES = {
    "mail": "email",
    "e-mail": "email",
    "user": "username",
    "login": "username",
    "nick": "username",
    "host": "domain",
    "website": "domain",
    "site": "domain",
    "person": "name",
}

_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", re.I
)


def normalise_seed_kind(kind: str) -> str:
    k = (kind or "").strip().lower()
    k = _SEED_KIND_ALIASES.get(k, k)
    if k not in SEED_KINDS:
        raise ValueError(f"unknown seed kind {kind!r}; expected one of {', '.join(SEED_KINDS)}")
    return k


def detect_kind(value: str) -> str:
    """Guess a seed kind from its shape. Ambiguity resolves to username."""
    v = (value or "").strip()
    if "@" in v and "." in v.split("@")[-1]:
        return "email"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.match(v):
        return "domain"
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    return "username"


@dataclass(frozen=True)
class Seed:
    kind: str
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", normalise_seed_kind(self.kind))
        object.__setattr__(self, "value", self.value.strip())

    def key(self) -> str:
        return f"{self.kind}:{self.value.lower()}"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.key()


@dataclass
class Claim:
    """One sourced assertion about the case subject."""

    kind: str            # account | profile | contact | domain | ip | package | key | mention | absence
    predicate: str       # e.g. full_name, profile_url, email, mx_provider
    value: str
    source: str          # connector name
    source_url: str
    excerpt: str
    fetched_at: str
    confidence: float    # 0..1
    sensitivity: str = "public"
    subject_kind: str = ""
    subject_value: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def as_row(self, case_id: str) -> tuple:
        return (
            case_id,
            self.kind,
            self.predicate,
            self.value,
            self.source,
            self.source_url,
            self.excerpt,
            self.fetched_at,
            float(self.confidence),
            self.sensitivity,
            self.subject_kind,
            self.subject_value,
            json.dumps(self.extra, sort_keys=True),
        )


@dataclass
class Check:
    """The outcome of one connector against one seed."""

    connector: str
    seed_kind: str
    seed_value: str
    status: str
    reason: str = ""
    fetched_at: str = ""

    def __post_init__(self) -> None:
        if self.status not in CHECK_STATES:
            raise ValueError(f"unknown check status {self.status!r}")
        if not self.fetched_at:
            self.fetched_at = now_iso()

    def as_row(self, case_id: str) -> tuple:
        return (case_id, self.connector, self.seed_kind, self.seed_value,
                self.status, self.reason, self.fetched_at)

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector": self.connector,
            "seed": f"{self.seed_kind}:{self.seed_value}",
            "status": self.status,
            "reason": self.reason,
            "fetched_at": self.fetched_at,
        }


def sourced(claims: Iterable[Claim]) -> list[Claim]:
    """Claims that assert something found (not an absence row, not a coverage row)."""
    return [c for c in claims if c.kind not in ("absence", "coverage")]


def coverage(checks: Iterable[Check]) -> dict[str, int]:
    """Counts for the line every run prints: matched / weak / absent / unknown."""
    out = {state: 0 for state in CHECK_STATES}
    total = 0
    for check in checks:
        out[check.status] = out.get(check.status, 0) + 1
        total += 1
    out["checks"] = total
    return out


@dataclass
class Result:
    claims: list[Claim] = field(default_factory=list)
    seeds: list[Seed] = field(default_factory=list)
    note: str = ""
    status: str = ""
    reason: str = ""


@dataclass
class Case:
    id: str
    seed: Seed
    created_at: str
    options: dict[str, Any]
    title: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "seed_kind": self.seed.kind,
            "seed_value": self.seed.value,
            "created_at": self.created_at,
            "title": self.title,
            "options": self.options,
        }


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  seed_kind TEXT NOT NULL,
  seed_value TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  options_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS claims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL REFERENCES cases(id),
  kind TEXT NOT NULL,
  predicate TEXT NOT NULL,
  value TEXT NOT NULL,
  source TEXT NOT NULL,
  source_url TEXT NOT NULL,
  excerpt TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  confidence REAL NOT NULL,
  sensitivity TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  subject_value TEXT NOT NULL,
  extra_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS claims_case ON claims(case_id);
CREATE INDEX IF NOT EXISTS claims_value ON claims(case_id, predicate, value);
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  connector TEXT NOT NULL,
  seed_kind TEXT NOT NULL,
  seed_value TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS checks_case ON checks(case_id);
CREATE INDEX IF NOT EXISTS checks_connector ON checks(connector, id);
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  connector TEXT NOT NULL,
  url TEXT NOT NULL,
  status INTEGER NOT NULL,
  elapsed_ms INTEGER NOT NULL,
  fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS seeds (
  case_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  depth INTEGER NOT NULL,
  added_by TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  PRIMARY KEY (case_id, kind, value)
);
"""


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self.db.executescript(SCHEMA)
        self.db.commit()

    # -- cases ---------------------------------------------------------
    def create_case(self, seed: Seed, options: dict[str, Any], title: str = "") -> Case:
        case = Case(id=uuid.uuid4().hex[:12], seed=seed, created_at=now_iso(),
                    options=options, title=title)
        self.db.execute(
            "INSERT INTO cases (id, seed_kind, seed_value, title, created_at, options_json)"
            " VALUES (?,?,?,?,?,?)",
            (case.id, seed.kind, seed.value, title, case.created_at,
             json.dumps(options, sort_keys=True)),
        )
        self.db.commit()
        return case

    def get_case(self, case_id: str) -> Case | None:
        row = self.db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            return None
        return Case(
            id=row["id"],
            seed=Seed(row["seed_kind"], row["seed_value"]),
            created_at=row["created_at"],
            options=json.loads(row["options_json"]),
            title=row["title"],
        )

    def list_cases(self, limit: int = 20) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM cases ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
        ).fetchall()

    def delete_case(self, case_id: str) -> bool:
        existed = self.get_case(case_id) is not None
        for table in ("claims", "checks", "requests", "seeds"):
            self.db.execute(f"DELETE FROM {table} WHERE case_id=?", (case_id,))
        self.db.execute("DELETE FROM cases WHERE id=?", (case_id,))
        self.db.commit()
        return existed

    # -- claims --------------------------------------------------------
    def add_claims(self, case_id: str, claims: Iterable[Claim]) -> int:
        rows = [c.as_row(case_id) for c in claims]
        if not rows:
            return 0
        with self._lock:
            self.db.executemany(
                "INSERT INTO claims (case_id, kind, predicate, value, source, source_url, excerpt,"
                " fetched_at, confidence, sensitivity, subject_kind, subject_value, extra_json)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self.db.commit()
        return len(rows)

    def claims(self, case_id: str) -> list[Claim]:
        out: list[Claim] = []
        for row in self.db.execute("SELECT * FROM claims WHERE case_id=? ORDER BY id", (case_id,)):
            out.append(
                Claim(
                    kind=row["kind"],
                    predicate=row["predicate"],
                    value=row["value"],
                    source=row["source"],
                    source_url=row["source_url"],
                    excerpt=row["excerpt"],
                    fetched_at=row["fetched_at"],
                    confidence=row["confidence"],
                    sensitivity=row["sensitivity"],
                    subject_kind=row["subject_kind"],
                    subject_value=row["subject_value"],
                    extra=json.loads(row["extra_json"]),
                )
            )
        return out

    def claim_values(self, case_id: str, predicate: str) -> list[str]:
        return [r["value"] for r in self.db.execute(
            "SELECT value FROM claims WHERE case_id=? AND predicate=? ORDER BY confidence DESC",
            (case_id, predicate),
        )]

    # -- checks --------------------------------------------------------
    def add_checks(self, case_id: str, checks: Iterable[Check]) -> int:
        rows = [c.as_row(case_id) for c in checks]
        if not rows:
            return 0
        with self._lock:
            self.db.executemany(
                "INSERT INTO checks (case_id, connector, seed_kind, seed_value, status, reason,"
                " fetched_at) VALUES (?,?,?,?,?,?,?)",
                rows,
            )
            self.db.commit()
        return len(rows)

    def checks(self, case_id: str) -> list[Check]:
        return [
            Check(
                connector=row["connector"],
                seed_kind=row["seed_kind"],
                seed_value=row["seed_value"],
                status=row["status"],
                reason=row["reason"],
                fetched_at=row["fetched_at"],
            )
            for row in self.db.execute(
                "SELECT * FROM checks WHERE case_id=? ORDER BY id", (case_id,)
            )
        ]

    def last_connector_states(self) -> dict[str, dict[str, str]]:
        """Latest observed status per connector, across every stored case."""
        last: dict[str, dict[str, str]] = {}
        for row in self.db.execute(
            "SELECT connector, status, fetched_at FROM checks ORDER BY id"
        ):
            last[row["connector"]] = {
                "status": row["status"],
                "fetched_at": row["fetched_at"],
            }
        return last

    # -- seeds / requests ---------------------------------------------
    def mark_seed(self, case_id: str, seed: Seed, depth: int, added_by: str) -> bool:
        """True if newly queued, False if already seen."""
        try:
            self.db.execute(
                "INSERT INTO seeds (case_id, kind, value, depth, added_by, fetched_at)"
                " VALUES (?,?,?,?,?,?)",
                (case_id, seed.kind, seed.value, depth, added_by, now_iso()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def log_request(self, case_id: str, connector: str, url: str, status: int,
                    elapsed_ms: int) -> None:
        with self._lock:
            self.db.execute(
                "INSERT INTO requests (case_id, connector, url, status, elapsed_ms, fetched_at)"
                " VALUES (?,?,?,?,?,?)",
                (case_id, connector, url, status, elapsed_ms, now_iso()),
            )
            self.db.commit()

    def requests(self, case_id: str) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM requests WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall()

    def stats(self, case_id: str) -> dict[str, Any]:
        n_claims = self.db.execute(
            "SELECT COUNT(*) c FROM claims WHERE case_id=?", (case_id,)
        ).fetchone()["c"]
        n_reqs = self.db.execute(
            "SELECT COUNT(*) c FROM requests WHERE case_id=?", (case_id,)
        ).fetchone()["c"]
        n_sources = self.db.execute(
            "SELECT COUNT(DISTINCT source) c FROM claims WHERE case_id=?", (case_id,)
        ).fetchone()["c"]
        return {"claims": n_claims, "requests": n_reqs, "sources": n_sources}

    def close(self) -> None:
        self.db.close()
