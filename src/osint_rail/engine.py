"""Budgeted BFS orchestrator: seeds -> connectors -> claims -> new seeds.

The engine owns two policies the connectors are not allowed to bend:

1. **Budget.** one HttpClient per case, capped by requests and wall clock, with
   a per-host interval and an audit row for every request.
2. **Tri-state.** every connector run becomes one ``Check`` row in the store:
   matched, weak, absent or unknown. A connector that raised, timed out or was
   served a 403 is ``unknown``, never ``absent``.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from . import connectors2  # noqa: F401  (registers the second connector batch)
from .connectors import REGISTRY, Connector, Context, connectors_for  # noqa: F401
from .model import Case, Check, Claim, Result, Seed, Store, coverage, sourced
from .net import BudgetExceeded, HttpClient, Transport
from .resolve import Resolution, resolve

ALLOWED_BY_DEFAULT = {"public", "registration"}


@dataclass
class RunOptions:
    max_depth: int = 2
    max_requests: int = 120
    max_seconds: float = 180.0
    username_sites: int = 40
    username_weak_sites: int = 20
    websearch: bool = True
    allow_registration: bool = True
    allow_sensitive: bool = False
    ai: bool = False
    concurrency: int = 6

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_depth": self.max_depth,
            "max_requests": self.max_requests,
            "max_seconds": self.max_seconds,
            "username_sites": self.username_sites,
            "username_weak_sites": self.username_weak_sites,
            "websearch": self.websearch,
            "allow_registration": self.allow_registration,
            "allow_sensitive": self.allow_sensitive,
            "ai": self.ai,
        }


@dataclass
class RunResult:
    case: Case
    claims: list[Claim]
    resolution: Resolution
    stats: dict[str, Any]
    checks: list[Check] = field(default_factory=list)
    coverage: dict[str, int] = field(default_factory=dict)
    queued: list[Seed] = field(default_factory=list)
    suggested: list[tuple[Seed, str]] = field(default_factory=list)
    ai: dict | None = None
    stop_reason: str = "complete"
    elapsed_s: float = 0.0


def _claim_key(claim: Claim) -> tuple:
    if claim.predicate == "social_link":
        # the same social link is often present on several pages of one site
        return (claim.source, claim.predicate, claim.value.lower())
    return (claim.source, claim.predicate, claim.value.lower(),
            claim.subject_kind, claim.subject_value.lower())


def allowed_sensitivities(options: RunOptions) -> set[str]:
    allowed = {"public"}
    if options.allow_registration:
        allowed.add("registration")
    if options.allow_sensitive:
        allowed |= {"breach", "intrusive"}
    return allowed


def derive_status(result: Result) -> tuple[str, str]:
    """Map a connector's output onto the tri-state, plus the reason shown to the user.

    A connector that answered "no" produced an absence row. A connector that was
    blocked produces a note (or an absence row explicitly marked unknown), and
    becomes ``unknown``. Silence with no note is treated as unknown too: we do
    not know why nothing came back, so we do not claim a negative.
    """
    if result.status:
        return result.status, result.reason
    claims = result.claims
    absences = [c for c in claims if c.kind == "absence"]
    real = [c for c in claims if c.kind not in ("absence", "coverage")]
    if real:
        strong = [c for c in real if c.confidence >= 0.5 and not (c.extra or {}).get("weak")]
        return ("matched" if strong else "weak"), ""
    # Rows written by 0.2 stores: that release recorded UNKNOWN as an absence row.
    unknown = [c for c in absences if c.value in ("unknown", "partial")]
    if unknown:
        return "unknown", unknown[0].excerpt or result.note
    if absences:
        return "absent", absences[0].excerpt
    if result.note:
        return "unknown", result.note
    return "unknown", "connector returned no claims and no note"


class Engine:
    def __init__(self, store: Store, options: RunOptions | None = None,
                 transport: Transport | None = None) -> None:
        self.store = store
        self.options = options or RunOptions()
        self.transport = transport

    def run(self, seed: Seed, title: str = "") -> RunResult:
        started = time.monotonic()
        case = self.store.create_case(seed, self.options.as_dict(), title=title)
        self.store.mark_seed(case.id, seed, 0, "root")
        http = HttpClient(
            max_requests=self.options.max_requests,
            max_seconds=self.options.max_seconds,
            audit=lambda conn, url, status, ms: self.store.log_request(
                case.id, conn, url, status, ms),
            transport=self.transport,
        )
        ctx = Context(case_id=case.id, options=self.options.as_dict(), http=http)
        allowed = allowed_sensitivities(self.options)

        seen_claims: set[tuple] = set()
        frontier: list[tuple[Seed, int]] = [(seed, 0)]
        queued: list[Seed] = []
        checks: list[Check] = []
        stop_reason = "complete"

        while frontier:
            seed_now, depth = frontier.pop(0)
            conns = [c for c in connectors_for(seed_now.kind)
                     if c.sensitivity in allowed and c.enabled(self.options.as_dict())]
            if not conns:
                continue
            results = self._run_connectors(conns, seed_now, ctx)
            for conn, result in results:
                if isinstance(result, BaseException):
                    if isinstance(result, BudgetExceeded):
                        # Not a block and not an absence: the check never finished.
                        stop_reason = f"budget: {result}"
                        checks.append(Check(
                            connector=conn.name, seed_kind=seed_now.kind,
                            seed_value=seed_now.value, status="unknown",
                            reason=f"budget: {result}",
                        ))
                        continue
                    checks.append(Check(
                        connector=conn.name, seed_kind=seed_now.kind,
                        seed_value=seed_now.value, status="unknown",
                        reason=f"connector raised {type(result).__name__}: {result}"[:200],
                    ))
                    continue
                status, reason = derive_status(result)
                checks.append(Check(
                    connector=conn.name, seed_kind=seed_now.kind,
                    seed_value=seed_now.value, status=status, reason=reason[:200],
                ))
                fresh: list[Claim] = []
                for claim in result.claims:
                    key = _claim_key(claim)
                    if key in seen_claims:
                        continue
                    seen_claims.add(key)
                    fresh.append(claim)
                if fresh:
                    self.store.add_claims(case.id, fresh)
                if depth < self.options.max_depth:
                    for new_seed in result.seeds:
                        if self.store.mark_seed(case.id, new_seed, depth + 1, conn.name):
                            frontier.append((new_seed, depth + 1))
                            queued.append(new_seed)
            if stop_reason.startswith("budget"):
                break

        self.store.add_checks(case.id, checks)
        claims = self.store.claims(case.id)
        resolution = resolve(seed, claims)
        suggested = suggest_pivots(seed, claims, queued)
        stats = self.store.stats(case.id)
        elapsed_s = round(time.monotonic() - started, 1)
        cov = coverage(checks)
        cov.update({
            "requests": stats["requests"],
            "seconds": elapsed_s,
            "claims": len(sourced(claims)),
        })

        ai = None
        if self.options.ai:
            try:
                from . import ai as ai_layer

                ai = ai_layer.analyse(seed, claims, resolution)
            except Exception as exc:  # AI is optional; never fail the case on it
                ai = {"error": str(exc)[:200]}

        return RunResult(
            case=case,
            claims=claims,
            resolution=resolution,
            stats=stats,
            checks=checks,
            coverage=cov,
            queued=queued,
            suggested=suggested,
            ai=ai,
            stop_reason=stop_reason,
            elapsed_s=elapsed_s,
        )

    def _run_connectors(
        self, conns: list[Connector], seed: Seed, ctx: Context
    ) -> list[tuple[Connector, Result | BaseException]]:
        out: list[tuple[Connector, Result | BaseException]] = []
        workers = min(self.options.concurrency, len(conns))
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {pool.submit(c.run, seed, ctx): c for c in conns}
            for future in as_completed(futures):
                conn = futures[future]
                try:
                    out.append((conn, future.result()))
                except BaseException as exc:  # noqa: BLE001 - recorded, not swallowed
                    out.append((conn, exc))
        return out


def registry_names() -> list[str]:
    return [c.name for c in REGISTRY]


def suggest_pivots(seed: Seed, claims: list[Claim],
                   already: list[Seed]) -> list[tuple[Seed, str]]:
    """Seeds a human/LLM would try next, derived only from what was actually found."""
    have = {s.key() for s in already} | {seed.key()}
    out: list[tuple[Seed, str]] = []
    seen: set[str] = set()

    def add(kind: str, value: str, why: str) -> None:
        value = (value or "").strip()
        if not value:
            return
        try:
            s = Seed(kind, value)
        except ValueError:
            return
        if s.key() in have or s.key() in seen:
            return
        seen.add(s.key())
        out.append((s, why))

    for claim in claims:
        if claim.kind == "contact" and claim.predicate == "email":
            add("email", claim.value, f"email exposed by {claim.source}")
        elif claim.kind == "account":
            username = (claim.extra or {}).get("username")
            if username:
                add("username", str(username), f"username on {claim.source}")
        elif claim.kind == "profile" and claim.predicate in (
                "blog", "twitter_username", "profile_url"):
            value = claim.value
            if claim.predicate == "blog":
                host = value.replace("https://", "").replace("http://", "").split("/")[0]
                if "." in host:
                    add("domain", host, f"site linked from {claim.source} profile")
            elif claim.predicate == "twitter_username":
                add("handle", value, f"handle linked from {claim.source} profile")
        elif claim.kind == "domain" and claim.predicate == "hostname":
            add("domain", claim.value, f"hostname from {claim.source}")
    return out[:15]
