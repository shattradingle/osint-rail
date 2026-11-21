"""Case report: markdown dossier, JSON dossier and cytoscape-style graph JSON."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace

from .engine import RunResult
from .model import Claim, Check, coverage, now_iso, sourced

_ORDER = {
    "profile": 0,
    "account": 1,
    "contact": 2,
    "domain": 3,
    "ip": 4,
    "package": 5,
    "key": 6,
    "mention": 7,
    "coverage": 8,
    "absence": 9,
}

_SAFE = re.compile(r"[^a-zA-Z0-9_.-]+")


def _md_escape(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(rows: list[list[str]], header: list[str]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


def _counts(claims: list[Claim]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for claim in claims:
        counts[claim.source] += 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def _top_claims(claims: list[Claim], limit: int = 25) -> list[Claim]:
    ranked = sorted(claims, key=lambda c: (_ORDER.get(c.kind, 8), -c.confidence))
    return ranked[:limit]


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def coverage_line(cov: dict) -> str:
    """The one line every run prints, and the first thing a reader checks."""
    return (
        f"matched {cov.get('matched', 0)} / weak {cov.get('weak', 0)} / "
        f"absent {cov.get('absent', 0)} / unknown {cov.get('unknown', 0)} "
        f"of {_plural(cov.get('checks', 0), 'check')} | "
        f"{_plural(cov.get('requests', 0), 'request')} | {cov.get('seconds', 0)}s | "
        f"{_plural(cov.get('claims', 0), 'claim')}"
    )


def _cov_of(result) -> dict:
    cov = dict(getattr(result, "coverage", None) or {})
    if cov.get("checks"):
        return cov
    checks = getattr(result, "checks", None) or []
    if checks:
        cov = coverage(checks)
        cov.update({
            "requests": result.stats.get("requests", 0),
            "seconds": getattr(result, "elapsed_s", 0),
            "claims": len(sourced(result.claims)),
        })
    return cov


def render_markdown(result: RunResult) -> str:
    case, claims, res = result.case, result.claims, result.resolution
    absences = [c for c in claims if c.kind == "absence"]
    real = sourced(claims)
    counts = _counts(real)
    date = case.created_at[:10]
    cov = _cov_of(result)

    lines: list[str] = [
        "---",
        f"created: {date}",
        "project: osint-rail",
        "type: case",
        "status: draft",
        f"case_id: {case.id}",
        "---",
        "",
        f"# Case {case.id} - {case.seed.kind}:{case.seed.value}",
        "",
        f"*Generated {now_iso()} | {result.stats['requests']} requests | "
        f"{len(real)} sourced claims | {len(claims)} rows | {result.elapsed_s}s | "
        f"stop: {result.stop_reason}*",
        "",
        "## Coverage",
        "",
        f"`{coverage_line(cov)}`",
        "",
    ]
    checks = list(getattr(result, "checks", None) or [])
    if checks:
        rows = []
        for check in checks:
            rows.append([
                _md_escape(check.connector),
                _md_escape(f"{check.seed_kind}:{check.seed_value}"),
                _md_escape(check.status),
                _md_escape(check.reason)[:120],
            ])
        lines.append(_table(rows, ["connector", "seed", "outcome", "reason"]))
        lines.append("")

    lines += ["## Verdict", ""]
    if real:
        sources = ", ".join(f"{s} ({n})" for s, n in list(counts.items())[:6])
        negative = len(absences)
        lines.append(
            f"Found {len(real)} sourced claims across {len(counts)} sources for "
            f"`{case.seed.value}`. Strongest sources: {sources}. "
            f"{negative} negative check{'s' if negative != 1 else ''} recorded. "
            "Treat every line as a lead with a source, not an established fact."
        )
        if case.seed.kind in ("username", "handle"):
            lines.append("")
            lines.append(
                "**Same handle is not the same person.** The accounts below are places where this "
                "string is registered; they are leads for verification, not one identity. Only the "
                "scored candidate links claim anything about identity."
            )
    else:
        lines.append(
            f"No sourced claims were returned for `{case.seed.value}` within the budget. "
            "That is a coverage result, not proof the subject has no footprint."
        )
    lines += ["", "## What was found", ""]
    rows = []
    for claim in _top_claims(real):
        rows.append([
            _md_escape(claim.kind),
            _md_escape(claim.predicate),
            _md_escape(claim.value)[:120],
            _md_escape(claim.source),
            f"{claim.confidence:.2f}",
            f"[evidence]({claim.source_url})" if claim.source_url else "",
        ])
    if rows:
        lines.append(_table(rows, ["kind", "field", "value", "source", "conf", "source"]))
    else:
        lines.append("_Nothing._")

    lines += ["", "## Identity resolution", ""]
    lines.append(
        f"{len(res.entities)} entities, {len(res.edges)} sourced edges. "
        "Merges below are deterministic only; candidate links are scored guesses."
    )
    lines.append("")
    if res.candidates:
        rows = []
        for cand in res.candidates[:10]:
            by_id = res.by_id()
            a = by_id.get(cand.a)
            b = by_id.get(cand.b)
            rows.append([
                _md_escape(f"{a.label if a else cand.a} / {b.label if b else cand.b}"),
                f"{cand.score:.2f}",
                _md_escape("; ".join(cand.reasons)),
            ])
        lines.append(_table(rows, ["candidate pair", "score", "why"]))
    else:
        lines.append("_No cross-profile candidates above threshold._")

    lines += ["", "## Evidence ledger", ""]
    rows = []
    for claim in sorted(claims, key=lambda c: (_ORDER.get(c.kind, 8), c.source)):
        rows.append([
            _md_escape(claim.source),
            _md_escape(claim.predicate),
            _md_escape(claim.value)[:90],
            f"{claim.confidence:.2f}",
            _md_escape(claim.excerpt)[:160],
            f"[{_md_escape(_host(claim.source_url))}]({claim.source_url})",
        ])
    lines.append(_table(rows, ["source", "field", "value", "conf", "excerpt", "url"]))

    lines += ["", "## Checked - negative or unknown", ""]
    if absences:
        for claim in absences:
            lines.append(f"- {claim.source}: {claim.excerpt} ([source]({claim.source_url}))")
    else:
        lines.append("_No negative results recorded._")

    lines += ["", "## Next pivots", ""]
    if result.queued:
        lines.append("Seeds followed:")
        lines.append("")
        for seed in result.queued[:20]:
            lines.append(f"- `{seed.kind}:{seed.value}`")
        lines.append("")
    if result.suggested:
        lines.append("Suggested, not run:")
        lines.append("")
        for seed, why in result.suggested[:15]:
            lines.append(f"- `{seed.kind}:{seed.value}` - {why}")

    if result.ai:
        lines += ["", "## AI analysis", ""]
        if result.ai.get("error"):
            lines.append(f"_AI layer failed: {result.ai['error']}_")
        else:
            for key in ("summary", "pivots", "risks"):
                value = result.ai.get(key)
                if not value:
                    continue
                lines.append(f"**{key}**")
                lines.append("")
                if isinstance(value, list):
                    for item in value:
                        lines.append(f"- {item}")
                else:
                    lines.append(str(value))
                lines.append("")

    lines += [
        "",
        "## Run & limits",
        "",
        f"- Budget: depth {case.options.get('max_depth')}, "
        f"{case.options.get('max_requests')} requests / {case.options.get('max_seconds')}s; "
        f"{result.stats['requests']} used.",
        f"- Sensitivity: registration checks "
        f"{'on' if case.options.get('allow_registration') else 'off'}; breach/intrusive "
        f"{'on' if case.options.get('allow_sensitive') else 'off (blocked by policy)'}.",
        "- Every claim above is single-sourced unless two rows agree on the same value. "
        "Absence means the connector answered, not that the account does not exist.",
        f"- Delete with `osint-rail delete {case.id}`.",
        "",
    ]
    return "\n".join(lines)


def _host(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url or "")
    return m.group(1) if m else (url or "")[:40]


def graph_json(result: RunResult) -> dict:
    nodes = []
    for entity in result.resolution.entities:
        nodes.append({
            "data": {
                "id": entity.id,
                "label": entity.label,
                "kind": entity.kind,
                "value": entity.value,
                "url": entity.url,
                "confidence": round(entity.confidence, 2),
                "claims": entity.claim_count,
            }
        })
    edges = []
    for i, edge in enumerate(result.resolution.edges):
        edges.append({
            "data": {
                "id": f"e{i}",
                "source": edge.src,
                "target": edge.dst,
                "label": edge.label,
                "confidence": round(edge.confidence, 2),
            }
        })
    for i, cand in enumerate(result.resolution.candidates):
        edges.append({
            "data": {
                "id": f"c{i}",
                "source": cand.a,
                "target": cand.b,
                "label": f"candidate {cand.score:.2f}",
                "confidence": cand.score,
                "candidate": True,
            }
        })
    return {"elements": {"nodes": nodes, "edges": edges}}


def case_json(result: RunResult) -> dict:
    """One machine-readable object for `--json` and for MCP structuredContent."""
    cov = _cov_of(result)
    return {
        "case": result.case.as_dict(),
        "coverage": cov,
        "coverage_line": coverage_line(cov),
        "stats": result.stats,
        "stop_reason": result.stop_reason,
        "elapsed_s": result.elapsed_s,
        "checks": [c.as_dict() for c in getattr(result, "checks", []) or []],
        "queued": [s.key() for s in result.queued],
        "suggested": [{"seed": s.key(), "why": why} for s, why in result.suggested],
        "ai": result.ai,
        "claims": [
            {
                "kind": c.kind, "predicate": c.predicate, "value": c.value, "source": c.source,
                "url": c.source_url, "excerpt": c.excerpt, "confidence": c.confidence,
                "fetched_at": c.fetched_at, "sensitivity": c.sensitivity, "extra": c.extra,
            }
            for c in result.claims
        ],
        "entities": [
            {"id": e.id, "kind": e.kind, "label": e.label, "value": e.value, "url": e.url}
            for e in result.resolution.entities
        ],
        "candidates": [
            {"a": c.a, "b": c.b, "score": c.score, "reasons": c.reasons}
            for c in result.resolution.candidates
        ],
    }


def write_report(result: RunResult, out_dir: str | Path) -> dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"{result.case.id}_{_SAFE.sub('_', result.case.seed.value)[:40]}"
    md_path = out / f"{stem}.md"
    json_path = out / f"{stem}.graph.json"
    raw_path = out / f"{stem}.json"
    md_path.write_text(render_markdown(result), encoding="utf-8")
    json_path.write_text(json.dumps(graph_json(result), indent=1), encoding="utf-8")
    raw_path.write_text(json.dumps(case_json(result), indent=1, ensure_ascii=False),
                        encoding="utf-8")
    return {"markdown": str(md_path), "graph": str(json_path), "json": str(raw_path)}


def stored_checks(store, case_id: str) -> list[Check]:
    try:
        return store.checks(case_id)
    except Exception:  # a store written by an older version has no checks table
        return []


def stored_json(store, case) -> dict:
    """Same shape as case_json, rebuilt from the store without re-running."""
    from .resolve import resolve

    claims = store.claims(case.id)
    checks = stored_checks(store, case.id)
    cov = coverage(checks)
    stats = store.stats(case.id)
    cov.update({"requests": stats["requests"], "seconds": 0.0,
                "claims": len(sourced(claims))})
    resolution = resolve(case.seed, claims)
    return {
        "case": case.as_dict(),
        "coverage": cov,
        "coverage_line": coverage_line(cov),
        "stats": stats,
        "stop_reason": "stored",
        "elapsed_s": 0.0,
        "checks": [c.as_dict() for c in checks],
        "queued": [],
        "suggested": [],
        "ai": None,
        "claims": [
            {
                "kind": c.kind, "predicate": c.predicate, "value": c.value, "source": c.source,
                "url": c.source_url, "excerpt": c.excerpt, "confidence": c.confidence,
                "fetched_at": c.fetched_at, "sensitivity": c.sensitivity, "extra": c.extra,
            }
            for c in claims
        ],
        "entities": [
            {"id": e.id, "kind": e.kind, "label": e.label, "value": e.value, "url": e.url}
            for e in resolution.entities
        ],
        "candidates": [
            {"a": c.a, "b": c.b, "score": c.score, "reasons": c.reasons}
            for c in resolution.candidates
        ],
    }


def render_stored(store, case) -> str:
    """Re-render a stored case from the claims table (no re-run)."""
    from .resolve import resolve

    claims = store.claims(case.id)
    checks = stored_checks(store, case.id)
    cov = coverage(checks)
    stats = store.stats(case.id)
    cov.update({"requests": stats["requests"], "seconds": 0.0,
                "claims": len(sourced(claims))})
    shim = SimpleNamespace(
        case=case,
        claims=claims,
        resolution=resolve(case.seed, claims),
        stats=stats,
        checks=checks,
        coverage=cov,
        queued=[],
        suggested=[],
        ai=None,
        stop_reason="stored",
        elapsed_s=0.0,
    )
    return render_markdown(shim)
