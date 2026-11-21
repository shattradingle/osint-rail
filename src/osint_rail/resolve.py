"""Entity resolution: deterministic nodes/edges first, scored candidates second.

Rule: a merge happens only on a deterministic key (same account, same profile
URL, same email, same domain/IP). Name/avatar/bio similarity produces a
*candidate link* with reasons, never a silent merge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Claim, Seed

_NAME_PREDICATES = {"full_name", "display_name", "name"}
_BIO_PREDICATES = {"bio", "about", "aboutme", "hn_about"}
_PROFILE_SOURCES = {"github", "bluesky", "hackernews", "pypi", "gravatar"}


def _norm(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _tokens(value: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", _norm(value)) if len(t) > 1}


def jaccard(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


@dataclass
class Entity:
    id: str
    kind: str
    label: str
    value: str
    url: str = ""
    sources: set[str] = field(default_factory=set)
    confidence: float = 0.0
    claim_count: int = 0
    names: set[str] = field(default_factory=set)
    bios: set[str] = field(default_factory=set)


@dataclass
class Edge:
    src: str
    dst: str
    label: str
    confidence: float


@dataclass
class Candidate:
    a: str
    b: str
    score: float
    reasons: list[str]


@dataclass
class Resolution:
    entities: list[Entity]
    edges: list[Edge]
    candidates: list[Candidate]

    def by_id(self) -> dict[str, Entity]:
        return {e.id: e for e in self.entities}


def _entity_for_claim(claim: Claim) -> Entity | None:
    extra = claim.extra or {}
    if claim.kind == "account":
        site = str(extra.get("site") or extra.get("domain") or claim.value)
        url = str(extra.get("profile_url") or "")
        key = f"account:{_norm(site)}:{_norm(str(extra.get('username') or claim.value))}"
        return Entity(key, "account", site, claim.value, url, {claim.source}, claim.confidence, 1)
    if claim.kind == "profile":
        url = str(extra.get("profile_url") or "")
        if claim.predicate == "profile_url":
            url = claim.value
        key = f"profile:{claim.source}:{_norm(url or claim.value)}"
        return Entity(key, "profile", claim.source, claim.value, url, {claim.source}, claim.confidence, 1)
    if claim.kind == "contact" and claim.predicate == "email":
        return Entity(f"email:{_norm(claim.value)}", "email", "email", claim.value,
                      "", {claim.source}, claim.confidence, 1)
    if claim.kind == "domain" and claim.predicate in ("a_record", "mx_host", "ns_host", "registrar"):
        return Entity(f"domain:{_norm(claim.value)}", "domain", claim.predicate, claim.value,
                      "", {claim.source}, claim.confidence, 1)
    if claim.kind == "ip" and claim.predicate in ("hostname", "org", "asn"):
        return Entity(f"ip-meta:{_norm(claim.value)}", "ip", claim.predicate, claim.value,
                      "", {claim.source}, claim.confidence, 1)
    if claim.kind == "package":
        return Entity(f"package:{claim.source}:{_norm(claim.value)}", "package", claim.source,
                      claim.value, "", {claim.source}, claim.confidence, 1)
    return None


def resolve(seed: Seed, claims: list[Claim]) -> Resolution:
    entities: dict[str, Entity] = {}
    edges: list[Edge] = []

    def add(entity: Entity) -> str:
        if entity.id in entities:
            cur = entities[entity.id]
            cur.sources |= entity.sources
            cur.confidence = max(cur.confidence, entity.confidence)
            cur.claim_count += 1
            return entity.id
        entities[entity.id] = entity
        return entity.id

    root = Entity(seed.key(), "seed", seed.kind, seed.value, sources=set(), confidence=1.0)
    entities[root.id] = root

    subject_nodes: dict[str, str] = {seed.key(): root.id}

    for claim in claims:
        entity = _entity_for_claim(claim)
        if entity is None:
            continue
        eid = add(entity)
        node = entities[eid]
        if claim.predicate in _NAME_PREDICATES:
            node.names.add(claim.value)
        if claim.predicate in _BIO_PREDICATES:
            node.bios.add(claim.value)
        subj_key = f"{claim.subject_kind}:{claim.subject_value}".lower()
        sid = subject_nodes.get(subj_key)
        if sid is None:
            sid = add(Entity(subj_key, "seed", claim.subject_kind, claim.subject_value,
                             sources=set(), confidence=1.0))
            subject_nodes[subj_key] = sid
        if sid != eid:
            edges.append(Edge(sid, eid, claim.predicate, claim.confidence))

    # Candidate person links across profiles: name/username/bio similarity.
    profiles = [e for e in entities.values() if e.kind == "profile"]
    candidates: list[Candidate] = []
    for i in range(len(profiles)):
        for j in range(i + 1, len(profiles)):
            a, b = profiles[i], profiles[j]
            reasons: list[str] = []
            score = 0.0
            if a.names and b.names:
                sim = max(jaccard(x, y) for x in a.names for y in b.names)
                if sim > 0:
                    score += 0.55 * sim
                    reasons.append(f"name similarity {sim:.2f}")
            if a.bios and b.bios:
                sim = max(jaccard(x, y) for x in a.bios for y in b.bios)
                if sim > 0:
                    score += 0.25 * sim
                    reasons.append(f"bio similarity {sim:.2f}")
            shared = {t for t in _tokens(a.value) if t in _tokens(b.value) and len(t) > 2}
            if shared:
                score += 0.20
                reasons.append(f"shared token {sorted(shared)[0]}")
            if score >= 0.45:
                candidates.append(Candidate(a.id, b.id, round(min(score, 0.99), 2), reasons))

    candidates.sort(key=lambda c: -c.score)
    return Resolution(entities=list(entities.values()), edges=edges, candidates=candidates[:20])
