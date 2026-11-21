"""Connector registry and the public-data connectors.

Every connector returns Claim objects that carry a source URL, a fetch time and
an excerpt taken from the response. Absence is recorded explicitly as a claim of
kind "absence" so the report can distinguish "checked, not found" from "not
checked"; a blocked source returns a note instead, and the engine stores that as
an UNKNOWN check.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .model import Claim, Result, Seed, now_iso
from .net import USER_AGENT, BudgetExceeded, HttpClient, excerpt


@dataclass
class Context:
    case_id: str
    options: dict
    http: HttpClient


class Connector:
    name: str = ""
    accepts: frozenset[str] = frozenset()
    sensitivity: str = "public"
    description: str = ""
    # Declared state, printed by `osint-rail connectors`. "live" means the source
    # is a stable public API or page. "limited" means it depends on something
    # extra (a downloaded dataset, a hard rate limit). "blocked" is never
    # declared: it is observed, and comes from the checks table.
    state: str = "live"
    state_note: str = ""

    def enabled(self, options: dict) -> bool:
        """False means the options switched this connector off, so it is not a check."""
        return True

    def run(self, seed: Seed, ctx: Context) -> Result:  # pragma: no cover - interface
        raise NotImplementedError


REGISTRY: list[Connector] = []


def register(cls: type[Connector]) -> type[Connector]:
    REGISTRY.append(cls())
    return cls


def connectors_for(kind: str) -> list[Connector]:
    return [c for c in REGISTRY if kind in c.accepts]


def _c(
    seed: Seed,
    *,
    kind: str,
    predicate: str,
    value: str,
    source: str,
    url: str,
    excerpt_text: str,
    confidence: float,
    sensitivity: str = "public",
    extra: dict | None = None,
) -> Claim:
    return Claim(
        kind=kind,
        predicate=predicate,
        value=value,
        source=source,
        source_url=url,
        excerpt=excerpt_text,
        fetched_at=now_iso(),
        confidence=confidence,
        sensitivity=sensitivity,
        subject_kind=seed.kind,
        subject_value=seed.value,
        extra=extra or {},
    )


# --------------------------------------------------------------------------
# Email: Gravatar (the canonical email -> profile pivot)
# --------------------------------------------------------------------------
@register
class Gravatar(Connector):
    name = "gravatar"
    accepts = frozenset({"email"})
    description = "Gravatar public profile by email hash"

    def run(self, seed: Seed, ctx: Context) -> Result:
        email = seed.value.lower()
        md5 = hashlib.md5(email.encode()).hexdigest()
        url = f"https://gravatar.com/{md5}.json"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if not resp.ok:
            if resp.status == 404:
                return Result(claims=[_c(seed, kind="absence", predicate="gravatar_profile",
                                         value="none", source=self.name, url=url,
                                         excerpt_text="HTTP 404 (no Gravatar profile for this hash)",
                                         confidence=0.85)])
            return Result(note=f"gravatar HTTP {resp.status}: {resp.error}")

        entry = (data.get("entry") or [{}])[0] if isinstance(data, dict) else {}
        claims: list[Claim] = []
        field_map = {
            "profileUrl": "profile_url",
            "preferredUsername": "username",
            "displayName": "display_name",
            "aboutMe": "bio",
            "thumbnailUrl": "avatar_url",
        }
        emit = lambda pred, val, conf=0.9, k="profile": claims.append(
            _c(seed, kind=k, predicate=pred, value=str(val), source=self.name, url=url,
               excerpt_text=excerpt(val), confidence=conf)
        )
        for src_field, pred in field_map.items():
            if entry.get(src_field):
                emit(pred, entry[src_field])
        name = entry.get("name") or {}
        if name.get("formatted"):
            emit("full_name", name["formatted"], 0.85)
        seeds: list[Seed] = []
        if entry.get("preferredUsername"):
            seeds.append(Seed("username", entry["preferredUsername"]))
        for acct in entry.get("accounts") or []:
            domain = acct.get("domain") or ""
            handle = acct.get("username") or acct.get("display") or ""
            if domain and handle:
                claims.append(_c(
                    seed, kind="account", predicate="account",
                    value=f"{domain}:{handle}", source=self.name, url=url,
                    excerpt_text=excerpt(acct), confidence=0.9,
                    extra={"domain": domain, "username": handle,
                           "verified": str(acct.get("verified", "")).lower() == "true",
                           "profile_url": acct.get("url", "")},
                ))
                seeds.append(Seed("username", handle))
        for link in entry.get("urls") or []:
            if link.get("value"):
                claims.append(_c(seed, kind="mention", predicate="url", value=link["value"],
                                 source=self.name, url=url, excerpt_text=excerpt(link), confidence=0.8))
        return Result(claims=claims, seeds=seeds)


@register
class OpenPgp(Connector):
    name = "openpgp"
    accepts = frozenset({"email"})
    description = "keys.openpgp.org key presence by email"

    def run(self, seed: Seed, ctx: Context) -> Result:
        email = urllib.parse.quote(seed.value, safe="")
        url = f"https://keys.openpgp.org/vks/v1/by-email/{email}"
        resp = ctx.http.get(url, connector=self.name)
        if resp.status == 200 and b"BEGIN PGP PUBLIC KEY BLOCK" in resp.body:
            return Result(claims=[_c(seed, kind="key", predicate="pgp_key", value="present",
                                     source=self.name, url=url,
                                     excerpt_text="-----BEGIN PGP PUBLIC KEY BLOCK-----",
                                     confidence=0.9)])
        if resp.status == 404:
            return Result(claims=[_c(seed, kind="absence", predicate="pgp_key", value="none",
                                     source=self.name, url=url, excerpt_text="HTTP 404 (no key)",
                                     confidence=0.8)])
        return Result(note=f"openpgp HTTP {resp.status}")


# --------------------------------------------------------------------------
# Username connectors
# --------------------------------------------------------------------------
@register
class GitHub(Connector):
    name = "github"
    accepts = frozenset({"username"})
    description = "GitHub public profile + commit author emails"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value)
        import os

        gh_headers = {"Accept": "application/vnd.github+json"}
        if os.environ.get("GITHUB_TOKEN"):
            gh_headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
        url = f"https://api.github.com/users/{u}"
        data, resp = ctx.http.get_json(url, connector=self.name, headers=gh_headers)
        if resp.status == 404:
            return Result(claims=[_c(seed, kind="absence", predicate="github_account", value="none",
                                     source=self.name, url=url, excerpt_text="HTTP 404 (no user)",
                                     confidence=0.9)])
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"github HTTP {resp.status}: {resp.error}")

        claims: list[Claim] = []
        emit = lambda pred, val, conf=0.9: claims.append(
            _c(seed, kind="profile", predicate=pred, value=str(val), source=self.name,
               url=url, excerpt_text=excerpt(val), confidence=conf,
               extra={"profile_url": data.get("html_url", "")})
        )
        for pred in ("login", "name", "company", "blog", "location", "bio", "twitter_username",
                     "public_repos", "followers", "created_at", "avatar_url"):
            if data.get(pred):
                conf = 0.95 if pred in ("login", "name") else 0.9
                emit("full_name" if pred == "name" else pred, data[pred], conf)
        seeds: list[Seed] = []
        for key, kind in (("blog", "domain"), ("twitter_username", "handle")):
            if data.get(key):
                val = str(data[key]).strip()
                if kind == "domain":
                    host = re.sub(r"^https?://", "", val).split("/")[0]
                    if "." in host:
                        seeds.append(Seed("domain", host))
                        if val.startswith("http://") or val.startswith("https://"):
                            seeds.append(Seed("url", val))
                else:
                    seeds.append(Seed("handle", val))

        # commit author emails from the public event feed (pivot back to email)
        events_url = f"https://api.github.com/users/{u}/events/public?per_page=30"
        events, ev_resp = ctx.http.get_json(events_url, connector=self.name,
                                           headers=gh_headers)
        if isinstance(events, list):
            seen: set[str] = set()
            for ev in events:
                for commit in ((ev.get("payload") or {}).get("commits") or []):
                    email = ((commit.get("author") or {}).get("email") or "").strip()
                    if not email or email in seen or "@users.noreply" in email:
                        continue
                    seen.add(email)
                    claims.append(_c(seed, kind="contact", predicate="email", value=email,
                                     source=self.name, url=events_url,
                                     excerpt_text=excerpt({"commit": commit.get("message", "")[:80],
                                                           "author_email": email}),
                                     confidence=0.55, extra={"via": "push event"}))
                    seeds.append(Seed("email", email))
        return Result(claims=claims, seeds=seeds)


@register
class HackerNews(Connector):
    name = "hackernews"
    accepts = frozenset({"username"})
    description = "Hacker News profile (about text, karma, creation date)"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value)
        url = f"https://hacker-news.firebaseio.com/v0/user/{u}.json"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if data is None:
            if resp.ok:
                return Result(claims=[_c(seed, kind="absence", predicate="hackernews_account",
                                         value="none", source=self.name, url=url,
                                         excerpt_text="HTTP 200 with null body (no such user)",
                                         confidence=0.85)])
            return Result(note=f"hn HTTP {resp.status}")
        claims = [_c(seed, kind="profile", predicate="profile_url",
                     value=f"https://news.ycombinator.com/user?id={data.get('id', u)}",
                     source=self.name, url=url, excerpt_text=excerpt(data), confidence=0.9)]
        for pred in ("about", "karma", "created"):
            if data.get(pred) not in (None, ""):
                claims.append(_c(seed, kind="profile", predicate=f"hn_{pred}", value=str(data[pred]),
                                 source=self.name, url=url, excerpt_text=excerpt(data[pred]),
                                 confidence=0.85))
        seeds = [Seed("domain", host) for host in re.findall(r"https?://([a-z0-9.-]+\.[a-z]{2,})", data.get("about") or "")]
        return Result(claims=claims, seeds=seeds[:5])


@register
class Bluesky(Connector):
    name = "bluesky"
    accepts = frozenset({"handle"})
    description = "Bluesky public profile by handle"

    def run(self, seed: Seed, ctx: Context) -> Result:
        actor = urllib.parse.quote(seed.value)
        url = f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={actor}"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"bluesky HTTP {resp.status}")
        claims = []
        for pred, key, conf in (
            ("profile_url", "handle", 0.9),
            ("full_name", "displayName", 0.9),
            ("bio", "description", 0.9),
            ("avatar_url", "avatar", 0.8),
            ("created_at", "createdAt", 0.9),
            ("followers", "followersCount", 0.85),
        ):
            if data.get(key):
                claims.append(_c(seed, kind="profile", predicate=pred, value=str(data[key]),
                                 source=self.name, url=url, excerpt_text=excerpt(data[key]),
                                 confidence=conf, extra={"did": data.get("did", "")}))
        return Result(claims=claims)


@register
class Npm(Connector):
    name = "npm"
    accepts = frozenset({"username"})
    description = "npm packages maintained by a username"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value)
        url = f"https://registry.npmjs.org/-/v1/search?text=maintainer:{u}&size=20"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"npm HTTP {resp.status}")
        objs = data.get("objects") or []
        claims = []
        seeds: list[Seed] = []
        seen_emails: set[str] = set()
        for obj in objs:
            pkg = obj.get("package") or {}
            publisher = pkg.get("publisher") or {}
            if not pkg.get("name"):
                continue
            if str(publisher.get("username", "")).lower() != seed.value.lower():
                continue
            claims.append(_c(seed, kind="package", predicate="npm_package", value=pkg["name"],
                             source=self.name, url=url,
                             excerpt_text=excerpt({"name": pkg.get("name"),
                                                   "description": pkg.get("description", "")}),
                             confidence=0.8, extra={"version": pkg.get("version", "")}))
            email = str(publisher.get("email") or "").strip()
            if email and email not in seen_emails and "@" in email:
                seen_emails.add(email)
                claims.append(_c(seed, kind="contact", predicate="email", value=email,
                                 source=self.name, url=url,
                                 excerpt_text=excerpt({"publisher": publisher}),
                                 confidence=0.55,
                                 extra={"via": "npm publisher",
                                        "note": "publisher email may be the account operator, not the person"}))
                seeds.append(Seed("email", email))
        if not claims:
            claims.append(_c(seed, kind="absence", predicate="npm_packages", value="none",
                             source=self.name, url=url, excerpt_text="0 verified publisher results",
                             confidence=0.6))
        return Result(claims=claims, seeds=seeds)


@register
class PyPI(Connector):
    name = "pypi"
    accepts = frozenset({"username"})
    description = "PyPI user page (published projects)"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value)
        url = f"https://pypi.org/user/{u}/"
        resp = ctx.http.get(url, connector=self.name)
        if resp.status == 404:
            return Result(claims=[_c(seed, kind="absence", predicate="pypi_user", value="none",
                                     source=self.name, url=url, excerpt_text="HTTP 404 (no user)",
                                     confidence=0.85)])
        if not resp.ok:
            return Result(note=f"pypi HTTP {resp.status}")
        html = resp.text()
        lowered = html.lower()
        if any(marker in lowered for marker in ("client challenge", "just a moment", "enable javascript")):
            return Result(note="anti-bot challenge page (UNKNOWN, not absent)")
        projects = re.findall(r'href="/project/([a-zA-Z0-9_.-]+)/"', html)
        title = re.search(r"<title>(.*?)</title>", html, re.S)
        heading = " ".join((title.group(1) if title else "PyPI user page").split())
        claims = [_c(seed, kind="profile", predicate="profile_url", value=url,
                     source=self.name, url=url, excerpt_text=excerpt(heading), confidence=0.85)]
        if projects:
            claims.append(_c(seed, kind="profile", predicate="pypi_projects", value=str(len(set(projects))),
                             source=self.name, url=url,
                             excerpt_text=excerpt(", ".join(sorted(set(projects))[:8])), confidence=0.85))
        for name in dict.fromkeys(projects):
            claims.append(_c(seed, kind="package", predicate="pypi_package", value=name,
                             source=self.name, url=url, excerpt_text=f"href=/project/{name}/",
                             confidence=0.8))
        return Result(claims=claims)


# --------------------------------------------------------------------------
# Name connector
# --------------------------------------------------------------------------
@register
class Orcid(Connector):
    name = "orcid"
    accepts = frozenset({"name"})
    description = "ORCID researcher search by name"

    def run(self, seed: Seed, ctx: Context) -> Result:
        q = urllib.parse.quote(seed.value)
        url = f"https://pub.orcid.org/v3.0/expanded-search/?q={q}&rows=5"
        data, resp = ctx.http.get_json(url, connector=self.name,
                                       headers={"Accept": "application/json"})
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"orcid HTTP {resp.status}")
        claims = []
        for item in data.get("expanded-result") or []:
            oid = item.get("orcid-id")
            if not oid:
                continue
            name = " ".join(x for x in (item.get("given-names"), item.get("family-names")) if x)
            insts = [i.get("institution-name") for i in (item.get("institution-name") or []) if i]
            claims.append(_c(seed, kind="account", predicate="orcid_id", value=oid,
                             source=self.name, url=url,
                             excerpt_text=excerpt({"name": name, "institutions": insts}),
                             confidence=0.5, extra={"candidate": True, "name": name,
                                                    "institutions": insts}))
        return Result(claims=claims)


# --------------------------------------------------------------------------
# Domain / IP connectors
# --------------------------------------------------------------------------
class _Dns:
    def __init__(self, ctx: Context):
        self.ctx = ctx

    def query(self, name: str, rtype: str) -> list[str]:
        url = f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={rtype}"
        data, resp = self.ctx.http.get_json(url, connector="dns")
        if not resp.ok or not isinstance(data, dict):
            return []
        return [a.get("data", "") for a in data.get("Answer") or [] if a.get("data")]


@register
class DomainIntel(Connector):
    name = "domain"
    accepts = frozenset({"domain"})
    description = "DNS records (A/MX/NS/TXT) + RDAP registration"

    def run(self, seed: Seed, ctx: Context) -> Result:
        domain = seed.value.lower().strip(".")
        claims: list[Claim] = []
        seeds: list[Seed] = []
        dns = _Dns(ctx)
        src_url = f"https://dns.google/resolve?name={domain}"
        for rtype, pred in (("A", "a_record"), ("MX", "mx_host"), ("NS", "ns_host")):
            for value in dns.query(domain, rtype)[:10]:
                clean = " ".join(str(value).split())
                if rtype == "MX":
                    # "10 mail.example.com." or the null MX "0 ." - neither is a host
                    parts = clean.split()
                    clean = parts[-1].rstrip(".") if parts else ""
                    if clean in ("", "."):
                        continue
                clean = clean.rstrip(".").strip()
                if rtype == "NS" or rtype == "MX":
                    clean = clean.lower()
                if not clean:
                    continue
                claims.append(_c(seed, kind="domain", predicate=pred, value=clean,
                                 source="dns", url=src_url, excerpt_text=f"{rtype} {clean}",
                                 confidence=0.95))
                if rtype == "A":
                    seeds.append(Seed("ip", clean))
        txt = dns.query(domain, "TXT")
        spf = [t for t in txt if t.startswith("v=spf1")]
        for record in txt:
            if record.startswith("v=spf1"):
                continue
            claims.append(_c(seed, kind="domain", predicate="txt_record", value=record,
                             source="dns", url=src_url,
                             excerpt_text=excerpt(record), confidence=0.85))
        dmarc = dns.query(f"_dmarc.{domain}", "TXT")
        claims.append(_c(seed, kind="domain", predicate="spf", value="present" if spf else "absent",
                         source="dns", url=src_url,
                         excerpt_text=excerpt(spf[0] if spf else "no v=spf1 TXT record"),
                         confidence=0.9))
        claims.append(_c(seed, kind="domain", predicate="dmarc", value="present" if dmarc else "absent",
                         source="dns", url=f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT",
                         excerpt_text=excerpt(dmarc[0] if dmarc else "no _dmarc TXT record"),
                         confidence=0.9))

        rdap_url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
        data, resp = ctx.http.get_json(rdap_url, connector=self.name)
        if resp.ok and isinstance(data, dict):
            for event in data.get("events") or []:
                action = event.get("eventAction") or ""
                if action in ("registration", "expiration", "last changed") and event.get("eventDate"):
                    claims.append(_c(seed, kind="domain", predicate=f"rdap_{action}",
                                     value=str(event["eventDate"]), source="rdap", url=rdap_url,
                                     excerpt_text=excerpt(event), confidence=0.85))
            for ns in data.get("nameservers") or []:
                if ns.get("ldhName"):
                    claims.append(_c(seed, kind="domain", predicate="ns_host",
                                     value=str(ns["ldhName"]).rstrip(".").lower(),
                                     source="rdap", url=rdap_url, excerpt_text=excerpt(ns),
                                     confidence=0.9))
            for ent in data.get("entities") or []:
                vcard = (ent.get("vcardArray") or [None, []])[1]
                for field in vcard or []:
                    if isinstance(field, list) and field and field[0] == "fn" and len(field) > 3 and field[3]:
                        claims.append(_c(seed, kind="domain", predicate="registrar", value=str(field[3]),
                                         source="rdap", url=rdap_url, excerpt_text=excerpt(field),
                                         confidence=0.85))
        seeds.append(Seed("url", f"https://{domain}"))
        return Result(claims=claims, seeds=seeds[:10])


@register
class IpIntel(Connector):
    name = "ip"
    accepts = frozenset({"ip"})
    description = "ip-api geo/ASN + Shodan InternetDB ports/hostnames"

    def run(self, seed: Seed, ctx: Context) -> Result:
        ip = urllib.parse.quote(seed.value)
        claims: list[Claim] = []
        seeds: list[Seed] = []
        api_url = (f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,"
                   "city,isp,org,as,query")
        data, resp = ctx.http.get_json(api_url, connector=self.name)
        if isinstance(data, dict) and data.get("status") == "success":
            for key, pred, conf in (("country", "country", 0.85), ("city", "city", 0.8),
                                    ("isp", "isp", 0.85), ("org", "org", 0.8), ("as", "asn", 0.85)):
                if data.get(key):
                    claims.append(_c(seed, kind="ip", predicate=pred, value=str(data[key]),
                                     source="ip-api", url=api_url, excerpt_text=excerpt(data),
                                     confidence=conf))
        ptr_url = f"https://dns.google/resolve?name={ip}&type=PTR"
        ptr, _ = ctx.http.get_json(ptr_url, connector=self.name)
        if isinstance(ptr, dict):
            for answer in (ptr.get("Answer") or []):
                data = answer.get("data")
                if data:
                    claims.append(_c(seed, kind="ip", predicate="ptr", value=str(data).rstrip("."),
                                     source="dns", url=ptr_url, excerpt_text=excerpt(data),
                                     confidence=0.9))
        idb_url = f"https://internetdb.shodan.io/{ip}"
        idb, idb_resp = ctx.http.get_json(idb_url, connector=self.name)
        if isinstance(idb, dict):
            ports = [str(p) for p in (idb.get("ports") or [])][:40]
            if ports:
                claims.append(_c(seed, kind="ip", predicate="open_ports", value=",".join(ports),
                                 source="internetdb", url=idb_url,
                                 excerpt_text=excerpt(idb.get("ports")), confidence=0.7))
            hostnames = [str(h) for h in (idb.get("hostnames") or [])][:10]
            if hostnames:
                claims.append(_c(seed, kind="ip", predicate="hostnames", value=",".join(hostnames),
                                 source="internetdb", url=idb_url, excerpt_text=excerpt(hostnames),
                                 confidence=0.7))
            cpes = [str(c) for c in (idb.get("cpes") or [])][:10]
            if cpes:
                claims.append(_c(seed, kind="ip", predicate="cpes", value=",".join(cpes),
                                 source="internetdb", url=idb_url, excerpt_text=excerpt(cpes),
                                 confidence=0.65))
            vulns = [str(v) for v in (idb.get("vulns") or [])][:10]
            if vulns:
                claims.append(_c(seed, kind="ip", predicate="vulns", value=",".join(vulns),
                                 source="internetdb", url=idb_url, excerpt_text=excerpt(vulns),
                                 confidence=0.75))
            # Deliberately do not seed hostnames: shared CDN IPs return unrelated
            # domains (Cloudflare), which pollutes the case with other people's sites.

        return Result(claims=claims, seeds=seeds[:10])


# --------------------------------------------------------------------------
# Username enumeration via the WhatsMyName dataset (CC BY-SA 4.0)
# --------------------------------------------------------------------------
_WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
_MAIGRET_URL = "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json"
_DATASET_LOCK = threading.Lock()
_WMN_DATA: dict | None = None
_MAIGRET_DATA: dict | None = None


def _http_json(url: str, timeout: int = 45) -> dict | None:
    """Plain GET for community datasets. Not part of a case, so not billed to it."""
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


# The only seam tests need for the datasets; they replace this with a stub.
_FETCH_JSON = _http_json


def reset_datasets(wmn: dict | None = None, maigret: dict | None = None) -> None:
    """Clear the dataset cache (tests, and `probe` after a failed download)."""
    global _WMN_DATA, _MAIGRET_DATA
    with _DATASET_LOCK:
        _WMN_DATA = wmn
        _MAIGRET_DATA = maigret


def _load_wmn() -> list[dict]:
    global _WMN_DATA
    with _DATASET_LOCK:
        if _WMN_DATA is None:
            _WMN_DATA = _FETCH_JSON(_WMN_URL) or {}
        data = _WMN_DATA
    out = []
    for site in data.get("sites") or []:
        uri = site.get("uri_check")
        if not uri or not site.get("name"):
            continue
        out.append({
            "name": site["name"],
            "uri": uri,
            "m_string": site.get("m_string") or None,
            "category": site.get("cat", ""),
        })
    return out


def _load_maigret() -> tuple[list[dict], list[dict]]:
    global _MAIGRET_DATA
    with _DATASET_LOCK:
        if _MAIGRET_DATA is None:
            _MAIGRET_DATA = _FETCH_JSON(_MAIGRET_URL) or {}
        data = _MAIGRET_DATA
    sites = data.get("sites") or {}
    items = sites.values() if isinstance(sites, dict) else sites
    strong, weak = [], []
    for site in items:
        if site.get("disabled"):
            continue
        uri = site.get("url") or ""
        if "{username}" not in uri and "{account}" not in uri:
            continue
        main = site.get("urlMain") or uri
        host = urllib.parse.urlsplit(main).netloc.replace("www.", "") or urllib.parse.urlsplit(uri).netloc
        presence = site.get("presenseStrs") or []
        entry = {"name": host, "uri": uri.replace("{account}", "{username}"),
                 "m_string": presence[0] if presence else None,
                 "category": ",".join(site.get("tags") or [])[:40]}
        if presence:
            strong.append(entry)
        elif site.get("checkType") in (None, "status_code"):
            weak.append(entry)
    return strong, weak


def _dedupe_sites(entries: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for entry in entries:
        host = urllib.parse.urlsplit(entry["uri"]).netloc.replace("www.", "").lower()
        if not host or host in seen:
            continue
        seen.add(host)
        out.append(entry)
    return out


def _username_sites(limit: int, weak_limit: int) -> tuple[list[dict], list[dict]]:
    """Strong checks (explicit presence string) and weak checks (status-only)."""
    if limit <= 0 and weak_limit <= 0:
        # Nothing to probe: do not download two multi-megabyte datasets to find out.
        return [], []
    wmn = _load_wmn()
    maigret_strong, maigret_weak = _load_maigret()
    strong = _dedupe_sites([s for s in wmn if s.get("m_string")] + maigret_strong)
    weak = _dedupe_sites([s for s in wmn if not s.get("m_string")] + maigret_weak)
    # no overlap with strong
    strong_hosts = {urllib.parse.urlsplit(s["uri"]).netloc.replace("www.", "").lower() for s in strong}
    weak = [s for s in weak if urllib.parse.urlsplit(s["uri"]).netloc.replace("www.", "").lower() not in strong_hosts]
    return strong[:max(0, limit)], weak[:max(0, weak_limit)]


@register
class WhatsMyName(Connector):
    name = "whatsmyname"
    accepts = frozenset({"username"})
    sensitivity = "registration"
    description = "Username registration probe over merged WhatsMyName + Maigret lists"
    state = "limited"
    state_note = "downloads two community site lists on first use"

    def enabled(self, options: dict) -> bool:
        return int(options.get("username_sites", 60)) > 0 or \
            int(options.get("username_weak_sites", 40)) > 0

    def run(self, seed: Seed, ctx: Context) -> Result:
        limit = int(ctx.options.get("username_sites", 60))
        weak_limit = int(ctx.options.get("username_weak_sites", 40))
        strong, weak = _username_sites(limit, weak_limit)
        all_sites = strong + weak
        if not all_sites:
            return Result(note="username datasets unavailable")
        username = seed.value
        results: list[Claim] = []
        lock = threading.Lock()
        stats = {"matched": 0, "weak": 0, "definitive_negative": 0, "blocked": 0, "errors": 0, "budget": 0}

        def probe(site: dict) -> None:
            uri = site["uri"].replace("{username}", urllib.parse.quote(username))
            try:
                resp = ctx.http.get(uri, connector=self.name, cache=False, timeout=5, retries=0)
            except BudgetExceeded:
                with lock:
                    stats["budget"] = 1
                return
            except Exception:
                with lock:
                    stats["errors"] += 1
                return
            m_string = site.get("m_string") or ""
            if resp.ok:
                body = resp.text().lower()
                if m_string:
                    if m_string.lower() in body:
                        with lock:
                            stats["matched"] += 1
                            results.append(_c(seed, kind="account", predicate="account", value=site["name"],
                                              source=self.name, url=uri,
                                              excerpt_text=f'"{m_string}" found on {site["name"]}',
                                              confidence=0.7, sensitivity="registration",
                                              extra={"profile_url": uri, "site": site["name"],
                                                     "category": site.get("category", "")}))
                    else:
                        with lock:
                            stats["definitive_negative"] += 1
                else:
                    with lock:
                        stats["weak"] += 1
                        results.append(_c(seed, kind="account", predicate="account", value=site["name"],
                                          source=self.name, url=uri,
                                          excerpt_text=f"HTTP {resp.status} on {site['name']} (status-only check)",
                                          confidence=0.35, sensitivity="registration",
                                          extra={"profile_url": uri, "site": site["name"],
                                                 "category": site.get("category", ""), "weak": True}))
            elif resp.status in (403, 429, 503, 401, 0, 500, 502, 504):
                with lock:
                    stats["blocked"] += 1
            else:
                with lock:
                    stats["definitive_negative"] += 1

        workers = min(14, max(2, len(all_sites)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(probe, s) for s in all_sites]
            for f in as_completed(futures):
                f.result()

        matched, neg, blocked = stats["matched"], stats["definitive_negative"], stats["blocked"]
        total = len(all_sites)
        results.append(_c(seed, kind="coverage", predicate="wmn_coverage",
                          value=f"{matched} matched / {stats['weak']} weak / {neg} no / {blocked} blocked of {total}",
                          source=self.name, url=_WMN_URL,
                          excerpt_text=f"probed {total} sites for {username}: {matched} strong hits, "
                                       f"{stats['weak']} weak, {neg} answered no, {blocked} blocked/unreachable",
                          confidence=0.6, sensitivity="registration",
                          extra={"matched": matched, "weak": stats["weak"], "negative": neg,
                                 "blocked": blocked, "total": total}))
        if stats["budget"]:
            results.append(_c(seed, kind="coverage", predicate="wmn_partial", value="partial",
                              source=self.name, url=_WMN_URL,
                              excerpt_text="request budget ran out mid-sweep; count is a lower bound",
                              confidence=0.7, sensitivity="registration"))
        note = ""
        if stats["weak"] == 0 and matched == 0:
            if blocked > max(2, total // 10):
                note = f"{blocked} of {total} sites blocked; no absence can be claimed"
            else:
                results.append(_c(seed, kind="absence", predicate="wmn_accounts", value="none",
                                  source=self.name, url=_WMN_URL,
                                  excerpt_text=f"0 of {total} probed sites matched, {blocked} blocked",
                                  confidence=0.55, sensitivity="registration"))
        return Result(claims=results, note=note)
