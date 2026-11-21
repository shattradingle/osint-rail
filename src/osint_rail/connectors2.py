"""Extra keyless connectors (v0.2) — public APIs and public pages only.

No login, no CAPTCHA bypass, no proxy rotation, no breach data. Every connector
returns sourced claims; blocks are recorded as UNKNOWN, never absence.
"""

from __future__ import annotations

import html as html_mod
import re
import urllib.parse
from datetime import datetime, timezone

from .connectors import Connector, Context, _c, register
from .model import Claim, Result, Seed
from .net import excerpt


def _iso(ts) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(ts)


# --------------------------------------------------------------------------
# Code hosting
# --------------------------------------------------------------------------
@register
class GitLab(Connector):
    name = "gitlab"
    accepts = frozenset({"username"})
    description = "GitLab public user profile"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value)
        url = f"https://gitlab.com/api/v4/users?username={u}"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if not resp.ok or not isinstance(data, list):
            return Result(note=f"gitlab HTTP {resp.status}")
        if not data:
            return Result(claims=[_c(seed, kind="absence", predicate="gitlab_account", value="none",
                                     source=self.name, url=url, excerpt_text="[] (no user)",
                                     confidence=0.85)])
        user = next((x for x in data if str(x.get("username", "")).lower() == seed.value.lower()), data[0])
        claims = []
        for key, pred, conf in (
            ("username", "username", 0.9), ("name", "full_name", 0.9), ("state", "account_state", 0.7),
            ("web_url", "profile_url", 0.9), ("avatar_url", "avatar_url", 0.85),
            ("location", "location", 0.85), ("bio", "bio", 0.85), ("public_email", "email", 0.85),
        ):
            if user.get(key):
                kind = "contact" if key == "public_email" else "profile"
                claims.append(_c(seed, kind=kind, predicate=pred, value=str(user[key]),
                                 source=self.name, url=url, excerpt_text=excerpt(user[key]),
                                 confidence=conf))
        seeds = [Seed("email", str(user["public_email"]))] if user.get("public_email") else []
        return Result(claims=claims, seeds=seeds)


@register
class Codeberg(Connector):
    name = "codeberg"
    accepts = frozenset({"username"})
    description = "Codeberg (Gitea) public user profile"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value)
        url = f"https://codeberg.org/api/v1/users/{u}"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if resp.status == 404:
            return Result(claims=[_c(seed, kind="absence", predicate="codeberg_account", value="none",
                                     source=self.name, url=url, excerpt_text="HTTP 404",
                                     confidence=0.85)])
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"codeberg HTTP {resp.status}")
        claims = []
        for key, pred, conf in (
            ("login", "username", 0.9), ("full_name", "full_name", 0.9), ("email", "email", 0.8),
            ("location", "location", 0.8), ("website", "website", 0.8),
            ("description", "bio", 0.8), ("created", "created_at", 0.8),
            ("html_url", "profile_url", 0.9),
        ):
            if data.get(key):
                kind = "contact" if key == "email" else "profile"
                claims.append(_c(seed, kind=kind, predicate=pred, value=str(data[key]),
                                 source=self.name, url=url, excerpt_text=excerpt(data[key]),
                                 confidence=conf))
        seeds = [Seed("email", str(data["email"]))] if data.get("email") else []
        return Result(claims=claims, seeds=seeds)


# --------------------------------------------------------------------------
# Consumer and chat platforms
# --------------------------------------------------------------------------
@register
class ChessCom(Connector):
    name = "chesscom"
    accepts = frozenset({"username"})
    description = "Chess.com public player profile"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value.lower())
        url = f"https://api.chess.com/pub/player/{u}"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if resp.status == 404:
            return Result(claims=[_c(seed, kind="absence", predicate="chesscom_account", value="none",
                                     source=self.name, url=url, excerpt_text="HTTP 404",
                                     confidence=0.85)])
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"chesscom HTTP {resp.status}")
        claims = []
        fields = (
            ("username", "username", 0.9), ("name", "full_name", 0.85), ("location", "location", 0.8),
            ("country", "country_url", 0.6), ("title", "chess_title", 0.8),
            ("followers", "followers", 0.8), ("joined", "joined_at", 0.8),
            ("last_online", "last_online", 0.8), ("url", "profile_url", 0.9),
        )
        for key, pred, conf in fields:
            if data.get(key) not in (None, "", 0):
                value = _iso(data[key]) if key in ("joined", "last_online") else str(data[key])
                claims.append(_c(seed, kind="profile", predicate=pred, value=value,
                                 source=self.name, url=url, excerpt_text=excerpt(data[key]),
                                 confidence=conf))
        return Result(claims=claims)


@register
class Telegram(Connector):
    name = "telegram"
    accepts = frozenset({"username"})
    description = "Telegram public preview page (t.me)"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value)
        url = f"https://t.me/{u}"
        resp = ctx.http.get(url, connector=self.name)
        if resp.status in (403, 429):
            return Result(note=f"telegram HTTP {resp.status} (blocked)")
        if not resp.ok:
            return Result(note=f"telegram HTTP {resp.status}")
        page = resp.text()
        title = re.search(r'<meta property="og:title" content="([^"]*)"', page)
        desc = re.search(r'<meta property="og:description" content="([^"]*)"', page)
        extra = re.search(r'<div class="tgme_page_extra">([^<]*)</div>', page)
        image = re.search(r'<meta property="og:image" content="([^"]*)"', page)
        if not title and not desc:
            return Result(claims=[_c(seed, kind="absence", predicate="telegram_account", value="none",
                                     source=self.name, url=url,
                                     excerpt_text="no preview metadata (no public account/page)",
                                     confidence=0.6)])
        claims = []
        if title:
            t = html_mod.unescape(title.group(1)).strip()
            pred = "channel_title" if ":" not in t else "display_name"
            claims.append(_c(seed, kind="profile", predicate=pred, value=t,
                             source=self.name, url=url, excerpt_text=excerpt(t), confidence=0.75))
        if desc:
            d = html_mod.unescape(desc.group(1)).strip()
            if d:
                claims.append(_c(seed, kind="profile", predicate="bio", value=d,
                                 source=self.name, url=url, excerpt_text=excerpt(d), confidence=0.7))
        if extra:
            x = html_mod.unescape(extra.group(1)).strip()
            if x:
                claims.append(_c(seed, kind="profile", predicate="telegram_meta", value=x,
                                 source=self.name, url=url, excerpt_text=excerpt(x), confidence=0.7))
        if image:
            claims.append(_c(seed, kind="profile", predicate="avatar_url", value=image.group(1),
                             source=self.name, url=url, excerpt_text=excerpt(image.group(1)),
                             confidence=0.7))
        return Result(claims=claims)


@register
class Mastodon(Connector):
    name = "mastodon"
    accepts = frozenset({"username"})
    description = "Mastodon.social account lookup (local instance only)"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value)
        url = f"https://mastodon.social/api/v1/accounts/lookup?acct={u}"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if resp.status == 404:
            return Result(claims=[_c(seed, kind="absence", predicate="mastodon_social", value="none",
                                     source=self.name, url=url,
                                     excerpt_text="HTTP 404 on mastodon.social (may exist on another instance)",
                                     confidence=0.5)])
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"mastodon HTTP {resp.status}")
        claims = []
        fields = (
            ("username", "username", 0.85), ("display_name", "display_name", 0.85),
            ("note", "bio", 0.75), ("url", "profile_url", 0.9), ("avatar", "avatar_url", 0.8),
            ("followers_count", "followers", 0.8), ("statuses_count", "posts", 0.8),
            ("created_at", "created_at", 0.8),
        )
        for key, pred, conf in fields:
            if data.get(key) not in (None, "", 0):
                claims.append(_c(seed, kind="profile", predicate=pred, value=str(data[key]),
                                 source=self.name, url=url, excerpt_text=excerpt(data[key]),
                                 confidence=conf))
        return Result(claims=claims)


@register
class Mojang(Connector):
    name = "mojang"
    accepts = frozenset({"username"})
    description = "Minecraft account UUID (Mojang API)"

    def run(self, seed: Seed, ctx: Context) -> Result:
        u = urllib.parse.quote(seed.value)
        url = f"https://api.mojang.com/users/profiles/minecraft/{u}"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if resp.status in (204, 404) or (resp.ok and not data):
            return Result(claims=[_c(seed, kind="absence", predicate="minecraft_account", value="none",
                                     source=self.name, url=url, excerpt_text="no Minecraft profile",
                                     confidence=0.8)])
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"mojang HTTP {resp.status}")
        claims = [
            _c(seed, kind="account", predicate="minecraft_uuid", value=str(data.get("id", "")),
               source=self.name, url=url, excerpt_text=excerpt(data), confidence=0.9),
            _c(seed, kind="profile", predicate="minecraft_username", value=str(data.get("name", "")),
               source=self.name, url=url, excerpt_text=excerpt(data), confidence=0.9),
        ]
        return Result(claims=claims)


# --------------------------------------------------------------------------
# Domain / IP expansion
# --------------------------------------------------------------------------
@register
class Urlscan(Connector):
    name = "urlscan"
    accepts = frozenset({"domain"})
    description = "urlscan.io public search for pages on a domain"

    def run(self, seed: Seed, ctx: Context) -> Result:
        d = urllib.parse.quote(seed.value)
        url = f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=10"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if resp.status == 429:
            return Result(note="urlscan rate-limited (429)")
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"urlscan HTTP {resp.status}")
        claims = []
        for result in (data.get("results") or [])[:10]:
            page = result.get("page") or {}
            if str(page.get("domain", "")).lower() != seed.value.lower():
                continue
            target = page.get("url") or (result.get("task") or {}).get("url")
            if not target:
                continue
            claims.append(_c(seed, kind="domain", predicate="observed_url", value=target,
                             source=self.name, url=url,
                             excerpt_text=excerpt({"domain": page.get("domain"),
                                                   "ip": page.get("ip"),
                                                   "asn": page.get("asnname")}),
                             confidence=0.65,
                             extra={"ip": page.get("ip"), "asn": page.get("asnname")}))
        if not claims:
            claims.append(_c(seed, kind="absence", predicate="urlscan_pages", value="none",
                             source=self.name, url=url, excerpt_text="0 results",
                             confidence=0.5))
        return Result(claims=claims)


@register
class OtxPassiveDns(Connector):
    name = "otx"
    accepts = frozenset({"domain"})
    description = "AlienVault OTX passive DNS (subdomains + IPs)"

    def run(self, seed: Seed, ctx: Context) -> Result:
        d = urllib.parse.quote(seed.value)
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns"
        data, resp = ctx.http.get_json(url, connector=self.name)
        if resp.status == 429:
            return Result(note="otx rate-limited (429)")
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"otx HTTP {resp.status}")
        claims: list[Claim] = []
        seeds: list[Seed] = []
        for row in (data.get("passive_dns") or [])[:25]:
            hostname = row.get("hostname")
            address = row.get("address")
            if hostname:
                claims.append(_c(seed, kind="domain", predicate="passive_dns_host", value=str(hostname),
                                 source=self.name, url=url,
                                 excerpt_text=excerpt({"hostname": hostname, "address": address,
                                                       "first": row.get("first"), "last": row.get("last")}),
                                 confidence=0.7))
                if str(hostname).lower() != seed.value.lower() and "." in str(hostname):
                    seeds.append(Seed("domain", str(hostname)))
            if address:
                claims.append(_c(seed, kind="domain", predicate="passive_dns_ip", value=str(address),
                                 source=self.name, url=url,
                                 excerpt_text=excerpt({"hostname": hostname, "address": address}),
                                 confidence=0.7))
        return Result(claims=claims, seeds=seeds[:10])


# --------------------------------------------------------------------------
# Email pivots
# --------------------------------------------------------------------------
@register
class GitHubCommitSearch(Connector):
    name = "github_commits"
    accepts = frozenset({"email"})
    description = "GitHub commit search by author email (public commits)"

    def run(self, seed: Seed, ctx: Context) -> Result:
        q = urllib.parse.quote(f'author-email:{seed.value}')
        url = f"https://api.github.com/search/commits?q={q}&per_page=10"
        data, resp = ctx.http.get_json(url, connector=self.name,
                                       headers={"Accept": "application/vnd.github+json"})
        if resp.status in (403, 429):
            return Result(note=f"github commit search blocked ({resp.status}); likely rate limit")
        if not resp.ok or not isinstance(data, dict):
            return Result(note=f"github commit search HTTP {resp.status}")
        claims: list[Claim] = []
        seeds: list[Seed] = []
        seen_users: set[str] = set()
        for item in (data.get("items") or [])[:10]:
            commit = item.get("commit") or {}
            author = commit.get("author") or {}
            repo = (item.get("repository") or {}).get("full_name") or ""
            login = ((item.get("author") or {}).get("login") or "")
            claims.append(_c(seed, kind="account", predicate="github_commit", value=repo or item.get("html_url", ""),
                             source=self.name, url=item.get("html_url") or url,
                             excerpt_text=excerpt({"repo": repo, "author": author,
                                                   "message": (commit.get("message") or "")[:60]}),
                             confidence=0.75,
                             extra={"repo": repo, "login": login, "date": author.get("date")}))
            if login and login not in seen_users:
                seen_users.add(login)
                seeds.append(Seed("username", login))
        if not claims:
            claims.append(_c(seed, kind="absence", predicate="github_commits", value="none",
                             source=self.name, url=url, excerpt_text="0 public commits for this email",
                             confidence=0.6))
        return Result(claims=claims, seeds=seeds[:5])


# --------------------------------------------------------------------------
# Web search (DuckDuckGo Lite)
# --------------------------------------------------------------------------
_DDG_URL = "https://lite.duckduckgo.com/lite/?q={query}"
_TAG_RE = re.compile(r"<[^>]+>")


def _clean(fragment: str) -> str:
    return " ".join(html_mod.unescape(_TAG_RE.sub(" ", fragment)).split())


def parse_ddg_lite(page: str, limit: int = 10) -> list[dict]:
    """Return [{title, url, snippet}] from a DuckDuckGo Lite results page."""
    links = re.findall(r'class=.result-link.>([^<]+)</a>', page)
    hrefs = re.findall(r'href="//duckduckgo\.com/l/\?uddg=([^"&]+)', page)
    snippets = [_clean(x) for x in re.findall(r"<td class='result-snippet'>(.*?)</td>", page, re.S)]
    out = []
    for i, href in enumerate(hrefs[:limit]):
        url = urllib.parse.unquote(href)
        title = _clean(links[i]) if i < len(links) else url
        snippet = snippets[i] if i < len(snippets) else ""
        out.append({"title": title, "url": url, "snippet": snippet})
    return out


@register
class WebSearch(Connector):
    name = "websearch"
    accepts = frozenset({"username", "email", "name", "domain", "handle"})
    description = "DuckDuckGo Lite web mentions (top 10, one query)"

    def enabled(self, options: dict) -> bool:
        return bool(options.get("websearch", True))

    def run(self, seed: Seed, ctx: Context) -> Result:
        q = urllib.parse.quote(f'"{seed.value}"')
        url = _DDG_URL.format(query=q)
        resp = ctx.http.get(url, connector=self.name)
        if resp.status != 200:
            return Result(note=f"DuckDuckGo HTTP {resp.status} (blocked or no answer)")
        page = resp.text()
        if "result-link" not in page:
            return Result(note="no result markup from DuckDuckGo (challenge page or zero results)")
        results = parse_ddg_lite(page, limit=10)
        claims = []
        for rank, row in enumerate(results, 1):
            claims.append(_c(seed, kind="mention", predicate="web_result", value=row["url"],
                             source=self.name, url=row["url"],
                             excerpt_text=excerpt(f"{row['title']} — {row['snippet']}"),
                             confidence=0.5,
                             extra={"title": row["title"], "snippet": row["snippet"], "rank": rank}))
        if not claims:
            claims.append(_c(seed, kind="absence", predicate="web_results", value="none",
                             source=self.name, url=url, excerpt_text="0 parsed results",
                             confidence=0.5))
        return Result(claims=claims)


# --------------------------------------------------------------------------
# UK company officers (Companies House, OGL public data)
# --------------------------------------------------------------------------
_CH_BASE = "https://find-and-update.company-information.service.gov.uk"
_CH_OFFICER_RE = re.compile(r'href="(/officers/[^"]+/appointments)"[^>]*>(.*?)</a>', re.S)


def parse_ch_officers(page: str, query: str, limit: int = 10) -> list[dict]:
    """Officer links whose displayed name contains every token of the query."""
    q_tokens = set(re.findall(r"[a-z]+", query.lower()))
    out, seen = [], set()
    for href, raw_name in _CH_OFFICER_RE.findall(page):
        name = _clean(raw_name)
        tokens = set(re.findall(r"[a-z]+", name.lower()))
        if not q_tokens or not q_tokens.issubset(tokens):
            continue
        key = (href, name.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "url": _CH_BASE + href})
        if len(out) >= limit:
            break
    return out


@register
class CompaniesHouse(Connector):
    name = "companieshouse"
    accepts = frozenset({"name"})
    description = "UK Companies House officer search (public register)"

    def run(self, seed: Seed, ctx: Context) -> Result:
        q = urllib.parse.quote(seed.value)
        url = f"{_CH_BASE}/search/officers?q={q}"
        resp = ctx.http.get(url, connector=self.name)
        if resp.status in (403, 429, 503):
            return Result(note=f"companieshouse HTTP {resp.status} (blocked)")
        if not resp.ok:
            return Result(note=f"companieshouse HTTP {resp.status}")
        officers = parse_ch_officers(resp.text(), seed.value)
        if not officers:
            return Result(claims=[_c(seed, kind="absence", predicate="companieshouse_officer",
                                     value="none", source=self.name, url=url,
                                     excerpt_text="no officer name containing all query tokens",
                                     confidence=0.6)])
        claims = [
            _c(seed, kind="account", predicate="companies_house_officer", value=officer["name"],
               source=self.name, url=officer["url"],
               excerpt_text=f'officer register match: "{officer["name"]}"', confidence=0.6,
               extra={"register": "Companies House", "note": "name match only; verify identity"})
            for officer in officers
        ]
        return Result(claims=claims)


# --------------------------------------------------------------------------
# Passive subdomains via hackertarget (free tier)
# --------------------------------------------------------------------------
@register
class HackerTarget(Connector):
    name = "hackertarget"
    accepts = frozenset({"domain"})
    description = "hackertarget hostsearch: subdomains + IPs"

    def run(self, seed: Seed, ctx: Context) -> Result:
        d = urllib.parse.quote(seed.value)
        url = f"https://api.hackertarget.com/hostsearch/?q={d}"
        resp = ctx.http.get(url, connector=self.name)
        if not resp.ok:
            return Result(note=f"hackertarget HTTP {resp.status}")
        body = resp.text().strip()
        if "API count exceeded" in body or "error" in body.lower()[:40]:
            return Result(note=f"hackertarget: {body[:80]}")
        claims, seeds = [], []
        for line in body.splitlines()[:30]:
            if "," not in line:
                continue
            host, _, ip = line.partition(",")
            host, ip = host.strip(), ip.strip()
            if not host or "." not in host:
                continue
            claims.append(_c(seed, kind="domain", predicate="subdomain", value=host,
                             source=self.name, url=url, excerpt_text=line.strip(),
                             confidence=0.7))
            if ip:
                claims.append(_c(seed, kind="domain", predicate="subdomain_ip", value=ip,
                                 source=self.name, url=url, excerpt_text=line.strip(),
                                 confidence=0.6))
                seeds.append(Seed("ip", ip))
        if not claims:
            claims.append(_c(seed, kind="absence", predicate="subdomains", value="none",
                             source=self.name, url=url, excerpt_text="0 hostsearch rows",
                             confidence=0.5))
        return Result(claims=claims, seeds=seeds[:8])


# --------------------------------------------------------------------------
# Generic public page extraction (url seeds)
# --------------------------------------------------------------------------
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TEL_RE = re.compile(r'href="tel:([+0-9()\-\s]{6,})"')
_RESERVED_HANDLES = {
    "search", "login", "signup", "register", "features", "marketplace", "topics", "explore",
    "about", "settings", "help", "privacy", "terms", "home", "watch", "channel", "user",
    "pricing", "enterprise", "security", "site", "apps", "blog", "news", "support", "contact",
    "download", "downloads", "collections", "trending", "sponsors", "organizations", "orgs",
    "new", "notifications", "pulls", "issues", "codespaces", "copilot", "readme", "join",
    "share", "sharer", "intent", "hashtag", "status", "i", "web", "m", "www",
}
_SOCIAL_PATTERNS = {
    "github": re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.\-]+)"),
    "x": re.compile(r"https?://(?:www\.)?(?:x|twitter)\.com/([A-Za-z0-9_]{2,})"),
    "linkedin": re.compile(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/in/([A-Za-z0-9_%\-]+)"),
    "instagram": re.compile(r"https?://(?:www\.)?instagram\.com/([A-Za-z0-9_.]+)"),
    "telegram": re.compile(r"https?://(?:www\.)?t\.me/([A-Za-z0-9_]+)"),
    "mastodon": re.compile(r"https?://([a-z0-9.\-]+)/@([A-Za-z0-9_]+)"),
    "youtube": re.compile(r"https?://(?:www\.)?youtube\.com/(?:@|channel/|user/)([A-Za-z0-9_\-]+)"),
}


def extract_page(page: str, base_url: str) -> dict:
    title = re.search(r"<title[^>]*>(.*?)</title>", page, re.S | re.I)
    desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', page, re.I)
    og = re.search(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)', page, re.I)
    emails = []
    for m in re.findall(r'href="mailto:([^"?]+)', page, re.I):
        emails.append(urllib.parse.unquote(m.strip()))
    if not emails:
        for m in _EMAIL_RE.findall(page):
            low = m.lower()
            if any(low.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js")):
                continue
            emails.append(m)
    phones = [p.strip() for p in _TEL_RE.findall(page)]
    socials = []
    for platform, pattern in _SOCIAL_PATTERNS.items():
        for match in pattern.findall(page)[:3]:
            handle = match[1] if isinstance(match, tuple) else match
            if not handle or handle.lower() in _RESERVED_HANDLES or len(handle) < 2:
                continue
            if platform == "mastodon":
                host, handle = match[0], match[1]
                url = f"https://{host}/@{handle}"
            else:
                url = {"x": "https://x.com/", "github": "https://github.com/",
                       "linkedin": "https://www.linkedin.com/in/", "instagram": "https://instagram.com/",
                       "telegram": "https://t.me/", "youtube": "https://youtube.com/@"}.get(platform, "") + handle
            if any(x["platform"] == platform and x["handle"].lower() == handle.lower() for x in socials):
                continue
            socials.append({"platform": platform, "handle": handle, "url": url})
    return {
        "title": _clean(title.group(1)) if title else "",
        "description": _clean((desc or og).group(1)) if (desc or og) else "",
        "emails": list(dict.fromkeys(emails))[:5],
        "phones": list(dict.fromkeys(phones))[:3],
        "socials": socials[:10],
        "base_url": base_url,
    }


@register
class PageFetch(Connector):
    name = "page"
    accepts = frozenset({"url"})
    description = "Public page extraction (title, description, mailto, tel, social links)"

    def run(self, seed: Seed, ctx: Context) -> Result:
        resp = ctx.http.get(seed.value, connector=self.name, timeout=10, retries=1)
        if not resp.ok:
            return Result(note=f"page HTTP {resp.status}")
        page = resp.text()
        if "<html" not in page[:2000].lower():
            return Result(note="page is not HTML")
        found = extract_page(page, seed.value)
        claims: list[Claim] = []
        if found["title"]:
            claims.append(_c(seed, kind="profile", predicate="page_title", value=found["title"],
                             source=self.name, url=seed.value, excerpt_text=excerpt(found["title"]),
                             confidence=0.7))
        if found["description"]:
            claims.append(_c(seed, kind="profile", predicate="page_description", value=found["description"],
                             source=self.name, url=seed.value, excerpt_text=excerpt(found["description"]),
                             confidence=0.7))
        for email in found["emails"]:
            claims.append(_c(seed, kind="contact", predicate="email", value=email,
                             source=self.name, url=seed.value,
                             excerpt_text=excerpt(f"published on page: {email}"), confidence=0.65,
                             extra={"via": "page publish"}))
        for phone in found["phones"]:
            claims.append(_c(seed, kind="contact", predicate="phone", value=phone,
                             source=self.name, url=seed.value,
                             excerpt_text=excerpt(f"tel: link {phone}"), confidence=0.7))
        seeds: list[Seed] = []
        for social in found["socials"]:
            claims.append(_c(seed, kind="account", predicate="social_link",
                             value=f"{social['platform']}:{social['handle']}",
                             source=self.name, url=social["url"],
                             excerpt_text=excerpt(f"{social['platform']} link on page"),
                             confidence=0.7, extra=social))
            if social["platform"] in ("github", "telegram", "instagram", "x"):
                seeds.append(Seed("username", social["handle"]))
        if not claims:
            claims.append(_c(seed, kind="absence", predicate="page_content", value="none",
                             source=self.name, url=seed.value,
                             excerpt_text="page fetched, no title/description/contact links",
                             confidence=0.5))
        return Result(claims=claims, seeds=seeds[:5])
