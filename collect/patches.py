#!/usr/bin/env python3
"""Collect runtime patch status into data/patches.json.

For each tracked language (collect/patches.yml): which major versions are
supported, the latest patch of each distribution and when it came out, whether
the official container image already holds that patch and how long that took,
when support ends, and the high-severity CVEs that exactly this patch fixed.

Sources (public APIs only, no scraping, no image pulls, no accounts):
  endoflife.date API v1  majors, latest patch, patch date, LTS, EOL date
  GitHub REST API        the time of day a patch came out (release or tag)
  Docker Hub API        last push of a named tag (one request per tag)
  OSV query API          advisories and their fixed versions
  NVD API 2.0            CVSS score, only for the CVEs OSV did not score

The output schema of collect/collect.py (data/latest.json) is not touched.
Each source is fetched on its own; a failure is recorded under "sources" and
the affected fields stay null, so the page says "unknown" instead of
showing a wrong number. Times are UTC ISO-8601 in the file; the page shows KST.

Environment (all optional):
  GITHUB_TOKEN   raised GitHub limit (Actions injects it; never put it in files)
  NVD_API_KEY    faster NVD requests (same secret as collect.yml)

Usage:  python collect/patches.py [--out data/patches.json] [--config collect/patches.yml]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import collect as base  # noqa: E402  (USER_AGENT, CVSS v3 scoring, log)

ROOT = Path(__file__).resolve().parent.parent
CONFIG = Path(__file__).resolve().parent / "patches.yml"
OUT = ROOT / "data" / "patches.json"
CVSS_CACHE = ROOT / "data" / "patches_cvss.json"

USER_AGENT = base.USER_AGENT
EOL_API = "https://endoflife.date/api/v1/products/"
GITHUB_API = "https://api.github.com"
HUB_API = "https://hub.docker.com/v2/namespaces"
OSV_QUERY = "https://api.osv.dev/v1/query"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HIGH_CVSS = 7.0
NEW_PATCH_DAYS = 7
CHANGELOG_DAYS = 30
CHANGELOG_MAX = 40
NVD_PER_RUN = 40
EOL_SOON_DAYS = 180
REBUILD_HOURS = 168
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

CVE_DEFINITION = {
    "en": ("High or critical (CVSS 7.0+) CVEs whose advisory names this patch's update release "
           "as the fixed version, found in the OSV sources listed. 0 means none found there, "
           "not that none exist."),
    "ko": ("OSV의 아래 출처에서, 수정 버전이 이 패치의 업데이트 릴리스와 일치하는 고위험(CVSS 7.0 이상) CVE입니다. "
           "0건은 이 출처에서 찾지 못했다는 뜻이며, 없다는 보증이 아닙니다."),
}


def log(msg: str) -> None:
    base.log(msg)


# ---------------------------------------------------------------- HTTP

class Fetcher:
    """GET/POST JSON with the collector's retry rules (403, 429, 5xx) and the
    limits the APIs ask for (Retry-After, X-RateLimit-*). ``sleep`` and ``opener``
    are injectable so tests never touch the network or the clock."""

    def __init__(self, sleep=time.sleep, opener=urllib.request.urlopen, min_gap: dict | None = None):
        self.sleep = sleep
        self.opener = opener
        # Seconds between two requests to one host (endoflife.date: at most 1/s).
        self.min_gap = min_gap if min_gap is not None else {"endoflife.date": 1.1}
        self._last: dict[str, float] = {}
        self.github_blocked = False
        self.nvd_failed = False   # NVD unreachable: ask no more this run
        self.nvd_asked = 0
        self.requests = 0
        # Optional lookups (GitHub, OSV, NVD) stop after this many seconds so a
        # slow run stays far below the workflow's 30 minutes.
        self.started = time.monotonic()
        self.budget = 600.0

    def over_budget(self) -> bool:
        return time.monotonic() - self.started > self.budget

    def _pace(self, host: str) -> None:
        gap = self.min_gap.get(host)
        if gap:
            wait = self._last.get(host, 0) + gap - time.monotonic()
            if wait > 0:
                self.sleep(wait)
            self._last[host] = time.monotonic()

    def json(self, url: str, headers: dict | None = None, body: dict | None = None,
             retries: int = 3, timeout: int = 60, not_found=None):
        """Decoded JSON. A 404 returns ``not_found`` when given, else raises."""
        host = urllib.parse.urlsplit(url).hostname or ""
        h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        h.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        last: Exception | None = None
        for attempt in range(retries):
            self._pace(host)
            self.requests += 1
            try:
                req = urllib.request.Request(url, data=data, headers=h)
                with self.opener(req, timeout=timeout) as r:
                    self._note_limits(host, r.headers)
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                last = e
                if e.code == 404 and not_found is not None:
                    return not_found
                if e.code == 404:
                    raise
                if host == "api.github.com" and e.code in (401, 403):
                    # Rate limit or no access: more tries only make it worse.
                    self.github_blocked = True
                    raise
                if e.code in (403, 429, 500, 502, 503, 504):
                    self.sleep(min(self._retry_after(e.headers, 2 ** (attempt + 1) * 3), 120))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last = e
                self.sleep(2 ** attempt)
        assert last is not None
        raise last

    @staticmethod
    def _retry_after(headers, default: float) -> float:
        try:
            return max(float(headers.get("Retry-After")), 1.0)
        except (TypeError, ValueError):
            return default

    def _note_limits(self, host: str, headers) -> None:
        remaining = headers.get("X-RateLimit-Remaining") if headers else None
        if remaining is None:
            remaining = headers.get("x-ratelimit-remaining") if headers else None
        try:
            left = int(remaining)
        except (TypeError, ValueError):
            return
        if host == "api.github.com" and left <= 1:
            self.github_blocked = True
        elif host == "hub.docker.com" and left <= 1:
            # Docker Hub counts per minute: wait for the window to reopen.
            try:
                reset = int(headers.get("X-RateLimit-Reset") or headers.get("x-ratelimit-reset"))
                self.sleep(max(0, min(reset - int(time.time()), 60)) + 1)
            except (TypeError, ValueError):
                self.sleep(30)


# ---------------------------------------------------------------- pure helpers

def parse_time(s: str) -> datetime:
    return base.parse_time(s)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def day_start(d: str) -> datetime:
    """'2026-11-17' as a UTC datetime (endoflife.date has no time of day)."""
    return datetime.fromisoformat(d).replace(tzinfo=timezone.utc)


def numbers(version: str) -> tuple[int, ...]:
    """Leading numeric parts of a version, ignoring distro revisions and builds:
    '21.0.13.1+2-1~24.04.1' -> (21, 0, 13, 1); '8u514-b01' -> (8, 514)."""
    v = re.sub(r"^\d+:", "", str(version))          # Debian epoch
    v = re.split(r"[-~+]", v, maxsplit=1)[0]
    return tuple(int(n) for n in re.findall(r"\d+", v))


def update_release(latest: str) -> tuple[int, ...] | None:
    """The OpenJDK-style update release a vendor version is built on:
    Temurin 21.0.13.1+2 and Corretto 21.0.13.1.2 -> (21, 0, 13); 8u514 and
    Corretto 8.514.01.1 -> (8, 514). None when the version is too short."""
    m = re.match(r"^8\.(\d+)\.", latest)
    if m:
        return (8, int(m.group(1)))
    nums = numbers(latest)
    k = 2 if nums[:1] == (8,) else 3
    return nums[:k] if len(nums) >= k else None


def base_version(latest: str) -> str:
    """Tag form of the update release: 17.0.21 or 8u514."""
    u = update_release(latest)
    if not u:
        return latest
    return f"8u{u[1]}" if u[0] == 8 else ".".join(str(n) for n in u)


def template_vars(name: str, latest: str) -> dict[str, str]:
    return {"name": name, "latest": latest, "latest_us": latest.replace("+", "_"),
            "base": base_version(latest)}


def fill(template: str, vars_: dict[str, str]) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: vars_[m.group(1)], template)


def is_exact_tag(template: str) -> bool:
    """A tag that names the full patch version."""
    return "{latest}" in template or "{latest_us}" in template


def select_majors(releases: list[dict], select: dict, today: date) -> dict[str, dict]:
    """Majors to show for one product: supported ones, plus recently ended ones.
    Keyed by release name, in the API's order (newest first)."""
    lts_only = bool(select.get("lts_only"))
    recent = int(select.get("recent_eol_days") or 0)
    out: dict[str, dict] = {}
    for r in releases:
        if lts_only and not r.get("isLts"):
            continue
        keep = bool(r.get("isMaintained")) and not r.get("isEol")
        if not keep and recent and r.get("isEol") and r.get("eolFrom"):
            ended = date.fromisoformat(r["eolFrom"])
            keep = 0 <= (today - ended).days <= recent
        if keep:
            out[str(r["name"])] = r
    return out


def github_ref(cfg: dict | None, vars_: dict[str, str], link: str | None) -> tuple[str, str, str] | None:
    """(repo, tag, kind) for the patch time: the config, else the release URL
    of endoflife.date when it points at a GitHub release."""
    if cfg and cfg.get("repo"):
        return cfg["repo"], fill(cfg["tag"], vars_), cfg.get("kind", "release")
    m = re.match(r"^https://github\.com/([^/]+/[^/]+)/releases/tag/(.+)$", link or "")
    if m:
        return m.group(1), urllib.parse.unquote(m.group(2)), "release"
    return None


def image_status(tag_results: list[dict], patch_time: datetime) -> tuple[bool | None, str | None]:
    """(contains the latest patch, earliest build time of a tag that does).

    tag_results: {"tag", "exact", "exists", "digest", "pushed_at"} per tag.
    Exact tags decide when a distribution has any; the others then need an
    identical digest. Without exact tags, a tag counts when it was pushed after
    the patch came out. None means no tag could be looked up."""
    looked = [t for t in tag_results if t.get("exists") is not None]
    if not looked:
        return None, None
    exact_all = [t for t in looked if t["exact"]]
    exact_ok = [t for t in exact_all if t["exists"]]
    if exact_all:
        digests = {t["digest"] for t in exact_ok if t.get("digest")}
        hits = [t for t in looked if t["exists"] and (t["exact"] or t.get("digest") in digests)]
    else:
        hits = [t for t in looked if t["exists"] and t.get("pushed_at")
                and parse_time(t["pushed_at"]) >= patch_time]
    for t in looked:
        t["contains_latest"] = t in hits
    if not hits:
        return False, None
    pushed = [t["pushed_at"] for t in hits if t.get("pushed_at")]
    return True, min(pushed) if pushed else None


def image_delay(patch_time: datetime | None, built_at: str | None, contains: bool | None,
                now: datetime, approx: bool = False) -> dict:
    """The ✅/⏳ numbers of the page, in whole hours.
    reflected: image build minus patch time (never negative);
    pending:   now minus patch time; unknown: no registry tracked."""
    if contains is None or patch_time is None:
        return {"state": "unknown", "hours": None, "approx": False}
    if contains and built_at:
        hours = max(0, int((parse_time(built_at) - patch_time).total_seconds() // 3600))
        if hours > REBUILD_HOURS:
            # Docker Hub gives the last push, and official images are rebuilt
            # for base-image updates. A week later is a rebuild, not the first
            # build, so no delay is claimed.
            return {"state": "reflected", "hours": None, "approx": approx, "rebuilt": True}
        return {"state": "reflected", "hours": hours, "approx": approx}
    if contains:
        return {"state": "reflected", "hours": None, "approx": approx}
    hours = max(0, int((now - patch_time).total_seconds() // 3600))
    return {"state": "pending", "hours": hours, "approx": approx}


def advisory_cves(rec: dict) -> list[str]:
    """CVE ids named by an OSV record (id, aliases, upstream, related)."""
    ids: list[str] = []
    for field in (rec.get("id"), *(rec.get("aliases") or []), *(rec.get("upstream") or []),
                  *(rec.get("related") or [])):
        for m in CVE_RE.findall(str(field or "")):
            if m not in ids:
                ids.append(m)
    return ids


def record_fixed(rec: dict, ecosystem: str, package: str) -> list[str]:
    """Fixed versions the record names for exactly this ecosystem and package."""
    out: list[str] = []
    for a in rec.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("name") != package or pkg.get("ecosystem") != ecosystem:
            continue
        for r in a.get("ranges") or []:
            for ev in r.get("events") or []:
                if ev.get("fixed") and ev["fixed"] not in out:
                    out.append(ev["fixed"])
    return out


def record_score(rec: dict) -> float | None:
    """CVSS v3 base score the record carries as a vector. CVSS v4 vectors and
    text labels (Ubuntu 'high') are not scores here."""
    for s in rec.get("severity") or []:
        if s.get("type") in ("CVSS_V3", "CVSS_V3_1") and str(s.get("score", "")).startswith("CVSS:3"):
            score = base.cvss3_base_score(s["score"])
            if score is not None:
                return score
    return None


def fixed_matches(fixed: str, latest: str, mode: str = "exact") -> bool:
    """Does a fixed version name this patch?
    exact:  same numbers (Go stdlib 1.26.11 == 1.26.11; Debian 3.13.18-1 == 3.13.18).
    update: same OpenJDK update release, so Ubuntu 21.0.13.1+2-1~24.04.1 matches
            Temurin 21.0.13.1+2 and Corretto 21.0.13.1.2 (update release 21.0.13)."""
    if mode == "update":
        want = update_release(latest)
        got = numbers(fixed)
        return bool(want) and len(got) >= len(want) and got[:len(want)] == want
    want = numbers(latest)
    return bool(want) and numbers(fixed) == want


def high_cves_from_records(sources: list[tuple[str, str, str, list[dict]]], latest: str,
                           nvd_scores: dict[str, float | None]) -> tuple[list[dict], int]:
    """High-severity CVEs fixed by ``latest`` from OSV records.

    sources: (ecosystem, package, match mode, records). nvd_scores: CVE -> NVD base score
    for CVEs whose records carry no usable score. Returns (cves, unrated) where
    unrated counts matching CVEs that have no score anywhere (not listed)."""
    found: dict[str, dict] = {}
    for eco, pkg, mode, recs in sources:
        for rec in recs:
            if rec.get("withdrawn"):
                continue
            fixes = [f for f in record_fixed(rec, eco, pkg) if fixed_matches(f, latest, mode)]
            if not fixes:
                continue
            cves = advisory_cves(rec)
            if not cves:
                continue
            single = len(cves) == 1
            score = record_score(rec) if single else None
            for cve in cves:
                e = found.setdefault(cve, {"id": cve, "cvss": None, "cvss_source": None, "osv_id": rec["id"]})
                if score is not None and e["cvss"] is None:
                    e["cvss"], e["cvss_source"] = score, "OSV"
                # Prefer a CVE-named record (UBUNTU-CVE-..., GO-...) as the link target.
                if single and not str(e["osv_id"]).startswith(("UBUNTU-CVE", "DEBIAN-CVE", "GO-")):
                    e["osv_id"] = rec["id"]
    out, unrated = [], 0
    for cve, e in sorted(found.items()):
        if e["cvss"] is None and nvd_scores.get(cve) is not None:
            e["cvss"], e["cvss_source"] = nvd_scores[cve], "NVD"
        if e["cvss"] is None:
            unrated += 1
            continue
        if e["cvss"] >= HIGH_CVSS:
            out.append({"id": cve, "cvss": e["cvss"], "cvss_source": e["cvss_source"],
                        "fixed_in": latest, "url": f"https://osv.dev/vulnerability/{e['osv_id']}"})
    out.sort(key=lambda c: (-c["cvss"], c["id"]))
    return out, unrated


def unscored_cves(sources: list[tuple[str, str, str, list[dict]]], latest: str) -> list[str]:
    """CVEs fixed by this patch that no record scores: the ones worth an NVD lookup."""
    got, _ = high_cves_from_records(sources, latest, {})
    scored = {c["id"] for c in got}
    want: list[str] = []
    for eco, pkg, mode, recs in sources:
        for rec in recs:
            if rec.get("withdrawn"):
                continue
            if not any(fixed_matches(f, latest, mode) for f in record_fixed(rec, eco, pkg)):
                continue
            cves = advisory_cves(rec)
            if len(cves) == 1 and record_score(rec) is not None:
                continue
            for c in cves:
                if c not in scored and c not in want:
                    want.append(c)
    return want


# ---------------------------------------------------------------- summary, changelog, EOL

def eol_state(eol_from: str | None, is_eol: bool, now: datetime) -> str:
    """'ended', 'soon' (within EOL_SOON_DAYS), 'ok', or 'none' (no date)."""
    if is_eol:
        return "ended"
    if not eol_from:
        return "none"
    days = (date.fromisoformat(eol_from) - now.date()).days
    return "ended" if days < 0 else "soon" if days <= EOL_SOON_DAYS else "ok"


def summarize(languages: list[dict], now: datetime) -> dict:
    new = pending = 0
    high: set[str] = set()
    cutoff = now - timedelta(days=NEW_PATCH_DAYS)
    for lang in languages:
        for ver in lang["versions"]:
            for d in ver["distros"]:
                if d.get("released_at") and parse_time(d["released_at"]) >= cutoff:
                    new += 1
                if (d.get("image_status") or {}).get("state") == "pending" and not d.get("is_eol"):
                    pending += 1
                high.update(c["id"] for c in d.get("high_cves") or [])
    return {"new_patches_7d": new, "images_pending": pending, "high_cves": len(high)}


def flatten(data: dict | None) -> dict[str, dict]:
    """(language/version/distro) -> distro record, for comparing two runs."""
    out: dict[str, dict] = {}
    for lang in (data or {}).get("languages") or []:
        for ver in lang.get("versions") or []:
            for d in ver.get("distros") or []:
                out[f"{lang['id']}/{ver['name']}/{d['id']}"] = {
                    "lang": lang["label"], "ver": ver["name"], "dist": d.get("label"),
                    "inline": bool(ver.get("inline")), **d}
    return out


def _name(rec: dict) -> str:
    return f"{rec['lang']} {rec['ver']}" if rec["inline"] else f"{rec['lang']} {rec['ver']} {rec['dist']}"


def build_changelog(prev: dict | None, languages: list[dict], now: datetime) -> list[dict]:
    """What changed since the previous file: a new patch, an image that caught up.
    Older entries are carried over for CHANGELOG_DAYS."""
    old, cur = flatten(prev), flatten({"languages": languages})
    events: list[dict] = []
    for key, rec in cur.items():
        before = old.get(key)
        if before is None:
            continue
        label = _name(rec)
        if rec.get("latest_patch") and rec["latest_patch"] != before.get("latest_patch"):
            at = rec.get("released_at") or iso(now)
            events.append({
                "key": f"patch:{key}:{rec['latest_patch']}", "at": at, "kind": "patch",
                "text_en": f"{label} {rec['latest_patch']} released",
                "text_ko": f"{label} {rec['latest_patch']} 배포",
            })
        was = (before.get("image_status") or {}).get("state")
        now_state = (rec.get("image_status") or {}).get("state")
        if now_state == "reflected" and was == "pending" and rec.get("latest_patch") == before.get("latest_patch"):
            at = next((i["built_at"] for i in rec.get("images") or [] if i.get("contains_latest") and i.get("built_at")),
                      iso(now))
            events.append({
                "key": f"image:{key}:{rec['latest_patch']}", "at": at, "kind": "image",
                "text_en": f"{label} {rec['latest_patch']}: Docker Hub image updated",
                "text_ko": f"{label} {rec['latest_patch']}: Docker Hub 이미지 반영",
            })
    kept = {e["key"]: e for e in (prev or {}).get("changelog") or [] if e.get("key")}
    for e in events:
        kept.setdefault(e["key"], e)
    cutoff = now - timedelta(days=CHANGELOG_DAYS)
    merged = [e for e in kept.values() if parse_time(e["at"]) >= cutoff]
    merged.sort(key=lambda e: e["at"], reverse=True)
    return merged[:CHANGELOG_MAX]


# ---------------------------------------------------------------- network layer

def gh_headers() -> dict:
    tok = os.environ.get("GITHUB_TOKEN")
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def github_time(f: Fetcher, repo: str, tag: str, kind: str) -> tuple[str, str] | None:
    """(ISO time, 'github-release' | 'github-tag') of a patch, or None."""
    if f.github_blocked or f.over_budget():
        return None
    q = urllib.parse.quote(tag, safe="")
    h = gh_headers()
    if kind == "release":
        rel = f.json(f"{GITHUB_API}/repos/{repo}/releases/tags/{q}", headers=h, not_found={})
        when = rel.get("published_at") or rel.get("created_at")
        if when:
            return when, "github-release"
    ref = f.json(f"{GITHUB_API}/repos/{repo}/git/ref/tags/{q}", headers=h, not_found={})
    obj = ref.get("object") or {}
    if obj.get("type") == "tag":
        t = f.json(obj["url"], headers=h, not_found={})
        when = (t.get("tagger") or {}).get("date")
    elif obj.get("type") == "commit":
        c = f.json(f"{GITHUB_API}/repos/{repo}/git/commits/{obj['sha']}", headers=h, not_found={})
        when = (c.get("committer") or {}).get("date")
    else:
        when = None
    return (when, "github-tag") if when else None


def hub_tag(f: Fetcher, repo: str, tag: str) -> dict:
    """Existence, digest and last push of one tag. exists=None: lookup failed."""
    ns, name = repo.split("/", 1)
    url = f"{HUB_API}/{ns}/repositories/{name}/tags/{urllib.parse.quote(tag, safe='')}"
    try:
        d = f.json(url, not_found={})
    except Exception as e:  # noqa: BLE001
        log(f"dockerhub {repo}:{tag}: {e}")
        return {"exists": None}
    if not d.get("name"):
        return {"exists": False}
    return {"exists": True, "digest": d.get("digest"),
            "pushed_at": d.get("tag_last_pushed") or d.get("last_updated")}


def osv_records(f: Fetcher, ecosystem: str, package: str) -> list[dict]:
    out, token = [], None
    while True:
        body: dict = {"package": {"name": package, "ecosystem": ecosystem}}
        if token:
            body["page_token"] = token
        d = f.json(OSV_QUERY, body=body)
        out += d.get("vulns") or []
        token = d.get("next_page_token")
        if not token:
            return out


def nvd_scores(f: Fetcher, cves: list[str], now: datetime, path: Path | None = None) -> dict[str, float | None]:
    """NVD base score per CVE, cached in data/patches_cvss.json (a CVE NVD has
    not scored yet is asked again after a day). At most NVD_PER_RUN requests."""
    path = path or CVSS_CACHE
    try:
        cache = json.loads(path.read_text())
    except (OSError, ValueError):
        cache = {}
    today = now.strftime("%Y-%m-%d")
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    for cve in cves:
        if f.over_budget() or f.nvd_failed:
            break
        c = cache.get(cve)
        if c and (c.get("cvss") is not None or c.get("checked") == today):
            continue
        if f.nvd_asked >= NVD_PER_RUN:
            break
        f.nvd_asked += 1
        try:
            data = f.json(f"{NVD_URL}?cveId={cve}", headers=headers, timeout=60, retries=2)
        except Exception as e:  # noqa: BLE001
            log(f"nvd {cve}: {e}")
            f.nvd_failed = True
            break
        finally:
            f.sleep(0.7 if headers else 6.5)
        metrics = ((data.get("vulnerabilities") or [{}])[0].get("cve") or {}).get("metrics") or {}
        entry = {"cvss": None, "checked": today}
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            if metrics.get(key):
                entry["cvss"] = metrics[key][0]["cvssData"]["baseScore"]
                break
        cache[cve] = entry
    try:
        path.write_text(json.dumps(dict(sorted(cache.items())), indent=1) + "\n")
    except OSError as e:
        log(f"nvd cache: {e}")
    return {c: (cache.get(c) or {}).get("cvss") for c in cves}


def collect_distro(f: Fetcher, lang_id: str, dcfg: dict, rel: dict, now: datetime,
                   status: dict) -> dict:
    """One distribution's record for one major version."""
    latest = (rel.get("latest") or {}).get("name") or ""
    vars_ = template_vars(str(rel["name"]), latest)
    out: dict = {
        "id": dcfg["id"], "label": dcfg["label"],
        "latest_patch": latest or None,
        "released_at": None, "released_precision": None, "released_source": None,
        "release_url": (rel.get("latest") or {}).get("link"),
        "is_lts": bool(rel.get("isLts")), "is_eol": bool(rel.get("isEol")),
        "eol_from": rel.get("eolFrom"),
        "high_cves": None, "cvss_unrated": 0, "cve_sources": [],
        "images": [], "image_status": {"state": "unknown", "hours": None, "approx": False},
        "image_note": dcfg.get("image_note"),
        "workaround_dockerfile": None,
    }
    if not latest:
        return out

    # When the patch came out: GitHub time of day, else the date endoflife.date has.
    patch_time = None
    ref = github_ref(dcfg.get("github"), vars_, out["release_url"])
    if ref:
        try:
            got = github_time(f, *ref)
        except Exception as e:  # noqa: BLE001
            log(f"github {ref[0]} {ref[1]}: {e}")
            status["github"]["failed"] += 1
            got = None
        if got:
            out["released_at"], out["released_source"] = iso(parse_time(got[0])), got[1]
            out["released_precision"] = "time"
            patch_time = parse_time(got[0])
            status["github"]["ok"] += 1
    if patch_time is None and (rel.get("latest") or {}).get("date"):
        patch_time = day_start(rel["latest"]["date"])
        out["released_at"], out["released_source"] = iso(patch_time), "endoflife.date"
        out["released_precision"] = "date"
    approx = out["released_precision"] == "date"

    # Does the official image hold it?
    hub = dcfg.get("dockerhub")
    if hub and patch_time is not None:
        results = []
        for tpl in hub["tags"]:
            tag = fill(tpl, vars_)
            r = hub_tag(f, hub["repo"], tag)
            results.append({"tag": tag, "exact": is_exact_tag(tpl), **r})
        contains, built = image_status(results, patch_time)
        out["images"] = [{
            "registry": "dockerhub", "repo": hub["repo"], "tag": r["tag"], "exact": r["exact"],
            "exists": r["exists"], "contains_latest": r.get("contains_latest"),
            "built_at": r.get("pushed_at") if r["exists"] else None,
            "match": "digest" if any(x["exact"] for x in results) else "pushed-after",
        } for r in results]
        out["image_status"] = image_delay(patch_time, built, contains, now, approx)
        out["image_status"]["built_at"] = built
        status["dockerhub"]["ok" if contains is not None else "failed"] += 1

    # High-severity CVEs fixed by this patch.
    osv = dcfg.get("osv")
    needs_update_release = any(x.get("match") == "update" for x in osv or [])
    if needs_update_release and not update_release(latest):
        osv = None        # '25' or '27' alone does not say which update release it is
    if osv and latest and not f.over_budget():
        sources = []
        for s in osv:
            eco, pkg = s["ecosystem"], fill(s["package"], vars_)
            try:
                recs = osv_records(f, eco, pkg)
            except Exception as e:  # noqa: BLE001
                log(f"osv {eco}/{pkg}: {e}")
                status["osv"]["failed"] += 1
                continue
            status["osv"]["ok"] += 1
            if recs:
                sources.append((eco, pkg, s.get("match", "exact"), recs))
        if sources:
            need = unscored_cves(sources, latest)
            scores = nvd_scores(f, need, now) if need else {}
            out["high_cves"], out["cvss_unrated"] = high_cves_from_records(sources, latest, scores)
            out["cve_sources"] = [f"{eco} {pkg}" for eco, pkg, _, _ in sources]
    return out


def collect(config: dict, prev: dict | None, f: Fetcher, now: datetime) -> dict:
    status = {k: {"ok": 0, "failed": 0} for k in ("endoflife", "github", "dockerhub", "osv")}
    prev_flat = flatten(prev)
    languages = []
    for lcfg in config["languages"]:
        eol: dict[str, list[dict]] = {}
        for dcfg in lcfg["distros"]:
            try:
                d = f.json(EOL_API + dcfg["eol"])
                eol[dcfg["id"]] = (d.get("result") or d)["releases"]
                status["endoflife"]["ok"] += 1
            except Exception as e:  # noqa: BLE001
                log(f"endoflife {dcfg['eol']}: {e}")
                status["endoflife"]["failed"] += 1
        chosen: dict[str, dict] = {}   # release name -> a record, newest first
        for dcfg in lcfg["distros"]:
            for name, r in select_majors(eol.get(dcfg["id"], []), lcfg.get("select") or {}, now.date()).items():
                chosen.setdefault(name, r)
        names = sorted(chosen, key=lambda n: [-x for x in numbers(n)] or [0])
        versions = []
        for name in names:
            distros = []
            for dcfg in lcfg["distros"]:
                rel = next((r for r in eol.get(dcfg["id"], []) if str(r["name"]) == name), None)
                if rel is None:
                    old = prev_flat.get(f"{lcfg['id']}/{name}/{dcfg['id']}")
                    if old and dcfg["id"] not in eol:      # endoflife.date failed: keep the last values
                        distros.append({k: v for k, v in old.items() if k not in ("lang", "ver", "dist", "inline")}
                                       | {"stale": True})
                    continue
                distros.append(collect_distro(f, lcfg["id"], dcfg, rel, now, status))
            if not distros:
                continue
            eols = [d["eol_from"] for d in distros if d.get("eol_from") and not d.get("is_eol")]
            all_eol = all(d.get("is_eol") for d in distros)
            ver_eol = max(eols) if eols else (max((d["eol_from"] for d in distros if d.get("eol_from")), default=None))
            versions.append({
                "name": name,
                "is_lts": any(d["is_lts"] for d in distros),
                "is_eol": all_eol,
                "eol_from": ver_eol,
                "inline": len(lcfg["distros"]) == 1,
                "distros": distros,
            })
        languages.append({"id": lcfg["id"], "label": lcfg["label"], "versions": versions})
    out = {
        "generated_at": iso(now),
        "summary": summarize(languages, now),
        "languages": languages,
        "changelog": build_changelog(prev, languages, now),
        "cve_definition": CVE_DEFINITION,
        "sources": status,
    }
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Collect runtime patch status into data/patches.json")
    p.add_argument("--config", type=Path, default=CONFIG)
    p.add_argument("--out", type=Path, default=OUT)
    args = p.parse_args(argv)
    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    try:
        prev = json.loads(args.out.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        prev = None
    f = Fetcher()
    started = time.monotonic()
    data = collect(config, prev, f, datetime.now(timezone.utc))
    n_ver = sum(len(l["versions"]) for l in data["languages"])
    if n_ver == 0:
        log("patches: endoflife.date returned nothing; keeping the previous file")
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    log(f"patches: {n_ver} versions, {f.requests} requests, {time.monotonic() - started:.0f}s, "
        f"sources {json.dumps(data['sources'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
