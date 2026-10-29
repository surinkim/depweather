#!/usr/bin/env python3
"""Collect today's vulnerability data for the packages in stacks.yml.

Writes data/latest.json and data/history/YYYY-MM-DD.json.

Sources:
  OSV.dev       per-ecosystem GCS export (modified_id.csv + one JSON per entry)
  CISA KEV      known_exploited_vulnerabilities.json
  FIRST EPSS    epss_scores-current.csv.gz
  NVD API 2.0   monthly / daily CVE publication counts
  npm, pypistats  weekly downloads (tile size)

Each source is fetched independently. When one fails, its fields are left
null and the failure is recorded under "sources" in the output, so the page
can say what is missing instead of showing wrong numbers.

Only dependency outside the standard library: PyYAML (for stacks.yml).
Optional environment variables: NVD_API_KEY (faster NVD requests),
DEPWEATHER_STACKS (path to a package list other than collect/stacks.yml).
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import math
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
# A personal watch list can live outside the repository: DEPWEATHER_STACKS=~/my-stacks.yml
STACKS = Path(os.environ.get("DEPWEATHER_STACKS") or Path(__file__).resolve().parent / "stacks.yml").expanduser()
DATA = ROOT / "data"

WINDOW_DAYS = 30
NVD_MONTHS = 14
USER_AGENT = "depweather-collector (+https://github.com/surinkim/depweather)"

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
OSV_QUERY = "https://api.osv.dev/v1/query"
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's own mirror of the same feed on GitHub
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
EPSS_URLS = [
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_RANK = {"NONE": 0, "UNKNOWN": 1, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_NAME = {"MODERATE": "MEDIUM"}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def http_get(url: str, headers: dict | None = None, timeout: int = 60, retries: int = 3) -> bytes:
    h = {"User-Agent": USER_AGENT}
    h.update(headers or {})
    last: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code == 404:
                raise
            if e.code in (403, 429, 500, 502, 503, 504):
                time.sleep(2 ** (attempt + 1) * 3)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
            time.sleep(2 ** attempt)
    assert last is not None
    raise last


def get_json(url: str, **kw):
    return json.loads(http_get(url, **kw))


def post_json(url: str, body: dict, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def effective_date(v: dict) -> datetime:
    """When a vulnerability became news: its publication, or its addition to
    CISA KEV if that came later (an old bug that is exploited now)."""
    published = parse_time(v["published"])
    if v.get("kev_date_added"):
        added = datetime.fromisoformat(v["kev_date_added"]).replace(tzinfo=timezone.utc)
        return max(published, added)
    return published


def parse_time(s: str) -> datetime:
    # OSV timestamps carry nanoseconds; datetime only takes microseconds.
    s = s.strip().replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        frac, tz = rest, ""
        for sep in ("+", "-"):
            if sep in rest:
                frac, tz = rest.split(sep, 1)
                tz = sep + tz
                break
        s = f"{head}.{frac[:6]}{tz}"
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- CVSS v3

_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score from a vector string (spec section 7.1)."""
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _V3["CIA"][m["C"]]) * (1 - _V3["CIA"][m["I"]]) * (1 - _V3["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _V3["AV"][m["AV"]] * _V3["AC"][m["AC"]] * pr * _V3["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + expl) if changed else impact + expl, 10))


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


# ---------------------------------------------------------------- OSV

def osv_recent_ids(ecosystem: str, since: datetime) -> list[str]:
    raw = http_get(f"{OSV_BUCKET}/{urllib.parse.quote(ecosystem)}/modified_id.csv", timeout=120).decode()
    ids = []
    for line in raw.splitlines():
        ts, _, vid = line.partition(",")
        if not vid:
            continue
        # A record published inside the window was also modified inside it.
        if parse_time(ts) < since:
            break  # file is sorted newest first
        ids.append(vid.strip())
    return ids


def osv_fetch(ecosystem: str, vid: str) -> dict | None:
    try:
        return get_json(f"{OSV_BUCKET}/{urllib.parse.quote(ecosystem)}/{urllib.parse.quote(vid)}.json")
    except Exception as e:  # noqa: BLE001 - one bad record must not stop the run
        log(f"  osv {ecosystem}/{vid}: {e}")
        return None


# Who wrote an OSV record, from its ID prefix; used to say where a severity label came from.
LABEL_SOURCES = {"GHSA": "GitHub Advisory", "BIT": "Bitnami", "PYSEC": "PyPA", "RUSTSEC": "RustSec", "GO": "Go"}


def record_severity(rec: dict) -> tuple[str, float | None, str | None]:
    """Severity label, CVSS score (if computable) and where the label came from."""
    score = None
    for s in rec.get("severity") or []:
        if s.get("type") in ("CVSS_V3", "CVSS_V3_1") and str(s.get("score", "")).startswith("CVSS:3"):
            score = cvss3_base_score(s["score"])
    label = (rec.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in SEVERITY_RANK:
        return SEVERITY_NAME.get(label.upper(), label.upper()), score, LABEL_SOURCES.get(rec["id"].split("-")[0], "OSV")
    if score is not None:
        return score_to_severity(score), score, "CVSS v3 vector"
    if rec["id"].startswith("MAL-"):
        return "CRITICAL", None, "malicious package"
    return "UNKNOWN", None, None


def fixed_versions(rec: dict, ecosystem: str, patterns: list[str]) -> list[str]:
    out: list[str] = []
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or not name_matches(ecosystem, pkg.get("name", ""), patterns):
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                v = ev.get("fixed")
                if v and v not in out and rng.get("type") != "GIT":
                    out.append(v)
    return out


def norm_name(ecosystem: str, s: str) -> str:
    if ecosystem == "PyPI":
        return s.lower().replace("_", "-").replace(".", "-")  # PEP 503
    if ecosystem == "NuGet":
        return s.lower()  # NuGet IDs are case-insensitive
    return s


def patterns_of(pkg: dict) -> list[str]:
    """OSV names that count as this tile: its own name plus `match` entries.

    An entry ending in "*" is a prefix, e.g. "Microsoft.AspNetCore.*" for the
    per-platform runtime packages ASP.NET Core advisories are filed under.
    """
    return [pkg["name"], *pkg.get("match", [])]


def name_matches(ecosystem: str, name: str, patterns: list[str]) -> bool:
    n = norm_name(ecosystem, name)
    for p in patterns:
        if p.endswith("*"):
            if n.startswith(norm_name(ecosystem, p[:-1])):
                return True
        elif n == norm_name(ecosystem, p):
            return True
    return False


def collect_osv(stacks: list[dict], now: datetime,
                extra: dict[tuple[str, str], list[dict]] | None = None) -> dict[tuple[str, str], list[dict]]:
    """Return {(ecosystem, package): [merged vulnerability, ...]} for the window.

    `extra` adds older records that must be shown anyway (see kev_backfill)."""
    since = now - timedelta(days=WINDOW_DAYS)
    wanted = {(e["osv"], p["name"]) for e in stacks for p in e["packages"]}
    found: dict[tuple[str, str], list[dict]] = {k: [] for k in wanted}

    for eco in stacks:
        osv_eco = eco["osv"]
        patterns = {p["name"]: patterns_of(p) for p in eco["packages"]}
        ids = osv_recent_ids(osv_eco, since)
        log(f"osv {osv_eco}: {len(ids)} records modified in the last {WINDOW_DAYS} days")
        with ThreadPoolExecutor(max_workers=16) as pool:
            records = [r for r in pool.map(lambda i: osv_fetch(osv_eco, i), ids) if r]
        for rec in records:
            if rec.get("withdrawn") or not rec.get("published"):
                continue
            if parse_time(rec["published"]) < since:
                continue
            hit = set()
            for aff in rec.get("affected") or []:
                pkg = aff.get("package") or {}
                if pkg.get("ecosystem") != osv_eco:
                    continue
                for n, pats in patterns.items():
                    if name_matches(osv_eco, pkg.get("name", ""), pats):
                        hit.add(n)
            for n in hit:
                found[(osv_eco, n)].append(rec)

    for k, recs in (extra or {}).items():
        have = {r["id"] for r in found[k]}
        found[k] += [r for r in recs if r["id"] not in have]

    pats = {(e["osv"], p["name"]): patterns_of(p) for e in stacks for p in e["packages"]}
    return {k: merge_aliases(k[0], pats[k], recs) for k, recs in found.items()}


def osv_package_records(ecosystem: str, name: str) -> list[dict]:
    """Every OSV record for one package, through the OSV query API (paginated)."""
    out, token = [], None
    while True:
        body = {"package": {"name": name, "ecosystem": ecosystem}}
        if token:
            body["page_token"] = token
        data = post_json(OSV_QUERY, body)
        out += data.get("vulns") or []
        token = data.get("next_page_token")
        if not token:
            return out


def kev_backfill(stacks: list[dict], kev: dict[str, dict], now: datetime) -> tuple[dict, int, list[str]]:
    """Older advisories of tracked packages whose CVE was added to CISA KEV
    within the window. The modified-records export only covers advisories
    published in the window, so these are looked up per package instead.

    Returns ({(ecosystem, package): [record, ...]}, records added, errors).
    Prefix patterns (e.g. "symfony/*") are not queried; exact names are."""
    since = now - timedelta(days=WINDOW_DAYS)
    recent = {c for c, v in kev.items() if v.get("dateAdded", "") >= since.date().isoformat()}
    if not recent:
        return {}, 0, []
    jobs = [((e["osv"], p["name"]), e["osv"], n)
            for e in stacks for p in e["packages"]
            for n in patterns_of(p) if not n.endswith("*")]
    errors: list[str] = []

    def run(job):
        key, eco, name = job
        try:
            return key, osv_package_records(eco, name)
        except Exception as e:  # noqa: BLE001 - one package must not stop the run
            errors.append(f"{eco}/{name}: {e}")
            return key, []

    extra: dict[tuple[str, str], list[dict]] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for key, recs in pool.map(run, jobs):
            for rec in recs:
                if rec.get("withdrawn") or not rec.get("published"):
                    continue
                if parse_time(rec["published"]) >= since:
                    continue  # already in the window export
                if {rec["id"], *rec.get("aliases", [])} & recent:
                    extra.setdefault(key, []).append(rec)
    added = sum(len(v) for v in extra.values())
    log(f"kev backfill: {len(recent)} CVEs added to KEV in {WINDOW_DAYS} days, "
        f"{added} older advisories of tracked packages, {len(errors)} lookup errors")
    return extra, added, errors


def merge_aliases(ecosystem: str, patterns: list[str], recs: list[dict]) -> list[dict]:
    """One entry per vulnerability: GO-/PYSEC-/GHSA- records of the same issue are merged."""
    groups: list[dict] = []
    for rec in recs:
        keys = {rec["id"], *rec.get("aliases", [])}
        merged = [g for g in groups if g["keys"] & keys]
        for g in merged:
            groups.remove(g)
            keys |= g["keys"]
        groups.append({"keys": keys, "recs": [r for g in merged for r in g["recs"]] + [rec]})

    out = []
    for g in groups:
        recs_g = sorted(g["recs"], key=lambda r: (not r["id"].startswith("GHSA-"), r["id"]))
        primary = recs_g[0]
        sev, score, sev_src = "UNKNOWN", None, None
        for r in recs_g:
            s, sc, src = record_severity(r)
            if SEVERITY_RANK[s] > SEVERITY_RANK[sev]:
                sev, sev_src = s, src
            if sc is not None and (score is None or sc > score):
                score = sc
        fixed: list[str] = []
        for r in recs_g:
            for v in fixed_versions(r, ecosystem, patterns):
                if v not in fixed:
                    fixed.append(v)
        published = min(parse_time(r["published"]) for r in recs_g)
        out.append({
            "id": primary["id"],
            "aliases": sorted(k for k in g["keys"] if k != primary["id"]),
            "cves": sorted(k for k in g["keys"] if k.startswith("CVE-")),
            "published": published.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": (primary.get("summary") or primary.get("details") or "").strip().split("\n")[0][:300],
            "severity": sev,
            "severity_source": sev_src,
            "cvss": score,
            "cvss_source": "advisory" if score is not None else None,
            "fixed": fixed,
            "url": f"https://osv.dev/vulnerability/{primary['id']}",
            "malicious": primary["id"].startswith("MAL-"),
        })
    out.sort(key=lambda v: v["published"], reverse=True)
    return out


# ---------------------------------------------------------------- KEV / EPSS

def collect_kev() -> tuple[dict[str, dict] | None, str | None]:
    for url in KEV_URLS:
        try:
            data = get_json(url, timeout=60)
            kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
            log(f"kev: {len(kev)} entries from {url}")
            return kev, url
        except Exception as e:  # noqa: BLE001
            log(f"kev {url}: {e}")
    return None, None


def collect_epss(cves: set[str]) -> tuple[dict[str, tuple[float, float]] | None, str | None, str | None]:
    for url in EPSS_URLS:
        try:
            raw = gzip.decompress(http_get(url, timeout=120)).decode()
        except Exception as e:  # noqa: BLE001
            log(f"epss {url}: {e}")
            continue
        lines = raw.splitlines()
        score_date = None
        if lines and lines[0].startswith("#"):
            # "#model_version:v2025.03.14,score_date:2026-10-24T00:00:00+0000"
            for part in lines[0].lstrip("#").split(","):
                if part.startswith("score_date:"):
                    score_date = part.split(":", 1)[1][:10]
            lines = lines[1:]
        out = {}
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            if row["cve"] in cves:
                out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
        log(f"epss: {len(out)} of {len(cves)} CVEs scored ({url})")
        return out, url, score_date
    return None, None, None


# ---------------------------------------------------------------- NVD counts

def nvd_count(start: datetime, end: datetime) -> int:
    q = urllib.parse.urlencode({
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.999Z"),
        "resultsPerPage": 1,
        "noRejected": "",
    }).replace("noRejected=", "noRejected")
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    data = get_json(f"{NVD_URL}?{q}", headers=headers, timeout=60, retries=5)
    # Public limit is 5 requests / 30 s without a key, 50 with one.
    time.sleep(0.7 if headers else 6.5)
    return int(data["totalResults"])


def month_bounds(y: int, m: int) -> tuple[datetime, datetime]:
    start = datetime(y, m, 1, tzinfo=timezone.utc)
    nxt = datetime(y + (m == 12), m % 12 + 1, 1, tzinfo=timezone.utc)
    return start, nxt - timedelta(seconds=1)


def collect_nvd(now: datetime, previous: dict | None) -> dict | None:
    """Monthly counts for the last NVD_MONTHS months plus today's count.

    Months older than the previous month are reused from the last run, so a
    normal daily run only makes three NVD requests.
    """
    cached = {}
    if previous:
        for row in previous.get("monthly") or []:
            if row.get("count") is not None:
                cached[row["month"]] = row["count"]
    months = []
    y, m = now.year, now.month
    for _ in range(NVD_MONTHS):
        months.append((y, m))
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    months.reverse()
    recent = {months[-1], months[-2]}
    try:
        rows = []
        for y, m in months:
            key = f"{y:04d}-{m:02d}"
            if key in cached and (y, m) not in recent:
                rows.append({"month": key, "count": cached[key]})
                continue
            start, end = month_bounds(y, m)
            rows.append({"month": key, "count": nvd_count(start, min(end, now))})
            log(f"nvd {key}: {rows[-1]['count']}")
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today = nvd_count(today_start, now)
        log(f"nvd today: {today}")
        return {"monthly": rows, "today": today}
    except Exception as e:  # noqa: BLE001
        log(f"nvd: {e}")
        return None


def nvd_fill_cvss(osv: dict, now: datetime, limit: int = 80) -> int:
    """Look up NVD CVSS for advisories without a score.

    Unrated advisories (e.g. Go stdlib) also take NVD's severity; rated ones keep
    their own label and only gain the number. Answers are cached in
    data/nvd_cvss.json so each CVE is fetched once after NVD scores it, and
    unscored CVEs are asked again at most once a day.
    """
    cache_path = DATA / "nvd_cvss.json"
    try:
        cache = json.loads(cache_path.read_text())
    except (OSError, ValueError):
        cache = {}
    today = now.strftime("%Y-%m-%d")
    todo: dict[str, list[dict]] = {}
    for vulns in osv.values():
        for v in vulns:
            if v["cvss"] is None and v["cves"]:
                todo.setdefault(v["cves"][0], []).append(v)
    # Unrated advisories first: for them NVD decides the color, not just the number.
    order = sorted(todo, key=lambda c: (all(v["severity"] != "UNKNOWN" for v in todo[c]), c))
    ask = [c for c in order if c not in cache or (cache[c]["cvss"] is None and cache[c]["checked"] < today)]
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    asked = 0
    for cve in ask[:limit]:
        try:
            data = get_json(f"{NVD_URL}?cveId={cve}", headers=headers, timeout=60, retries=3)
        except Exception as e:  # noqa: BLE001
            log(f"nvd {cve}: {e}")
            break
        finally:
            time.sleep(0.7 if headers else 6.5)
        asked += 1
        items = data.get("vulnerabilities") or []
        metrics = items[0]["cve"].get("metrics", {}) if items else {}
        entry = {"cvss": None, "severity": None, "checked": today}
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            if metrics.get(key):
                cvss = metrics[key][0]["cvssData"]
                entry.update(cvss=cvss["baseScore"], severity=cvss["baseSeverity"].upper())
                break
        cache[cve] = entry
    filled = 0
    for cve, vulns in todo.items():
        entry = cache.get(cve)
        if not entry or entry["cvss"] is None:
            continue
        filled += 1
        for v in vulns:
            v["cvss"], v["cvss_source"] = entry["cvss"], "NVD"
            if v["severity"] == "UNKNOWN" and entry["severity"] in SEVERITY_RANK:
                v["severity"], v["severity_source"] = entry["severity"], "NVD"
    # Keep only CVEs still on the page so the file does not grow forever.
    cache_path.write_text(json.dumps({c: cache[c] for c in sorted(todo) if c in cache}, indent=1) + "\n")
    log(f"nvd cvss: asked {asked}, scored {filled} of {len(todo)} advisories without CVSS")
    return filled


# ---------------------------------------------------------------- popularity

def popularity(eco: dict, pkg: dict) -> tuple[float, str]:
    """Tile size. Each ecosystem uses one metric, so tiles compare only within a group."""
    kind = eco.get("popularity", "fixed")
    name = pkg.get("downloads_name", pkg["name"])
    q = urllib.parse.quote
    try:
        if kind == "npm":
            d = get_json(f"https://api.npmjs.org/downloads/point/last-week/{name}", timeout=30, retries=2)
            return float(d["downloads"]), "npm downloads, last week"
        if kind == "pypistats":
            d = get_json(f"https://pypistats.org/api/packages/{name.lower()}/recent", timeout=30, retries=2)
            time.sleep(1)  # pypistats asks clients to keep request rates low
            return float(d["data"]["last_week"]), "PyPI downloads, last week (pypistats)"
        if kind == "crates":
            d = get_json(f"https://crates.io/api/v1/crates/{q(name)}", timeout=30, retries=2)
            time.sleep(1)  # crates.io crawler policy: at most 1 request per second
            return float(d["crate"]["recent_downloads"]), "crates.io downloads, last 90 days"
        if kind == "packagist":
            d = get_json(f"https://packagist.org/packages/{name}.json", timeout=30, retries=2)
            return float(d["package"]["downloads"]["monthly"]), "Packagist downloads, last 30 days"
        if kind == "rubygems":
            d = get_json(f"https://rubygems.org/api/v1/gems/{q(name)}.json", timeout=30, retries=2)
            return float(d["downloads"]), "RubyGems downloads, all time"
        if kind == "hex":
            d = get_json(f"https://hex.pm/api/packages/{q(name)}", timeout=30, retries=2)
            return float(d["downloads"]["week"]), "Hex downloads, last week"
    except Exception as e:  # noqa: BLE001
        log(f"popularity {eco['id']}/{name}: {e}")
    return float(pkg.get("weight", 1)), "fixed weight"


# ---------------------------------------------------------------- today.md

LEVEL_WORD = {4: "critical", 3: "high", 2: "medium", 1: "low or unrated", 0: "none"}


def today_markdown(out: dict, days: int = 7) -> str:
    """The day's forecast as plain Markdown, for readers that do not run JavaScript
    (search engines, AI assistants, feed readers)."""
    gen = parse_time(out["generated_at"])
    since = gen - timedelta(days=days)
    s = out["summary"]
    rows = []
    for e in out["ecosystems"]:
        hits = []
        for p in e["packages"]:
            recent = [v for v in p["vulns"] if effective_date(v) >= since]
            if not recent:
                continue
            kev = [v for v in recent if v.get("kev")]
            rank = max(SEVERITY_RANK[v["severity"]] for v in recent)
            fixed = []
            for v in recent:
                fixed += [f for f in v["fixed"] if f not in fixed]
            top = sorted(recent, key=lambda v: (bool(v.get("kev")), SEVERITY_RANK[v["severity"]]), reverse=True)[0]
            hits.append((bool(kev), rank, len(recent), p, fixed, top))
        hits.sort(key=lambda h: (h[0], h[1], h[2]), reverse=True)
        rows.append((e, hits))
    rows.sort(key=lambda r: max(((h[0], h[1]) for h in r[1]), default=(False, -1)), reverse=True)

    lines = [
        f"# depweather forecast, {gen:%Y-%m-%d}",
        "",
        f"Vulnerabilities published in the last {days} days for {s['tracked_packages']} popular "
        f"open-source packages, generated {out['generated_at']} by https://depweather.com "
        "from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.",
        "",
        "## Numbers",
        "",
        f"- Popular packages with a new advisory this week: {s['affected_packages_7d']} of {s['tracked_packages']}",
    ]
    if s.get("kev_new_7d") is not None:
        lines.append(f"- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): {s['kev_new_7d']}")
    if s.get("today_cves") is not None:
        lines.append(f"- New CVEs in NVD today (UTC): {s['today_cves']}")
    if s.get("month_cves") is not None:
        lines.append(f"- CVEs published in {s['month']} so far: {s['month_cves']:,}"
                     + (f" (same month last year: {s['month_cves_last_year']:,})" if s.get("month_cves_last_year") else ""))
    lines += ["", "## By ecosystem", ""]
    for e, hits in rows:
        if not hits:
            lines.append(f"### {e['label']}\n\nNo new advisories for the tracked packages.\n")
            continue
        lines.append(f"### {e['label']}\n")
        for kev, rank, n, p, fixed, top in hits:
            name = p["label"] if p["label"].lower() == p["name"].lower() else f"{p['label']} ({p['name']})"
            worst = "actively exploited (CISA KEV)" if kev else LEVEL_WORD[rank]
            line = f"- **{name}**: {n} advisor{'y' if n == 1 else 'ies'}, worst {worst}"
            if fixed:
                line += f"; fixed in {', '.join(fixed[:4])}{' and more' if len(fixed) > 4 else ''}"
            line += f". Example: [{top['id']}]({top['url']})" + (f" {top['summary']}" if top["summary"] else "")
            lines.append(line)
        lines.append("")
    if out.get("kev_recent"):
        lines += ["## Added to CISA KEV this week (all vendors)", ""]
        lines += [f"- {k['date_added']}: {k['cve']}, {k['vendor']} {k['product']}: {k['name']}" for k in out["kev_recent"]]
        lines.append("")
    lines.append("Full data: https://depweather.com/data/latest.json")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- main

def worst(vulns: list[dict]) -> str:
    best = "NONE"
    for v in vulns:
        if SEVERITY_RANK[v["severity"]] > SEVERITY_RANK[best]:
            best = v["severity"]
    return best


def main() -> int:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    config = yaml.safe_load(STACKS.read_text())
    stacks = config["ecosystems"]
    latest_path = DATA / "latest.json"
    previous = json.loads(latest_path.read_text()) if latest_path.exists() else None
    sources: dict[str, dict] = {}

    kev, kev_url = collect_kev()
    sources["kev"] = {"ok": kev is not None, "url": kev_url}

    extra, backfilled, errors = kev_backfill(stacks, kev, now) if kev else ({}, 0, [])
    sources["kev_backfill"] = {"ok": not errors, "url": OSV_QUERY, "added": backfilled,
                               "errors": errors[:5]}

    try:
        osv = collect_osv(stacks, now, extra)
        sources["osv"] = {"ok": True, "url": OSV_BUCKET}
    except Exception as e:  # noqa: BLE001
        # Without OSV there is nothing to draw; keep the last good file.
        log(f"osv failed: {e}")
        return 1

    all_cves = {c for vulns in osv.values() for v in vulns for c in v["cves"]}
    epss, epss_url, epss_date = collect_epss(all_cves)
    sources["epss"] = {"ok": epss is not None, "url": epss_url, "score_date": epss_date}

    nvd = collect_nvd(now, previous)
    sources["nvd"] = {"ok": nvd is not None, "url": NVD_URL}
    if nvd is not None:
        nvd_fill_cvss(osv, now)

    ecosystems = []
    week_ago = now - timedelta(days=7)
    pop_sources = set()
    for eco in stacks:
        pkgs = []
        for p in eco["packages"]:
            vulns = osv[(eco["osv"], p["name"])]
            for v in vulns:
                k = [kev[c] for c in v["cves"] if kev and c in kev]
                v["kev"] = bool(k) if kev is not None else None
                v["kev_date_added"] = min(x["dateAdded"] for x in k) if k else None
                scores = [epss[c] for c in v["cves"] if epss and c in epss]
                v["epss"] = max(s[0] for s in scores) if scores else None
                v["epss_percentile"] = max(s[1] for s in scores) if scores else None
            pop, pop_src = popularity(eco, p)
            pop_sources.add(f"{eco['label']}: {pop_src}")
            recent = [v for v in vulns if effective_date(v) >= week_ago]
            pkgs.append({
                "key": f"{eco['id']}/{p['name']}",
                "name": p["name"],
                "label": p.get("label", p["name"]),
                "popularity": pop,
                "popularity_source": pop_src,
                "survey": p.get("survey"),
                "worst_7d": worst(recent),
                "worst_30d": worst(vulns),
                "vulns": vulns,
            })
        ecosystems.append({
            "id": eco["id"], "label": eco["label"], "osv": eco["osv"],
            "languages": eco.get("languages"), "survey_share": eco.get("survey_share"), "area": eco.get("area"),
            "packages": pkgs,
        })
    sources["popularity"] = {"ok": True, "detail": sorted(pop_sources)}

    kev_new = None
    kev_recent = []
    if kev is not None:
        cutoff = (now - timedelta(days=7)).date().isoformat()
        kev_recent = sorted(
            ({"cve": c, "vendor": v.get("vendorProject"), "product": v.get("product"),
              "name": v.get("vulnerabilityName"), "date_added": v["dateAdded"]}
             for c, v in kev.items() if v["dateAdded"] >= cutoff),
            key=lambda x: x["date_added"], reverse=True)
        kev_new = len(kev_recent)

    monthly = nvd["monthly"] if nvd else (previous or {}).get("monthly", [])
    this_month = f"{now.year:04d}-{now.month:02d}"
    last_year = f"{now.year - 1:04d}-{now.month:02d}"
    by_month = {r["month"]: r["count"] for r in monthly}
    affected = [p["key"] for e in ecosystems for p in e["packages"] if p["worst_7d"] != "NONE"]

    out = {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": WINDOW_DAYS,
        "survey": config.get("survey"),
        "sources": sources,
        "summary": {
            "today_cves": nvd["today"] if nvd else None,
            "month": this_month,
            "month_cves": by_month.get(this_month) if nvd else None,
            "month_cves_last_year": by_month.get(last_year) if nvd else None,
            "kev_new_7d": kev_new,
            "affected_packages_7d": len(affected),
            "tracked_packages": sum(len(e["packages"]) for e in ecosystems),
        },
        "monthly": monthly,
        "monthly_is_stale": nvd is None and bool(monthly),
        "kev_recent": kev_recent,
        "ecosystems": ecosystems,
    }

    DATA.mkdir(exist_ok=True)
    (DATA / "history").mkdir(exist_ok=True)
    text = json.dumps(out, ensure_ascii=False, indent=1)
    latest_path.write_text(text + "\n")
    (DATA / "history" / f"{now.date().isoformat()}.json").write_text(text + "\n")
    (DATA / "today.md").write_text(today_markdown(out))
    log(f"wrote {latest_path} ({len(text) // 1024} KiB), affected packages (7d): {len(affected)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
