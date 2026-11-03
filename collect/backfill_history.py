#!/usr/bin/env python3
"""Fill data/history from OSV's per-ecosystem zip dumps. One-off, not for CI.

Request budget for a full run (about 150 tracked packages, 10 ecosystems):

  * 1 CISA KEV JSON download (the GitHub mirror only if the first URL fails)
  * 10 OSV ``all.zip`` downloads, one ecosystem at a time, from
    ``osv-vulnerabilities.storage.googleapis.com``
  * no per-package calls, no per-advisory calls, no OSV query API, no NVD

The ten zips are about 315 MB (npm is about 210 MB of that). They are fetched
one after another, with a pause between network calls, a descriptive
User-Agent, and backoff that honors ``Retry-After`` on 429 and 503. Files land
in ``.cache/osv/`` (gitignored). A second run with a warm cache makes no HTTP
requests. Severity comes from the advisory (GitHub Advisory label or a CVSS v3
vector). NVD is not asked.

The window is the same 1Y chart window: the month of the day 365 days before
``--as-of``, through that date. Days already stored outside the window are
kept. Days inside it are replaced, so re-running is safe. The daily collector
then rewrites the last 30 days, which is where an NVD severity fill can still
change a count.

    python collect/backfill_history.py
    python collect/backfill_history.py --months 12 --sleep 2
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import collect
import history
import yaml

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache" / "osv"
USER_AGENT = "depweather-backfill (+https://github.com/surinkim/depweather)"
MAX_MEMBER = 8_000_000


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _retry_delay(exc: Exception, attempt: int) -> float:
    if isinstance(exc, urllib.error.HTTPError) and exc.code in (429, 503):
        header = exc.headers.get("Retry-After") if exc.headers else None
        if header:
            try:
                return max(1.0, float(header))
            except ValueError:
                try:
                    when = parsedate_to_datetime(header)
                    if when.tzinfo is None:
                        when = when.replace(tzinfo=timezone.utc)
                    return max(1.0, (when - datetime.now(timezone.utc)).total_seconds())
                except (TypeError, ValueError, OverflowError):
                    pass
    return min(60.0, 2 ** attempt * 2)


def download(url: str, dest: Path, timeout: int = 300, retries: int = 4) -> bool:
    """Save ``url`` to ``dest``. Return True when a request was made.

    A non-empty destination is a cache hit and does not touch the network.
    """
    if dest.is_file() and dest.stat().st_size > 0:
        log(f"cache {dest} ({dest.stat().st_size} bytes)")
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as response, tmp.open("wb") as out:
                while True:
                    chunk = response.read(256 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
            if tmp.stat().st_size <= 0:
                raise OSError(f"empty response from {url}")
            tmp.replace(dest)
            log(f"saved {dest} ({dest.stat().st_size} bytes)")
            return True
        except urllib.error.HTTPError as exc:
            last = exc
            tmp.unlink(missing_ok=True)
            if exc.code == 404:
                raise
            delay = _retry_delay(exc, attempt + 1)
            log(f"{url}: HTTP {exc.code}, sleeping {delay:.0f}s")
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            last = exc
            tmp.unlink(missing_ok=True)
            delay = _retry_delay(exc, attempt + 1)
            log(f"{url}: {exc}, sleeping {delay:.0f}s")
            time.sleep(delay)
    assert last is not None
    raise last


def fetch_kev(cache: Path) -> tuple[dict[str, dict], int]:
    dest = cache / "kev.json"
    requests = 0
    last: Exception | None = None
    for url in collect.KEV_URLS:
        try:
            if download(url, dest):
                requests += 1
            doc = json.loads(dest.read_text(encoding="utf-8"))
            rows = doc.get("vulnerabilities") or []
            kev = {row["cveID"]: row for row in rows if row.get("cveID")}
            log(f"kev: {len(kev)} entries")
            return kev, requests
        except Exception as exc:  # noqa: BLE001 - try the mirror
            last = exc
            dest.unlink(missing_ok=True)
            log(f"kev {url}: {exc}")
    raise SystemExit(f"KEV catalog unavailable: {last}")


def slim(rec: dict) -> dict:
    db = rec.get("database_specific") if isinstance(rec.get("database_specific"), dict) else {}
    label = db.get("severity") if isinstance(db.get("severity"), str) else None
    severity = []
    for item in rec.get("severity") or []:
        if isinstance(item, dict) and item.get("type") in ("CVSS_V3", "CVSS_V3_1"):
            severity.append({"type": item.get("type"), "score": item.get("score")})
    return {
        "id": rec["id"],
        "aliases": [a for a in rec.get("aliases") or [] if isinstance(a, str)],
        "published": rec.get("published"),
        "severity": severity,
        "database_specific": {"severity": label} if label else {},
        "affected": [],
    }


def iter_zip_records(path: Path):
    with zipfile.ZipFile(path) as bundle:
        for info in bundle.infolist():
            name = info.filename
            if info.is_dir() or not name.endswith(".json"):
                continue
            if info.file_size > MAX_MEMBER:
                log(f"skip {name}: {info.file_size} bytes")
                continue
            with bundle.open(info) as handle:
                try:
                    yield json.load(handle)
                except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                    continue


def match_records(records, eco: dict) -> dict[str, list[dict]]:
    """Keep slim OSV records that name a tracked package. No merging yet."""
    osv_eco = eco["osv"]
    patterns = {pkg["name"]: collect.patterns_of(pkg) for pkg in eco["packages"]}
    found = {pkg["name"]: [] for pkg in eco["packages"]}
    seen = {pkg["name"]: set() for pkg in eco["packages"]}
    scanned = 0
    for rec in records:
        scanned += 1
        if not isinstance(rec, dict) or rec.get("withdrawn") or not rec.get("published") or not rec.get("id"):
            continue
        hits = []
        for affected in rec.get("affected") or []:
            pkg = (affected or {}).get("package") or {}
            if pkg.get("ecosystem") != osv_eco:
                continue
            name = pkg.get("name") or ""
            for tracked, pats in patterns.items():
                if collect.name_matches(osv_eco, name, pats):
                    hits.append(tracked)
        if not hits:
            continue
        small = slim(rec)
        for tracked in set(hits):
            if small["id"] in seen[tracked]:
                continue
            seen[tracked].add(small["id"])
            found[tracked].append(small)
        if scanned % 20000 == 0:
            log(f"  scanned {scanned} records")
    kept = sum(len(v) for v in found.values())
    log(f"  {eco['osv']}: scanned {scanned}, kept {kept} package rows")
    return found


def vulns_for_package(osv_eco: str, patterns: list[str], records: list[dict], kev: dict[str, dict]) -> list[dict]:
    merged = collect.merge_aliases(osv_eco, patterns, records)
    for vuln in merged:
        hits = [kev[cve] for cve in vuln["cves"] if cve in kev]
        vuln["kev"] = bool(hits)
        vuln["kev_date_added"] = min(row["dateAdded"] for row in hits) if hits else None
    return merged


def ecosystem_from_records(eco: dict, records, kev: dict[str, dict]) -> dict:
    matched = match_records(records, eco)
    packages = []
    for pkg in eco["packages"]:
        patterns = collect.patterns_of(pkg)
        vulns = vulns_for_package(eco["osv"], patterns, matched[pkg["name"]], kev)
        packages.append({"key": f"{eco['id']}/{pkg['name']}", "vulns": vulns})
    return {"id": eco["id"], "packages": packages}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Backfill data/history from OSV ecosystem dumps")
    parser.add_argument("--months", type=int, default=0,
                        help="calendar months including the current one; 0 uses the 1Y chart window")
    parser.add_argument("--as-of", default=None, help="UTC end date YYYY-MM-DD (default: today)")
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--history", type=Path, default=ROOT / "data" / "history")
    parser.add_argument("--stacks", type=Path, default=collect.STACKS)
    parser.add_argument("--sleep", type=float, default=2.0, help="seconds between network calls")
    parser.add_argument("--refresh", action="store_true", help="redownload cached files")
    args = parser.parse_args(argv)
    if args.as_of:
        as_of = date.fromisoformat(args.as_of)
    else:
        as_of = datetime.now(timezone.utc).date()
    start = history.months_start(as_of, args.months) if args.months else history.period_start(as_of, "1y")
    log(f"window {start.isoformat()} .. {as_of.isoformat()}")

    config = yaml.safe_load(args.stacks.read_text(encoding="utf-8"))
    stacks = config["ecosystems"]
    cache = args.cache
    if args.refresh:
        kev_path = cache / "kev.json"
        kev_path.unlink(missing_ok=True)
    requests = 0
    kev, kev_requests = fetch_kev(cache)
    requests += kev_requests

    built = []
    for eco in stacks:
        url = f"{collect.OSV_BUCKET}/{urllib.parse.quote(eco['osv'])}/all.zip"
        dest = cache / eco["osv"] / "all.zip"
        if args.refresh and dest.is_file():
            dest.unlink()
        needs_network = not (dest.is_file() and dest.stat().st_size > 0)
        if needs_network and requests > 0 and args.sleep > 0:
            time.sleep(args.sleep)
        made = download(url, dest, timeout=300)
        if made:
            requests += 1
        log(f"reading {eco['osv']}")
        built.append(ecosystem_from_records(eco, iter_zip_records(dest), kev))

    days = history.aggregate_snapshot(built, start, as_of)
    history.remove_legacy_snapshots(args.history)
    history.apply_days(args.history, days, start, as_of)
    packages = sum(len(eco["packages"]) for eco in built)
    log(
        f"wrote {len(days)} days for {packages} packages, {requests} HTTP request(s). "
        "No per-advisory calls and no NVD calls. A warm cache makes the next run free."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
