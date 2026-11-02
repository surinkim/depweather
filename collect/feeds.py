#!/usr/bin/env python3
"""Write Atom feeds from data/latest.json.

Site feed:  <out>/feed.xml
Per package: <out>/feed/<ecosystem>/<name>.xml

Item ids are tag URIs of the package key and the advisory id. They do not
include the snapshot time, so regenerating the feed does not look like a new
item to a reader. An item stays for RETENTION_DAYS after it was published, or
after it was added to CISA KEV if that is later.

Maven coordinates use ':' in the package key. The filename writes that as
'~', and a real '~' in a name is written as '~~', so the path round-trips
and does not contain a colon.

Only the standard library is used, so the Pages workflow can run this
without installing anything.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
SITE = "https://depweather.com"
# Year the tag authority was introduced. Do not change it: readers key off it.
TAG_YEAR = "2026"
RETENTION_DAYS = 14
SITE_FEED_CAP = 200
ATOM = "http://www.w3.org/2005/Atom"
XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"

SEVERITY_RANK = {"NONE": 0, "UNKNOWN": 1, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

ET.register_namespace("", ATOM)


def parse_time(s: str) -> datetime:
    """Same parsing as collect.py: OSV timestamps can carry nanoseconds."""
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


def effective_date(v: dict) -> datetime:
    published = parse_time(v["published"])
    if v.get("kev_date_added"):
        added = datetime.fromisoformat(v["kev_date_added"]).replace(tzinfo=timezone.utc)
        return max(published, added)
    return published


def iso_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def encode_segment(seg: str) -> str:
    return seg.replace("~", "~~").replace(":", "~")


def decode_segment(seg: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(seg):
        if seg.startswith("~~", i):
            out.append("~")
            i += 2
        elif seg[i] == "~":
            out.append(":")
            i += 1
        else:
            out.append(seg[i])
            i += 1
    return "".join(out)


def feed_relpath(key: str) -> str:
    """Path under the site root, posix, no leading slash."""
    if not key or key.startswith("/") or any(p in ("", ".", "..") for p in key.split("/")):
        raise ValueError(f"bad package key: {key!r}")
    eco, _, name = key.partition("/")
    if not eco or not name:
        raise ValueError(f"bad package key: {key!r}")
    parts = [encode_segment(eco), *[encode_segment(p) for p in name.split("/")]]
    return "feed/" + "/".join(parts) + ".xml"


def feed_url(key: str) -> str:
    return f"{SITE}/{feed_relpath(key)}"


def package_page_rel(key: str) -> str:
    """Site path with a trailing slash and no leading slash: pkg/npm/next/."""
    rel = feed_relpath(key)
    if not rel.startswith("feed/") or not rel.endswith(".xml"):
        raise ValueError(f"bad package key: {key!r}")
    return "pkg/" + rel[len("feed/"):-len(".xml")] + "/"


def package_page_url(key: str) -> str:
    return f"{SITE}/{package_page_rel(key)}"


def badge_relpath(key: str, lang: str = "en") -> str:
    """Site path with no leading slash: badge/npm/next.svg or badge/npm/next.ko.svg."""
    if lang not in ("en", "ko"):
        raise ValueError(f"bad badge language: {lang!r}")
    page = package_page_rel(key)
    stem = "badge/" + page[len("pkg/"):-1]
    if lang == "ko":
        return stem + ".ko.svg"
    return stem + ".svg"


def badge_url(key: str, lang: str = "en") -> str:
    return f"{SITE}/{badge_relpath(key, lang)}"


def entry_id(pkg_key: str, advisory_id: str) -> str:
    return f"tag:depweather.com,{TAG_YEAR}:advisory:{pkg_key}/{advisory_id}"


def _esc(s: object) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def entry_title(label: str, vuln: dict) -> str:
    bits: list[str] = []
    if vuln.get("kev"):
        bits.append("KEV")
    if vuln.get("malicious"):
        bits.append("Malicious")
    elif str(vuln.get("severity") or "").upper() == "CRITICAL":
        bits.append("Critical")
    prefix = (" · ".join(bits) + " · ") if bits else ""
    text = (vuln.get("summary") or "").strip() or vuln.get("id") or "advisory"
    title = f"{prefix}{label}: {text}"
    if len(title) > 180:
        title = title[:179].rstrip() + "…"
    return title


def entry_html(eco_label: str, pkg: dict, vuln: dict) -> str:
    flags: list[str] = []
    if vuln.get("kev"):
        added = vuln.get("kev_date_added")
        flags.append("<strong>CISA KEV</strong>" + (f" (added {_esc(added)})" if added else ""))
    if vuln.get("malicious"):
        flags.append("<strong>Malicious package</strong>")
    flags.append(f"<strong>{_esc(vuln.get('severity') or 'UNKNOWN')}</strong>")
    parts = [f"<p>{' · '.join(flags)} — {_esc(pkg.get('label') or pkg.get('name'))} ({_esc(eco_label)})</p>"]
    if vuln.get("summary"):
        parts.append(f"<p>{_esc(vuln['summary'])}</p>")
    fixed = [f for f in (vuln.get("fixed") or []) if f]
    if fixed:
        shown = fixed[:6]
        more = " and more" if len(fixed) > len(shown) else ""
        parts.append(f"<p>Fixed in {_esc(', '.join(shown))}{more}</p>")
    links = []
    if vuln.get("url"):
        links.append(f'<a href="{_esc(vuln["url"])}">Advisory</a>')
    page = package_page_url(pkg["key"])
    links.append(f'<a href="{_esc(page)}">Package on depweather</a>')
    links.append(f'<a href="{_esc(feed_url(pkg["key"]))}">Package feed</a>')
    parts.append("<p>" + " · ".join(links) + "</p>")
    return "".join(parts)


def _atom(tag: str) -> str:
    return f"{{{ATOM}}}{tag}"


def build_feed(*, title: str, subtitle: str, self_url: str, alternate_url: str,
               updated: datetime, entries: list[dict]) -> ET.Element:
    feed = ET.Element(_atom("feed"), {XML_LANG: "en"})
    ET.SubElement(feed, _atom("title")).text = title
    ET.SubElement(feed, _atom("subtitle")).text = subtitle
    ET.SubElement(feed, _atom("link"), {"rel": "alternate", "type": "text/html", "href": alternate_url})
    ET.SubElement(feed, _atom("link"), {"rel": "self", "type": "application/atom+xml", "href": self_url})
    ET.SubElement(feed, _atom("id")).text = self_url
    ET.SubElement(feed, _atom("updated")).text = iso_z(updated)
    author = ET.SubElement(feed, _atom("author"))
    ET.SubElement(author, _atom("name")).text = "depweather"
    ET.SubElement(author, _atom("uri")).text = f"{SITE}/"
    gen = ET.SubElement(feed, _atom("generator"), {"uri": "https://github.com/surinkim/depweather"})
    gen.text = "depweather"
    ET.SubElement(feed, _atom("rights")).text = (
        "Advisory text belongs to its upstream database. "
        "The GitHub Advisory Database is CC-BY 4.0. Generated by depweather."
    )
    for e in entries:
        entry = ET.SubElement(feed, _atom("entry"))
        ET.SubElement(entry, _atom("title")).text = e["title"]
        ET.SubElement(entry, _atom("link"), {"rel": "alternate", "type": "text/html", "href": e["href"]})
        ET.SubElement(entry, _atom("id")).text = e["id"]
        ET.SubElement(entry, _atom("published")).text = e["published"]
        ET.SubElement(entry, _atom("updated")).text = e["updated"]
        for term in e["categories"]:
            ET.SubElement(entry, _atom("category"), {"term": term})
        ET.SubElement(entry, _atom("summary")).text = e["summary"]
        content = ET.SubElement(entry, _atom("content"), {"type": "html"})
        content.text = e["html"]
    return feed


def _categories(eco_id: str, vuln: dict) -> list[str]:
    out = [eco_id]
    sev = str(vuln.get("severity") or "UNKNOWN").lower()
    if sev and sev not in out:
        out.append(sev)
    if vuln.get("kev"):
        out.append("kev")
    if vuln.get("malicious"):
        out.append("malicious")
    return out


def _one_entry(eco: dict, pkg: dict, vuln: dict, when: datetime) -> dict:
    summary = (vuln.get("summary") or "").strip() or vuln["id"]
    return {
        "id": entry_id(pkg["key"], vuln["id"]),
        "title": entry_title(pkg.get("label") or pkg.get("name") or pkg["key"], vuln),
        "href": vuln.get("url") or package_page_url(pkg["key"]),
        "published": iso_z(parse_time(vuln["published"])),
        "updated": iso_z(when),
        "categories": _categories(eco.get("id") or "", vuln),
        "summary": summary,
        "html": entry_html(eco.get("label") or eco.get("id") or "", pkg, vuln),
        "when": when,
        "kev": bool(vuln.get("kev")),
        "rank": SEVERITY_RANK.get(str(vuln.get("severity") or "").upper(), 0),
        "pkg_key": pkg["key"],
        "advisory_id": vuln["id"],
    }


def gather(data: dict, days: int = RETENTION_DAYS) -> tuple[datetime, list[dict], dict[str, list[dict]]]:
    generated = parse_time(data["generated_at"])
    cutoff = generated - timedelta(days=days)
    by_pkg: dict[str, list[dict]] = {}
    order: list[str] = []
    site: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for eco in data.get("ecosystems") or []:
        for pkg in eco.get("packages") or []:
            key = pkg.get("key")
            if not key:
                continue
            if key not in by_pkg:
                by_pkg[key] = []
                order.append(key)
            for vuln in pkg.get("vulns") or []:
                if not vuln.get("id") or not vuln.get("published"):
                    continue
                ident = (key, vuln["id"])
                if ident in seen:
                    continue
                try:
                    when = effective_date(vuln)
                except (KeyError, ValueError):
                    continue
                if when < cutoff:
                    continue
                seen.add(ident)
                entry = _one_entry(eco, pkg, vuln, when)
                by_pkg[key].append(entry)
                site.append(entry)

    def sort_key(e: dict):
        return (-e["when"].timestamp(), 0 if e["kev"] else 1, -e["rank"], e["pkg_key"], e["advisory_id"])

    site.sort(key=sort_key)
    for key in by_pkg:
        by_pkg[key].sort(key=sort_key)
    return generated, site, {k: by_pkg[k] for k in order}


def _write(path: Path, feed: ET.Element) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tree = ET.ElementTree(feed)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)


def write_feeds(data: dict, out: Path, days: int = RETENTION_DAYS) -> int:
    """Write feed.xml and one file per tracked package. Returns the file count."""
    generated, site, by_pkg = gather(data, days)
    subtitle = (
        f"Advisories from the last {days} days for popular packages tracked by depweather. "
        "KEV and critical items are marked at the start of the title. "
        "The same advisory keeps the same id across updates, so readers do not see it twice."
    )
    site_entries = site[:SITE_FEED_CAP]
    site_feed = build_feed(
        title="depweather — new advisories",
        subtitle=subtitle,
        self_url=f"{SITE}/feed.xml",
        alternate_url=f"{SITE}/",
        updated=generated,
        entries=site_entries,
    )
    _write(out / "feed.xml", site_feed)
    n = 1
    for key, entries in by_pkg.items():
        label = _label_for(data, key)
        eco_label = _eco_label_for(data, key)
        page = package_page_url(key)
        pkg_sub = (
            f"Advisories for {label} ({eco_label}) from the last {days} days. "
            "KEV and critical items are marked at the start of the title."
        )
        feed = build_feed(
            title=f"depweather — {label}",
            subtitle=pkg_sub,
            self_url=feed_url(key),
            alternate_url=page,
            updated=generated,
            entries=entries,
        )
        _write(out / feed_relpath(key), feed)
        n += 1
    return n


def _label_for(data: dict, key: str) -> str:
    for eco in data.get("ecosystems") or []:
        for pkg in eco.get("packages") or []:
            if pkg.get("key") == key:
                return pkg.get("label") or pkg.get("name") or key
    return key


def _eco_label_for(data: dict, key: str) -> str:
    for eco in data.get("ecosystems") or []:
        for pkg in eco.get("packages") or []:
            if pkg.get("key") == key:
                return eco.get("label") or eco.get("id") or ""
    return ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Write depweather Atom feeds from data/latest.json")
    p.add_argument("--latest", type=Path, default=ROOT / "data" / "latest.json")
    p.add_argument("--out", type=Path, default=ROOT, help="Site root. Writes <out>/feed.xml and <out>/feed/")
    p.add_argument("--days", type=int, default=RETENTION_DAYS)
    args = p.parse_args(argv)
    data = json.loads(args.latest.read_text(encoding="utf-8"))
    n = write_feeds(data, args.out, days=args.days)
    print(f"wrote {n} feed files under {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
