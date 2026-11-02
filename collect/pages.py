#!/usr/bin/env python3
"""Write one static HTML page per tracked package.

    <out>/pkg/<ecosystem>/<name>/index.html

The path uses the same slug as the Atom feed (collect/feeds.py): a Maven
':' is '~', and a real '~' is '~~'. Pages are built in the Pages workflow
from data/latest.json and are not committed, same as feed.xml.

A package page lists advisories from the snapshot. "Current" means the
effective date (published, or added to CISA KEV if that is later) falls in
the last 7 days before generated_at. Everything else in the snapshot is
"recent". Advisory text is escaped. Links are emitted only for https URLs
on the same host allowlist as alert/check.js.

Both languages are in the HTML (English visible, Korean in attributes and
meta). A short script applies ?lang=ko and the light/dark choice stored in
the same localStorage key as the map. Each page includes a README badge
snippet (Markdown and HTML, English and Korean) that points at the SVG
written by collect/badges.py. Pass --out pointing somewhere other than the
repository root to also write sitemap.xml with a URL per package. The
committed sitemap.xml is left as the source of the static entries.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collect"))

import feeds  # noqa: E402

SITE = feeds.SITE
CURRENT_DAYS = 7
# Keep in step with ALLOWED_LINK_HOSTS in alert/check.js.
ALLOWED_LINK_HOSTS = frozenset({
    "depweather.com",
    "www.depweather.com",
    "osv.dev",
    "github.com",
    "www.github.com",
    "nvd.nist.gov",
    "cisa.gov",
    "www.cisa.gov",
})
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SEV_LEVEL = {"NONE": 0, "UNKNOWN": 1, "LOW": 1, "MEDIUM": 1, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}
_URL_BLOCK = re.compile(r"\n[ \t]*<url>\s*.*?</url>", re.S)


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def oneline(value: object) -> str:
    return " ".join(str(value if value is not None else "").split())


def safe_href(value: object) -> str | None:
    """https URL on the allowlist, or None. No userinfo, no control characters."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if any(ord(c) < 32 or c in " \t\\" for c in raw):
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme != "https" or parts.username or parts.password:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if host not in ALLOWED_LINK_HOSTS:
        return None
    port = f":{parts.port}" if parts.port else ""
    if parts.netloc.lower() != host + port:
        return None
    return raw


def fmt_epss(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0 or value > 1:
        return None
    if value < 0.001:
        return "<0.1%"
    return f"{math.floor(value * 1000) / 10:.1f}%"


def _cmp_version(a: str, b: str) -> int:
    pa, pb = re.split(r"[.\-+]", a), re.split(r"[.\-+]", b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else ""
        y = pb[i] if i < len(pb) else ""
        if x.isdigit() and y.isdigit():
            d = int(x) - int(y)
        else:
            d = (x > y) - (x < y)
        if d:
            return d
    return 0


def _sort_fixed(values: list[str]) -> list[str]:
    from functools import cmp_to_key
    return sorted(values, key=cmp_to_key(_cmp_version), reverse=True)


def fixed_list(vulns: list[dict]) -> list[str]:
    seen: list[str] = []
    for v in vulns:
        for f in v.get("fixed") or []:
            if isinstance(f, str) and f and f not in seen:
                seen.append(f)
    return _sort_fixed(seen)


def _when(v: dict) -> datetime | None:
    try:
        return feeds.effective_date(v)
    except (KeyError, TypeError, ValueError):
        return None


def classify(vulns: list, generated: datetime) -> tuple[list[dict], list[dict]]:
    cutoff = generated - timedelta(days=CURRENT_DAYS)
    current: list[dict] = []
    earlier: list[dict] = []
    for v in vulns or []:
        if not isinstance(v, dict) or not v.get("id"):
            continue
        when = _when(v)
        (current if when is not None and when >= cutoff else earlier).append(v)

    def sort_key(v: dict):
        when = _when(v)
        stamp = when.timestamp() if when else 0
        kev = 0 if v.get("kev") is True else 1
        rank = feeds.SEVERITY_RANK.get(str(v.get("severity") or "").upper(), 0)
        return (kev, -rank, -stamp, str(v.get("id")))

    current.sort(key=sort_key)
    earlier.sort(key=sort_key)
    return current, earlier


def _pill_level(v: dict) -> int:
    if v.get("kev") is True:
        return 3
    return SEV_LEVEL.get(str(v.get("severity") or "").upper(), 1)


def _link(href: str | None, text: str) -> str:
    safe = safe_href(href)
    label = esc(text)
    if not safe:
        return label
    return f'<a href="{esc(safe)}" target="_blank" rel="noopener noreferrer">{label}</a>'


def _cve_links(v: dict) -> str:
    links = []
    for cve in v.get("cves") or []:
        if not isinstance(cve, str) or not CVE_RE.match(cve):
            continue
        url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        links.append(_link(url, cve))
    if not links:
        return ""
    return "<br><span class=\"meta\">" + ", ".join(links) + "</span>"


def _fixed_cell(v: dict) -> str:
    shown = [f for f in (v.get("fixed") or []) if isinstance(f, str) and f][:8]
    extra = len([f for f in (v.get("fixed") or []) if isinstance(f, str) and f]) - len(shown)
    if not shown:
        return "–"
    more = f" +{extra}" if extra > 0 else ""
    return esc(", ".join(shown)) + more


def _row(v: dict) -> str:
    published = str(v.get("published") or "")
    day = published[:10] if len(published) >= 10 and published[4:5] == "-" else published
    severity = str(v.get("severity") or "UNKNOWN")
    bits = [f'<span class="pill l{_pill_level(v)}">{esc(severity)}</span>']
    if v.get("malicious") is True:
        bits.append('<span class="pill mal" data-i18n="malicious">Malicious</span>')
    if v.get("kev") is True:
        bits.append('<span class="pill kev">KEV</span>')
    meta = []
    added = v.get("kev_date_added")
    if v.get("kev") is True and isinstance(added, str) and added:
        meta.append("KEV " + esc(added))
    source = v.get("severity_source")
    if isinstance(source, str) and source:
        meta.append(esc(source))
    sev_html = " ".join(bits)
    if meta:
        sev_html += "<br><span class=\"meta\">" + " · ".join(meta) + "</span>"
    cvss = v.get("cvss")
    cvss_html = esc(cvss) if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) else "–"
    epss = fmt_epss(v.get("epss"))
    summary = v.get("summary") if isinstance(v.get("summary"), str) else ""
    return (
        "<tr>"
        f'<td class="nowrap">{esc(day)}</td>'
        f'<td class="nowrap" lang="en">{_link(v.get("url") if isinstance(v.get("url"), str) else None, str(v.get("id")))}{_cve_links(v)}</td>'
        f"<td>{sev_html}</td>"
        f'<td class="num">{cvss_html}</td>'
        f'<td class="num">{esc(epss) if epss else "–"}</td>'
        f"<td>{_fixed_cell(v)}</td>"
        f'<td class="summary" lang="en">{esc(summary)}</td>'
        "</tr>"
    )


def _table(vulns: list[dict]) -> str:
    if not vulns:
        return ""
    rows = "".join(_row(v) for v in vulns)
    return (
        '<div class="scroll-x"><table class="data">'
        "<thead><tr>"
        '<th data-i18n="th_published">Published</th>'
        '<th data-i18n="th_advisory">Advisory</th>'
        '<th data-i18n="th_severity">Severity</th>'
        '<th class="num">CVSS</th>'
        '<th class="num">EPSS</th>'
        '<th data-i18n="th_fixed">Fixed in</th>'
        '<th data-i18n="th_summary">Summary</th>'
        "</tr></thead><tbody>"
        f"{rows}</tbody></table></div>"
    )


def _fixed_line(vulns: list[dict]) -> tuple[str, str]:
    versions = fixed_list(vulns)
    if not versions:
        return "No fixed version listed", "수정 버전 정보 없음"
    shown, rest = versions[:8], versions[8:]
    joined = ", ".join(shown)
    if rest:
        joined_en = f"{joined} +{len(rest)}"
        joined_ko = f"{joined} 외 {len(rest)}개"
    else:
        joined_en = joined_ko = joined
    return f"Fixed in {joined_en}", f"수정 버전 {joined_ko}"


def _descriptions(label: str, eco: str, n30: int, n7: int, kev_n: int, worst: str | None) -> tuple[str, str]:
    en = f"{label} ({eco}) vulnerabilities: {n30} in 30 days, {n7} in the last 7 days"
    ko = f"{label} ({eco}) 취약점: 30일 {n30}건, 최근 7일 {n7}건"
    if kev_n:
        en += f", {kev_n} in CISA KEV"
        ko += f", KEV {kev_n}건"
    if worst:
        en += f". Worst {worst}"
        ko += f". 최고 {worst}"
    en += ". Severity, fixed versions and EPSS, updated daily."
    ko += ". 심각도, 수정 버전, EPSS. 매일 갱신."
    return oneline(en), oneline(ko)


def _worst(vulns: list[dict]) -> str | None:
    best = None
    rank = -1
    for v in vulns:
        sev = str(v.get("severity") or "").upper()
        r = feeds.SEVERITY_RANK.get(sev, 0)
        if r > rank and sev:
            rank = r
            best = str(v.get("severity") or sev)
    return best


def _json_ld(url: str, en_title: str, ko_title: str, en_desc: str, generated: str,
             label: str, vulns: list[dict]) -> str:
    items = []
    for i, v in enumerate(vulns, start=1):
        item: dict = {"@type": "ListItem", "position": i, "name": str(v.get("id") or "")}
        summary = v.get("summary") if isinstance(v.get("summary"), str) else ""
        if summary:
            item["description"] = oneline(summary)[:300]
        href = safe_href(v.get("url"))
        if href:
            item["url"] = href
        items.append(item)
    graph = [
        {
            "@type": "WebPage",
            "@id": url,
            "url": url,
            "name": en_title,
            "alternateName": ko_title,
            "description": en_desc,
            "inLanguage": ["en", "ko"],
            "dateModified": generated,
            "isPartOf": {"@type": "WebSite", "name": "depweather", "url": f"{SITE}/"},
            "breadcrumb": {"@id": url + "#breadcrumb"},
        },
        {
            "@type": "BreadcrumbList",
            "@id": url + "#breadcrumb",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "depweather", "item": f"{SITE}/"},
                {"@type": "ListItem", "position": 2, "name": label, "item": url},
            ],
        },
        {
            "@type": "ItemList",
            "name": f"Advisories for {label}",
            "numberOfItems": len(items),
            "itemListElement": items,
        },
    ]
    raw = json.dumps({"@context": "https://schema.org", "@graph": graph}, ensure_ascii=False)
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def iter_packages(data: dict):
    seen: set[str] = set()
    for eco in data.get("ecosystems") or []:
        if not isinstance(eco, dict):
            continue
        for pkg in eco.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            key = pkg.get("key")
            if not isinstance(key, str) or not key or key in seen:
                continue
            seen.add(key)
            yield eco, pkg


def render_page(eco: dict, pkg: dict, generated: datetime, generated_raw: str) -> str:
    key = pkg["key"]
    label = str(pkg.get("label") or pkg.get("name") or key)
    name = str(pkg.get("name") or label)
    eco_label = str(eco.get("label") or eco.get("id") or "")
    page_url = feeds.package_page_url(key)
    feed_path = "/" + feeds.feed_relpath(key)
    current, earlier = classify(pkg.get("vulns") or [], generated)
    shown = current + earlier
    n7, n30 = len(current), len(shown)
    kev_n = sum(1 for v in shown if v.get("kev") is True)
    worst = _worst(shown)
    en_title = oneline(f"{label} ({eco_label}) vulnerabilities — depweather")
    ko_title = oneline(f"{label} ({eco_label}) 취약점 — depweather")
    en_desc, ko_desc = _descriptions(label, eco_label, n30, n7, kev_n, worst)
    en_fixed, ko_fixed = _fixed_line(shown) if shown else ("", "")
    stamp = generated.strftime("%Y-%m-%d %H:%M")
    en_updated = f"Data updated {stamp} UTC."
    ko_updated = f"데이터 갱신 {stamp} UTC."
    en_current = f"Current, last 7 days ({n7})"
    ko_current = f"현재, 최근 7일 ({n7}건)"
    en_recent = f"Recent, last 30 days ({len(earlier)})"
    ko_recent = f"최근 30일 중 이전 권고 ({len(earlier)}건)"
    current_body = _table(current) or '<p class="empty" data-i18n="empty_current">No advisories in the last 7 days.</p>'
    recent_body = _table(earlier) or '<p class="empty" data-i18n="empty_recent">No earlier advisories in this 30-day window.</p>'
    fixed_html = ""
    if shown:
        fixed_html = f'<p class="fixed" data-en="{esc(en_fixed)}" data-ko="{esc(ko_fixed)}">{esc(en_fixed)}</p>'
    ld = _json_ld(page_url, en_title, ko_title, en_desc, generated_raw, label, shown)
    import badges
    panel = badges.panel_html(pkg, generated)
    return f"""<!doctype html>
<html lang="en" data-title-en="{esc(en_title)}" data-title-ko="{esc(ko_title)}" data-desc-en="{esc(en_desc)}" data-desc-ko="{esc(ko_desc)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script async src="https://www.googletagmanager.com/gtag/js?id=G-HF5GM88Y3V"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){{dataLayer.push(arguments);}}
  gtag('js', new Date());
  gtag('config', 'G-HF5GM88Y3V');
</script>
<title>{esc(en_title)}</title>
<meta id="desc" name="description" lang="en" content="{esc(en_desc)}">
<meta name="description" lang="ko" content="{esc(ko_desc)}">
<link rel="canonical" href="{esc(page_url)}">
<link rel="alternate" hreflang="en" href="{esc(page_url)}">
<link rel="alternate" hreflang="ko" href="{esc(page_url)}?lang=ko">
<link rel="alternate" hreflang="x-default" href="{esc(page_url)}">
<meta name="robots" content="index,follow">
<meta property="og:type" content="website">
<meta property="og:site_name" content="depweather">
<meta property="og:title" content="{esc(en_title)}">
<meta property="og:description" content="{esc(en_desc)}">
<meta property="og:url" content="{esc(page_url)}">
<meta property="og:image" content="{SITE}/og.png">
<meta property="og:locale" content="en">
<meta property="og:locale:alternate" content="ko">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/fonts/fonts.css">
<link rel="alternate" type="application/atom+xml" href="{esc(SITE + feed_path)}" title="{esc(label)} advisories">
<script type="application/ld+json">
{ld}
</script>
<script>
(function () {{
  try {{
    var q = new URLSearchParams(location.search).get("lang");
    var p = JSON.parse(localStorage.getItem("depweather:prefs") || "{{}}");
    var lang = (q === "ko" || q === "en") ? q : (p.lang === "ko" || p.lang === "en" ? p.lang : ((navigator.language || "").toLowerCase().indexOf("ko") === 0 ? "ko" : "en"));
    document.documentElement.lang = lang;
    if (p.theme === "dark" || p.theme === "light") document.documentElement.dataset.theme = p.theme;
    var title = document.documentElement.getAttribute(lang === "ko" ? "data-title-ko" : "data-title-en");
    var desc = document.documentElement.getAttribute(lang === "ko" ? "data-desc-ko" : "data-desc-en");
    if (title) document.title = title;
    var md = document.getElementById("desc");
    if (md && desc) {{ md.setAttribute("content", desc); md.setAttribute("lang", lang); }}
    var ogt = document.querySelector('meta[property="og:title"]');
    var ogd = document.querySelector('meta[property="og:description"]');
    if (ogt && title) ogt.setAttribute("content", title);
    if (ogd && desc) ogd.setAttribute("content", desc);
  }} catch (e) {{}}
}})();
</script>
<style>
:root {{
  color-scheme: light;
  --page: #eef5fa; --surface: #ffffff; --ink: #12324d; --ink-2: #3f5b73; --muted: #62798d;
  --grid: #dce7ef; --border: rgba(18, 50, 77, 0.12); --accent: #1d6fb8;
  --sev-0: #e3ecf3; --sev-0-ink: #3f5b73; --sev-1: #f4c542; --sev-1-ink: #12324d;
  --sev-2: #f28c38; --sev-2-ink: #12324d; --sev-3: #d9433b; --sev-3-ink: #ffffff;
  --sev-kev: #a32ca0; --group-head: #e6f0f7;
}}
@media (prefers-color-scheme: dark) {{
  :root:where(:not([data-theme="light"])) {{
    color-scheme: dark;
    --page: #0d1b27; --surface: #12242f; --ink: #e4eef6; --ink-2: #b2c5d4; --muted: #8299ab;
    --grid: #1f3444; --border: rgba(228, 238, 246, 0.12); --accent: #6cb0ec;
    --sev-0: #1a2e3c; --sev-0-ink: #b2c5d4; --sev-kev: #c44bc0; --group-head: #172c3a;
  }}
}}
:root[data-theme="dark"] {{
  color-scheme: dark;
  --page: #0d1b27; --surface: #12242f; --ink: #e4eef6; --ink-2: #b2c5d4; --muted: #8299ab;
  --grid: #1f3444; --border: rgba(228, 238, 246, 0.12); --accent: #6cb0ec;
  --sev-0: #1a2e3c; --sev-0-ink: #b2c5d4; --sev-kev: #c44bc0; --group-head: #172c3a;
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; }}
body {{
  background: var(--page); color: var(--ink);
  font: 15px/1.5 "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", "Apple SD Gothic Neo", "Malgun Gothic", "Noto Sans KR", sans-serif;
  font-feature-settings: "calt" 0;
}}
:lang(ko) body {{ word-break: keep-all; }}
a {{ color: var(--accent); }}
h1, h2 {{ font-family: "Bricolage Grotesque", "IBM Plex Sans", system-ui, "Apple SD Gothic Neo", "Malgun Gothic", sans-serif; }}
:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
.wrap {{ max-width: 1100px; margin: 0 auto; padding: 0 24px; }}
@media (max-width: 767px) {{ .wrap {{ padding: 0 16px; }} }}
header.top {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; padding: 18px 0 10px; }}
header.top h1 {{ margin: 0; font-size: 24px; font-weight: 800; }}
header.top h1 a {{ color: inherit; text-decoration: none; display: flex; align-items: center; gap: 10px; }}
header.top h1 img {{ width: 32px; height: 32px; }}
.tag {{ color: var(--ink-2); font-size: 14px; }}
.spacer {{ flex: 1; }}
.controls {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }}
.iconbtn, .seg button {{
  font: inherit; font-size: 13px; padding: 6px 12px; border: 1px solid var(--border); border-radius: 999px;
  background: var(--surface); color: var(--ink-2); cursor: pointer; text-decoration: none;
}}
.seg {{ display: inline-flex; border: 1px solid var(--border); border-radius: 999px; overflow: hidden; background: var(--surface); }}
.seg button {{ border: 0; border-radius: 0; }}
.seg button + button {{ border-left: 1px solid var(--border); }}
.seg button[aria-pressed="true"] {{ background: var(--ink); color: var(--page); }}
h1.pkg {{ font-size: clamp(28px, 4vw, 40px); line-height: 1.15; margin: 12px 0 4px; letter-spacing: -0.02em; }}
h1.pkg .meta {{ font-family: "IBM Plex Sans", system-ui, sans-serif; font-size: 15px; font-weight: 400; color: var(--muted); margin-left: 8px; }}
.lede {{ font-size: 17px; max-width: 68ch; margin: 8px 0; }}
.fixed {{ color: var(--ink-2); margin: 0 0 14px; }}
.panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 12px 14px; margin: 12px 0; }}
.panel h2 {{ font-size: 18px; margin: 0 0 6px; }}
.note {{ color: var(--muted); font-size: 13px; margin: 0 0 8px; }}
.empty {{ color: var(--ink-2); margin: 0; }}
.meta {{ color: var(--muted); font-size: 12.5px; }}
table.data {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
table.data th, table.data td {{ text-align: left; padding: 6px 8px; border-top: 1px solid var(--grid); vertical-align: top; }}
table.data th {{ color: var(--ink-2); font-weight: 600; border-top: 0; }}
table.data td.num, table.data th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
table.data td.nowrap {{ white-space: nowrap; }}
.scroll-x {{ overflow-x: auto; }}
.summary {{ min-width: 16em; }}
.pill {{ display: inline-block; padding: 0 6px; border-radius: 4px; font-size: 12px; font-weight: 600; white-space: nowrap; }}
.pill.l0 {{ background: var(--sev-0); color: var(--sev-0-ink); }}
.pill.l1 {{ background: var(--sev-1); color: var(--sev-1-ink); }}
.pill.l2 {{ background: var(--sev-2); color: var(--sev-2-ink); }}
.pill.l3 {{ background: var(--sev-3); color: var(--sev-3-ink); }}
.pill.kev {{ background: var(--sev-kev); color: #fff; }}
.pill.mal {{ background: var(--ink); color: var(--page); }}
.badge-preview {{ margin: 8px 0 4px; line-height: 1; }}
.badge-preview img {{ height: 20px; width: auto; vertical-align: middle; }}
.snippet {{ margin-top: 10px; }}
.snippet-head {{ display: flex; align-items: center; justify-content: space-between; gap: 8px; margin: 0 0 4px; }}
.snippet-head span {{ font-size: 13px; font-weight: 650; }}
.snippet pre {{
  margin: 0; padding: 8px 10px; background: var(--page); color: var(--ink);
  border: 1px solid var(--border); border-radius: 8px; overflow-x: auto;
  font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, "Apple SD Gothic Neo", monospace;
  white-space: pre-wrap; word-break: break-all;
}}
footer {{ color: var(--muted); font-size: 12.5px; padding: 8px 0 32px; }}
footer p {{ margin: 4px 0; }}
@media (max-width: 767px) {{
  table.data thead {{ display: none; }}
  table.data tr {{ display: block; border-top: 1px solid var(--grid); padding: 6px 0; }}
  table.data td {{ display: inline-block; border: 0; padding: 2px 6px 2px 0; }}
  table.data td.summary {{ display: block; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1><a href="/" id="brand"><img src="/favicon.svg" alt="" width="32" height="32">depweather</a></h1>
    <span class="tag" data-i18n="tagline">Vulnerability weather for popular packages</span>
    <span class="spacer"></span>
    <div class="controls">
      <a class="iconbtn" id="back" href="/" data-i18n="back">Back to the map</a>
      <a class="iconbtn" id="feedlink" href="{esc(feed_path)}" data-i18n="feed">Package feed</a>
      <button type="button" class="iconbtn" id="theme" data-i18n="theme" data-i18n-title="theme_title" title="Toggle light / dark">Theme</button>
      <div class="seg lang" role="group" aria-label="Language">
        <button type="button" data-lang="en" lang="en" aria-pressed="true">EN</button>
        <button type="button" data-lang="ko" lang="ko" aria-pressed="false">KO</button>
      </div>
    </div>
  </header>
  <main>
    <h1 class="pkg">{esc(label)} <span class="meta">{esc(eco_label)} · {esc(name)}</span></h1>
    <p class="lede" data-en="{esc(en_desc)}" data-ko="{esc(ko_desc)}">{esc(en_desc)}</p>
    {fixed_html}
    {panel}
    <section class="panel" id="current">
      <h2 data-en="{esc(en_current)}" data-ko="{esc(ko_current)}">{esc(en_current)}</h2>
      <p class="note" data-i18n="current_note">Published in the last 7 days, or added to CISA KEV in that time.</p>
      {current_body}
    </section>
    <section class="panel" id="recent">
      <h2 data-en="{esc(en_recent)}" data-ko="{esc(ko_recent)}">{esc(en_recent)}</h2>
      <p class="note" data-i18n="recent_note">Earlier advisories still inside the 30-day window.</p>
      {recent_body}
    </section>
    <p class="note" data-i18n="advisory_lang">Advisory text is quoted from the source and stays in English.</p>
  </main>
  <footer>
    <p data-en="{esc(en_updated)}" data-ko="{esc(ko_updated)}">{esc(en_updated)}</p>
    <p>Data: <a href="https://osv.dev">OSV</a>, <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a>, FIRST EPSS, <a href="https://nvd.nist.gov">NVD</a>.</p>
    <p data-i18n="footer_nvd">This product uses the NVD API but is not endorsed or certified by the NVD.</p>
    <p data-i18n="footer_analytics">This site uses Google Analytics to count visits.</p>
    <p data-i18n="footer_disclaimer">Severity comes from the upstream advisory and can be wrong. Check the linked advisory before acting.</p>
  </footer>
</div>
<script>
(function () {{
  var KEY = "depweather:prefs";
  var I18N = {{
    en: {{
      tagline: "Vulnerability weather for popular packages",
      back: "Back to the map",
      feed: "Package feed",
      theme: "Theme",
      theme_title: "Toggle light / dark",
      current_note: "Published in the last 7 days, or added to CISA KEV in that time.",
      recent_note: "Earlier advisories still inside the 30-day window.",
      empty_current: "No advisories in the last 7 days.",
      empty_recent: "No earlier advisories in this 30-day window.",
      advisory_lang: "Advisory text is quoted from the source and stays in English.",
      th_published: "Published",
      th_advisory: "Advisory",
      th_severity: "Severity",
      th_fixed: "Fixed in",
      th_summary: "Summary",
      malicious: "Malicious",
      footer_nvd: "This product uses the NVD API but is not endorsed or certified by the NVD.",
      footer_analytics: "This site uses Google Analytics to count visits.",
      footer_disclaimer: "Severity comes from the upstream advisory and can be wrong. Check the linked advisory before acting."
    }},
    ko: {{
      tagline: "인기 패키지의 취약점 날씨",
      back: "지도로 돌아가기",
      feed: "패키지 피드",
      theme: "테마",
      theme_title: "라이트 / 다크 전환",
      current_note: "최근 7일 동안 공개됐거나 그 사이에 CISA KEV에 추가된 권고입니다.",
      recent_note: "30일 창 안에서 그보다 이전인 권고입니다.",
      empty_current: "최근 7일 동안 공개되거나 KEV에 추가된 권고가 없습니다.",
      empty_recent: "최근 30일 중 그 이전 권고가 없습니다.",
      advisory_lang: "권고 본문은 출처의 영어 그대로입니다.",
      th_published: "공개일",
      th_advisory: "권고",
      th_severity: "심각도",
      th_fixed: "수정 버전",
      th_summary: "요약",
      malicious: "악성",
      footer_nvd: "이 제품은 NVD API를 사용하지만 NVD가 보증하거나 인증하지 않습니다.",
      footer_analytics: "방문 통계를 위해 Google Analytics를 사용합니다.",
      footer_disclaimer: "심각도는 원 권고의 값이며 틀릴 수 있습니다. 조치 전에 링크된 권고를 확인하세요."
    }}
  }};
  function prefs() {{
    try {{ return JSON.parse(localStorage.getItem(KEY)) || {{}}; }} catch (e) {{ return {{}}; }}
  }}
  function save(patch) {{
    var cur = prefs();
    Object.keys(patch).forEach(function (k) {{ cur[k] = patch[k]; }});
    try {{ localStorage.setItem(KEY, JSON.stringify(cur)); }} catch (e) {{}}
  }}
  function initialLang() {{
    var q = new URLSearchParams(location.search).get("lang");
    if (q === "ko" || q === "en") return q;
    var p = prefs();
    if (p.lang === "ko" || p.lang === "en") return p.lang;
    return (navigator.language || "").toLowerCase().indexOf("ko") === 0 ? "ko" : "en";
  }}
  function apply(lang) {{
    var dict = I18N[lang] || I18N.en;
    document.documentElement.lang = lang;
    var title = document.documentElement.getAttribute(lang === "ko" ? "data-title-ko" : "data-title-en");
    var desc = document.documentElement.getAttribute(lang === "ko" ? "data-desc-ko" : "data-desc-en");
    if (title) document.title = title;
    var md = document.getElementById("desc");
    if (md && desc) {{ md.setAttribute("content", desc); md.setAttribute("lang", lang); }}
    var ogt = document.querySelector('meta[property="og:title"]');
    var ogd = document.querySelector('meta[property="og:description"]');
    if (ogt && title) ogt.setAttribute("content", title);
    if (ogd && desc) ogd.setAttribute("content", desc);
    document.querySelectorAll("[data-i18n]").forEach(function (el) {{
      var key = el.getAttribute("data-i18n");
      if (dict[key] != null) el.textContent = dict[key];
    }});
    document.querySelectorAll("[data-i18n-title]").forEach(function (el) {{
      var key = el.getAttribute("data-i18n-title");
      if (dict[key] != null) el.title = dict[key];
    }});
    document.querySelectorAll("[data-en]").forEach(function (el) {{
      var v = el.getAttribute(lang === "ko" ? "data-ko" : "data-en");
      if (v != null) el.textContent = v;
    }});
    document.querySelectorAll("[data-src-en]").forEach(function (el) {{
      var src = el.getAttribute(lang === "ko" ? "data-src-ko" : "data-src-en");
      var alt = el.getAttribute(lang === "ko" ? "data-alt-ko" : "data-alt-en");
      if (src) el.setAttribute("src", src);
      if (alt != null) el.alt = alt;
    }});
    document.querySelectorAll("[data-lang]").forEach(function (b) {{
      b.setAttribute("aria-pressed", b.getAttribute("data-lang") === lang ? "true" : "false");
    }});
    var map = lang === "ko" ? "/?lang=ko" : "/";
    ["back", "brand"].forEach(function (id) {{
      var el = document.getElementById(id);
      if (el) el.setAttribute("href", map);
    }});
  }}
  document.getElementById("theme").addEventListener("click", function () {{
    var root = document.documentElement;
    var dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    save({{ theme: root.dataset.theme }});
  }});
  document.querySelectorAll("[data-lang]").forEach(function (b) {{
    b.addEventListener("click", function () {{
      var next = b.getAttribute("data-lang");
      save({{ lang: next }});
      apply(next);
      var u = new URL(location.href);
      u.searchParams.set("lang", next);
      history.replaceState(null, "", u.pathname + u.search + u.hash);
    }});
  }});
  document.querySelectorAll("[data-copy]").forEach(function (btn) {{
    btn.addEventListener("click", function () {{
      var node = document.getElementById(btn.getAttribute("data-copy"));
      if (!node) return;
      var text = node.textContent || "";
      var restore = function () {{
        var langNow = document.documentElement.lang === "ko" ? "ko" : "en";
        var back = btn.getAttribute(langNow === "ko" ? "data-ko" : "data-en");
        if (back != null) btn.textContent = back;
        btn.removeAttribute("data-flash");
      }};
      var mark = function () {{
        var langNow = document.documentElement.lang === "ko" ? "ko" : "en";
        var done = btn.getAttribute(langNow === "ko" ? "data-copied-ko" : "data-copied-en");
        btn.setAttribute("data-flash", "1");
        if (done != null) btn.textContent = done;
        setTimeout(restore, 1600);
      }};
      var fallback = function () {{
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        try {{ document.execCommand("copy"); mark(); }} catch (e) {{}}
        ta.remove();
      }};
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).then(mark, fallback);
      }} else fallback();
    }});
  }});
  apply(initialLang());
}})();
</script>
</body>
</html>
"""


def write_pages(data: dict, out: Path) -> int:
    """Write index.html for every tracked package. Returns the page count."""
    generated_raw = str(data.get("generated_at") or "")
    generated = feeds.parse_time(generated_raw)
    n = 0
    for eco, pkg in iter_packages(data):
        rel = feeds.package_page_rel(pkg["key"]) + "index.html"
        path = out / rel
        # feed_relpath rejects absolute and '..' segments; keep the file under out.
        if not path.resolve().is_relative_to(out.resolve()):
            raise ValueError(f"package page escapes output dir: {pkg['key']!r}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_page(eco, pkg, generated, generated_raw), encoding="utf-8")
        n += 1
    return n


def _sitemap_entry(loc: str, en: str, ko: str, lastmod: str) -> str:
    e_loc, e_en, e_ko = esc(loc), esc(en), esc(ko)
    return (
        "  <url>\n"
        f"    <loc>{e_loc}</loc>\n"
        f"    <lastmod>{esc(lastmod)}</lastmod>\n"
        "    <changefreq>daily</changefreq>\n"
        f'    <xhtml:link rel="alternate" hreflang="en" href="{e_en}"/>\n'
        f'    <xhtml:link rel="alternate" hreflang="ko" href="{e_ko}"/>\n'
        f'    <xhtml:link rel="alternate" hreflang="x-default" href="{e_en}"/>\n'
        "  </url>"
    )


def strip_pkg_urls(text: str) -> str:
    def keep(match: re.Match[str]) -> str:
        block = match.group(0)
        if f"{SITE}/pkg/" in block:
            return ""
        return block
    return _URL_BLOCK.sub(keep, text)


def render_sitemap(data: dict, base_text: str) -> str:
    """Static URLs from the committed sitemap, plus one en/ko pair per package."""
    if "</urlset>" not in base_text:
        raise ValueError("sitemap base has no </urlset>")
    generated = feeds.parse_time(str(data.get("generated_at") or ""))
    lastmod = generated.date().isoformat()
    blocks = []
    for _eco, pkg in iter_packages(data):
        url = feeds.package_page_url(pkg["key"])
        ko = url + "?lang=ko"
        blocks.append(_sitemap_entry(url, url, ko, lastmod))
        blocks.append(_sitemap_entry(ko, url, ko, lastmod))
    body = strip_pkg_urls(base_text)
    body = re.sub(r"\s*</urlset>\s*$", "", body).rstrip() + "\n"
    if blocks:
        body += "\n".join(blocks) + "\n"
    return body + "</urlset>\n"


def write_sitemap(data: dict, out: Path, base: Path) -> Path | None:
    """Write out/sitemap.xml. Returns None when that path is the committed file."""
    dest = out / "sitemap.xml"
    if dest.resolve() == base.resolve():
        return None
    text = base.read_text(encoding="utf-8") if base.is_file() else (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
        'xmlns:xhtml="http://www.w3.org/1999/xhtml">\n</urlset>\n'
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(render_sitemap(data, text), encoding="utf-8")
    return dest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Write depweather package pages from data/latest.json")
    p.add_argument("--latest", type=Path, default=ROOT / "data" / "latest.json")
    p.add_argument("--out", type=Path, default=ROOT, help="Site root. Writes <out>/pkg/ and, unless it is the repo, <out>/sitemap.xml")
    p.add_argument("--sitemap-base", type=Path, default=ROOT / "sitemap.xml")
    args = p.parse_args(argv)
    data = json.loads(args.latest.read_text(encoding="utf-8"))
    n = write_pages(data, args.out)
    written = write_sitemap(data, args.out, args.sitemap_base)
    where = written if written else "sitemap.xml left unchanged"
    print(f"wrote {n} package pages under {args.out} ({where})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
