#!/usr/bin/env python3
"""Write one shields-style SVG badge per tracked package.

    <out>/badge/<ecosystem>/<name>.svg
    <out>/badge/<ecosystem>/<name>.ko.svg

The path uses the same slug as the package page (collect/feeds.py): a Maven
':' is '~', and a real '~' is '~~'. English is the issue path
/badge/<pkg>.svg. Korean is the same path with .ko.svg. Both are built in
the Pages workflow from data/latest.json and are not committed.

The badge is the last 7 days before generated_at, the same window as the
map and the package page's "Current" section. An advisory counts when it
was published in that window, or added to CISA KEV then if that is later.
Nothing new is "clear". Low, medium or unknown only is "cloudy". High and
critical show a count. KEV is the color of the badge and the first word.
A malicious-package report counts as critical.

Colors are the site's severity colors. The critical red is one step darker
than --sev-3 so 11px white text stays above 4.5:1. Every string that comes
from the data is escaped. The SVG links to the package page; the Markdown
and HTML snippets do too, because an <img> does not follow a link inside
the file.
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collect"))

import feeds  # noqa: E402

CURRENT_DAYS = 7
# index.html :root. Critical fill is --sev-3 (#d9433b) darkened so white
# 11px text clears 4.5:1 (the site red is 4.36:1 at this size).
COLORS = {
    "clear": ("#e3ecf3", "#3f5b73"),
    "cloudy": ("#f4c542", "#12324d"),
    "high": ("#f28c38", "#12324d"),
    "critical": ("#d04039", "#ffffff"),
    "kev": ("#a32ca0", "#ffffff"),
}
LABEL_BG = "#12324d"
LABEL_FG = "#ffffff"
LABEL = "depweather"
PAD = 10
_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
_XML_BAD = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

NOTE_EN = (
    "Last 7 days, same window as the map. Clear, cloudy, or a count of high "
    "and critical. KEV is marked first."
)
NOTE_KO = (
    "최근 7일입니다. 지도와 같은 기간입니다. 맑음, 흐림, 또는 높음·치명 건수이고, "
    "KEV는 맨 앞에 표시합니다."
)
CACHE_EN = (
    "GitHub caches README images on its camo proxy, so a badge on GitHub can "
    "lag this page by a few hours."
)
CACHE_KO = (
    "GitHub는 README 이미지를 camo로 캐시합니다. GitHub에 올린 배지는 이 페이지보다 "
    "몇 시간 늦을 수 있습니다."
)


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _clean(value: object) -> str:
    text = _XML_BAD.sub("", "" if value is None else str(value))
    return " ".join(text.split())


def short_label(value: object) -> str:
    text = _clean(value)
    if len(text) > 42:
        text = text[:41].rstrip() + "…"
    return text or "package"


def text_px(text: str) -> int:
    """Generous width at 11px Verdana 600, so textLength only adds spacing."""
    width = 0.0
    for ch in text:
        o = ord(ch)
        if ch == " ":
            width += 4.0
        elif o >= 0x2E80 or 0x1100 <= o <= 0x11FF or 0xAC00 <= o <= 0xD7A3:
            width += 11.0
        elif ch in "mwMW@#%&":
            width += 10.0
        elif ch in "iljtfr.,':;|!":
            width += 4.0
        elif ch in "()[]{}":
            width += 5.0
        else:
            width += 7.6
    return max(1, math.ceil(width))


def _message_en(kev: int, crit: int, high: int, other: int) -> str:
    if not kev and not crit and not high:
        return "cloudy" if other else "clear"
    bits: list[str] = []
    if kev == 1:
        bits.append("KEV")
    elif kev:
        bits.append(f"{kev} KEV")
    tail: list[str] = []
    if crit:
        tail.append(f"{crit} critical")
    if high:
        tail.append(f"{high} high")
    if tail:
        bits.append(", ".join(tail))
    return " · ".join(bits)


def _message_ko(kev: int, crit: int, high: int, other: int) -> str:
    if not kev and not crit and not high:
        return "흐림" if other else "맑음"
    bits: list[str] = []
    if kev == 1:
        bits.append("KEV")
    elif kev:
        bits.append(f"KEV {kev}건")
    tail: list[str] = []
    if crit:
        tail.append(f"치명 {crit}건")
    if high:
        tail.append(f"높음 {high}건")
    if tail:
        bits.append(", ".join(tail))
    return " · ".join(bits)


def _kind_of(v: dict) -> str:
    if v.get("kev") is True:
        return "kev"
    if v.get("malicious") is True or str(v.get("severity") or "").upper() == "CRITICAL":
        return "critical"
    if str(v.get("severity") or "").upper() == "HIGH":
        return "high"
    return "other"


def status_of(vulns: list, generated: datetime) -> dict:
    """Counts for the current window. KEV items also add to critical or high."""
    cutoff = generated - timedelta(days=CURRENT_DAYS)
    kev = crit = high = other = 0
    for v in vulns or []:
        if not isinstance(v, dict) or not v.get("id"):
            continue
        try:
            when = feeds.effective_date(v)
        except (KeyError, TypeError, ValueError):
            continue
        if when < cutoff:
            continue
        kind = _kind_of(v)
        sev = str(v.get("severity") or "").upper()
        if kind == "kev":
            kev += 1
            if v.get("malicious") is True or sev == "CRITICAL":
                crit += 1
            elif sev == "HIGH":
                high += 1
        elif kind == "critical":
            crit += 1
        elif kind == "high":
            high += 1
        else:
            other += 1
    if kev:
        color = "kev"
    elif crit:
        color = "critical"
    elif high:
        color = "high"
    elif other:
        color = "cloudy"
    else:
        color = "clear"
    fill, ink = COLORS[color]
    return {
        "color": color,
        "kev": kev,
        "critical": crit,
        "high": high,
        "other": other,
        "en": _message_en(kev, crit, high, other),
        "ko": _message_ko(kev, crit, high, other),
        "fill": fill,
        "ink": ink,
    }


def render_svg(*, label: str, message: str, fill: str, ink: str, href: str) -> str:
    if not _HEX.match(fill) or not _HEX.match(ink):
        raise ValueError("badge color is not a hex color")
    if not href.startswith(feeds.SITE + "/"):
        raise ValueError("badge link must stay on depweather.com")
    left = LABEL
    right = f"{short_label(label)}: {message}"
    title = f"{left}: {right}"
    lw_text, rw_text = text_px(left), text_px(right)
    lw, rw = lw_text + PAD * 2, rw_text + PAD * 2
    width = lw + rw
    lx, rx = lw / 2, lw + rw / 2
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"'
        f' width="{width}" height="20" viewBox="0 0 {width} 20" role="img" aria-label="{esc(title)}">\n'
        f"  <title>{esc(title)}</title>\n"
        f'  <defs><clipPath id="dw"><rect width="{width}" height="20" rx="3"/></clipPath></defs>\n'
        f'  <a href="{esc(href)}" xlink:href="{esc(href)}">\n'
        f'    <g clip-path="url(#dw)">\n'
        f'      <rect width="{lw}" height="20" fill="{LABEL_BG}"/>\n'
        f'      <rect x="{lw}" width="{rw}" height="20" fill="{fill}"/>\n'
        f"    </g>\n"
        f'    <rect x="0.5" y="0.5" width="{width - 1}" height="19" rx="2.5" fill="none"'
        f' stroke="#3f5b73" stroke-opacity="0.45"/>\n'
        f'    <g text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif"'
        f' font-size="11" font-weight="600">\n'
        f'      <text x="{lx:.1f}" y="14" fill="{LABEL_FG}" textLength="{lw_text}"'
        f' lengthAdjust="spacing">{esc(left)}</text>\n'
        f'      <text x="{rx:.1f}" y="14" fill="{ink}" textLength="{rw_text}"'
        f' lengthAdjust="spacing">{esc(right)}</text>\n'
        f"    </g>\n"
        f"  </a>\n"
        f"</svg>\n"
    )


def _alt(label: str, message: str) -> str:
    text = f"{LABEL}: {short_label(label)}: {message}"
    return text.replace("[", "").replace("]", "")


def markdown_snippet(alt: str, badge: str, page: str) -> str:
    return f"[![{alt}]({badge})]({page})"


def html_snippet(alt: str, badge: str, page: str) -> str:
    return (
        f'<a href="{esc(page)}"><img alt="{esc(alt)}" src="{esc(badge)}" height="20"></a>'
    )


def snippets(pkg: dict, generated: datetime) -> dict:
    key = pkg["key"]
    label = str(pkg.get("label") or pkg.get("name") or key)
    st = status_of(pkg.get("vulns") or [], generated)
    page = feeds.package_page_url(key)
    page_ko = page + "?lang=ko"
    badge = feeds.badge_url(key, "en")
    badge_ko = feeds.badge_url(key, "ko")
    alt_en = _alt(label, st["en"])
    alt_ko = _alt(label, st["ko"])
    return {
        "status": st,
        "alt_en": alt_en,
        "alt_ko": alt_ko,
        "src_en": "/" + feeds.badge_relpath(key, "en"),
        "src_ko": "/" + feeds.badge_relpath(key, "ko"),
        "md_en": markdown_snippet(alt_en, badge, page),
        "md_ko": markdown_snippet(alt_ko, badge_ko, page_ko),
        "html_en": html_snippet(alt_en, badge, page),
        "html_ko": html_snippet(alt_ko, badge_ko, page_ko),
        "svg_en": render_svg(label=label, message=st["en"], fill=st["fill"], ink=st["ink"], href=page),
        "svg_ko": render_svg(label=label, message=st["ko"], fill=st["fill"], ink=st["ink"], href=page_ko),
    }


def panel_html(pkg: dict, generated: datetime) -> str:
    s = snippets(pkg, generated)
    return f"""<section class="panel" id="badge">
      <h2 data-en="README badge" data-ko="README 배지">README badge</h2>
      <p class="badge-preview"><img id="badge-img" height="20" src="{esc(s["src_en"])}" alt="{esc(s["alt_en"])}" data-src-en="{esc(s["src_en"])}" data-src-ko="{esc(s["src_ko"])}" data-alt-en="{esc(s["alt_en"])}" data-alt-ko="{esc(s["alt_ko"])}"></p>
      <p class="note" data-en="{esc(NOTE_EN)}" data-ko="{esc(NOTE_KO)}">{esc(NOTE_EN)}</p>
      <div class="snippet">
        <div class="snippet-head">
          <span data-en="Markdown" data-ko="Markdown">Markdown</span>
          <button type="button" class="iconbtn" data-copy="badge-md" aria-live="polite" data-en="Copy" data-ko="복사" data-copied-en="Copied" data-copied-ko="복사됨">Copy</button>
        </div>
        <pre id="badge-md" data-en="{esc(s["md_en"])}" data-ko="{esc(s["md_ko"])}">{esc(s["md_en"])}</pre>
      </div>
      <div class="snippet">
        <div class="snippet-head">
          <span data-en="HTML" data-ko="HTML">HTML</span>
          <button type="button" class="iconbtn" data-copy="badge-html" aria-live="polite" data-en="Copy" data-ko="복사" data-copied-en="Copied" data-copied-ko="복사됨">Copy</button>
        </div>
        <pre id="badge-html" data-en="{esc(s["html_en"])}" data-ko="{esc(s["html_ko"])}">{esc(s["html_en"])}</pre>
      </div>
      <p class="note" data-en="{esc(CACHE_EN)}" data-ko="{esc(CACHE_KO)}">{esc(CACHE_EN)}</p>
    </section>"""


def _write_one(out: Path, rel: str, text: str) -> None:
    path = out / rel
    if not path.resolve().is_relative_to(out.resolve()):
        raise ValueError(f"badge escapes output dir: {rel}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_badges(data: dict, out: Path) -> int:
    """Write an English and a Korean SVG for every tracked package."""
    import pages

    generated = feeds.parse_time(str(data.get("generated_at") or ""))
    n = 0
    for _eco, pkg in pages.iter_packages(data):
        key = pkg["key"]
        built = snippets(pkg, generated)
        _write_one(out, feeds.badge_relpath(key, "en"), built["svg_en"])
        _write_one(out, feeds.badge_relpath(key, "ko"), built["svg_ko"])
        n += 2
    return n


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Write depweather README badges from data/latest.json")
    p.add_argument("--latest", type=Path, default=ROOT / "data" / "latest.json")
    p.add_argument("--out", type=Path, default=ROOT, help="Site root. Writes <out>/badge/")
    args = p.parse_args(argv)
    data = json.loads(args.latest.read_text(encoding="utf-8"))
    n = write_badges(data, args.out)
    print(f"wrote {n} badge files under {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
