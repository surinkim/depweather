#!/usr/bin/env python3
"""Compact daily history for the long-term trend charts.

``data/history/YYYY-MM.json`` stores counts, not copies of ``latest.json``.
Each day lists only the packages and ecosystems that had at least one
advisory. A normal month stays in the tens of kilobytes, and the daily
collect job updates the file in the same ``data/`` commit it already makes.
Full ``YYYY-MM-DD.json`` snapshots are not written anymore.

Count keys, always in this order when present:

  c  critical
  h  high
  m  medium (OSV "MODERATE" is stored as m)
  l  low
  u  unknown or unrated
  k  CISA KEV

``k`` counts advisories that are also in a severity bucket. It is a marker,
not an extra slice of the stack. An advisory is counted on its effective
date (UTC): the day it was published, or the day it was added to CISA KEV
if that is later. Several OSV records for one issue count once. An
ecosystem total counts an advisory once even when it lists several tracked
packages; each of those packages still counts it.

The chart windows are calendar-based, ending on the snapshot date:

  3M   the current month and the two before it, one bar per week
  6M   the current month and the five before it, one bar per week
  1Y   the month of the day 365 days earlier through the current month,
       one bar per month

Weeks start on Monday. The first and last bars are clipped to the window.
"""

from __future__ import annotations

import html
import json
import math
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import feeds

SCHEMA = 1
COUNT_KEYS = ("c", "h", "m", "l", "u", "k")
# Bottom of a stacked bar to the top. Critical sits on top so the worst
# color stays visible; KEV is drawn as a diamond, not a segment.
STACK_ORDER = ("u", "l", "m", "h", "c")
SEVERITY_KEY = {
    "CRITICAL": "c",
    "HIGH": "h",
    "MEDIUM": "m",
    "MODERATE": "m",
    "LOW": "l",
    "UNKNOWN": "u",
}
FILL = {
    "u": "var(--sev-unk)",
    "l": "var(--sev-low)",
    "m": "var(--sev-1)",
    "h": "var(--sev-2)",
    "c": "var(--sev-3)",
}
SEV_EN = {"c": "critical", "h": "high", "m": "medium", "l": "low", "u": "unknown"}
SEV_KO = {"c": "치명", "h": "높음", "m": "중간", "l": "낮음", "u": "미평가"}
PERIOD_EN = {"3m": "3 months", "6m": "6 months", "1y": "1 year"}
PERIOD_KO = {"3m": "3개월", "6m": "6개월", "1y": "1년"}
PERIODS = ("3m", "6m", "1y")

CHART_W = 720
CHART_H = 228
PAD_L = 36
PAD_R = 10
PAD_T = 18
PAD_B = 32

_MONTH_RE = re.compile(r"^(\d{4})-(\d{2})$")
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_LEGACY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\.json$")


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def severity_key(vuln: dict) -> str | None:
    sev = str(vuln.get("severity") or "UNKNOWN").upper()
    if sev == "NONE":
        return None
    return SEVERITY_KEY.get(sev, "u")


def compact_counts(raw: object) -> dict:
    """Positive integer counts only, in COUNT_KEYS order. Booleans are ignored."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key in COUNT_KEYS:
        value = raw.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if not math.isfinite(value):
            continue
        number = int(value)
        if number > 0:
            out[key] = number
    return out


def _day_of(vuln: dict) -> date | None:
    try:
        return feeds.effective_date(vuln).astimezone(timezone.utc).date()
    except (KeyError, TypeError, ValueError):
        return None


def aggregate_snapshot(ecosystems: list, start: date | None = None, end: date | None = None) -> dict:
    """Fold a latest.json-shaped ecosystem list into ``{day: {packages, ecosystems}}``.

    ``start`` and ``end`` are inclusive UTC dates. Days outside them are dropped.
    """
    pkg_days: dict[str, dict[str, dict]] = {}
    eco_days: dict[str, dict[str, dict]] = {}
    seen: dict[tuple[str, str], set[str]] = {}
    for eco in ecosystems or []:
        if not isinstance(eco, dict):
            continue
        eco_id = str(eco.get("id") or "")
        if not eco_id:
            continue
        for pkg in eco.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            key = pkg.get("key")
            if not isinstance(key, str) or not key:
                continue
            for vuln in pkg.get("vulns") or []:
                if not isinstance(vuln, dict):
                    continue
                day = _day_of(vuln)
                if day is None:
                    continue
                if start is not None and day < start:
                    continue
                if end is not None and day > end:
                    continue
                slot_key = severity_key(vuln)
                if slot_key is None:
                    continue
                day_s = day.isoformat()
                kev = vuln.get("kev") is True
                pkg_slot = pkg_days.setdefault(day_s, {}).setdefault(key, {k: 0 for k in COUNT_KEYS})
                pkg_slot[slot_key] += 1
                if kev:
                    pkg_slot["k"] += 1
                vid = str(vuln.get("id") or "") or f"anon-{id(vuln)}"
                seen_ids = seen.setdefault((day_s, eco_id), set())
                if vid in seen_ids:
                    continue
                seen_ids.add(vid)
                eco_slot = eco_days.setdefault(day_s, {}).setdefault(eco_id, {k: 0 for k in COUNT_KEYS})
                eco_slot[slot_key] += 1
                if kev:
                    eco_slot["k"] += 1
    out = {}
    for day in sorted(set(pkg_days) | set(eco_days)):
        body = {}
        packages = pkg_days.get(day) or {}
        ecosystems_day = eco_days.get(day) or {}
        packed = {k: compact_counts(packages[k]) for k in sorted(packages)}
        packed = {k: v for k, v in packed.items() if v}
        ecos = {k: compact_counts(ecosystems_day[k]) for k in sorted(ecosystems_day)}
        ecos = {k: v for k, v in ecos.items() if v}
        if packed:
            body["packages"] = packed
        if ecos:
            body["ecosystems"] = ecos
        if body:
            out[day] = body
    return out


def normalize_day(body: object) -> dict:
    if not isinstance(body, dict):
        return {}
    out = {}
    for section in ("packages", "ecosystems"):
        src = body.get(section)
        if not isinstance(src, dict):
            continue
        cleaned = {}
        for key in sorted(src):
            if not isinstance(key, str) or not key or len(key) > 300:
                continue
            counts = compact_counts(src[key])
            if counts:
                cleaned[key] = counts
        if cleaned:
            out[section] = cleaned
    return out


def list_month_names(directory: Path) -> list[str]:
    if not directory.is_dir():
        return []
    names = []
    for path in directory.glob("*.json"):
        match = _MONTH_RE.match(path.stem)
        if not match:
            continue
        month = int(match.group(2))
        if 1 <= month <= 12:
            names.append(path.stem)
    return sorted(names)


def read_month(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"history file is not an object: {path}")
    schema = doc.get("schema", SCHEMA)
    if schema != SCHEMA:
        raise ValueError(f"unsupported history schema {schema} in {path}")
    days = doc.get("days") or {}
    if not isinstance(days, dict):
        raise ValueError(f"history days is not an object: {path}")
    return days


def write_month(path: Path, month: str, days: dict) -> None:
    ordered = {day: days[day] for day in sorted(days)}
    doc = {"schema": SCHEMA, "month": month, "days": ordered}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def write_manifest(directory: Path) -> None:
    doc = {"schema": SCHEMA, "months": list_month_names(directory)}
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "manifest.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")


def load_days(directory: Path) -> dict:
    """Every stored day, later files overriding earlier ones (months do not overlap)."""
    days: dict[str, dict] = {}
    for month in list_month_names(directory):
        for day, body in read_month(directory / f"{month}.json").items():
            if not isinstance(day, str) or not _DAY_RE.match(day) or not day.startswith(month):
                continue
            cleaned = normalize_day(body)
            if cleaned:
                days[day] = cleaned
    return days


def load_for_pages(directory: Path) -> dict | None:
    """Day map for page generation, or None when history has not been collected."""
    if not directory.is_dir() or not list_month_names(directory):
        return None
    return load_days(directory)


def remove_legacy_snapshots(directory: Path) -> list[Path]:
    """Delete full ``YYYY-MM-DD.json`` copies of latest.json left by older runs."""
    removed = []
    if not directory.is_dir():
        return removed
    for path in sorted(directory.iterdir()):
        if path.is_file() and _LEGACY_RE.match(path.name):
            path.unlink()
            removed.append(path)
    return removed


def _parse_day(value: str) -> date | None:
    if not _DAY_RE.match(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def apply_days(directory: Path, new_days: dict, start: date, end: date) -> None:
    """Replace every day in ``[start, end]`` and leave days outside it alone.

    An empty replacement deletes that day, so a withdrawn advisory drops out
    of a day the collector can still see. Months that become empty are removed.
    """
    if end < start:
        raise ValueError("history window ends before it starts")
    directory.mkdir(parents=True, exist_ok=True)
    incoming: dict[str, dict] = {}
    for day, body in (new_days or {}).items():
        parsed = _parse_day(day) if isinstance(day, str) else None
        if parsed is None or parsed < start or parsed > end:
            continue
        cleaned = normalize_day(body)
        if cleaned:
            incoming[day] = cleaned

    cursor = date(start.year, start.month, 1)
    last = date(end.year, end.month, 1)
    while cursor <= last:
        month = f"{cursor.year:04d}-{cursor.month:02d}"
        path = directory / f"{month}.json"
        existing: dict = {}
        if path.is_file():
            existing = read_month(path)
        kept = {}
        for day, body in existing.items():
            parsed = _parse_day(day) if isinstance(day, str) else None
            if parsed is None:
                continue
            if start <= parsed <= end:
                continue
            cleaned = normalize_day(body)
            if cleaned:
                kept[day] = cleaned
        for day, body in incoming.items():
            if day[:7] == month:
                kept[day] = body
        if kept:
            write_month(path, month, kept)
        elif path.is_file():
            path.unlink()
        if cursor.month == 12:
            cursor = date(cursor.year + 1, 1, 1)
        else:
            cursor = date(cursor.year, cursor.month + 1, 1)
    write_manifest(directory)


def complete_window(now: datetime, window_days: int) -> tuple[date, date]:
    """UTC dates the daily snapshot fully covers.

    The collector's window is ``now - window_days``, a timestamp. The calendar
    day that contains that instant is only partly included, so it is left to
    the backfill (or to the next run, once the whole day is inside the window).
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    since = now - timedelta(days=window_days)
    start = since.date()
    if (since.hour, since.minute, since.second, since.microsecond) != (0, 0, 0, 0):
        start = start + timedelta(days=1)
    end = now.date()
    if start > end:
        start = end
    return start, end


def apply_window(directory: Path, ecosystems: list, now: datetime, window_days: int) -> tuple[date, date]:
    start, end = complete_window(now, window_days)
    days = aggregate_snapshot(ecosystems, start, end)
    apply_days(directory, days, start, end)
    return start, end


def months_start(as_of: date, months: int) -> date:
    """First day of a window of ``months`` calendar months, including ``as_of``'s month."""
    if months < 1:
        raise ValueError("months must be at least 1")
    index = as_of.year * 12 + (as_of.month - 1) - (months - 1)
    return date(index // 12, index % 12 + 1, 1)


def period_start(as_of: date, period: str) -> date:
    if period == "1y":
        prev = as_of - timedelta(days=365)
        return date(prev.year, prev.month, 1)
    if period == "3m":
        return months_start(as_of, 3)
    if period == "6m":
        return months_start(as_of, 6)
    raise ValueError(f"unknown trend period: {period}")


def build_buckets(as_of: date, period: str) -> list[dict]:
    """Inclusive buckets from the period start through ``as_of``.

    1Y is one bucket per calendar month. 3M and 6M are Monday-Sunday weeks,
    clipped to the window. ``label`` is ``YYYY-MM`` or the week start date.
    """
    start = period_start(as_of, period)
    end = as_of
    if start > end:
        start = end
    unit = "month" if period == "1y" else "week"
    out = []
    if unit == "month":
        cursor = date(start.year, start.month, 1)
        while cursor <= end:
            if cursor.month == 12:
                nxt = date(cursor.year + 1, 1, 1)
            else:
                nxt = date(cursor.year, cursor.month + 1, 1)
            bucket_end = min(end, nxt - timedelta(days=1))
            bucket_start = cursor if cursor >= start else start
            out.append({
                "start": bucket_start.isoformat(),
                "end": bucket_end.isoformat(),
                "label": f"{cursor.year:04d}-{cursor.month:02d}",
                "unit": unit,
            })
            cursor = nxt
        return out
    cursor = start
    while cursor <= end:
        sunday = cursor + timedelta(days=(6 - cursor.weekday()))
        bucket_end = min(end, sunday)
        out.append({
            "start": cursor.isoformat(),
            "end": bucket_end.isoformat(),
            "label": cursor.isoformat(),
            "unit": unit,
        })
        cursor = bucket_end + timedelta(days=1)
    return out


def sum_buckets(day_counts: dict, buckets: list[dict]) -> list[dict]:
    rows = []
    items = []
    for day, counts in (day_counts or {}).items():
        if isinstance(day, str) and _DAY_RE.match(day):
            items.append((day, compact_counts(counts)))
    for bucket in buckets:
        acc = {k: 0 for k in COUNT_KEYS}
        for day, counts in items:
            if bucket["start"] <= day <= bucket["end"]:
                for key in COUNT_KEYS:
                    acc[key] += counts.get(key, 0)
        rows.append({**bucket, "counts": acc})
    return rows


def grand_total(rows: list[dict]) -> dict:
    acc = {k: 0 for k in COUNT_KEYS}
    for row in rows:
        for key in COUNT_KEYS:
            acc[key] += int(row["counts"].get(key, 0))
    return acc


def severity_total(counts: dict) -> int:
    return sum(int(counts.get(key, 0)) for key in STACK_ORDER)


def counts_phrase(counts: dict, lang: str) -> str:
    names = SEV_KO if lang == "ko" else SEV_EN
    parts = [f"{names[key]} {int(counts.get(key, 0))}" for key in ("c", "h", "m", "l", "u")]
    return ", ".join(parts) + f". KEV {int(counts.get('k', 0))}."


def summary_text(label: str, period: str, counts: dict, lang: str) -> str:
    span = PERIOD_KO[period] if lang == "ko" else PERIOD_EN[period]
    if lang == "ko":
        return f"{label}, {span}, 심각도별 누적. {counts_phrase(counts, lang)}"
    return f"{label}, {span}, stacked by severity. {counts_phrase(counts, lang)}"


def nice_max(n: int) -> int:
    if n <= 1:
        return 1
    if n <= 4:
        return n
    mag = 10 ** int(math.floor(math.log10(n)))
    for mult in (1, 2, 5, 10):
        if mult * mag >= n:
            return mult * mag
    return 10 * mag


def axis_ticks(top: int) -> list[int]:
    if top <= 4:
        return list(range(0, top + 1))
    if top % 4 == 0:
        step = top // 4
    elif top % 2 == 0:
        step = top // 2
    else:
        step = top
    return list(range(0, top + 1, step))


def _num(value: float) -> str:
    text = f"{value:.1f}"
    return text[:-2] if text.endswith(".0") else text


def _slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return (slug or "trend")[:60]


def _label_indexes(count: int) -> set[int]:
    if count <= 16:
        step = 1
    elif count <= 24:
        step = 2
    else:
        step = 4
    return {i for i in range(count) if i % step == 0 or i == count - 1}


def _axis_label(row: dict) -> str:
    if row.get("unit") == "month":
        label = str(row.get("label") or row["start"])
        return label[2:] if len(label) >= 7 else label
    return str(row["start"])[5:]


def package_day_counts(days: dict | None, key: str) -> dict | None:
    if days is None:
        return None
    out = {}
    for day, body in days.items():
        if not isinstance(body, dict):
            continue
        counts = compact_counts((body.get("packages") or {}).get(key))
        if counts:
            out[day] = counts
    return out


def render_svg(rows: list[dict], summary_en: str, summary_ko: str, dom_id: str) -> str:
    """One stacked-bar SVG. Text from data is escaped. Colors are CSS variables."""
    title_id = f"trend-title-{dom_id}"
    desc_id = f"trend-desc-{dom_id}"
    top = nice_max(max((severity_total(row["counts"]) for row in rows), default=0))
    plot_w = CHART_W - PAD_L - PAD_R
    plot_h = CHART_H - PAD_T - PAD_B
    base = CHART_H - PAD_B
    parts = [
        f'<svg class="trend-svg" viewBox="0 0 {CHART_W} {CHART_H}" width="100%" role="img" '
        f'aria-labelledby="{title_id} {desc_id}">',
        f'<title id="{title_id}" data-en="{esc(summary_en)}" data-ko="{esc(summary_ko)}">{esc(summary_en)}</title>',
        f'<desc id="{desc_id}" data-en="{esc(summary_en)}" data-ko="{esc(summary_ko)}">{esc(summary_en)}</desc>',
    ]
    for tick in axis_ticks(top):
        y = base - (plot_h * tick / top)
        parts.append(
            f'<line x1="{PAD_L}" x2="{CHART_W - PAD_R}" y1="{_num(y)}" y2="{_num(y)}" '
            f'stroke="{"var(--axis)" if tick == 0 else "var(--grid)"}" stroke-width="1"></line>'
        )
        parts.append(
            f'<text x="{PAD_L - 6}" y="{_num(y + 4)}" font-size="11" fill="var(--muted)" '
            f'text-anchor="end">{tick}</text>'
        )
    n = max(1, len(rows))
    slot = plot_w / n
    gap = min(4.0, slot * 0.28)
    bar_w = max(1.0, slot - gap)
    show = _label_indexes(len(rows))
    total = severity_total(grand_total(rows)) if rows else 0
    for index, row in enumerate(rows):
        x = PAD_L + index * slot + (slot - bar_w) / 2
        counts = row["counts"]
        height_used = 0.0
        y_top = float(base)
        segments = []
        for key in STACK_ORDER:
            count = int(counts.get(key, 0))
            if count <= 0:
                continue
            h = plot_h * count / top
            y = base - height_used - h
            height_used += h
            y_top = y
            segments.append(
                f'<rect x="{_num(x)}" y="{_num(y)}" width="{_num(bar_w)}" height="{_num(max(h, 0.8))}" '
                f'fill="{FILL[key]}"><title>{esc(SEV_EN[key])} {count}</title></rect>'
            )
        en = f"{row['start']} – {row['end']}: {counts_phrase(counts, 'en')}"
        ko = f"{row['start']} – {row['end']}: {counts_phrase(counts, 'ko')}"
        parts.append(f'<g><title data-en="{esc(en)}" data-ko="{esc(ko)}">{esc(en)}</title>')
        parts.extend(segments)
        kev = int(counts.get("k", 0))
        if kev > 0:
            cx = x + bar_w / 2
            cy = y_top - 7
            r = 4.5
            if cy - r < 2:
                cy = r + 2
            diamond = (
                f"M{_num(cx)} {_num(cy - r)}L{_num(cx + r)} {_num(cy)}"
                f"L{_num(cx)} {_num(cy + r)}L{_num(cx - r)} {_num(cy)}Z"
            )
            parts.append(
                f'<path class="kev-mark" d="{diamond}" fill="var(--sev-kev)" '
                f'stroke="var(--surface)" stroke-width="1"><title>KEV {kev}</title></path>'
            )
        parts.append("</g>")
        if index in show:
            anchor = "start" if index == 0 else "end" if index == len(rows) - 1 else "middle"
            lx = x if index == 0 else x + bar_w if index == len(rows) - 1 else x + bar_w / 2
            parts.append(
                f'<text x="{_num(lx)}" y="{CHART_H - 10}" font-size="11" fill="var(--muted)" '
                f'text-anchor="{anchor}">{esc(_axis_label(row))}</text>'
            )
    if total == 0:
        empty_en = "No advisories in this period"
        empty_ko = "이 기간에 권고가 없습니다"
        parts.append(
            f'<text x="{CHART_W / 2}" y="{PAD_T + plot_h / 2}" font-size="13" fill="var(--muted)" '
            f'text-anchor="middle" data-en="{empty_en}" data-ko="{empty_ko}">{empty_en}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def render_table(rows: list[dict], summary_en: str, summary_ko: str) -> str:
    heads = [
        ("Period", "기간", ""),
        ("Critical", "치명", " num"),
        ("High", "높음", " num"),
        ("Medium", "중간", " num"),
        ("Low", "낮음", " num"),
        ("Unknown", "미평가", " num"),
        ("KEV", "KEV", " num"),
    ]
    ths = []
    for en, ko, cls in heads:
        attr = f' class="{cls.strip()}"' if cls else ""
        shown = en if en != "KEV" else "KEV"
        ths.append(f'<th{attr} data-en="{esc(en)}" data-ko="{esc(ko)}">{esc(shown)}</th>')
    body = []
    for row in rows:
        counts = row["counts"]
        label = row["label"] if row.get("unit") == "month" else f"{row['start']} – {row['end']}"
        cells = [f'<th scope="row">{esc(label)}</th>']
        for key in ("c", "h", "m", "l", "u", "k"):
            cells.append(f'<td class="num">{int(counts.get(key, 0))}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    return (
        '<div class="scroll-x"><table class="data trend-table">'
        f'<caption data-en="{esc(summary_en)}" data-ko="{esc(summary_ko)}">{esc(summary_en)}</caption>'
        f'<thead><tr>{"".join(ths)}</tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table></div>'
    )


def _legend() -> str:
    items = [
        ("c", "Critical", "치명"),
        ("h", "High", "높음"),
        ("m", "Medium", "중간"),
        ("l", "Low", "낮음"),
        ("u", "Unknown", "미평가"),
    ]
    lis = []
    for key, en, ko in items:
        lis.append(
            f'<li><i class="swatch {key}"></i>'
            f'<span data-en="{en}" data-ko="{ko}">{en}</span></li>'
        )
    lis.append('<li><i class="kev"></i><span>KEV</span></li>')
    return '<ul class="trend-legend">' + "".join(lis) + "</ul>"


def render_trend_section(label: str, day_counts: dict | None, as_of: date, dom_id: str) -> str:
    """The package-page block: period switch, three SVGs, and a number table for each.

    ``day_counts is None`` means history has not been collected. An empty dict
    means it has, and this package had no advisories in the files.
    """
    heading = (
        '<div class="trend-head">'
        '<h2 data-en="Longer trend" data-ko="장기 추이">Longer trend</h2>'
    )
    note = (
        '<p class="note" data-en="Weekly bars for 3 months and 6 months, monthly bars for 1 year. '
        'Stacked bottom to top: unknown, low, medium, high, critical. A magenta diamond marks '
        'CISA KEV in that bar. KEV is already inside the stack, not an extra slice. '
        'An advisory counts on the day it was published, or on the day it was added to KEV if that is later." '
        'data-ko="3개월·6개월은 주 단위, 1년은 월 단위입니다. 아래부터 미평가, 낮음, 중간, 높음, 치명 순으로 쌓입니다. '
        '마젠타 마름모는 그 막대의 CISA KEV입니다. KEV는 스택 안의 권고이지 추가 칸이 아닙니다. '
        '권고가 공개된 날, KEV 등재가 더 늦으면 그 날을 기준으로 셉니다.">'
        'Weekly bars for 3 months and 6 months, monthly bars for 1 year. '
        'Stacked bottom to top: unknown, low, medium, high, critical. A magenta diamond marks '
        'CISA KEV in that bar. KEV is already inside the stack, not an extra slice. '
        'An advisory counts on the day it was published, or on the day it was added to KEV if that is later.'
        '</p>'
    )
    if day_counts is None:
        return (
            '<section class="panel" id="trend">'
            + heading + "</div>"
            + '<p class="empty" data-en="Long-term counts have not been collected yet." '
            'data-ko="아직 장기 추이 데이터가 없습니다.">Long-term counts have not been collected yet.</p>'
            "</section>"
        )
    buttons = []
    for period, visible, en, ko in (
        ("3m", "3M", "3 months", "3개월"),
        ("6m", "6M", "6 months", "6개월"),
        ("1y", "1Y", "1 year", "1년"),
    ):
        pressed = "true" if period == "6m" else "false"
        buttons.append(
            f'<button type="button" data-trend="{period}" aria-pressed="{pressed}" '
            f'data-aria-en="{en}" data-aria-ko="{ko}">{visible}</button>'
        )
    controls = (
        '<div class="seg" role="group" data-aria-en="Trend period" data-aria-ko="추이 기간" '
        'aria-label="Trend period">' + "".join(buttons) + "</div></div>"
    )
    panels = []
    for period in PERIODS:
        rows = sum_buckets(day_counts, build_buckets(as_of, period))
        totals = grand_total(rows)
        summary_en = summary_text(label, period, totals, "en")
        summary_ko = summary_text(label, period, totals, "ko")
        hidden = "" if period == "6m" else " hidden"
        svg = render_svg(rows, summary_en, summary_ko, f"{_slug(dom_id)}-{period}")
        table = render_table(rows, summary_en, summary_ko)
        panels.append(
            f'<div class="trend-panel" data-trend-panel="{period}"{hidden}>'
            f"{svg}"
            '<details class="trend-fallback">'
            '<summary data-en="Numbers for this chart" data-ko="이 그래프의 숫자">Numbers for this chart</summary>'
            f"{table}</details></div>"
        )
    return (
        '<section class="panel" id="trend">'
        + heading + controls + note + _legend() + "".join(panels)
        + "</section>"
    )
