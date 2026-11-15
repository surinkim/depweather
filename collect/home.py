#!/usr/bin/env python3
"""Write the home page in English and Korean from index.html.

    <out>/index.html      English  (https://depweather.com/)
    <out>/ko/index.html   Korean   (https://depweather.com/ko/)

index.html in the repository is the template and still works on its own
(English). The text for each language comes from the page's own I18N table
(read with collect/i18n_eval.js, so the browser and the build share one
source) and from data-ko-<attr> markers in <head>. collect/localize.py
writes it into the markup, so each file is served with its own <html lang>,
title, description, og:* tags, canonical and hreflang links.

The summary line (#meta), the numbers row (#stats) and the footer version
(#build) are also filled from data/latest.json with the same I18N strings
and markup as renderMeta() and renderStats() in the page, so the first
paint shows "149 packages, 12 affected, 12 new in KEV, made <time>" instead
of "Loading data…". The treemap and the other views are still drawn by the
page's script.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collect"))

from localize import localize  # noqa: E402

LANGS = ("en", "ko")


def eval_i18n(template: Path, calls: list | None = None) -> dict:
    """Run collect/i18n_eval.js: {"strings": {lang: {key: text}}, "calls": [...]}."""
    r = subprocess.run(
        ["node", str(ROOT / "collect" / "i18n_eval.js"), str(template)],
        input=json.dumps(calls or []), capture_output=True, text=True, check=False,
    )
    if r.returncode != 0:
        raise RuntimeError(f"i18n_eval.js failed: {r.stderr.strip()}")
    return json.loads(r.stdout)


def strings_for(strings: dict, lang: str) -> dict:
    """t() in the page: the language's text, else English."""
    merged = dict(strings.get("en") or {})
    merged.update(strings.get(lang) or {})
    return merged


def render_home(template_text: str, strings: dict, lang: str,
                replace_text: dict | None = None, replace_html: dict | None = None) -> str:
    if lang not in LANGS:
        raise ValueError(f"bad page language: {lang!r}")
    text = strings_for(strings, lang)
    return localize(
        template_text, lang,
        strings=text,
        # data-i18n-html sections keep the English written in the HTML when the
        # table has no entry, as applyStaticText() does.
        html_strings=text,
        replace_text=replace_text,
        replace_html=replace_html,
        root_attrs={"lang": lang},
    )


def _fmt(n: object) -> str | None:
    """fmt() in the page: toLocaleString("en-US") for integers."""
    if isinstance(n, bool) or not isinstance(n, (int, float)):
        return None
    return f"{int(n):,}" if float(n).is_integer() else f"{n:,}"


def _gen_stamp(generated_at: str) -> str:
    """'2026-11-14T22:24:37Z' -> '2026-11-14 22:24' (UTC), as renderMeta() shows it."""
    from datetime import datetime, timezone
    dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00")).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M")


def page_build(template_text: str) -> str | None:
    m = re.search(r'^const BUILD = "([^"]+)";', template_text, re.M)
    return m.group(1) if m else None


def summary_calls(data: dict, lang: str, build: str | None) -> tuple[list, dict]:
    """I18N calls for the prerendered parts, and how to put the answers together."""
    s = data.get("summary") or {}
    gen = _gen_stamp(str(data["generated_at"]))
    calls: list = [
        [lang, "meta", gen, s.get("tracked_packages"), len(data.get("ecosystems") or [])],
        [lang, "rd_kev"],
        [lang, "rd_aff", s.get("tracked_packages")],
        [lang, "rd_today"],
        [lang, "rd_month", s.get("month")],
    ]
    plan = {"meta": 0, "rd_kev": 1, "rd_aff": 2, "rd_today": 3, "rd_month": 4}
    month, last = s.get("month_cves"), s.get("month_cves_last_year")
    if month is not None and last and isinstance(s.get("month"), str):
        # Math.round in the page rounds .5 up.
        pct = math.floor((month / last - 1) * 100 + 0.5)
        ym = f"{int(s['month'][:4]) - 1}-{s['month'][5:]}"
        plan["yoy"] = len(calls)
        calls.append([lang, "st_yoy", f"{'+' if pct >= 0 else ''}{pct}%", ym, _fmt(last)])
    if build:
        plan["build"] = len(calls)
        calls.append([lang, "build", build, gen])
    return calls, plan


def _stat(value: str | int | None, label: str, sub: str = "") -> str:
    """item() in renderStats()."""
    if value is None:
        return ""
    e = lambda v: html.escape(str(v), quote=True)  # noqa: E731
    sub_html = f'<span class="sub">{e(sub)}</span>' if sub else ""
    return (f'<div class="stat"><span class="value">{e(value)}</span>'
            f'<span class="label">{e(label)}</span>{sub_html}</div>')


def prerender(data: dict, answers: list, plan: dict) -> tuple[dict, dict]:
    """(replace_text, replace_html) for localize()."""
    s = data.get("summary") or {}
    get = lambda k: answers[plan[k]] if k in plan else ""  # noqa: E731
    stats = (
        _stat(_fmt(s.get("kev_new_7d")), get("rd_kev"))
        + _stat(s.get("affected_packages_7d"), get("rd_aff"))
        + _stat(_fmt(s.get("today_cves")), get("rd_today"))
        + _stat(_fmt(s.get("month_cves")), get("rd_month"), get("yoy"))
    )
    text = {"meta": get("meta")}
    if "build" in plan:
        text["build"] = get("build")
    return text, {"stats": stats}


def write_home(template: Path, out: Path, data: dict | None = None) -> list[Path]:
    """Write <out>/index.html and <out>/ko/index.html. ``data`` is latest.json, or None
    to leave the summary to the page's script."""
    template_text = template.read_text(encoding="utf-8")
    build = page_build(template_text)
    calls: list = []
    plans: dict = {}
    if data is not None:
        for lang in LANGS:
            lang_calls, plan = summary_calls(data, lang, build)
            plans[lang] = {k: v + len(calls) for k, v in plan.items()}
            calls += lang_calls
    result = eval_i18n(template, calls)
    written = []
    for lang in LANGS:
        dest = out / ("ko/index.html" if lang == "ko" else "index.html")
        if dest.resolve() == template.resolve():
            raise ValueError("refusing to overwrite the template; pass --out")
        replace_text, replace_html = (
            prerender(data, result["calls"], plans[lang]) if data is not None else ({}, {})
        )
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            render_home(template_text, result["strings"], lang, replace_text, replace_html),
            encoding="utf-8",
        )
        written.append(dest)
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Write the English and Korean home pages")
    p.add_argument("--template", type=Path, default=ROOT / "index.html")
    p.add_argument("--latest", type=Path, default=ROOT / "data" / "latest.json")
    p.add_argument("--out", type=Path, required=True, help="Site root (not the repository)")
    args = p.parse_args(argv)
    data = json.loads(args.latest.read_text(encoding="utf-8"))
    written = write_home(args.template, args.out, data)
    print("wrote " + ", ".join(str(w) for w in written), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
