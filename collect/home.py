#!/usr/bin/env python3
"""Write the home page in English and Korean from index.html.

    <out>/index.html      English  (https://depweather.com/)
    <out>/ko/index.html   Korean   (https://depweather.com/ko/)

index.html in the repository is the template and still works on its own
(English). The text for each language comes from the page's own I18N table
(read with collect/i18n_eval.js, so the browser and the build share one
source) and from data-ko-<attr> markers in <head>. collect/localize.py
writes it into the markup, so each file is served with its own <html lang>,
title, description, og:* tags, canonical and hreflang links. The map itself
is still drawn by the page's script from data/latest.json.
"""

from __future__ import annotations

import argparse
import json
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


def write_home(template: Path, out: Path) -> list[Path]:
    template_text = template.read_text(encoding="utf-8")
    result = eval_i18n(template)
    written = []
    for lang in LANGS:
        dest = out / ("ko/index.html" if lang == "ko" else "index.html")
        if dest.resolve() == template.resolve():
            raise ValueError("refusing to overwrite the template; pass --out")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(render_home(template_text, result["strings"], lang), encoding="utf-8")
        written.append(dest)
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Write the English and Korean home pages")
    p.add_argument("--template", type=Path, default=ROOT / "index.html")
    p.add_argument("--out", type=Path, required=True, help="Site root (not the repository)")
    args = p.parse_args(argv)
    written = write_home(args.template, args.out)
    print("wrote " + ", ".join(str(w) for w in written), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
