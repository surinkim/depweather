#!/usr/bin/env python3
"""README badges: slug, window, colors, escaping, snippets, both languages."""

from __future__ import annotations

import html
import json
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collect"))

import badges  # noqa: E402
import feeds  # noqa: E402
import pages  # noqa: E402

SVG = "http://www.w3.org/2000/svg"


def generated_iso(days_ago: int) -> str:
    dt = datetime(2026, 11, 2, tzinfo=timezone.utc) - timedelta(days=days_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def fixture() -> dict:
    recent = generated_iso(3)
    old = generated_iso(20)
    return {
        "generated_at": "2026-11-02T00:00:00Z",
        "ecosystems": [
            {
                "id": "npm",
                "label": "npm",
                "packages": [
                    {
                        "key": "npm/next",
                        "name": "next",
                        "label": 'a<b>&"c</script>',
                        "vulns": [
                            {
                                "id": "GHSA-crit",
                                "severity": "CRITICAL",
                                "published": recent,
                                "kev": False,
                            },
                            {
                                "id": "GHSA-kev",
                                "severity": "HIGH",
                                "published": recent,
                                "kev": True,
                                "kev_date_added": "2026-11-01",
                            },
                            {
                                "id": "GHSA-old",
                                "severity": "LOW",
                                "published": old,
                                "kev": False,
                            },
                        ],
                    },
                    {
                        "key": "npm/@angular/core",
                        "name": "@angular/core",
                        "label": "Angular",
                        "vulns": [],
                    },
                    {
                        "key": "npm/react",
                        "name": "react",
                        "label": "React",
                        "vulns": [
                            {"id": "GHSA-h1", "severity": "HIGH", "published": recent, "kev": False},
                            {"id": "GHSA-h2", "severity": "HIGH", "published": recent, "kev": False},
                            {"id": "GHSA-m", "severity": "MEDIUM", "published": recent, "kev": False},
                        ],
                    },
                    {
                        "key": "npm/foo~bar:baz",
                        "name": "foo~bar:baz",
                        "label": "Tilde",
                        "vulns": [
                            {"id": "MAL-1", "severity": "LOW", "published": recent, "kev": False, "malicious": True},
                        ],
                    },
                ],
            },
            {
                "id": "maven",
                "label": "Maven",
                "packages": [
                    {
                        "key": "maven/org.springframework.boot:spring-boot",
                        "name": "org.springframework.boot:spring-boot",
                        "label": "Spring Boot",
                        "vulns": [
                            {"id": "GHSA-low", "severity": "LOW", "published": recent, "kev": False},
                        ],
                    }
                ],
            },
            {
                "id": "pypi",
                "label": "PyPI",
                "packages": [
                    {
                        "key": "pypi/django",
                        "name": "django",
                        "label": "Django",
                        "vulns": [
                            {"id": "PYSEC-old", "severity": "CRITICAL", "published": old, "kev": False},
                        ],
                    }
                ],
            },
            {
                "id": "go",
                "label": "Go",
                "packages": [
                    {
                        "key": "go/github.com/gin-gonic/gin",
                        "name": "github.com/gin-gonic/gin",
                        "label": "Gin",
                        "vulns": [
                            {
                                "id": "GO-kev",
                                "severity": "MEDIUM",
                                "published": old,
                                "kev": True,
                                "kev_date_added": "2026-11-01",
                            },
                        ],
                    }
                ],
            },
        ],
    }


def _contrast(fg: str, bg: str) -> float:
    def lin(channel: int) -> float:
        c = channel / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    def lum(color: str) -> float:
        h = color.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)

    a, b = lum(fg), lum(bg)
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


def parse_svg(text: str) -> ET.Element:
    return ET.fromstring(text)


def fills(root: ET.Element) -> list[str]:
    return [el.attrib.get("fill", "") for el in root.iter() if el.tag == f"{{{SVG}}}rect"]


def texts(root: ET.Element) -> list[str]:
    return [el.text or "" for el in root.iter() if el.tag == f"{{{SVG}}}text"]


def links(root: ET.Element) -> list[str]:
    return [el.attrib.get("href", "") for el in root.iter() if el.tag == f"{{{SVG}}}a"]


def hrefs(text: str) -> list[str]:
    return [html.unescape(h) for h in re.findall(r'href="([^"]*)"', text)]


class BadgeTests(unittest.TestCase):
    def test_paths_match_the_page_slug_and_the_script(self):
        self.assertEqual(badges.CURRENT_DAYS, pages.CURRENT_DAYS)
        keys = [
            "npm/next",
            "npm/@angular/core",
            "maven/org.springframework.boot:spring-boot",
            "go/github.com/gin-gonic/gin",
            "packagist/symfony/http-kernel",
            "npm/foo~bar:baz",
        ]
        for key in keys:
            page = feeds.package_page_rel(key)
            stem = "badge/" + page[len("pkg/"):-1]
            self.assertEqual(feeds.badge_relpath(key), stem + ".svg")
            self.assertEqual(feeds.badge_relpath(key, "ko"), stem + ".ko.svg")
            self.assertEqual(feeds.badge_url(key), "https://depweather.com/" + stem + ".svg")
            self.assertNotIn(":", feeds.badge_relpath(key).split("badge/", 1)[1])
        with self.assertRaises(ValueError):
            feeds.badge_relpath("npm/next", "fr")
        script = (
            "const p = require('./js/pkg-path.js');"
            "for (const k of process.argv.slice(1)) {"
            "  console.log(p.pkgBadgePath(k));"
            "  console.log(p.pkgBadgePath(k, 'ko'));"
            "}"
        )
        r = subprocess.run(
            ["node", "-e", script, *keys],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        expect = []
        for key in keys:
            expect.append("/" + feeds.badge_relpath(key))
            expect.append("/" + feeds.badge_relpath(key, "ko"))
        self.assertEqual(r.stdout.strip().splitlines(), expect)

    def test_colors_stay_readable(self):
        self.assertGreaterEqual(_contrast(badges.LABEL_FG, badges.LABEL_BG), 4.5)
        for _name, (fill, ink) in badges.COLORS.items():
            self.assertGreaterEqual(_contrast(ink, fill), 4.5, _name)
        # The map's critical red with white text is a bit under 4.5 at 11px.
        self.assertLess(_contrast("#ffffff", "#d9433b"), 4.5)
        self.assertNotEqual(badges.COLORS["critical"][0], badges.COLORS["high"][0])
        self.assertNotEqual(badges.COLORS["kev"][0], badges.COLORS["critical"][0])

    def test_window_counts_kev_ahead_of_older_advisories(self):
        generated = feeds.parse_time("2026-11-02T00:00:00Z")
        recent = generated_iso(3)
        old = generated_iso(20)
        both = badges.status_of([
            {"id": "c", "severity": "CRITICAL", "published": recent},
            {"id": "h", "severity": "HIGH", "published": recent},
        ], generated)
        self.assertEqual(both["color"], "critical")
        self.assertEqual(both["en"], "1 critical, 1 high")
        self.assertEqual(both["ko"], "치명 1건, 높음 1건")
        stale = badges.status_of([
            {"id": "old", "severity": "CRITICAL", "published": old, "kev": True, "kev_date_added": "2026-10-01"},
        ], generated)
        self.assertEqual(stale["color"], "clear")
        self.assertEqual(stale["en"], "clear")

    def test_fixture_svg_escapes_and_snippets(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            n = badges.write_badges(data, out)
            self.assertEqual(n, 14)  # 7 packages, two languages
            nasty = (out / "badge" / "npm" / "next.svg").read_text(encoding="utf-8")
            self.assertNotIn("<script>", nasty)
            self.assertNotIn("<b>", nasty)
            self.assertIn("&lt;/script&gt;", nasty)
            self.assertIn("&amp;", nasty)
            root = parse_svg(nasty)
            self.assertEqual(root.attrib["role"], "img")
            self.assertIn(badges.COLORS["kev"][0], fills(root))
            self.assertIn(badges.LABEL_BG, fills(root))
            joined = " ".join(texts(root))
            self.assertIn("depweather", joined)
            self.assertIn("KEV · 1 critical, 1 high", joined)
            self.assertIn('</script>', joined)
            self.assertEqual(links(root), ["https://depweather.com/pkg/npm/next/"])
            # No element was smuggled in through the label.
            for el in root.iter():
                self.assertFalse(el.tag.endswith("script"), el.tag)
            ko = parse_svg((out / "badge" / "npm" / "next.ko.svg").read_text(encoding="utf-8"))
            self.assertIn("KEV · 치명 1건, 높음 1건", " ".join(texts(ko)))
            self.assertEqual(links(ko), ["https://depweather.com/pkg/npm/next/?lang=ko"])
            self.assertEqual(fills(ko), fills(root))

            clear = parse_svg((out / "badge" / "npm" / "@angular" / "core.svg").read_text(encoding="utf-8"))
            self.assertIn(badges.COLORS["clear"][0], fills(clear))
            self.assertIn("Angular: clear", " ".join(texts(clear)))
            clear_ko = (out / "badge" / "npm" / "@angular" / "core.ko.svg").read_text(encoding="utf-8")
            self.assertIn("Angular: 맑음", clear_ko)

            boot = out / "badge" / "maven" / "org.springframework.boot~spring-boot.svg"
            self.assertTrue(boot.is_file())
            boot_root = parse_svg(boot.read_text(encoding="utf-8"))
            self.assertIn(badges.COLORS["cloudy"][0], fills(boot_root))
            self.assertIn("Spring Boot: cloudy", " ".join(texts(boot_root)))
            self.assertEqual(
                links(boot_root),
                ["https://depweather.com/pkg/maven/org.springframework.boot~spring-boot/"],
            )

            react = parse_svg((out / "badge" / "npm" / "react.svg").read_text(encoding="utf-8"))
            self.assertIn(badges.COLORS["high"][0], fills(react))
            self.assertIn("React: 2 high", " ".join(texts(react)))
            react_ko = (out / "badge" / "npm" / "react.ko.svg").read_text(encoding="utf-8")
            self.assertIn("높음 2건", react_ko)

            django = parse_svg((out / "badge" / "pypi" / "django.svg").read_text(encoding="utf-8"))
            self.assertIn("Django: clear", " ".join(texts(django)))
            self.assertNotIn("critical", " ".join(texts(django)).lower())

            gin = parse_svg((out / "badge" / "go" / "github.com" / "gin-gonic" / "gin.svg").read_text(encoding="utf-8"))
            self.assertIn(badges.COLORS["kev"][0], fills(gin))
            self.assertIn("Gin: KEV", " ".join(texts(gin)))
            self.assertNotIn("critical", " ".join(texts(gin)))

            tilde = out / "badge" / "npm" / "foo~~bar~baz.svg"
            self.assertTrue(tilde.is_file())
            tilde_root = parse_svg(tilde.read_text(encoding="utf-8"))
            self.assertIn(badges.COLORS["critical"][0], fills(tilde_root))
            self.assertIn("Tilde: 1 critical", " ".join(texts(tilde_root)))

            first = (out / "badge" / "npm" / "next.svg").read_bytes()
            badges.write_badges(data, out)
            self.assertEqual((out / "badge" / "npm" / "next.svg").read_bytes(), first)

            pages.write_pages(data, out)
            page = (out / "pkg" / "npm" / "next" / "index.html").read_text(encoding="utf-8")
            self.assertIn('id="badge"', page)
            self.assertIn('id="badge-md"', page)
            self.assertIn('id="badge-html"', page)
            self.assertIn('data-copy="badge-md"', page)
            self.assertIn('data-copy="badge-html"', page)
            self.assertIn("README badge", page)
            self.assertIn("README 배지", page)
            self.assertIn("맑음", page)
            self.assertIn("camo", page)
            self.assertIn("복사", page)
            self.assertIn('src="/badge/npm/next.svg"', page)
            self.assertIn('data-src-ko="/badge/npm/next.ko.svg"', page)
            self.assertIn("https://depweather.com/badge/npm/next.svg", page)
            self.assertIn("https://depweather.com/badge/npm/next.ko.svg", page)
            self.assertIn("https://depweather.com/pkg/npm/next/?lang=ko", page)
            self.assertIn("KEV · 1 critical, 1 high", page)
            self.assertIn("치명 1건", page)
            self.assertIn(".snippet pre", page)
            self.assertIn("var(--ink)", page)
            self.assertIn("var(--page)", page)
            self.assertIn('data-theme="dark"', page)
            self.assertNotIn("<script>", page[page.index('id="badge"'):page.index('id="current"')])
            self.assertIn("&lt;/script&gt;", page)
            for href in hrefs(page):
                if href.startswith("/") or href.startswith("?") or href.startswith("#"):
                    continue
                self.assertIsNotNone(pages.safe_href(href), href)

    def test_real_snapshot(self):
        data = json.loads((ROOT / "data" / "latest.json").read_text(encoding="utf-8"))
        generated = feeds.parse_time(data["generated_at"])
        keys = [p["key"] for e in data["ecosystems"] for p in e["packages"]]
        self.assertGreater(len(keys), 100)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            n = badges.write_badges(data, out)
            self.assertEqual(n, len(set(keys)) * 2)
            pages.write_pages(data, out)
            for eco in data["ecosystems"]:
                for pkg in eco["packages"]:
                    key = pkg["key"]
                    for lang, message_key in (("en", "en"), ("ko", "ko")):
                        path = out / feeds.badge_relpath(key, lang)
                        self.assertTrue(path.is_file(), key)
                        self.assertTrue(path.resolve().is_relative_to(out.resolve()))
                        root = parse_svg(path.read_text(encoding="utf-8"))
                        st = badges.status_of(pkg.get("vulns") or [], generated)
                        self.assertIn(st["fill"], fills(root))
                        self.assertIn(st[message_key], " ".join(texts(root)))
                        self.assertIn("depweather", " ".join(texts(root)))
                        page = feeds.package_page_url(key)
                        if lang == "ko":
                            page += "?lang=ko"
                        self.assertEqual(links(root), [page])
                        raw = path.read_text(encoding="utf-8")
                        self.assertNotIn("<script", raw.lower())
                        self.assertNotIn("foreignObject", raw)
                    html_page = (out / (feeds.package_page_rel(key) + "index.html")).read_text(encoding="utf-8")
                    self.assertIn("/" + feeds.badge_relpath(key), html_page)
                    self.assertIn("/" + feeds.badge_relpath(key, "ko"), html_page)
            first = (out / "badge" / "npm" / "lodash.svg").read_bytes()
            badges.write_badges(data, out)
            self.assertEqual((out / "badge" / "npm" / "lodash.svg").read_bytes(), first)

    def test_docs_workflow_and_homepage_mention_the_badge(self):
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/badge/", ignore)
        workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        self.assertIn("collect/badges.py", workflow)
        test_workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
        self.assertIn("tests/test_badges.py", test_workflow)
        for name in (
            "README.md",
            "README.ko.md",
            "docs/how-it-works.md",
            "docs/how-it-works.ko.md",
            "docs/alerts.md",
            "docs/alerts.ko.md",
            "llms.txt",
        ):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("/badge/", text, name)
        for name in ("docs/how-it-works.md", "docs/how-it-works.ko.md", "README.md", "README.ko.md"):
            text = (ROOT / name).read_text(encoding="utf-8").lower()
            self.assertIn("camo", text, name)
        howto = (ROOT / "docs" / "how-it-works.md").read_text(encoding="utf-8")
        howto_ko = (ROOT / "docs" / "how-it-works.ko.md").read_text(encoding="utf-8")
        self.assertIn('id="readme-badge"', howto)
        self.assertIn('id="readme-badge"', howto_ko)
        home = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn("/badge/npm/lodash.svg", home)
        self.assertIn("/badge/npm/lodash.ko.svg", home)
        self.assertIn("how-it-works.md#readme-badge", home)
        self.assertIn("how-it-works.ko.md#readme-badge", home)


if __name__ == "__main__":
    unittest.main()
