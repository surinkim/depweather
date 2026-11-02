#!/usr/bin/env python3
"""Static package pages: paths, escaping, allowlisted links, both languages, sitemap."""

from __future__ import annotations

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

import feeds  # noqa: E402
import pages  # noqa: E402

NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}


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
                        "label": "Next.js",
                        "vulns": [
                            {
                                "id": "GHSA-bad",
                                "summary": 'RCE <img src=x onerror=alert(1)> & "q" </script><script>alert(1)',
                                "severity": "CRITICAL",
                                "published": recent,
                                "url": "javascript:alert(1)",
                                "fixed": ["1.0</b>", "2.0"],
                                "kev": False,
                                "cves": ["CVE-2026-1", "not a cve"],
                            },
                            {
                                "id": "GHSA-ok",
                                "summary": "auth bypass",
                                "severity": "HIGH",
                                "published": recent,
                                "url": "https://osv.dev/vulnerability/GHSA-ok",
                                "fixed": ["16.0.1"],
                                "kev": True,
                                "kev_date_added": "2026-11-01",
                                "epss": 0.99999,
                                "cvss": 9.8,
                                "cves": ["CVE-2026-10001"],
                            },
                            {
                                "id": "GHSA-evil",
                                "summary": "ignore this link",
                                "severity": "LOW",
                                "published": old,
                                "url": "https://evil.example/advisory",
                                "fixed": [],
                                "kev": False,
                            },
                            {
                                "id": "GHSA-user",
                                "summary": "credentials in the url",
                                "severity": "LOW",
                                "published": old,
                                "url": "https://user:pass@osv.dev/vulnerability/GHSA-user",
                                "fixed": [],
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
                        "vulns": [],
                    }
                ],
            },
        ],
    }


def hrefs(text: str) -> list[str]:
    return [html_unescape(h) for h in re.findall(r'href="([^"]*)"', text)]


def html_unescape(value: str) -> str:
    import html
    return html.unescape(value)


class PageTests(unittest.TestCase):
    def test_paths_match_the_feed_slug(self):
        keys = [
            "npm/next",
            "npm/@angular/core",
            "maven/org.springframework.boot:spring-boot",
            "go/github.com/gin-gonic/gin",
            "packagist/symfony/http-kernel",
        ]
        for key in keys:
            feed = feeds.feed_relpath(key)
            page = feeds.package_page_rel(key)
            self.assertTrue(page.endswith("/"))
            self.assertEqual("pkg/" + feed[len("feed/"):-len(".xml")] + "/", page)
            self.assertEqual(feeds.package_page_url(key), "https://depweather.com/" + page)

    def test_paths_match_the_action(self):
        keys = [
            "npm/next",
            "npm/@angular/core",
            "maven/org.springframework.boot:spring-boot",
            "go/github.com/gin-gonic/gin",
        ]
        script = (
            "const c = require('./alert/check.js');"
            "for (const k of process.argv.slice(1)) console.log(c.packagePageUrl(k));"
        )
        r = subprocess.run(
            ["node", "-e", script, *keys],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        self.assertEqual(r.stdout.strip().splitlines(), [feeds.package_page_url(k) for k in keys])

    def test_allowlist_matches_the_action(self):
        text = (ROOT / "alert" / "check.js").read_text(encoding="utf-8")
        m = re.search(r"const ALLOWED_LINK_HOSTS = new Set\(\[(.*?)\]\);", text, re.S)
        self.assertIsNotNone(m)
        hosts = set(re.findall(r'"([^"]+)"', m.group(1)))
        self.assertEqual(hosts, set(pages.ALLOWED_LINK_HOSTS))
        self.assertIsNone(pages.safe_href("javascript:alert(1)"))
        self.assertIsNone(pages.safe_href("http://osv.dev/vulnerability/GHSA-ok"))
        self.assertIsNone(pages.safe_href("https://user:pass@osv.dev/x"))
        self.assertIsNone(pages.safe_href("https://osv.dev.evil.example/x"))
        self.assertIsNone(pages.safe_href("https://evil.example/advisory"))
        self.assertEqual(
            pages.safe_href("https://osv.dev/vulnerability/GHSA-ok"),
            "https://osv.dev/vulnerability/GHSA-ok",
        )

    def test_fixture_page_escapes_links_and_languages(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            n = pages.write_pages(data, out)
            self.assertEqual(n, 3)
            page = (out / "pkg" / "npm" / "next" / "index.html").read_text(encoding="utf-8")
            self.assertIn("<title>Next.js (npm) vulnerabilities — depweather</title>", page)
            self.assertIn('data-title-ko="Next.js (npm) 취약점 — depweather"', page)
            self.assertIn('lang="ko" content="Next.js (npm) 취약점:', page)
            self.assertIn("in CISA KEV", page)
            self.assertIn("99.9%", page)
            self.assertIn("16.0.1", page)
            self.assertIn("KEV 2026-11-01", page)
            self.assertIn("https://osv.dev/vulnerability/GHSA-ok", page)
            self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2026-10001", page)
            self.assertIn('href="/feed/npm/next.xml"', page)
            self.assertIn('id="back" href="/"', page)
            self.assertIn('rel="canonical" href="https://depweather.com/pkg/npm/next/"', page)
            self.assertIn('hreflang="ko" href="https://depweather.com/pkg/npm/next/?lang=ko"', page)
            self.assertIn("depweather:prefs", page)
            self.assertIn('id="theme"', page)
            self.assertIn('data-lang="ko"', page)
            self.assertIn('data-theme="dark"', page)
            self.assertIn("지도로 돌아가기", page)
            self.assertIn("RCE &lt;img src=x onerror=alert(1)&gt;", page)
            self.assertNotIn("<img src=x", page)
            self.assertNotIn("href=\"javascript:", page)
            self.assertNotIn("evil.example", page)
            self.assertNotIn("user:pass", page)
            self.assertNotIn("not a cve", page)
            # The id is still visible when its URL is rejected.
            self.assertIn("GHSA-bad", page)
            self.assertIn("GHSA-evil", page)
            for href in hrefs(page):
                if href.startswith("/") or href.startswith("?") or href.startswith("#"):
                    continue
                self.assertIsNotNone(pages.safe_href(href), href)
            ld = re.search(r'<script type="application/ld\+json">\s*(.*?)\s*</script>', page, re.S)
            self.assertIsNotNone(ld)
            graph = json.loads(ld.group(1))
            types = [node["@type"] for node in graph["@graph"]]
            self.assertIn("WebPage", types)
            self.assertIn("BreadcrumbList", types)
            self.assertIn("ItemList", types)
            self.assertNotIn("<script", ld.group(1))
            self.assertIn("GHSA-ok", ld.group(1))

            angular = out / "pkg" / "npm" / "@angular" / "core" / "index.html"
            self.assertTrue(angular.is_file())
            boot = out / "pkg" / "maven" / "org.springframework.boot~spring-boot" / "index.html"
            self.assertTrue(boot.is_file())
            self.assertIn("No advisories in the last 7 days.", angular.read_text(encoding="utf-8"))

            base = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
            sm = pages.render_sitemap(data, base)
            self.assertEqual(pages.render_sitemap(data, sm), sm)
            root = ET.fromstring(sm)
            locs = [el.text for el in root.findall("sm:url/sm:loc", NS)]
            self.assertIn("https://depweather.com/", locs)
            self.assertIn("https://depweather.com/?lang=ko", locs)
            self.assertIn("https://depweather.com/feed.xml", locs)
            self.assertIn("https://depweather.com/pkg/npm/next/", locs)
            self.assertIn("https://depweather.com/pkg/npm/next/?lang=ko", locs)
            self.assertIn("https://depweather.com/pkg/npm/@angular/core/", locs)
            self.assertIn(
                "https://depweather.com/pkg/maven/org.springframework.boot~spring-boot/",
                locs,
            )
            self.assertEqual(pages.write_sitemap(data, ROOT, ROOT / "sitemap.xml"), None)

            first = (out / "pkg" / "npm" / "next" / "index.html").read_bytes()
            pages.write_pages(data, out)
            self.assertEqual((out / "pkg" / "npm" / "next" / "index.html").read_bytes(), first)

    def test_real_snapshot(self):
        latest = ROOT / "data" / "latest.json"
        data = json.loads(latest.read_text(encoding="utf-8"))
        keys = [p["key"] for e in data["ecosystems"] for p in e["packages"]]
        self.assertGreater(len(keys), 100)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            n = pages.write_pages(data, out)
            self.assertEqual(n, len(set(keys)))
            for key in keys:
                path = out / (feeds.package_page_rel(key) + "index.html")
                self.assertTrue(path.is_file(), key)
                self.assertTrue(path.resolve().is_relative_to(out.resolve()))
            php = (out / "pkg" / "runtimes" / "php" / "index.html").read_text(encoding="utf-8")
            self.assertIn("PHP (Runtimes &amp; servers) vulnerabilities", php)
            self.assertIn("CISA KEV", php)
            self.assertIn("99.9%", php)
            self.assertIn('href="/feed/runtimes/php.xml"', php)
            self.assertIn("8.2.35", php)
            for href in hrefs(php):
                if href.startswith("/") or href.startswith("?"):
                    continue
                self.assertIsNotNone(pages.safe_href(href), href)
            sm = pages.render_sitemap(data, (ROOT / "sitemap.xml").read_text(encoding="utf-8"))
            root = ET.fromstring(sm)
            locs = [el.text or "" for el in root.findall("sm:url/sm:loc", NS)]
            pkg_locs = [loc for loc in locs if "/pkg/" in loc and "lang=ko" not in loc]
            self.assertEqual(len(pkg_locs), len(set(keys)))
            self.assertIn("https://depweather.com/", locs)

    def test_map_links_to_package_pages(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('src="js/pkg-path.js', html)
        self.assertGreaterEqual(html.count("DepweatherPath.pkgPagePath("), 4)
        for needle in ("function renderForecast", "function drawTile", "function renderTimeline"):
            start = html.index(needle)
            self.assertIn("pkgPagePath", html[start:start + 6000], needle)


if __name__ == "__main__":
    unittest.main()
