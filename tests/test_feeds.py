#!/usr/bin/env python3
"""Atom feeds: well-formed XML, stable ids, retention, KEV and critical marks."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collect"))

import feeds  # noqa: E402

ATOM = "http://www.w3.org/2005/Atom"
NS = {"a": ATOM}


def tag(name: str) -> str:
    return f"{{{ATOM}}}{name}"


def parse(path: Path) -> ET.Element:
    text = path.read_text(encoding="utf-8")
    # A feed that is not well-formed raises here.
    return ET.fromstring(text)


def entry_ids(root: ET.Element) -> list[str]:
    return [e.text or "" for e in root.findall("a:entry/a:id", NS)]


def titles(root: ET.Element) -> list[str]:
    return [e.text or "" for e in root.findall("a:entry/a:title", NS)]


class FeedTests(unittest.TestCase):
    def test_segment_roundtrip(self):
        samples = [
            "next",
            "org.springframework.boot:spring-boot",
            "@angular",
            "foo~bar:baz",
            "foo:bar~baz",
            "a~~b",
        ]
        for s in samples:
            self.assertEqual(feeds.decode_segment(feeds.encode_segment(s)), s)

    def test_fixture_retention_highlights_and_stable_ids(self):
        generated = datetime(2026, 11, 2, tzinfo=timezone.utc)
        old = (generated - timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
        recent = (generated - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = {
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
                                    "id": "GHSA-crit",
                                    "summary": "RCE <in> next & friends",
                                    "severity": "CRITICAL",
                                    "published": recent,
                                    "url": "https://osv.dev/vulnerability/GHSA-crit",
                                    "fixed": ["16.0.1"],
                                    "kev": False,
                                    "malicious": False,
                                },
                                {
                                    "id": "GHSA-old",
                                    "summary": "too old for the feed",
                                    "severity": "CRITICAL",
                                    "published": old,
                                    "url": "https://osv.dev/vulnerability/GHSA-old",
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
                            "vulns": [
                                {
                                    "id": "GHSA-boot",
                                    "summary": "auth bypass",
                                    "severity": "HIGH",
                                    "published": "2026-10-01T00:00:00Z",
                                    "url": "https://osv.dev/vulnerability/GHSA-boot",
                                    "fixed": ["3.2.1"],
                                    "kev": True,
                                    "kev_date_added": "2026-11-01",
                                    "malicious": False,
                                }
                            ],
                        }
                    ],
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            n1 = feeds.write_feeds(data, out)
            self.assertEqual(n1, 4)  # site + 3 packages
            site = parse(out / "feed.xml")
            self.assertEqual(site.tag, tag("feed"))
            self.assertEqual(site.findtext("a:title", default="", namespaces=NS), "depweather — new advisories")
            self.assertEqual(site.find("a:link[@rel='self']", NS).attrib["href"], "https://depweather.com/feed.xml")
            self.assertEqual(site.find("a:link[@rel='alternate']", NS).attrib["href"], "https://depweather.com/")
            self.assertTrue(site.findtext("a:updated", default="", namespaces=NS))
            self.assertIsNotNone(site.find("a:author/a:name", NS))
            ids = entry_ids(site)
            self.assertEqual(len(ids), len(set(ids)))
            self.assertIn("tag:depweather.com,2026:advisory:npm/next/GHSA-crit", ids)
            self.assertIn("tag:depweather.com,2026:advisory:maven/org.springframework.boot:spring-boot/GHSA-boot", ids)
            self.assertNotIn("tag:depweather.com,2026:advisory:npm/next/GHSA-old", ids)
            # KEV sorts ahead of a newer critical item.
            self.assertTrue(titles(site)[0].startswith("KEV · "))
            crit = [t for t in titles(site) if "Next.js" in t][0]
            self.assertTrue(crit.startswith("Critical · "))
            self.assertIn("RCE <in> next & friends", crit)
            # Regenerating does not change ids or titles.
            n2 = feeds.write_feeds(data, out)
            self.assertEqual(n1, n2)
            site_again = parse(out / "feed.xml")
            self.assertEqual(entry_ids(site_again), ids)
            self.assertEqual(titles(site_again), titles(site))

            pkg = parse(out / "feed" / "npm" / "next.xml")
            self.assertEqual(entry_ids(pkg), ["tag:depweather.com,2026:advisory:npm/next/GHSA-crit"])
            self.assertEqual(pkg.find("a:link[@rel='self']", NS).attrib["href"], "https://depweather.com/feed/npm/next.xml")
            self.assertEqual(pkg.find("a:link[@rel='alternate']", NS).attrib["href"], "https://depweather.com/pkg/npm/next/")
            content = pkg.findtext("a:entry/a:content", default="", namespaces=NS)
            # type="html": after XML parsing the text is HTML, so "<" in the summary is still escaped.
            self.assertIn("RCE &lt;in&gt; next &amp; friends", content)
            self.assertIn("<strong>CRITICAL</strong>", content)
            raw = (out / "feed" / "npm" / "next.xml").read_text(encoding="utf-8")
            self.assertNotIn("RCE <in>", raw)
            self.assertIn("RCE &lt;in&gt; next &amp; friends", raw)

            angular = parse(out / "feed" / "npm" / "@angular" / "core.xml")
            self.assertEqual(entry_ids(angular), [])
            self.assertIn("Angular", angular.findtext("a:title", default="", namespaces=NS))
            self.assertEqual(
                angular.find("a:link[@rel='alternate']", NS).attrib["href"],
                "https://depweather.com/pkg/npm/@angular/core/",
            )

            boot = out / "feed" / "maven" / "org.springframework.boot~spring-boot.xml"
            self.assertTrue(boot.is_file())
            boot_root = parse(boot)
            self.assertEqual(
                boot_root.find("a:link[@rel='alternate']", NS).attrib["href"],
                "https://depweather.com/pkg/maven/org.springframework.boot~spring-boot/",
            )
            self.assertTrue(titles(boot_root)[0].startswith("KEV · "))
            cats = [c.attrib["term"] for c in boot_root.findall("a:entry/a:category", NS)]
            self.assertIn("kev", cats)
            self.assertIn("high", cats)

            # A changed summary updates the text and keeps the id.
            data["ecosystems"][0]["packages"][0]["vulns"][0]["summary"] = "updated wording"
            feeds.write_feeds(data, out)
            again = parse(out / "feed" / "npm" / "next.xml")
            self.assertEqual(entry_ids(again), ["tag:depweather.com,2026:advisory:npm/next/GHSA-crit"])
            self.assertIn("updated wording", titles(again)[0])

    def test_site_feed_cap(self):
        generated = "2026-11-02T00:00:00Z"
        vulns = []
        for i in range(SITE_OVER):
            vulns.append({
                "id": f"GHSA-{i:04d}",
                "summary": f"item {i}",
                "severity": "LOW",
                "published": "2026-11-01T00:00:00Z",
                "url": f"https://osv.dev/vulnerability/GHSA-{i:04d}",
                "fixed": [],
                "kev": False,
            })
        data = {
            "generated_at": generated,
            "ecosystems": [{"id": "npm", "label": "npm", "packages": [
                {"key": "npm/left", "name": "left", "label": "left", "vulns": vulns},
            ]}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            feeds.write_feeds(data, Path(tmp))
            site = parse(Path(tmp) / "feed.xml")
            pkg = parse(Path(tmp) / "feed" / "npm" / "left.xml")
            self.assertEqual(len(entry_ids(site)), feeds.SITE_FEED_CAP)
            self.assertEqual(len(entry_ids(pkg)), SITE_OVER)
            self.assertEqual(len(set(entry_ids(site))), feeds.SITE_FEED_CAP)

    def test_real_snapshot(self):
        latest = ROOT / "data" / "latest.json"
        data = json.loads(latest.read_text(encoding="utf-8"))
        generated = feeds.parse_time(data["generated_at"])
        keys = [p["key"] for e in data["ecosystems"] for p in e["packages"]]
        self.assertGreater(len(keys), 100)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            feeds.write_feeds(data, out)
            site = parse(out / "feed.xml")
            ids = entry_ids(site)
            self.assertEqual(len(ids), len(set(ids)))
            self.assertLessEqual(len(ids), feeds.SITE_FEED_CAP)
            self.assertTrue(all(i.startswith("tag:depweather.com,2026:advisory:") for i in ids))
            for entry in site.findall("a:entry", NS):
                updated = feeds.parse_time(entry.findtext("a:updated", default="", namespaces=NS))
                self.assertGreaterEqual(updated, generated - timedelta(days=feeds.RETENTION_DAYS))
                title = entry.findtext("a:title", default="", namespaces=NS)
                terms = [c.attrib["term"] for c in entry.findall("a:category", NS)]
                if "kev" in terms:
                    self.assertTrue(title.startswith("KEV"), title)
                if "critical" in terms and "kev" not in terms:
                    self.assertTrue(title.startswith("Critical") or title.startswith("Malicious") or title.startswith("KEV"), title)
            for key in keys:
                path = out / feeds.feed_relpath(key)
                self.assertTrue(path.is_file(), key)
                root = parse(path)
                self.assertEqual(root.find("a:link[@rel='self']", NS).attrib["href"], feeds.feed_url(key))
                for eid in entry_ids(root):
                    self.assertIn(f":advisory:{key}/", eid)
            # Second write is byte-identical: nothing in the feed depends on the clock.
            first = (out / "feed.xml").read_bytes()
            feeds.write_feeds(data, out)
            self.assertEqual((out / "feed.xml").read_bytes(), first)

    def test_urls_match_the_action(self):
        import subprocess
        keys = [
            "npm/next",
            "npm/@angular/core",
            "maven/org.springframework.boot:spring-boot",
            "go/github.com/gin-gonic/gin",
            "packagist/symfony/http-kernel",
        ]
        script = (
            "const c = require('./alert/check.js');"
            "for (const k of process.argv.slice(1)) console.log(c.packageFeedUrl(k));"
        )
        r = subprocess.run(
            ["node", "-e", script, *keys],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        got = r.stdout.strip().splitlines()
        self.assertEqual(got, [feeds.feed_url(k) for k in keys])

    def test_page_autodiscovery(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('rel="alternate"', html)
        self.assertIn('type="application/atom+xml"', html)
        self.assertIn('href="https://depweather.com/feed.xml"', html)
        self.assertIn('id="alerts"', html)
        self.assertIn("docs/alerts.md", html)
        self.assertIn("docs/alerts.ko.md", html)
        self.assertIn("알림 받기", html)


SITE_OVER = feeds.SITE_FEED_CAP + 5


if __name__ == "__main__":
    unittest.main()
