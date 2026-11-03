#!/usr/bin/env python3
"""Compact monthly history: counts, windows, chart escaping, backfill merge."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collect"))

import backfill_history as backfill  # noqa: E402
import history  # noqa: E402
import pages  # noqa: E402


AS_OF = date(2026, 11, 3)
WEEK_STARTS = [
    "2026-09-01", "2026-09-07", "2026-09-14", "2026-09-21", "2026-09-28",
    "2026-10-05", "2026-10-12", "2026-10-19", "2026-10-26", "2026-11-02",
]


def vuln(vid, published, severity="HIGH", kev=False, kev_date=None):
    row = {"id": vid, "published": published, "severity": severity, "kev": kev}
    if kev_date:
        row["kev_date_added"] = kev_date
        row["kev"] = True
    return row


class HistoryTests(unittest.TestCase):
    def test_counts_use_the_kev_date_and_dedupe_ecosystems(self):
        ecosystems = [{
            "id": "npm",
            "packages": [
                {"key": "npm/left-pad", "vulns": [
                    vuln("GHSA-1", "2024-01-02T00:00:00Z", "HIGH", kev_date="2026-10-01"),
                ]},
                {"key": "npm/lodash", "vulns": [
                    vuln("GHSA-1", "2024-01-02T00:00:00Z", "HIGH", kev_date="2026-10-01"),
                    vuln("GHSA-2", "2026-09-15T12:00:00Z", "CRITICAL"),
                    vuln("NONE-1", "2026-09-15T12:00:00Z", "NONE"),
                ]},
            ],
        }]
        days = history.aggregate_snapshot(ecosystems, date(2025, 11, 1), AS_OF)
        self.assertEqual(set(days), {"2026-09-15", "2026-10-01"})
        self.assertEqual(days["2026-10-01"]["packages"]["npm/left-pad"], {"h": 1, "k": 1})
        self.assertEqual(days["2026-10-01"]["packages"]["npm/lodash"], {"h": 1, "k": 1})
        # The same advisory id on two packages counts once for the ecosystem.
        self.assertEqual(days["2026-10-01"]["ecosystems"]["npm"], {"h": 1, "k": 1})
        self.assertEqual(days["2026-09-15"]["packages"]["npm/lodash"], {"c": 1})
        self.assertEqual(days["2026-09-15"]["ecosystems"]["npm"], {"c": 1})

    def test_apply_replaces_the_window_and_keeps_older_days(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            history.apply_days(directory, {
                "2026-01-15": {"packages": {"npm/a": {"c": 1, "h": 0}}},
            }, date(2026, 1, 1), date(2026, 1, 31))
            history.apply_days(directory, {
                "2026-11-03": {"packages": {"npm/a": {"h": 2, "k": True}}},
            }, date(2026, 11, 1), date(2026, 11, 3))
            days = history.load_days(directory)
            self.assertEqual(days["2026-01-15"]["packages"]["npm/a"], {"c": 1})
            # Booleans are not counts, so a true KEV flag is dropped rather than stored as 1.
            self.assertEqual(days["2026-11-03"]["packages"]["npm/a"], {"h": 2})
            history.apply_days(directory, {}, date(2026, 11, 1), date(2026, 11, 30))
            days = history.load_days(directory)
            self.assertNotIn("2026-11-03", days)
            self.assertIn("2026-01-15", days)
            manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["months"], ["2026-01"])
            self.assertFalse((directory / "2026-11.json").exists())

    def test_legacy_snapshots_are_removed_and_history_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            legacy = directory / "2026-11-03.json"
            legacy.write_text("{}", encoding="utf-8")
            (directory / "2026-11.json").write_text("{}\n", encoding="utf-8")
            removed = history.remove_legacy_snapshots(directory)
            self.assertEqual(removed, [legacy])
            self.assertTrue((directory / "2026-11.json").is_file())
        ignored = subprocess.run(
            ["git", "check-ignore", "data/history/2026-11.json"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertNotEqual(ignored.returncode, 0)
        cached = subprocess.run(
            ["git", "check-ignore", ".cache/osv/npm/all.zip"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(cached.returncode, 0)

    def test_buckets_match_the_chart_windows(self):
        self.assertEqual(history.period_start(AS_OF, "3m"), date(2026, 9, 1))
        self.assertEqual(history.period_start(AS_OF, "6m"), date(2026, 6, 1))
        self.assertEqual(history.period_start(AS_OF, "1y"), date(2025, 11, 1))
        weeks = history.build_buckets(AS_OF, "3m")
        self.assertEqual([row["start"] for row in weeks], WEEK_STARTS)
        self.assertEqual(weeks[-1]["end"], "2026-11-03")
        months = history.build_buckets(AS_OF, "1y")
        self.assertEqual(len(months), 13)
        self.assertEqual(months[0]["label"], "2025-11")
        self.assertEqual(months[-1]["label"], "2026-11")
        summed = history.sum_buckets({"2026-11-02": {"c": 2, "k": 1}, "2026-08-01": {"h": 9}}, weeks)
        last = summed[-1]["counts"]
        self.assertEqual(last["c"], 2)
        self.assertEqual(last["k"], 1)
        self.assertEqual(sum(row["counts"]["h"] for row in summed), 0)

    def test_complete_window_skips_the_partial_boundary_day(self):
        now = datetime(2026, 11, 3, 0, 59, tzinfo=timezone.utc)
        self.assertEqual(history.complete_window(now, 30), (date(2026, 10, 5), date(2026, 11, 3)))

    def test_chart_escapes_and_marks_kev(self):
        label = '</svg><script>alert(1)&"'
        html = history.render_trend_section(
            label,
            {"2026-10-01": {"c": 1, "k": 1}},
            AS_OF,
            "npm/next",
        )
        self.assertNotIn("<script", html)
        self.assertIn("&lt;/svg&gt;&lt;script&gt;alert(1)&amp;&quot;", html)
        self.assertIn('class="kev-mark"', html)
        self.assertIn('data-trend-panel="6m"', html)
        self.assertIn('data-trend-panel="1y" hidden', html)
        self.assertIn("장기 추이", html)
        self.assertIn("이 그래프의 숫자", html)
        self.assertIn('aria-pressed="true"', html)
        self.assertIn('role="img"', html)
        missing = history.render_trend_section("Next", None, AS_OF, "npm/next")
        self.assertIn("아직 장기 추이 데이터가 없습니다", missing)
        self.assertNotIn("<svg", missing)

    def test_package_page_includes_the_chart(self):
        generated = datetime(2026, 11, 3, tzinfo=timezone.utc)
        eco = {"id": "npm", "label": "npm"}
        pkg = {
            "key": "npm/next",
            "name": "next",
            "label": "Next <b>js",
            "vulns": [],
        }
        page = pages.render_page(
            eco, pkg, generated, "2026-11-03T00:00:00Z",
            {"2026-10-01": {"packages": {"npm/next": {"h": 1, "k": 1}}}},
        )
        self.assertIn('id="trend"', page)
        self.assertIn('class="kev-mark"', page)
        self.assertIn("Next &lt;b&gt;js", page)
        self.assertNotIn("<b>js", page)
        self.assertIn("data-trend=\"1y\"", page)
        empty = pages.render_page(eco, pkg, generated, "2026-11-03T00:00:00Z", None)
        self.assertIn("Long-term counts have not been collected yet.", empty)

    def test_committed_history_is_compact_monthly_counts(self):
        directory = ROOT / "data" / "history"
        months = history.list_month_names(directory)
        self.assertGreaterEqual(len(months), 10)
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], 1)
        self.assertEqual(manifest["months"], months)
        self.assertFalse(list(directory.glob("????-??-??.json")))
        for month in months:
            path = directory / f"{month}.json"
            self.assertLess(path.stat().st_size, 80_000, month)
            doc = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(doc["schema"], 1)
            self.assertEqual(doc["month"], month)
            self.assertTrue(doc["days"])

    def test_month_file_stays_small(self):
        days = {}
        for day in range(1, 31):
            packages = {f"npm/pkg-{i}": {"h": 1, "k": 1} for i in range(20)}
            days[f"2026-10-{day:02d}"] = {"packages": packages, "ecosystems": {"npm": {"h": 20, "k": 4}}}
        with tempfile.TemporaryDirectory() as tmp:
            history.apply_days(Path(tmp), days, date(2026, 10, 1), date(2026, 10, 31))
            size = (Path(tmp) / "2026-10.json").stat().st_size
        self.assertLess(size, 80_000)

    def test_backfill_merges_alias_records_without_double_counting(self):
        eco = {
            "id": "npm",
            "osv": "npm",
            "packages": [
                {"name": "left-pad"},
                {"name": "symfony/http-kernel", "match": ["symfony/*"]},
            ],
        }
        records = [
            {
                "id": "CVE-2024-1111",
                "aliases": ["GHSA-aaaa-bbbb-cccc"],
                "published": "2024-01-01T00:00:00Z",
                "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}}],
            },
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2024-1111"],
                "published": "2024-01-02T00:00:00Z",
                "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}}],
                "database_specific": {"severity": "HIGH"},
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            },
            {
                "id": "GHSA-symfony",
                "published": "2026-08-01T00:00:00Z",
                "affected": [{"package": {"ecosystem": "Packagist", "name": "symfony/console"}}],
                "database_specific": {"severity": "MEDIUM"},
            },
            {
                "id": "GHSA-other-eco",
                "published": "2026-08-01T00:00:00Z",
                "affected": [{"package": {"ecosystem": "Packagist", "name": "symfony/console"}}],
            },
        ]
        # The third record's ecosystem is Packagist, so an npm scan must ignore it.
        built = backfill.ecosystem_from_records(eco, records, {
            "CVE-2024-1111": {"cveID": "CVE-2024-1111", "dateAdded": "2026-10-01"},
        })
        by_key = {pkg["key"]: pkg["vulns"] for pkg in built["packages"]}
        self.assertEqual(len(by_key["npm/left-pad"]), 1)
        self.assertEqual(by_key["npm/left-pad"][0]["severity"], "HIGH")
        low = {
            "id": "GHSA-low-low-low",
            "published": "2026-10-22T00:00:00Z",
            "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}}],
            "database_specific": {"severity": "LOW"},
        }
        low_built = backfill.ecosystem_from_records(eco, [low], {})
        self.assertEqual(low_built["packages"][0]["vulns"][0]["severity"], "LOW")
        self.assertEqual(by_key["npm/left-pad"][0]["kev_date_added"], "2026-10-01")
        self.assertEqual(by_key["npm/symfony/http-kernel"], [])
        packagist = {
            "id": "packagist",
            "osv": "Packagist",
            "packages": [{"name": "symfony/http-kernel", "match": ["symfony/*"]}],
        }
        built = backfill.ecosystem_from_records(packagist, records, {})
        vulns = built["packages"][0]["vulns"]
        self.assertEqual(sorted(v["id"] for v in vulns), ["GHSA-other-eco", "GHSA-symfony"])
        days = history.aggregate_snapshot([built], date(2026, 1, 1), AS_OF)
        self.assertEqual(days["2026-08-01"]["ecosystems"]["packagist"]["m"], 1)
        self.assertEqual(days["2026-08-01"]["ecosystems"]["packagist"]["u"], 1)


if __name__ == "__main__":
    unittest.main()
