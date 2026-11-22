#!/usr/bin/env python3
"""patches_page.py: the page shows what patches.json says and nothing else."""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collect"))

import patches_page as pp  # noqa: E402

TODAY = date(2026, 11, 22)


def dist(id_, label, latest, released, **kw):
    d = {"id": id_, "label": label, "latest_patch": latest, "released_at": released, "released_precision": "time",
         "release_url": "https://github.com/corretto/corretto-17/releases/tag/" + latest,
         "is_lts": True, "is_eol": False, "eol_from": "2029-10-31", "high_cves": [], "cvss_unrated": 0,
         "cve_sources": [], "images": [],
         "image_status": {"state": "reflected", "hours": 3, "approx": False}, "image_note": None,
         "workaround_dockerfile": None}
    d.update(kw)
    return d


DATA = {
    "generated_at": "2026-11-21T23:30:00Z",
    "summary": {"new_patches_7d": 12, "images_pending": 3, "high_cves": 2},
    "languages": [
        {"id": "java", "label": "Java", "versions": [{
            "name": "17", "is_lts": True, "is_eol": False, "eol_from": "2029-10-31", "inline": False,
            "distros": [
                dist("amazon-corretto", "Amazon Corretto", "17.0.21.1.2", "2026-11-17T20:05:00Z", high_cves=[
                    {"id": "CVE-2026-12345", "cvss": 9.1, "fixed_in": "17.0.21.1.2",
                     "url": "https://osv.dev/vulnerability/UBUNTU-CVE-2026-12345"},
                    # Not shown: not a real id, a low score, no score.
                    {"id": "CVE-2026-XXXX", "cvss": 9.1, "url": "https://osv.dev/vulnerability/x"},
                    {"id": "CVE-2026-22222", "cvss": 6.9, "url": "https://osv.dev/vulnerability/y"},
                    {"id": "CVE-2026-33333", "cvss": None, "url": "https://osv.dev/vulnerability/z"},
                ], images=[{"registry": "dockerhub", "repo": "library/amazoncorretto", "tag": "17-al2023", "exact": False,
                            "exists": True, "contains_latest": True, "built_at": "2026-11-17T23:11:00Z"}]),
                dist("eclipse-temurin", "Eclipse Temurin", "17.0.21.1+2", "2026-11-18T04:28:00Z",
                     image_status={"state": "pending", "hours": 4, "approx": False}, high_cves=None,
                     workaround_dockerfile="FROM eclipse-temurin:17\nRUN echo patch"),
                dist("oracle-openjdk", "Oracle OpenJDK", "17.0.2", "2022-01-18T00:00:00Z", released_precision="date",
                     is_eol=True, eol_from="2022-03-22", image_status={"state": "unknown", "hours": None, "approx": False},
                     image_note={"en": "No anonymous API.", "ko": "공개 API가 없습니다."}),
            ]}]},
        {"id": "nodejs", "label": "Node.js", "versions": [{
            "name": "22", "is_lts": True, "is_eol": False, "eol_from": "2027-04-30", "inline": True,
            "distros": [dist("official", "Node.js", "22.23.5", "2026-11-11T04:22:00Z", eol_from="2027-04-30", high_cves=None)]}]},
    ],
    "changelog": [{"key": "k", "at": "2026-11-20T19:28:00Z", "kind": "patch", "text_en": "Eclipse Temurin 17.0.21.1+2 released",
                   "text_ko": "Eclipse Temurin 17.0.21.1+2 배포"}],
}


class Page(unittest.TestCase):
    def setUp(self):
        self.en = pp.render_page(DATA, "en", TODAY)
        self.ko = pp.render_page(DATA, "ko", TODAY)

    def test_summary_cards_use_the_data(self):
        nums = re.findall(r'<span class="num">(\d+)', self.en)
        self.assertEqual(nums, ["12", "3", "2"])

    def test_only_real_scored_cves_are_rendered(self):
        self.assertIn("CVE-2026-12345", self.en)
        self.assertIn("CVSS 9.1", self.en)
        self.assertNotIn("XXXX", self.en)
        self.assertNotIn("CVE-2026-22222", self.en)
        self.assertNotIn("CVE-2026-33333", self.en)
        self.assertNotIn("예시 데이터", self.ko)
        self.assertNotIn("patchwatch", self.en.lower())

    def test_row_cve_counts_and_unknown(self):
        corretto = self.en[self.en.index('data-key="java/17/amazon-corretto"'):]
        self.assertIn('<span class="cvecount">1</span>', corretto.split("</tr>")[0])
        temurin = self.en[self.en.index('data-key="java/17/eclipse-temurin"'):].split("</tr>")[0]
        self.assertIn('<td class="num"><span class="muted"', temurin)           # null: "–", not 0
        self.assertIn("Not covered", self.en)

    def test_delay_states(self):
        self.assertIn("✅ +3h", self.en)
        self.assertIn("⏳ waiting 4h", self.en)
        self.assertIn("⏳ 대기 4h", self.ko)

    def test_eol_badge_and_soon_and_ok(self):
        self.assertIn('class="pill bad" title="2022-03-22">2022-03 ended', self.en)
        self.assertIn("2022-03 종료", self.ko)
        self.assertIn('class="pill warn" title="2027-04-30"', self.en)       # 159 days
        self.assertIn('class="pill plain" title="2029-10-31"', self.en)

    def test_date_only_time_is_marked(self):
        self.assertIn("date only", self.en)

    def test_workaround_only_while_the_image_is_pending(self):
        self.assertEqual(self.en.count("If you must patch right now"), 1)
        self.assertIn("RUN echo patch", self.en)
        data = {**DATA}
        self.assertNotIn("RUN echo patch", pp.render_page({**data, "languages": [{**DATA["languages"][0], "versions": [{
            **DATA["languages"][0]["versions"][0], "distros": [dist("x", "X", "1", "2026-11-17T20:05:00Z",
                                                                    workaround_dockerfile="RUN echo patch")]}]}]}, "en", TODAY))

    def test_changelog_eol_list_kst_and_updated(self):
        self.assertIn("11/21 08:28", pp.kst_stamp("2026-11-20T23:28:00Z") and "11/21 08:28")
        self.assertEqual(pp.kst_stamp("2026-11-17T20:05:00Z"), "11/18 05:05")
        self.assertIn("11/22 08:30 KST", self.en)
        self.assertIn("Eclipse Temurin 17.0.21.1+2 released", self.en)
        self.assertIn("Eclipse Temurin 17.0.21.1+2 배포", self.ko)
        self.assertIn("159 days left", self.en)
        self.assertIn("159일 남음", self.ko)

    def test_language_head_and_links(self):
        self.assertIn('<html lang="ko">', self.ko)
        self.assertIn('rel="canonical" href="https://depweather.com/ko/patches/"', self.ko)
        self.assertIn('rel="canonical" href="https://depweather.com/patches/"', self.en)
        self.assertIn('href="/ko/"', self.ko)         # back to the Korean home
        self.assertIn('href="/"', self.en)
        self.assertIn('/js/patches.js', self.en)
        self.assertNotIn("depweather:stack", self.en)    # not the home page's key

    def test_no_secrets_or_tokens(self):
        for bad in ("ghp_", "github_pat", "apiKey", "Bearer"):
            self.assertNotIn(bad, self.en)

    def test_empty_data(self):
        page = pp.render_page({"generated_at": "2026-11-21T23:30:00Z", "languages": [], "changelog": []}, "en", TODAY)
        self.assertIn("No data yet.", page)

    def test_write_pages(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pp.write_pages(DATA, Path(tmp))
            self.assertEqual(sorted(p.relative_to(tmp).as_posix() for p in out),
                             ["ko/patches/index.html", "patches/index.html"])


if __name__ == "__main__":
    unittest.main()
