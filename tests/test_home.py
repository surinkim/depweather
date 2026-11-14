#!/usr/bin/env python3
"""Home page: / and /ko/ are separate static HTML with their own language and links."""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collect"))

import home  # noqa: E402
from localize import localize  # noqa: E402


def head_of(page: str) -> str:
    return page[:page.index("</head>")]


class LocalizeTests(unittest.TestCase):
    def test_text_attributes_and_markers(self):
        src = (
            '<html lang="en"><head><title data-ko="KO title">EN title</title>'
            '<meta name="description" content="en" data-ko-content="ko &amp; more"></head>'
            '<body><p data-en="Hi" data-ko="안녕 <b>">Hi</p>'
            '<span data-i18n="x" title="t" data-i18n-title="y">old</span>'
            '<div data-i18n-html="h"><b>old</b> html</div>'
            '<img src="/a.svg" data-src-ko="/a.ko.svg" data-alt-ko="대체" alt="alt">'
            '<p id="n">Loading…</p>'
            '<script>var s = "<p data-ko=\'no\'>";</script></body></html>'
        )
        out = localize(src, "ko", strings={"x": "엑스", "y": "와이"},
                       html_strings={"h": "<i>새</i>"}, replace_text={"n": "149개 중 12개"},
                       root_attrs={"lang": "ko"})
        self.assertIn('<html lang="ko">', out)
        self.assertIn(">KO title</title>", out)
        self.assertIn('content="ko &amp; more"', out)
        self.assertNotIn("data-ko-content", out)
        self.assertIn(">안녕 &lt;b&gt;</p>", out)
        self.assertIn('title="와이"', out)
        self.assertIn(">엑스</span>", out)
        self.assertIn("><i>새</i></div>", out)
        self.assertIn('src="/a.ko.svg"', out)
        self.assertIn('alt="대체"', out)
        self.assertIn(">149개 중 12개</p>", out)
        # Script text is copied as is.
        self.assertIn('var s = "<p data-ko=\'no\'>";', out)
        # English leaves the markup as written, minus the Korean markers.
        en = localize(src, "en")
        self.assertIn(">EN title</title>", en)
        self.assertIn('content="en"', en)
        self.assertNotIn("data-ko-content", en)


DATA = {
    "generated_at": "2026-11-14T22:24:37Z",
    "summary": {
        "today_cves": 62, "month": "2026-11", "month_cves": 7862, "month_cves_last_year": 3021,
        "kev_new_7d": 12, "affected_packages_7d": 12, "tracked_packages": 149,
    },
    "ecosystems": [{"id": str(i), "label": str(i), "packages": []} for i in range(10)],
}


class HomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        out = Path(cls.tmp.name)
        home.write_home(ROOT / "index.html", out, DATA)
        cls.en = (out / "index.html").read_text(encoding="utf-8")
        cls.ko = (out / "ko" / "index.html").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_english(self):
        h = head_of(self.en)
        self.assertIn('<html lang="en">', self.en)
        self.assertRegex(h, r"<title[^>]*>depweather — vulnerability weather for popular packages</title>")
        self.assertIn('<link rel="canonical" href="https://depweather.com/">', h)
        self.assertIn('<meta property="og:url" content="https://depweather.com/">', h)
        self.assertIn('<meta property="og:locale" content="en_US">', h)
        self.assertNotRegex(self.en, r"\sdata-ko-[a-z-]+=")

    def test_korean_is_rendered_in_html(self):
        h = head_of(self.ko)
        self.assertIn('<html lang="ko">', self.ko)
        self.assertRegex(h, r"<title[^>]*>depweather — 인기 패키지의 취약점 날씨</title>")
        self.assertIn('<link rel="canonical" href="https://depweather.com/ko/">', h)
        self.assertIn('<meta property="og:url" content="https://depweather.com/ko/">', h)
        self.assertIn('<meta property="og:locale" content="ko_KR">', h)
        self.assertIn('<meta property="og:locale:alternate" content="en_US">', h)
        self.assertRegex(h, r'<meta name="description" content="[^"]*취약점')
        self.assertRegex(h, r'<meta property="og:title" content="[^"]*취약점')
        self.assertRegex(h, r'<meta property="og:description" content="[^"]*[가-힣]')
        self.assertNotRegex(self.ko, r"\sdata-ko-[a-z-]+=")
        body = self.ko[self.ko.index("<body>"):]
        self.assertIn('data-i18n="tagline">인기 패키지의 취약점 날씨<', body)
        self.assertIn("<h2>depweather 소개</h2>", body)
        self.assertIn(">알림 받기</h2>", body)
        self.assertIn(">7일</button>", body)
        self.assertNotIn("About depweather", body[:body.index("<script")])

    def test_hreflang_both_ways(self):
        for page in (self.en, self.ko):
            h = head_of(page)
            self.assertIn('<link rel="alternate" hreflang="en" href="https://depweather.com/">', h)
            self.assertIn('<link rel="alternate" hreflang="ko" href="https://depweather.com/ko/">', h)
            self.assertIn('<link rel="alternate" hreflang="x-default" href="https://depweather.com/">', h)
            self.assertNotRegex(h, r'(href|content)="[^"]*\?lang=')
            self.assertIn('<a href="/ko/" hreflang="ko"', page)
            self.assertIn('<a href="/" hreflang="en"', page)

    def test_old_lang_links_are_forwarded(self):
        for page in (self.en, self.ko):
            h = head_of(page)
            # Runs before anything else in <head>.
            self.assertLess(h.index('want = q.get("lang")'), h.index("googletagmanager"))
            self.assertIn("location.replace(url)", h)

    def test_numbers_are_in_the_html(self):
        self.assertIn('<p class="meta" id="meta">Forecast for 149 popular packages in 10 groups, '
                      'made 2026-11-14 22:24 UTC.</p>', self.en)
        self.assertIn('<p class="meta" id="meta">2026-11-14 22:24 UTC 예보. 10개 그룹, 인기 패키지 149개.</p>', self.ko)
        self.assertIn('<span class="value">12</span><span class="label">of 149 packages affected this week</span>', self.en)
        self.assertIn('<span class="value">12</span><span class="label">이번 주 영향받은 패키지 (149개 중)</span>', self.ko)
        self.assertIn('<span class="value">12</span><span class="label">이번 주 CISA KEV 추가</span>', self.ko)
        self.assertIn('<span class="value">7,862</span>', self.ko)
        self.assertIn('<span class="sub">2025-11 대비 +160% (3,021건, 이번 달은 진행 중)</span>', self.ko)
        self.assertIn("데이터 갱신 2026-11-14 22:24 UTC.", self.ko)
        self.assertIn('aria-label="오늘의 숫자"', self.ko)
        self.assertNotIn("Loading data", self.en[:self.en.index("<script>\n\"use strict\"")])
        self.assertNotIn("불러오는 중", self.ko[:self.ko.index("<script>\n\"use strict\"")])

    def test_missing_numbers_are_left_out(self):
        data = json.loads(json.dumps(DATA))
        data["summary"]["today_cves"] = None
        data["summary"]["month_cves_last_year"] = 0
        with tempfile.TemporaryDirectory() as tmp:
            home.write_home(ROOT / "index.html", Path(tmp), data)
            page = (Path(tmp) / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("new CVEs today", page[:page.index("<script>\n\"use strict\"")])
        self.assertNotIn('class="sub"', page[:page.index("<script>\n\"use strict\"")])
        self.assertIn('<span class="value">7,862</span>', page)

    def test_assets_are_absolute(self):
        # /ko/index.html must load the same files as /.
        for attr in re.findall(r'(?:src|href)="([^"]+)"', self.ko):
            if attr.startswith(("http", "#", "mailto:", "/", "${")):
                continue
            self.fail(f"relative URL in the Korean home page: {attr}")
        self.assertIn('fetch("/data/latest.json"', self.ko)


if __name__ == "__main__":
    unittest.main()
