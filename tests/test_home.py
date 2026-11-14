#!/usr/bin/env python3
"""Home page: / and /ko/ are separate static HTML with their own language and links."""

from __future__ import annotations

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


class HomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        out = Path(cls.tmp.name)
        home.write_home(ROOT / "index.html", out)
        cls.en = (out / "index.html").read_text(encoding="utf-8")
        cls.ko = (out / "ko" / "index.html").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_english(self):
        h = head_of(self.en)
        self.assertIn('<html lang="en">', self.en)
        self.assertIn('<link rel="canonical" href="https://depweather.com/">', h)
        self.assertIn('<meta property="og:url" content="https://depweather.com/">', h)
        self.assertIn('<meta property="og:locale" content="en_US">', h)
        self.assertNotRegex(self.en, r"\sdata-ko-[a-z-]+=")

    def test_korean_is_rendered_in_html(self):
        h = head_of(self.ko)
        self.assertIn('<html lang="ko">', self.ko)
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

    def test_assets_are_absolute(self):
        # /ko/index.html must load the same files as /.
        for attr in re.findall(r'(?:src|href)="([^"]+)"', self.ko):
            if attr.startswith(("http", "#", "mailto:", "/", "${")):
                continue
            self.fail(f"relative URL in the Korean home page: {attr}")
        self.assertIn('fetch("/data/latest.json"', self.ko)


if __name__ == "__main__":
    unittest.main()
