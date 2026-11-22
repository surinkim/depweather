#!/usr/bin/env python3
"""patches.py: version choice, image delay, CVE matching, summary, changelog.
Fixtures only: nothing here calls an external API."""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collect"))

import patches  # noqa: E402

NOW = datetime(2026, 11, 22, 3, 0, tzinfo=timezone.utc)


def rel(name, lts=False, eol=False, maintained=True, eol_from=None, latest="1.0.0", day="2026-11-10", link=None):
    return {"name": name, "isLts": lts, "isEol": eol, "isMaintained": maintained, "eolFrom": eol_from,
            "latest": {"name": latest, "date": day, "link": link}}


class VersionChoice(unittest.TestCase):
    RELEASES = [
        rel("26", lts=True, eol_from="2029-04-30"),
        rel("25", eol=True, maintained=False, eol_from="2026-06-01"),
        rel("24", lts=True, eol_from="2028-04-30"),
        # Extended support keeps isMaintained true after the EOL date.
        rel("20", lts=True, eol=True, maintained=True, eol_from="2026-04-30"),
        rel("18", lts=True, eol=True, maintained=True, eol_from="2025-04-30"),
    ]

    def test_supported_only(self):
        got = patches.select_majors(self.RELEASES, {}, date(2026, 11, 22))
        self.assertEqual(list(got), ["26", "24"])

    def test_recent_eol_is_added_and_old_eol_is_not(self):
        got = patches.select_majors(self.RELEASES, {"recent_eol_days": 365}, date(2026, 11, 22))
        self.assertEqual(list(got), ["26", "25", "24", "20"])

    def test_lts_only(self):
        got = patches.select_majors(self.RELEASES, {"lts_only": True, "recent_eol_days": 365}, date(2026, 11, 22))
        self.assertEqual(list(got), ["26", "24", "20"])


class Versions(unittest.TestCase):
    def test_numbers_ignore_revisions_and_builds(self):
        self.assertEqual(patches.numbers("21.0.13.1+2-1~24.04.1"), (21, 0, 13, 1))
        self.assertEqual(patches.numbers("3.13.18-1"), (3, 13, 18))
        self.assertEqual(patches.numbers("1:3.13.18-1"), (3, 13, 18))
        self.assertEqual(patches.numbers("8u514-b01"), (8, 514))

    def test_update_release_and_tag_forms(self):
        self.assertEqual(patches.update_release("21.0.13.1+2"), (21, 0, 13))
        self.assertEqual(patches.update_release("21.0.13.1.2"), (21, 0, 13))
        self.assertEqual(patches.update_release("8.514.01.1"), (8, 514))
        self.assertIsNone(patches.update_release("25"))
        v = patches.template_vars("17", "17.0.21.1+2")
        self.assertEqual((v["base"], v["latest_us"]), ("17.0.21", "17.0.21.1_2"))
        self.assertEqual(patches.template_vars("8", "8u514-b01")["base"], "8u514")
        self.assertEqual(patches.fill("{base}-al2023", v), "17.0.21-al2023")

    def test_fixed_matches(self):
        self.assertTrue(patches.fixed_matches("1.26.11", "1.26.11"))
        self.assertFalse(patches.fixed_matches("1.26.10", "1.26.11"))
        self.assertTrue(patches.fixed_matches("3.13.18-1", "3.13.18"))
        self.assertFalse(patches.fixed_matches("3.13.5-2+deb13u1", "3.13.18"))
        self.assertTrue(patches.fixed_matches("21.0.13.1+2-1~24.04.1", "21.0.13.1.2", "update"))
        self.assertTrue(patches.fixed_matches("21.0.13+9-1", "21.0.13.1+2", "update"))
        self.assertFalse(patches.fixed_matches("21.0.12+7-1", "21.0.13.1+2", "update"))


class ImageDelay(unittest.TestCase):
    T = datetime(2026, 11, 17, 20, 0, tzinfo=timezone.utc)

    def test_exact_tag_decides_and_floating_needs_same_digest(self):
        tags = [
            {"tag": "1.26", "exact": False, "exists": True, "digest": "sha256:a", "pushed_at": "2026-11-17T23:00:00Z"},
            {"tag": "1.26.11", "exact": True, "exists": True, "digest": "sha256:a", "pushed_at": "2026-11-17T23:30:00Z"},
            {"tag": "1.25", "exact": False, "exists": True, "digest": "sha256:old", "pushed_at": "2026-11-18T01:00:00Z"},
        ]
        ok, built = patches.image_status(tags, self.T)
        self.assertTrue(ok)
        self.assertEqual(built, "2026-11-17T23:00:00Z")
        self.assertEqual([t["contains_latest"] for t in tags], [True, True, False])

    def test_missing_exact_tag_means_pending_even_if_floating_is_new(self):
        tags = [
            {"tag": "24", "exact": False, "exists": True, "digest": "sha256:a", "pushed_at": "2026-11-18T01:00:00Z"},
            {"tag": "24.22.3", "exact": True, "exists": False},
        ]
        self.assertEqual(patches.image_status(tags, self.T), (False, None))

    def test_without_exact_tags_push_time_decides(self):
        tags = [
            {"tag": "17", "exact": False, "exists": True, "digest": "x", "pushed_at": "2026-11-17T10:00:00Z"},
            {"tag": "17-al2023", "exact": False, "exists": True, "digest": "y", "pushed_at": "2026-11-18T08:00:00Z"},
        ]
        ok, built = patches.image_status(tags, self.T)
        self.assertTrue(ok)
        self.assertEqual(built, "2026-11-18T08:00:00Z")

    def test_lookup_failure_is_unknown(self):
        self.assertEqual(patches.image_status([{"tag": "a", "exact": True, "exists": None}], self.T), (None, None))

    def test_reflected_and_pending_hours(self):
        d = patches.image_delay(self.T, "2026-11-17T23:59:00Z", True, NOW)
        self.assertEqual((d["state"], d["hours"]), ("reflected", 3))
        d = patches.image_delay(self.T, None, False, datetime(2026, 11, 18, 0, 30, tzinfo=timezone.utc))
        self.assertEqual((d["state"], d["hours"]), ("pending", 4))
        self.assertEqual(patches.image_delay(self.T, None, None, NOW)["state"], "unknown")

    def test_a_build_long_after_the_release_claims_no_delay(self):
        d = patches.image_delay(self.T, "2026-12-30T00:00:00Z", True, NOW)
        self.assertEqual(d["state"], "reflected")
        self.assertIsNone(d["hours"])
        self.assertTrue(d["rebuilt"])

    def test_never_negative(self):
        d = patches.image_delay(self.T, "2026-11-17T10:00:00Z", True, NOW)
        self.assertEqual(d["hours"], 0)


def osv(id_, cves, fixed, eco, pkg, vector=None, withdrawn=False):
    r = {"id": id_, "upstream": cves, "affected": [{"package": {"name": pkg, "ecosystem": eco},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}
    if vector:
        r["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if withdrawn:
        r["withdrawn"] = "2026-11-19T00:00:00Z"
    return r


HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"      # 9.1
MEDIUM = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"


class Cves(unittest.TestCase):
    def test_only_this_patch_and_only_high(self):
        recs = [
            osv("UBUNTU-CVE-2026-10001", ["CVE-2026-10001"], "21.0.13.1+2-1~24.04.1", "Ubuntu:24.04:LTS", "openjdk-21", HIGH),
            osv("UBUNTU-CVE-2026-10002", ["CVE-2026-10002"], "21.0.13.1+2-1~24.04.1", "Ubuntu:24.04:LTS", "openjdk-21", MEDIUM),
            osv("UBUNTU-CVE-2026-10003", ["CVE-2026-10003"], "21.0.12+7-1~24.04.1", "Ubuntu:24.04:LTS", "openjdk-21", HIGH),
            osv("UBUNTU-CVE-2026-10004", ["CVE-2026-10004"], "21.0.13.1+2-1~24.04.1", "Ubuntu:24.04:LTS", "openjdk-21", HIGH, withdrawn=True),
            osv("UBUNTU-CVE-2026-10005", ["CVE-2026-10005"], "21.0.13.1+2-1~24.04.1", "Ubuntu:24.04:LTS", "openjdk-17", HIGH),
        ]
        src = [("Ubuntu:24.04:LTS", "openjdk-21", "update", recs)]
        cves, unrated = patches.high_cves_from_records(src, "21.0.13.1.2", {})
        self.assertEqual([(c["id"], c["fixed_in"]) for c in cves], [("CVE-2026-10001", "21.0.13.1.2")])
        self.assertEqual(unrated, 0)
        self.assertEqual(cves[0]["url"], "https://osv.dev/vulnerability/UBUNTU-CVE-2026-10001")

    def test_no_fake_cves_when_nothing_matches(self):
        cves, unrated = patches.high_cves_from_records([("Go", "stdlib", "exact", [])], "1.26.11", {})
        self.assertEqual((cves, unrated), ([], 0))

    def test_unrated_go_advisory_takes_the_nvd_score(self):
        rec = osv("GO-2026-1", ["CVE-2026-97054"], "1.26.11", "Go", "stdlib")
        src = [("Go", "stdlib", "exact", [rec])]
        self.assertEqual(patches.unscored_cves(src, "1.26.11"), ["CVE-2026-97054"])
        cves, unrated = patches.high_cves_from_records(src, "1.26.11", {})
        self.assertEqual((cves, unrated), ([], 1))               # no score anywhere: not listed, but counted
        cves, _ = patches.high_cves_from_records(src, "1.26.11", {"CVE-2026-97054": 7.5})
        self.assertEqual((cves[0]["id"], cves[0]["cvss"], cves[0]["cvss_source"]), ("CVE-2026-97054", 7.5, "NVD"))
        cves, _ = patches.high_cves_from_records(src, "1.26.11", {"CVE-2026-97054": 5.0})
        self.assertEqual(cves, [])

    def test_multi_cve_advisory_never_lends_its_score(self):
        rec = osv("USN-1-1", ["CVE-2026-10008", "CVE-2026-10009"], "21.0.13.1+2-1", "Ubuntu:24.04:LTS", "openjdk-21", HIGH)
        cves, unrated = patches.high_cves_from_records([("Ubuntu:24.04:LTS", "openjdk-21", "update", [rec])], "21.0.13.1+2", {})
        self.assertEqual((cves, unrated), ([], 2))


class FakeFetcher(patches.Fetcher):
    """Answers from a dict, so collect() runs without a network."""

    def __init__(self, answers):
        super().__init__(sleep=lambda s: None)
        self.answers = answers

    def json(self, url, headers=None, body=None, retries=3, timeout=60, not_found=None):
        for key, val in self.answers.items():
            if url.startswith(key):
                if isinstance(val, Exception):
                    raise val
                return val
        if not_found is not None:
            return not_found
        raise OSError(f"no fixture for {url}")


CONFIG = {"languages": [{
    "id": "go", "label": "Go", "select": {"recent_eol_days": 120},
    "distros": [{"id": "official", "label": "Go", "eol": "go",
                 "github": {"repo": "golang/go", "tag": "go{latest}", "kind": "tag"},
                 "dockerhub": {"repo": "library/golang", "tags": ["{name}", "{latest}"]},
                 "osv": [{"ecosystem": "Go", "package": "stdlib"}]}],
}]}
EOL = {"result": {"releases": [
    rel("1.27", latest="1.27.4", day="2026-11-10"),
    rel("1.26", latest="1.26.11", day="2026-11-10"),
    rel("1.25", eol=True, maintained=False, eol_from="2026-08-19", latest="1.25.14", day="2026-08-19"),
    rel("1.20", eol=True, maintained=False, eol_from="2024-02-01", latest="1.20.14", day="2024-02-01"),
]}}


def answers(**over):
    a = {
        "https://endoflife.date/api/v1/products/go": EOL,
        "https://api.github.com/repos/golang/go/git/ref/tags/go1.27.4": {"object": {"type": "commit", "sha": "abc"}},
        "https://api.github.com/repos/golang/go/git/commits/abc": {"committer": {"date": "2026-11-10T19:00:00Z"}},
        "https://hub.docker.com/v2/namespaces/library/repositories/golang/tags/1.27.4":
            {"name": "1.27.4", "digest": "sha256:a", "tag_last_pushed": "2026-11-10T22:00:00Z"},
        "https://hub.docker.com/v2/namespaces/library/repositories/golang/tags/1.27":
            {"name": "1.27", "digest": "sha256:a", "tag_last_pushed": "2026-11-10T22:00:00Z"},
        # An older fix only: the source is known, this patch has nothing high.
        "https://api.osv.dev/v1/query": {"vulns": [osv("GO-2026-0", ["CVE-2026-10000"], "1.27.3", "Go", "stdlib", HIGH)]},
    }
    a.update(over)
    return a


class Collect(unittest.TestCase):
    def run_collect(self, a, prev=None):
        with tempfile.TemporaryDirectory() as tmp:
            patches.CVSS_CACHE_BACKUP = patches.CVSS_CACHE
            patches.CVSS_CACHE = Path(tmp) / "c.json"
            try:
                return patches.collect(CONFIG, prev, FakeFetcher(a), NOW)
            finally:
                patches.CVSS_CACHE = patches.CVSS_CACHE_BACKUP

    def test_end_to_end(self):
        out = self.run_collect(answers())
        go = out["languages"][0]
        self.assertEqual([v["name"] for v in go["versions"]], ["1.27", "1.26", "1.25"])   # 1.20 is long gone
        v = go["versions"][0]
        self.assertTrue(v["inline"])
        d = v["distros"][0]
        self.assertEqual((d["latest_patch"], d["released_at"], d["released_precision"]), ("1.27.4", "2026-11-10T19:00:00Z", "time"))
        self.assertEqual((d["image_status"]["state"], d["image_status"]["hours"]), ("reflected", 3))
        self.assertEqual(d["high_cves"], [])               # a known source with nothing for this patch: 0
        self.assertTrue(go["versions"][2]["is_eol"])
        # No GitHub or Docker answers for 1.26: pending is not invented from nothing.
        d26 = go["versions"][1]["distros"][0]
        self.assertEqual(d26["released_precision"], "date")
        self.assertEqual(d26["image_status"]["state"], "pending")
        self.assertEqual(out["summary"]["images_pending"], 1)
        self.assertEqual(out["summary"]["new_patches_7d"], 0)   # 11/10 is outside 7 days

    def test_endoflife_failure_keeps_the_previous_values(self):
        first = self.run_collect(answers())
        out = self.run_collect({"https://endoflife.date": OSError("down")}, prev=first)
        self.assertEqual(out["sources"]["endoflife"]["failed"], 1)
        kept = out["languages"][0]["versions"] if out["languages"][0]["versions"] else []
        self.assertEqual(kept, [])       # nothing to choose majors from: no versions, caller keeps the old file

    def test_changelog_notes_a_new_patch_and_an_image_catching_up(self):
        first = self.run_collect(answers())
        later = answers()
        later["https://endoflife.date/api/v1/products/go"] = {"result": {"releases": [
            rel("1.27", latest="1.27.5", day="2026-11-21"), rel("1.26", latest="1.26.11", day="2026-11-10")]}}
        later["https://api.github.com/repos/golang/go/git/ref/tags/go1.27.5"] = {"object": {"type": "commit", "sha": "def"}}
        later["https://api.github.com/repos/golang/go/git/commits/def"] = {"committer": {"date": "2026-11-21T19:00:00Z"}}
        out = self.run_collect(later, prev=first)
        texts = [e["text_en"] for e in out["changelog"]]
        self.assertIn("Go 1.27 1.27.5 released", texts)
        self.assertTrue(all(e["text_ko"] for e in out["changelog"]))


class UnknownCoverage(unittest.TestCase):
    def test_a_source_without_records_is_unknown_not_zero(self):
        a = answers(**{"https://api.osv.dev/v1/query": {"vulns": []}})
        out = Collect().run_collect(a)
        self.assertIsNone(out["languages"][0]["versions"][0]["distros"][0]["high_cves"])


class WriteOnlyOnChange(unittest.TestCase):
    def doc(self, generated, hours=4, **kw):
        d = {"generated_at": generated, "sources": {"osv": {"ok": 1}}, "summary": {}, "changelog": [],
             "languages": [{"id": "go", "label": "Go", "versions": [{"name": "1.26", "distros": [
                 {"id": "official", "latest_patch": "1.26.11",
                  "image_status": {"state": "pending", "hours": hours}, **kw}]}]}]}
        return d

    def test_only_the_clock_and_pending_hours_differ(self):
        prev = self.doc("2026-11-22T00:23:00Z", hours=4)
        new = self.doc("2026-11-22T01:23:00Z", hours=5)
        self.assertTrue(patches.unchanged(prev, new, datetime(2026, 11, 22, 1, 23, tzinfo=timezone.utc)))

    def test_a_new_patch_is_a_change(self):
        prev = self.doc("2026-11-22T00:23:00Z")
        new = self.doc("2026-11-22T01:23:00Z")
        new["languages"][0]["versions"][0]["distros"][0]["latest_patch"] = "1.26.12"
        self.assertFalse(patches.unchanged(prev, new, datetime(2026, 11, 22, 1, 23, tzinfo=timezone.utc)))

    def test_an_image_catching_up_is_a_change(self):
        prev = self.doc("2026-11-22T00:23:00Z")
        new = self.doc("2026-11-22T01:23:00Z")
        new["languages"][0]["versions"][0]["distros"][0]["image_status"] = {"state": "reflected", "hours": 5}
        self.assertFalse(patches.unchanged(prev, new, datetime(2026, 11, 22, 1, 23, tzinfo=timezone.utc)))

    def test_heartbeat_rewrites_an_old_file_and_first_run_writes(self):
        prev = self.doc("2026-11-22T00:23:00Z")
        new = self.doc("2026-11-22T07:00:00Z")
        self.assertFalse(patches.unchanged(prev, new, datetime(2026, 11, 22, 7, 0, tzinfo=timezone.utc)))
        self.assertFalse(patches.unchanged(None, new, NOW))


class Summary(unittest.TestCase):
    def test_counts_each_cve_once(self):
        def dist(i, **kw):
            return {"id": i, "released_at": "2026-11-20T00:00:00Z", "image_status": {"state": "reflected"},
                    "high_cves": [{"id": "CVE-2026-10001"}], **kw}
        langs = [{"versions": [{"distros": [dist("a"), dist("b"),
                 dist("c", image_status={"state": "pending"}, high_cves=None),
                 dist("d", image_status={"state": "pending"}, is_eol=True, released_at="2026-01-01T00:00:00Z")]}]}]
        s = patches.summarize(langs, NOW)
        self.assertEqual(s, {"new_patches_7d": 3, "images_pending": 1, "high_cves": 1})


if __name__ == "__main__":
    unittest.main()
