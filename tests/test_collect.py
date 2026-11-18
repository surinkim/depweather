#!/usr/bin/env python3
"""collect.py: extra OSV sources per tile (stacks.yml `also`), merged by CVE."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "collect"))

import collect  # noqa: E402

NOW = datetime(2026, 11, 18, 3, 0, tzinfo=timezone.utc)
STACKS = [{
    "id": "runtimes", "osv": "Bitnami",
    "packages": [
        {"name": "java", "match": ["java-min", "jre"], "also": {"Debian": ["openjdk-*"]}},
        {"name": "php"},
    ],
}]


def deb(id_, cves, names, published="2026-11-17T22:18:24Z", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        eco="Debian:13"):
    return {
        "id": id_, "published": published, "upstream": cves,
        "severity": [{"type": "CVSS_V3", "score": vector}],
        "affected": [{"package": {"name": n, "ecosystem": eco},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "21.0.9+10-1~deb13u1"}]}]}
                     for n in names],
    }


RECORDS = [
    deb("DEBIAN-CVE-2026-1", ["CVE-2026-1"], ["openjdk-17", "openjdk-21"]),
    deb("DEBIAN-CVE-2026-2", ["CVE-2026-2"], ["openjdk-25"], vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    # Not Java, too old, a bundle of CVEs, withdrawn: all left out.
    deb("DEBIAN-CVE-2026-3", ["CVE-2026-3"], ["php8.4"]),
    deb("DEBIAN-CVE-2026-4", ["CVE-2026-4"], ["openjdk-21"], published="2026-09-01T00:00:00Z"),
    deb("DSA-9999-1", ["CVE-2026-1", "CVE-2026-2"], ["openjdk-21"]),
    {**deb("DEBIAN-CVE-2026-5", ["CVE-2026-5"], ["openjdk-21"]), "withdrawn": "2026-11-17T23:00:00Z"},
]


class AlsoSourceTests(unittest.TestCase):
    def test_sources_from_stacks(self):
        self.assertEqual(collect.also_sources(STACKS), {"Debian": [(("Bitnami", "java"), ["openjdk-*"])]})
        self.assertTrue(collect.eco_matches("Debian", "Debian:12"))
        self.assertFalse(collect.eco_matches("Debian", "Debianish"))

    def test_collect_filters_records(self):
        found, status = collect.collect_also(STACKS, NOW, read=lambda eco: iter(RECORDS))
        self.assertEqual(status, {"Debian": {"ok": True, "added": 2}})
        self.assertEqual(sorted(r["id"] for r in found[("Bitnami", "java")]),
                         ["DEBIAN-CVE-2026-1", "DEBIAN-CVE-2026-2"])

    def test_failure_is_reported_not_raised(self):
        def boom(eco):
            raise OSError("bucket down")
        found, status = collect.collect_also(STACKS, NOW, read=boom)
        self.assertEqual(found, {})
        self.assertFalse(status["Debian"]["ok"])

    def test_merged_with_bitnami_by_cve(self):
        found, _ = collect.collect_also(STACKS, NOW, read=lambda eco: iter(RECORDS))
        bitnami = {
            "id": "BIT-java-2026-1", "published": "2026-11-18T01:00:00Z", "aliases": ["CVE-2026-1"],
            "summary": "Java SE: remote code execution in the Networking component",
            "database_specific": {"severity": "Critical"},
            "affected": [{"package": {"name": "java", "ecosystem": "Bitnami"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "21.0.9"}]}]}],
        }
        pats = collect.patterns_of(STACKS[0]["packages"][0])
        out = collect.merge_aliases("Bitnami", pats, [bitnami, *found[("Bitnami", "java")]])
        by_cve = {v["cves"][0]: v for v in out}
        self.assertEqual(len(out), 2)
        one = by_cve["CVE-2026-1"]
        self.assertEqual(one["id"], "BIT-java-2026-1")
        self.assertEqual(one["severity"], "CRITICAL")
        self.assertEqual(one["published"], "2026-11-17T22:18:24Z")   # Debian saw it first
        self.assertEqual(one["fixed"], ["21.0.9"])                   # Debian package versions left out
        two = by_cve["CVE-2026-2"]
        self.assertEqual(two["id"], "DEBIAN-CVE-2026-2")
        self.assertEqual(two["severity"], "LOW")
        self.assertEqual(two["severity_source"], "CVSS v3 vector")
        self.assertEqual(two["fixed"], [])
        self.assertEqual(two["summary"], "Listed by Debian for openjdk-25; no summary yet")
        self.assertEqual(two["url"], "https://osv.dev/vulnerability/DEBIAN-CVE-2026-2")


if __name__ == "__main__":
    unittest.main()
