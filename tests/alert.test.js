"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const check = require("../alert/check.js");

const NOW = Date.parse("2026-11-02T00:00:00Z");
const DAY = 86400000;

function iso(ms) { return new Date(ms).toISOString().replace(".000Z", "Z"); }

function vuln(partial) {
  return Object.assign({
    id: "GHSA-test-test-test",
    summary: "example",
    severity: "CRITICAL",
    published: iso(NOW - 2 * DAY),
    url: "https://osv.dev/vulnerability/GHSA-test-test-test",
    fixed: ["1.2.3"],
    malicious: false,
    kev: false,
    kev_date_added: null,
    cvss: 9.8,
    epss: 0.1,
  }, partial);
}

const ECO = [
  { id: "npm", label: "npm", packages: [
    { key: "npm/next", name: "next", label: "Next.js", vulns: [
      vuln({ id: "GHSA-crit", summary: "remote code execution", severity: "CRITICAL" }),
      vuln({ id: "GHSA-med", summary: "cache leak", severity: "MEDIUM", cvss: 5.3 }),
      vuln({ id: "GHSA-old", summary: "old bug", severity: "CRITICAL", published: iso(NOW - 20 * DAY) }),
    ]},
    { key: "npm/lodash", name: "lodash", label: "lodash", vulns: [
      vuln({ id: "GHSA-high", summary: "prototype pollution", severity: "HIGH", cvss: 7.5 }),
    ]},
  ]},
  { id: "pypi", label: "PyPI", packages: [
    { key: "pypi/pillow", name: "pillow", label: "pillow", vulns: [
      vuln({ id: "PYSEC-1", summary: "buffer overflow & <tag>", severity: "CRITICAL" }),
    ]},
  ]},
  { id: "maven", label: "Maven", packages: [
    { key: "maven/org.springframework.boot:spring-boot", name: "org.springframework.boot:spring-boot", label: "Spring Boot", vulns: [
      vuln({ id: "GHSA-boot", summary: "auth bypass", severity: "HIGH" }),
    ]},
  ]},
  { id: "rubygems", label: "RubyGems", packages: [
    { key: "rubygems/rails", name: "rails", label: "Ruby on Rails", vulns: [
      vuln({
        id: "GHSA-rails",
        summary: "old bug, exploited now",
        severity: "MEDIUM",
        published: iso(NOW - 40 * DAY),
        kev: true,
        kev_date_added: "2026-11-01",
      }),
    ]},
  ]},
  { id: "runtimes", label: "Runtimes & servers", packages: [
    { key: "runtimes/php", name: "php", label: "PHP", vulns: [
      vuln({ id: "BIT-php-1", summary: "memory corruption", severity: "CRITICAL", kev: true, kev_date_added: "2026-10-26" }),
    ]},
  ]},
];

function ids(alerts) { return alerts.map((a) => a.id); }

test("feed URLs encode Maven colons and keep slashes and scopes", () => {
  assert.equal(check.packageFeedUrl("npm/next"), "https://depweather.com/feed/npm/next.xml");
  assert.equal(check.packageFeedUrl("npm/@angular/core"), "https://depweather.com/feed/npm/@angular/core.xml");
  assert.equal(
    check.packageFeedUrl("maven/org.springframework.boot:spring-boot"),
    "https://depweather.com/feed/maven/org.springframework.boot~spring-boot.xml"
  );
  assert.equal(
    check.packageFeedUrl("go/github.com/gin-gonic/gin"),
    "https://depweather.com/feed/go/github.com/gin-gonic/gin.xml"
  );
  assert.equal(check.encodeSegment("foo~bar:baz"), "foo~~bar~baz");
});

test("package page URLs use the feed slug", () => {
  assert.equal(check.packagePageUrl("npm/next"), "https://depweather.com/pkg/npm/next/");
  assert.equal(check.packagePageUrl("npm/@angular/core"), "https://depweather.com/pkg/npm/@angular/core/");
  assert.equal(
    check.packagePageUrl("maven/org.springframework.boot:spring-boot"),
    "https://depweather.com/pkg/maven/org.springframework.boot~spring-boot/"
  );
  assert.equal(
    check.packagePageUrl("go/github.com/gin-gonic/gin"),
    "https://depweather.com/pkg/go/github.com/gin-gonic/gin/"
  );
  assert.equal(check.packagePageUrl("npm/../../etc"), "https://depweather.com/");
});

test("critical threshold keeps KEV and critical, drops high, medium, and old", () => {
  const matched = check.matchFiles([
    { path: "package.json", text: JSON.stringify({ dependencies: { next: "1.0.0", lodash: "1.0.0", "left-pad": "1.0.0" } }) },
  ], ECO);
  assert.deepEqual(matched.tracked, ["npm/next", "npm/lodash"]);
  assert.equal(matched.untracked.length, 1);
  const alerts = check.selectAlerts(ECO, matched.tracked, { severity: "critical", days: 7, now: NOW });
  assert.deepEqual(ids(alerts), ["GHSA-crit"]);
});

test("high threshold includes high but not medium", () => {
  const alerts = check.selectAlerts(ECO, ["npm/next", "npm/lodash"], { severity: "high", days: 7, now: NOW });
  assert.deepEqual(ids(alerts).sort(), ["GHSA-crit", "GHSA-high"]);
});

test("kev threshold is KEV only, and a later KEV date makes an old advisory new", () => {
  const only = check.selectAlerts(ECO, ["npm/next", "rubygems/rails", "runtimes/php"], { severity: "kev", days: 7, now: NOW });
  assert.deepEqual(ids(only).sort(), ["BIT-php-1", "GHSA-rails"]);
  const widened = check.selectAlerts(ECO, ["npm/next"], { severity: "critical", days: 30, now: NOW });
  assert.ok(ids(widened).includes("GHSA-old"));
});

test("PyPI names and Spring starters match the website aliases", () => {
  const py = check.matchFiles([
    { path: "requirements.txt", text: "Pillow==10.0.0\nDjango>=4\n" },
  ], ECO);
  assert.deepEqual(py.tracked, ["pypi/pillow"]);
  const pom = `<?xml version="1.0"?>
<project><dependencies>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
</dependencies></project>`;
  const mv = check.matchFiles([{ path: "pom.xml", text: pom }], ECO);
  assert.deepEqual(mv.tracked, ["maven/org.springframework.boot:spring-boot"]);
  const gem = 'gem "actionpack", ">= 7.1"\n';
  const rb = check.matchFiles([{ path: "Gemfile", text: gem }], ECO);
  assert.deepEqual(rb.tracked, ["rubygems/rails"]);
});

test("several manifests are merged, and node_modules is ignored", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "depweather-alert-"));
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { next: "^15.0.0" } }));
  fs.writeFileSync(path.join(dir, "requirements.txt"), "pillow==10.0.0\n");
  fs.mkdirSync(path.join(dir, "node_modules", "lodash"), { recursive: true });
  fs.writeFileSync(path.join(dir, "node_modules", "lodash", "package.json"), JSON.stringify({ dependencies: { express: "1.0.0" } }));
  fs.writeFileSync(path.join(dir, "README.md"), "not a manifest");
  const files = check.findManifests(dir);
  assert.equal(files.length, 2);
  const matched = check.matchFiles(files, ECO);
  assert.deepEqual(matched.tracked.sort(), ["npm/next", "pypi/pillow"]);
});

test("issue marker is stable and skips advisories that already have an issue", () => {
  const alerts = check.selectAlerts(ECO, ["npm/next"], { severity: "critical", days: 7, now: NOW });
  const body = check.issueBody(alerts[0]);
  assert.match(body, /<!-- depweather-id:npm\/next\/GHSA-crit -->/);
  assert.match(check.issueTitle(alerts[0]), /^\[depweather\] critical · Next\.js: remote code execution$/);
  const known = check.markersInIssues([
    { body, title: "x" },
    { pull_request: {}, body: "<!-- depweather-id:npm/lodash/GHSA-high -->" },
  ]);
  assert.deepEqual([...known], ["npm/next/GHSA-crit"]);
  assert.equal(check.unseenAlerts(alerts, known).length, 0);
  const again = check.issueBody(alerts[0]);
  assert.equal(again, body);
});

test("KEV title is marked, and webhook payloads follow Slack or Discord", () => {
  const alerts = check.selectAlerts(ECO, ["runtimes/php"], { severity: "critical", days: 14, now: NOW });
  assert.equal(alerts[0].kev, true);
  assert.match(check.issueTitle(alerts[0]), /^\[depweather\] KEV, critical · PHP:/);
  assert.match(check.alertText(alerts[0]), /\[KEV, critical\]/);
  assert.deepEqual(check.webhookPayload("https://hooks.slack.com/services/T/B/x", "hello"), { text: "hello" });
  assert.deepEqual(check.webhookPayload("https://discord.com/api/webhooks/1/secret", "hello"), { content: "hello" });
  const long = "x".repeat(3000);
  assert.equal(check.webhookPayload("https://discord.com/api/webhooks/1/s", long).content.length, 1900);
});

test("dry run prints the critical match and does not mention an untracked package", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "depweather-dry-"));
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({
    dependencies: { next: "15.0.0", "left-pad": "1.0.0" },
  }));
  const data = { generated_at: "2026-11-02T00:00:00Z", ecosystems: ECO };
  const dataFile = path.join(dir, "latest.json");
  fs.writeFileSync(dataFile, JSON.stringify(data));
  const r = spawnSync(process.execPath, [path.join(__dirname, "..", "alert", "run.js")], {
    encoding: "utf8",
    env: Object.assign({}, process.env, {
      DEPWEATHER_DRY_RUN: "1",
      DEPWEATHER_ROOT: dir,
      DEPWEATHER_DATA_FILE: dataFile,
      DEPWEATHER_SEVERITY: "critical",
      DEPWEATHER_DAYS: "7",
      DEPWEATHER_NOW: "2026-11-02T00:00:00Z",
      DEPWEATHER_OPEN_ISSUE: "true",
      GITHUB_REPOSITORY: "example/app",
    }),
  });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /alert npm\/next\/GHSA-crit/);
  assert.match(r.stdout, /Dry run/);
  assert.doesNotMatch(r.stdout, /left-pad/);
  assert.doesNotMatch(r.stdout, /GHSA-med/);
  assert.doesNotMatch(r.stdout, /GHSA-old/);
});
