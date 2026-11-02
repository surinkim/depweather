"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const check = require("../alert/check.js");

function advisory(partial) {
  return Object.assign({
    key: "npm/next",
    id: "GHSA-crit",
    label: "Next.js",
    eco: "npm",
    summary: "remote code execution",
    severity: "CRITICAL",
    kev: false,
    malicious: false,
    fixed: ["1.2.3"],
    url: "https://osv.dev/vulnerability/GHSA-crit",
    cvss: 9.8,
    epss: 0.1,
  }, partial);
}

test("mentions, html, and unexpected links are neutralized", () => {
  const nasty = advisory({
    label: "@octocat <script>",
    summary: "@everyone @here please [click](https://evil.example/phish) or https://evil.example/a <!channel> <@123>",
    id: "GHSA-x -->\n@everyone",
    url: "https://evil.example/advisory",
    fixed: ["1.0\n@here", "ok"],
  });
  const title = check.issueTitle(nasty);
  const body = check.issueBody(nasty);
  const text = check.alertText(nasty);
  for (const out of [title, body, text]) {
    assert.doesNotMatch(out, /@everyone/);
    assert.doesNotMatch(out, /@here/);
    assert.doesNotMatch(out, /@octocat/);
    assert.doesNotMatch(out, /<script/);
    assert.doesNotMatch(out, /<!channel/);
    assert.doesNotMatch(out, /<@123>/);
    assert.doesNotMatch(out, /https:\/\/evil\.example/);
  }
  assert.match(body, /<!-- depweather-id:npm\/next\/GHSA-x--everyone -->/);
  assert.match(title, /＠everyone/);
  assert.match(body, /&lt;script&gt;/);
  assert.match(body, /\(link removed\)/);
  assert.doesNotMatch(body, /Advisory: https:\/\/evil\.example/);
  assert.match(body, /<!-- depweather-id:npm\/next\/GHSA-x--everyone -->/);
});

test("allowlisted https links stay, and other schemes do not", () => {
  const body = check.issueBody(advisory({
    summary: "see javascript:alert(1) and https://osv.dev/vulnerability/GHSA-crit",
    url: "https://osv.dev/vulnerability/GHSA-crit",
  }));
  assert.match(body, /Advisory: https:\/\/osv\.dev\/vulnerability\/GHSA-crit/);
  assert.match(body, /https:\/\/depweather\.com\/pkg\/npm\/next\//);
  assert.match(body, /https:\/\/depweather\.com\/feed\/npm\/next\.xml/);
  assert.doesNotMatch(body, /javascript:/);
  assert.equal(check.isAllowedHttpsUrl("https://user:pass@osv.dev/x"), false);
  assert.equal(check.isAllowedHttpsUrl("http://osv.dev/vulnerability/GHSA-crit"), false);
  assert.equal(check.isAllowedHttpsUrl("https://osv.dev.evil.example/x"), false);
});

test("package keys that escape the path are not turned into links", () => {
  assert.equal(check.safePackageKey("../npm/next"), null);
  assert.equal(check.safePackageKey("npm//next"), null);
  assert.equal(check.safePackageKey("npm/next"), "npm/next");
  const body = check.issueBody(advisory({ key: "npm/../../etc", id: "GHSA-crit" }));
  assert.match(body, /\(omitted\)/);
  assert.doesNotMatch(body, /\?pkg=/);
  assert.doesNotMatch(body, /\/pkg\//);
  assert.doesNotMatch(body, /\/feed\//);
  assert.doesNotMatch(body, /depweather-id:/);
});

test("webhook URLs are https Slack or Discord only", () => {
  assert.equal(check.webhookKind("https://hooks.slack.com/services/T/B/x"), "slack");
  assert.equal(check.webhookKind("https://discord.com/api/webhooks/1/secret"), "discord");
  assert.equal(check.webhookKind("https://discordapp.com/api/webhooks/1/secret"), "discord");
  assert.equal(check.webhookKind("http://hooks.slack.com/services/T/B/x"), null);
  assert.equal(check.webhookKind("https://hooks.slack.com.evil.example/services/T/B/x"), null);
  assert.equal(check.webhookKind("https://evil.example/hooks.slack.com/services/x"), null);
  assert.equal(check.webhookKind("https://user:pass@hooks.slack.com/services/T/B/x"), null);
  assert.throws(() => check.webhookPayload("https://example.com/hook", "hi"), /webhook URL/);
  const secret = "https://hooks.slack.com/services/T00/B00/secret-token";
  const err = new Error("posted to " + secret + " with ghp_abcdefghijklmnopqrstuvwxyz");
  const redacted = check.redactSecrets(err.message, [secret]);
  assert.doesNotMatch(redacted, /secret-token/);
  assert.doesNotMatch(redacted, /ghp_/);
  assert.match(redacted, /\[redacted/);
});

test("data URL and repository name are constrained", () => {
  assert.equal(check.assertDataUrl("https://depweather.com/data/latest.json"), "https://depweather.com/data/latest.json");
  assert.throws(() => check.assertDataUrl("http://depweather.com/data/latest.json"), /https/);
  assert.throws(() => check.assertDataUrl("https://depweather.com/data/other.json"), /latest\.json/);
  assert.throws(() => check.assertDataUrl("https://user:pw@depweather.com/data/latest.json"), /credentials/);
  assert.equal(check.safeRepo("surinkim/depweather"), "surinkim/depweather");
  assert.throws(() => check.safeRepo("owner/name;touch /tmp/x"), /owner\/name/);
  assert.throws(() => check.safeRepo("owner/name\n"), /owner\/name/);
});

test("lengths are capped and the title stays one line", () => {
  const title = check.issueTitle(advisory({ summary: "@everyone " + "A".repeat(500) }));
  assert.ok(title.length <= 240);
  assert.equal(title.includes("\n"), false);
  assert.match(title, /＠everyone/);
  const text = check.alertText(advisory({ summary: "B".repeat(4000) }));
  assert.ok(text.length <= 1800);
});

test("the example workflow does not track main or a risky trigger", () => {
  const root = path.join(__dirname, "..");
  const example = fs.readFileSync(path.join(root, "examples", "depweather-alert.yml"), "utf8");
  const action = fs.readFileSync(path.join(root, "alert", "action.yml"), "utf8");
  const run = fs.readFileSync(path.join(root, "alert", "run.js"), "utf8");
  const code = example.split("\n").filter((line) => !line.trim().startsWith("#")).join("\n");
  assert.doesNotMatch(code, /pull_request_target/);
  const useLines = code.split("\n").filter((line) => /^\s*- uses:/.test(line));
  assert.ok(useLines.length >= 2);
  for (const line of useLines) assert.doesNotMatch(line, /@main\b/);
  assert.match(example, /contents:\s*read/);
  assert.match(example, /issues:\s*write/);
  assert.doesNotMatch(code, /contents:\s*write/);
  assert.match(example, /persist-credentials:\s*false/);
  assert.match(example, /actions\/checkout@[0-9a-f]{40}/);
  assert.match(example, /alert@v1\.0\.0/);
  assert.doesNotMatch(action, /^\s*uses:/m);
  const runLine = action.split("run:")[1];
  assert.doesNotMatch(runLine, /\$\{\{/);
  assert.doesNotMatch(run, /console\.(log|error)\([^)]*WEBHOOK/);
  assert.doesNotMatch(run, /eval\(/);
});
