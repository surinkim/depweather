#!/usr/bin/env node
/* Daily alert runner. Reads manifests in DEPWEATHER_ROOT (or the GitHub
   workspace), downloads data/latest.json, and opens an issue and/or posts
   a Slack or Discord webhook for each new KEV/critical match.

   Dedup is the issue list: the body contains <!-- depweather-id:KEY -->.
   Closed issues count, so the same advisory is not reported every day.
   Set DEPWEATHER_DRY_RUN=1 to print matches and write nothing. */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const check = require("./check.js");

const DEFAULT_DATA = "https://depweather.com/data/latest.json";

function envFlag(name, fallback) {
  const v = process.env[name];
  if (v == null || v === "") return fallback;
  return !/^(0|false|no|off)$/i.test(v);
}

function gh(args) {
  const r = spawnSync("gh", args, { encoding: "utf8" });
  return r;
}

function ghOk(args, what) {
  const r = gh(args);
  if (r.error) throw new Error(`${what}: ${r.error.message}`);
  if (r.status !== 0) {
    const msg = ((r.stderr || "") + (r.stdout || "")).trim();
    const err = new Error(msg || `${what} failed`);
    err.status = r.status;
    throw err;
  }
  return r.stdout || "";
}

function existingMarkers(repo) {
  const r = gh([
    "issue", "list", "--repo", repo, "--state", "all", "--label", "depweather",
    "--limit", "300", "--json", "number,body,title",
  ]);
  if (r.error) throw new Error(`gh issue list: ${r.error.message}`);
  if (r.status !== 0) {
    const msg = ((r.stderr || "") + (r.stdout || "")).trim();
    if (/not found|could not find|no labels/i.test(msg)) return new Set();
    throw new Error(msg || "gh issue list failed");
  }
  let issues = [];
  try { issues = JSON.parse(r.stdout || "[]"); }
  catch (e) { throw new Error("gh issue list returned invalid JSON"); }
  return check.markersInIssues(issues);
}

function ensureLabel(repo) {
  const args = [
    "label", "create", "depweather", "--repo", repo, "--color", "A32CA0",
    "--description", "Opened by the depweather alert action", "--force",
  ];
  let r = gh(args);
  if (r.status === 0) return;
  const msg = ((r.stderr || "") + (r.stdout || "")).trim();
  if (/already exists/i.test(msg)) return;
  r = gh(args.filter((a) => a !== "--force"));
  if (r.status === 0) return;
  const msg2 = ((r.stderr || "") + (r.stdout || "")).trim();
  if (/already exists/i.test(msg2)) return;
  throw new Error(msg2 || msg || "could not create the depweather label");
}

function createIssue(repo, title, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "depweather-"));
  const bodyFile = path.join(dir, "body.md");
  fs.writeFileSync(bodyFile, body);
  try {
    const url = ghOk([
      "issue", "create", "--repo", repo, "--title", title,
      "--body-file", bodyFile, "--label", "depweather",
    ], "gh issue create").trim();
    return url;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function closeIssue(repo, url) {
  const number = String(url).split("/").filter(Boolean).pop();
  ghOk([
    "issue", "close", number, "--repo", repo, "--reason", "not planned",
    "--comment", "Recorded so depweather does not send this advisory again.",
  ], "gh issue close");
}

async function loadData() {
  if (process.env.DEPWEATHER_DATA_FILE) {
    return JSON.parse(fs.readFileSync(process.env.DEPWEATHER_DATA_FILE, "utf8"));
  }
  const url = process.env.DEPWEATHER_DATA_URL || DEFAULT_DATA;
  const res = await fetch(url, { headers: { "user-agent": "depweather-alert (+https://depweather.com)" } });
  if (!res.ok) throw new Error(`could not download latest.json (HTTP ${res.status})`);
  return res.json();
}

async function postWebhook(url, text) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "depweather-alert" },
    body: JSON.stringify(check.webhookPayload(url, text)),
  });
  if (!res.ok) throw new Error(`webhook returned HTTP ${res.status}`);
}

async function main() {
  const root = process.env.DEPWEATHER_ROOT || process.env.GITHUB_WORKSPACE || process.cwd();
  const dry = envFlag("DEPWEATHER_DRY_RUN", false);
  const openIssue = envFlag("DEPWEATHER_OPEN_ISSUE", true);
  const webhook = process.env.DEPWEATHER_WEBHOOK_URL || "";
  const severity = check.normalizeSeverity(process.env.DEPWEATHER_SEVERITY || "critical");
  const days = check.clampDays(process.env.DEPWEATHER_DAYS || "7");
  let max = Number(process.env.DEPWEATHER_MAX || 20);
  if (!Number.isFinite(max) || max < 1) max = 20;
  max = Math.min(100, Math.floor(max));

  const files = check.findManifests(root);
  if (!files.length) {
    console.log("No dependency manifests found.");
    return;
  }
  const data = await loadData();
  const ecosystems = data.ecosystems || [];
  const matched = check.matchFiles(files, ecosystems);
  const now = process.env.DEPWEATHER_NOW ? Date.parse(process.env.DEPWEATHER_NOW) : Date.now();
  if (process.env.DEPWEATHER_NOW && !Number.isFinite(now)) {
    throw new Error("DEPWEATHER_NOW is not a time");
  }
  console.log(`Read ${matched.used.length} manifest(s), ${matched.tracked.length} tracked package(s), ${matched.skipped.length} skipped.`);
  for (const u of matched.used) {
    console.log(`  ${path.relative(root, u.path) || u.path}: ${u.format}, ${u.tracked} tracked, ${u.untracked} not tracked`);
  }
  const alerts = check.selectAlerts(ecosystems, matched.tracked, { severity, days, now });
  if (!alerts.length) {
    console.log(`No ${severity} advisories in the last ${days} days for those packages.`);
    return;
  }

  let fresh = alerts;
  if (!dry && (openIssue || webhook)) {
    const repo = process.env.GITHUB_REPOSITORY;
    if (!repo) throw new Error("GITHUB_REPOSITORY is not set");
    if (!process.env.GITHUB_TOKEN && !process.env.GH_TOKEN) {
      throw new Error("GITHUB_TOKEN is not set; the workflow must pass it to open issues");
    }
    ensureLabel(repo);
    const known = existingMarkers(repo);
    fresh = check.unseenAlerts(alerts, known);
  }

  if (!fresh.length) {
    console.log(`${alerts.length} matching advisory(ies); all of them already have a depweather issue.`);
    return;
  }
  const batch = fresh.slice(0, max);
  const held = fresh.length - batch.length;
  console.log(`${fresh.length} new advisory(ies); sending ${batch.length}.`);

  for (const a of batch) {
    console.log(`alert ${a.marker}${a.kev ? " kev" : ""} ${a.severity}`);
    if (dry || (!openIssue && !webhook)) continue;
    const repo = process.env.GITHUB_REPOSITORY;
    const url = createIssue(repo, check.issueTitle(a), check.issueBody(a));
    console.log(`  issue ${url}`);
    if (!openIssue) {
      closeIssue(repo, url);
      console.log("  closed (webhook-only record)");
    }
    if (webhook) {
      await postWebhook(webhook, check.alertText(a));
      console.log("  webhook posted");
    }
  }
  if (held > 0) console.log(`${held} more left for the next run.`);
  if (dry) console.log("Dry run: no issues opened, no webhook posted.");
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e && e.message ? e.message : e);
    process.exit(1);
  });
}

module.exports = { main };
