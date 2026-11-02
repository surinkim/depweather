/* Match a repository's manifests against a depweather snapshot and decide
   which advisories are worth an alert. Reuses js/stack.js, the same parser
   the website uses for "My stack". No network and no GitHub calls here. */
"use strict";

const fs = require("fs");
const path = require("path");
const stack = require("../js/stack.js");

const SITE = "https://depweather.com";
const RANK = { NONE: 0, UNKNOWN: 1, LOW: 1, MEDIUM: 2, MODERATE: 2, HIGH: 3, CRITICAL: 4 };
const THRESHOLD = { kev: 99, low: 1, medium: 2, high: 3, critical: 4 };
const DAY = 86400000;
const MARKER_RE = /<!--\s*depweather-id:(\S+)\s*-->/;

const SKIP_DIRS = new Set([
  "node_modules", "vendor", ".git", "dist", "build", "target",
  ".venv", "venv", "__pycache__", ".next", "coverage", "out",
  ".idea", ".gradle", "Pods", "Carthage", "third_party", "bower_components",
]);

function encodeSegment(seg) {
  return String(seg).replace(/~/g, "~~").replace(/:/g, "~");
}

function packageFeedUrl(key) {
  const slash = String(key).indexOf("/");
  if (slash <= 0) return `${SITE}/feed.xml`;
  const eco = key.slice(0, slash);
  const name = key.slice(slash + 1);
  const parts = [eco].concat(name.split("/")).map(encodeSegment);
  return `${SITE}/feed/${parts.join("/")}.xml`;
}

function normalizeSeverity(severity) {
  const x = String(severity == null || severity === "" ? "critical" : severity).trim().toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(THRESHOLD, x)) {
    throw new Error(`unknown severity "${severity}" (use kev, low, medium, high, or critical)`);
  }
  return x;
}

function clampDays(days) {
  if (days == null || days === "") return 7;
  const n = Number(days);
  if (!Number.isFinite(n) || n < 1) throw new Error(`days must be between 1 and 30 (got ${days})`);
  return Math.min(30, Math.floor(n));
}

function effectiveTime(v) {
  const published = Date.parse(v && v.published);
  if (!Number.isFinite(published)) return null;
  if (v.kev_date_added) {
    const added = Date.parse(String(v.kev_date_added) + "T00:00:00Z");
    if (Number.isFinite(added)) return Math.max(published, added);
  }
  return published;
}

function meetsThreshold(vuln, severity) {
  if (severity === "kev") return !!vuln.kev;
  if (vuln.kev) return true;
  if (vuln.malicious) return true;
  const rank = RANK[String(vuln.severity || "").toUpperCase()] || 0;
  return rank >= THRESHOLD[severity];
}

function markerFor(pkgKey, advisoryId) {
  return `${pkgKey}/${advisoryId}`;
}

function isManifestName(name) {
  if (name === "package.json" || name === "package-lock.json" || name === "npm-shrinkwrap.json") return true;
  if (name === "requirements.txt" || /^requirements-[^/]+\.txt$/.test(name)) return true;
  if (name === "pyproject.toml" || name === "Pipfile" || name === "go.mod" || name === "Cargo.toml") return true;
  if (name === "pom.xml" || name === "Gemfile" || name === "composer.json" || name === "mix.exs") return true;
  if (name === "packages.config" || name === "Directory.Packages.props") return true;
  if (/\.(csproj|fsproj|vbproj)$/i.test(name)) return true;
  return false;
}

function findManifests(root) {
  const out = [];
  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (e) { return; }
    for (let i = 0; i < entries.length; i++) {
      const ent = entries[i];
      if (ent.isSymbolicLink()) continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name) || ent.name.startsWith(".")) continue;
        walk(full);
        continue;
      }
      if (!ent.isFile() || !isManifestName(ent.name)) continue;
      let st;
      try { st = fs.statSync(full); }
      catch (e) { continue; }
      if (!st.isFile() || st.size > stack.MAX_CHARS) continue;
      let text;
      try { text = fs.readFileSync(full, "utf8"); }
      catch (e) { continue; }
      out.push({ path: full, text: text });
    }
  }
  walk(root);
  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

function matchFiles(files, ecosystems) {
  let state = null;
  const used = [];
  const skipped = [];
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    const parsed = stack.parseManifest(f.text);
    if (!parsed || parsed.error || !parsed.eco) {
      skipped.push({ path: f.path, error: (parsed && parsed.error) || "format" });
      continue;
    }
    const matched = stack.matchStack(parsed, ecosystems);
    state = stack.stackFromMatch(matched, state, state ? "add" : "replace");
    used.push({
      path: f.path,
      format: parsed.format,
      tracked: matched.tracked.length,
      untracked: matched.untracked.length,
    });
  }
  return {
    tracked: (state && state.tracked) || [],
    untracked: (state && state.untracked) || [],
    used: used,
    skipped: skipped,
  };
}

function indexPackages(ecosystems) {
  const map = new Map();
  const list = ecosystems || [];
  for (let i = 0; i < list.length; i++) {
    const e = list[i];
    const pkgs = e.packages || [];
    for (let j = 0; j < pkgs.length; j++) map.set(pkgs[j].key, { eco: e, pkg: pkgs[j] });
  }
  return map;
}

function toAlert(hit, vuln, when) {
  const pkg = hit.pkg;
  const eco = hit.eco;
  const severity = String(vuln.severity || "UNKNOWN").toUpperCase();
  return {
    key: pkg.key,
    name: pkg.name,
    label: pkg.label || pkg.name,
    eco: eco.id,
    ecoLabel: eco.label || eco.id,
    id: vuln.id,
    url: vuln.url || "",
    summary: vuln.summary || "",
    severity: severity,
    kev: !!vuln.kev,
    kevDate: vuln.kev_date_added || null,
    malicious: !!vuln.malicious,
    cvss: vuln.cvss == null ? null : vuln.cvss,
    epss: vuln.epss == null ? null : vuln.epss,
    fixed: Array.isArray(vuln.fixed) ? vuln.fixed.filter(Boolean) : [],
    published: vuln.published,
    when: when,
    rank: vuln.malicious ? 4 : (RANK[severity] || 0),
    marker: markerFor(pkg.key, vuln.id),
  };
}

function selectAlerts(ecosystems, trackedKeys, opts) {
  const options = opts || {};
  const severity = normalizeSeverity(options.severity);
  const days = clampDays(options.days);
  const now = options.now != null ? options.now : Date.now();
  const since = now - days * DAY;
  const wanted = new Set(trackedKeys || []);
  const index = indexPackages(ecosystems);
  const out = [];
  const seen = new Set();
  for (const key of wanted) {
    const hit = index.get(key);
    if (!hit) continue;
    const vulns = hit.pkg.vulns || [];
    for (let i = 0; i < vulns.length; i++) {
      const vuln = vulns[i];
      if (!vuln || !vuln.id) continue;
      const when = effectiveTime(vuln);
      if (when == null || when < since) continue;
      if (!meetsThreshold(vuln, severity)) continue;
      const marker = markerFor(key, vuln.id);
      if (seen.has(marker)) continue;
      seen.add(marker);
      out.push(toAlert(hit, vuln, when));
    }
  }
  return sortAlerts(out);
}

function sortAlerts(items) {
  return items.slice().sort((a, b) => {
    if (a.kev !== b.kev) return a.kev ? -1 : 1;
    if (b.rank !== a.rank) return b.rank - a.rank;
    if (b.when !== a.when) return b.when - a.when;
    return a.marker < b.marker ? -1 : a.marker > b.marker ? 1 : 0;
  });
}

function markersInIssues(issues) {
  const set = new Set();
  const list = issues || [];
  for (let i = 0; i < list.length; i++) {
    const issue = list[i];
    if (!issue || issue.pull_request) continue;
    const m = MARKER_RE.exec(issue.body || "");
    if (m) set.add(m[1]);
  }
  return set;
}

function unseenAlerts(alerts, known) {
  const have = known instanceof Set ? known : new Set(known || []);
  return (alerts || []).filter((a) => !have.has(a.marker));
}

function issueTitle(a) {
  const tags = [];
  if (a.kev) tags.push("KEV");
  if (a.malicious) tags.push("malicious");
  else if (a.severity === "CRITICAL") tags.push("critical");
  else tags.push(String(a.severity || "unrated").toLowerCase());
  const prefix = `[depweather] ${tags.join(", ")} · ${a.label}: `;
  let summary = a.summary || a.id;
  const room = 240 - prefix.length;
  if (summary.length > room) summary = summary.slice(0, Math.max(0, room - 1)).trimEnd() + "…";
  return prefix + summary;
}

function issueBody(a) {
  const lines = [`<!-- depweather-id:${a.marker} -->`, ""];
  const flags = [];
  if (a.kev) flags.push(a.kevDate ? `**CISA KEV** (added ${a.kevDate})` : "**CISA KEV**");
  if (a.malicious) flags.push("**Malicious package**");
  lines.push(`**${a.label}** (\`${a.key}\`) · ${a.severity || "unrated"}${flags.length ? " · " + flags.join(" · ") : ""}`);
  lines.push("");
  if (a.summary) {
    lines.push(a.summary);
    lines.push("");
  }
  if (a.fixed.length) lines.push(`Fixed in: ${a.fixed.join(", ")}`);
  if (a.cvss != null) lines.push(`CVSS: ${a.cvss}`);
  if (a.epss != null) lines.push(`EPSS: ${a.epss}`);
  lines.push("");
  if (a.url) lines.push(`- Advisory: ${a.url}`);
  lines.push(`- On depweather: ${SITE}/?pkg=${encodeURIComponent(a.key)}`);
  lines.push(`- Package feed: ${packageFeedUrl(a.key)}`);
  lines.push("");
  lines.push("depweather only knows that this package has a new advisory. It does not check the version you have installed. Read the advisory before changing anything.");
  lines.push("");
  lines.push(`Source: ${SITE}`);
  return lines.join("\n");
}

function alertText(a) {
  const tags = [];
  if (a.kev) tags.push("KEV");
  if (a.malicious) tags.push("malicious");
  else if (a.severity === "CRITICAL") tags.push("critical");
  else tags.push(String(a.severity || "unrated").toLowerCase());
  const fixed = a.fixed.length ? `; fixed in ${a.fixed.slice(0, 4).join(", ")}` : "";
  const summary = a.summary ? ` — ${a.summary}` : "";
  return `depweather: [${tags.join(", ")}] ${a.label} (${a.eco}) ${a.id}${summary}${fixed} ${a.url}`.trim();
}

function webhookPayload(url, text) {
  const body = String(text || "");
  if (/discord(?:app)?\.com\/api\/webhooks/i.test(String(url || ""))) {
    return { content: body.slice(0, 1900) };
  }
  return { text: body.slice(0, 3500) };
}

module.exports = {
  SITE,
  MARKER_RE,
  encodeSegment,
  packageFeedUrl,
  normalizeSeverity,
  clampDays,
  effectiveTime,
  meetsThreshold,
  markerFor,
  isManifestName,
  findManifests,
  matchFiles,
  selectAlerts,
  sortAlerts,
  markersInIssues,
  unseenAlerts,
  issueTitle,
  issueBody,
  alertText,
  webhookPayload,
};
