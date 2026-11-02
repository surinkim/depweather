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
const MARKER_RE = /<!--\s*depweather-id:([A-Za-z0-9@._~:/-]+)\s*-->/;
const SEVERITIES = new Set(["NONE", "UNKNOWN", "LOW", "MEDIUM", "MODERATE", "HIGH", "CRITICAL"]);
const ALLOWED_LINK_HOSTS = new Set([
  "depweather.com",
  "www.depweather.com",
  "osv.dev",
  "github.com",
  "www.github.com",
  "nvd.nist.gov",
  "cisa.gov",
  "www.cisa.gov",
]);

// Untrusted advisory text is flattened, then mentions and unexpected links are
// broken before it is placed in an issue or a chat message.
function plain(value, max) {
  let s = String(value == null ? "" : value);
  s = s.replace(/[\u0000-\u001F\u007F]/g, " ");
  s = s.replace(/\s+/g, " ").trim();
  // Fullwidth substitutes, so a parser that strips format characters still
  // does not see @everyone, @user, <!channel>, or <@id>.
  s = s.replace(/<!/g, "＜!");
  s = s.replace(/<@/g, "＜＠");
  s = s.replace(/@(?=[A-Za-z0-9])/g, "＠");
  s = s.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1");
  s = s.replace(/\b(?:https?|javascript|data):[^\s]+/gi, "(link removed)");
  if (s.length > max) s = s.slice(0, Math.max(0, max - 1)).trimEnd() + "…";
  s = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  s = s.replace(/[\\`*_{}\[\]#|]/g, (ch) => "\\" + ch);
  return s;
}

function safeSeverity(value) {
  const u = String(value || "").toUpperCase();
  if (!SEVERITIES.has(u)) return "UNKNOWN";
  return u === "MODERATE" ? "MEDIUM" : u;
}

function safePackageKey(key) {
  const s = String(key || "");
  if (!/^[A-Za-z0-9][A-Za-z0-9@._~:/-]{0,200}$/.test(s)) return null;
  if (s.includes("..") || s.includes("//")) return null;
  return s;
}

function safeAdvisoryId(id) {
  const s = String(id || "").replace(/[^A-Za-z0-9._:-]/g, "").slice(0, 80);
  return s || null;
}

function isAllowedHttpsUrl(value) {
  let u;
  try { u = new URL(String(value || "")); }
  catch (e) { return false; }
  if (u.protocol !== "https:") return false;
  if (u.username || u.password) return false;
  return ALLOWED_LINK_HOSTS.has(u.hostname.toLowerCase());
}

function webhookKind(value) {
  let u;
  try { u = new URL(String(value || "")); }
  catch (e) { return null; }
  if (u.protocol !== "https:" || u.username || u.password) return null;
  const host = u.hostname.toLowerCase();
  if ((host === "hooks.slack.com" || host === "hooks.slack-gov.com") && u.pathname.startsWith("/services/")) return "slack";
  if ((host === "discord.com" || host === "discordapp.com") && u.pathname.startsWith("/api/webhooks/")) return "discord";
  return null;
}

function assertDataUrl(value) {
  let u;
  try { u = new URL(String(value || "")); }
  catch (e) { throw new Error("data URL is not a valid URL"); }
  if (u.protocol !== "https:" || u.username || u.password) throw new Error("data URL must be https with no credentials");
  if (u.hostname !== "depweather.com" || u.pathname !== "/data/latest.json" || u.search || u.hash) {
    throw new Error("data URL must be https://depweather.com/data/latest.json");
  }
  return u.toString();
}

function safeRepo(name) {
  const s = String(name || "");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(s)) throw new Error("GITHUB_REPOSITORY is not owner/name");
  return s;
}

function plainNumber(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || Math.abs(n) > 1000) return null;
  return String(Math.round(n * 100000) / 100000);
}

function redactSecrets(msg, secrets) {
  let s = String(msg == null ? "" : msg);
  const list = secrets || [];
  for (let i = 0; i < list.length; i++) {
    const secret = list[i];
    if (typeof secret === "string" && secret.length >= 8) s = s.split(secret).join("[redacted]");
  }
  s = s.replace(/\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]+/g, "[redacted]");
  s = s.replace(/https:\/\/hooks\.slack(?:-gov)?\.com\/\S+/gi, "[redacted-webhook]");
  s = s.replace(/https:\/\/discord(?:app)?\.com\/api\/webhooks\/\S+/gi, "[redacted-webhook]");
  return s.slice(0, 500);
}

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
  if (severity === "kev") return vuln.kev === true;
  if (vuln.kev === true) return true;
  if (vuln.malicious === true) return true;
  const rank = RANK[String(vuln.severity || "").toUpperCase()] || 0;
  return rank >= THRESHOLD[severity];
}

function markerFor(pkgKey, advisoryId) {
  const key = safePackageKey(pkgKey);
  const id = safeAdvisoryId(advisoryId);
  if (!key || !id) return "";
  return `${key}/${id}`;
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
  const severity = safeSeverity(vuln.severity);
  const key = safePackageKey(pkg.key);
  const id = safeAdvisoryId(vuln.id);
  return {
    key: key || "",
    name: pkg.name,
    label: pkg.label || pkg.name,
    eco: eco.id,
    ecoLabel: eco.label || eco.id,
    id: id || "",
    url: isAllowedHttpsUrl(vuln.url) ? String(vuln.url) : "",
    summary: vuln.summary || "",
    severity: severity,
    kev: vuln.kev === true,
    kevDate: /^\d{4}-\d{2}-\d{2}$/.test(String(vuln.kev_date_added || "")) ? vuln.kev_date_added : null,
    malicious: vuln.malicious === true,
    cvss: plainNumber(vuln.cvss),
    epss: plainNumber(vuln.epss),
    fixed: (Array.isArray(vuln.fixed) ? vuln.fixed : []).filter((f) => typeof f === "string" && f).slice(0, 8),
    published: vuln.published,
    when: when,
    rank: vuln.malicious === true ? 4 : (RANK[severity] || 0),
    marker: key && id ? `${key}/${id}` : "",
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
      if (!marker || seen.has(marker)) continue;
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
  const severity = safeSeverity(a.severity);
  if (a.kev === true) tags.push("KEV");
  if (a.malicious === true) tags.push("malicious");
  else if (severity === "CRITICAL") tags.push("critical");
  else tags.push(severity.toLowerCase());
  const label = plain(a.label, 80);
  const summary = plain(a.summary || a.id, 160);
  let title = `[depweather] ${tags.join(", ")} · ${label}: ${summary}`;
  if (title.length > 240) title = title.slice(0, 239).trimEnd() + "…";
  return title;
}

function issueBody(a) {
  const marker = markerFor(a.key, a.id);
  const severity = safeSeverity(a.severity);
  const lines = [];
  if (marker) lines.push(`<!-- depweather-id:${marker} -->`, "");
  const flags = [];
  if (a.kev === true) flags.push(a.kevDate && /^\d{4}-\d{2}-\d{2}$/.test(a.kevDate) ? `**CISA KEV** (added ${a.kevDate})` : "**CISA KEV**");
  if (a.malicious === true) flags.push("**Malicious package**");
  const key = safePackageKey(a.key);
  const keyText = key ? plain(key, 200) : "(omitted)";
  lines.push(`**${plain(a.label, 80)}** (\`${keyText}\`) · ${severity}${flags.length ? " · " + flags.join(" · ") : ""}`);
  lines.push("");
  const summary = plain(a.summary, 500);
  if (summary) lines.push(summary, "");
  const fixed = (Array.isArray(a.fixed) ? a.fixed : []).slice(0, 8).map((f) => plain(f, 40)).filter(Boolean);
  if (fixed.length) lines.push(`Fixed in: ${fixed.join(", ")}`);
  const cvss = plainNumber(a.cvss);
  const epss = plainNumber(a.epss);
  if (cvss != null) lines.push(`CVSS: ${cvss}`);
  if (epss != null) lines.push(`EPSS: ${epss}`);
  lines.push("");
  if (isAllowedHttpsUrl(a.url)) lines.push(`- Advisory: ${a.url}`);
  if (key) {
    lines.push(`- On depweather: ${SITE}/?pkg=${encodeURIComponent(key)}`);
    lines.push(`- Package feed: ${packageFeedUrl(key)}`);
  }
  lines.push("");
  lines.push("depweather only knows that this package has a new advisory. It does not check the version you have installed. Read the advisory before changing anything.");
  lines.push("");
  lines.push(`Source: ${SITE}`);
  return lines.join("\n").slice(0, 6000);
}

function alertText(a) {
  const tags = [];
  const severity = safeSeverity(a.severity);
  if (a.kev === true) tags.push("KEV");
  if (a.malicious === true) tags.push("malicious");
  else if (severity === "CRITICAL") tags.push("critical");
  else tags.push(severity.toLowerCase());
  const fixed = (Array.isArray(a.fixed) ? a.fixed : []).slice(0, 4).map((f) => plain(f, 40)).filter(Boolean);
  const fixedPart = fixed.length ? `; fixed in ${fixed.join(", ")}` : "";
  const summary = a.summary ? ` — ${plain(a.summary, 240)}` : "";
  const link = isAllowedHttpsUrl(a.url) ? ` ${a.url}` : "";
  let text = `depweather: [${tags.join(", ")}] ${plain(a.label, 80)} (${plain(a.eco, 32)}) ${plain(a.id, 80)}${summary}${fixedPart}${link}`.trim();
  if (text.length > 1800) text = text.slice(0, 1799).trimEnd() + "…";
  return text;
}

function webhookPayload(url, text) {
  const kind = webhookKind(url);
  if (!kind) throw new Error("webhook URL must be https on hooks.slack.com or discord.com/api/webhooks");
  const body = String(text || "").slice(0, kind === "discord" ? 1900 : 3000);
  if (kind === "discord") return { content: body };
  return { text: body };
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
  plain,
  safePackageKey,
  isAllowedHttpsUrl,
  webhookKind,
  assertDataUrl,
  safeRepo,
  redactSecrets,
};
