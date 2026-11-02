/* depweather "My stack" — parse a dependency manifest and match it to tracked packages.
   Runs in the browser (classic script, exposes DepweatherStack) and in Node tests.
   Nothing in here sends the file anywhere. */
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.DepweatherStack = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  // Extra OSV names that count as a tile. Mirrors `match` in collect/stacks.yml.
  // Keys are the package keys published in data/latest.json (`<eco id>/<name>`).
  // A trailing * is a prefix, same rule as the collector.
  var MATCH_ALIASES = {
    "maven/org.springframework.boot:spring-boot": ["org.springframework.boot:*"],
    "nuget/Microsoft.AspNetCore.App.Runtime.linux-x64": ["Microsoft.AspNetCore.*"],
    "nuget/Microsoft.NETCore.App.Runtime.linux-x64": ["Microsoft.NETCore.App.Runtime.*"],
    "nuget/Microsoft.AspNetCore.Components": ["Microsoft.AspNetCore.Components*"],
    "nuget/System.IdentityModel.Tokens.Jwt": ["Microsoft.IdentityModel.*"],
    "crates/rustls": ["rustls-webpki"],
    "packagist/symfony/http-kernel": ["symfony/*"],
    "packagist/drupal/core": ["drupal/core*", "drupal/drupal"],
    "go/github.com/docker/docker": ["github.com/moby/moby"],
    "rubygems/rails": [
      "actionpack", "actionview", "actiontext", "actionmailer", "actioncable",
      "activerecord", "activestorage", "activesupport", "activemodel", "activejob", "railties"
    ],
    "hex/cowboy": ["cowlib"],
    "runtimes/php": ["php-min", "libphp"],
    "runtimes/node": ["node-min"],
    "runtimes/python": ["python-min", "libpython"],
    "runtimes/java": ["java-min", "jre"],
    "runtimes/ruby": ["ruby-min"]
  };

  var FORMAT_ECO = {
    npm: "npm",
    pypi: "pypi",
    gomod: "go",
    cargo: "crates",
    maven: "maven",
    gem: "rubygems",
    composer: "packagist",
    nuget: "nuget",
    mix: "hex"
  };

  var MAX_CHARS = 1000000;

  function normName(eco, s) {
    var x = String(s == null ? "" : s).trim();
    if (eco === "pypi") return x.toLowerCase().replace(/[-_.]+/g, "-"); // PEP 503
    // Registries that treat names as case-insensitive.
    if (eco === "nuget" || eco === "packagist" || eco === "rubygems" || eco === "npm" || eco === "crates" || eco === "hex") {
      return x.toLowerCase();
    }
    return x;
  }

  function dedupe(names, sensitive) {
    var out = [], seen = Object.create(null);
    for (var i = 0; i < names.length; i++) {
      var n = names[i];
      if (!n) continue;
      var key = sensitive ? n : n.toLowerCase();
      if (seen[key]) continue;
      seen[key] = 1;
      out.push(n);
    }
    return out;
  }

  function stripBom(s) { return String(s || "").replace(/^\uFEFF/, ""); }

  function reqName(spec) {
    var line = String(spec || "").trim();
    if (!line) return null;
    var at = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*@/);
    if (at) return at[1];
    var m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
    return m ? m[1] : null;
  }

  function stripReqComment(line) {
    if (/:\/\//.test(line) || /^(git|hg|svn|bzr)\+/.test(line)) return line;
    return line.replace(/\s+#.*$/, "");
  }

  function parseRequirements(text) {
    var names = [];
    var lines = text.replace(/\\\r?\n/g, " ").split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.charAt(0) === "#") continue;
      if (/^(-r|--requirement|-c|--constraint|-f|--find-links|-i|--index-url|--extra-index-url|--hash|--no-binary|--only-binary|--trusted-host|--use-feature)\b/.test(line)) continue;
      if (/^--/.test(line)) continue;
      var editable = false;
      if (/^(-e|--editable)\s+/.test(line)) {
        editable = true;
        line = line.replace(/^(-e|--editable)\s+/, "");
      }
      line = stripReqComment(line).split(";")[0].trim();
      if (!line) continue;
      var name = null;
      if (/^(https?:|git\+|svn\+|hg\+|bzr\+|file:|\.\/|\.\.\/)/.test(line) || editable && /:\/\//.test(line)) {
        var egg = line.match(/[#&]egg=([^&\s]+)/);
        if (egg) name = egg[1];
      } else {
        name = reqName(line);
      }
      if (name && /^[A-Za-z0-9]/.test(name)) names.push(name);
    }
    return dedupe(names, false);
  }

  function looksLikeRequirements(text) {
    var lines = text.split(/\r?\n/);
    var kept = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (line && line.charAt(0) !== "#") kept.push(line);
    }
    if (!kept.length) return false;
    var good = 0;
    for (var j = 0; j < kept.length; j++) {
      var l = kept[j];
      if (/^(-r|--requirement|-c|--constraint)\b/.test(l) || /^--/.test(l) || /^(-e|--editable)\s+/.test(l)) { good++; continue; }
      if (/^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]+\])?\s*(===|==|~=|!=|>=|<=|>|<|@|;|$)/.test(l)) good++;
    }
    return good >= 1 && good / kept.length >= 0.5;
  }

  function namesFromMaps(obj, keys) {
    var names = [];
    for (var i = 0; i < keys.length; i++) {
      var map = obj[keys[i]];
      if (!map || typeof map !== "object" || Array.isArray(map)) continue;
      var ks = Object.keys(map);
      for (var j = 0; j < ks.length; j++) names.push(ks[j]);
    }
    return names;
  }

  function parsePackageJson(obj) {
    var keys = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
    var names = namesFromMaps(obj, keys);
    var bundled = obj.bundleDependencies || obj.bundledDependencies;
    if (Array.isArray(bundled)) {
      for (var i = 0; i < bundled.length; i++) if (typeof bundled[i] === "string") names.push(bundled[i]);
    }
    // package-lock / npm-shrinkwrap: direct deps live on the root package, not every node_modules entry.
    if (obj.lockfileVersion && obj.packages && obj.packages[""] && typeof obj.packages[""] === "object") {
      names = names.concat(namesFromMaps(obj.packages[""], keys));
    }
    return dedupe(names, false);
  }

  function isPackageJson(obj) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
    var keys = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundleDependencies", "bundledDependencies"];
    for (var i = 0; i < keys.length; i++) if (keys[i] in obj) return true;
    return !!(obj.lockfileVersion && obj.packages);
  }

  function parseComposer(obj) {
    var names = [];
    var fields = ["require", "require-dev"];
    for (var i = 0; i < fields.length; i++) {
      var map = obj[fields[i]];
      if (!map || typeof map !== "object") continue;
      var ks = Object.keys(map);
      for (var j = 0; j < ks.length; j++) {
        var name = ks[j];
        if (name === "php" || name === "composer-plugin-api" || name === "composer-runtime-api") continue;
        if (name.indexOf("ext-") === 0 || name.indexOf("lib-") === 0) continue;
        names.push(name);
      }
    }
    return dedupe(names, false);
  }

  function isComposer(obj) {
    return !!(obj && typeof obj === "object" && !Array.isArray(obj) && (("require" in obj) || ("require-dev" in obj)) && !isPackageJson(obj));
  }

  function parseGoMod(text) {
    var names = [];
    var lines = text.split(/\r?\n/);
    var inRequire = false;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].replace(/\/\/.*/, "").trim();
      if (!line) continue;
      if (line.indexOf("require (") === 0) { inRequire = true; continue; }
      if (inRequire && line === ")") { inRequire = false; continue; }
      if (!inRequire && line.indexOf("require ") === 0 && line.charAt(line.length - 1) !== "(") {
        var one = line.slice(8).trim().split(/\s+/)[0];
        if (one) names.push(one);
        continue;
      }
      if (inRequire) {
        var mod = line.split(/\s+/)[0];
        if (mod && mod !== ")") names.push(mod);
      }
    }
    return dedupe(names, true);
  }

  function isGoMod(text) {
    return /^\s*module\s+\S+/m.test(text) || (/^\s*go\s+\d+\.\d+/m.test(text) && /^\s*require\s+/m.test(text));
  }

  function parseGemfile(text) {
    var names = [];
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].replace(/#.*/, "").trim();
      var m = line.match(/^gem\s+["']([^"']+)["']/);
      if (m) names.push(m[1]);
    }
    return dedupe(names, false);
  }

function sectionIsCargoDeps(section) {
  // dependencies, dev-dependencies, build-dependencies, target.'cfg(...)'.dependencies, workspace.dependencies
  return /dependencies$/.test(section) || /dependencies\.[^.\]]+$/.test(section);
}

  function parseCargo(text) {
    var names = [];
    var lines = text.split(/\r?\n/);
    var section = "";
    var inDeps = false;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].replace(/(^|\s)#.*$/, "").trim();
      if (!line) continue;
      var sec = line.match(/^\[([^\]]+)\]$/);
      if (sec) {
        section = sec[1].trim();
        var sub = section.match(/(?:^|\.)dependencies\.(.+)$/);
        inDeps = sectionIsCargoDeps(section) && !sub;
        if (sub) names.push(sub[1].replace(/^"|"$/g, ""));
        continue;
      }
      if (!inDeps) continue;
      var renamed = line.match(/^[A-Za-z0-9_-]+\s*=\s*\{[^}]*\bpackage\s*=\s*"([^"]+)"/);
      if (renamed) { names.push(renamed[1]); continue; }
      var kv = line.match(/^([A-Za-z0-9_-]+)\s*=/);
      if (kv) names.push(kv[1]);
    }
    return dedupe(names, false);
  }

  function isCargo(text) {
    return /^\s*\[[^\]]*dependencies[^\]]*\]/m.test(text) ||
      (/^\s*\[package\]/m.test(text) && /^\s*name\s*=/.test(text) && !/^\s*\[project\]/m.test(text) && !/tool\.poetry/.test(text));
  }

  function isPyproject(text) {
    return /^\s*\[project\]/m.test(text) || /^\s*\[tool\.poetry\./m.test(text);
  }

  function isPoetryDepSection(section) {
    return section === "tool.poetry.dependencies" || section === "tool.poetry.dev-dependencies" ||
      /^tool\.poetry\.group\.[^.]+\.dependencies$/.test(section);
  }

  function takeQuotedReqs(buf, names) {
    var re = /"([^"]+)"|'([^']+)'/g, m;
    while ((m = re.exec(buf))) {
      var name = reqName(m[1] || m[2]);
      if (name && name.toLowerCase() !== "python") names.push(name);
    }
  }

  function parsePyproject(text) {
    var names = [];
    var lines = text.split(/\r?\n/);
    var section = "";
    var arrayBuf = null;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].replace(/(^|\s)#.*$/, "").trim();
      if (!line && arrayBuf == null) continue;
      if (arrayBuf != null) {
        arrayBuf += " " + line;
        if (line.indexOf("]") !== -1) { takeQuotedReqs(arrayBuf, names); arrayBuf = null; }
        continue;
      }
      var sec = line.match(/^\[([^\]]+)\]$/);
      if (sec) { section = sec[1]; continue; }
      var projectArray = section === "project" && /^dependencies\s*=\s*\[/.test(line);
      var optionalArray = section.indexOf("project.optional-dependencies") === 0 && /^[A-Za-z0-9_-]+\s*=\s*\[/.test(line);
      if (projectArray || optionalArray) {
        if (line.indexOf("]") !== -1) takeQuotedReqs(line, names);
        else arrayBuf = line;
        continue;
      }
      if (isPoetryDepSection(section)) {
        var kv = line.match(/^(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9][A-Za-z0-9._-]*))\s*=/);
        var dep = kv && (kv[1] || kv[2] || kv[3]);
        if (dep && dep.toLowerCase() !== "python") names.push(dep);
      }
    }
    return dedupe(names, false);
  }

  function isPipfile(text) {
    return /^\s*\[\[source\]\]/m.test(text) || /^\s*\[(packages|dev-packages)\]/m.test(text);
  }

  function parsePipfile(text) {
    var names = [];
    var lines = text.split(/\r?\n/);
    var inPkgs = false;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].replace(/(^|\s)#.*$/, "").trim();
      if (!line) continue;
      var sec = line.match(/^\[([^\]]+)\]$/);
      if (sec) { inPkgs = sec[1] === "packages" || sec[1] === "dev-packages"; continue; }
      if (!inPkgs || line.charAt(0) === "[") continue;
      var kv = line.match(/^(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9][A-Za-z0-9._-]*))\s*=/);
      if (kv) names.push(kv[1] || kv[2] || kv[3]);
    }
    return dedupe(names, false);
  }

function parsePom(text) {
  var names = [];
  var src = text.replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<pluginManagement\b[^>]*>[\s\S]*?<\/pluginManagement>/gi, "")
    .replace(/<plugins\b[^>]*>[\s\S]*?<\/plugins>/gi, "");
  var re = /<dependency\b[^>]*>([\s\S]*?)<\/dependency>/gi;
    var m;
    while ((m = re.exec(src))) {
      var g = m[1].match(/<groupId>\s*([^<\s]+)\s*<\/groupId>/i);
      var a = m[1].match(/<artifactId>\s*([^<\s]+)\s*<\/artifactId>/i);
      if (g && a && g[1].indexOf("${") === -1 && a[1].indexOf("${") === -1) names.push(g[1] + ":" + a[1]);
    }
    return dedupe(names, true);
  }

  function isPom(text) {
    return /<dependency\b/i.test(text) && /<groupId>/i.test(text);
  }

  function parseNuget(text) {
    var names = [];
    var src = text.replace(/<!--[\s\S]*?-->/g, "");
    var re = /<(?:PackageReference|PackageVersion)\b[^>]*\bInclude\s*=\s*["']([^"']+)["']/gi;
    var m;
    while ((m = re.exec(src))) names.push(m[1]);
    var re2 = /<package\b[^>]*\bid\s*=\s*["']([^"']+)["']/gi;
    while ((m = re2.exec(src))) names.push(m[1]);
    return dedupe(names, false);
  }

  function isNuget(text) {
    return /<PackageReference\b/i.test(text) || /<PackageVersion\b/i.test(text) || /<package\b[^>]*\bid\s*=/i.test(text);
  }

  function parseMix(text) {
    var block = text.match(/defp?\s+deps\s+do\b([\s\S]*?)\n\s*end\b/);
    var body = block ? block[1] : "";
    var names = [];
    var re = /\{\s*:([A-Za-z][A-Za-z0-9_]*)\s*,/g;
    var m;
    while ((m = re.exec(body))) names.push(m[1]);
    return dedupe(names, false);
  }

  function isMix(text) { return /defp?\s+deps\s+do\b/.test(text); }

  function finish(format, packages) {
    return { format: format, eco: FORMAT_ECO[format], packages: packages, error: null };
  }

  function parseManifest(text) {
    var raw = stripBom(text);
    if (raw.length > MAX_CHARS) return { format: null, eco: null, packages: [], error: "large" };
    var trimmed = raw.trim();
    if (!trimmed) return { format: null, eco: null, packages: [], error: "empty" };

    if (trimmed.charAt(0) === "<" || /<Project[\s>]/.test(trimmed) || /<packages[\s>]/.test(trimmed)) {
      if (isNuget(trimmed)) return finish("nuget", parseNuget(trimmed));
      if (isPom(trimmed)) return finish("maven", parsePom(trimmed));
    }

    // `{` starts package.json / composer.json. `[` is a TOML table, not JSON, for the manifests we read.
    if (trimmed.charAt(0) === "{") {
      var obj;
      try { obj = JSON.parse(trimmed); }
      catch (e) { return { format: null, eco: null, packages: [], error: "json" }; }
      if (isPackageJson(obj)) return finish("npm", parsePackageJson(obj));
      if (isComposer(obj)) return finish("composer", parseComposer(obj));
      return { format: null, eco: null, packages: [], error: "format" };
    }

    if (isGoMod(trimmed)) return finish("gomod", parseGoMod(trimmed));
    if (/^\s*gem\s+["']/m.test(trimmed)) return finish("gem", parseGemfile(trimmed));
    if (isPyproject(trimmed)) return finish("pypi", parsePyproject(trimmed));
    if (isPipfile(trimmed)) return finish("pypi", parsePipfile(trimmed));
    if (isCargo(trimmed)) return finish("cargo", parseCargo(trimmed));
    if (isMix(trimmed)) return finish("mix", parseMix(trimmed));
    if (looksLikeRequirements(trimmed)) return finish("pypi", parseRequirements(trimmed));
    return { format: null, eco: null, packages: [], error: "format" };
  }

  function aliasList(eco, pkg) {
    var fromData = Array.isArray(pkg.match) ? pkg.match : [];
    var fromTable = MATCH_ALIASES[pkg.key] || MATCH_ALIASES[eco.id + "/" + pkg.name] || [];
    var all = [pkg.name].concat(fromData, fromTable);
    var out = [], seen = Object.create(null);
    for (var i = 0; i < all.length; i++) {
      if (!all[i] || seen[all[i]]) continue;
      seen[all[i]] = 1;
      out.push(all[i]);
    }
    return out;
  }

  function buildIndex(ecosystems) {
    var exact = Object.create(null);
    var prefixes = [];
    var list = ecosystems || [];
    for (var i = 0; i < list.length; i++) {
      var e = list[i];
      var pkgs = e.packages || [];
      for (var j = 0; j < pkgs.length; j++) {
        var p = pkgs[j];
        var aliases = aliasList(e, p);
        for (var k = 0; k < aliases.length; k++) {
          var raw = aliases[k];
          var entry = { key: p.key, name: p.name, label: p.label || p.name, eco: e.id, ecoLabel: e.label || e.id };
          if (raw.charAt(raw.length - 1) === "*") {
            var prefix = normName(e.id, raw.slice(0, -1));
            if (prefix) prefixes.push({ eco: e.id, prefix: prefix, entry: entry });
          } else {
            exact[e.id + "\0" + normName(e.id, raw)] = entry;
          }
        }
      }
    }
    prefixes.sort(function (a, b) { return b.prefix.length - a.prefix.length; });
    return { exact: exact, prefixes: prefixes };
  }

  function matchOne(eco, name, index) {
    var n = normName(eco, name);
    var hit = index.exact[eco + "\0" + n];
    if (hit) return hit;
    for (var i = 0; i < index.prefixes.length; i++) {
      var pre = index.prefixes[i];
      if (pre.eco === eco && n.indexOf(pre.prefix) === 0) return pre.entry;
    }
    return null;
  }

  function matchStack(parsed, ecosystems) {
    var tracked = [];
    var untracked = [];
    var byKey = Object.create(null);
    if (!parsed || parsed.error || !parsed.eco) return { tracked: tracked, untracked: untracked };
    var index = buildIndex(ecosystems);
    var pkgs = parsed.packages || [];
    for (var i = 0; i < pkgs.length; i++) {
      var name = pkgs[i];
      var hit = matchOne(parsed.eco, name, index);
      if (!hit) {
        untracked.push({ eco: parsed.eco, name: name });
        continue;
      }
      if (!byKey[hit.key]) {
        byKey[hit.key] = { key: hit.key, name: hit.name, label: hit.label, eco: hit.eco, ecoLabel: hit.ecoLabel, via: [] };
        tracked.push(byKey[hit.key]);
      }
      if (byKey[hit.key].via.indexOf(name) === -1) byKey[hit.key].via.push(name);
    }
    return { tracked: tracked, untracked: untracked };
  }

  function stackFromMatch(matched, prev, mode) {
    var freshTracked = [];
    var freshSources = {};
    var freshUntracked = [];
    var t = (matched && matched.tracked) || [];
    var u = (matched && matched.untracked) || [];
    for (var i = 0; i < t.length; i++) {
      freshTracked.push(t[i].key);
      freshSources[t[i].key] = (t[i].via || []).slice();
    }
    for (var j = 0; j < u.length; j++) freshUntracked.push({ eco: u[j].eco, name: u[j].name });
    if (mode !== "add" || !prev) return { tracked: freshTracked, untracked: freshUntracked, sources: freshSources };

    var tracked = (prev.tracked || []).slice();
    var seen = Object.create(null);
    for (var a = 0; a < tracked.length; a++) seen[tracked[a]] = 1;
    for (var b = 0; b < freshTracked.length; b++) {
      if (!seen[freshTracked[b]]) { tracked.push(freshTracked[b]); seen[freshTracked[b]] = 1; }
    }
    var sources = {};
    var prevSrc = prev.sources || {};
    var sk = Object.keys(prevSrc);
    for (var c = 0; c < sk.length; c++) sources[sk[c]] = prevSrc[sk[c]].slice();
    var fk = Object.keys(freshSources);
    for (var d = 0; d < fk.length; d++) {
      var merged = (sources[fk[d]] || []).concat(freshSources[fk[d]]);
      var uniq = [], us = Object.create(null);
      for (var e = 0; e < merged.length; e++) if (!us[merged[e]]) { us[merged[e]] = 1; uniq.push(merged[e]); }
      sources[fk[d]] = uniq;
    }
    var untracked = (prev.untracked || []).map(function (x) { return { eco: x.eco, name: x.name }; });
    var uSeen = Object.create(null);
    for (var f = 0; f < untracked.length; f++) uSeen[untracked[f].eco + "\0" + normName(untracked[f].eco, untracked[f].name)] = 1;
    for (var g = 0; g < freshUntracked.length; g++) {
      var id = freshUntracked[g].eco + "\0" + normName(freshUntracked[g].eco, freshUntracked[g].name);
      if (!uSeen[id]) { untracked.push(freshUntracked[g]); uSeen[id] = 1; }
    }
    return { tracked: tracked, untracked: untracked, sources: sources };
  }

  return {
    MATCH_ALIASES: MATCH_ALIASES,
    FORMAT_ECO: FORMAT_ECO,
    MAX_CHARS: MAX_CHARS,
    normName: normName,
    parseManifest: parseManifest,
    matchStack: matchStack,
    stackFromMatch: stackFromMatch
  };
});
