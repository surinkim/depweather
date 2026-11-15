#!/usr/bin/env node
/* Read the I18N table from index.html so the build can render the home page
   in each language with the same strings the browser uses.

     node collect/i18n_eval.js index.html < calls.json > out.json

   stdin: [[lang, key, ...args], ...]  calls to make, with t()'s fallback to
          English; a string entry is returned as is, a function is called.
   stdout: { strings: { en: {key: text}, ko: {...} }, calls: [result, ...] }
   Only the object literal `const I18N = { ... };` is evaluated, in an empty
   context, so nothing else in the page runs. */
"use strict";
const fs = require("fs");
const vm = require("vm");

function loadI18n(file) {
  const src = fs.readFileSync(file, "utf8");
  const head = "const I18N = {";
  const start = src.indexOf(head);
  if (start < 0) throw new Error(`${file}: no "${head}"`);
  const end = src.indexOf("\n};\n", start);
  if (end < 0) throw new Error(`${file}: I18N table not closed by a line "};"`);
  const literal = src.slice(start + head.length - 1, end + 2);
  return vm.runInNewContext(`(${literal})`, Object.create(null), { timeout: 2000 });
}

function main() {
  const file = process.argv[2];
  if (!file) throw new Error("usage: i18n_eval.js <index.html>");
  const I18N = loadI18n(file);
  const input = fs.readFileSync(0, "utf8").trim();
  const calls = input ? JSON.parse(input) : [];
  const strings = {};
  for (const [lang, dict] of Object.entries(I18N)) {
    strings[lang] = {};
    for (const [k, v] of Object.entries(dict)) if (typeof v === "string") strings[lang][k] = v;
  }
  const results = calls.map(([lang, key, ...args]) => {
    const v = (I18N[lang] || {})[key] ?? I18N.en[key];
    if (v === undefined) throw new Error(`no I18N key ${key}`);
    return typeof v === "function" ? v(...args) : v;
  });
  process.stdout.write(JSON.stringify({ strings, calls: results }));
}

main();
