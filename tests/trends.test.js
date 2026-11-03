"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const trends = require("../js/trends.js");

const AS_OF = "2026-11-03";
const WEEK_STARTS = [
  "2026-09-01", "2026-09-07", "2026-09-14", "2026-09-21", "2026-09-28",
  "2026-10-05", "2026-10-12", "2026-10-19", "2026-10-26", "2026-11-02",
];

test("period windows match the Python history buckets", () => {
  assert.equal(trends.periodStart(AS_OF, "3m"), "2026-09-01");
  assert.equal(trends.periodStart(AS_OF, "6m"), "2026-06-01");
  assert.equal(trends.periodStart(AS_OF, "1y"), "2025-11-01");
  const weeks = trends.buildBuckets(AS_OF, "3m");
  assert.deepEqual(weeks.map((row) => row.start), WEEK_STARTS);
  assert.equal(weeks.at(-1).end, "2026-11-03");
  const months = trends.buildBuckets(AS_OF, "1y");
  assert.equal(months.length, 13);
  assert.equal(months[0].label, "2025-11");
  assert.equal(months.at(-1).label, "2026-11");
});

test("selection sums packages or ecosystems and keeps KEV out of the stack", () => {
  const days = {
    "2026-10-01": {
      packages: {
        "npm/left-pad": { h: 1, k: 1 },
        "npm/lodash": { c: 2 },
      },
      ecosystems: { npm: { h: 1, c: 2, k: 1 } },
    },
    "2026-11-02": {
      packages: { "pypi/django": { m: 1 } },
      ecosystems: { pypi: { m: 1 }, npm: { l: 4 } },
    },
    "not-a-day": { ecosystems: { npm: { c: 9 } } },
  };
  const stacked = trends.selectionDays(days, { packageKeys: ["npm/left-pad", "npm/lodash"] });
  assert.equal(stacked["2026-10-01"].h, 1);
  assert.equal(stacked["2026-10-01"].c, 2);
  assert.equal(stacked["2026-10-01"].k, 1);
  assert.equal(trends.severityTotal(stacked["2026-10-01"]), 3);
  const eco = trends.selectionDays(days, { ecosystemId: "npm" });
  assert.equal(eco["2026-11-02"].l, 4);
  assert.equal(eco["2026-10-01"].k, 1);
  const all = trends.selectionDays(days, { ecosystemId: "all" });
  assert.equal(all["2026-11-02"].m, 1);
  assert.equal(all["2026-11-02"].l, 4);
  const rows = trends.sumBuckets(stacked, trends.buildBuckets(AS_OF, "3m"));
  const hit = rows.find((row) => row.start === "2026-09-28");
  assert.equal(hit.counts.c, 2);
  assert.equal(hit.counts.k, 1);
});

test("svg escapes labels and marks KEV", () => {
  const label = '</svg><script>alert(1)&"';
  const figure = trends.renderFigure({
    asOf: AS_OF,
    period: "6m",
    dayCounts: { "2026-10-01": { c: 1, k: 1 } },
    label,
    lang: "ko",
    domId: 'eco/npm"><x',
  });
  assert.equal(figure.svg.includes("<script"), false);
  assert.match(figure.svg, /&lt;\/svg&gt;&lt;script&gt;alert\(1\)&amp;&quot;/);
  assert.match(figure.svg, /class="kev-mark"/);
  assert.match(figure.svg, /role="img"/);
  assert.match(figure.svg, /aria-labelledby="trend-title-eco-npm-x-6m/);
  assert.match(figure.summary, /심각도별 누적/);
  assert.match(figure.table, /<th scope="row">/);
  assert.match(figure.table, />1</);
  const empty = trends.renderFigure({ asOf: AS_OF, period: "1y", dayCounts: {}, label: "npm", lang: "en", domId: "all" });
  assert.match(empty.svg, /No advisories in this period/);
});

test("the home page loads history and the trend script", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
  assert.match(html, /js\/trends\.js/);
  assert.match(html, /data\/history\/manifest\.json/);
  assert.match(html, /DepweatherTrends\.renderFigure/);
  assert.match(html, /권고 추이/);
  const workflow = fs.readFileSync(path.join(__dirname, "..", ".github", "workflows", "pages.yml"), "utf8");
  assert.match(workflow, /js\/trends\.js/);
  assert.match(workflow, /data\/history/);
  const collect = fs.readFileSync(path.join(__dirname, "..", ".github", "workflows", "collect.yml"), "utf8");
  assert.equal(collect.includes("backfill_history"), false);
});
