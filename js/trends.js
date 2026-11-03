/* Long-term severity bars. Bucket rules match collect/history.py:
   3M and 6M are Monday-Sunday weeks inside the calendar-month window,
   1Y is one bar per month from the month of (as-of minus 365 days)
   through the as-of month. KEV (k) is a marker, not a stack slice.
   Every string written into the SVG is escaped. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.DepweatherTrends = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const COUNT_KEYS = ["c", "h", "m", "l", "u", "k"];
  const STACK_ORDER = ["u", "l", "m", "h", "c"];
  const FILL = { u: "var(--sev-unk)", l: "var(--sev-low)", m: "var(--sev-1)", h: "var(--sev-2)", c: "var(--sev-3)" };
  const SEV_EN = { c: "critical", h: "high", m: "medium", l: "low", u: "unknown" };
  const SEV_KO = { c: "치명", h: "높음", m: "중간", l: "낮음", u: "미평가" };
  const PERIOD_EN = { "3m": "3 months", "6m": "6 months", "1y": "1 year" };
  const PERIOD_KO = { "3m": "3개월", "6m": "6개월", "1y": "1년" };
  const CHART = { w: 720, h: 228, padL: 36, padR: 10, padT: 18, padB: 32 };
  const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function parseDay(value) {
    if (!DAY_RE.test(value)) return null;
    const [y, m, d] = value.split("-").map(Number);
    const dt = new Date(Date.UTC(y, m - 1, d));
    if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return null;
    return dt;
  }

  function iso(dt) {
    const y = dt.getUTCFullYear();
    const m = String(dt.getUTCMonth() + 1).padStart(2, "0");
    const d = String(dt.getUTCDate()).padStart(2, "0");
    return `${y}-${m}-${d}`;
  }

  function addDays(dt, n) {
    return new Date(dt.getTime() + n * 86400000);
  }

  function monthsStart(asOf, months) {
    const index = asOf.getUTCFullYear() * 12 + asOf.getUTCMonth() - (months - 1);
    const year = Math.floor(index / 12);
    const month = ((index % 12) + 12) % 12;
    return new Date(Date.UTC(year, month, 1));
  }

  function periodStart(asOf, period) {
    const end = parseDay(asOf);
    if (!end) throw new Error("bad as-of date");
    if (period === "1y") {
      const prev = addDays(end, -365);
      return iso(new Date(Date.UTC(prev.getUTCFullYear(), prev.getUTCMonth(), 1)));
    }
    if (period === "3m" || period === "6m") return iso(monthsStart(end, period === "3m" ? 3 : 6));
    throw new Error("unknown trend period");
  }

  function buildBuckets(asOf, period) {
    const end = parseDay(asOf);
    if (!end) return [];
    let start = parseDay(periodStart(asOf, period));
    if (start > end) start = end;
    const unit = period === "1y" ? "month" : "week";
    const out = [];
    if (unit === "month") {
      let cursor = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), 1));
      while (cursor <= end) {
        const nxt = new Date(Date.UTC(cursor.getUTCFullYear(), cursor.getUTCMonth() + 1, 1));
        const bucketEnd = addDays(nxt, -1) < end ? addDays(nxt, -1) : end;
        const bucketStart = cursor < start ? start : cursor;
        const label = iso(cursor).slice(0, 7);
        out.push({ start: iso(bucketStart), end: iso(bucketEnd), label, unit });
        cursor = nxt;
      }
      return out;
    }
    let cursor = start;
    while (cursor <= end) {
      const mondayIndex = (cursor.getUTCDay() + 6) % 7;
      const sunday = addDays(cursor, 6 - mondayIndex);
      const bucketEnd = sunday < end ? sunday : end;
      out.push({ start: iso(cursor), end: iso(bucketEnd), label: iso(cursor), unit });
      cursor = addDays(bucketEnd, 1);
    }
    return out;
  }

  function emptyCounts() {
    return { c: 0, h: 0, m: 0, l: 0, u: 0, k: 0 };
  }

  function addCounts(dst, src) {
    if (!src || typeof src !== "object") return dst;
    for (const key of COUNT_KEYS) {
      const n = Number(src[key]);
      if (Number.isFinite(n) && n > 0) dst[key] += n;
    }
    return dst;
  }

  function severityTotal(counts) {
    return STACK_ORDER.reduce((sum, key) => sum + (counts[key] || 0), 0);
  }

  function sumBuckets(dayCounts, buckets) {
    const items = [];
    for (const [day, counts] of Object.entries(dayCounts || {})) {
      if (!DAY_RE.test(day)) continue;
      const acc = emptyCounts();
      addCounts(acc, counts);
      items.push([day, acc]);
    }
    return buckets.map((bucket) => {
      const acc = emptyCounts();
      for (const [day, counts] of items) {
        if (day >= bucket.start && day <= bucket.end) addCounts(acc, counts);
      }
      return { ...bucket, counts: acc };
    });
  }

  function grandTotal(rows) {
    const acc = emptyCounts();
    for (const row of rows) addCounts(acc, row.counts);
    return acc;
  }

  function selectionDays(allDays, opts) {
    const packageKeys = opts && opts.packageKeys;
    const eco = opts && opts.ecosystemId;
    const out = {};
    for (const [day, doc] of Object.entries(allDays || {})) {
      if (!DAY_RE.test(day) || !doc || typeof doc !== "object") continue;
      const acc = emptyCounts();
      if (Array.isArray(packageKeys)) {
        const pkgs = doc.packages || {};
        for (const key of packageKeys) addCounts(acc, pkgs[key]);
      } else if (eco && eco !== "all") {
        addCounts(acc, (doc.ecosystems || {})[eco]);
      } else {
        const ecos = doc.ecosystems || {};
        for (const id of Object.keys(ecos)) addCounts(acc, ecos[id]);
      }
      if (severityTotal(acc) || acc.k) out[day] = acc;
    }
    return out;
  }

  function countsPhrase(counts, lang) {
    const names = lang === "ko" ? SEV_KO : SEV_EN;
    const parts = ["c", "h", "m", "l", "u"].map((key) => `${names[key]} ${counts[key] || 0}`);
    return `${parts.join(", ")}. KEV ${counts.k || 0}.`;
  }

  function summaryText(label, period, counts, lang) {
    const span = lang === "ko" ? PERIOD_KO[period] : PERIOD_EN[period];
    const body = countsPhrase(counts, lang);
    if (lang === "ko") return `${label}, ${span}, 심각도별 누적. ${body}`;
    return `${label}, ${span}, stacked by severity. ${body}`;
  }

  function niceMax(n) {
    if (n <= 1) return 1;
    if (n <= 4) return n;
    const mag = 10 ** Math.floor(Math.log10(n));
    for (const mult of [1, 2, 5, 10]) if (mult * mag >= n) return mult * mag;
    return 10 * mag;
  }

  function axisTicks(top) {
    if (top <= 4) return Array.from({ length: top + 1 }, (_, i) => i);
    let step = top;
    if (top % 4 === 0) step = top / 4;
    else if (top % 2 === 0) step = top / 2;
    const ticks = [];
    for (let v = 0; v <= top; v += step) ticks.push(v);
    return ticks;
  }

  function num(value) {
    const text = value.toFixed(1);
    return text.endsWith(".0") ? text.slice(0, -2) : text;
  }

  function labelIndexes(count) {
    const step = count <= 16 ? 1 : count <= 24 ? 2 : 4;
    const out = new Set();
    for (let i = 0; i < count; i += 1) if (i % step === 0 || i === count - 1) out.add(i);
    return out;
  }

  function axisLabel(row) {
    if (row.unit === "month") return String(row.label || row.start).slice(2);
    return String(row.start).slice(5);
  }

  function renderSvg(rows, summary, domId, lang) {
    const titleId = `trend-title-${domId}`;
    const descId = `trend-desc-${domId}`;
    const top = niceMax(rows.reduce((max, row) => Math.max(max, severityTotal(row.counts)), 0));
    const plotW = CHART.w - CHART.padL - CHART.padR;
    const plotH = CHART.h - CHART.padT - CHART.padB;
    const base = CHART.h - CHART.padB;
    const parts = [
      `<svg class="trend-svg" viewBox="0 0 ${CHART.w} ${CHART.h}" width="100%" role="img" aria-labelledby="${titleId} ${descId}">`,
      `<title id="${titleId}">${escapeHtml(summary)}</title>`,
      `<desc id="${descId}">${escapeHtml(summary)}</desc>`,
    ];
    for (const tick of axisTicks(top)) {
      const y = base - (plotH * tick / top);
      const stroke = tick === 0 ? "var(--axis)" : "var(--grid)";
      parts.push(`<line x1="${CHART.padL}" x2="${CHART.w - CHART.padR}" y1="${num(y)}" y2="${num(y)}" stroke="${stroke}" stroke-width="1"></line>`);
      parts.push(`<text x="${CHART.padL - 6}" y="${num(y + 4)}" font-size="11" fill="var(--muted)" text-anchor="end">${tick}</text>`);
    }
    const n = Math.max(1, rows.length);
    const slot = plotW / n;
    const gap = Math.min(4, slot * 0.28);
    const barW = Math.max(1, slot - gap);
    const show = labelIndexes(rows.length);
    const total = severityTotal(grandTotal(rows));
    rows.forEach((row, index) => {
      const x = CHART.padL + index * slot + (slot - barW) / 2;
      let used = 0;
      let yTop = base;
      const segments = [];
      for (const key of STACK_ORDER) {
        const count = row.counts[key] || 0;
        if (count <= 0) continue;
        const h = plotH * count / top;
        const y = base - used - h;
        used += h;
        yTop = y;
        segments.push(
          `<rect x="${num(x)}" y="${num(y)}" width="${num(barW)}" height="${num(Math.max(h, 0.8))}" fill="${FILL[key]}"><title>${escapeHtml(SEV_EN[key])} ${count}</title></rect>`,
        );
      }
      const tip = `${row.start} – ${row.end}: ${countsPhrase(row.counts, lang)}`;
      parts.push(`<g><title>${escapeHtml(tip)}</title>`);
      parts.push(segments.join(""));
      if ((row.counts.k || 0) > 0) {
        const cx = x + barW / 2;
        let cy = yTop - 7;
        const r = 4.5;
        if (cy - r < 2) cy = r + 2;
        const d = `M${num(cx)} ${num(cy - r)}L${num(cx + r)} ${num(cy)}L${num(cx)} ${num(cy + r)}L${num(cx - r)} ${num(cy)}Z`;
        parts.push(`<path class="kev-mark" d="${d}" fill="var(--sev-kev)" stroke="var(--surface)" stroke-width="1"><title>KEV ${row.counts.k}</title></path>`);
      }
      parts.push("</g>");
      if (show.has(index)) {
        const anchor = index === 0 ? "start" : index === rows.length - 1 ? "end" : "middle";
        const lx = index === 0 ? x : index === rows.length - 1 ? x + barW : x + barW / 2;
        parts.push(`<text x="${num(lx)}" y="${CHART.h - 10}" font-size="11" fill="var(--muted)" text-anchor="${anchor}">${escapeHtml(axisLabel(row))}</text>`);
      }
    });
    if (total === 0) {
      const empty = lang === "ko" ? "이 기간에 권고가 없습니다" : "No advisories in this period";
      parts.push(`<text x="${CHART.w / 2}" y="${CHART.padT + plotH / 2}" font-size="13" fill="var(--muted)" text-anchor="middle">${escapeHtml(empty)}</text>`);
    }
    parts.push("</svg>");
    return parts.join("");
  }

  function renderTable(rows, summary, lang) {
    const heads = lang === "ko"
      ? ["기간", "치명", "높음", "중간", "낮음", "미평가", "KEV"]
      : ["Period", "Critical", "High", "Medium", "Low", "Unknown", "KEV"];
    const th = heads.map((label, i) => `<th${i ? ' class="num"' : ""}>${escapeHtml(label)}</th>`).join("");
    const body = rows.map((row) => {
      const label = row.unit === "month" ? row.label : `${row.start} – ${row.end}`;
      const cells = ["c", "h", "m", "l", "u", "k"].map((key) => `<td class="num">${row.counts[key] || 0}</td>`);
      return `<tr><th scope="row">${escapeHtml(label)}</th>${cells.join("")}</tr>`;
    }).join("");
    return `<div class="scroll-x"><table class="data trend-table"><caption>${escapeHtml(summary)}</caption><thead><tr>${th}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function renderFigure(opts) {
    const period = opts.period || "6m";
    const lang = opts.lang === "ko" ? "ko" : "en";
    const rows = sumBuckets(opts.dayCounts || {}, buildBuckets(opts.asOf, period));
    const summary = summaryText(String(opts.label || ""), period, grandTotal(rows), lang);
    const slug = String(opts.domId || "trend").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").toLowerCase().slice(0, 60) || "trend";
    return {
      summary,
      rows,
      svg: renderSvg(rows, summary, `${slug}-${period}`, lang),
      table: renderTable(rows, summary, lang),
    };
  }

  return {
    COUNT_KEYS,
    escapeHtml,
    periodStart,
    buildBuckets,
    addCounts,
    sumBuckets,
    grandTotal,
    selectionDays,
    summaryText,
    renderFigure,
    severityTotal,
  };
});
