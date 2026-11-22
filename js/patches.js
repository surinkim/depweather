/* depweather patch page: open/close rows, search, "my stack only".
   Browser: classic script, exposes DepweatherPatches. Node: module.exports (tests).
   The stack is kept in this browser's localStorage and goes nowhere else.
   It uses its own key, not the home page's depweather:stack. */
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.DepweatherPatches = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var STACK_KEY = "depweather:patches-stack";

  /* Every word of the query must appear in the row's text. */
  function matches(text, query) {
    var words = String(query || "").toLowerCase().split(/\s+/).filter(Boolean);
    var hay = String(text || "").toLowerCase();
    return words.every(function (w) { return hay.indexOf(w) !== -1; });
  }

  /* A row is in the stack when its key, a parent's key or a child's key was starred. */
  function inStack(key, stack) {
    return stack.some(function (s) {
      return s === key || key.indexOf(s + "/") === 0 || s.indexOf(key + "/") === 0;
    });
  }

  /* rows: [{key, parent, search, leaf}] in page order (detail rows excluded).
     state: {query, mine, stack, open: Set of keys}.
     Returns {visible: Set, expanded: Set}. A search opens the rows that lead to a match. */
  function compute(rows, state) {
    var hasQuery = !!(state.query && state.query.trim());
    var filtering = hasQuery || !!state.mine;
    var byKey = {};
    rows.forEach(function (r) { byKey[r.key] = r; });
    var keep = {};
    rows.forEach(function (r) {
      var ok = (!hasQuery || matches(r.search, state.query)) && (!state.mine || inStack(r.key, state.stack || []));
      if (!ok) return;
      keep[r.key] = true;
      for (var p = r.parent; p; p = byKey[p] && byKey[p].parent) keep[p] = true;
    });
    var expanded = new Set(state.open || []);
    if (filtering) rows.forEach(function (r) { if (keep[r.key] && r.parent) expanded.add(r.parent); });
    var visible = new Set();
    rows.forEach(function (r) {
      if (filtering && !keep[r.key]) return;
      for (var p = r.parent; p; p = byKey[p].parent) {
        if (!expanded.has(p)) return;
      }
      visible.add(r.key);
    });
    return { visible: visible, expanded: expanded };
  }

  /* ?q=java+17&open=java,java/17&mine=1 */
  function parseQuery(search) {
    var p = new URLSearchParams(search || "");
    return {
      query: p.get("q") || "",
      open: (p.get("open") || "").split(",").filter(Boolean),
      mine: p.get("mine") === "1"
    };
  }

  function buildQuery(state) {
    var p = new URLSearchParams();
    if (state.query) p.set("q", state.query);
    var open = Array.from(state.open || []);
    if (open.length) p.set("open", open.join(","));
    if (state.mine) p.set("mine", "1");
    var s = p.toString();
    return s ? "?" + s : "";
  }

  function readStack(storage) {
    try {
      var v = JSON.parse(storage.getItem(STACK_KEY));
      return Array.isArray(v) ? v.filter(function (x) { return typeof x === "string"; }) : [];
    } catch (e) { return []; }
  }

  function writeStack(storage, stack) {
    try { storage.setItem(STACK_KEY, JSON.stringify(stack)); } catch (e) { /* private mode */ }
  }

  function init(doc, win) {
    var table = doc.getElementById("tree");
    if (!table) return;
    var trs = Array.prototype.slice.call(table.querySelectorAll("tbody tr[data-key]"));
    var main = trs.filter(function (tr) { return !tr.classList.contains("detail"); });
    var rows = main.map(function (tr) {
      return { key: tr.dataset.key, parent: tr.dataset.parent || "", search: tr.dataset.search || "", leaf: !!tr.dataset.leaf, el: tr };
    });
    var details = {};
    trs.forEach(function (tr) { if (tr.classList.contains("detail")) details[tr.dataset.parent] = tr; });
    var q = doc.getElementById("q"), mine = doc.getElementById("mine"), none = doc.getElementById("nomatch");
    var storage; try { storage = win.localStorage; } catch (e) { storage = null; }
    var stack = storage ? readStack(storage) : [];
    var init0 = parseQuery(win.location.search);
    var open = new Set(init0.open);
    if (!init0.open.length) rows.forEach(function (r) { if (r.el.dataset.open === "1") open.add(r.key); });
    q.value = init0.query;
    mine.checked = init0.mine;

    function paint() {
      var state = { query: q.value, mine: mine.checked, stack: stack, open: open };
      var res = compute(rows, state);
      var any = false;
      rows.forEach(function (r) {
        var show = res.visible.has(r.key);
        r.el.hidden = !show;
        any = any || show;
        var btn = r.el.querySelector("[data-toggle]");
        var isOpen = res.expanded.has(r.key);
        if (btn) btn.setAttribute("aria-expanded", isOpen ? "true" : "false");
        var d = details[r.key];
        if (d) d.hidden = !(show && isOpen);
        var star = r.el.querySelector("[data-star]");
        if (star) {
          var on = stack.indexOf(r.key) !== -1;
          star.setAttribute("aria-pressed", on ? "true" : "false");
          star.textContent = on ? "★" : "☆";
        }
      });
      if (none) none.hidden = any;
      try {
        win.history.replaceState(null, "", win.location.pathname + buildQuery({ query: q.value.trim(), mine: mine.checked, open: open }) + win.location.hash);
      } catch (e) { /* file: or sandbox */ }
    }

    table.addEventListener("click", function (e) {
      var star = e.target.closest("[data-star]");
      if (star) {
        var k = star.dataset.star, i = stack.indexOf(k);
        if (i === -1) stack.push(k); else stack.splice(i, 1);
        if (storage) writeStack(storage, stack);
        return paint();
      }
      var tw = e.target.closest("[data-toggle]");
      if (tw) {
        var key = tw.dataset.toggle;
        if (open.has(key)) open.delete(key); else open.add(key);
        paint();
      }
    });
    q.addEventListener("input", paint);
    mine.addEventListener("change", paint);
    paint();
  }

  if (typeof document !== "undefined" && typeof window !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { init(document, window); });
    else init(document, window);
  }

  return { STACK_KEY: STACK_KEY, matches: matches, inStack: inStack, compute: compute, parseQuery: parseQuery,
           buildQuery: buildQuery, readStack: readStack, writeStack: writeStack };
});
