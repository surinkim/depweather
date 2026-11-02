/* Package page and feed paths. The Pages workflow writes the same paths
   from collect/feeds.py (Maven ":" is "~", a real "~" is "~~"). */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.DepweatherPath = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  function encodeSegment(seg) {
    return String(seg).replace(/~/g, "~~").replace(/:/g, "~");
  }

  function pkgPagePath(key) {
    if (typeof key !== "string" || !key || key[0] === "/" || key.includes("..") || key.includes("//")) return null;
    const slash = key.indexOf("/");
    if (slash <= 0) return null;
    const eco = key.slice(0, slash);
    const name = key.slice(slash + 1);
    if (!name) return null;
    const parts = [eco].concat(name.split("/")).map(encodeSegment);
    if (parts.some((p) => p === "" || p === "." || p === "..")) return null;
    return "/pkg/" + parts.join("/") + "/";
  }

  // /pkg/npm/next/ -> /feed/npm/next.xml
  function pkgFeedPath(key) {
    const page = pkgPagePath(key);
    if (!page) return null;
    return "/feed/" + page.slice("/pkg/".length, -1) + ".xml";
  }

  return { encodeSegment, pkgPagePath, pkgFeedPath };
});
