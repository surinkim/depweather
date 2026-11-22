// js/patches.js: search, "my stack only", the URL and the saved stack.
const test = require("node:test");
const assert = require("node:assert");
const P = require("../js/patches.js");

const ROWS = [
  { key: "java", parent: "", search: "java" },
  { key: "java/17", parent: "java", search: "java 17" },
  { key: "java/17/amazon-corretto", parent: "java/17", search: "java 17 amazon corretto", leaf: true },
  { key: "java/17/eclipse-temurin", parent: "java/17", search: "java 17 eclipse temurin", leaf: true },
  { key: "go", parent: "", search: "go" },
  { key: "go/1.26", parent: "go", search: "go 1.26", leaf: true },
];
const state = (o) => Object.assign({ query: "", mine: false, stack: [], open: new Set(["java", "go"]) }, o);
const keys = (r) => Array.from(r.visible);

test("closed rows hide their children, open rows show them", () => {
  assert.deepStrictEqual(keys(P.compute(ROWS, state({}))), ["java", "java/17", "go", "go/1.26"]);
  const open = state({ open: new Set(["java", "java/17", "go"]) });
  assert.strictEqual(keys(P.compute(ROWS, open)).length, 6);
});

test("every word of the query must match, and the way to a match opens", () => {
  assert.ok(P.matches("Java 17 Amazon Corretto", "java corretto"));
  assert.ok(!P.matches("Java 17 Amazon Corretto", "java temurin"));
  const r = P.compute(ROWS, state({ query: "temurin" }));
  assert.deepStrictEqual(keys(r), ["java", "java/17", "java/17/eclipse-temurin"]);
});

test("my stack only keeps starred rows with their parents", () => {
  const r = P.compute(ROWS, state({ mine: true, stack: ["go/1.26"] }));
  assert.deepStrictEqual(keys(r), ["go", "go/1.26"]);
  const v = P.compute(ROWS, state({ mine: true, stack: ["java/17"] }));
  assert.ok(v.visible.has("java/17/amazon-corretto"));
  assert.ok(!v.visible.has("go"));
});

test("inStack understands parents and children", () => {
  assert.ok(P.inStack("java/17/x", ["java/17"]));
  assert.ok(P.inStack("java", ["java/17"]));
  assert.ok(!P.inStack("javascript", ["java"]));
});

test("query string round trip", () => {
  const q = P.buildQuery({ query: "java 17", open: new Set(["java", "java/17"]), mine: true });
  const back = P.parseQuery(q);
  assert.strictEqual(back.query, "java 17");
  assert.deepStrictEqual(back.open, ["java", "java/17"]);
  assert.strictEqual(back.mine, true);
  assert.strictEqual(P.buildQuery({ query: "", open: new Set(), mine: false }), "");
});

test("the stack uses its own storage key and survives bad data", () => {
  assert.strictEqual(P.STACK_KEY, "depweather:patches-stack");
  assert.notStrictEqual(P.STACK_KEY, "depweather:stack");
  const mem = {};
  const st = { getItem: (k) => (k in mem ? mem[k] : null), setItem: (k, v) => { mem[k] = v; } };
  P.writeStack(st, ["go/1.26"]);
  assert.deepStrictEqual(P.readStack(st), ["go/1.26"]);
  mem[P.STACK_KEY] = "{not json";
  assert.deepStrictEqual(P.readStack(st), []);
  mem[P.STACK_KEY] = JSON.stringify([1, "a"]);
  assert.deepStrictEqual(P.readStack(st), ["a"]);
  assert.deepStrictEqual(P.readStack({ getItem() { throw new Error("blocked"); } }), []);
});
