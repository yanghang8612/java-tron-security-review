"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const view = require("../../src/tron_security_review/web/finding-view.js");
const fixture = require("../fixtures/report_ui.json");

// Small DOM double for text/structure assertions; real-browser layout is checked separately.
class Element {
  constructor(tag) {this.tagName = tag; this.children = []; this.className = ""; this.content = "";}
  set textContent(text) {this.content = String(text); this.children = [];}
  get textContent() {return this.content + this.children.map(child => child.textContent).join("");}
  append(...children) {this.children.push(...children);}
}
global.document = {createElement: tag => new Element(tag), createTextNode: text => {const node = new Element("#text"); node.textContent = text; return node;}};
const descendants = node => [node, ...node.children.flatMap(descendants)];

test("real candidate schema produces overview, sections and conservative severity", () => {
  const result = view.normalize(fixture.item.candidate);
  assert.match(result.title, /跨模块/);
  assert.equal(result.severity, "unknown");
  assert.equal(result.severityBasis, "部署评估");
  assert.ok(result.sections.some(([title]) => title === "反证与限制"));
  assert.ok(result.sections.some(([title]) => title === "验证与生产可达性"));
});

test("deferred card makes missing proof clear and keeps JSON collapsed", () => {
  const card = view.deferred(fixture, 1), nodes = descendants(card);
  assert.match(card.textContent, /尚未确认为漏洞/);
  assert.match(card.textContent, /为何仍待验证/);
  assert.match(card.textContent, /ExampleVM.java/);
  assert.match(card.textContent, /ExampleVM.java:120–138/);
  const raw = nodes.find(n => n.className === "raw-data");
  assert.ok(raw);
  assert.notEqual(raw.open, true);
  assert.deepEqual(JSON.parse(raw.children[1].textContent), fixture.item);
  assert.equal(nodes.filter(n => n.tagName === "pre").length, 1);
});

test("legacy strings, missing candidate and unknown fields remain readable", () => {
  const card = view.deferred({item: {id: "legacy", reason: "Missing evidence", candidate: {preliminaryAssessment: "Check deployment", novelField: {enabled: false, count: 0}}}}, 2);
  assert.match(card.textContent, /Check deployment/);
  assert.match(card.textContent, /novel Field/);
  assert.match(card.textContent, /否/);
  assert.match(card.textContent, /0/);
  assert.match(view.deferred({item: {id: "scan-stopped", reason: "Incomplete scan"}}, 3).textContent, /Incomplete scan/);
  assert.match(view.deferred({item: "Plain reason"}, 4).textContent, /Plain reason/);
});

test("model-controlled markup and URLs never become executable elements", () => {
  const payload = '<img src=x onerror=alert(1)> <script>bad()</script> [click](javascript:bad())';
  const card = view.card({title: payload, description: payload, evidence: {text: payload}, severity: '<script>'});
  assert.ok(card.textContent.includes(payload));
  assert.ok(descendants(card).every(n => !["img", "script", "iframe", "a"].includes(n.tagName)));
  assert.ok(descendants(card).every(n => !n.className.includes("<script>")));
});

test("multiple model occurrences are kept separate, not merged as confirmed", () => {
  const finding = {title: "Example", description: "First model assessment", severity: "medium"};
  const group = view.group({corroborated_by_multiple_profiles: true, occurrences: [
    {profile: "triage", finding, artifact_path: "triage-example/results/findings.json"},
    {profile: "verifier", finding: {...finding, description: "Second model disagrees"}}
  ]}, 1, path => "/allowed/" + path);
  assert.match(group.textContent, /Second model disagrees/);
  assert.match(group.textContent, /不代表已经独立验证/);
  assert.ok(descendants(group).some(n => n.className === "alternate-review"));
  assert.equal(descendants(group).filter(n => n.tagName === "a").length, 1);
});

test("JSON artifact reader shows cards, preserves wrappers and handles broken JSON", () => {
  const parent = new Element("div");
  view.artifact(parent, "triage-example/results/findings.json", JSON.stringify({version: 1, results: {findings: [{title: "Example", description: "Readable"}]}}));
  assert.ok(descendants(parent).some(n => n.className.includes("finding-card")));
  assert.match(parent.textContent, /Readable/);
  assert.match(parent.textContent, /完整文件 JSON/);
  const broken = new Element("div"); view.artifact(broken, "coverage.json", "{");
  assert.match(broken.textContent, /不是有效 JSON/);
});

test("deep objects stop rendering safely while preserving original JSON", () => {
  let data = {text: "deep value"}; for (let i = 0; i < 12; i++) data = {nested: data};
  const parent = new Element("div"); view.structured(parent, data);
  assert.match(parent.textContent, /内容层级较深/);
  const raw = descendants(parent).find(n => n.className === "raw-data");
  assert.deepEqual(JSON.parse(raw.children[1].textContent), data);
});

test("review distinguishes not reviewed, evidence gaps, rejection and support", () => {
  for (const status of ["pending", "running", "supported", "rejected", "insufficient_evidence", "failed", "blocked", "skipped"]) {
    const card = view.verification({candidate: {title: "Example"}, status}, 1);
    assert.ok(card.textContent.includes(view.reviewStatuses[status]));
    assert.ok(!card.textContent.includes("已确认漏洞"));
  }
});

test("review outcome and missing evidence are readable without expanding JSON", () => {
  const card = view.verification({candidate: {title: "Example"}, status: "insufficient_evidence",
    verdict: {rationale: "Source guard checked", missing_evidence: ["Current activation value"], evidence: ["Example.java:12"], production_reachability: {status: "unverified", evidence: []}},
    primary: {model: "example-model", effort: "high"}, effective_attempt: "primary"}, 1);
  assert.match(card.textContent, /独立复核结论/);
  assert.match(card.textContent, /Current activation value/);
  assert.match(card.textContent, /example-model/);
  assert.notEqual(descendants(card).find(n => n.className === "raw-data").open, true);
});

test("malicious review status and verdict stay plain text", () => {
  const payload = '<script>alert(1)</script>';
  const card = view.verification({status: payload, verdict: {rationale: payload, missing_evidence: [payload]}, candidate: {title: "Example"}}, 1);
  assert.ok(descendants(card).every(n => n.tagName !== "script" && !n.className.includes(payload)));
});
