"use strict";
// Dependency-free, text-only presentation of untrusted scanner output.
const ReportView = (() => {
  const labels = {
    title: "标题", summary: "问题概述", description: "问题描述", reason: "待验证原因",
    impact: "影响", attacker: "攻击者能力与前提", violatedinvariant: "违反的安全约束",
    rootcause: "根因", trigger: "触发条件", preconditions: "前置条件", entrypoint: "入口",
    evidence: "支持证据", counterevidence: "反证与限制", remediation: "修复建议",
    recommendation: "建议", validation: "验证记录", verification: "复核记录",
    preliminaryassessment: "初步评估", preliminaryassessments: "初步评估",
    confidence: "模型置信度", reachability: "生产可达性",
    deploymentadjustedseverity: "部署条件下的严重性（模型评估）", sourceseverity: "源码严重性",
    severity: "报告严重性", status: "记录状态", verdict: "模型结论", conclusion: "结论",
    source: "来源", sourcelocations: "代码位置", locations: "代码位置", location: "代码位置",
    path: "文件", paths: "涉及文件", file: "文件", filepath: "文件", uri: "文件路径",
    line: "行号", startline: "起始行", endline: "结束行", linestart: "起始行", lineend: "结束行",
    column: "列号", symbol: "符号", function: "函数", snippet: "代码片段",
    content: "内容", text: "说明", result: "结果", expected: "预期行为", actual: "实际行为",
    steps: "步骤", reproducer: "复现记录", reproduction: "复现记录", poc: "验证样例",
    identity: "关联标识", candidateid: "候选编号", findingid: "发现编号", id: "编号",
    anchor: "定位标识", ruleid: "规则编号", taxonomy: "问题分类", category: "分类", cwe: "CWE",
    surfaceids: "关联分析面", surfaces: "分析面", completeness: "覆盖完整性",
    openquestions: "未解决的问题", explicitexclusions: "明确排除项", includepaths: "纳入路径",
    excludepaths: "排除路径", deferred: "待验证项", inventorystrategy: "范围梳理策略",
    scanid: "扫描编号", schemaversion: "格式版本", documenttype: "文档类型", mode: "扫描模式",
    hypothesis: "问题假设", attackpath: "触发路径", callchain: "调用链", notes: "备注"
  };
  const severities = {critical: "严重", high: "高", medium: "中", low: "低", informational: "提示", info: "提示", none: "无", unknown: "待评估"};
  const reviewStatuses = {not_reviewed: "未复核", pending: "等待复核", running: "正在复核", supported: "复核支持 · 仍需人工确认", rejected: "复核排除 · 模型结论", insufficient_evidence: "已复核 · 证据不足", failed: "复核失败", blocked: "安全限制 · 未重试", skipped: "超出本轮上限 · 未复核", not_candidate: "覆盖记录 · 非复核候选"};
  const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
  const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
  const present = (value) => value !== undefined && value !== null && value !== "" && !(Array.isArray(value) && !value.length) && !(typeof value === "object" && !Object.keys(value).length);
  const first = (...values) => values.find(present);
  const node = (tag, content, className) => {
    const element = document.createElement(tag);
    if (content != null) element.textContent = String(content);
    if (className) element.className = className;
    return element;
  };
  function label(key) {
    const normalized = key.replace(/[_\-\s]/g, "").toLowerCase();
    return own(labels, normalized) ? labels[normalized] : key.replace(/_/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2");
  }
  function inline(parent, content) {
    // Formatting only; never interpret HTML, links, images or model-provided URLs.
    for (const part of String(content).split(/(`[^`\n]+`|\*\*[^*\n]+\*\*)/g)) {
      if (part.startsWith("`") && part.endsWith("`")) parent.append(node("code", part.slice(1, -1)));
      else if (part.startsWith("**") && part.endsWith("**")) parent.append(node("strong", part.slice(2, -2)));
      else parent.append(document.createTextNode(part));
    }
  }
  function value(parent, data, depth = 0) {
    if (depth > 8) {parent.append(node("p", "内容层级较深，请在原始 JSON 中查看。", "muted")); return;}
    if (Array.isArray(data)) {
      if (!data.length) {parent.append(node("span", "未记录", "muted")); return;}
      const list = node("ul", null, "value-list");
      for (const entry of data) {const li = node("li"); value(li, entry, depth + 1); list.append(li);}
      parent.append(list);
    } else if (data !== null && typeof data === "object") {
      const fields = node("dl", null, "field-list");
      for (const [key, entry] of Object.entries(data)) {
        const row = node("div", null, "field-row"), description = node("dd");
        value(description, entry, depth + 1); row.append(node("dt", label(key)), description); fields.append(row);
      }
      parent.append(fields);
    } else {
      const paragraph = node("p", null, "readable-text");
      inline(paragraph, data == null ? "未记录" : typeof data === "boolean" ? data ? "是" : "否" : data);
      parent.append(paragraph);
    }
  }
  function block(parent, title, data, className = "") {
    if (!present(data)) return;
    const part = node("section", null, "finding-block " + className);
    part.append(node("h5", title));
    if (className === "code-locations") locations(part, data); else value(part, data);
    parent.append(part);
  }
  function locations(parent, data) {
    if (Array.isArray(data)) {
      const list = node("ul", null, "value-list");
      for (const item of data) {const li = node("li"); locations(li, item); list.append(li);}
      parent.append(list); return;
    }
    const record = object(data), path = first(record.path, record.file, record.filePath, record.uri);
    if (typeof path !== "string") {value(parent, data); return;}
    const start = first(record.startLine, record.lineStart, record.line), end = first(record.endLine, record.lineEnd);
    const scalar = item => typeof item === "number" || typeof item === "string";
    const suffix = scalar(start) ? ":" + start + (scalar(end) && end !== start ? "–" + end : "") : "";
    parent.append(node("p", path + suffix, "readable-text"));
    const used = ["path", "file", "filePath", "uri", "startLine", "lineStart", "line", "endLine", "lineEnd"];
    // Preserve unusual metadata or malformed line values instead of silently losing it.
    const extra = Object.fromEntries(Object.entries(record).filter(([key, item]) => !used.includes(key) || (key !== "path" && key !== "file" && key !== "filePath" && key !== "uri" && !scalar(item))));
    if (Object.keys(extra).length) value(parent, extra);
  }
  function raw(parent, data, title = "原始 JSON（保留全部字段）") {
    const details = node("details", null, "raw-data");
    details.append(node("summary", title), node("pre", JSON.stringify(data, null, 2)));
    parent.append(details);
  }
  function normalize(input, options = {}) {
    const data = object(input), identity = object(data.identity);
    const assessment = object(first(data.preliminaryAssessments, data.preliminaryAssessment));
    const used = new Set();
    function take(keys) {
      const found = keys.filter(key => own(data, key) && present(data[key]));
      found.forEach(key => used.add(key));
      return found.length > 1 ? Object.fromEntries(found.map(key => [key, data[key]])) : data[found[0]];
    }
    const title = first(data.title, identity.title, data.name, options.title, data.candidateId, data.findingId, data.id, "未命名条目");
    const severity = first(data.severity, data.level, assessment.deploymentAdjustedSeverity, assessment.sourceSeverity);
    const severityText = typeof severity === "string" ? severity.toLowerCase() : "unknown";
    const severityLabel = own(severities, severityText) ? severities[severityText] : String(severity || "待评估");
    const severityBasis = present(data.severity) || present(data.level) ? "报告严重性" : present(assessment.deploymentAdjustedSeverity) ? "部署评估" : "源码严重性";
    for (const key of ["title", "name", "severity", "level", "candidateId", "findingId", "finding_id", "id"]) used.add(key);
    const overview = take(["summary", "description", "hypothesis"]);
    const locations = first(take(["sourceLocations", "source_locations", "locations", "location", "paths", "path", "file"]), options.paths);
    const sections = [
      ["影响与触发条件", take(["impact", "attacker", "preconditions", "trigger", "entryPoint", "entry_point", "violatedInvariant", "violated_invariant"])],
      ["根因与调用路径", take(["rootCause", "root_cause", "cause", "attackPath", "callChain"])],
      ["支持证据", take(["evidence"])],
      ["反证与限制", take(["counterEvidence", "counter_evidence"])],
      ["验证与生产可达性", take(["preliminaryAssessments", "preliminaryAssessment", "validation", "verification", "reachability", "confidence", "verdict"])],
      ["复现与验证记录", take(["reproducer", "reproduction", "poc"])],
      ["修复建议", take(["remediation", "recommendation", "recommendations", "fix"])],
    ].filter(([, content]) => present(content));
    const remaining = Object.fromEntries(Object.entries(data).filter(([key]) => !used.has(key)));
    if (Object.keys(remaining).length) sections.push(["其他报告信息", remaining]);
    return {title: typeof title === "string" ? title : "未命名条目", overview, locations, sections,
      severity: own(severities, severityText) ? severityText : "unknown", severityLabel, severityBasis,
      hasSeverity: present(severity), id: first(data.candidateId, data.findingId, data.finding_id, data.id, options.id)};
  }
  function card(input, options = {}) {
    const model = normalize(input, options), deferred = options.kind === "deferred";
    if (present(options.metadata)) model.sections.push(["线索关联信息", options.metadata]);
    const article = node("article", null, "finding-card " + (deferred ? "is-deferred" : "is-finding"));
    article.append(node("p", (options.index ? String(options.index).padStart(2, "0") + " / " : "") + (deferred ? "待验证线索 · 尚未确认为漏洞" : "模型报告的发现 · 仍需人工确认"), "finding-kind"));
    article.append(node("h4", model.title));
    const badges = node("div", null, "finding-badges");
    if (model.hasSeverity) badges.append(node("span", model.severityBasis + "：" + model.severityLabel, "severity severity-" + model.severity));
    if (options.profile) badges.append(node("span", options.profile, "profile-tag"));
    if (model.id) badges.append(node("span", model.id, "finding-id"));
    const status = own(reviewStatuses, options.reviewStatus) ? options.reviewStatus : "not_reviewed";
    if (options.reviewStatus) badges.append(node("span", reviewStatuses[status], "review-status review-" + status));
    article.append(badges);
    if (options.review) reviewDetails(article, options.review);
    if (options.reason) block(article, "为何仍待验证", options.reason, "review-gap");
    if (options.warning) article.append(node("p", options.warning, "error"));
    block(article, "问题概述", model.overview);
    block(article, "代码位置", model.locations, "code-locations");
    if (model.sections.length) {
      const analysis = node("details", null, "finding-analysis");
      analysis.append(node("summary", "展开分析与证据 · " + model.sections.length + " 个分区"));
      for (const [title, content] of model.sections) block(analysis, title, content);
      article.append(analysis);
    }
    if (options.source) article.append(node("p", "来源：" + options.source, "finding-source"));
    if (options.downloadUrl) {const link = node("a", "下载原始报告 JSON", "source-download"); link.href = options.downloadUrl; article.append(link);}
    raw(article, options.raw === undefined ? input : options.raw);
    return article;
  }
  function reviewDetails(parent, record) {
    const verdict = object(record.verdict);
    const reasons = {first_response_timeout: "等待首次有效进展超时；启动提示和预检心跳不计为进展。", no_progress_timeout: "审查长时间没有新的有效进展，已中止并保留中间结果。", wall_timeout: "达到本条复核总时限，未将中间结果当成完整结论。", missing_invalid_or_conflicting_explicit_verdict: "复核没有返回可核验的明确结论，不能按未发现问题判定排除。", review_attempt_failed_or_interrupted: "复核执行失败或中断，已保留其他候选结果。", review_turn_not_completed: "复核未正常完成。", safety_blocked: "触发安全限制，未通过更换模型重试。"};
    block(parent, "独立复核结论", first(verdict.rationale, reasons[record.reason], record.reason));
    block(parent, "仍缺少的证据", verdict.missing_evidence, "review-gap");
    if (present(verdict.evidence) || present(verdict.production_reachability)) {
      const details = node("details", null, "finding-analysis"); details.append(node("summary", "复核证据与生产可达性"));
      block(details, "复核证据", verdict.evidence);
      const reachability = object(verdict.production_reachability);
      block(details, "生产可达性", {status: {proven: "模型提供了可达性证据", not_reachable: "模型判断不可达", unverified: "尚未证明"}[reachability.status] || "未记录", evidence: reachability.evidence});
      parent.append(details);
    }
    const attempt = object(record[record.effective_attempt || "primary"]);
    if (record.retry_count) parent.append(node("p", "原模型重试：" + record.retry_count + " 次，共享原有成本与总时限。", "finding-source"));
    if (record.fallback_reason) block(parent, "恢复原因", ({first_response_timeout: "首响应超时", no_progress_timeout: "长时间无进展", network_error: "网络连接中断", rate_limit: "模型限流", usage_limit: "模型额度限制", model_unavailable: "模型不可用"})[record.fallback_reason] || record.fallback_reason);
    if (attempt.model) parent.append(node("p", "复核模型：" + attempt.model + " · " + (attempt.effort || "未记录") + (record.effective_attempt === "fallback" ? " · 可用性故障后降级" : ""), "finding-source"));
  }
  function verification(record, index) {
    return card(record.candidate || {}, {kind: "deferred", index, paths: record.paths || record.source_paths,
      reviewStatus: record.status || "not_reviewed", review: record,
      reason: record.deferral_reason, source: record.source_artifact, raw: record});
  }
  function deferred(entry, index) {
    const item = object(entry.item), candidate = object(item.candidate);
    return card(Object.keys(candidate).length ? candidate : item, {
      kind: "deferred", index, id: first(item.id, item.candidateId),
      title: first(item.title, item.id, item.candidateId), paths: item.paths,
      metadata: Object.keys(candidate).length ? Object.fromEntries(Object.entries(item).filter(([key]) => !["candidate", "id", "candidateId", "title", "reason", "paths"].includes(key))) : null,
      reason: first(item.reason, typeof entry.item === "string" ? entry.item : null), source: entry.source, raw: entry.item,
      reviewStatus: entry.review_status || "not_reviewed", review: entry.review
    });
  }
  function group(group, index, downloadUrl) {
    const wrapper = node("div", null, "finding-group");
    const occurrences = Array.isArray(group.occurrences) ? group.occurrences : [];
    occurrences.forEach((occurrence, i) => {
      const article = card(occurrence.finding || occurrence, {
        index: i ? undefined : index, title: occurrence.title, id: occurrence.native_id,
        profile: occurrence.profile, source: occurrence.artifact_path || occurrence.source,
        reviewStatus: occurrence.review?.status, review: occurrence.review,
        warning: occurrence.detail_warning, downloadUrl: occurrence.artifact_path ? downloadUrl(occurrence.artifact_path) : null
      });
      if (group.corroborated_by_multiple_profiles) article.append(node("p", "多个审查配置提供了佐证；不代表已经独立验证或人工确认。", "corroboration-note"));
      if (i) {const alternate = node("details", null, "alternate-review"); alternate.append(node("summary", "同一发现的其他审查记录 · " + (occurrence.profile || "配置未记录")), article); wrapper.append(alternate);}
      else wrapper.append(article);
    });
    if (!occurrences.length) wrapper.append(card(group, {index, warning: "缺少发现记录，请下载原始报告核验。"}));
    return wrapper;
  }
  function structured(parent, data) {value(parent, data); raw(parent, data);}
  function findingsIn(data) {
    if (Array.isArray(data)) return data.filter(item => item && typeof item === "object" && !Array.isArray(item));
    for (const key of ["findings", "items", "results"]) {
      if (own(object(data), key)) {const items = findingsIn(data[key]); if (items.length) return items;}
    }
    return [];
  }
  function artifact(parent, path, content) {
    let data;
    try {data = JSON.parse(content);} catch (_) {parent.append(node("p", "文件不是有效 JSON，以下保留原文。", "error"), node("pre", content)); return;}
    if (path.endsWith("/findings.json")) {
      const items = findingsIn(data);
      if (!items.length) parent.append(node("p", "此文件没有可读取的发现条目；这不代表已证明安全。", "muted"));
      items.forEach((item, index) => parent.append(card(item, {index: index + 1})));
      raw(parent, data, "完整文件 JSON（包含元数据）");
    } else structured(parent, data);
  }
  return {normalize, value, raw, card, deferred, group, structured, artifact, verification, reviewStatuses};
})();
if (typeof module !== "undefined" && module.exports) module.exports = ReportView;
