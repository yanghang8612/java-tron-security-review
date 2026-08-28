"use strict";
// All model/repository-controlled content is rendered as text, never as raw HTML.
const $ = (id) => document.getElementById(id);
const base = new URL("./", window.location.href).pathname.replace(/\/$/, "");
const statuses = {completed: "扫描完成", partial: "覆盖不完整", failed: "执行失败", unfinished: "未结束 / 中断", unknown: "记录待核验", dry_run: "演练模式"};
let page = 1, selected = null, listRequest = 0, detailRequest = 0;
function el(tag, text, className) { const node = document.createElement(tag); if (text != null) node.textContent = String(text); if (className) node.className = className; return node; }
function date(value) { if (!value) return "—"; const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString("zh-CN", {hour12: false}); }
function money(value) { return typeof value === "number" ? "$" + value.toFixed(4) : "未知"; }
function showLogin() { $("workspace").hidden = true; $("login").hidden = false; $("detail").replaceChildren(); selected = null; detailRequest++; }
async function api(path, options) {
  const response = await fetch(base + "/api" + path, {credentials: "same-origin", cache: "no-store", ...options});
  if (response.status === 401 && path !== "/login") showLogin();
  if (!response.ok) { let message = "请求失败 (" + response.status + ")"; try {message = (await response.json()).error || message;} catch (_) {} throw new Error(message); }
  return response.json();
}
function post(path, data) { return api(path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(data)}); }
function error(value) { $("global-error").textContent = value ? value.message || String(value) : ""; }
function stat(label, value, note) { const box = el("div", null, "stat"); box.append(el("span", label), el("strong", value), el("span", note)); return box; }
function badge(status) { return el("span", statuses[status] || "记录待核验", "badge " + status); }
function download(id, path) { return base + "/api/runs/" + encodeURIComponent(id) + (path ? "/artifact?path=" + encodeURIComponent(path) : "/download"); }
async function loadRuns() {
  const request = ++listRequest;
  error(null);
  try {
    const data = await api("/runs?page=" + page);
    if (request !== listRequest) return;
    $("login").hidden = true; $("workspace").hidden = false;
    const runs = data.runs, latest = runs[0];
    $("stats").replaceChildren(stat("归档运行", data.total, "按 UTC 运行编号倒序"), stat("本页最近一次", latest ? statuses[latest.status] : "暂无记录", latest ? date(latest.completed_at || latest.created_at) : "等待首次扫描"), stat("本页最近发现", latest?.finding_count ?? "未知", "模型假设，需人工确认"), stat("本页最近估算用量", money(latest?.estimated_cost), "模型估算值，非订阅账单"));
    $("page-info").textContent = "第 " + page + " / " + Math.max(1, Math.ceil(data.total / data.page_size)) + " 页 · 时间按浏览器时区显示";
    $("previous").disabled = page <= 1; $("next").disabled = page * data.page_size >= data.total;
    const list = $("run-list"); list.replaceChildren();
    for (const run of runs) {
      const row = el("button", null, "run-row" + (selected === run.id ? " selected" : ""));
      row.type = "button"; row.setAttribute("aria-label", "查看运行 " + run.id);
      const title = el("div"); title.append(el("div", date(run.created_at), "run-title"), el("div", run.id, "run-id"));
      row.append(title, badge(run.status), el("span", run.models.join(" · ") || "模型待记录", "run-model"), el("span", (run.finding_count ?? "?") + " 发现", "metric"), el("span", money(run.estimated_cost), "metric"));
      row.addEventListener("click", () => {for (const child of list.children) child.classList.remove("selected"); row.classList.add("selected"); loadDetail(run.id);}); list.append(row);
    }
    if (!runs.length) list.append(el("div", "还没有运行记录。每日扫描生成报告后，会自动出现在这里。", "empty"));
  } catch (err) {error(err);} finally {$("loading").hidden = true;}
}
function section(parent, title) { const node = el("section", null, "detail-section"); node.append(el("h3", title)); parent.append(node); return node; }
function markdown(parent, content) {
  // Deliberately small renderer: no HTML, images, active links, or embedded content.
  let pre = null, list = null;
  for (const line of content.split(/\r?\n/)) {
    if (line.startsWith("```")) {if (pre) pre = null; else {pre = el("pre", ""); parent.append(pre);} list = null; continue;}
    if (pre) {pre.append(document.createTextNode(line + "\n")); continue;}
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {parent.append(el("h" + heading[1].length, heading[2])); list = null; continue;}
    const item = line.match(/^\s*[-*]\s+(.*)$/);
    if (item) {if (!list) {list = el("ul"); parent.append(list);} list.append(el("li", item[1])); continue;}
    list = null; if (line.trim()) parent.append(el("p", line));
  }
}
async function loadDetail(id) {
  selected = id; const request = ++detailRequest; error(null);
  try {
    const data = await api("/runs/" + encodeURIComponent(id)); if (request !== detailRequest) return;
    const panel = $("detail"); panel.replaceChildren(); panel.hidden = false;
    const header = el("div", null, "detail-header"), title = el("div"), archive = el("a", "下载完整报告 ZIP", "download"); archive.href = download(id);
    title.append(el("p", "RUN DETAIL", "eyebrow"), el("h2", "执行记录与分析证据"), el("p", id, "detail-id"), badge(data.status)); header.append(title, archive); panel.append(header);
    const meta = el("div", null, "metadata");
    for (const [key, value] of [["扫描范围", data.scopes.join(" · ") || "见报告"], ["目标版本", data.revision || "未记录"], ["开始 / 完成", date(data.created_at) + " → " + date(data.completed_at)], ["模型 / 估算用量", data.models.join(" · ") + " / " + money(data.estimated_cost)]]) {const item = el("div"); item.append(el("span", key), document.createTextNode(value)); meta.append(item);} panel.append(meta);
    for (const warning of data.warnings) panel.append(el("p", warning, "error"));
    const filter = el("div", null, "finding-filter"), searchLabel = el("label", "筛选发现与线索"), search = el("input"), count = el("span", "", "small muted");
    search.id = "finding-search"; search.type = "search"; search.placeholder = "搜索标题、文件、证据或编号"; searchLabel.htmlFor = search.id;
    count.setAttribute("role", "status"); filter.append(searchLabel, search, count); panel.append(filter);
    const searchable = [];
    const findings = section(panel, "发现 · " + (data.finding_count ?? "未知"));
    data.finding_groups.forEach((group, index) => {const card = ReportView.group(group, index + 1, path => download(id, path)); findings.append(card); searchable.push([card, JSON.stringify(group).toLowerCase()]);});
    if (!data.finding_groups.length) findings.append(el("div", data.finding_count === 0 ? "本次尚无正式发现。请继续查看覆盖缺口与待验证线索，这不代表已证明安全。" : "没有可读取的发现汇总，不能据此判断风险。", "empty"));
    const deferred = section(panel, "待验证线索 · " + data.deferred.length);
    data.deferred.forEach((entry, index) => {const card = ReportView.deferred(entry, index + 1); deferred.append(card); searchable.push([card, JSON.stringify(entry).toLowerCase()]);});
    if (!data.deferred.length) deferred.append(el("div", "覆盖文件中未记录待验证线索。", "empty"));
    const noMatch = el("p", "没有匹配的发现或线索。清空搜索可恢复全部条目。", "empty"); noMatch.hidden = true; panel.append(noMatch);
    const applyFilter = () => {const query = search.value.trim().toLowerCase(); let visible = 0; for (const [card, text] of searchable) {card.hidden = !text.includes(query); if (!card.hidden) visible++;} count.textContent = "显示 " + visible + " / " + searchable.length + " 条"; noMatch.hidden = !query || visible > 0;};
    search.addEventListener("input", applyFilter); applyFilter();
    const coverage = section(panel, "覆盖记录 · " + data.coverage.length);
    for (const item of data.coverage) {const node = el("details", null, "coverage-entry"), body = el("div", null, "coverage-body"); const complete = {complete: "覆盖完整", partial: "覆盖不完整"}[item.document.completeness] || "覆盖状态待核验"; node.append(el("summary", complete + " · " + item.path)); ReportView.structured(body, item.document); node.append(body); coverage.append(node);}
    const files = section(panel, "报告文件"), viewer = el("div", null, "viewer"); viewer.hidden = true;
    for (const item of data.artifacts) {
      const row = el("div", null, "artifact"), actions = el("div", null, "actions"); row.append(el("span", item.path + " · " + (item.size / 1024).toFixed(1) + " KB", "artifact-name"));
      if (item.available) {
        const view = el("button", "阅读"), link = el("a", "下载"); link.href = download(id, item.path); link.download = item.path.split("/").pop();
        view.addEventListener("click", async () => {view.disabled = true; error(null); try {const response = await fetch(link.href, {credentials: "same-origin", cache: "no-store"}); if (response.status === 401) showLogin(); if (!response.ok) throw new Error("读取报告失败 (" + response.status + ")"); const content = await response.text(); if (selected !== id || request !== detailRequest) return; viewer.replaceChildren(el("h3", item.path)); if (item.path.endsWith(".md")) markdown(viewer, content); else if (item.path.endsWith(".json") || item.path.endsWith(".sarif")) ReportView.artifact(viewer, item.path, content); else viewer.append(el("pre", content)); viewer.hidden = false; viewer.scrollIntoView({behavior: "smooth", block: "start"});} catch (err) {error(err);} finally {view.disabled = false;}});
        actions.append(view, link);
      } else actions.append(el("span", "超过在线大小限制", "muted"));
      row.append(actions); files.append(row);
    }
    panel.append(viewer); panel.scrollIntoView({behavior: "smooth", block: "start"});
  } catch (err) {error(err);}
}
$("login-form").addEventListener("submit", async (event) => {event.preventDefault(); const form = event.currentTarget, button = form.querySelector("button"); button.disabled = true; $("login-error").textContent = ""; try {await post("/login", {username: form.elements.username.value, password: form.elements.password.value}); form.elements.password.value = ""; page = 1; await loadRuns();} catch (err) {$("login-error").textContent = err.message;} finally {button.disabled = false;}});
$("logout").addEventListener("click", async () => {try {await post("/logout", {}); listRequest++; showLogin(); error(null);} catch (err) {error(err);}});
$("refresh").addEventListener("click", async () => {await loadRuns(); if (selected) loadDetail(selected);});
$("previous").addEventListener("click", () => {page--; loadRuns();});
$("next").addEventListener("click", () => {page++; loadRuns();});
api("/session").then(loadRuns).catch(() => {showLogin(); $("loading").hidden = true;});
