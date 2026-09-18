"use strict";
const $ = (selector) => document.querySelector(selector);
const state = { user: null, cases: [], current: null, tab: "overview", tools: null, audit: null, busy: false };
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const pretty = (value) => esc(JSON.stringify(value, null, 2));
const label = (value) => String(value).replaceAll("_", " ");
const badge = (value, color = "") => `<span class="badge ${color}">${esc(label(value))}</span>`;
const time = (value) => value ? new Date(value).toLocaleString([], {dateStyle:"medium",timeStyle:"short"}) : "Not reported";
const empty = (title, text) => `<div class="empty"><h2>${esc(title)}</h2><p>${esc(text)}</p></div>`;
function notify(message, failure = false) {
  const node = $("#toast"); node.textContent = message; node.className = "toast" + (failure ? " failure" : ""); node.hidden = false;
  clearTimeout(notify.timer); notify.timer = setTimeout(() => { node.hidden = true; }, 6500);
}
async function api(path, options = {}) {
  const headers = {...options.headers};
  if (options.body !== undefined) { headers["Content-Type"] = "application/json"; options.body = JSON.stringify(options.body); }
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = sessionStorage.getItem("tfir-csrf") || "";
  const response = await fetch(path, {...options, headers, credentials: "same-origin"});
  const body = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    throw new Error(label(body.error || "Request failed") + (body.fields ? ": " + body.fields.map((x) => x.join(".")).join(", ") : ""));
  }
  return body;
}
function showLogin() { state.user = null; $("#workspace").hidden = true; $("#login-view").hidden = false; sessionStorage.removeItem("tfir-csrf"); }
async function loadWorkspace() {
  state.tools = await api("/api/tools"); state.cases = await api("/api/cases");
  $("#login-view").hidden = true; $("#workspace").hidden = false;
  $("#account").textContent = state.user.username + " · " + state.user.roles.join(", ");
  if (state.cases.length) await selectCase(state.current?.id || state.cases[0].id); else render();
}
async function selectCase(id) { state.current = await api(`/api/cases/${encodeURIComponent(id)}`); state.audit = null; if (state.tab === "audit") state.audit = await api(`/api/cases/${id}/audit`); render(); }
async function refresh() { state.cases = await api("/api/cases"); if (state.current) await selectCase(state.current.id); else render(); }
function render() {
  $("#case-list").innerHTML = state.cases.map((c) => `<button class="case-button ${state.current?.id === c.id ? "active" : ""}" data-action="case" data-id="${esc(c.id)}">${esc(c.title)}<small>${esc(c.id.slice(0,8))} · ${c.closed ? "CLOSED" : "OPEN"}</small></button>`).join("");
  if (!state.current) {
    $("#main-content").innerHTML = `<div class="panel start-empty">${empty("Start with a named investigation", "Create a case, preserve your source evidence, and submit the first operation for human review.")}<div class="panel-body"><button class="primary wide" data-action="new-case">Create investigation <span>+</span></button></div></div>`; return;
  }
  const c = state.current; const pending = c.decisions.filter((d) => d.state === "PENDING").length;
  const tabs = [["overview","Overview"],["evidence","Evidence"],["decisions","Decisions"],["findings","Findings"],["audit","Audit trail"],["packs","Research packs"]];
  $("#main-content").innerHTML = `<section class="case-heading"><div><p class="eyebrow">CASE ${esc(c.id.slice(0,8))}</p><h1>${esc(c.title)}</h1><div class="subline">${badge(c.closed ? "closed" : "investigating", c.closed ? "" : "green")}<span>Opened ${esc(time(c.created))}</span></div></div><div class="button-row"><button data-action="member">Manage access</button><button class="primary" data-action="proposal">+ Propose operation</button></div></section>
    <div class="stats"><div class="stat"><span>EVIDENCE SOURCES</span><strong>${c.artifacts.filter((a) => a.kind === "source").length}</strong><small>Original bytes preserved</small></div><div class="stat"><span>PENDING DECISIONS</span><strong>${pending}</strong><small>Human review required</small></div><div class="stat"><span>ACCEPTED FINDINGS</span><strong>${c.findings.length}</strong><small>Linked to source citations</small></div><div class="stat"><span>AUDIT RECORDS</span><strong>${c.integrity.event_count}</strong><small>Signed local checkpoint</small></div></div>
    <nav class="tabs" aria-label="Investigation sections">${tabs.map(([id,name]) => `<button class="tab ${state.tab === id ? "active" : ""}" data-action="tab" data-id="${id}">${name}</button>`).join("")}</nav><div id="tab-content">${renderTab()}</div>`;
}
function renderTab() {
  if (state.tab === "evidence") return evidenceView();
  if (state.tab === "decisions") return decisionsView(state.current.decisions);
  if (state.tab === "findings") return findingsView();
  if (state.tab === "audit") return auditView();
  if (state.tab === "packs") return packsView();
  const c = state.current;
  return `<div class="overview-grid"><div><section class="panel"><div class="panel-head"><h2>From evidence to a reviewed decision</h2><small>CONTROLLED WORKFLOW</small></div><div class="panel-body step-list"><div><div class="step-number">01</div><h3>Preserve the source</h3><p>Stage exact bytes with acquisition details and known coverage gaps.</p></div><div><div class="step-number">02</div><h3>Review the operation</h3><p>A named human reviews the scope, evidence, and exact arguments.</p></div><div><div class="step-number">03</div><h3>Run and verify</h3><p>Consume the approval once. Keep the receipt and review the result.</p></div></div></section>${decisionsView(c.decisions.filter((d) => d.state === "PENDING").slice(0,3), "Awaiting a human decision")}</div><div><section class="panel"><div class="panel-head"><h2>Investigation brief</h2></div><div class="panel-body"><p>${esc(c.description)}</p><div class="trust-row"><span>Originator</span><strong>${esc(c.creator)}</strong></div><div class="trust-row"><span>Case members</span><strong>${c.members.filter((m) => m.active).length}</strong></div><div class="trust-row"><span>Source completeness</span>${badge("not proven","amber")}</div></div></section><section class="panel"><div class="panel-head"><h2>Integrity & authority</h2></div><div class="panel-body"><div class="trust-row"><span>Local audit chain</span>${badge("verified","green")}</div><div class="trust-row"><span>External witness</span>${badge("not configured","amber")}</div><div class="trust-row"><span>Model connection</span>${badge(state.tools.model_configured ? "configured" : "disabled")}</div><p class="meta block-space">HEAD ${esc(c.integrity.head_hash)}</p><div class="trust-note block-space">Local signatures detect changes relative to retained keys and checkpoints. Independent retention and enterprise identity are deployment requirements.</div></div></section></div></div>`;
}
function evidenceView() {
  const artifacts = state.current.artifacts;
  return `<section class="panel"><div class="panel-head"><h2>Preserved evidence</h2><button class="primary compact" data-action="stage">+ Stage evidence</button></div>${artifacts.length ? `<div class="table-wrap"><table><thead><tr><th>Artifact</th><th>Source / coverage</th><th>Integrity</th><th>Action</th></tr></thead><tbody>${artifacts.map((a) => `<tr><td><strong>${esc(a.filename)}</strong><small>${esc(a.kind)} · ${a.byte_count.toLocaleString()} bytes</small><small class="mono">${esc(a.id)}</small></td><td>${esc(a.source)}<small>${esc(a.coverage)} · ${esc(a.source_version || "local output")}</small><small>${esc(a.coverage_note || "")}</small></td><td>${badge(a.source_integrity || "derived artifact", a.source_integrity === "failed" ? "red" : "")}<small class="mono">SHA-256 ${esc(a.sha256.slice(0,20))}…</small></td><td><button class="compact" data-action="download" data-id="${esc(a.id)}">Retrieve bytes</button>${a.kind === "source" ? `<button class="compact block-space" data-action="import" data-id="${esc(a.id)}">Propose import</button>` : ""}</td></tr>`).join("")}</tbody></table></div>` : empty("No evidence staged", "Add a JSON or JSONL log export, or a research pack manifest. Importing or analyzing it requires a separate approved operation.")}</section><p class="coverage-note">Source integrity and acquisition hashes answer different questions. A matching local hash does not establish that the source was complete or truthful.</p>`;
}
function decisionsView(decisions, title = "Decision register") {
  return `<section class="panel"><div class="panel-head"><h2>${title}</h2><button class="refresh compact" data-action="refresh">↻ Refresh</button></div>${decisions.length ? decisions.map((d) => {
    const b = d.body; const execution = state.current.executions.find((e) => e.decision_id === d.id);
    const reviewed = d.approvals.some((a) => a.body.subject === state.user.username);
    const active = d.state === "PENDING" && b.expires_at > new Date().toISOString();
    return `<article class="decision"><div class="decision-title"><h3>${esc(label(b.tool))}</h3>${badge(execution?.state || (active ? d.state : d.state === "PENDING" ? "expired" : d.state), execution?.state === "COMPLETED" ? "green" : "amber")}</div><p>${esc(b.purpose)}</p><div class="meta">${esc(d.id)} · ${d.approvals.length}/${b.required_role_groups.length} review records · expires ${esc(time(b.expires_at))}</div><details><summary>Exact scope, authority & evidence</summary><pre>${pretty(b)}</pre><p class="meta">DECISION SHA-256 ${esc(d.digest)}</p></details>${d.approvals.map((a) => `<div class="approval-entry">${badge(a.body.verdict, a.body.verdict === "approve" ? "green" : "red")} ${esc(a.body.subject)} · ${esc(a.body.rationale)} ${d.revoked_approval_ids.includes(a.body.id) ? badge("revoked", "red") : `<span class="button-row"><button data-action="revoke" data-id="${esc(a.body.id)}">Revoke</button></span>`}</div>`).join("")}<div class="button-row"><button data-action="review" data-id="${esc(d.id)}" ${!active || reviewed ? "disabled" : ""}>Review decision</button><button class="primary" data-action="execute" data-id="${esc(d.id)}" ${!active || d.approvals.length < b.required_role_groups.length ? "disabled" : ""}>Execute approved operation</button></div>${execution ? `<details><summary>Execution receipt & result</summary><pre>${pretty(execution)}</pre></details>` : ""}</article>`;
  }).join("") : empty("No decisions waiting", "Each operation starts with a proposal. Nothing runs because a timer expires or a reviewer stays silent.")}</section>`;
}
function allCandidates() {
  return state.current.executions.flatMap((e) => e.result?.review_status === "unreviewed" ? (e.result.findings || []).map((f) => ({...f, execution_id:e.id})) : []);
}
function findingsView() {
  const renderFinding = (f, index, candidate) => `<article class="finding"><div class="pill-list">${badge(f.classification, "blue")}${badge(candidate ? "candidate · unreviewed" : "human accepted", candidate ? "amber" : "green")}${f.severity ? badge(f.severity) : ""}</div><h3>${esc(f.claim)}</h3><div class="meta">${esc((f.citations || []).map((x) => typeof x === "string" ? x : `${x.chunk_id} (${x.relation})`).join(" · "))}</div>${f.limitations ? `<p class="muted">${esc(f.limitations)}</p>` : ""}${candidate ? `<div class="button-row"><button class="compact" data-action="finding" data-id="${index}">Propose acceptance</button></div>` : ""}</article>`;
  const candidates = allCandidates();
  return `<section class="panel"><div class="panel-head"><h2>Accepted findings</h2><small>HUMAN REVIEW DOES NOT CHANGE EVIDENCE TYPE</small></div>${state.current.findings.length ? state.current.findings.map((f,i) => renderFinding(f,i,false)).join("") : empty("No accepted findings", "A tool result remains a candidate until a separate human-reviewed acceptance decision.")}</section><section class="panel"><div class="panel-head"><h2>Candidate findings</h2><button class="compact" data-action="suggest">Propose analysis</button></div>${candidates.length ? candidates.map((f,i) => renderFinding(f,i,true)).join("") : empty("No candidates yet", "Approve a rule analysis, a research pack run, or a configured model assessment.")}</section>`;
}
function auditView() {
  if (!state.audit) return empty("Loading audit records", "Retrieving the signed case ledger.");
  return `<section class="panel"><div class="panel-head"><h2>Accountability trail</h2><button class="compact" data-action="refresh">↻ Refresh</button></div><div class="panel-body"><p class="meta">CHECKPOINT ${esc(state.audit.checkpoint.body.head_hash)}</p><p class="muted">Every record includes an actor, timestamp, predecessor hash, and operation metadata. Sensitive evidence and model transcripts are held separately.</p></div>${[...state.audit.events].reverse().map((e) => `<article class="audit-row"><span class="audit-seq">${esc(e.body.sequence.padStart(3,"0"))}</span><div><h3>${esc(e.body.event)}</h3><span class="meta">${esc(e.body.actor)} · ${esc(e.hash.slice(0,24))}…</span><details><summary>Inspect record</summary><pre>${pretty(e)}</pre></details></div><time>${esc(time(e.body.timestamp))}</time></article>`).join("")}</section>`;
}
function packsView() {
  return `<section class="panel"><div class="panel-head"><h2>Research-derived investigation packs</h2><button class="primary compact" data-action="promote">Propose pack release</button></div><div class="panel-body"><p>Translate a research method into bounded matching rules, record its sources, and include positive and negative test vectors. Release requires separate administrator and supervisor approvals.</p><div class="trust-note">Packs contain declarative rules. The application never installs dependencies, executes code from a paper, or follows instructions found in evidence.</div></div>${state.current.packs.length ? state.current.packs.map((p) => `<article class="decision"><div class="decision-title"><h3>${esc(p.name)}</h3>${badge("released","green")}</div><p class="meta">${esc(p.digest)}</p><button class="compact" data-action="run-pack" data-id="${esc(p.id)}">Propose pack run</button></article>`).join("") : empty("No packs released", "Stage a validated pack JSON file as evidence, then submit it for release review.")}</section>`;
}
function modal(title, body, footer = '<button type="button" data-action="close-modal">Cancel</button><button class="primary" type="submit">Save</button>', handler = null) {
  $("#modal-content").innerHTML = `<form id="modal-form"><div class="modal-head"><h2>${esc(title)}</h2><button class="close" type="button" data-action="close-modal" aria-label="Close">×</button></div><div class="modal-body">${body}<p class="error" id="modal-error" role="alert"></p></div><div class="modal-footer">${footer}</div></form>`;
  $("#modal-form").addEventListener("submit", async (event) => {
    event.preventDefault(); if (!handler || state.busy) return; state.busy = true;
    const submit = event.submitter; if (submit) submit.disabled = true;
    try { await handler(new FormData(event.target), event.submitter?.value); $("#modal").close(); await refresh(); }
    catch (error) { $("#modal-error").textContent = error.message; }
    finally { state.busy = false; if (submit) submit.disabled = false; }
  });
  $("#modal").showModal();
}
function newCase() {
  modal("Create investigation", '<label>Case title<input name="title" required maxlength="200" placeholder="Cloud credential investigation"></label><label>Investigation purpose<textarea name="description" required maxlength="3000" placeholder="What prompted this case, and what is currently known?"></textarea></label><p class="hint">This explicit human instruction creates the case and records you as its originator.</p>', undefined, async (form) => {
    const c = await api("/api/cases", {method:"POST",body:Object.fromEntries(form)}); state.current = {id:c.id}; state.tab="overview"; notify("Investigation created. No tools have run.");
  });
}
function stageEvidence() {
  modal("Stage source evidence", '<label>Source file · maximum 2 MB<input type="file" id="source-file" required></label><label>Source system<input name="source" required maxlength="200" placeholder="AWS CloudTrail export · account 123456789012"></label><label>Source version or acquisition reference<input name="source_version" maxlength="200" value="unavailable"></label><div class="form-grid"><label>Coverage declaration<select name="coverage"><option value="unknown">Unknown</option><option value="partial">Partial</option><option value="complete">Declared complete</option></select></label><label>Native source integrity<select name="source_integrity"><option value="not_checked">Not checked</option><option value="failed">Failed</option><option value="verified_externally">Verified externally</option></select></label></div><label>Coverage limits<textarea name="coverage_note" required minlength="8" maxlength="2000" placeholder="Collection interval, omitted pages, missing audit settings, or unknowns"></textarea></label><label>Source verification details<input name="integrity_note" maxlength="2000" value="Not assessed"></label>', '<button type="button" data-action="close-modal">Cancel</button><button class="primary" type="submit">Preserve exact bytes</button>', async (form) => {
    const file = $("#source-file").files[0]; if (file.size > 2000000) throw new Error("File exceeds the 2 MB source limit.");
    const bytes = new Uint8Array(await file.arrayBuffer()); let binary = ""; for (let i=0;i<bytes.length;i+=8192) binary += String.fromCharCode(...bytes.subarray(i,i+8192));
    await api(`/api/cases/${state.current.id}/evidence`, {method:"POST", body:{...Object.fromEntries(form),filename:file.name,content_base64:btoa(binary)}}); notify("Source preserved. Import requires human approval.");
  });
}
function defaults(tool) {
  const ids = state.current.artifacts.filter((a) => a.kind === "source").map((a) => a.id);
  const values = {
    import_logs:{artifact_id:ids[0] || "",format:"cloudtrail"}, timeline:{artifact_ids:ids,actor:"",action:"",start:"",end:"",limit:200},
    suggest_findings:{artifact_ids:ids}, accept_finding:{claim:"",classification:"hypothesis",severity:"medium",citations:[],limitations:"Source completeness and causation require independent verification."},
    record_gap:{description:"",affected_scope:""}, close_case:{conclusion:"",residual_uncertainty:""},
    export_case:{artifact_ids:ids,recipient:state.user.username}, model_assess:{artifact_ids:ids,question:""},
    promote_pack:{artifact_id:ids[0] || ""}, draft_pack:{artifact_id:ids[0] || "",goal:""}, run_pack:{artifact_ids:ids,pack_id:state.current.packs[0]?.id || ""}
  }; return values[tool];
}
function argumentFields(tool, initial) {
  const spec = state.tools.tools.find((t) => t.name === tool); const properties = spec.arguments_schema.properties;
  const values = {...defaults(tool),...initial};
  const html = Object.entries(properties).map(([name,schema]) => {
    const value = values[name] ?? schema.default ?? ""; let widget;
    if (name === "artifact_ids") widget = `<div class="checks">${state.current.artifacts.filter((a) => a.kind === "source").map((a) => `<label class="check"><input type="checkbox" name="arg-${name}" value="${esc(a.id)}" ${(value || []).includes(a.id) ? "checked" : ""}><span>${esc(a.filename)}<span class="hint mono">${esc(a.id)}</span></span></label>`).join("") || '<span class="hint">Stage and import evidence first.</span>'}</div>`;
    else if (name === "artifact_id") widget = `<select name="arg-${name}" required>${state.current.artifacts.filter((a) => a.kind === "source").map((a) => `<option value="${esc(a.id)}" ${a.id === value ? "selected" : ""}>${esc(a.filename)} · ${esc(a.id.slice(0,8))}</option>`).join("")}</select>`;
    else if (name === "pack_id") widget = `<select name="arg-${name}" required>${state.current.packs.map((p) => `<option value="${esc(p.id)}" ${p.id === value ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select>`;
    else if (name === "recipient") widget = `<select name="arg-${name}">${state.current.members.filter((m) => m.active).map((m) => `<option ${m.username === value ? "selected" : ""}>${esc(m.username)}</option>`).join("")}</select>`;
    else if (schema.enum) widget = `<select name="arg-${name}">${schema.enum.map((v) => `<option value="${esc(v)}" ${v === value ? "selected" : ""}>${esc(label(v))}</option>`).join("")}</select>`;
    else if (schema.type === "array" || schema.type === "object") widget = `<textarea name="arg-${name}" data-kind="json" required class="mono">${pretty(value)}</textarea>`;
    else if (schema.type === "integer") widget = `<input type="number" name="arg-${name}" data-kind="integer" min="${schema.minimum}" max="${schema.maximum}" value="${esc(value)}" required>`;
    else if (schema.maxLength >= 1000) widget = `<textarea name="arg-${name}" minlength="${schema.minLength || 0}" maxlength="${schema.maxLength}" ${(schema.minLength || 0) > 0 ? "required" : ""}>${esc(value)}</textarea>`;
    else widget = `<input name="arg-${name}" value="${esc(value)}" maxlength="${schema.maxLength || 200}" ${(schema.minLength || 0) > 0 ? "required" : ""}>`;
    if (name === "artifact_ids") return `<fieldset class="artifact-fields"><legend>Selected artifacts</legend>${widget}</fieldset>`;
    widget = widget.replace(/^(<(?:input|select|textarea)) /, '$1 id="arg-' + name + '" ');
    return `<div class="field"><label for="arg-${esc(name)}">${esc(label(name))}</label>${widget}${["start","end"].includes(name) ? '<span class="hint">Optional ISO 8601 timestamp with timezone, e.g. 2026-09-18T00:00:00Z</span>' : ""}</div>`;
  }).join("");
  $("#argument-fields").innerHTML = `<div class="review-banner">${esc(spec.description)}<br>Required: ${spec.required_role_groups.map((g) => esc(g.join(" or "))).join(" + a different ")}.</div>${["model_assess","draft_pack"].includes(tool) ? '<p class="error">This operation sends the selected evidence or research text and your question to the configured external model.</p>' : ""}${html}`;
}
function newProposal(tool = "timeline", initial = {}) {
  modal("Propose an exact operation", `<label for="tool-select">Operation</label><select name="tool" id="tool-select">${state.tools.tools.map((t) => `<option value="${esc(t.name)}" ${t.name === tool ? "selected" : ""} ${["model_assess","draft_pack"].includes(t.name) && !state.tools.model_configured ? "disabled" : ""}>${esc(label(t.name))}</option>`).join("")}</select><div id="argument-fields"></div><label>Purpose of this operation<textarea name="purpose" required minlength="8" maxlength="3000" placeholder="Why is this exact operation needed for the investigation?"></textarea></label><label>Approval lifetime · minutes<input name="ttl_minutes" type="number" min="1" max="60" value="30" required></label>`, '<button type="button" data-action="close-modal">Cancel</button><button class="primary" type="submit">Submit for human review</button>', async (form) => {
    const chosen = form.get("tool"); const schema = state.tools.tools.find((t) => t.name === chosen).arguments_schema; const args = {};
    for (const [key,spec] of Object.entries(schema.properties)) {
      if (key === "artifact_ids") args[key] = form.getAll("arg-"+key);
      else if (spec.type === "array" || spec.type === "object") args[key] = JSON.parse(form.get("arg-"+key));
      else if (spec.type === "integer") args[key] = Number(form.get("arg-"+key));
      else args[key] = form.get("arg-"+key);
    }
    await api(`/api/cases/${state.current.id}/decisions`, {method:"POST",body:{tool:chosen,arguments:args,purpose:form.get("purpose"),ttl_minutes:Number(form.get("ttl_minutes"))}}); state.tab="decisions"; notify("Proposal recorded. The operation has not run.");
  });
  argumentFields(tool, initial); $("#tool-select").addEventListener("change", (event) => argumentFields(event.target.value, {}));
}
function review(id) {
  const d = state.current.decisions.find((x) => x.id === id);
  modal("Review the exact decision", `<div class="review-banner">Your approval applies only to these parameters, evidence hashes, tool version, and lifetime. Signing does not execute the operation.</div><pre>${pretty(d.body)}</pre><p class="meta">DECISION SHA-256 ${esc(d.digest)}</p><label>Review rationale<textarea name="rationale" required minlength="8" maxlength="3000" placeholder="What did you check? What limits or risks did you consider?"></textarea></label><label>Re-enter your password<input name="password" type="password" autocomplete="current-password" required></label>`, '<button type="button" data-action="close-modal">Cancel</button><button class="danger" type="submit" value="reject">Reject decision</button><button class="primary" type="submit" value="approve">Sign human approval</button>', async (form, verdict) => {
    await api(`/api/cases/${state.current.id}/decisions/${id}/reviews`, {method:"POST",body:{verdict,rationale:form.get("rationale"),password:form.get("password"),decision_digest:d.digest}}); notify("Human review signed and recorded.");
  });
}
async function dispatch(action, id) {
  if (action === "new-case") return newCase();
  if (action === "case") { state.tab="overview"; return selectCase(id); }
  if (action === "tab") { state.tab=id; if (id === "audit") state.audit=await api(`/api/cases/${state.current.id}/audit`); render(); return; }
  if (action === "refresh") return refresh();
  if (action === "stage") return stageEvidence();
  if (action === "proposal") return newProposal();
  if (action === "import") return newProposal("import_logs",{artifact_id:id});
  if (action === "suggest") return newProposal("suggest_findings");
  if (action === "promote") return newProposal("promote_pack");
  if (action === "run-pack") return newProposal("run_pack",{pack_id:id});
  if (action === "review") return review(id);
  if (action === "close-modal") return $("#modal").close();
  if (action === "logout") { await api("/api/logout",{method:"POST"}); showLogin(); return; }
  if (action === "execute") {
    if (state.busy) return; state.busy=true;
    try { const result=await api(`/api/cases/${state.current.id}/decisions/${id}/execute`,{method:"POST"}); notify("Execution " + label(result.state) + (result.result?.error ? ": "+label(result.result.error) : ""),result.state !== "COMPLETED"); await refresh(); } finally {state.busy=false;} return;
  }
  if (action === "download") {
    const response=await fetch(`/api/cases/${state.current.id}/artifacts/${id}`,{credentials:"same-origin"});
    if (!response.ok) throw new Error(label((await response.json()).error));
    const url=URL.createObjectURL(await response.blob()); const anchor=document.createElement("a"); anchor.href=url; anchor.download=id+(state.current.artifacts.find((a)=>a.id===id)?.kind==="export"?".zip":".bin"); anchor.click(); setTimeout(()=>URL.revokeObjectURL(url),1000); return;
  }
  if (action === "finding") { const f=allCandidates()[Number(id)]; return newProposal("accept_finding",{claim:f.claim,classification:f.classification,severity:f.severity||"medium",citations:f.citations.map((c)=>typeof c==="string"?{chunk_id:c,relation:"supports"}:c)}); }
  if (action === "member") {
    return modal("Case access", `<p class="muted">A supervisor or administrator can add an existing human account from this tenant.</p><div class="pill-list">${state.current.members.map((m)=>badge(m.username+(m.active?"":" · removed"))).join("")}</div><label>Username<input name="username" required pattern="[a-zA-Z0-9_-]{1,80}"></label><label>Action<select name="operation"><option value="add">Add case member</option><option value="remove">Remove case member</option></select></label>`,undefined,async(form)=>{
      const name=form.get("username"); await api(`/api/cases/${state.current.id}/members`+(form.get("operation")==="remove"?"/"+encodeURIComponent(name):""),{method:form.get("operation")==="remove"?"DELETE":"POST",...(form.get("operation")==="add"?{body:{username:name}}:{})}); notify("Case membership recorded.");
    });
  }
  if (action === "revoke") return modal("Revoke approval", '<p class="muted">Revocation blocks future use. It cannot reverse an operation that has already started.</p><label>Reason<textarea name="reason" required minlength="8" maxlength="2000"></textarea></label>',undefined,async(form)=>{await api(`/api/cases/${state.current.id}/approvals/${id}/revoke`,{method:"POST",body:{reason:form.get("reason")}});notify("Revocation recorded.");});
}
document.addEventListener("click",(event)=>{const button=event.target.closest("[data-action]");if(button&&!button.disabled) dispatch(button.dataset.action,button.dataset.id).catch((error)=>notify(error.message,true));});
$("#login-form").addEventListener("submit",async(event)=>{
  event.preventDefault(); $("#login-error").textContent="";
  const button=event.target.querySelector("button");button.disabled=true;
  try {const result=await api("/api/login",{method:"POST",body:{username:$("#username").value,password:$("#password").value}});$("#password").value="";sessionStorage.setItem("tfir-csrf",result.csrf_token);state.user=result.user;await loadWorkspace();}
  catch(error){$("#login-error").textContent=error.message;}finally{button.disabled=false;}
});
(async()=>{if(!sessionStorage.getItem("tfir-csrf"))return;try{state.user=await api("/api/me");await loadWorkspace();}catch{showLogin();}})();
