/* Aggios demo UI */
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

let currentElection = null;   // election_id
let electionData = null;      // last fetched summary
let benchTimer = null;
const benchEventSeq = {};     // benchmark_id -> next seq to fetch
const benchEventLog = {};     // benchmark_id -> [lines]

async function api(path, opts = {}) {
  if (window.AGGIOS_WASM) {
    // Static-site mode: everything runs in a WebAssembly worker, no backend.
    const method = (opts.method || "GET").toUpperCase();
    const body = opts.body ? JSON.parse(opts.body) : {};
    const res = await window.aggiosWasmCall(method, path, body);
    if (res.status !== 200) {
      throw new Error((res.body && res.body.error) || `status ${res.status}`);
    }
    return res.body;
  }
  const res = await fetch(`/api/aggios${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
  return body;
}

/* Download helper: <a href> against the backend, blob download in WASM mode. */
window.wasmDownload = async (path, filename) => {
  try {
    const res = await api(path);
    const isCsv = filename.endsWith(".csv");
    const content =
      isCsv && res.csv !== undefined ? res.csv : JSON.stringify(res, null, 2);
    const blob = new Blob([content], {
      type: isCsv ? "text/csv" : "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  } catch (err) {
    alert(err.message);
  }
};

function downloadControl(path, filename, label, disabled) {
  if (window.AGGIOS_WASM) {
    return `<button class="ghost" ${disabled ? "disabled" : ""}
      onclick="wasmDownload('${esc(path)}','${esc(filename)}')">${esc(label)}</button>`;
  }
  return `<a class="button ghost" href="/api/aggios${esc(path)}" target="_blank"
    ${disabled ? 'style="pointer-events:none;opacity:.4"' : ""}>${esc(label)}</a>`;
}

function log(msg, isError = false) {
  const el = $("#admin-log");
  const time = new Date().toLocaleTimeString();
  el.textContent += `[${time}] ${isError ? "ERROR: " : ""}${msg}\n`;
  el.scrollTop = el.scrollHeight;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function pill(text, cls) {
  return `<span class="pill ${cls}">${esc(text)}</span>`;
}

function fmtMs(ms) {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function fmtBytes(b) {
  if (b == null) return "—";
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}

/* ---------------- tabs ---------------- */

function activateTab(name) {
  const btn = $$("#tabs button").find((b) => b.dataset.tab === name);
  if (!btn) return;
  $$("#tabs button").forEach((b) => b.classList.remove("active"));
  $$(".tab").forEach((t) => t.classList.remove("active"));
  btn.classList.add("active");
  $(`#tab-${name}`).classList.add("active");
  if (name === "benchmark") refreshBenchmarks();
}

$$("#tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    history.replaceState(null, "", `#${btn.dataset.tab}`);
    activateTab(btn.dataset.tab);
  });
});

/* ---------------- election selection ---------------- */

async function refreshElectionList() {
  const data = await api("/elections");
  const sel = $("#election-select");
  const prev = currentElection;
  sel.innerHTML = data.elections.length
    ? data.elections
        .map((e) => `<option value="${esc(e.election_id)}">${esc(e.title)} (${esc(e.phase)})</option>`)
        .join("")
    : `<option value="">— none —</option>`;
  if (prev && data.elections.some((e) => e.election_id === prev)) {
    sel.value = prev;
  } else if (data.elections.length) {
    currentElection = data.elections[data.elections.length - 1].election_id;
    sel.value = currentElection;
  } else {
    currentElection = null;
  }
}

$("#election-select").addEventListener("change", (e) => {
  currentElection = e.target.value || null;
  refreshElection();
});

$("#refresh-btn").addEventListener("click", () => refreshAll());

async function refreshElection() {
  if (!currentElection) {
    electionData = null;
    renderAll();
    return;
  }
  try {
    electionData = await api(`/elections/${currentElection}`);
  } catch (err) {
    electionData = null;
  }
  renderAll();
}

async function refreshAll() {
  await refreshElectionList();
  await refreshElection();
}

/* ---------------- rendering ---------------- */

function renderAll() {
  renderOverview();
  renderAdmin();
  renderVoters();
  renderAggregators();
  renderValidator();
}

function tallyBars(tally, candidates) {
  const total = Object.values(tally).reduce((a, b) => a + b, 0) || 1;
  return `<div class="tally-bars">` + candidates.map((c) => {
    const n = tally[c.id] || 0;
    return `<div class="tally-bar">
      <div class="lbl"><span>${esc(c.name)}</span><span>${n}</span></div>
      <div class="track"><div class="fill" style="width:${(100 * n / total).toFixed(1)}%"></div></div>
    </div>`;
  }).join("") + `</div>`;
}

function renderOverview() {
  const el = $("#overview-status");
  const tallyEl = $("#overview-tally");
  if (!electionData) {
    el.textContent = "No election selected. Create one in the Admin tab.";
    tallyEl.innerHTML = "";
    return;
  }
  const e = electionData;
  el.innerHTML = `
    <div class="stat-grid">
      <span class="k">Election</span><span class="v">${esc(e.election.title)} (${esc(e.election.election_id)})</span>
      <span class="k">Phase</span><span class="v">${pill(e.phase, "info")}</span>
      <span class="k">Candidates</span><span class="v">${e.election.candidates.map((c) => esc(c.name)).join(", ")}</span>
      <span class="k">Aggregators</span><span class="v">${e.election.aggregators.map(esc).join(", ")}</span>
      <span class="k">Demo voters</span><span class="v">${e.num_voters}</span>
    </div>`;
  tallyEl.innerHTML = e.verified_global_tally
    ? `<h3>Verified global tally (verified aggregators only; NO_VOTE/PAD excluded)</h3>` +
      tallyBars(e.verified_global_tally, e.election.candidates)
    : `<p class="muted">No verified tally yet — run proofs and verification.</p>`;
}

function renderAdmin() {
  const phaseEl = $("#admin-phase");
  const aggEl = $("#admin-aggregator-actions");
  if (!electionData) {
    phaseEl.textContent = "Select an election first.";
    aggEl.innerHTML = "";
    return;
  }
  phaseEl.innerHTML = `Current phase: ${pill(electionData.phase, "info")}`;
  aggEl.innerHTML = `<table><thead><tr>
      <th>Aggregator</th><th>Registered</th><th>Votes</th><th>Status</th><th>Actions</th>
    </tr></thead><tbody>` +
    electionData.aggregators.map((a) => `<tr>
      <td><strong>${esc(a.aggregator_id)}</strong></td>
      <td>${a.registered_voters}</td>
      <td>${a.votes_received}</td>
      <td>${statusPill(a)}</td>
      <td class="btn-row">
        <button onclick="aggAction('${esc(a.aggregator_id)}','finalize-registration')" ${a.finalized ? "disabled" : ""}>Finalize</button>
        <button onclick="aggAction('${esc(a.aggregator_id)}','prove')" ${!a.finalized ? "disabled" : ""}>Prove</button>
        <button onclick="aggAction('${esc(a.aggregator_id)}','verify')" ${a.proof_status === "pending" || a.proof_status === "ready" ? "disabled" : ""}>Verify</button>
      </td>
    </tr>`).join("") + `</tbody></table>`;
}

function statusPill(a) {
  switch (a.proof_status) {
    case "verified": return pill("proof verified", "good");
    case "rejected": return pill("proof rejected", "bad");
    case "proved": return pill("proved, not verified", "warn");
    case "ready": return pill("finalized", "info");
    default: return pill("registering", "");
  }
}

function renderVoters() {
  const el = $("#voter-table");
  if (!electionData) { el.innerHTML = `<p class="muted">Select an election first.</p>`; return; }
  const e = electionData;
  if (!e.voters.length) { el.innerHTML = `<p class="muted">No demo voters yet.</p>`; return; }
  const aggOptions = e.election.aggregators.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join("");
  const candOptions = e.election.candidates.map((c) => `<option value="${esc(c.id)}">${esc(c.name)}</option>`).join("");
  el.innerHTML = `<table><thead><tr>
      <th>Voter</th><th>Aggregator</th><th>Vote</th><th>Receipt</th>
    </tr></thead><tbody>` +
    e.voters.map((v) => `<tr>
      <td>${esc(v.voter_id)}</td>
      <td>${v.registered_with
        ? pill(v.registered_with, "info")
        : `<span class="btn-row"><select id="agg-${esc(v.voter_id)}">${aggOptions}</select>
           <button onclick="registerVoter('${esc(v.voter_id)}')">Register</button></span>`}</td>
      <td>${v.has_voted
        ? pill(esc(v.vote) + " (known to aggregator)", "good")
        : v.registered_with
          ? `<span class="btn-row"><select id="cand-${esc(v.voter_id)}">${candOptions}</select>
             <button onclick="castVote('${esc(v.voter_id)}')">Vote</button></span>`
          : `<span class="muted">register first</span>`}</td>
      <td><button class="ghost" onclick="checkReceipt('${esc(v.voter_id)}')">Check</button></td>
    </tr>`).join("") + `</tbody></table>`;
}

function renderAggregators() {
  const el = $("#aggregator-cards");
  if (!electionData) { el.innerHTML = `<p class="muted">Select an election first.</p>`; return; }
  const e = electionData;
  el.innerHTML = e.aggregators.map((a) => {
    const counts = e.election.candidates
      .map((c) => `<span class="k">${esc(c.name)}</span><span class="v">${a.candidate_counts[c.id] ?? "—"}</span>`)
      .join("");
    return `<div class="card">
      <h2>${esc(a.aggregator_id)} ${statusPill(a)}</h2>
      <div class="stat-grid">
        <span class="k">Registered voters</span><span class="v">${a.registered_voters}</span>
        <span class="k">Votes received</span><span class="v">${a.votes_received}</span>
        <span class="k">Domain size</span><span class="v">${a.domain_size ?? "—"}</span>
        <span class="k">PAD count</span><span class="v">${a.pad_count ?? "—"}</span>
        <span class="k">NO_VOTE count</span><span class="v">${a.no_vote_count ?? "—"}</span>
        ${counts}
        <span class="k">Registration valid</span><span class="v">${a.registration_valid == null ? "—" : a.registration_valid ? "yes" : "NO"}</span>
        <span class="k">Proving time</span><span class="v">${fmtMs(a.proving_time_ms)}</span>
        <span class="k">Verification time</span><span class="v">${fmtMs(a.verification_time_ms)}</span>
        <span class="k">Proof size</span><span class="v">${fmtBytes(a.proof_size_bytes)}</span>
      </div>
      ${a.verification_errors && a.verification_errors.length
        ? `<p class="note warn">${a.verification_errors.map(esc).join("<br>")}</p>` : ""}
      <div class="btn-row">
        ${downloadControl(
          `/elections/${e.election.election_id}/aggregators/${a.aggregator_id}/proof.json`,
          `${a.aggregator_id}-proof.json`,
          "Download proof JSON",
          a.proof_status === "pending" || a.proof_status === "ready")}
      </div>
    </div>`;
  }).join("");
}

function renderValidator() {
  const paramsEl = $("#validator-params");
  const artifactLink = $("#download-artifact");
  if (!electionData) {
    paramsEl.innerHTML = `<p class="muted">Select an election first.</p>`;
    $("#bulletin-board").innerHTML = "";
    artifactLink.removeAttribute("href");
    return;
  }
  const e = electionData;
  if (window.AGGIOS_WASM) {
    artifactLink.removeAttribute("href");
    artifactLink.onclick = () =>
      wasmDownload(
        `/elections/${e.election.election_id}/public-artifact.json`,
        `${e.election.election_id}-public-artifact.json`,
      );
  } else {
    artifactLink.href = `/api/aggios/elections/${e.election.election_id}/public-artifact.json`;
  }
  paramsEl.innerHTML = `
    <div class="stat-grid">
      <span class="k">Election ID</span><span class="v">${esc(e.election.election_id)}</span>
      <span class="k">Curve / backend</span><span class="v">${esc(e.election.curve)}</span>
      <span class="k">SRS</span><span class="v">${esc(e.election.srs_ref)}</span>
      <span class="k">NO_VOTE label</span><span class="v">${esc(e.no_vote_label.slice(0, 18))}…</span>
      <span class="k">PAD label</span><span class="v">${esc(e.pad_label.slice(0, 18))}…</span>
    </div>
    <h3>Candidate labels (w_j = hash_to_fr)</h3>
    <table><thead><tr><th>Candidate</th><th>Label</th></tr></thead><tbody>
      ${e.election.candidates.map((c, j) =>
        `<tr><td>${esc(c.name)}</td><td class="v" style="font-family:var(--mono);font-size:12px">${esc(e.candidate_labels[j])}</td></tr>`).join("")}
    </tbody></table>`;
  refreshBulletin();
}

async function refreshBulletin() {
  if (!currentElection) return;
  try {
    const data = await api(`/elections/${currentElection}/bulletin-board`);
    $("#bulletin-board").innerHTML = data.events.slice().reverse().map((ev) => `
      <div class="event">
        <div class="head">
          <span class="kind">#${ev.seq} ${esc(ev.kind)}</span>
          <span class="ts">${new Date(ev.timestamp_unix_ms).toLocaleTimeString()}</span>
        </div>
        <pre>${esc(JSON.stringify(ev.payload).slice(0, 2000))}</pre>
      </div>`).join("");
  } catch (e) { /* ignore */ }
}

/* ---------------- admin actions ---------------- */

$("#new-template").addEventListener("change", (e) => {
  $("#custom-options-wrap").classList.toggle("hidden", e.target.value !== "custom");
});

$("#create-election-btn").addEventListener("click", async () => {
  try {
    const template = $("#new-template").value;
    const body = {
      template,
      title: $("#new-title").value || null,
      custom_options: $("#new-options").value.split("\n").map((s) => s.trim()).filter(Boolean),
      aggregators: $("#new-aggregators").value.split(",").map((s) => s.trim()).filter(Boolean),
    };
    const data = await api("/elections", { method: "POST", body: JSON.stringify(body) });
    currentElection = data.election.election_id;
    log(`created election ${currentElection} ("${data.election.title}")`);
    await refreshAll();
  } catch (err) { log(err.message, true); }
});

$$(".phase-btn").forEach((btn) => btn.addEventListener("click", async () => {
  if (!currentElection) return log("no election selected", true);
  try {
    await api(`/elections/${currentElection}/phase`, {
      method: "POST",
      body: JSON.stringify({ phase: btn.dataset.phase }),
    });
    log(`phase set to ${btn.dataset.phase}`);
    await refreshElection();
  } catch (err) { log(err.message, true); }
}));

window.aggAction = async (aggregatorId, action) => {
  if (!currentElection) return;
  try {
    log(`${action} for ${aggregatorId}…`);
    const data = await api(
      `/elections/${currentElection}/aggregators/${aggregatorId}/${action}`,
      { method: "POST", body: "{}" });
    log(`${action} ${aggregatorId}: ${JSON.stringify(data)}`);
    await refreshElection();
  } catch (err) { log(`${action} ${aggregatorId}: ${err.message}`, true); }
};

$("#admin-finalize-all").addEventListener("click", async () => {
  if (!electionData) return;
  for (const a of electionData.aggregators) {
    if (!a.finalized) await window.aggAction(a.aggregator_id, "finalize-registration");
  }
});

$("#admin-prove-all").addEventListener("click", async () => {
  if (!electionData) return;
  for (const a of electionData.aggregators) {
    if (a.finalized) await window.aggAction(a.aggregator_id, "prove");
  }
});

async function verifyAll() {
  if (!currentElection) return;
  try {
    log("validator: running all checks…");
    const data = await api(`/elections/${currentElection}/verify-all`, { method: "POST", body: "{}" });
    log(`validator results: ${JSON.stringify(data.verifications)}`);
    if (data.duplicate_voter_errors.length) {
      log(`duplicate voters: ${data.duplicate_voter_errors.join("; ")}`, true);
    }
    renderValidatorResults(data);
    await refreshElection();
  } catch (err) { log(err.message, true); }
}

$("#admin-verify-all").addEventListener("click", verifyAll);
$("#validator-verify-all").addEventListener("click", verifyAll);

function renderValidatorResults(data) {
  const el = $("#validator-results");
  el.innerHTML = `
    <h3>Registration checks</h3>
    <table><thead><tr><th>Aggregator</th><th>Registration</th><th>Errors</th></tr></thead><tbody>
      ${data.registration.map((r) => `<tr>
        <td>${esc(r.aggregator_id)}</td>
        <td>${r.registration_valid ? pill("valid", "good") : pill("invalid", "bad")}</td>
        <td class="muted">${r.errors.map(esc).join("; ") || "—"}</td></tr>`).join("")}
    </tbody></table>
    <h3>EPA proof checks</h3>
    <table><thead><tr><th>Aggregator</th><th>Proof</th><th>Time</th><th>Errors</th></tr></thead><tbody>
      ${data.verifications.map((v) => `<tr>
        <td>${esc(v.aggregator_id)}</td>
        <td>${v.valid ? pill("valid", "good") : pill("invalid", "bad")}</td>
        <td>${fmtMs(v.verification_time_ms)}</td>
        <td class="muted">${v.errors.map(esc).join("; ") || "—"}</td></tr>`).join("")}
    </tbody></table>
    ${data.duplicate_voter_errors.length
      ? `<p class="note warn">Duplicate voters: ${data.duplicate_voter_errors.map(esc).join("; ")}</p>` : ""}`;
  const tallyEl = $("#validator-tally");
  tallyEl.innerHTML = electionData
    ? tallyBars(data.verified_global_tally, electionData.election.candidates)
    : JSON.stringify(data.verified_global_tally);
}

/* ---------------- voter actions ---------------- */

$("#create-voters-btn").addEventListener("click", async () => {
  if (!currentElection) return log("no election selected", true);
  try {
    const count = parseInt($("#voter-count").value, 10) || 1;
    const data = await api(`/elections/${currentElection}/voters/demo-create`, {
      method: "POST", body: JSON.stringify({ count }),
    });
    log(`created ${data.created.length} demo voters`);
    await refreshElection();
  } catch (err) { log(err.message, true); }
});

window.registerVoter = async (voterId) => {
  try {
    const aggregatorId = $(`#agg-${CSS.escape(voterId)}`)?.value ?? document.getElementById(`agg-${voterId}`).value;
    await api(`/elections/${currentElection}/register`, {
      method: "POST",
      body: JSON.stringify({ voter_id: voterId, aggregator_id: aggregatorId }),
    });
    log(`${voterId} registered with ${aggregatorId} (BLS delegation verified)`);
    await refreshElection();
  } catch (err) { log(err.message, true); }
};

window.castVote = async (voterId) => {
  try {
    const candidateId = document.getElementById(`cand-${voterId}`).value;
    await api(`/elections/${currentElection}/vote`, {
      method: "POST",
      body: JSON.stringify({ voter_id: voterId, candidate_id: candidateId }),
    });
    log(`${voterId} voted (sent to its aggregator)`);
    await refreshElection();
  } catch (err) { log(err.message, true); }
};

window.checkReceipt = async (voterId) => {
  try {
    const data = await api(`/elections/${currentElection}/voters/${voterId}/receipt`);
    alert(data.available ? "Receipt available" : `Receipt not available: ${data.reason}`);
  } catch (err) { alert(err.message); }
};

$("#auto-run-btn").addEventListener("click", async () => {
  if (!electionData) return;
  const e = electionData;
  try {
    if (e.phase === "registration") {
      const unregistered = e.voters.filter((v) => !v.registered_with);
      for (let i = 0; i < unregistered.length; i++) {
        const agg = e.election.aggregators[i % e.election.aggregators.length];
        await api(`/elections/${currentElection}/register`, {
          method: "POST",
          body: JSON.stringify({ voter_id: unregistered[i].voter_id, aggregator_id: agg }),
        });
      }
      log(`auto-registered ${unregistered.length} voters round-robin`);
    } else if (e.phase === "voting") {
      const pending = e.voters.filter((v) => v.registered_with && !v.has_voted);
      for (const v of pending) {
        const cand = e.election.candidates[Math.floor(Math.random() * e.election.candidates.length)];
        await api(`/elections/${currentElection}/vote`, {
          method: "POST",
          body: JSON.stringify({ voter_id: v.voter_id, candidate_id: cand.id }),
        });
      }
      log(`auto-voted for ${pending.length} voters`);
    } else {
      log("auto-assign works in the registration phase (registers) or voting phase (votes)", true);
    }
    await refreshElection();
  } catch (err) { log(err.message, true); }
});

/* ---------------- benchmarks ---------------- */

function benchWarnings() {
  const real = $("#bench-real").checked;
  const voters = parseInt($("#bench-voters").value, 10);
  $("#bench-sim-note").style.display = real ? "none" : "block";
  const bigNote = $("#bench-big-note");
  if (window.AGGIOS_WASM) {
    bigNote.style.display = real && voters >= 10000 ? "block" : "none";
    bigNote.textContent =
      "In-browser runs are single-threaded WebAssembly and block until complete: " +
      "10⁴ voters takes minutes; 10⁵–10⁶ can take hours or exhaust tab memory " +
      "(failures are recorded honestly, never downsampled). For large sizes use the native " +
      "benchmark CLI from the repository. Cancellation is unavailable in-browser.";
  } else {
    bigNote.style.display = real && voters >= 100000 ? "block" : "none";
  }
}
$("#bench-real").addEventListener("change", benchWarnings);
$("#bench-voters").addEventListener("change", benchWarnings);

/* Live progress stream from the WASM worker (static-site mode). */
window.addEventListener("aggios-progress", (e) => {
  const { benchmark_id, event } = e.detail;
  if (!benchEventLog[benchmark_id]) {
    benchEventLog[benchmark_id] = [];
    benchEventSeq[benchmark_id] = 0;
  }
  benchEventSeq[benchmark_id] = Math.max(benchEventSeq[benchmark_id], event.seq + 1);
  benchEventLog[benchmark_id].push(
    `[${event.stage}] ${event.aggregator ? event.aggregator + ": " : ""}${event.message}`);
  const live = $("#bench-live");
  if (live) {
    live.style.display = "block";
    live.textContent = benchEventLog[benchmark_id].slice(-25).join("\n");
    live.scrollTop = live.scrollHeight;
  }
});

$("#bench-run").addEventListener("click", async () => {
  try {
    const config = {
      voters: parseInt($("#bench-voters").value, 10),
      aggregators: parseInt($("#bench-aggregators").value, 10),
      template: $("#bench-template").value,
      custom_candidates: [],
      assignment: $("#bench-assignment").value,
      assignment_weights: [],
      vote_distribution: $("#bench-votedist").value,
      vote_percentages: [],
      seed: parseInt($("#bench-seed").value, 10) || 42,
      real_crypto: $("#bench-real").checked,
      receipts: false,
    };
    const runBtn = $("#bench-run");
    if (window.AGGIOS_WASM) {
      // The in-browser run is synchronous inside the worker: this call
      // resolves when the whole benchmark is done, with live progress
      // streamed into #bench-live meanwhile.
      runBtn.disabled = true;
      runBtn.textContent = "Running in browser…";
      const live = $("#bench-live");
      if (live) { live.style.display = "block"; live.textContent = "starting…"; }
    }
    try {
      const data = await api("/benchmarks", { method: "POST", body: JSON.stringify(config) });
      if (!benchEventLog[data.benchmark_id]) {
        benchEventSeq[data.benchmark_id] = 0;
        benchEventLog[data.benchmark_id] = [];
      }
      await refreshBenchmarks();
    } finally {
      const runBtn2 = $("#bench-run");
      runBtn2.disabled = false;
      runBtn2.textContent = "Start benchmark";
      const live = $("#bench-live");
      if (live && window.AGGIOS_WASM) live.style.display = "none";
    }
  } catch (err) { alert(err.message); }
});

window.cancelBenchmark = async (bid) => {
  try { await api(`/benchmarks/${bid}/cancel`, { method: "POST", body: "{}" }); }
  catch (err) { alert(err.message); }
};

async function refreshBenchmarks() {
  let data;
  try { data = await api("/benchmarks"); } catch (e) { return; }
  const el = $("#bench-jobs");
  if (!data.benchmarks.length) {
    el.innerHTML = `<p class="muted">No benchmark jobs yet.</p>`;
  } else {
    // Pull new events for running jobs.
    for (const job of data.benchmarks) {
      if (!(job.benchmark_id in benchEventSeq)) {
        benchEventSeq[job.benchmark_id] = 0;
        benchEventLog[job.benchmark_id] = [];
      }
      try {
        const ev = await api(`/benchmarks/${job.benchmark_id}/events?since=${benchEventSeq[job.benchmark_id]}`);
        for (const e of ev.events) {
          benchEventSeq[job.benchmark_id] = e.seq + 1;
          benchEventLog[job.benchmark_id].push(
            `[${e.stage}] ${e.aggregator ? e.aggregator + ": " : ""}${e.message}`);
        }
      } catch (e) { /* ignore */ }
    }
    el.innerHTML = data.benchmarks.map(renderBenchJob).join("");
    // keep logs scrolled to bottom
    $$(".bench-log").forEach((l) => { l.scrollTop = l.scrollHeight; });
  }
  const anyRunning = data.benchmarks.some((j) => j.status === "running");
  clearTimeout(benchTimer);
  if (anyRunning) benchTimer = setTimeout(refreshBenchmarks, 2000);
}

function statusPillBench(status) {
  return {
    running: pill("running", "info"),
    completed: pill("completed", "good"),
    failed: pill("failed", "bad"),
    cancelled: pill("cancelled", "warn"),
  }[status] || pill(status, "");
}

function renderBenchJob(job) {
  const c = job.config;
  const r = job.result;
  const lines = (benchEventLog[job.benchmark_id] || []).slice(-40).join("\n");
  let resultHtml = "";
  if (r) {
    const perAgg = (r.per_aggregator || []).map((a) => `<tr>
      <td>${esc(a.aggregator_id)}</td><td>${a.voters}</td><td>${a.domain_size}</td><td>${a.pad_count}</td>
      <td>${fmtMs(a.registration_ms + a.finalization_ms + a.registration_validation_ms)}</td>
      <td>${fmtMs(a.epa_proving_ms)}</td><td>${fmtMs(a.epa_verification_ms)}</td>
      <td>${fmtBytes(a.proof_size_bytes)}</td>
      <td>${a.verified ? pill("yes", "good") : pill("no", "bad")}</td>
    </tr>`).join("");
    resultHtml = `
      <div class="stat-grid">
        <span class="k">Mode</span><span class="v">${esc(r.mode)}</span>
        <span class="k">Total time</span><span class="v">${fmtMs(r.total_ms)}</span>
        <span class="k">Registration (all)</span><span class="v">${fmtMs(r.registration_time_ms)}</span>
        <span class="k">EPA proving (all)</span><span class="v">${fmtMs(r.epa_proving_time_ms)}</span>
        <span class="k">EPA verification (all)</span><span class="v">${fmtMs(r.epa_verification_time_ms)}</span>
        <span class="k">Proof bytes (all)</span><span class="v">${fmtBytes(r.proof_size_bytes_total)}</span>
        <span class="k">Public artifact</span><span class="v">${fmtBytes(r.public_artifact_size_bytes)}</span>
        <span class="k">Peak RSS</span><span class="v">${r.max_rss_bytes ? fmtBytes(r.max_rss_bytes) : "—"}</span>
        <span class="k">Tally matches expected</span><span class="v">${r.tally_matches_expected ? "yes" : "no"}</span>
        <span class="k">Receipts</span><span class="v">${esc(r.receipts)}</span>
      </div>
      ${r.error ? `<p class="note warn">Recorded failure: ${esc(r.error)}</p>` : ""}
      ${perAgg ? `<table><thead><tr><th>Agg</th><th>Voters</th><th>Domain</th><th>Pad</th>
        <th>Registration</th><th>EPA prove</th><th>EPA verify</th><th>Proof</th><th>Verified</th></tr></thead>
        <tbody>${perAgg}</tbody></table>` : ""}
      <div class="btn-row">
        ${downloadControl(`/benchmarks/${job.benchmark_id}/results.json`, `${job.benchmark_id}.json`, "JSON", false)}
        ${downloadControl(`/benchmarks/${job.benchmark_id}/results.csv`, `${job.benchmark_id}.csv`, "CSV", false)}
      </div>`;
  }
  return `<div class="bench-job">
    <div class="head">
      <span class="title">${esc(job.benchmark_id)} — ${c.voters.toLocaleString()} voters,
        ${c.aggregators} aggregators, ${esc(c.assignment)} / ${esc(c.vote_distribution)}, seed ${c.seed},
        ${c.real_crypto ? "real crypto" : "SIMULATION (non-cryptographic)"}</span>
      <span class="btn-row">${statusPillBench(job.status)}
        ${job.status === "running" ? `<button onclick="cancelBenchmark('${esc(job.benchmark_id)}')">Cancel</button>` : ""}</span>
    </div>
    ${job.status === "running" && lines ? `<pre class="log bench-log">${esc(lines)}</pre>` : ""}
    ${resultHtml}
  </div>`;
}

/* ---------------- boot ---------------- */

if (window.AGGIOS_WASM) {
  const banner = document.querySelector(".banner");
  if (banner) {
    banner.innerHTML +=
      ' <span class="pill info" style="margin-left:6px">Running fully in your browser: ' +
      "all cryptography (including the black-box EPA prover/verifier) executes locally " +
      "via WebAssembly; no data leaves this page.</span>";
  }
}
benchWarnings();
if (location.hash.length > 1) activateTab(location.hash.slice(1));
refreshAll();
setInterval(() => { if (currentElection) refreshElection(); }, 4000);
