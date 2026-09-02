// mechanic GUI — vanilla JS, no framework, no CDN dependency (offline by
// construction). Every number rendered here comes verbatim from the core's
// own JSON (`/api/jobs/{id}/result`, the same shape `mechanic triage --json`
// produces) - this file only filters/sorts/displays already-computed data,
// it never derives a new number. Recent-repo memory uses localStorage only
// (per-browser convenience, never sent anywhere).

const state = {
  jobId: null,
  report: null,
  legend: null,
  filters: { search: "", priority: new Set(), tier: new Set() },
  sort: { key: "priority", dir: 1 },
};

const PRIORITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNCERTAIN: 4 };
const PRIORITY_LABELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNCERTAIN"];
const TIER_ORDER = { IOC: 0, Artifact: 1, Tool: 2, TTP: 3 };
const BAND_LABEL = {
  stale_over_2yr: ">2yr",
  aging_6mo_to_2yr: "6mo-2yr",
  fresh_under_6mo: "<6mo",
};
const RECENT_KEY = "mechanic-gui-recent-repos";
const RECENT_MAX = 8;

function el(tag, attrs, children) {
  const e = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") e.className = v;
      else if (k === "html") e.innerHTML = v;
      else e.setAttribute(k, v);
    }
  }
  (children || []).forEach((c) => e.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
  return e;
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail;
    try {
      detail = (await res.json()).detail;
    } catch (e) {
      detail = res.statusText;
    }
    const err = new Error(detail || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// ---------------- recent repos (localStorage only) ----------------

function loadRecent() {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
  } catch (e) {
    return [];
  }
}

function saveRecent(entry) {
  try {
    let list = loadRecent().filter((r) => !(r.path === entry.path && r.fmt === entry.fmt && r.subdir === entry.subdir));
    list.unshift({ ...entry, lastLoaded: Date.now() });
    list = list.slice(0, RECENT_MAX);
    localStorage.setItem(RECENT_KEY, JSON.stringify(list));
  } catch (e) {
    /* localStorage unavailable (private mode, etc.) - not fatal, just no memory */
  }
  renderRecent();
}

function renderRecent() {
  const list = loadRecent();
  const section = document.getElementById("recent-section");
  const ul = document.getElementById("recent-list");
  ul.innerHTML = "";
  if (!list.length) {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  list.forEach((r) => {
    const name = r.path.replace(/[\\/]+$/, "").split(/[\\/]/).pop();
    const li = el("li", null, [
      el("span", { class: "recent-name" }, [name]),
      el("span", { class: "recent-meta" }, [`${r.fmt}${r.subdir ? " · " + r.subdir : ""}`]),
    ]);
    li.title = r.path;
    li.onclick = () => {
      document.getElementById("f-path").value = r.path;
      document.getElementById("f-fmt").value = r.fmt;
      document.getElementById("f-subdir").value = r.subdir || "";
      document.getElementById("load-form").requestSubmit();
    };
    ul.appendChild(li);
  });
}

// ---------------- load flow ----------------

document.getElementById("load-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  hideError();
  const path = document.getElementById("f-path").value.trim();
  const fmt = document.getElementById("f-fmt").value;
  const subdir = document.getElementById("f-subdir").value.trim() || null;
  const threshold = parseFloat(document.getElementById("f-threshold").value) || 0.1;
  const refresh = document.getElementById("f-refresh").checked;

  showProgress(true);
  try {
    const { job_id } = await api("/api/load", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, fmt, subdir, mechanical_threshold: threshold, refresh }),
    });
    state.jobId = job_id;
    pollJob(job_id, { path, fmt, subdir });
  } catch (e) {
    showProgress(false);
    showError(e.message);
  }
});

document.getElementById("change-repo-btn").addEventListener("click", () => {
  document.getElementById("load-panel").hidden = false;
  document.getElementById("loaded-summary").hidden = true;
});

function pollJob(jobId, loadedWith) {
  const timer = setInterval(async () => {
    let status;
    try {
      status = await api(`/api/jobs/${jobId}`);
    } catch (e) {
      clearInterval(timer);
      showProgress(false);
      showError(e.message);
      return;
    }
    renderProgress(status);
    if (status.status === "done") {
      clearInterval(timer);
      loadResult(jobId, loadedWith);
    } else if (status.status === "error") {
      clearInterval(timer);
      showProgress(false);
      showError(status.error || "Unknown error while loading this repository.");
    }
  }, 600);
}

function renderProgress(status) {
  const labels = {
    pending: "Starting…",
    mining: status.total ? `Mining git history… (${status.done} commits)` : "Mining git history…",
    staleness: "Computing staleness…",
    semantic_diff: "Computing behavioral diff…",
    classifying: `Classifying fragility… (${status.done}/${status.total || "?"})`,
  };
  const label = labels[status.status] || status.status;
  const fill = document.getElementById("progress-fill");
  const lbl = document.getElementById("progress-label");
  lbl.textContent = `${label} — ${status.elapsed_seconds}s`;
  if (status.status === "classifying" && status.total) {
    fill.classList.remove("indeterminate");
    fill.style.width = `${Math.max(4, Math.round((status.done / status.total) * 100))}%`;
  } else {
    fill.classList.add("indeterminate");
  }
}

function showProgress(visible) {
  document.getElementById("progress-area").hidden = !visible;
  if (visible) renderProgress({ status: "pending", done: 0, total: 0, elapsed_seconds: 0 });
}

function showError(message) {
  const b = document.getElementById("error-banner");
  b.textContent = message;
  b.hidden = false;
}
function hideError() {
  document.getElementById("error-banner").hidden = true;
}

async function loadResult(jobId, loadedWith) {
  try {
    const [report, legend] = await Promise.all([
      api(`/api/jobs/${jobId}/result?ordering=priority_first`),
      state.legend ? Promise.resolve(state.legend) : api("/api/priority-legend"),
    ]);
    state.report = report;
    state.legend = legend;
    showProgress(false);
    if (report.rule_count === 0) {
      showError("No rules were discovered under this path. Check the path/format/subdirectory.");
      return;
    }
    if (loadedWith) saveRecent(loadedWith);

    document.getElementById("empty-state").hidden = true;
    document.getElementById("load-panel").hidden = true;
    document.getElementById("loaded-summary").hidden = false;
    document.getElementById("loaded-path").textContent = report.root + (report.fmt !== "sigma" ? ` (${report.fmt})` : "");

    renderOverview(report);
    renderControls(report);
    applyAndRenderTable();
    document.getElementById("overview").hidden = false;
    document.getElementById("triage-section").hidden = false;
  } catch (e) {
    showError(e.message);
  }
}

// ---------------- legend modal ----------------

document.getElementById("legend-toggle").addEventListener("click", async () => {
  if (!state.legend) state.legend = await api("/api/priority-legend");
  renderLegend(state.legend);
  document.getElementById("legend-overlay").hidden = false;
});
document.getElementById("legend-close").onclick = () => (document.getElementById("legend-overlay").hidden = true);
document.getElementById("legend-overlay").addEventListener("click", (e) => {
  if (e.target.id === "legend-overlay") e.target.hidden = true;
});

function renderLegend(legend) {
  document.getElementById("legend-rationale").textContent =
    legend.rationale_plain || legend.rationale;
  const table = document.getElementById("legend-table");
  table.innerHTML = "";
  const thead = el("tr", null, [el("th", null, ["tier \\ staleness"])]);
  legend.staleness_bands_stale_to_fresh.forEach((b) => thead.appendChild(el("th", null, [BAND_LABEL[b] || b])));
  table.appendChild(el("thead", null, [thead]));
  const tbody = el("tbody");
  legend.tiers_worst_to_best.forEach((tier) => {
    const row = el("tr", null, [el("th", null, [tier])]);
    legend.staleness_bands_stale_to_fresh.forEach((band) => {
      const cell = legend.cells.find((c) => c.tier === tier && c.staleness_band === band);
      row.appendChild(el("td", null, [priorityBadge(cell.label, null, null, false)]));
    });
    tbody.appendChild(row);
  });
  table.appendChild(tbody);
}

// ---------------- overview: stats + charts ----------------

function renderOverview(report) {
  const cards = document.getElementById("stat-cards");
  cards.innerHTML = "";
  const m = report.summary.match(/^(\d+) rules, (\d+) fragile, (\d+) stale, (\d+) need attention/);
  const values = m ? [m[1], m[2], m[3], m[4]] : ["-", "-", "-", "-"];
  const labels = ["Rules", "Fragile", "Stale", "Need attention"];
  values.forEach((v, i) => {
    cards.appendChild(
      el("div", { class: "stat-card" + (i === 3 ? " accent" : "") }, [
        el("div", { class: "stat-value" }, [String(v)]),
        el("div", { class: "stat-label" }, [labels[i]]),
      ])
    );
  });

  renderPriorityChart(report.priority_breakdown);
  renderTierChart(report);
  renderStalenessChart(report);
}

function renderPriorityChart(breakdown) {
  const total = PRIORITY_LABELS.reduce((s, l) => s + (breakdown[l] || 0), 0) || 1;
  const body = document.getElementById("chart-priority-body");
  body.innerHTML = "";
  const bar = el("div", { class: "stack-bar" });
  PRIORITY_LABELS.forEach((label) => {
    const count = breakdown[label] || 0;
    if (!count) return;
    const pct = (count / total) * 100;
    const seg = el("div", { class: "stack-seg" });
    seg.style.width = `${pct}%`;
    seg.style.background = `var(--${label.toLowerCase()})`;
    seg.title = `${label}: ${count}`;
    bar.appendChild(seg);
  });
  body.appendChild(bar);
  const legend = el("div", { class: "chart-legend" });
  PRIORITY_LABELS.forEach((label) => {
    const count = breakdown[label] || 0;
    legend.appendChild(
      el("span", { class: "chart-legend-item" }, [
        el("span", { class: "chart-legend-swatch", style: `background:var(--${label.toLowerCase()})` }),
        `${label} ${count}`,
      ])
    );
  });
  body.appendChild(legend);
}

function hbarChart(containerBody, rows) {
  containerBody.innerHTML = "";
  const max = Math.max(1, ...rows.map((r) => r.count));
  rows.forEach((r) => {
    const pct = Math.max(2, Math.round((r.count / max) * 100));
    containerBody.appendChild(
      el("div", { class: "hbar-row" }, [
        el("span", { class: "hbar-label" }, [r.label]),
        el("div", { class: "hbar-track" }, [el("div", { class: "hbar-fill", style: `width:${pct}%` })]),
        el("span", { class: "hbar-value" }, [String(r.count)]),
      ])
    );
  });
}

function renderTierChart(report) {
  const all = [...report.rules, ...report.unscoreable];
  const counts = { IOC: 0, Artifact: 0, Tool: 0, TTP: 0 };
  all.forEach((r) => {
    if (r.fragility.tier) counts[r.fragility.tier] = (counts[r.fragility.tier] || 0) + 1;
  });
  hbarChart(
    document.getElementById("chart-tier-body"),
    Object.entries(counts).map(([label, count]) => ({ label, count }))
  );
}

function renderStalenessChart(report) {
  const all = [...report.rules, ...report.unscoreable];
  const counts = { ">2yr": 0, "6mo-2yr": 0, "<6mo": 0, unknown: 0 };
  all.forEach((r) => {
    const band = r.priority.staleness_band;
    if (band === "stale_over_2yr") counts[">2yr"]++;
    else if (band === "aging_6mo_to_2yr") counts["6mo-2yr"]++;
    else if (band === "fresh_under_6mo") counts["<6mo"]++;
    else counts.unknown++;
  });
  const rows = Object.entries(counts)
    .filter(([, c]) => c > 0)
    .map(([label, count]) => ({ label, count }));
  hbarChart(document.getElementById("chart-staleness-body"), rows);
}

// ---------------- controls ----------------

function renderControls(report) {
  const all = [...report.rules, ...report.unscoreable];

  const priorityCounts = {};
  const tierCounts = {};
  all.forEach((r) => {
    const p = r.priority.uncertain || !r.priority.label ? "UNCERTAIN" : r.priority.label;
    priorityCounts[p] = (priorityCounts[p] || 0) + 1;
    const t = r.fragility.tier || "unscoreable";
    tierCounts[t] = (tierCounts[t] || 0) + 1;
  });

  buildChips("chip-priority", PRIORITY_LABELS, priorityCounts, state.filters.priority, "chip-");
  buildChips("chip-tier", ["IOC", "Artifact", "Tool", "TTP", "unscoreable"], tierCounts, state.filters.tier, "");

  document.getElementById("c-search").oninput = (e) => {
    state.filters.search = e.target.value.toLowerCase();
    applyAndRenderTable();
  };
  document.getElementById("c-ordering").onchange = async (e) => {
    state.report = await api(`/api/jobs/${state.jobId}/result?ordering=${e.target.value}`);
    applyAndRenderTable();
  };
  document.querySelectorAll("#triage-table th[data-sort]").forEach((th) => {
    th.onclick = () => {
      const key = th.dataset.sort;
      if (state.sort.key === key) state.sort.dir *= -1;
      else {
        state.sort.key = key;
        state.sort.dir = 1;
      }
      applyAndRenderTable();
    };
  });
}

function buildChips(containerId, values, counts, activeSet, classPrefix) {
  const container = document.getElementById(containerId);
  container.querySelectorAll(".chip").forEach((c) => c.remove());
  values
    .filter((v) => counts[v])
    .forEach((v) => {
      const chip = el("span", { class: `chip ${classPrefix}${v}${activeSet.has(v) ? " active" : ""}` }, [
        `${v} (${counts[v]})`,
      ]);
      chip.onclick = () => {
        if (activeSet.has(v)) activeSet.delete(v);
        else activeSet.add(v);
        chip.classList.toggle("active");
        applyAndRenderTable();
      };
      container.appendChild(chip);
    });
}

// ---------------- table ----------------

function applyAndRenderTable() {
  const report = state.report;
  if (!report) return;
  let rows = [...report.rules];

  const { search, priority, tier } = state.filters;
  if (search) rows = rows.filter((r) => r.file.toLowerCase().includes(search));
  if (priority.size) {
    rows = rows.filter((r) => {
      const p = r.priority.uncertain || !r.priority.label ? "UNCERTAIN" : r.priority.label;
      return priority.has(p);
    });
  }
  if (tier.size) rows = rows.filter((r) => tier.has(r.fragility.tier || "unscoreable"));

  const { key, dir } = state.sort;
  rows.sort((a, b) => {
    let av, bv;
    if (key === "priority") {
      av = a.priority.uncertain ? 5 : PRIORITY_ORDER[a.priority.label] ?? 5;
      bv = b.priority.uncertain ? 5 : PRIORITY_ORDER[b.priority.label] ?? 5;
    } else if (key === "staleness") {
      av = a.staleness.never_revised ? Infinity : a.staleness.days_since_behavioral_change ?? -1;
      bv = b.staleness.never_revised ? Infinity : b.staleness.days_since_behavioral_change ?? -1;
    } else if (key === "age") {
      av = a.staleness.age_days ?? -1;
      bv = b.staleness.age_days ?? -1;
    } else {
      av = a.file;
      bv = b.file;
    }
    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;
    return 0;
  });

  const tbody = document.getElementById("triage-tbody");
  tbody.innerHTML = "";
  rows.forEach((r) => tbody.appendChild(buildRow(r)));
  document.getElementById("row-count").textContent = `${rows.length} of ${report.rules.length} rules`;

  renderUnscoreable(report.unscoreable);
}

function priorityBadge(label, tier, band, showAxis = true) {
  const safeLabel = label || "UNCERTAIN";
  const axisText = showAxis && tier && band ? `${tier}×${BAND_LABEL[band] || band}` : null;
  const children = [el("span", { class: "dot" }), safeLabel];
  if (axisText) children.push(el("span", { class: "axis" }, [axisText]));
  return el("span", { class: `priority-badge ${safeLabel}` }, children);
}

function fileCell(path) {
  const parts = path.split("/");
  const name = parts.pop();
  const dir = parts.length ? parts.join("/") + "/" : "";
  return el("span", null, [el("span", { class: "file-dir" }, [dir]), name]);
}

function buildRow(r) {
  const tr = el("tr");

  const p = r.priority;
  const badge = priorityBadge(p.uncertain ? null : p.label, p.tier, p.staleness_band);
  if (p.lower_confidence) badge.appendChild(el("span", { class: "caveat-flag" }, ["TXT"]));
  tr.appendChild(el("td", null, [badge]));

  const fileTd = el("td", { class: "file-cell" }, [fileCell(r.file)]);
  tr.appendChild(fileTd);

  tr.appendChild(el("td", { class: "why-cell", title: r.short_reason }, [r.short_reason]));
  tr.appendChild(
    el("td", null, [r.staleness.never_revised ? "NEVER REVISED" : `${r.staleness.days_since_behavioral_change}d ago`])
  );
  tr.appendChild(el("td", { class: "mono" }, [r.staleness.age_days != null ? `${r.staleness.age_days}d` : "-"]));

  tr.onclick = () => openDetail(r);
  return tr;
}

function renderUnscoreable(list) {
  document.getElementById("unscoreable-summary").textContent = `Unscoreable rules (${list.length}) — no tier assigned, never defaulted`;
  const tbody = document.getElementById("unscoreable-tbody");
  tbody.innerHTML = "";
  list.forEach((r) => {
    tbody.appendChild(
      el("tr", null, [
        el("td", { class: "file-cell" }, [fileCell(r.file)]),
        el("td", { class: "why-cell" }, [r.fragility.unscoreable_reason || "-"]),
      ])
    );
  });
}

// ---------------- detail panel (tabbed) ----------------

let currentDetailRule = null;

function openDetail(r) {
  currentDetailRule = r;
  document.getElementById("detail-file").textContent = r.file;
  renderDetailOverview(r);
  document.getElementById("source-view").textContent = "Loading…";
  document.getElementById("history-view").textContent = "Loading…";
  switchTab("overview");
  document.getElementById("detail-overlay").hidden = false;
}

function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
  if (name === "source") loadSourceTab();
  if (name === "history") loadHistoryTab();
}

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

function renderDetailOverview(r) {
  const content = document.getElementById("tab-overview");
  content.innerHTML = "";

  content.appendChild(el("h3", null, ["Explanation"]));
  content.appendChild(el("div", { class: "narrative" }, [r.narrative]));

  if (r.fragility.caveat) content.appendChild(el("div", { class: "caveat-box" }, [r.fragility.caveat]));

  content.appendChild(el("h3", null, ["Priority"]));
  content.appendChild(el("div", { style: "margin-top:6px" }, [priorityBadge(r.priority.uncertain ? null : r.priority.label, r.priority.tier, r.priority.staleness_band)]));
  if (r.priority.uncertain) {
    content.appendChild(el("p", { class: "muted", style: "margin-top:8px" }, [r.priority.uncertainty_reason]));
  }

  content.appendChild(el("h3", null, ["Key facts"]));
  content.appendChild(
    tableOf([
      ["Fragility tier", r.fragility.tier || "-"],
      ["Confidence", r.fragility.confidence],
      ["Never revised", String(r.staleness.never_revised)],
      ["Days since behavioral change", r.staleness.days_since_behavioral_change ?? "N/A"],
      ["Age (days)", r.staleness.age_days ?? "unknown"],
    ])
  );

  if (r.fragility.atoms && r.fragility.atoms.length) {
    content.appendChild(el("h3", null, ["Contributing atoms"]));
    const chips = el("div", { class: "atom-chips" });
    r.fragility.atoms.forEach((a) => chips.appendChild(el("span", { class: "atom-chip" }, [`${a.field}=${a.value}`])));
    content.appendChild(chips);
  }

  if (r.triage_hypotheses && r.triage_hypotheses.length) {
    content.appendChild(el("h3", null, ["Triage hypotheses (untested)"]));
    const tags = el("div", { class: "hyp-tags" });
    r.triage_hypotheses.forEach((h) => tags.appendChild(el("span", { class: "hyp-tag" }, [h])));
    content.appendChild(tags);
  }
}

function tableOf(pairs) {
  const t = el("table");
  pairs.forEach(([k, v]) => t.appendChild(el("tr", null, [el("td", null, [k]), el("td", null, [String(v)])])));
  return t;
}

async function loadSourceTab() {
  const view = document.getElementById("source-view");
  try {
    const data = await api(`/api/jobs/${state.jobId}/rule-source?file=${encodeURIComponent(currentDetailRule.file)}`);
    view.innerHTML = "";
    view.appendChild(highlightYaml(data.content));
  } catch (e) {
    view.textContent = `Could not load source: ${e.message}`;
  }
}

function highlightYaml(text) {
  // A small, dependency-free highlighter - just enough to make keys/strings/
  // comments visually distinct. Not a real YAML parser; purely cosmetic.
  const frag = document.createDocumentFragment();
  text.split("\n").forEach((line, i) => {
    if (i > 0) frag.appendChild(document.createTextNode("\n"));
    const commentIdx = line.indexOf("#");
    const codePart = commentIdx >= 0 ? line.slice(0, commentIdx) : line;
    const commentPart = commentIdx >= 0 ? line.slice(commentIdx) : "";
    const keyMatch = codePart.match(/^(\s*(?:-\s*)?)([\w.|-]+)(:)(.*)$/);
    if (keyMatch) {
      frag.appendChild(document.createTextNode(keyMatch[1]));
      frag.appendChild(el("span", { class: "yaml-key" }, [keyMatch[2]]));
      frag.appendChild(document.createTextNode(keyMatch[3]));
      appendValuePart(frag, keyMatch[4]);
    } else {
      appendValuePart(frag, codePart);
    }
    if (commentPart) frag.appendChild(el("span", { class: "yaml-comment" }, [commentPart]));
  });
  return frag;
}

function appendValuePart(frag, text) {
  const strMatch = text.match(/^(\s*)(['"].*['"])(\s*)$/);
  if (strMatch) {
    frag.appendChild(document.createTextNode(strMatch[1]));
    frag.appendChild(el("span", { class: "yaml-string" }, [strMatch[2]]));
    frag.appendChild(document.createTextNode(strMatch[3]));
  } else {
    frag.appendChild(document.createTextNode(text));
  }
}

async function loadHistoryTab() {
  const view = document.getElementById("history-view");
  try {
    const data = await api(`/api/jobs/${state.jobId}/rule-history?file=${encodeURIComponent(currentDetailRule.file)}`);
    view.innerHTML = "";
    if (!data.commits.length) {
      view.appendChild(el("p", { class: "muted" }, ["No commits found for this file (may have been created in a mechanical/bulk commit)."]));
      return;
    }
    data.commits.forEach((c) => {
      view.appendChild(
        el("div", { class: "history-item" }, [
          el("span", { class: "history-date" }, [c.date]),
          el("div", { class: "history-body" }, [
            el("div", { class: "history-subject" }, [c.subject || "(no subject)"]),
            el("div", { class: "history-meta" }, [`${c.short_hash} · ${c.author}${c.is_merge ? " · merge" : ""}`]),
          ]),
        ])
      );
    });
  } catch (e) {
    view.textContent = `Could not load history: ${e.message}`;
  }
}

document.getElementById("detail-close").onclick = () => {
  document.getElementById("detail-overlay").hidden = true;
};
document.getElementById("detail-overlay").addEventListener("click", (e) => {
  if (e.target.id === "detail-overlay") e.target.hidden = true;
});
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  document.getElementById("detail-overlay").hidden = true;
  document.getElementById("legend-overlay").hidden = true;
});

// ---------------- init ----------------

renderRecent();
