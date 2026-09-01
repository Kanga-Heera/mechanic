// mechanic GUI — vanilla JS, no framework, no CDN dependency (offline by
// construction). Every number rendered here comes verbatim from the core's
// own JSON (`/api/jobs/{id}/result`, the same shape `mechanic triage --json`
// produces) - this file only filters/sorts/displays already-computed data,
// it never derives a new number.

const state = {
  jobId: null,
  report: null, // full to_dict() payload from /api/jobs/{id}/result
  legend: null,
  filters: { search: "", priority: new Set(), tier: new Set() },
  sort: { key: "priority", dir: 1 },
};

const PRIORITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNCERTAIN: 4 };
const TIER_ORDER = { IOC: 0, Artifact: 1, Tool: 2, TTP: 3 };
const BAND_LABEL = {
  stale_over_2yr: ">2yr",
  aging_6mo_to_2yr: "6mo-2yr",
  fresh_under_6mo: "<6mo",
};

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

// ---------------- load flow ----------------

document.getElementById("load-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  hideError();
  const path = document.getElementById("f-path").value.trim();
  const fmt = document.getElementById("f-fmt").value;
  const subdir = document.getElementById("f-subdir").value.trim() || null;
  const threshold = parseFloat(document.getElementById("f-threshold").value) || 0.1;
  const refresh = document.getElementById("f-refresh").checked;

  showProgress(true, "Starting…", 0, 0);
  try {
    const { job_id } = await api("/api/load", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, fmt, subdir, mechanical_threshold: threshold, refresh }),
    });
    state.jobId = job_id;
    pollJob(job_id);
  } catch (e) {
    showProgress(false);
    showError(e.message);
  }
});

function pollJob(jobId) {
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
      loadResult(jobId);
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
    mining: status.total ? `Mining git history… (${status.done} commits so far)` : "Mining git history…",
    staleness: "Computing staleness…",
    semantic_diff: "Computing behavioral diff…",
    classifying: `Classifying rule fragility… (${status.done}/${status.total || "?"})`,
  };
  const label = labels[status.status] || status.status;
  const fill = document.getElementById("progress-fill");
  const lbl = document.getElementById("progress-label");
  lbl.textContent = `${label} — ${status.elapsed_seconds}s elapsed`;
  if (status.status === "classifying" && status.total) {
    fill.classList.remove("indeterminate");
    fill.style.width = `${Math.max(4, Math.round((status.done / status.total) * 100))}%`;
  } else {
    fill.classList.add("indeterminate");
  }
}

function showProgress(visible, label, done, total) {
  document.getElementById("progress-area").hidden = !visible;
  if (visible) renderProgress({ status: "pending", done: done || 0, total: total || 0, elapsed_seconds: 0 });
}

function showError(message) {
  const b = document.getElementById("error-banner");
  b.textContent = message;
  b.hidden = false;
}
function hideError() {
  document.getElementById("error-banner").hidden = true;
}

async function loadResult(jobId) {
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
    renderLegend(legend);
    renderOverview(report);
    renderControls(report);
    applyAndRenderTable();
    document.getElementById("overview").hidden = false;
    document.getElementById("triage-section").hidden = false;
  } catch (e) {
    showError(e.message);
  }
}

// ---------------- legend ----------------

document.getElementById("legend-toggle").addEventListener("click", async () => {
  const panel = document.getElementById("legend-panel");
  if (panel.hidden && !state.legend) {
    state.legend = await api("/api/priority-legend");
    renderLegend(state.legend);
  }
  panel.hidden = !panel.hidden;
});

function renderLegend(legend) {
  document.getElementById("legend-rationale").textContent = legend.rationale;
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
      const td = el("td", null, [priorityBadge(cell.label, null, null, false)]);
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  table.appendChild(tbody);
}

// ---------------- overview ----------------

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

  const pills = document.getElementById("priority-pills");
  pills.innerHTML = "";
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNCERTAIN"];
  order.forEach((label) => {
    const count = report.priority_breakdown[label] ?? 0;
    pills.appendChild(
      el("span", { class: `pill pill-${label}` }, [label, el("span", { class: "pill-count" }, [String(count)])])
    );
  });
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

  buildChips("chip-priority", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNCERTAIN"], priorityCounts, state.filters.priority, "chip-");
  buildChips("chip-tier", ["IOC", "Artifact", "Tool", "TTP", "unscoreable"], tierCounts, state.filters.tier, "");

  document.getElementById("c-search").oninput = (e) => {
    state.filters.search = e.target.value.toLowerCase();
    applyAndRenderTable();
  };
  document.getElementById("c-ordering").onchange = async (e) => {
    const ordering = e.target.value;
    state.report = await api(`/api/jobs/${state.jobId}/result?ordering=${ordering}`);
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
    } else if (key === "tier") {
      av = TIER_ORDER[a.fragility.tier] ?? 9;
      bv = TIER_ORDER[b.fragility.tier] ?? 9;
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
  const children = [safeLabel];
  if (axisText) children.push(el("span", { class: "axis" }, [axisText]));
  return el("span", { class: `priority-badge ${safeLabel}` }, children);
}

function buildRow(r) {
  const tr = el("tr");
  tr.appendChild(el("td", { class: "file-cell" }, [r.file]));

  const p = r.priority;
  const badge = priorityBadge(p.uncertain ? null : p.label, p.tier, p.staleness_band);
  if (p.lower_confidence) badge.appendChild(el("span", { class: "caveat-flag" }, ["TEXT-PATH"]));
  tr.appendChild(el("td", null, [badge]));

  tr.appendChild(el("td", { class: "mono" }, [r.fragility.tier || "-"]));
  tr.appendChild(el("td", { class: "why-cell" }, [r.short_reason]));
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
        el("td", { class: "file-cell" }, [r.file]),
        el("td", { class: "why-cell" }, [r.fragility.unscoreable_reason || "-"]),
      ])
    );
  });
}

// ---------------- detail panel ----------------

function openDetail(r) {
  const content = document.getElementById("detail-content");
  content.innerHTML = "";
  content.appendChild(el("div", { class: "rule-file" }, [r.file]));

  content.appendChild(el("h3", null, ["Explanation"]));
  content.appendChild(el("div", { class: "narrative" }, [r.narrative]));

  if (r.fragility.caveat) {
    content.appendChild(el("div", { class: "caveat-box" }, [r.fragility.caveat]));
  }

  content.appendChild(el("h3", null, ["Priority"]));
  content.appendChild(
    tableOf([
      ["Label", r.priority.uncertain ? "UNCERTAIN" : r.priority.label],
      ["Fragility tier (axis 1)", r.priority.tier || "-"],
      ["Staleness band (axis 2)", r.priority.staleness_band ? BAND_LABEL[r.priority.staleness_band] : "-"],
      ["Lower confidence (text-path)", r.priority.lower_confidence ? "yes" : "no"],
      ...(r.priority.uncertain ? [["Why uncertain", r.priority.uncertainty_reason]] : []),
    ])
  );

  content.appendChild(el("h3", null, ["Staleness"]));
  content.appendChild(
    tableOf([
      ["Never revised", String(r.staleness.never_revised)],
      ["Behavioral commit count", String(r.staleness.behavioral_commit_count)],
      ["Days since last behavioral change", r.staleness.days_since_behavioral_change ?? "N/A"],
      ["Age (days)", r.staleness.age_days ?? "unknown"],
      ["Classification confidence", r.staleness.classification_confidence || "n/a"],
    ])
  );

  content.appendChild(el("h3", null, ["Fragility"]));
  content.appendChild(
    tableOf([
      ["Tier", r.fragility.tier || "-"],
      ["Confidence", r.fragility.confidence],
      ["AND/OR-corrected (AST walk)", String(r.fragility.and_or_corrected)],
      ["Structural findings", r.fragility.structural_findings.join(", ") || "none"],
    ])
  );

  if (r.fragility.atoms && r.fragility.atoms.length) {
    content.appendChild(el("h3", null, ["Contributing atoms"]));
    const t = el("table");
    r.fragility.atoms.forEach((a) => {
      t.appendChild(
        el("tr", null, [el("td", null, [String(a.field)]), el("td", null, [String(a.value)])])
      );
    });
    content.appendChild(t);
  }

  if (r.triage_hypotheses && r.triage_hypotheses.length) {
    content.appendChild(el("h3", null, ["Triage hypotheses (UNTESTED)"]));
    content.appendChild(el("div", { class: "narrative" }, [r.triage_hypotheses.join(", ")]));
  }

  document.getElementById("detail-overlay").hidden = false;
}

function tableOf(pairs) {
  const t = el("table");
  pairs.forEach(([k, v]) => t.appendChild(el("tr", null, [el("td", null, [k]), el("td", null, [String(v)])])));
  return t;
}

document.getElementById("detail-close").onclick = () => {
  document.getElementById("detail-overlay").hidden = true;
};
document.getElementById("detail-overlay").addEventListener("click", (e) => {
  if (e.target.id === "detail-overlay") e.target.hidden = true;
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") document.getElementById("detail-overlay").hidden = true;
});
