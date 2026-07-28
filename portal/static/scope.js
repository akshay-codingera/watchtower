/* scope.js — page controllers using Chart.js and reusing the atlas API client. */
(function () {
  "use strict";

  const W = window.Watchtower = window.Watchtower || {};
  const api = W.api;
  const dom = W.dom;
  const pulse = W.pulse;

  // ---------------------------------------------------------------- Chronicle
  const chronicle = (function () {
    let offset = 0;
    const limit = 100;
    let total = 0;
    let lastFilters = {};

    function currentFilters() {
      const form = document.getElementById("chronicle-form");
      if (!form) return {};
      const data = new FormData(form);
      const out = {};
      data.forEach(function (v, k) { if (v) out[k] = v; });
      return out;
    }

    function render(rows) {
      const body = document.getElementById("chronicle-body");
      dom.replaceRows(body, rows, function (r) {
        return dom.el("tr", null, [
          dom.el("td", { text: dom.formatTimestamp(r.timestamp) }),
          dom.el("td", { text: r.source_ip || "" }),
          dom.el("td", { text: r.hostname || "" }),
          dom.el("td", null, [dom.severityBadge(r.severity)]),
          dom.el("td", { text: r.message || "" })
        ]);
      }, "No matching logs.");
      const info = document.getElementById("chronicle-page-info");
      if (info) info.textContent = (offset + 1) + "–" + (offset + rows.length) + " of " + total;
    }

    async function search() {
      const params = Object.assign({}, lastFilters, { limit: limit, offset: offset });
      const data = await api.logs(params);
      total = data.total || 0;
      render(data.items || []);
    }

    function mount() {
      const form = document.getElementById("chronicle-form");
      if (!form) return;
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        offset = 0;
        lastFilters = currentFilters();
        search().catch(showError);
      });
      document.querySelectorAll("[data-page-action]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          const action = btn.getAttribute("data-page-action");
          if (action === "next" && offset + limit < total) offset += limit;
          if (action === "prev" && offset >= limit) offset -= limit;
          search().catch(showError);
        });
      });
    }

    return { mount: mount };
  })();
  W.chronicle = chronicle;

  // ---------------------------------------------------------------- Registry
  const registry = (function () {
    async function refresh() {
      const params = {
        type: valueOf("registry-type"),
        q: valueOf("registry-q")
      };
      const data = await api.devices(params);
      const body = document.getElementById("registry-body");
      dom.replaceRows(body, data.items || [], function (d) {
        const removeBtn = dom.el("button", { class: "btn-ghost", text: "Remove", "data-testid": "registry-remove-" + d.id });
        removeBtn.addEventListener("click", function () {
          if (!window.confirm("Remove device " + (d.hostname || d.ip) + "?")) return;
          api.removeDevice(d.id).then(refresh).catch(showError);
        });
        return dom.el("tr", null, [
          dom.el("td", { text: d.ip || "" }),
          dom.el("td", { text: d.hostname || "" }),
          dom.el("td", { text: d.mac || "" }),
          dom.el("td", { text: d.classification || "" }),
          dom.el("td", null, [statusBadge(d.status)]),
          dom.el("td", { text: dom.formatTimestamp(d.last_seen) }),
          dom.el("td", null, [removeBtn])
        ]);
      }, "No devices registered.");
    }

    function statusBadge(status) {
      const s = String(status || "unknown").toLowerCase();
      let cls = "";
      if (s === "up" || s === "online") cls = "ok";
      else if (s === "warn") cls = "warn";
      else if (s === "down" || s === "offline") cls = "err";
      return dom.el("span", { class: "badge " + cls, text: s });
    }

    function mount() {
      const body = document.getElementById("registry-body");
      if (!body) return;
      ["registry-type", "registry-q"].forEach(function (id) {
        const el = document.getElementById(id);
        if (el) el.addEventListener("input", debounce(refresh, 250));
      });
      const dialog = document.getElementById("registry-dialog");
      const addBtn = document.getElementById("registry-add");
      if (addBtn && dialog) {
        addBtn.addEventListener("click", function () { dialog.showModal(); });
        dialog.addEventListener("close", function () {
          if (dialog.returnValue !== "submit") return;
          const form = dialog.querySelector("form");
          const body = new FormData(form);
          const payload = { ip: body.get("ip"), hostname: body.get("hostname"), classification: body.get("classification") };
          api.registerDevice(payload).then(function () { form.reset(); refresh(); }).catch(showError);
        });
      }
      refresh().catch(showError);
    }
    return { mount: mount };
  })();
  W.registry = registry;

  // ---------------------------------------------------------------- Watchdog
  const watchdog = (function () {
    let state = "open";
    async function refresh() {
      const data = await api.incidents({ state: state });
      const body = document.getElementById("watchdog-body");
      dom.replaceRows(body, data.items || [], function (inc) {
        const actions = dom.el("td", null, []);
        if (state !== "resolved") {
          const ackBtn = dom.el("button", { class: "btn-ghost", text: "Ack", "data-testid": "watchdog-ack-" + inc.id });
          ackBtn.addEventListener("click", function () { api.ackIncident(inc.id, null).then(refresh).catch(showError); });
          actions.appendChild(ackBtn);
          const resBtn = dom.el("button", { class: "btn-primary", text: "Resolve", "data-testid": "watchdog-resolve-" + inc.id });
          resBtn.addEventListener("click", function () { api.resolveIncident(inc.id, null).then(refresh).catch(showError); });
          actions.appendChild(resBtn);
        }
        return dom.el("tr", null, [
          dom.el("td", { text: dom.formatTimestamp(inc.opened_at) }),
          dom.el("td", null, [dom.severityBadge(inc.severity)]),
          dom.el("td", { text: inc.rule || "" }),
          dom.el("td", { text: inc.source || "" }),
          dom.el("td", { text: inc.state || "" }),
          actions
        ]);
      }, "No incidents in this state.");
    }
    function mount() {
      const panel = document.querySelector('[data-testid="watchdog-panel"]');
      if (!panel) return;
      panel.querySelectorAll(".tab").forEach(function (btn) {
        btn.addEventListener("click", function () {
          panel.querySelectorAll(".tab").forEach(function (b) { b.classList.remove("active"); });
          btn.classList.add("active");
          state = btn.getAttribute("data-tab") || "open";
          refresh().catch(showError);
        });
      });
      pulse.on("alert", function () { refresh().catch(function () {}); });
      refresh().catch(showError);
    }
    return { mount: mount };
  })();
  W.watchdog = watchdog;

  // ---------------------------------------------------------------- Observatory
  const observatory = (function () {
    const charts = {};
    function ensureChart(id, config) {
      if (!window.Chart) return null;
      const canvas = document.getElementById(id);
      if (!canvas) return null;
      if (charts[id]) return charts[id];
      charts[id] = new window.Chart(canvas.getContext("2d"), config);
      return charts[id];
    }
    function baseLine(label, color) {
      return {
        type: "line",
        data: { labels: [], datasets: [{ label: label, data: [], borderColor: color, backgroundColor: color + "22", tension: 0.3, fill: true, pointRadius: 0 }] },
        options: { responsive: true, animation: false, scales: { x: { display: false }, y: { beginAtZero: true, grid: { color: "#1e2836" }, ticks: { color: "#8a9bb0" } } }, plugins: { legend: { display: false } } }
      };
    }
    function baseDoughnut() {
      return {
        type: "doughnut",
        data: { labels: [], datasets: [{ data: [], backgroundColor: ["#ff3d68", "#ff6a6a", "#f2c34e", "#6bb8ff", "#7cf3c7", "#8b9aae"] }] },
        options: { responsive: true, plugins: { legend: { position: "bottom", labels: { color: "#b6c2d1" } } } }
      };
    }
    function baseBar() {
      return {
        type: "bar",
        data: { labels: [], datasets: [{ data: [], backgroundColor: "#7cf3c7" }] },
        options: { responsive: true, animation: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: "#1e2836" }, ticks: { color: "#8a9bb0" } }, x: { ticks: { color: "#8a9bb0" } } } }
      };
    }

    function updateKpis(counters) {
      setText("kpi-lps", counters.logs_per_second);
      setText("kpi-queue", counters.queue_depth);
      setText("kpi-parse-fail", counters.parse_failures);
      setText("kpi-devices", counters.devices_online);
    }

    function updateCharts(agg) {
      const throughput = ensureChart("chart-throughput", baseLine("logs/s", "#7cf3c7"));
      if (throughput && Array.isArray(agg.throughput)) {
        throughput.data.labels = agg.throughput.map(function (p) { return p.t; });
        throughput.data.datasets[0].data = agg.throughput.map(function (p) { return p.v; });
        throughput.update("none");
      }
      const sev = ensureChart("chart-severity", baseDoughnut());
      if (sev && agg.severity) {
        sev.data.labels = Object.keys(agg.severity);
        sev.data.datasets[0].data = Object.values(agg.severity);
        sev.update();
      }
      const sources = ensureChart("chart-sources", baseBar());
      if (sources && Array.isArray(agg.top_sources)) {
        sources.data.labels = agg.top_sources.map(function (p) { return p.source; });
        sources.data.datasets[0].data = agg.top_sources.map(function (p) { return p.count; });
        sources.update();
      }
      const inc = ensureChart("chart-incidents", baseLine("incidents", "#ff6a6a"));
      if (inc && Array.isArray(agg.incidents_timeline)) {
        inc.data.labels = agg.incidents_timeline.map(function (p) { return p.t; });
        inc.data.datasets[0].data = agg.incidents_timeline.map(function (p) { return p.v; });
        inc.update("none");
      }
    }

    async function refresh() {
      const data = await api.stats({ window: 300 });
      updateKpis(data.counters || {});
      updateCharts(data.aggregates || {});
    }
    function mount() {
      if (!document.querySelector('[data-testid="observatory-panel"]')) return;
      refresh().catch(showError);
      pulse.on("stats", function (snap) { updateKpis(snap || {}); });
      window.setInterval(function () { refresh().catch(function () {}); }, 15000);
    }
    return { mount: mount };
  })();
  W.observatory = observatory;

  // ---------------------------------------------------------------- Manifest
  const manifest = (function () {
    function mount() {
      const form = document.getElementById("manifest-form");
      if (!form) return;
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        const data = new FormData(form);
        const params = {};
        data.forEach(function (v, k) { if (v && k !== "csrf_token") params[k] = v; });
        api.exportLogs(params).then(function (res) {
          const status = document.getElementById("manifest-status");
          status.hidden = false;
          status.className = "alert alert-ok";
          status.textContent = "Export queued: " + JSON.stringify(res.job || res);
        }).catch(showError);
      });
    }
    return { mount: mount };
  })();
  W.manifest = manifest;

  // ---------------------------------------------------------------- Audit
  const audit = (function () {
    async function search() {
      const params = {
        actor: valueOf("audit-actor"),
        action: valueOf("audit-action"),
        since: valueOf("audit-since"),
        until: valueOf("audit-until")
      };
      let data;
      try { data = await api.audit(params); }
      catch (err) { if (err.status === 404) { data = { items: [] }; } else { throw err; } }
      const body = document.getElementById("audit-body");
      dom.replaceRows(body, data.items || [], function (row) {
        return dom.el("tr", null, [
          dom.el("td", { text: dom.formatTimestamp(row.timestamp) }),
          dom.el("td", { text: row.actor || "" }),
          dom.el("td", { text: row.action || "" }),
          dom.el("td", { text: row.target || "" }),
          dom.el("td", { text: row.metadata ? JSON.stringify(row.metadata) : "" })
        ]);
      }, "No audit records.");
    }
    function mount() {
      const btn = document.getElementById("audit-search");
      if (!btn) return;
      btn.addEventListener("click", function () { search().catch(showError); });
      search().catch(function () {});
    }
    return { mount: mount };
  })();
  W.audit = audit;

  // ---------------------------------------------------------------- Health
  const health = (function () {
    async function refresh() {
      const data = await api.health();
      const badge = document.getElementById("health-badge");
      const stats = document.getElementById("health-stats");
      const status = (data && data.status) || "unknown";
      badge.textContent = status;
      badge.className = "badge " + (status === "ok" ? "ok" : status === "degraded" ? "warn" : "err");
      stats.innerHTML = "";
      const telemetry = (data && data.telemetry) || {};
      Object.keys(telemetry).forEach(function (k) {
        stats.appendChild(dom.el("dt", { text: k }));
        stats.appendChild(dom.el("dd", { text: String(telemetry[k]) }));
      });
    }
    function mount() {
      if (!document.getElementById("health-badge")) return;
      refresh().catch(showError);
      window.setInterval(function () { refresh().catch(function () {}); }, 10000);
    }
    return { mount: mount };
  })();
  W.health = health;

  // ---------------------------------------------------------------- Forge (settings)
  const forge = (function () {
    async function loadSettings() {
      const data = await api.settings();
      const container = document.getElementById("forge-cards");
      container.innerHTML = "";
      Object.keys(data || {}).forEach(function (section) {
        const card = dom.el("article", { class: "card" }, [dom.el("h3", { text: section })]);
        const dl = dom.el("dl", { class: "stat-grid" });
        Object.keys(data[section]).forEach(function (opt) {
          dl.appendChild(dom.el("dt", { text: opt }));
          dl.appendChild(dom.el("dd", { text: String(data[section][opt]) }));
        });
        card.appendChild(dl);
        container.appendChild(card);
      });
    }
    async function loadWebhooks() {
      const data = await api.webhooks();
      const body = document.getElementById("forge-webhooks");
      dom.replaceRows(body, data.items || [], function (w) {
        const del = dom.el("button", { class: "btn-ghost", text: "Delete", "data-testid": "forge-delete-" + w.id });
        del.addEventListener("click", function () {
          if (!window.confirm("Delete webhook " + (w.name || w.url) + "?")) return;
          api.deleteWebhook(w.id).then(loadWebhooks).catch(showError);
        });
        return dom.el("tr", null, [
          dom.el("td", { text: w.name || "" }),
          dom.el("td", { text: w.url }),
          dom.el("td", { text: (w.events || []).join(", ") }),
          dom.el("td", null, [del])
        ]);
      }, "No webhooks configured.");
    }
    function mount() {
      if (!document.getElementById("forge-cards")) return;
      loadSettings().catch(showError);
      loadWebhooks().catch(showError);
      const addBtn = document.getElementById("forge-add-webhook");
      const dialog = document.getElementById("webhook-dialog");
      if (addBtn && dialog) {
        addBtn.addEventListener("click", function () {
          dialog.querySelector("form").reset();
          dialog.showModal();
        });
        dialog.addEventListener("close", function () {
          if (dialog.returnValue !== "submit") return;
          const form = dialog.querySelector("form");
          const data = new FormData(form);
          const payload = {
            name: data.get("name"),
            url: data.get("url"),
            events: String(data.get("events") || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean)
          };
          const id = data.get("id");
          api.saveWebhook(id || null, payload).then(loadWebhooks).catch(showError);
        });
      }
    }
    return { mount: mount };
  })();
  W.forge = forge;

  // -------------------------------------------------------------- utilities
  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value === undefined || value === null ? "—" : String(value);
  }
  function valueOf(id) { const el = document.getElementById(id); return el ? el.value : ""; }
  function debounce(fn, ms) {
    let t; return function () {
      const args = arguments; const ctx = this;
      window.clearTimeout(t);
      t = window.setTimeout(function () { fn.apply(ctx, args); }, ms);
    };
  }
  function showError(err) {
    if (!err) return;
    const msg = err.message || "Request failed";
    const banner = document.createElement("div");
    banner.className = "alert alert-error";
    banner.setAttribute("role", "alert");
    banner.setAttribute("data-testid", "toast-error");
    banner.textContent = msg;
    banner.style.position = "fixed";
    banner.style.right = "24px";
    banner.style.bottom = "24px";
    banner.style.zIndex = "50";
    document.body.appendChild(banner);
    window.setTimeout(function () { banner.remove(); }, 5000);
  }
  W.showError = showError;
})();
