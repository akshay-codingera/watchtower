/* atlas.js — reusable API client and shared helpers. Exposed on window.Watchtower. */
(function () {
  "use strict";

  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const CSRF = csrfMeta ? csrfMeta.getAttribute("content") : "";

  const HEADERS_JSON = { "Content-Type": "application/json", "X-CSRF-Token": CSRF };

  async function request(path, options) {
    options = options || {};
    const opts = {
      method: options.method || "GET",
      credentials: "same-origin",
      headers: Object.assign({ "Accept": "application/json" }, options.headers || {}),
    };
    if (options.body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.headers["X-CSRF-Token"] = CSRF;
      opts.body = JSON.stringify(options.body);
    }
    if (options.method && options.method !== "GET" && options.method !== "HEAD") {
      opts.headers["X-CSRF-Token"] = CSRF;
    }
    const resp = await fetch(path, opts);
    let payload = null;
    try { payload = await resp.json(); } catch (_e) { payload = null; }
    if (!resp.ok) {
      const err = new Error((payload && payload.error && payload.error.message) || resp.statusText);
      err.status = resp.status;
      err.code = payload && payload.error && payload.error.code;
      err.payload = payload;
      throw err;
    }
    if (payload && payload.success === false) {
      const err = new Error(payload.error && payload.error.message);
      err.code = payload.error && payload.error.code;
      throw err;
    }
    return payload ? payload.data : null;
  }

  function qs(params) {
    const parts = [];
    Object.keys(params || {}).forEach(function (k) {
      const v = params[k];
      if (v === undefined || v === null || v === "") return;
      parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
    });
    return parts.length ? "?" + parts.join("&") : "";
  }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === "class") node.className = attrs[k];
        else if (k === "text") node.textContent = attrs[k];
        else if (k.startsWith("data-")) node.setAttribute(k, attrs[k]);
        else if (k in node) node[k] = attrs[k];
        else node.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      if (c === null || c === undefined) return;
      if (typeof c === "string") node.appendChild(document.createTextNode(c));
      else node.appendChild(c);
    });
    return node;
  }

  function severityBadge(sev) {
    const label = (sev || "info").toString().toLowerCase();
    return el("span", { class: "sev " + label, text: label });
  }

  function formatTimestamp(value) {
    if (!value) return "";
    const d = new Date(value);
    if (isNaN(d.getTime())) return String(value);
    return d.toISOString().replace("T", " ").replace("Z", "");
  }

  function replaceRows(tbody, rows, renderRow, emptyLabel) {
    tbody.innerHTML = "";
    if (!rows || !rows.length) {
      const tr = el("tr", null, [el("td", { colspan: tbody.parentNode.querySelectorAll("th").length, class: "muted", text: emptyLabel || "No results" })]);
      tbody.appendChild(tr);
      return;
    }
    rows.forEach(function (row) { tbody.appendChild(renderRow(row)); });
  }

  window.Watchtower = window.Watchtower || {};
  window.Watchtower.api = {
    logs: function (params) { return request("/api/logs" + qs(params)); },
    log: function (id) { return request("/api/logs/" + encodeURIComponent(id)); },
    exportLogs: function (params) { return request("/api/logs/export" + qs(params)); },
    stats: function (params) { return request("/api/stats" + qs(params)); },
    devices: function (params) { return request("/api/devices" + qs(params)); },
    device: function (id) { return request("/api/devices/" + encodeURIComponent(id)); },
    deviceStatus: function (id) { return request("/api/devices/" + encodeURIComponent(id) + "/status"); },
    registerDevice: function (body) { return request("/api/devices", { method: "POST", body: body }); },
    removeDevice: function (id) { return request("/api/devices/" + encodeURIComponent(id), { method: "DELETE" }); },
    topology: function () { return request("/api/topology"); },
    incidents: function (params) { return request("/api/incidents" + qs(params)); },
    ackIncident: function (id, note) { return request("/api/incidents/" + encodeURIComponent(id) + "/ack", { method: "POST", body: { note: note } }); },
    resolveIncident: function (id, note) { return request("/api/incidents/" + encodeURIComponent(id) + "/resolve", { method: "POST", body: { note: note } }); },
    settings: function () { return request("/api/settings"); },
    webhooks: function () { return request("/api/webhooks"); },
    saveWebhook: function (id, body) {
      return id
        ? request("/api/webhooks/" + encodeURIComponent(id), { method: "PUT", body: body })
        : request("/api/webhooks", { method: "POST", body: body });
    },
    deleteWebhook: function (id) { return request("/api/webhooks/" + encodeURIComponent(id), { method: "DELETE" }); },
    health: function () { return request("/health"); },
    audit: function (params) { return request("/api/audit" + qs(params)); }
  };

  window.Watchtower.dom = { el: el, severityBadge: severityBadge, formatTimestamp: formatTimestamp, replaceRows: replaceRows };
  window.Watchtower.qs = qs;
})();
