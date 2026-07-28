/* pulse.js — SSE client with automatic reconnect and per-page live updates. */
(function () {
  "use strict";

  const state = {
    source: null,
    listeners: { log: [], alert: [], stats: [], heartbeat: [], disconnect: [] },
    lastEventId: null,
    reconnectMs: 1000,
    maxReconnectMs: 15000,
    indicator: document.getElementById("live-pulse"),
    stalled: null
  };

  function setIndicator(cls) {
    if (!state.indicator) return;
    state.indicator.classList.remove("online", "stalled", "offline");
    if (cls) state.indicator.classList.add(cls);
    state.indicator.setAttribute("title", cls || "");
  }

  function fireStalledTimer() {
    if (state.stalled) window.clearTimeout(state.stalled);
    state.stalled = window.setTimeout(function () { setIndicator("stalled"); }, 25000);
  }

  function connect() {
    if (!("EventSource" in window)) return;
    try {
      state.source = new EventSource("/stream");
    } catch (_e) {
      setIndicator("offline");
      scheduleReconnect();
      return;
    }
    state.source.onopen = function () {
      setIndicator("online");
      state.reconnectMs = 1000;
      fireStalledTimer();
    };
    state.source.onerror = function () {
      setIndicator("offline");
      if (state.source) { try { state.source.close(); } catch (_e) {} state.source = null; }
      scheduleReconnect();
    };
    ["log", "alert", "stats", "heartbeat", "disconnect"].forEach(function (kind) {
      state.source.addEventListener(kind, function (evt) {
        state.lastEventId = evt.lastEventId || state.lastEventId;
        fireStalledTimer();
        let data = {};
        try { data = evt.data ? JSON.parse(evt.data) : {}; } catch (_e) { data = { raw: evt.data }; }
        (state.listeners[kind] || []).forEach(function (fn) {
          try { fn(data, evt); } catch (err) { console.warn("pulse listener error", err); }
        });
      });
    });
  }

  function scheduleReconnect() {
    window.setTimeout(function () {
      state.reconnectMs = Math.min(state.reconnectMs * 2, state.maxReconnectMs);
      connect();
    }, state.reconnectMs);
  }

  function on(kind, fn) {
    if (!state.listeners[kind]) state.listeners[kind] = [];
    state.listeners[kind].push(fn);
    return function off() {
      state.listeners[kind] = state.listeners[kind].filter(function (x) { return x !== fn; });
    };
  }

  window.addEventListener("beforeunload", function () {
    if (state.source) { try { state.source.close(); } catch (_e) {} }
  });

  window.Watchtower = window.Watchtower || {};
  window.Watchtower.pulse = { on: on, connect: connect };

  // Live-feed page mount
  const livefeed = (function () {
    let paused = false;
    let severityFilter = "";
    let unsubscribe = null;

    function mount() {
      const body = document.getElementById("livefeed-body");
      if (!body) return;
      const sev = document.getElementById("livefeed-severity");
      const pause = document.getElementById("livefeed-pause");
      if (sev) sev.addEventListener("change", function () { severityFilter = sev.value; });
      if (pause) pause.addEventListener("change", function () { paused = pause.checked; });

      unsubscribe = on("log", function (record) {
        if (paused) return;
        if (severityFilter && String(record.severity).toLowerCase() !== severityFilter) return;
        const dom = window.Watchtower.dom;
        const row = dom.el("tr", null, [
          dom.el("td", { text: dom.formatTimestamp(record.timestamp) }),
          dom.el("td", { text: record.source_ip || "" }),
          dom.el("td", { text: record.hostname || "" }),
          dom.el("td", null, [dom.severityBadge(record.severity)]),
          dom.el("td", { text: record.message || "" })
        ]);
        body.insertBefore(row, body.firstChild);
        while (body.childElementCount > 500) body.removeChild(body.lastChild);
      });
    }

    function unmount() { if (unsubscribe) unsubscribe(); unsubscribe = null; }
    return { mount: mount, unmount: unmount };
  })();

  window.Watchtower.livefeed = livefeed;

  // Auto-connect if we are on an authenticated page (indicator exists).
  if (state.indicator) connect();
})();
