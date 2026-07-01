// flowguard.js — módulo do dashboard FlowGuard (padrão IIFE)
(function () {
  "use strict";

  var REFRESH_MS = 5000;
  var STATUS_ENDPOINT = "/cgi-bin/flowguard-status.sh";
  var ATTACKS_ENDPOINT = "/cgi-bin/flowguard-attacks.sh";
  var FLOWS_ENDPOINT = "/cgi-bin/flowguard-flows.sh";
  var RULES_ENDPOINT = "/cgi-bin/flowguard-rules.sh";
  var CFG_ENDPOINT = "/cgi-bin/flowguard-cfg.sh";
  var AI_ENDPOINT = "/cgi-bin/flowguard-ai.sh";
  var HISTORY_ENDPOINT = "/cgi-bin/flowguard-history.sh";
  var LOGIN_ENDPOINT = "/cgi-bin/flowguard-login.sh";
  var LOGOUT_ENDPOINT = "/cgi-bin/flowguard-logout.sh";
  var CG_STATUS_ENDPOINT = "/cgi-bin/clientguard-status.sh";
  var CG_SUSPICIOUS_ENDPOINT = "/cgi-bin/clientguard-suspicious.sh";
  var CG_CFG_ENDPOINT = "/cgi-bin/clientguard-cfg.sh";

  var PROTO_NAMES = { 6: "TCP", 17: "UDP", 1: "ICMP" };

  var state = {
    topPrefixes: [],
    flows: [],
    attacks: [],
    attacksView: "active",
    attacksWindow: "24h",
    sort: {
      topPrefixes: { key: "bps", dir: "desc" },
      flows: { key: "bps", dir: "desc" },
    },
    filter: {
      topPrefixes: "",
      flows: "",
      attacksSeverity: "",
      attacksPrefix: "",
    },
    page: {
      topPrefixes: 1,
      flows: 1,
      attacks: 1,
    },
    chart: {
      window: "6h",
      prefix: null,
      prefixesLoaded: false,
    },
    cgSuspiciousView: "open",
    cgSuspicious: [],
  };

  function getToken() {
    return window.localStorage.getItem("portal_token") || "";
  }

  function setToken(token) {
    window.localStorage.setItem("portal_token", token);
  }

  function clearToken() {
    window.localStorage.removeItem("portal_token");
  }

  function showApp() {
    var login = document.getElementById("fg-login-screen");
    var app = document.getElementById("fg-app");
    if (login) login.style.display = "none";
    if (app) app.style.display = "";
  }

  function showLogin(message) {
    clearToken();
    var login = document.getElementById("fg-login-screen");
    var app = document.getElementById("fg-app");
    if (app) app.style.display = "none";
    if (login) login.style.display = "";
    var status = document.getElementById("fg-login-status");
    if (status) status.textContent = message || "";
  }

  function fmtBps(bps) {
    if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " Gbps";
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " Mbps";
    if (bps >= 1e3) return (bps / 1e3).toFixed(0) + " Kbps";
    return bps + " bps";
  }

  function fmtDateTime(ts) {
    if (!ts) return "-";
    var d = new Date(ts * 1000);
    return pad2(d.getDate()) + "/" + pad2(d.getMonth() + 1) + " " + pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
  }

  function fmtAttackDuration(a) {
    var end = a.ts_end || Math.floor(Date.now() / 1000);
    return fmtUptime(end - a.ts_start);
  }

  function fmtUptime(s) {
    s = Math.floor(s || 0);
    var h = Math.floor(s / 3600);
    var m = Math.floor((s % 3600) / 60);
    if (h > 0) return h + "h" + m + "m";
    return m + "m" + (s % 60) + "s";
  }

  function protoName(proto) {
    return PROTO_NAMES[proto] || String(proto);
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return n.toFixed(1) + " " + units[i];
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function getJson(url) {
    var token = encodeURIComponent(getToken());
    var sep = url.indexOf("?") === -1 ? "?" : "&";
    return fetch(url + sep + "token=" + token, { credentials: "same-origin" }).then(function (resp) {
      if (resp.status === 401) {
        showLogin("sessão expirada, faça login novamente.");
        throw new Error("unauthorized");
      }
      return resp.json();
    });
  }

  function postJson(url, body) {
    var token = encodeURIComponent(getToken());
    return fetch(url + "?token=" + token, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then(function (resp) {
      if (resp.status === 401) {
        showLogin("sessão expirada, faça login novamente.");
        throw new Error("unauthorized");
      }
      return resp.json();
    });
  }

  function showError(el, message) {
    if (el) el.innerHTML = '<p class="fg-error">FlowGuard: ' + escapeHtml(message) + "</p>";
  }

  // --- toasts -----------------------------------------------------------

  function showToast(message, type) {
    var container = document.getElementById("fg-toast-container");
    if (!container) return;
    var el = document.createElement("div");
    el.className = "fg-toast fg-toast-" + (type || "info");
    el.textContent = message;
    container.appendChild(el);
    setTimeout(function () {
      el.classList.add("fg-toast-out");
      setTimeout(function () { el.remove(); }, 300);
    }, 4000);
  }

  // --- sort/filter helpers ------------------------------------------------

  function filterRows(rows, text, fields) {
    if (!text) return rows;
    var needle = text.toLowerCase();
    return rows.filter(function (r) {
      return fields.some(function (f) { return String(r[f] || "").toLowerCase().indexOf(needle) !== -1; });
    });
  }

  function sortRows(rows, sort) {
    var copy = rows.slice();
    copy.sort(function (a, b) {
      var av = a[sort.key];
      var bv = b[sort.key];
      if (av < bv) return sort.dir === "asc" ? -1 : 1;
      if (av > bv) return sort.dir === "asc" ? 1 : -1;
      return 0;
    });
    return copy;
  }

  function sortableTh(label, key, sort) {
    var cls = sort.key === key ? "fg-sorted" + (sort.dir === "asc" ? " fg-sorted-asc" : "") : "";
    return '<th data-sort-key="' + key + '" class="' + cls + '">' + escapeHtml(label) + "</th>";
  }

  // --- paginação genérica (client-side, sobre a lista já filtrada/ordenada) --

  var PAGE_SIZE = 15;

  function paginate(rows, pageKey) {
    var totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    var page = Math.min(Math.max(1, state.page[pageKey] || 1), totalPages);
    state.page[pageKey] = page;
    var start = (page - 1) * PAGE_SIZE;
    return { pageRows: rows.slice(start, start + PAGE_SIZE), page: page, totalPages: totalPages, total: rows.length };
  }

  function paginationHtml(pageKey, page, totalPages, total) {
    if (total <= PAGE_SIZE) return "";
    return (
      '<div class="fg-pagination" data-page-key="' + pageKey + '">' +
      '<button class="fg-btn" data-page-action="prev" ' + (page <= 1 ? "disabled" : "") + ">« Anterior</button>" +
      "<span>página " + page + " de " + totalPages + " — " + total + " itens</span>" +
      '<button class="fg-btn" data-page-action="next" ' + (page >= totalPages ? "disabled" : "") + ">Próxima »</button>" +
      "</div>"
    );
  }

  function initPaginationHandlers() {
    document.addEventListener("click", function (ev) {
      var btn = ev.target.closest("button[data-page-action]");
      if (!btn) return;
      var wrap = btn.closest("[data-page-key]");
      if (!wrap) return;
      var key = wrap.getAttribute("data-page-key");
      var delta = btn.getAttribute("data-page-action") === "next" ? 1 : -1;
      state.page[key] = (state.page[key] || 1) + delta;
      if (key === "topPrefixes") renderTopPrefixesFiltered();
      if (key === "flows") renderFlowsFiltered();
      if (key === "attacks") renderAttacksFiltered();
    });
  }

  // --- menus de ação (dropdown compacto) -------------------------------------

  function initActionMenus() {
    document.addEventListener("click", function (ev) {
      var toggle = ev.target.closest("[data-menu-toggle]");
      document.querySelectorAll(".fg-menu-list").forEach(function (list) {
        if (!toggle || list !== toggle.nextElementSibling) list.hidden = true;
      });
      if (toggle) {
        var list = toggle.nextElementSibling;
        if (list) list.hidden = !list.hidden;
        ev.stopPropagation();
      }
    });
  }

  // --- tabs ---------------------------------------------------------------

  function initTabs() {
    var tabsEl = document.getElementById("fg-tabs");
    if (!tabsEl) return;
    tabsEl.addEventListener("click", function (ev) {
      var btn = ev.target.closest(".fg-tab-btn");
      if (!btn) return;
      var tab = btn.getAttribute("data-tab");
      document.querySelectorAll(".fg-tab-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
      document.querySelectorAll(".fg-tab-panel").forEach(function (p) { p.classList.toggle("active", p.getAttribute("data-tab") === tab); });
      if (tab === "charts") loadCharts();
      if (tab === "clientguard") loadClientGuard();
    });
  }

  function updateAttacksBadge(count) {
    var badge = document.getElementById("fg-attacks-badge");
    if (!badge) return;
    if (count > 0) {
      badge.style.display = "inline-block";
      badge.textContent = count;
    } else {
      badge.style.display = "none";
    }
  }

  // --- KPIs ---------------------------------------------------------------

  function kpiCard(label, valueHtml, sub) {
    return (
      '<div class="fg-card"><div class="fg-kpi-label">' + escapeHtml(label) + '</div>' +
      '<div class="fg-kpi-value">' + valueHtml + '</div>' +
      '<div class="fg-kpi-sub">' + escapeHtml(sub || "") + '</div></div>'
    );
  }

  function renderKpis(data) {
    var el = document.getElementById("fg-kpis");
    if (!el) return;

    if (!data.ok) {
      el.innerHTML = kpiCard("Daemon", '<span class="fg-dot fg-dot-down"></span>indisponível', data.error || "");
      updateAttacksBadge(0);
      return;
    }

    var s = data.stats;
    var daemon = data.daemon || {};
    var daemonHtml = daemon.alive
      ? '<span class="fg-dot fg-dot-up"></span>ativo'
      : '<span class="fg-dot fg-dot-down"></span>indisponível';
    var daemonSub = daemon.alive ? "uptime " + fmtUptime(daemon.uptime_s) + " · pid " + daemon.pid : "socket não respondeu";

    el.innerHTML =
      kpiCard("Tráfego", fmtBps(s.bps), s.flows + " flows/s") +
      kpiCard("Pacotes/s", Number(s.pps).toLocaleString("pt-BR"), "") +
      kpiCard("Ataques Ativos", s.active_attacks, s.active_attacks > 0 ? "requer atenção" : "tudo normal") +
      kpiCard("Regras FlowSpec", s.active_rules, "") +
      kpiCard("Daemon", daemonHtml, daemonSub);

    updateAttacksBadge(s.active_attacks);
  }

  // --- sparklines -----------------------------------------------------------

  function renderSparklines(series) {
    var el = document.getElementById("flowguard-sparklines");
    if (!el || !series || !series.length) return;

    var protos = [
      { key: "tcp", label: "TCP", color: "#58a6ff" },
      { key: "udp", label: "UDP", color: "#3fb950" },
      { key: "icmp", label: "ICMP", color: "#d29922" },
      { key: "other", label: "OTHER", color: "#8b949e" },
    ];

    var max = 1;
    series.forEach(function (point) {
      protos.forEach(function (p) {
        if (point[p.key] > max) max = point[p.key];
      });
    });

    var width = 220;
    var height = 36;
    var html = protos
      .map(function (p) {
        var points = series
          .map(function (point, i) {
            var x = (i / Math.max(series.length - 1, 1)) * width;
            var y = height - (point[p.key] / max) * height;
            return x.toFixed(1) + "," + y.toFixed(1);
          })
          .join(" ");
        var last = series[series.length - 1][p.key];
        return (
          '<div class="fg-spark"><span class="fg-spark-label" style="color:' + p.color + '">' + p.label + "</span>" +
          '<svg width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + " " + height + '">' +
          '<polyline points="' + points + '" fill="none" stroke="' + p.color + '" stroke-width="1.5" /></svg>' +
          '<span class="fg-spark-value">' + fmtBps(last) + "</span></div>"
        );
      })
      .join("");

    el.innerHTML = html;
  }

  // --- top prefixos (com busca/ordenação) ---------------------------------

  function renderTopPrefixesTable(rows) {
    var el = document.getElementById("flowguard-top-prefixes");
    if (!el) return;
    var p = paginate(rows, "topPrefixes");
    var bodyRows = p.pageRows
      .map(function (p) {
        return (
          "<tr><td>" + escapeHtml(p.dst_prefix) + "</td><td>" + escapeHtml(p.customer || "-") + "</td>" +
          "<td>" + fmtBps(p.bps) + "</td><td>" + p.pps + " pps</td></tr>"
        );
      })
      .join("");
    el.innerHTML =
      '<table data-table="topPrefixes"><thead><tr>' +
      sortableTh("Prefixo", "dst_prefix", state.sort.topPrefixes) +
      "<th>Cliente</th>" +
      sortableTh("Tráfego", "bps", state.sort.topPrefixes) +
      sortableTh("Pacotes", "pps", state.sort.topPrefixes) +
      "</tr></thead><tbody>" +
      (bodyRows || '<tr><td colspan="4">Sem dados.</td></tr>') +
      "</tbody></table>" +
      paginationHtml("topPrefixes", p.page, p.totalPages, p.total);
  }

  function renderTopPrefixesFiltered() {
    var rows = filterRows(state.topPrefixes, state.filter.topPrefixes, ["dst_prefix", "customer"]);
    rows = sortRows(rows, state.sort.topPrefixes);
    renderTopPrefixesTable(rows);
  }

  // --- ataques --------------------------------------------------------------

  function renderAttacks(attacks) {
    var el = document.getElementById("flowguard-attacks");
    if (!el) return;

    if (!attacks.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum ataque encontrado para o filtro atual.</p>';
      return;
    }

    var p = paginate(attacks, "attacks");
    var rows = p.pageRows
      .map(function (a) {
        var sevClass = "fg-sev-" + a.severity;
        var suggestion = a.suggested_mitigation;
        var suggestionMenuItem = suggestion
          ? '<span class="fg-menu-hint">' + escapeHtml(suggestion.label) + "</span>" +
            '<button data-action="apply_suggestion">Aplicar sugestão</button>'
          : "";
        var targetHtml = a.target_host
          ? escapeHtml(a.target_host) + "/32" + '<br><span class="fg-kpi-sub">' + escapeHtml(a.dst_prefix) + "</span>"
          : escapeHtml(a.dst_prefix);
        return (
          '<tr data-attack-id="' + a.id + '" data-prefix="' + escapeHtml(a.dst_prefix) + '">' +
          "<td>" + fmtDateTime(a.ts_start) + "</td>" +
          "<td>" + fmtAttackDuration(a) + "</td>" +
          '<td class="fg-wrap-cell">' + targetHtml + "</td>" +
          "<td>" + escapeHtml(a.customer || "-") + "</td>" +
          "<td>" + escapeHtml(a.attack_type) + "</td>" +
          "<td class=\"" + sevClass + "\">" + escapeHtml(a.severity) + "</td>" +
          "<td>" + fmtBps(a.bps_peak || 0) + "</td>" +
          "<td>" + (a.pps_peak || 0).toLocaleString("pt-BR") + " pps</td>" +
          "<td>" + (a.mitigated ? "sim" : "não") + "</td>" +
          '<td><div class="fg-menu">' +
          '<button class="fg-btn" data-menu-toggle>Ações ▾</button>' +
          '<div class="fg-menu-list" hidden>' +
          '<button data-action="detail">Detalhes</button>' +
          '<button data-action="analyze">Detalhes IA</button>' +
          '<button data-action="mitigate">Mitigar</button>' +
          '<button data-action="release">Liberar</button>' +
          suggestionMenuItem +
          "</div></div></td></tr>"
        );
      })
      .join("");

    el.innerHTML =
      "<table><thead><tr><th>Início</th><th>Duração</th><th>Alvo</th><th>Cliente</th><th>Tipo</th><th>Severidade</th>" +
      "<th>Pico (bps)</th><th>Pico (pps)</th><th>Mitigado</th><th>Ações</th></tr></thead><tbody>" +
      rows +
      "</tbody></table>" +
      paginationHtml("attacks", p.page, p.totalPages, p.total);
  }

  function renderAttacksFiltered() {
    var rows = state.attacks;
    if (state.filter.attacksSeverity) {
      rows = rows.filter(function (a) { return a.severity === state.filter.attacksSeverity; });
    }
    rows = filterRows(rows, state.filter.attacksPrefix, ["dst_prefix", "customer"]);
    renderAttacks(rows);
  }

  function renderAttackDetail(prefix, resp) {
    var el = document.getElementById("flowguard-attack-detail");
    if (!el) return;
    if (!resp.ok) {
      el.innerHTML = '<p class="fg-error">Detalhes (' + escapeHtml(prefix) + "): " + escapeHtml(resp.error) + "</p>";
      el.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    var byPort = resp.by_port || [];
    var topSources = resp.top_sources || [];
    var topHosts = resp.top_hosts || [];
    var summary = resp.summary || {};
    var series = resp.timeseries || [];
    var portRows = byPort.length
      ? byPort.map(function (p) {
          return "<tr><td>" + protoName(p.protocol) + "</td><td>" + p.dst_port + "</td><td>" + fmtBps(p.bps) + "</td><td>" +
            p.pps + " pps</td><td>" + fmtBytes(p.total_bytes) + "</td><td>" + (p.total_packets || 0).toLocaleString("pt-BR") +
            "</td><td>" + (p.avg_pkt_size || 0) + " B</td><td>" + (p.flow_count || 0).toLocaleString("pt-BR") + "</td></tr>";
        }).join("")
      : '<tr><td colspan="8">sem dados de flow na janela do ataque</td></tr>';
    var hostItems = topHosts.length
      ? topHosts.map(function (h) { return "<li>" + escapeHtml(h.ip) + "/32 — " + h.occurrences + " ciclo(s)</li>"; }).join("")
      : "<li>sem host específico identificado na janela do ataque</li>";
    var sourceItems = topSources.length
      ? topSources.map(function (s) { return "<li>" + escapeHtml(s.ip) + " — " + s.occurrences + " ciclo(s)</li>"; }).join("")
      : "<li>sem IPs de origem registrados na janela do ataque</li>";
    var summaryLine =
      "Duração: " + fmtUptime(summary.duration_s) + "  |  Total: " + fmtBytes(summary.total_bytes) + ", " +
      (summary.total_packets || 0).toLocaleString("pt-BR") + " pacotes, " +
      (summary.total_flows || 0).toLocaleString("pt-BR") + " flows (" + (summary.cycles || 0) + " ciclos de agregação)";
    el.innerHTML =
      '<div class="fg-ai-panel"><div class="fg-panel-header"><h4>Detalhes — ' + escapeHtml(prefix) + "</h4>" +
      '<button class="fg-btn" data-action="close-detail">Fechar</button></div>' +
      '<p class="fg-kpi-sub">' + summaryLine + "</p>" +
      "<h5>Linha do tempo (bps recebido)</h5>" +
      '<canvas id="fg-attack-detail-chart" width="760" height="140"></canvas>' +
      "<h5>Host(s) atacado(s) (top " + topHosts.length + ")</h5>" +
      "<ul>" + hostItems + "</ul>" +
      "<h5>Tráfego por protocolo/porta</h5>" +
      "<table><thead><tr><th>Protocolo</th><th>Porta</th><th>bps</th><th>pps</th><th>Bytes totais</th>" +
      "<th>Pacotes totais</th><th>Tam. médio pkt</th><th>Flows</th></tr></thead><tbody>" + portRows + "</tbody></table>" +
      "<h5>IPs de origem observados (top " + topSources.length + ")</h5>" +
      "<ul>" + sourceItems + "</ul>" +
      '<p class="fg-kpi-sub">Ocorrências = em quantos ciclos de agregação o IP apareceu entre os top 10 daquele grupo — não é volume exato por IP. ' +
      "Bytes/pacotes totais são estimados a partir das taxas bps/pps de cada ciclo, não medidos diretamente.</p>" +
      "</div>";
    var canvas = document.getElementById("fg-attack-detail-chart");
    if (canvas) {
      drawLineChart(canvas, series, [{ key: "bps", color: "#58a6ff" }]);
    }
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderAiResult(prefix, resp) {
    var el = document.getElementById("flowguard-attack-detail");
    if (!el) return;
    if (!resp.ok) {
      el.innerHTML = '<p class="fg-error">Análise IA (' + escapeHtml(prefix) + "): " + escapeHtml(resp.error) + "</p>";
      el.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    el.innerHTML =
      '<div class="fg-ai-panel"><div class="fg-panel-header"><h4>Análise IA — ' + escapeHtml(prefix) + "</h4>" +
      '<button class="fg-btn" data-action="close-detail">Fechar</button></div>' +
      "<pre>" + escapeHtml(resp.analysis) + "</pre></div>";
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function onAttackDetailClick(ev) {
    var btn = ev.target.closest("button[data-action='close-detail']");
    if (!btn) return;
    var el = document.getElementById("flowguard-attack-detail");
    if (el) el.innerHTML = "";
  }

  function onAttacksClick(ev) {
    var btn = ev.target.closest("button[data-action]");
    if (!btn) return;
    var row = btn.closest("tr[data-attack-id]");
    if (!row) return;
    var attackId = Number(row.getAttribute("data-attack-id"));
    var prefix = row.getAttribute("data-prefix");
    var action = btn.getAttribute("data-action");

    btn.disabled = true;
    var original = btn.textContent;
    btn.textContent = "...";
    var done = function () {
      btn.disabled = false;
      btn.textContent = original;
    };

    if (action === "analyze") {
      postJson(AI_ENDPOINT, { attack_id: attackId }).then(function (resp) {
        renderAiResult(prefix, resp);
        done();
      }).catch(done);
      return;
    }

    if (action === "detail") {
      getJson(ATTACKS_ENDPOINT + "?detail=" + attackId).then(function (resp) {
        renderAttackDetail(prefix, resp);
        done();
      }).catch(done);
      return;
    }

    var successLabel = {
      mitigate: "Mitigação solicitada para ",
      release: "Liberação solicitada para ",
      apply_suggestion: "Mitigação sugerida aplicada para ",
    }[action] || "Ação aplicada para ";

    postJson(ATTACKS_ENDPOINT, { action: action, attack_id: attackId }).then(function (resp) {
      showToast(resp.ok ? successLabel + prefix : resp.error, resp.ok ? "success" : "error");
      done();
    }).catch(done);
  }

  function initAttacksControls() {
    var toggle = document.getElementById("fg-attacks-view-toggle");
    var windowToggle = document.getElementById("fg-attacks-window");
    if (toggle) {
      toggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        state.attacksView = btn.getAttribute("data-view");
        state.page.attacks = 1;
        toggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
        if (windowToggle) windowToggle.hidden = state.attacksView !== "history";
        loadAttacks();
      });
    }
    if (windowToggle) {
      windowToggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        state.attacksWindow = btn.getAttribute("data-window");
        state.page.attacks = 1;
        windowToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
        loadAttacks();
      });
    }
    var sevFilter = document.getElementById("fg-attacks-severity-filter");
    if (sevFilter) {
      sevFilter.addEventListener("change", function () {
        state.filter.attacksSeverity = sevFilter.value;
        state.page.attacks = 1;
        renderAttacksFiltered();
      });
    }
    var prefixFilter = document.getElementById("fg-attacks-prefix-filter");
    if (prefixFilter) {
      prefixFilter.addEventListener("input", function () {
        state.filter.attacksPrefix = prefixFilter.value;
        state.page.attacks = 1;
        renderAttacksFiltered();
      });
    }
  }

  // --- top flows ----------------------------------------------------------

  function renderFlowsTable(rows) {
    var el = document.getElementById("flowguard-flows");
    if (!el) return;
    var p = paginate(rows, "flows");
    var bodyRows = p.pageRows
      .map(function (f) {
        return (
          "<tr><td>" + escapeHtml(f.dst_prefix) + "</td><td>" + protoName(f.protocol) + "</td><td>" + f.dst_port +
          "</td><td>" + fmtBps(f.bps) + "</td><td>" + f.pps + " pps</td></tr>"
        );
      })
      .join("");
    el.innerHTML =
      '<table data-table="flows"><thead><tr>' +
      sortableTh("Prefixo", "dst_prefix", state.sort.flows) +
      sortableTh("Protocolo", "protocol", state.sort.flows) +
      sortableTh("Porta", "dst_port", state.sort.flows) +
      sortableTh("Tráfego", "bps", state.sort.flows) +
      sortableTh("Pacotes", "pps", state.sort.flows) +
      "</tr></thead><tbody>" +
      (bodyRows || '<tr><td colspan="5">Sem flows na janela atual.</td></tr>') +
      "</tbody></table>" +
      paginationHtml("flows", p.page, p.totalPages, p.total);
  }

  function renderFlowsFiltered() {
    var needle = state.filter.flows;
    var rows = state.flows;
    if (needle) {
      var n = needle.toLowerCase();
      rows = rows.filter(function (f) {
        return String(f.dst_prefix).toLowerCase().indexOf(n) !== -1 || String(f.dst_port).indexOf(n) !== -1;
      });
    }
    rows = sortRows(rows, state.sort.flows);
    renderFlowsTable(rows);
  }

  // --- regras flowspec ------------------------------------------------------

  function renderRules(data) {
    var el = document.getElementById("flowguard-rules");
    if (!el) return;

    if (!data.ok) {
      showError(el, data.error || "erro desconhecido");
      return;
    }

    if (!data.rules.length) {
      el.innerHTML = '<p class="fg-ok">Nenhuma regra FlowSpec ativa.</p>';
      return;
    }

    var rows = data.rules
      .map(function (r) {
        return (
          '<tr data-rule-id="' + r.id + '"><td>' + escapeHtml(r.dst_prefix || "-") + "</td><td>" +
          escapeHtml(r.protocol || "-") + "</td><td>" + escapeHtml(r.action) + "</td><td>" +
          new Date(r.expires_at * 1000).toLocaleString() + '</td><td><button class="fg-btn" data-action="del">Remover</button></td></tr>'
        );
      })
      .join("");

    el.innerHTML =
      "<table><thead><tr><th>Destino</th><th>Protocolo</th><th>Ação</th><th>Expira</th><th></th></tr></thead><tbody>" +
      rows +
      "</tbody></table>";
  }

  function onRulesClick(ev) {
    var btn = ev.target.closest("button[data-action='del']");
    if (!btn) return;
    var row = btn.closest("tr[data-rule-id]");
    if (!row) return;
    var ruleId = Number(row.getAttribute("data-rule-id"));
    btn.disabled = true;
    postJson(RULES_ENDPOINT, { id: ruleId }).then(function (resp) {
      showToast(resp.ok ? "Regra removida" : resp.error, resp.ok ? "success" : "error");
      loadRules();
    });
  }

  // --- configuração: prefixos monitorados + whitelist --------------------

  function renderCfg(data) {
    var el = document.getElementById("flowguard-cfg");
    if (!el) return;

    if (!data.ok) {
      showError(el, data.error || "erro desconhecido");
      return;
    }

    populateChartPrefixSelect(data.protected_prefixes);

    var prefixRows = data.protected_prefixes
      .map(function (p) {
        var th = p.thresholds || {};
        return (
          '<tr data-prefix="' + escapeHtml(p.prefix) + '">' +
          "<td>" + escapeHtml(p.prefix) + "</td><td>" + escapeHtml(p.customer || "-") + "</td><td>" +
          (p.capacity_mbps || 0) + " Mbps</td><td>" + (p.auto_mitigate ? "sim" : "não") + "</td><td>" +
          (th.ddos_bps_threshold ? fmtBps(th.ddos_bps_threshold) : "-") + "</td>" +
          '<td><button class="fg-btn" data-action="edit-monitor">Editar</button> ' +
          '<button class="fg-btn" data-action="del-monitor">Remover</button></td></tr>'
        );
      })
      .join("");

    var wlRows = data.whitelist
      .map(function (prefix) {
        return (
          '<tr data-prefix="' + escapeHtml(prefix) + '"><td>' + escapeHtml(prefix) +
          '</td><td><button class="fg-btn" data-action="del-whitelist">Remover</button></td></tr>'
        );
      })
      .join("");

    el.innerHTML =
      "<h4>Prefixos monitorados</h4>" +
      "<table><thead><tr><th>Prefixo</th><th>Cliente</th><th>Capacidade</th><th>Auto-mitigar</th><th>Limiar bps</th><th></th></tr></thead><tbody>" +
      prefixRows +
      "</tbody></table>" +
      '<form id="fg-monitor-form" class="fg-form">' +
      '<input name="prefix" placeholder="prefixo (ex: 177.86.30.0/24)" required>' +
      '<input name="customer" placeholder="cliente">' +
      '<input name="capacity_mbps" type="number" placeholder="capacidade (Mbps)">' +
      '<input name="ddos_bps_threshold_mbps" type="number" placeholder="limiar DDoS (Mbps)">' +
      '<label><input type="checkbox" name="auto_mitigate"> auto-mitigar</label>' +
      '<label><input type="checkbox" name="notify_wa"> notificar WhatsApp</label>' +
      '<button type="submit" class="fg-btn">Salvar</button></form>' +
      "<h4>Whitelist</h4>" +
      "<table><thead><tr><th>Prefixo</th><th></th></tr></thead><tbody>" +
      wlRows +
      "</tbody></table>" +
      '<form id="fg-whitelist-form" class="fg-form">' +
      '<input name="prefix" placeholder="prefixo (ex: 8.8.4.4/32)" required>' +
      '<button type="submit" class="fg-btn">Adicionar à whitelist</button></form>';
  }

  function onCfgClick(ev) {
    var btn = ev.target.closest("button[data-action]");
    if (!btn) return;
    var row = btn.closest("tr[data-prefix]");
    if (!row) return;
    var prefix = row.getAttribute("data-prefix");
    var action = btn.getAttribute("data-action");

    if (action === "del-monitor") {
      postJson(CFG_ENDPOINT, { cmd: "monitor_del", prefix: prefix }).then(function (resp) {
        showToast(resp.ok ? "Prefixo removido do monitoramento" : resp.error, resp.ok ? "success" : "error");
        loadCfg();
      });
    } else if (action === "del-whitelist") {
      postJson(CFG_ENDPOINT, { cmd: "whitelist_del", prefix: prefix }).then(function (resp) {
        showToast(resp.ok ? "Prefixo removido da whitelist" : resp.error, resp.ok ? "success" : "error");
        loadCfg();
      });
    } else if (action === "edit-monitor") {
      var form = document.getElementById("fg-monitor-form");
      if (!form) return;
      var cells = row.querySelectorAll("td");
      form.prefix.value = prefix;
      form.prefix.readOnly = true;
      form.customer.value = cells[1].textContent === "-" ? "" : cells[1].textContent;
      form.capacity_mbps.value = parseInt(cells[2].textContent, 10) || "";
      form.auto_mitigate.checked = cells[3].textContent.trim() === "sim";
      form.scrollIntoView({ behavior: "smooth" });
    }
  }

  function onCfgSubmit(ev) {
    var form = ev.target;
    if (form.id === "fg-monitor-form") {
      ev.preventDefault();
      var thresholds = {};
      var mbps = Number(form.ddos_bps_threshold_mbps.value);
      if (mbps > 0) thresholds.ddos_bps_threshold = Math.round(mbps * 1e6);
      postJson(CFG_ENDPOINT, {
        cmd: "monitor_set",
        prefix: form.prefix.value,
        customer: form.customer.value,
        capacity_mbps: Number(form.capacity_mbps.value) || 0,
        auto_mitigate: form.auto_mitigate.checked,
        notify_wa: form.notify_wa.checked,
        thresholds: thresholds,
      }).then(function (resp) {
        showToast(resp.ok ? "Prefixo salvo" : resp.error, resp.ok ? "success" : "error");
        loadCfg();
      });
    } else if (form.id === "fg-whitelist-form") {
      ev.preventDefault();
      postJson(CFG_ENDPOINT, { cmd: "whitelist_add", prefix: form.prefix.value }).then(function (resp) {
        showToast(resp.ok ? "Adicionado à whitelist" : resp.error, resp.ok ? "success" : "error");
        loadCfg();
      });
    }
  }

  // --- ClientGuard: status + top clientes ---------------------------------

  var CG_SIGNAL_LABELS = {
    port_scan_horizontal: "scan horizontal",
    port_scan_vertical: "scan vertical",
    amplifier_hosted: "amplificador hospedado",
    spam_bot: "spam bot",
    malicious_contact: "contato com IP malicioso conhecido",
    coordinated_destination: "destino coordenado (múltiplos clientes)",
    dns_tunneling: "túnel DNS / exfiltração via DNS",
  };

  function updateCgBadge(count) {
    var badge = document.getElementById("cg-suspicious-badge");
    if (!badge) return;
    if (count > 0) {
      badge.style.display = "inline-block";
      badge.textContent = count;
    } else {
      badge.style.display = "none";
    }
  }

  function renderCgKpis(status) {
    var el = document.getElementById("cg-kpis");
    if (!el) return;
    if (!status || !status.ok) {
      el.innerHTML = kpiCard("Daemon", '<span class="fg-dot fg-dot-down"></span>indisponível', (status && status.error) || "");
      return;
    }
    el.innerHTML =
      kpiCard("Flows na janela", status.flows_window, "") +
      kpiCard("Clientes ativos", status.distinct_src_ips, "na janela atual") +
      kpiCard("Sinais abertos", status.open_signals, status.open_signals > 0 ? "requer atenção" : "tudo normal") +
      kpiCard("Redes cadastradas", status.n_customers, "") +
      kpiCard("Whitelist", status.n_whitelist, "") +
      kpiCard("Daemon", '<span class="fg-dot fg-dot-up"></span>ativo', "uptime " + fmtUptime(status.uptime_s) + " · pid " + status.pid);
  }

  function renderCgTop(rows) {
    var el = document.getElementById("cg-top");
    if (!el) return;
    if (!rows.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum tráfego na janela atual.</p>';
      return;
    }
    var body = rows
      .map(function (r) {
        return (
          "<tr><td>" + escapeHtml(r.src_ip) + "</td><td>" + escapeHtml(r.customer_prefix || "-") + "</td><td>" +
          fmtBytes(r.bytes) + "</td><td>" + (r.flows || 0).toLocaleString("pt-BR") + "</td></tr>"
        );
      })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>src_ip</th><th>Cliente</th><th>Tráfego</th><th>Flows</th></tr></thead><tbody>" +
      body + "</tbody></table>";
  }

  function loadClientGuardStatus() {
    getJson(CG_STATUS_ENDPOINT).then(function (data) {
      if (!data.ok) {
        renderCgKpis(null);
        showError(document.getElementById("cg-top"), data.error || "erro desconhecido");
        return;
      }
      renderCgKpis(data.status);
      renderCgTop(data.top || []);
    }).catch(function (err) {
      showError(document.getElementById("cg-kpis"), "falha ao consultar status do ClientGuard");
      console.error("flowguard.js:", err);
    });
  }

  // --- ClientGuard: sinais suspeitos ---------------------------------------

  function renderCgSuspicious(rows) {
    var el = document.getElementById("cg-suspicious");
    if (!el) return;
    if (state.cgSuspiciousView === "open") updateCgBadge(rows.length);
    if (!rows.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum sinal ' + (state.cgSuspiciousView === "open" ? "aberto" : "resolvido") + ".</p>";
      return;
    }
    var body = rows
      .map(function (r) {
        var resolveBtn = state.cgSuspiciousView === "open"
          ? '<button class="fg-btn" data-action="resolve">Resolver</button> '
          : "";
        return (
          '<tr data-signal-id="' + r.id + '">' +
          "<td>" + escapeHtml(r.src_ip) + "</td><td>" + escapeHtml(r.customer_prefix || "-") + "</td><td>" +
          escapeHtml(CG_SIGNAL_LABELS[r.signal_type] || r.signal_type) + "</td><td>" +
          Math.round((r.confidence || 0) * 100) + "%</td><td>" + fmtDateTime(r.ts_detected) + "</td><td>" +
          fmtDateTime(r.ts_last_seen) + "</td>" +
          "<td>" + resolveBtn + '<button class="fg-btn" data-action="detail">Detalhes</button></td></tr>'
        );
      })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>src_ip</th><th>Cliente</th><th>Sinal</th><th>Confiança</th><th>Detectado</th>" +
      "<th>Última vez</th><th>Ações</th></tr></thead><tbody>" + body + "</tbody></table>";
  }

  function loadClientGuardSuspicious() {
    var url = state.cgSuspiciousView === "history" ? CG_SUSPICIOUS_ENDPOINT + "?history=1" : CG_SUSPICIOUS_ENDPOINT;
    getJson(url).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("cg-suspicious"), data.error || "erro desconhecido");
        return;
      }
      state.cgSuspicious = data.suspicious;
      renderCgSuspicious(data.suspicious);
    }).catch(function (err) {
      showError(document.getElementById("cg-suspicious"), "falha ao consultar sinais suspeitos");
      console.error("flowguard.js:", err);
    });
  }

  function renderCgSuspiciousDetail(row) {
    var el = document.getElementById("cg-suspicious-detail");
    if (!el) return;
    var evidence = row.evidence;
    try {
      var parsed = typeof row.evidence === "string" ? JSON.parse(row.evidence) : row.evidence;
      evidence = Object.keys(parsed || {}).map(function (k) { return k + "=" + parsed[k]; }).join(", ");
    } catch (e) {
      // evidencia não é JSON válido — mostra a string crua mesmo
    }
    var aiHtml = row.ai_explanation
      ? "<h5>Explicação (IA)</h5><pre>" + escapeHtml(row.ai_explanation) + "</pre>"
      : '<p class="fg-kpi-sub">sem explicação de IA registrada para este sinal</p>';
    el.innerHTML =
      '<div class="fg-ai-panel"><div class="fg-panel-header"><h4>Sinal #' + row.id + " — " + escapeHtml(row.src_ip) + "</h4>" +
      '<button class="fg-btn" data-action="close-detail">Fechar</button></div>' +
      '<p class="fg-kpi-sub">Tipo: ' + escapeHtml(CG_SIGNAL_LABELS[row.signal_type] || row.signal_type) +
      " · Confiança: " + Math.round((row.confidence || 0) * 100) + "% · Evidência: " + escapeHtml(evidence) + "</p>" +
      aiHtml +
      "</div>";
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function onCgSuspiciousClick(ev) {
    var btn = ev.target.closest("button[data-action]");
    if (!btn) return;
    var row = btn.closest("tr[data-signal-id]");
    if (!row) return;
    var signalId = Number(row.getAttribute("data-signal-id"));
    var action = btn.getAttribute("data-action");

    if (action === "detail") {
      var data = (state.cgSuspicious || []).filter(function (r) { return r.id === signalId; })[0];
      if (data) renderCgSuspiciousDetail(data);
      return;
    }

    if (action === "resolve") {
      btn.disabled = true;
      postJson(CG_SUSPICIOUS_ENDPOINT, { id: signalId }).then(function (resp) {
        showToast(resp.ok ? "Sinal marcado como resolvido" : resp.error, resp.ok ? "success" : "error");
        loadClientGuardSuspicious();
      });
    }
  }

  function onCgDetailClick(ev) {
    var btn = ev.target.closest("button[data-action='close-detail']");
    if (!btn) return;
    var el = document.getElementById("cg-suspicious-detail");
    if (el) el.innerHTML = "";
  }

  function initCgSuspiciousControls() {
    var toggle = document.getElementById("cg-suspicious-view-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", function (ev) {
      var btn = ev.target.closest(".fg-toggle-btn");
      if (!btn) return;
      state.cgSuspiciousView = btn.getAttribute("data-view");
      toggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
      loadClientGuardSuspicious();
    });
  }

  // --- ClientGuard: redes de clientes + whitelist --------------------------

  function renderCgCustomers(customers) {
    var el = document.getElementById("cg-customers");
    if (!el) return;
    if (!customers.length) {
      el.innerHTML = '<p class="fg-ok">Nenhuma rede cadastrada.</p>';
      return;
    }
    var rows = customers
      .map(function (c) {
        return (
          '<tr data-network="' + escapeHtml(c.network) + '"><td>' + escapeHtml(c.network) + "</td><td>" +
          escapeHtml(c.prefix) + "</td><td>" + escapeHtml(c.name || "-") + "</td>" +
          '<td><button class="fg-btn" data-action="del-customer">Remover</button></td></tr>'
        );
      })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>Rede</th><th>Rótulo</th><th>Nome</th><th></th></tr></thead><tbody>" + rows + "</tbody></table>";
  }

  function renderCgWhitelist(whitelist) {
    var el = document.getElementById("cg-whitelist");
    if (!el) return;
    if (!whitelist.length) {
      el.innerHTML = '<p class="fg-ok">Whitelist vazia.</p>';
      return;
    }
    var rows = whitelist
      .map(function (ip) {
        return (
          '<tr data-ip="' + escapeHtml(ip) + '"><td>' + escapeHtml(ip) +
          '</td><td><button class="fg-btn" data-action="del-whitelist-ip">Remover</button></td></tr>'
        );
      })
      .join("");
    el.innerHTML = "<table><thead><tr><th>IP</th><th></th></tr></thead><tbody>" + rows + "</tbody></table>";
  }

  function loadClientGuardCfg() {
    if (!getToken()) return;
    getJson(CG_CFG_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("cg-customers"), data.error || "erro desconhecido");
        return;
      }
      renderCgCustomers(data.customers);
      renderCgWhitelist(data.whitelist);
    }).catch(function (err) {
      showError(document.getElementById("cg-customers"), "falha ao consultar configuração do ClientGuard");
      console.error("flowguard.js:", err);
    });
  }

  function onCgCfgClick(ev) {
    var btn = ev.target.closest("button[data-action]");
    if (!btn) return;
    var action = btn.getAttribute("data-action");
    if (action === "del-customer") {
      var row = btn.closest("tr[data-network]");
      if (!row) return;
      postJson(CG_CFG_ENDPOINT, { cmd: "customers_del", network: row.getAttribute("data-network") }).then(function (resp) {
        showToast(resp.ok ? "Rede removida" : resp.error, resp.ok ? "success" : "error");
        loadClientGuardCfg();
        loadClientGuardStatus();
      });
    } else if (action === "del-whitelist-ip") {
      var row2 = btn.closest("tr[data-ip]");
      if (!row2) return;
      postJson(CG_CFG_ENDPOINT, { cmd: "whitelist_del", ip: row2.getAttribute("data-ip") }).then(function (resp) {
        showToast(resp.ok ? "IP removido da whitelist" : resp.error, resp.ok ? "success" : "error");
        loadClientGuardCfg();
        loadClientGuardStatus();
      });
    }
  }

  function onCgCfgSubmit(ev) {
    var form = ev.target;
    if (form.id === "cg-customers-form") {
      ev.preventDefault();
      postJson(CG_CFG_ENDPOINT, {
        cmd: "customers_add", network: form.network.value.trim(), prefix: form.prefix.value.trim(), name: form.name.value.trim(),
      }).then(function (resp) {
        showToast(resp.ok ? "Rede adicionada" : resp.error, resp.ok ? "success" : "error");
        if (resp.ok) form.reset();
        loadClientGuardCfg();
        loadClientGuardStatus();
      });
    } else if (form.id === "cg-whitelist-form") {
      ev.preventDefault();
      postJson(CG_CFG_ENDPOINT, { cmd: "whitelist_add", ip: form.ip.value.trim() }).then(function (resp) {
        showToast(resp.ok ? "IP adicionado à whitelist" : resp.error, resp.ok ? "success" : "error");
        if (resp.ok) form.reset();
        loadClientGuardCfg();
        loadClientGuardStatus();
      });
    }
  }

  function loadClientGuard() {
    loadClientGuardStatus();
    loadClientGuardSuspicious();
  }

  // --- gráficos (canvas, sem dependência externa) -------------------------

  var SEV_COLORS = { critical: "#f85149", high: "#ffa657", medium: "#d29922", info: "#8b949e" };
  var SEV_ROWS = ["critical", "high", "medium", "info"];

  function chartScale(canvas) {
    var ctx = canvas.getContext("2d");
    var w = canvas.width;
    var h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    return { ctx: ctx, w: w, h: h, padding: { left: 55, right: 10, top: 10, bottom: 20 } };
  }

  function drawEmpty(canvas, message) {
    var s = chartScale(canvas);
    s.ctx.fillStyle = "#8b949e";
    s.ctx.font = "12px sans-serif";
    s.ctx.fillText(message, s.padding.left, s.h / 2);
  }

  function pad2(n) {
    return n < 10 ? "0" + n : String(n);
  }

  function fmtAxisTime(ts, spanS) {
    var d = new Date(ts * 1000);
    var hhmm = pad2(d.getHours()) + ":" + pad2(d.getMinutes());
    if (spanS > 86400) return pad2(d.getDate()) + "/" + pad2(d.getMonth() + 1) + " " + hhmm;
    return hhmm;
  }

  // rótulos de horário no eixo X — usado pelos três gráficos (linha, área
  // empilhada e timeline), sempre a partir de timestamps unix reais dos dados.
  function drawTimeAxis(s, sinceTs, nowTs) {
    if (sinceTs == null || nowTs == null) return;
    var plotW = s.w - s.padding.left - s.padding.right;
    var span = nowTs - sinceTs || 1;
    var ticks = 6;
    var ctx = s.ctx;
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px sans-serif";
    ctx.textAlign = "center";
    for (var t = 0; t <= ticks; t++) {
      var frac = t / ticks;
      var xx = s.padding.left + frac * plotW;
      ctx.fillText(fmtAxisTime(sinceTs + frac * span, span), xx, s.h - 5);
    }
    ctx.textAlign = "left";
  }

  function drawLineChart(canvas, series, lines, band) {
    if (!series || series.length < 2) {
      drawEmpty(canvas, "Sem dados suficientes na janela selecionada.");
      return;
    }
    var s = chartScale(canvas);
    var ctx = s.ctx;
    var plotW = s.w - s.padding.left - s.padding.right;
    var plotH = s.h - s.padding.top - s.padding.bottom;

    var maxV = 1;
    series.forEach(function (pt) {
      lines.forEach(function (l) { if (pt[l.key] > maxV) maxV = pt[l.key]; });
      if (band && pt[band.upperKey] > maxV) maxV = pt[band.upperKey];
    });

    function x(i) { return s.padding.left + (i / (series.length - 1)) * plotW; }
    function y(v) { return s.padding.top + plotH - (v / maxV) * plotH; }

    ctx.strokeStyle = "#21262d";
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px sans-serif";
    for (var g = 0; g <= 4; g++) {
      var v = (maxV * g) / 4;
      var yy = y(v);
      ctx.beginPath();
      ctx.moveTo(s.padding.left, yy);
      ctx.lineTo(s.w - s.padding.right, yy);
      ctx.stroke();
      ctx.fillText(fmtBps(v), 2, yy + 3);
    }

    if (band) {
      ctx.fillStyle = "rgba(88,166,255,0.18)";
      ctx.beginPath();
      series.forEach(function (pt, i) {
        var yy = y(pt[band.upperKey] || 0);
        if (i === 0) ctx.moveTo(x(i), yy);
        else ctx.lineTo(x(i), yy);
      });
      for (var i = series.length - 1; i >= 0; i--) ctx.lineTo(x(i), y(0));
      ctx.closePath();
      ctx.fill();
    }

    lines.forEach(function (l) {
      ctx.strokeStyle = l.color;
      ctx.lineWidth = 1.5;
      ctx.setLineDash(l.dashed ? [5, 4] : []);
      ctx.beginPath();
      series.forEach(function (pt, i) {
        var yy = y(pt[l.key] || 0);
        if (i === 0) ctx.moveTo(x(i), yy);
        else ctx.lineTo(x(i), yy);
      });
      ctx.stroke();
    });
    ctx.setLineDash([]);

    drawTimeAxis(s, series[0].ts, series[series.length - 1].ts);
  }

  function drawStackedArea(canvas, series, keys, colors) {
    if (!series || series.length < 2) {
      drawEmpty(canvas, "Sem dados suficientes na janela selecionada.");
      return;
    }
    var s = chartScale(canvas);
    var ctx = s.ctx;
    var plotW = s.w - s.padding.left - s.padding.right;
    var plotH = s.h - s.padding.top - s.padding.bottom;

    var totals = series.map(function (pt) { return keys.reduce(function (sum, k) { return sum + (pt[k] || 0); }, 0); });
    var maxV = Math.max.apply(null, totals.concat([1]));

    function x(i) { return s.padding.left + (i / (series.length - 1)) * plotW; }
    function y(v) { return s.padding.top + plotH - (v / maxV) * plotH; }

    ctx.strokeStyle = "#21262d";
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px sans-serif";
    for (var g = 0; g <= 4; g++) {
      var v = (maxV * g) / 4;
      var yy = y(v);
      ctx.beginPath();
      ctx.moveTo(s.padding.left, yy);
      ctx.lineTo(s.w - s.padding.right, yy);
      ctx.stroke();
      ctx.fillText(fmtBps(v), 2, yy + 3);
    }

    var cumulative = series.map(function () { return 0; });
    keys.forEach(function (key, ki) {
      ctx.fillStyle = colors[ki];
      ctx.beginPath();
      series.forEach(function (pt, i) {
        var top = cumulative[i] + (pt[key] || 0);
        var yy = y(top);
        if (i === 0) ctx.moveTo(x(i), yy);
        else ctx.lineTo(x(i), yy);
      });
      for (var i = series.length - 1; i >= 0; i--) ctx.lineTo(x(i), y(cumulative[i]));
      ctx.closePath();
      ctx.fill();
      series.forEach(function (pt, i) { cumulative[i] += pt[key] || 0; });
    });

    drawTimeAxis(s, series[0].ts, series[series.length - 1].ts);
  }

  function drawTimeline(canvas, attacks, windowS) {
    if (!attacks || !attacks.length) {
      drawEmpty(canvas, "Nenhum ataque no período selecionado.");
      return;
    }
    var s = chartScale(canvas);
    var ctx = s.ctx;
    var plotW = s.w - s.padding.left - s.padding.right;
    var rowH = (s.h - s.padding.top - s.padding.bottom) / SEV_ROWS.length;
    var now = Math.floor(Date.now() / 1000);
    var since = now - windowS;

    ctx.fillStyle = "#8b949e";
    ctx.font = "10px sans-serif";
    SEV_ROWS.forEach(function (sev, i) {
      var yy = s.padding.top + i * rowH;
      ctx.fillText(sev, 2, yy + rowH / 2 + 3);
      ctx.strokeStyle = "#21262d";
      ctx.beginPath();
      ctx.moveTo(s.padding.left, yy + rowH);
      ctx.lineTo(s.w - s.padding.right, yy + rowH);
      ctx.stroke();
    });

    attacks.forEach(function (a) {
      var row = SEV_ROWS.indexOf(a.severity);
      if (row === -1) row = SEV_ROWS.length - 1;
      var start = Math.max(a.ts_start, since);
      var end = a.ts_end || now;
      var x1 = s.padding.left + ((start - since) / windowS) * plotW;
      var x2 = s.padding.left + ((end - since) / windowS) * plotW;
      var yy = s.padding.top + row * rowH + rowH * 0.25;
      ctx.fillStyle = SEV_COLORS[a.severity] || "#8b949e";
      ctx.fillRect(x1, yy, Math.max(x2 - x1, 2), rowH * 0.5);
    });

    drawTimeAxis(s, since, now);
  }

  function populateChartPrefixSelect(prefixes) {
    var select = document.getElementById("fg-chart-prefix");
    if (!select || state.chart.prefixesLoaded) return;
    select.innerHTML = prefixes
      .map(function (p) { return '<option value="' + escapeHtml(p.prefix) + '">' + escapeHtml(p.prefix) + (p.customer ? " — " + escapeHtml(p.customer) : "") + "</option>"; })
      .join("");
    if (prefixes.length) {
      state.chart.prefix = prefixes[0].prefix;
      state.chart.prefixesLoaded = true;
    }
  }

  function loadCharts() {
    if (!state.chart.prefix) return;
    var windowName = state.chart.window;

    getJson(HISTORY_ENDPOINT + "?metric=prefix&prefix=" + encodeURIComponent(state.chart.prefix) + "&window=" + windowName)
      .then(function (data) {
        var canvas = document.getElementById("fg-chart-traffic");
        if (!canvas) return;
        if (!data.ok) { drawEmpty(canvas, data.error || "erro ao carregar"); return; }
        var series = data.series.map(function (pt) {
          var withBaseline = { ts: pt.ts, bps_in: pt.bps_in, bps_out: pt.bps_out };
          if (data.baseline) {
            withBaseline.baseline_mean = data.baseline.bps_mean;
            withBaseline.baseline_upper = data.baseline.bps_upper;
          }
          return withBaseline;
        });
        var lines = [
          { key: "bps_in", color: "#58a6ff" },
          { key: "bps_out", color: "#ffa657" },
        ];
        var band = null;
        if (data.baseline) {
          lines.push({ key: "baseline_mean", color: "#8b949e", dashed: true });
          band = { upperKey: "baseline_upper" };
        }
        drawLineChart(canvas, series, lines, band);
      });

    getJson(HISTORY_ENDPOINT + "?metric=protocol&window=" + windowName).then(function (data) {
      var canvas = document.getElementById("fg-chart-protocol");
      if (!canvas) return;
      if (!data.ok) { drawEmpty(canvas, data.error || "erro ao carregar"); return; }
      drawStackedArea(canvas, data.series, ["tcp", "udp", "icmp", "other"], ["#58a6ff", "#3fb950", "#d29922", "#8b949e"]);
    });

    getJson(HISTORY_ENDPOINT + "?metric=attacks&window=" + windowName).then(function (data) {
      var canvas = document.getElementById("fg-chart-timeline");
      if (!canvas) return;
      if (!data.ok) { drawEmpty(canvas, data.error || "erro ao carregar"); return; }
      var windowSeconds = { "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800 }[windowName] || 21600;
      drawTimeline(canvas, data.attacks, windowSeconds);
    });

    getJson(HISTORY_ENDPOINT + "?metric=hosts&prefix=" + encodeURIComponent(state.chart.prefix) + "&window=" + windowName)
      .then(function (data) {
        var el = document.getElementById("flowguard-top-hosts");
        if (!el) return;
        if (!data.ok) { showError(el, data.error || "erro ao carregar"); return; }
        renderTopHosts(el, data.hosts || []);
      });
  }

  function renderTopHosts(el, hosts) {
    if (!hosts.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum host individual identificado na janela selecionada.</p>';
      return;
    }
    var rows = hosts
      .map(function (h) { return "<tr><td>" + escapeHtml(h.ip) + "/32</td><td>" + h.occurrences + " ciclo(s)</td></tr>"; })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>Host</th><th>Presença na janela</th></tr></thead><tbody>" + rows + "</tbody></table>" +
      '<p class="fg-kpi-sub">Presença = em quantos ciclos de agregação o host apareceu entre os top 10 de destino do prefixo — não é volume exato por host.</p>';
  }

  function initChartControls() {
    var select = document.getElementById("fg-chart-prefix");
    if (select) {
      select.addEventListener("change", function () {
        state.chart.prefix = select.value;
        loadCharts();
      });
    }
    var windowToggle = document.getElementById("fg-chart-window");
    if (windowToggle) {
      windowToggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        state.chart.window = btn.getAttribute("data-window");
        windowToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
        loadCharts();
      });
    }
  }

  // --- sort click delegation (global) -------------------------------------

  function initSortHandlers() {
    document.addEventListener("click", function (ev) {
      var th = ev.target.closest("th[data-sort-key]");
      if (!th) return;
      var table = th.closest("table[data-table]");
      if (!table) return;
      var tableName = table.getAttribute("data-table");
      var key = th.getAttribute("data-sort-key");
      var sort = state.sort[tableName];
      if (!sort) return;
      if (sort.key === key) sort.dir = sort.dir === "asc" ? "desc" : "asc";
      else { sort.key = key; sort.dir = "desc"; }
      if (tableName === "topPrefixes") renderTopPrefixesFiltered();
      if (tableName === "flows") renderFlowsFiltered();
    });
  }

  // --- polling --------------------------------------------------------------

  function loadStatus() {
    getJson(STATUS_ENDPOINT).then(function (data) {
      renderKpis(data);
      if (data.ok) {
        state.topPrefixes = data.top_prefixes;
        renderSparklines(data.protocol_series);
        renderTopPrefixesFiltered();
      } else {
        showError(document.getElementById("flowguard-top-prefixes"), data.error);
      }
    }).catch(function (err) {
      showError(document.getElementById("fg-kpis"), "falha ao consultar status");
      console.error("flowguard.js:", err);
    });
  }

  function loadAttacks() {
    var url = state.attacksView === "history"
      ? ATTACKS_ENDPOINT + "?history=1&window=" + encodeURIComponent(state.attacksWindow)
      : ATTACKS_ENDPOINT;
    getJson(url).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("flowguard-attacks"), data.error);
        return;
      }
      state.attacks = data.attacks;
      renderAttacksFiltered();
    }).catch(function (err) {
      showError(document.getElementById("flowguard-attacks"), "falha ao consultar ataques");
      console.error("flowguard.js:", err);
    });
  }

  function loadFlows() {
    getJson(FLOWS_ENDPOINT + "?limit=50").then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("flowguard-flows"), data.error);
        return;
      }
      state.flows = data.flows;
      renderFlowsFiltered();
    }).catch(function (err) {
      showError(document.getElementById("flowguard-flows"), "falha ao consultar flows");
      console.error("flowguard.js:", err);
    });
  }

  function loadRules() {
    getJson(RULES_ENDPOINT).then(renderRules).catch(function (err) {
      showError(document.getElementById("flowguard-rules"), "falha ao consultar regras");
      console.error("flowguard.js:", err);
    });
  }

  function loadCfg() {
    if (!getToken()) return;
    getJson(CFG_ENDPOINT).then(renderCfg).catch(function (err) {
      showError(document.getElementById("flowguard-cfg"), "falha ao consultar configuração");
      console.error("flowguard.js:", err);
    });
  }

  function poll() {
    if (!getToken()) return;
    loadStatus();
    loadAttacks();
    loadFlows();
    loadRules();
  }

  function initLogin() {
    var form = document.getElementById("fg-login-form");
    if (!form) return;

    var userInput = document.getElementById("fg-login-user");
    var passInput = document.getElementById("fg-login-pass");
    var status = document.getElementById("fg-login-status");
    var logoutBtn = document.getElementById("fg-logout-btn");

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      status.textContent = "autenticando...";
      fetch(LOGIN_ENDPOINT, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: userInput.value.trim(), password: passInput.value }),
      })
        .then(function (resp) {
          return resp.json().then(function (data) {
            return { status: resp.status, data: data };
          });
        })
        .then(function (result) {
          if (result.status === 200 && result.data.ok) {
            setToken(result.data.token);
            passInput.value = "";
            status.textContent = "";
            showApp();
            poll();
            loadCfg();
          } else {
            status.textContent = "usuário ou senha inválidos";
          }
        })
        .catch(function () {
          status.textContent = "erro ao conectar com o portal";
        });
    });

    if (logoutBtn) {
      logoutBtn.addEventListener("click", function () {
        var token = getToken();
        showLogin();
        if (token) {
          fetch(LOGOUT_ENDPOINT + "?token=" + encodeURIComponent(token), { credentials: "same-origin" });
        }
      });
    }

    if (getToken()) {
      showApp();
    } else {
      showLogin();
    }
  }

  function init() {
    if (!document.getElementById("fg-kpis")) return;

    initLogin();
    initTabs();
    initSortHandlers();
    initAttacksControls();
    initPaginationHandlers();
    initActionMenus();

    var topSearch = document.getElementById("fg-top-prefixes-search");
    if (topSearch) topSearch.addEventListener("input", function () { state.filter.topPrefixes = topSearch.value; state.page.topPrefixes = 1; renderTopPrefixesFiltered(); });

    var flowsSearch = document.getElementById("fg-flows-search");
    if (flowsSearch) flowsSearch.addEventListener("input", function () { state.filter.flows = flowsSearch.value; state.page.flows = 1; renderFlowsFiltered(); });

    var attacksEl = document.getElementById("flowguard-attacks");
    if (attacksEl) attacksEl.addEventListener("click", onAttacksClick);

    var attackDetailEl = document.getElementById("flowguard-attack-detail");
    if (attackDetailEl) attackDetailEl.addEventListener("click", onAttackDetailClick);

    var rulesEl = document.getElementById("flowguard-rules");
    if (rulesEl) rulesEl.addEventListener("click", onRulesClick);

    var cfgEl = document.getElementById("flowguard-cfg");
    if (cfgEl) {
      cfgEl.addEventListener("click", onCfgClick);
      cfgEl.addEventListener("submit", onCfgSubmit);
      loadCfg();
    }

    var cgSuspiciousEl = document.getElementById("cg-suspicious");
    if (cgSuspiciousEl) cgSuspiciousEl.addEventListener("click", onCgSuspiciousClick);

    var cgDetailEl = document.getElementById("cg-suspicious-detail");
    if (cgDetailEl) cgDetailEl.addEventListener("click", onCgDetailClick);

    initCgSuspiciousControls();

    var cgCustomersForm = document.getElementById("cg-customers-form");
    if (cgCustomersForm) cgCustomersForm.addEventListener("submit", onCgCfgSubmit);

    var cgWhitelistForm = document.getElementById("cg-whitelist-form");
    if (cgWhitelistForm) cgWhitelistForm.addEventListener("submit", onCgCfgSubmit);

    var cgCustomersEl = document.getElementById("cg-customers");
    if (cgCustomersEl) cgCustomersEl.addEventListener("click", onCgCfgClick);

    var cgWhitelistEl = document.getElementById("cg-whitelist");
    if (cgWhitelistEl) cgWhitelistEl.addEventListener("click", onCgCfgClick);

    if (getToken()) loadClientGuardCfg();

    initChartControls();

    poll();
    setInterval(poll, REFRESH_MS);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
