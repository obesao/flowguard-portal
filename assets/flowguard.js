// flowguard.js — módulo do dashboard FlowGuard (padrão IIFE)
(function () {
  "use strict";

  var REFRESH_MS = 5000;
  var STATUS_ENDPOINT = "/cgi-bin/flowguard-status.sh";
  var ATTACKS_ENDPOINT = "/cgi-bin/flowguard-attacks.sh";
  var FLOWS_ENDPOINT = "/cgi-bin/flowguard-flows.sh";
  var RULES_ENDPOINT = "/cgi-bin/flowguard-rules.sh";
  var CFG_ENDPOINT = "/cgi-bin/flowguard-cfg.sh";
  var TOGGLES_ENDPOINT = "/cgi-bin/flowguard-toggles.sh";
  var MITIGATION_CFG_ENDPOINT = "/cgi-bin/flowguard-mitigation-cfg.sh";
  var AI_ENDPOINT = "/cgi-bin/flowguard-ai.sh";
  var HISTORY_ENDPOINT = "/cgi-bin/flowguard-history.sh";
  var LOGIN_ENDPOINT = "/cgi-bin/flowguard-login.sh";
  var LOGOUT_ENDPOINT = "/cgi-bin/flowguard-logout.sh";
  var CG_STATUS_ENDPOINT = "/cgi-bin/clientguard-status.sh";
  var CG_SUSPICIOUS_ENDPOINT = "/cgi-bin/clientguard-suspicious.sh";
  var CG_CFG_ENDPOINT = "/cgi-bin/clientguard-cfg.sh";
  var CG_TOP_ENDPOINT = "/cgi-bin/clientguard-top.sh";
  var CG_CLIENT_DETAIL_ENDPOINT = "/cgi-bin/clientguard-client-detail.sh";
  var CG_BLOCK_ENDPOINT = "/cgi-bin/clientguard-block.sh";
  var CG_TOGGLES_ENDPOINT = "/cgi-bin/clientguard-toggles.sh";
  var WARMODE_ENDPOINT = "/cgi-bin/flowguard-warmode.sh";
  var WARMODE_AUTH_ENDPOINT = "/cgi-bin/flowguard-warmode-auth.sh";
  var WARMODE_CFG_ENDPOINT = "/cgi-bin/flowguard-warmode-cfg.sh";
  var ROUTERCFG_ENDPOINT = "/cgi-bin/flowguard-routercfg.sh";
  var WHATSAPP_ENDPOINT = "/cgi-bin/flowguard-whatsapp.sh";

  var warmodeToken = null; // em memória só — some ao recarregar a página (relock)
  var rcTemplates = [];
  var rcCountdownTimer = null;

  var PROTO_NAMES = { 6: "TCP", 17: "UDP", 1: "ICMP" };

  // ordem fixa de exibição na aba Configuração > Funções de Detecção — mesmas chaves
  // de configio.DEFAULT_FEATURE_TOGGLES no backend do FlowGuard
  var FG_TOGGLE_META = [
    { key: "ddos_volumetrico", label: "DDoS volumétrico", desc: "tráfego total (bps/pps) pra um prefixo protegido acima do limiar configurado." },
    { key: "dns_amp", label: "Amplificação DNS", desc: "resposta UDP/53 em volume alto vinda de fora pro prefixo — reflexão via resolvers abertos." },
    { key: "ntp_amp", label: "Amplificação NTP", desc: "resposta UDP/123 em volume alto — reflexão via servidores NTP abertos." },
    { key: "ssdp_amp", label: "Amplificação SSDP", desc: "resposta UDP/1900 em volume alto — reflexão via dispositivos UPnP/SSDP expostos." },
    { key: "memcached_amp", label: "Amplificação Memcached", desc: "resposta UDP/11211 em volume alto — reflexão via Memcached exposto (fator de amplificação altíssimo)." },
    { key: "cldap_amp", label: "Amplificação CLDAP", desc: "resposta UDP/389 em volume alto — reflexão via serviços CLDAP (Active Directory) expostos." },
    { key: "anomalia_baseline", label: "Anomalia de baseline", desc: "desvio estatístico (EWMA) do tráfego normal do prefixo — pega ataques pequenos demais pro limiar fixo global." },
  ];

  var MITIGATION_KIND_LABELS = {
    rtbh: "RTBH (bloqueio total)",
    discard: "Descartar (FlowSpec)",
    rate_limit: "Limitar banda (FlowSpec)",
  };
  var MITIGATION_KIND_KEYS = ["rtbh", "discard", "rate_limit"];
  // só esses 2 tipos têm limiar de tamanho de pacote configurável — nos outros o
  // tamanho do pacote nunca fez parte do match (ver bgp/flowspec.py no backend)
  var MITIGATION_PKT_LEN_TYPES = { dns_amp: true, ntp_amp: true };

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
      prefixMeta: {},
      prefixesLoaded: false,
      _requestSeq: 0,
      _resolved: {},
    },
    kpiHistory: { bps: [], pps: [] },
    cgSuspiciousView: "open",
    cgSuspicious: [],
    cgTopWindow: 21600,
    cgTogglesLoaded: {},
    cgTogglesPending: {},
    fgTogglesLoaded: {},
    fgTogglesPending: {},
    fgMitigationLoaded: {},
    fgMitigationPending: {},
  };

  // Compartilhado pelas telas de toggles do ClientGuard e do FlowGuard — mostra quantas
  // mudanças estão pendentes (não aplicadas ainda) direto no rótulo do botão.
  function updateTogglesApplyBtn(btnId, pendingCount) {
    var btn = document.getElementById(btnId);
    if (!btn) return;
    btn.disabled = pendingCount === 0;
    btn.textContent = pendingCount > 0
      ? "Aplicar " + pendingCount + " " + (pendingCount === 1 ? "alteração" : "alterações")
      : "Aplicar novas configurações";
  }

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

  function kpiCard(label, valueHtml, sub, trendHtml) {
    return (
      '<div class="fg-card"><div class="fg-kpi-label">' + escapeHtml(label) + '</div>' +
      '<div class="fg-kpi-value">' + valueHtml + '</div>' +
      '<div class="fg-kpi-sub">' + escapeHtml(sub || "") + (trendHtml || "") + '</div></div>'
    );
  }

  // seta de tendência comparando o valor atual com a média da primeira
  // metade do minuto de histórico em memória (suaviza ruído de um poll só) —
  // só aparece depois de ter buffer suficiente e quando a variação é notável
  function kpiTrend(key, current) {
    var buf = state.kpiHistory[key];
    var html = "";
    if (buf.length >= 6) {
      var half = Math.floor(buf.length / 2);
      var prevAvg = buf.slice(0, half).reduce(function (a, b) { return a + b; }, 0) / half;
      if (prevAvg > 0) {
        var deltaPct = ((current - prevAvg) / prevAvg) * 100;
        if (Math.abs(deltaPct) >= 5) {
          var arrow = deltaPct > 0 ? "▲" : "▼";
          html = '<span class="fg-trend">' + arrow + " " + Math.abs(deltaPct).toFixed(0) + "% vs. último min.</span>";
        }
      }
    }
    buf.push(current);
    if (buf.length > 12) buf.shift();
    return html;
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

    var bgp = data.bgp || {};
    var bgpUp = bgp.peer_state === "up";
    var bgpHtml = bgpUp
      ? '<span class="fg-dot fg-dot-up"></span>Up'
      : '<span class="fg-dot fg-dot-down"></span>Down/Idle';
    var bgpSub = bgp.peer_ip
      ? (bgpUp ? "peer " + bgp.peer_ip : (bgp.detail || bgp.reason || "peer " + bgp.peer_ip))
      : "";

    var bpsTrend = kpiTrend("bps", s.bps);
    var ppsTrend = kpiTrend("pps", s.pps);

    el.innerHTML =
      kpiCard("Tráfego", fmtBps(s.bps), s.flows + " flows/s", bpsTrend) +
      kpiCard("Pacotes/s", Number(s.pps).toLocaleString("pt-BR"), "", ppsTrend) +
      kpiCard("Ataques Ativos", s.active_attacks, s.active_attacks > 0 ? "requer atenção" : "tudo normal") +
      kpiCard("Regras FlowSpec", s.active_rules, "") +
      kpiCard("BGP (ExaBGP)", bgpHtml, bgpSub) +
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
        var areaPoints = points + " " + width + "," + height + " 0," + height;
        var last = series[series.length - 1][p.key];
        return (
          '<div class="fg-spark"><span class="fg-spark-label" style="color:' + p.color + '">' + p.label + "</span>" +
          '<svg width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + " " + height + '">' +
          '<line x1="0" y1="' + height / 2 + '" x2="' + width + '" y2="' + height / 2 + '" stroke="#30363d" stroke-width="1" stroke-dasharray="2,2" />' +
          '<polygon points="' + areaPoints + '" fill="' + p.color + '" fill-opacity="0.15" />' +
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
      drawLineChart(canvas, series, [{ key: "bps", color: "#58a6ff", label: "tráfego (bps)" }]);
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
          '<tr data-rule-id="' + r.id + '"><td>' + escapeHtml(r.src_prefix || "-") + "</td><td>" +
          escapeHtml(r.dst_prefix || "-") + "</td><td>" +
          escapeHtml(r.protocol || "-") + "</td><td>" + escapeHtml(r.action) + "</td><td>" +
          new Date(r.expires_at * 1000).toLocaleString() + '</td><td><button class="fg-btn" data-action="del">Remover</button></td></tr>'
        );
      })
      .join("");

    el.innerHTML =
      "<table><thead><tr><th>Origem</th><th>Destino</th><th>Protocolo</th><th>Ação</th><th>Expira</th><th></th></tr></thead><tbody>" +
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

  function onBlockSubmit() {
    var input = document.getElementById("fg-block-ip");
    var ttlSelect = document.getElementById("fg-block-ttl");
    var btn = document.getElementById("fg-block-submit");
    var ip = (input.value || "").trim();
    if (!ip) {
      showToast("Informe um IP ou CIDR", "error");
      return;
    }
    btn.disabled = true;
    postJson(RULES_ENDPOINT, { src_prefix: ip, action: "discard", ttl_s: Number(ttlSelect.value) })
      .then(function (resp) {
        showToast(resp.ok ? "IP bloqueado: " + ip : resp.error, resp.ok ? "success" : "error");
        if (resp.ok) input.value = "";
        loadRules();
      })
      .finally(function () { btn.disabled = false; });
  }

  // --- modo guerra: SSH em vários equipamentos de uma vez -----------------

  function renderWarmodeDevices(data) {
    var el = document.getElementById("fg-warmode-devices");
    var confirmBtn = document.getElementById("fg-warmode-confirm-btn");
    if (!data.ok) {
      showError(el, data.error || "erro desconhecido");
      confirmBtn.disabled = true;
      return;
    }
    if (!data.devices.length) {
      el.innerHTML = '<p class="fg-error">Nenhum equipamento configurado (warmode.yaml não existe ou está vazio no servidor).</p>';
      confirmBtn.disabled = true;
      return;
    }
    var withoutCommands = data.devices.filter(function (d) { return !d.n_commands; });
    el.innerHTML = data.devices
      .map(function (d) {
        var cmdLabel = d.n_commands
          ? d.n_commands + " comando(s)"
          : '<span class="fg-error">0 comandos — nada vai rodar aqui</span>';
        return '<div class="fg-warmode-device-row"><span>' + escapeHtml(d.name) + " (" + escapeHtml(d.host || "-") +
          ", " + escapeHtml(d.device_type || "-") + ")</span><span>" + cmdLabel + "</span></div>";
      })
      .join("");
    confirmBtn.disabled = withoutCommands.length === data.devices.length;
  }

  function warmodeExecShowStep(step) {
    ["needs-setup", "lock", "content"].forEach(function (s) {
      document.getElementById("fg-warmode-exec-" + s).hidden = s !== step;
    });
  }

  function loadWarmodeExecDevices() {
    document.getElementById("fg-warmode-results").innerHTML = "";
    document.getElementById("fg-warmode-devices").textContent = "Carregando...";
    warmodeGetJson(WARMODE_ENDPOINT + "?warmode_token=" + encodeURIComponent(warmodeToken)).then(function (r) {
      if (r.status === 401 || !r.data.ok) {
        warmodeToken = null;
        warmodeExecShowStep("lock");
        document.getElementById("fg-warmode-exec-unlock-status").textContent = r.data.error || "sessão expirada, desbloqueie de novo";
        return;
      }
      renderWarmodeDevices(r.data);
    });
  }

  function openWarmodeModal() {
    document.getElementById("fg-warmode-overlay").hidden = false;
    document.getElementById("fg-warmode-exec-unlock-status").textContent = "";
    if (warmodeToken) {
      warmodeExecShowStep("content");
      loadWarmodeExecDevices();
      return;
    }
    warmodeGetJson(WARMODE_AUTH_ENDPOINT).then(function (r) {
      if (!r.data.ok) {
        showToast(r.data.error || "falha ao consultar configuração do Modo Guerra", "error");
        return;
      }
      warmodeExecShowStep(r.data.configured ? "lock" : "needs-setup");
    });
  }

  function onWarmodeExecUnlockSubmit() {
    var pass = document.getElementById("fg-warmode-exec-unlock-pass").value;
    var status = document.getElementById("fg-warmode-exec-unlock-status");
    warmodePostJson(WARMODE_AUTH_ENDPOINT, { action: "unlock", password: pass }).then(function (r) {
      if (!r.data.ok) { status.textContent = r.data.error || "senha incorreta"; return; }
      warmodeToken = r.data.warmode_token;
      document.getElementById("fg-warmode-exec-unlock-pass").value = "";
      status.textContent = "";
      warmodeExecShowStep("content");
      loadWarmodeExecDevices();
    });
  }

  function closeWarmodeModal() {
    document.getElementById("fg-warmode-overlay").hidden = true;
  }

  function renderWarmodeResults(data) {
    var el = document.getElementById("fg-warmode-results");
    if (!data.ok) {
      showError(el, data.error || "erro desconhecido");
      return;
    }
    el.innerHTML = data.results
      .map(function (r) {
        var cls = r.ok ? "ok" : "fail";
        var label = r.ok ? "OK" : "FALHOU";
        var body = r.ok ? (r.output || "(sem saída)") : (r.error || "erro desconhecido");
        return (
          '<div class="fg-warmode-result ' + cls + '"><strong>' + (r.ok ? "✅" : "❌") + " " + label + " — " +
          escapeHtml(r.device) + '</strong> (' + r.elapsed_s + 's)<pre>' + escapeHtml(body) + "</pre></div>"
        );
      })
      .join("");
  }

  function initWarmode() {
    var openBtn = document.getElementById("fg-warmode-open-btn");
    if (openBtn) openBtn.addEventListener("click", openWarmodeModal);
    var closeBtn = document.getElementById("fg-warmode-close-btn");
    if (closeBtn) closeBtn.addEventListener("click", closeWarmodeModal);
    var confirmBtn = document.getElementById("fg-warmode-confirm-btn");
    if (confirmBtn) confirmBtn.addEventListener("click", onWarmodeConfirm);
    var execUnlockBtn = document.getElementById("fg-warmode-exec-unlock-btn");
    if (execUnlockBtn) execUnlockBtn.addEventListener("click", onWarmodeExecUnlockSubmit);
    initWarmodeCfg();
  }

  // --- modo guerra: configuração (protegida por senha própria) -----------

  function warmodeGetJson(url) {
    var token = encodeURIComponent(getToken());
    var sep = url.indexOf("?") === -1 ? "?" : "&";
    return fetch(url + sep + "token=" + token, { credentials: "same-origin" }).then(function (resp) {
      return resp.json().then(function (data) { return { status: resp.status, data: data }; });
    });
  }

  function warmodePostJson(url, body) {
    var token = encodeURIComponent(getToken());
    return fetch(url + "?token=" + token, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then(function (resp) {
      return resp.json().then(function (data) { return { status: resp.status, data: data }; });
    });
  }

  function warmodeCfgShowStep(step) {
    ["setup", "lock", "editor"].forEach(function (s) {
      document.getElementById("fg-warmode-cfg-" + s).hidden = s !== step;
    });
  }

  function openWarmodeCfgModal() {
    document.getElementById("fg-warmode-cfg-overlay").hidden = false;
    document.getElementById("fg-warmode-setup-status").textContent = "";
    document.getElementById("fg-warmode-unlock-status").textContent = "";
    document.getElementById("fg-warmode-save-status").textContent = "";
    if (warmodeToken) {
      loadWarmodeCfgDevices();
      return;
    }
    warmodeGetJson(WARMODE_AUTH_ENDPOINT).then(function (r) {
      if (!r.data.ok) {
        showToast(r.data.error || "falha ao consultar configuração do Modo Guerra", "error");
        return;
      }
      warmodeCfgShowStep(r.data.configured ? "lock" : "setup");
    });
  }

  function closeWarmodeCfgModal() {
    document.getElementById("fg-warmode-cfg-overlay").hidden = true;
  }

  function onWarmodeSetupSubmit() {
    var p1 = document.getElementById("fg-warmode-setup-pass").value;
    var p2 = document.getElementById("fg-warmode-setup-pass2").value;
    var status = document.getElementById("fg-warmode-setup-status");
    if (p1.length < 6) { status.textContent = "senha precisa de pelo menos 6 caracteres"; return; }
    if (p1 !== p2) { status.textContent = "as senhas não coincidem"; return; }
    warmodePostJson(WARMODE_AUTH_ENDPOINT, { action: "setup", password: p1 }).then(function (r) {
      if (!r.data.ok) { status.textContent = r.data.error || "erro ao definir senha"; return; }
      warmodeToken = r.data.warmode_token;
      document.getElementById("fg-warmode-setup-pass").value = "";
      document.getElementById("fg-warmode-setup-pass2").value = "";
      loadWarmodeCfgDevices();
    });
  }

  function onWarmodeUnlockSubmit() {
    var pass = document.getElementById("fg-warmode-unlock-pass").value;
    var status = document.getElementById("fg-warmode-unlock-status");
    warmodePostJson(WARMODE_AUTH_ENDPOINT, { action: "unlock", password: pass }).then(function (r) {
      if (!r.data.ok) { status.textContent = r.data.error || "senha incorreta"; return; }
      warmodeToken = r.data.warmode_token;
      document.getElementById("fg-warmode-unlock-pass").value = "";
      status.textContent = "";
      loadWarmodeCfgDevices();
    });
  }

  function warmodeDeviceCardHtml(d) {
    d = d || { name: "", host: "", port: 22, device_type: "", username: "", has_password: false, enable_mode: false, commands: [] };
    return (
      '<div class="fg-wm-device">' +
      '<div class="fg-wm-row-top"><strong>' + (d.name ? escapeHtml(d.name) : "(novo equipamento)") +
      '</strong><button class="fg-btn" data-action="remove-device">Remover</button></div>' +
      '<div class="fg-wm-device-grid">' +
      '<div><label>Nome</label><input type="text" class="fg-wm-name" value="' + escapeHtml(d.name) + '" placeholder="ex: NE8000 borda"></div>' +
      '<div><label>Host</label><input type="text" class="fg-wm-host" value="' + escapeHtml(d.host) + '" placeholder="IP de gerência"></div>' +
      '<div><label>Porta</label><input type="text" class="fg-wm-port" value="' + (d.port || 22) + '"></div>' +
      '<div><label>Tipo (driver Netmiko)</label><input type="text" class="fg-wm-device-type" value="' + escapeHtml(d.device_type) +
      '" placeholder="huawei_vrp, a10, cisco_ios..." list="fg-wm-device-types"></div>' +
      '<div><label>Usuário</label><input type="text" class="fg-wm-username" value="' + escapeHtml(d.username) + '"></div>' +
      '<div><label>Senha' + (d.has_password ? ' (já definida — deixe em branco pra manter)' : '') +
      '</label><input type="password" class="fg-wm-password" placeholder="' + (d.has_password ? "••••••••" : "definir senha") + '"></div>' +
      "</div>" +
      '<label style="margin-top:0.5rem;"><input type="checkbox" class="fg-wm-enable-mode"' + (d.enable_mode ? " checked" : "") +
      '> precisa de "enable" antes dos comandos</label>' +
      '<label>Comandos (um por linha)</label>' +
      '<textarea class="fg-wm-commands" placeholder="ex: display version">' + escapeHtml((d.commands || []).join("\n")) + "</textarea>" +
      "</div>"
    );
  }

  function renderWarmodeCfgDevices(devices) {
    var el = document.getElementById("fg-warmode-cfg-devices");
    el.innerHTML = devices.map(warmodeDeviceCardHtml).join("") ||
      '<p class="fg-kpi-sub">Nenhum equipamento cadastrado ainda.</p>';
  }

  function loadWarmodeCfgDevices() {
    warmodeGetJson(WARMODE_CFG_ENDPOINT + "?warmode_token=" + encodeURIComponent(warmodeToken)).then(function (r) {
      if (r.status === 401 || !r.data.ok) {
        warmodeToken = null;
        warmodeCfgShowStep("lock");
        document.getElementById("fg-warmode-unlock-status").textContent = r.data.error || "sessão expirada, desbloqueie de novo";
        return;
      }
      renderWarmodeCfgDevices(r.data.devices);
      warmodeCfgShowStep("editor");
    });
  }

  function collectWarmodeCfgDevices() {
    return Array.prototype.map.call(document.querySelectorAll("#fg-warmode-cfg-devices .fg-wm-device"), function (card) {
      var commandsRaw = card.querySelector(".fg-wm-commands").value;
      return {
        name: card.querySelector(".fg-wm-name").value.trim(),
        host: card.querySelector(".fg-wm-host").value.trim(),
        port: Number(card.querySelector(".fg-wm-port").value) || 22,
        device_type: card.querySelector(".fg-wm-device-type").value.trim(),
        username: card.querySelector(".fg-wm-username").value.trim(),
        password: card.querySelector(".fg-wm-password").value,
        enable_mode: card.querySelector(".fg-wm-enable-mode").checked,
        commands: commandsRaw.split("\n").map(function (c) { return c.trim(); }).filter(Boolean),
      };
    });
  }

  function onWarmodeAddDevice() {
    document.getElementById("fg-warmode-cfg-devices").insertAdjacentHTML("beforeend", warmodeDeviceCardHtml(null));
  }

  function onWarmodeCfgDevicesClick(ev) {
    var btn = ev.target.closest("button[data-action='remove-device']");
    if (!btn) return;
    btn.closest(".fg-wm-device").remove();
  }

  function onWarmodeSaveClick() {
    var status = document.getElementById("fg-warmode-save-status");
    var devices = collectWarmodeCfgDevices();
    for (var i = 0; i < devices.length; i++) {
      if (!devices[i].host || !devices[i].device_type) {
        status.className = "fg-error";
        status.textContent = "todo equipamento precisa de host e tipo (device_type)";
        return;
      }
    }
    warmodePostJson(WARMODE_CFG_ENDPOINT, { warmode_token: warmodeToken, devices: devices }).then(function (r) {
      if (r.status === 401 || !r.data.ok) {
        status.className = "fg-error";
        status.textContent = r.data.error || "erro ao salvar";
        if (r.status === 401) { warmodeToken = null; warmodeCfgShowStep("lock"); }
        return;
      }
      status.className = "fg-ok";
      status.textContent = "salvo.";
      loadWarmodeCfgDevices();
    });
  }

  function onWarmodeChangepassToggle() {
    var box = document.getElementById("fg-warmode-changepass-box");
    box.hidden = !box.hidden;
  }

  function onWarmodeChangepassSubmit() {
    var oldPass = document.getElementById("fg-warmode-old-pass").value;
    var newPass = document.getElementById("fg-warmode-new-pass").value;
    var newPass2 = document.getElementById("fg-warmode-new-pass2").value;
    var status = document.getElementById("fg-warmode-changepass-status");
    if (newPass.length < 6) { status.textContent = "nova senha precisa de pelo menos 6 caracteres"; return; }
    if (newPass !== newPass2) { status.textContent = "as senhas novas não coincidem"; return; }
    warmodePostJson(WARMODE_AUTH_ENDPOINT, {
      action: "change", warmode_token: warmodeToken, old_password: oldPass, new_password: newPass,
    }).then(function (r) {
      if (!r.data.ok) { status.textContent = r.data.error || "erro ao trocar senha"; return; }
      status.textContent = "";
      document.getElementById("fg-warmode-old-pass").value = "";
      document.getElementById("fg-warmode-new-pass").value = "";
      document.getElementById("fg-warmode-new-pass2").value = "";
      document.getElementById("fg-warmode-changepass-box").hidden = true;
      showToast("senha do Modo Guerra alterada", "success");
    });
  }

  function onWarmodeLockNow() {
    warmodeToken = null;
    warmodeCfgShowStep("lock");
  }

  function initWarmodeCfg() {
    var openBtn = document.getElementById("fg-warmode-cfg-open-btn");
    if (openBtn) openBtn.addEventListener("click", openWarmodeCfgModal);
    var closeBtn = document.getElementById("fg-warmode-cfg-close-btn");
    if (closeBtn) closeBtn.addEventListener("click", closeWarmodeCfgModal);
    var setupBtn = document.getElementById("fg-warmode-setup-btn");
    if (setupBtn) setupBtn.addEventListener("click", onWarmodeSetupSubmit);
    var unlockBtn = document.getElementById("fg-warmode-unlock-btn");
    if (unlockBtn) unlockBtn.addEventListener("click", onWarmodeUnlockSubmit);
    var addBtn = document.getElementById("fg-warmode-add-device-btn");
    if (addBtn) addBtn.addEventListener("click", onWarmodeAddDevice);
    var devicesEl = document.getElementById("fg-warmode-cfg-devices");
    if (devicesEl) devicesEl.addEventListener("click", onWarmodeCfgDevicesClick);
    var saveBtn = document.getElementById("fg-warmode-save-btn");
    if (saveBtn) saveBtn.addEventListener("click", onWarmodeSaveClick);
    var changepassToggleBtn = document.getElementById("fg-warmode-changepass-toggle-btn");
    if (changepassToggleBtn) changepassToggleBtn.addEventListener("click", onWarmodeChangepassToggle);
    var changepassBtn = document.getElementById("fg-warmode-changepass-btn");
    if (changepassBtn) changepassBtn.addEventListener("click", onWarmodeChangepassSubmit);
    var lockBtn = document.getElementById("fg-warmode-lock-btn");
    if (lockBtn) lockBtn.addEventListener("click", onWarmodeLockNow);
  }

  function onWarmodeConfirm() {
    var btn = document.getElementById("fg-warmode-confirm-btn");
    btn.disabled = true;
    document.getElementById("fg-warmode-results").innerHTML = '<p class="fg-kpi-sub">Executando em paralelo em todos os equipamentos...</p>';
    warmodePostJson(WARMODE_ENDPOINT, { warmode_token: warmodeToken })
      .then(function (r) {
        if (r.status === 401) {
          warmodeToken = null;
          warmodeExecShowStep("lock");
          document.getElementById("fg-warmode-exec-unlock-status").textContent = r.data.error || "sessão expirada, desbloqueie de novo";
          return;
        }
        renderWarmodeResults(r.data);
        showToast(r.data.ok ? "Modo Guerra executado" : r.data.error, r.data.ok ? "success" : "error");
      })
      .catch(function (err) {
        showError(document.getElementById("fg-warmode-results"), "falha ao executar");
        console.error("flowguard.js:", err);
      })
      .finally(function () { btn.disabled = false; });
  }

  // --- config. roteador de borda: templates validados via SSH ------------
  // reaproveita warmodeGetJson/warmodePostJson (mesma sessão do Modo Guerra)

  function rcShowStep(step) {
    ["needs-setup", "lock", "content"].forEach(function (s) {
      document.getElementById("fg-rc-" + s).hidden = s !== step;
    });
  }

  function rcFieldInputHtml(f) {
    var id = "fg-rc-field-" + f.name;
    if (f.type === "enum") {
      var opts = (f.options || [])
        .map(function (o) {
          var sel = f.default === o ? " selected" : "";
          return '<option value="' + escapeHtml(o) + '"' + sel + ">" + escapeHtml(o) + "</option>";
        })
        .join("");
      return '<select id="' + id + '" data-field="' + escapeHtml(f.name) + '">' + opts + "</select>";
    }
    var placeholder = f.help || f.label;
    var defaultVal = f.default != null ? ' value="' + escapeHtml(String(f.default)) + '"' : "";
    return (
      '<input type="text" id="' + id + '" data-field="' + escapeHtml(f.name) +
      '" placeholder="' + escapeHtml(placeholder) + '"' + defaultVal + ">"
    );
  }

  function renderRcFields(template) {
    var el = document.getElementById("fg-rc-fields");
    if (!template) {
      el.innerHTML = "";
      return;
    }
    el.innerHTML = template.fields
      .map(function (f) {
        return "<label>" + escapeHtml(f.label) + (f.required ? " *" : "") + rcFieldInputHtml(f) + "</label>";
      })
      .join("");
  }

  function rcSelectedTemplate() {
    var id = document.getElementById("fg-rc-template-select").value;
    return rcTemplates.filter(function (t) { return t.id === id; })[0] || null;
  }

  function collectRcValues(template) {
    var values = {};
    template.fields.forEach(function (f) {
      var input = document.getElementById("fg-rc-field-" + f.name);
      values[f.name] = input ? input.value : "";
    });
    return values;
  }

  function onRcTemplateChange() {
    var template = rcSelectedTemplate();
    renderRcFields(template);
    document.getElementById("fg-rc-preview").innerHTML = "";
    document.getElementById("fg-rc-apply-btn").disabled = true;
    document.getElementById("fg-rc-preview-btn").disabled = !template;
    var statusEl = document.getElementById("fg-rc-device-status");
    if (template && !template.device_ready) {
      statusEl.innerHTML = '<span class="fg-error">Equipamento "' + escapeHtml(template.device_name) +
        '" ainda não está configurado em warmode.yaml (⚙️ Modo Guerra) — a aplicação vai falhar até isso ser preenchido.</span>';
    } else {
      statusEl.textContent = "";
    }
  }

  function renderRcTemplateSelect(templates) {
    rcTemplates = templates;
    var select = document.getElementById("fg-rc-template-select");
    select.innerHTML =
      '<option value="">selecione um template...</option>' +
      templates
        .map(function (t) { return '<option value="' + escapeHtml(t.id) + '">' + escapeHtml(t.label) + "</option>"; })
        .join("");
  }

  function onRcPreviewClick() {
    var template = rcSelectedTemplate();
    if (!template) return;
    var values = collectRcValues(template);
    var previewEl = document.getElementById("fg-rc-preview");
    previewEl.innerHTML = '<p class="fg-kpi-sub">Validando...</p>';
    warmodePostJson(ROUTERCFG_ENDPOINT, { warmode_token: warmodeToken, action: "preview", template_id: template.id, values: values })
      .then(function (r) {
        if (r.status === 401) { warmodeToken = null; rcShowStep("lock"); return; }
        if (!r.data.ok) {
          showError(previewEl, r.data.error || "erro de validação");
          document.getElementById("fg-rc-apply-btn").disabled = true;
          return;
        }
        var p = r.data.preview;
        previewEl.innerHTML =
          '<div class="fg-rc-job"><strong>Comandos a aplicar:</strong><pre>' + escapeHtml(p.commands.join("\n")) + "</pre>" +
          '<strong>Reversão (se necessário):</strong><pre>' + escapeHtml(p.undo_commands.join("\n")) + "</pre></div>";
        document.getElementById("fg-rc-apply-btn").disabled = false;
      })
      .catch(function (err) {
        showError(previewEl, "falha ao consultar o preview");
        console.error("flowguard.js:", err);
      });
  }

  function rcStopCountdown() {
    if (rcCountdownTimer) { clearInterval(rcCountdownTimer); rcCountdownTimer = null; }
  }

  function rcStartCountdown(job) {
    rcStopCountdown();
    var el = document.getElementById("fg-rc-active-job");
    function tick() {
      var remaining = Math.max(0, Math.round(job.expires_at - Date.now() / 1000));
      var span = el.querySelector(".fg-rc-countdown");
      if (!span) { rcStopCountdown(); return; }
      if (remaining <= 0) {
        span.textContent = "revertendo automaticamente...";
        rcStopCountdown();
        setTimeout(loadRouterCfgData, 3000);
        return;
      }
      var m = Math.floor(remaining / 60), s = remaining % 60;
      span.textContent = m + "m " + (s < 10 ? "0" : "") + s + "s";
    }
    tick();
    rcCountdownTimer = setInterval(tick, 1000);
  }

  function renderActiveJob(job) {
    var el = document.getElementById("fg-rc-active-job");
    if (!job || job.status !== "pending_confirm") {
      el.innerHTML = "";
      rcStopCountdown();
      return;
    }
    el.innerHTML =
      '<div class="fg-rc-job status-' + escapeHtml(job.status) + '"><strong>⏳ Aguardando confirmação — ' + escapeHtml(job.label) +
      '</strong><p class="fg-kpi-sub">Reverte automaticamente em <span class="fg-rc-countdown"></span> se não for confirmada.</p>' +
      '<pre>' + escapeHtml(job.commands.join("\n")) + '</pre>' +
      '<div class="fg-toolbar">' +
      '<button class="fg-btn" data-rc-confirm="' + escapeHtml(job.id) + '">Confirmar mudança</button>' +
      '<button class="fg-btn fg-btn-danger" data-rc-revert="' + escapeHtml(job.id) + '">Reverter agora</button>' +
      "</div></div>";
    rcStartCountdown(job);
  }

  function onRcApplyClick() {
    var template = rcSelectedTemplate();
    if (!template) return;
    var values = collectRcValues(template);
    if (!window.confirm('Isto vai aplicar "' + template.label + '" de verdade no roteador de borda agora. Confirma?')) return;
    var btn = document.getElementById("fg-rc-apply-btn");
    btn.disabled = true;
    warmodePostJson(ROUTERCFG_ENDPOINT, { warmode_token: warmodeToken, action: "apply", template_id: template.id, values: values })
      .then(function (r) {
        if (r.status === 401) { warmodeToken = null; rcShowStep("lock"); return; }
        if (!r.data.ok) {
          showToast(r.data.error || "falha ao aplicar", "error");
          btn.disabled = false;
          return;
        }
        showToast("Aplicado — aguardando confirmação", "success");
        document.getElementById("fg-rc-preview").innerHTML = "";
        renderActiveJob(r.data.job);
        loadRouterCfgHistory();
      })
      .catch(function (err) {
        showToast("falha ao aplicar", "error");
        console.error("flowguard.js:", err);
        btn.disabled = false;
      });
  }

  function onRcActiveJobClick(ev) {
    var confirmBtn = ev.target.closest("[data-rc-confirm]");
    var revertBtn = ev.target.closest("[data-rc-revert]");
    if (confirmBtn) {
      warmodePostJson(ROUTERCFG_ENDPOINT, { warmode_token: warmodeToken, action: "confirm", job_id: confirmBtn.getAttribute("data-rc-confirm") })
        .then(function (r) {
          if (r.status === 401) { warmodeToken = null; rcShowStep("lock"); return; }
          showToast(r.data.ok ? "Confirmado" : (r.data.error || "erro"), r.data.ok ? "success" : "error");
          if (r.data.ok) { renderActiveJob(null); loadRouterCfgHistory(); }
        });
    }
    if (revertBtn) {
      if (!window.confirm("Reverter esta mudança agora?")) return;
      warmodePostJson(ROUTERCFG_ENDPOINT, { warmode_token: warmodeToken, action: "revert", job_id: revertBtn.getAttribute("data-rc-revert") })
        .then(function (r) {
          if (r.status === 401) { warmodeToken = null; rcShowStep("lock"); return; }
          showToast(r.data.ok ? "Revertido" : (r.data.error || "erro"), r.data.ok ? "success" : "error");
          if (r.data.ok) { renderActiveJob(null); loadRouterCfgHistory(); }
        });
    }
  }

  function renderRcHistory(jobs) {
    var el = document.getElementById("fg-rc-history");
    if (!jobs.length) {
      el.innerHTML = '<p class="fg-kpi-sub">Nenhuma mudança registrada ainda.</p>';
      return;
    }
    var statusLabel = {
      pending_confirm: "aguardando confirmação", confirmed: "confirmada",
      reverted: "revertida (manual)", auto_reverted: "revertida (automática)",
    };
    var rows = jobs
      .map(function (j) {
        var when = new Date(j.created_at * 1000).toLocaleString("pt-BR");
        return (
          "<tr><td>" + when + "</td><td>" + escapeHtml(j.label) + "</td><td>" +
          escapeHtml(statusLabel[j.status] || j.status) + "</td></tr>"
        );
      })
      .join("");
    el.innerHTML = "<table><thead><tr><th>Quando</th><th>Template</th><th>Status</th></tr></thead><tbody>" + rows + "</tbody></table>";
  }

  function loadRouterCfgHistory() {
    warmodeGetJson(ROUTERCFG_ENDPOINT + "?warmode_token=" + encodeURIComponent(warmodeToken)).then(function (r) {
      if (r.status === 401 || !r.data.ok) return;
      renderRcHistory(r.data.history || []);
    });
  }

  function loadRouterCfgData() {
    document.getElementById("fg-rc-history").textContent = "Carregando...";
    warmodeGetJson(ROUTERCFG_ENDPOINT + "?warmode_token=" + encodeURIComponent(warmodeToken)).then(function (r) {
      if (r.status === 401 || !r.data.ok) {
        warmodeToken = null;
        rcShowStep("lock");
        document.getElementById("fg-rc-unlock-status").textContent = r.data.error || "sessão expirada, desbloqueie de novo";
        return;
      }
      renderRcTemplateSelect(r.data.templates || []);
      renderRcFields(null);
      renderRcHistory(r.data.history || []);
      var pending = (r.data.history || []).filter(function (j) { return j.status === "pending_confirm"; })[0];
      renderActiveJob(pending || null);
    });
  }

  function openRouterCfgModal() {
    document.getElementById("fg-routercfg-overlay").hidden = false;
    document.getElementById("fg-rc-unlock-status").textContent = "";
    if (warmodeToken) {
      rcShowStep("content");
      loadRouterCfgData();
      return;
    }
    warmodeGetJson(WARMODE_AUTH_ENDPOINT).then(function (r) {
      if (!r.data.ok) {
        showToast(r.data.error || "falha ao consultar configuração do Modo Guerra", "error");
        return;
      }
      rcShowStep(r.data.configured ? "lock" : "needs-setup");
    });
  }

  function onRcUnlockSubmit() {
    var pass = document.getElementById("fg-rc-unlock-pass").value;
    var status = document.getElementById("fg-rc-unlock-status");
    warmodePostJson(WARMODE_AUTH_ENDPOINT, { action: "unlock", password: pass }).then(function (r) {
      if (!r.data.ok) { status.textContent = r.data.error || "senha incorreta"; return; }
      warmodeToken = r.data.warmode_token;
      document.getElementById("fg-rc-unlock-pass").value = "";
      status.textContent = "";
      rcShowStep("content");
      loadRouterCfgData();
    });
  }

  function closeRouterCfgModal() {
    document.getElementById("fg-routercfg-overlay").hidden = true;
    rcStopCountdown();
  }

  function initRouterCfg() {
    var openBtn = document.getElementById("fg-routercfg-open-btn");
    if (openBtn) openBtn.addEventListener("click", openRouterCfgModal);
    var closeBtn = document.getElementById("fg-rc-close-btn");
    if (closeBtn) closeBtn.addEventListener("click", closeRouterCfgModal);
    var unlockBtn = document.getElementById("fg-rc-unlock-btn");
    if (unlockBtn) unlockBtn.addEventListener("click", onRcUnlockSubmit);
    var templateSelect = document.getElementById("fg-rc-template-select");
    if (templateSelect) templateSelect.addEventListener("change", onRcTemplateChange);
    var previewBtn = document.getElementById("fg-rc-preview-btn");
    if (previewBtn) previewBtn.addEventListener("click", onRcPreviewClick);
    var applyBtn = document.getElementById("fg-rc-apply-btn");
    if (applyBtn) applyBtn.addEventListener("click", onRcApplyClick);
    var activeJobEl = document.getElementById("fg-rc-active-job");
    if (activeJobEl) activeJobEl.addEventListener("click", onRcActiveJobClick);
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

  // ordem fixa de exibição das funções na aba Configurações — mesmas chaves de
  // configio.DEFAULT_FEATURE_TOGGLES no backend do ClientGuard
  var CG_TOGGLE_META = [
    { key: "scan_horizontal", label: "Scan horizontal", desc: "1 cliente falando com muitos hosts distintos na mesma porta — reconhecimento de rede." },
    { key: "scan_vertical", label: "Scan vertical", desc: "1 cliente falando com muitas portas distintas no mesmo host — busca de vulnerabilidade." },
    { key: "amplifier", label: "Amplificador hospedado", desc: "serviço UDP do cliente (DNS/NTP/SSDP/...) respondendo em volume alto pra fora — refletor de amplificação." },
    { key: "spam", label: "Spam bot", desc: "volume alto de conexões outbound em portas de e-mail (25/465/587) pra muitos destinos." },
    { key: "malicious_contact", label: "Contato com IP malicioso", desc: "tráfego com IP de reputação conhecida (threat feed) — C2/malware/spam." },
    { key: "coordinated_destination", label: "Destino coordenado", desc: "vários clientes falando com o mesmo destino externo ao mesmo tempo — possível botnet." },
    { key: "dns_tunneling", label: "Túnel DNS", desc: "volume anômalo de queries DNS pequenas pro mesmo servidor — possível exfiltração." },
    { key: "ai_explanations", label: "Explicação por IA", desc: "gera uma explicação em texto (Claude) pra cada sinal novo disparado por qualquer detector acima." },
  ];

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

  function loadClientGuardStatus() {
    getJson(CG_STATUS_ENDPOINT).then(function (data) {
      renderCgKpis(data.ok ? data.status : null);
    }).catch(function (err) {
      showError(document.getElementById("cg-kpis"), "falha ao consultar status do ClientGuard");
      console.error("flowguard.js:", err);
    });
  }

  // --- ClientGuard: top clientes por consumo de dados ----------------------

  function renderCgTop(rows) {
    var el = document.getElementById("cg-top");
    if (!el) return;
    if (!rows.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum tráfego na janela selecionada.</p>';
      return;
    }
    var body = rows
      .map(function (r) {
        return (
          '<tr data-src-ip="' + escapeHtml(r.src_ip) + '"><td>' + escapeHtml(r.src_ip) + "</td><td>" +
          escapeHtml(r.customer_prefix || "-") + "</td><td>" + fmtBytes(r.bytes) + "</td><td>" +
          (r.packets || 0).toLocaleString("pt-BR") + "</td><td>" + (r.flows || 0).toLocaleString("pt-BR") +
          '</td><td><button class="fg-btn" data-action="detail">Detalhes</button></td></tr>'
        );
      })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>src_ip</th><th>Cliente</th><th>Tráfego</th><th>Pacotes</th><th>Flows</th>" +
      "<th>Ações</th></tr></thead><tbody>" + body + "</tbody></table>";
  }

  function loadCgTop() {
    getJson(CG_TOP_ENDPOINT + "?window_s=" + state.cgTopWindow + "&limit=20").then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("cg-top"), data.error || "erro desconhecido");
        return;
      }
      renderCgTop(data.top || []);
    }).catch(function (err) {
      showError(document.getElementById("cg-top"), "falha ao consultar top clientes");
      console.error("flowguard.js:", err);
    });
  }

  function initCgTopWindowControls() {
    var toggle = document.getElementById("cg-top-window");
    if (!toggle) return;
    toggle.addEventListener("click", function (ev) {
      var btn = ev.target.closest(".fg-toggle-btn");
      if (!btn) return;
      state.cgTopWindow = Number(btn.getAttribute("data-window-s"));
      toggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
      loadCgTop();
      var detailEl = document.getElementById("cg-client-detail");
      if (detailEl) detailEl.innerHTML = "";
    });
  }

  // --- ClientGuard: detalhe de um cliente (série temporal + top destinos) --

  function renderClientDetail(srcIp, data) {
    var el = document.getElementById("cg-client-detail");
    if (!el) return;
    if (!data.ok) {
      el.innerHTML = '<p class="fg-error">Detalhes (' + escapeHtml(srcIp) + "): " + escapeHtml(data.error) + "</p>";
      el.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    var destRows = (data.top_destinations || []).length
      ? data.top_destinations.map(function (d) {
          var geo = d.dst_asn ? "AS" + d.dst_asn + (d.dst_country ? " (" + escapeHtml(d.dst_country) + ")" : "") : "-";
          return (
            "<tr><td>" + escapeHtml(d.dst_ip) + "</td><td>" + protoName(d.protocol) + "</td><td>" + d.dst_port +
            "</td><td>" + geo + "</td><td>" + fmtBytes(d.bytes) + "</td><td>" +
            (d.packets || 0).toLocaleString("pt-BR") + "</td></tr>"
          );
        }).join("")
      : '<tr><td colspan="6">sem destinos na janela selecionada</td></tr>';
    el.innerHTML =
      '<div class="fg-ai-panel"><div class="fg-panel-header"><h4>Consumo de dados — ' + escapeHtml(srcIp) + "</h4>" +
      '<button class="fg-btn" data-action="close-detail">Fechar</button></div>' +
      "<h5>Tráfego ao longo do tempo</h5>" +
      '<canvas id="cg-client-detail-chart" width="760" height="160"></canvas>' +
      "<h5>Top destinos (" + (data.top_destinations || []).length + ")</h5>" +
      "<table><thead><tr><th>Destino</th><th>Protocolo</th><th>Porta</th><th>ASN/País</th>" +
      "<th>Tráfego</th><th>Pacotes</th></tr></thead><tbody>" + destRows + "</tbody></table>" +
      "</div>";
    var canvas = document.getElementById("cg-client-detail-chart");
    if (canvas) {
      drawLineChart(canvas, data.timeseries || [], [{ key: "bps", color: "#58a6ff", label: "Tráfego" }]);
    }
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function loadClientDetail(srcIp) {
    var el = document.getElementById("cg-client-detail");
    if (el) el.innerHTML = "<p>Carregando detalhes de " + escapeHtml(srcIp) + "...</p>";
    getJson(CG_CLIENT_DETAIL_ENDPOINT + "?src_ip=" + encodeURIComponent(srcIp) + "&window_s=" + state.cgTopWindow)
      .then(function (data) { renderClientDetail(srcIp, data); })
      .catch(function (err) {
        showError(el, "falha ao consultar detalhes do cliente");
        console.error("flowguard.js:", err);
      });
  }

  function onCgTopClick(ev) {
    var btn = ev.target.closest("button[data-action='detail']");
    if (!btn) return;
    var row = btn.closest("tr[data-src-ip]");
    if (!row) return;
    loadClientDetail(row.getAttribute("data-src-ip"));
  }

  function onCgClientDetailClick(ev) {
    var btn = ev.target.closest("button[data-action='close-detail']");
    if (!btn) return;
    var el = document.getElementById("cg-client-detail");
    if (el) el.innerHTML = "";
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

  function renderCgBlocks(data) {
    var el = document.getElementById("cg-blocks");
    if (!el) return;
    if (!data.ok) {
      showError(el, data.error || "erro desconhecido");
      return;
    }
    if (!data.blocks.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum IP bloqueado no momento.</p>';
      return;
    }
    var rows = data.blocks
      .map(function (r) {
        return (
          '<tr data-rule-id="' + r.id + '"><td>' + escapeHtml(r.src_prefix) + "</td><td>" +
          escapeHtml(r.action) + "</td><td>" + new Date(r.expires_at * 1000).toLocaleString() +
          '</td><td><button class="fg-btn" data-action="del-block">Remover</button></td></tr>'
        );
      })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>IP/rede bloqueado</th><th>Ação</th><th>Expira</th><th></th></tr></thead><tbody>" +
      rows + "</tbody></table>";
  }

  function loadCgBlocks() {
    if (!getToken()) return;
    getJson(CG_BLOCK_ENDPOINT).then(renderCgBlocks).catch(function (err) {
      showError(document.getElementById("cg-blocks"), "falha ao consultar bloqueios");
      console.error("flowguard.js:", err);
    });
  }

  function onCgBlocksClick(ev) {
    var btn = ev.target.closest("button[data-action='del-block']");
    if (!btn) return;
    var row = btn.closest("tr[data-rule-id]");
    if (!row) return;
    btn.disabled = true;
    postJson(CG_BLOCK_ENDPOINT, { id: Number(row.getAttribute("data-rule-id")) }).then(function (resp) {
      showToast(resp.ok ? "Bloqueio removido" : resp.error, resp.ok ? "success" : "error");
      loadCgBlocks();
    });
  }

  function onCgBlockSubmit() {
    var input = document.getElementById("cg-block-ip");
    var ttlSelect = document.getElementById("cg-block-ttl");
    var btn = document.getElementById("cg-block-submit");
    var ip = (input.value || "").trim();
    if (!ip) {
      showToast("Informe um IP ou CIDR", "error");
      return;
    }
    btn.disabled = true;
    postJson(CG_BLOCK_ENDPOINT, { ip: ip, ttl_s: Number(ttlSelect.value) })
      .then(function (resp) {
        showToast(resp.ok ? "Cliente bloqueado: " + ip : resp.error, resp.ok ? "success" : "error");
        if (resp.ok) input.value = "";
        loadCgBlocks();
      })
      .finally(function () { btn.disabled = false; });
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

  // --- ClientGuard: configurações (toggles de funções + limpar suspeitos) --

  function renderCgToggles(toggles) {
    var el = document.getElementById("cg-toggles");
    if (!el) return;
    el.innerHTML = CG_TOGGLE_META.map(function (meta) {
      var enabled = toggles[meta.key] !== false; // ausente = habilitado, mesmo default do backend
      var id = "cg-toggle-" + meta.key;
      return (
        '<div class="fg-toggle-item' + (enabled ? "" : " disabled") + '" data-key="' + meta.key + '">' +
        '<input type="checkbox" id="' + id + '"' + (enabled ? " checked" : "") + ">" +
        '<label for="' + id + '"><div class="fg-toggle-name">' + escapeHtml(meta.label) + "</div>" +
        '<div class="fg-toggle-desc">' + escapeHtml(meta.desc) + "</div></label></div>"
      );
    }).join("");
  }

  function loadCgToggles() {
    if (!getToken()) return;
    getJson(CG_TOGGLES_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("cg-toggles"), data.error || "erro desconhecido");
        return;
      }
      state.cgTogglesLoaded = data.toggles;
      state.cgTogglesPending = {};
      updateTogglesApplyBtn("cg-toggles-apply-btn", 0);
      renderCgToggles(data.toggles);
    }).catch(function (err) {
      showError(document.getElementById("cg-toggles"), "falha ao consultar configurações do ClientGuard");
      console.error("flowguard.js:", err);
    });
  }

  // Checkbox só marca a mudança como pendente (feedback visual imediato) — o valor só
  // é enviado ao daemon quando o usuário clica em "Aplicar novas configurações", pra
  // permitir mexer em várias funções de uma vez e confirmar tudo junto. Se o usuário
  // desmarcar e remarcar (voltar ao valor já salvo), a chave sai de "pendente" — evita
  // mandar uma mudança que não é mudança nenhuma.
  function onCgTogglesChange(ev) {
    var checkbox = ev.target.closest("input[type='checkbox']");
    if (!checkbox) return;
    var item = checkbox.closest(".fg-toggle-item[data-key]");
    if (!item) return;
    var key = item.getAttribute("data-key");
    var value = checkbox.checked;
    item.classList.toggle("disabled", !value);
    var original = state.cgTogglesLoaded[key] !== false;
    if (value === original) {
      delete state.cgTogglesPending[key];
    } else {
      state.cgTogglesPending[key] = value;
    }
    updateTogglesApplyBtn("cg-toggles-apply-btn", Object.keys(state.cgTogglesPending).length);
  }

  function onCgTogglesApplyClick() {
    var pending = state.cgTogglesPending;
    var keys = Object.keys(pending);
    if (!keys.length) return;
    var btn = document.getElementById("cg-toggles-apply-btn");
    btn.disabled = true;
    // 1 requisição só com todas as mudanças (não 1 por checkbox) — o socket do
    // ClientGuard atende em threads reais, N chamadas paralelas independentes
    // poderiam intercalar leitura/escrita de toggles.yaml e perder uma mudança.
    postJson(CG_TOGGLES_ENDPOINT, { toggles: pending }).then(function (resp) {
      showToast(resp.ok ? "Configurações aplicadas" : (resp.error || "falha ao aplicar configurações"),
                resp.ok ? "success" : "error");
      loadCgToggles(); // resincroniza com o estado real do daemon (limpa pendências)
    }).catch(function (err) {
      showToast("falha ao aplicar configurações", "error");
      console.error("flowguard.js:", err);
      btn.disabled = false;
    });
  }

  function onCgClearSuspiciousClick() {
    if (!window.confirm("Marcar TODOS os sinais suspeitos abertos como resolvidos? Isso não pode ser desfeito (histórico continua na aba Resolvidos).")) {
      return;
    }
    var btn = document.getElementById("cg-clear-suspicious-btn");
    btn.disabled = true;
    postJson(CG_SUSPICIOUS_ENDPOINT, { clear_all: true }).then(function (resp) {
      showToast(resp.ok ? resp.cleared + " host(s) suspeito(s) limpo(s)" : resp.error, resp.ok ? "success" : "error");
      loadClientGuardSuspicious();
    }).finally(function () { btn.disabled = false; });
  }

  function loadClientGuard() {
    loadClientGuardStatus();
    loadCgTop();
    loadClientGuardSuspicious();
    loadCgBlocks();
    loadCgToggles();
  }

  // --- gráficos (canvas, sem dependência externa) -------------------------

  var SEV_COLORS = { critical: "#f85149", high: "#ffa657", medium: "#d29922", info: "#8b949e" };
  var SEV_ROWS = ["critical", "high", "medium", "info"];
  var CHART_BG = "#0d1117";

  // paleta categórica das linhas de barramento no modo "Todos" — ordem fixa
  // (não cosmética: é o que garante a distinção adjacente para daltonismo),
  // validada com scripts/validate_palette.js do skill dataviz contra o
  // surface real do app (#0d1117, modo dark): contraste >=3:1 em todas e
  // pior ΔE adjacente de CVD 16.1 (acima do alvo de 12). Um 9º barramento
  // nunca gera uma nova cor — cai em CHART_OTHER_COLOR ("Outros").
  var CHART_PREFIX_COLORS = ["#58a6ff", "#ffa657", "#a371f7", "#3fb950", "#db61a2", "#39c5cf", "#d29922", "#79c0ff"];
  var CHART_OTHER_COLOR = "#8b949e";

  // chartScale() desenha no espaço de pixels CSS (não nos atributos width/height
  // fixos do <canvas>) e redimensiona o backing store pelo devicePixelRatio —
  // sem isso o canvas de 900x220 fica borrado quando o CSS estica pra largura
  // real do card (ex.: 1326px). Todo o resto do código de desenho continua
  // trabalhando em coordenadas s.w/s.h normalmente, sem saber disso.
  function chartScale(canvas) {
    var dpr = window.devicePixelRatio || 1;
    var cssW = canvas.clientWidth || canvas.width;
    var cssH = canvas.clientHeight || canvas.height;
    var pixelW = Math.max(1, Math.round(cssW * dpr));
    var pixelH = Math.max(1, Math.round(cssH * dpr));
    if (canvas.width !== pixelW || canvas.height !== pixelH) {
      canvas.width = pixelW;
      canvas.height = pixelH;
    }
    var ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);
    return { ctx: ctx, w: cssW, h: cssH, padding: { left: 55, right: 10, top: 10, bottom: 20 } };
  }

  // --- tooltip compartilhado pelos 3 gráficos de canvas --------------------

  var chartRegistry = {}; // canvasId -> { type, redraw(hoverIndex), hitTest(mouseX, mouseY) -> {index, tooltip} | null }

  function showChartTooltip(clientX, clientY, html) {
    var tt = document.getElementById("fg-chart-tooltip");
    if (!tt) return;
    tt.innerHTML = html;
    tt.hidden = false;
    var left = clientX + 14;
    var top = clientY + 14;
    var maxLeft = window.innerWidth - tt.offsetWidth - 8;
    var maxTop = window.innerHeight - tt.offsetHeight - 8;
    tt.style.left = Math.max(4, Math.min(left, maxLeft)) + "px";
    tt.style.top = Math.max(4, Math.min(top, maxTop)) + "px";
  }

  function hideChartTooltip() {
    var tt = document.getElementById("fg-chart-tooltip");
    if (tt) tt.hidden = true;
  }

  function registerChartHover(canvas, entry) {
    chartRegistry[canvas.id] = entry;
    if (canvas._hoverBound) return;
    canvas._hoverBound = true;
    canvas.addEventListener("mousemove", function (ev) {
      var reg = chartRegistry[canvas.id];
      if (!reg) return;
      var rect = canvas.getBoundingClientRect();
      var mouseX = ev.clientX - rect.left;
      var mouseY = ev.clientY - rect.top;
      var hit = reg.hitTest(mouseX, mouseY);
      if (hit) {
        reg.redraw(hit.index);
        showChartTooltip(ev.clientX, ev.clientY, hit.tooltip);
        canvas.style.cursor = hit.pointer ? "pointer" : "crosshair";
      } else {
        reg.redraw(null);
        hideChartTooltip();
        canvas.style.cursor = "crosshair";
      }
    });
    canvas.addEventListener("mouseleave", function () {
      var reg = chartRegistry[canvas.id];
      if (reg) reg.redraw(null);
      hideChartTooltip();
    });
    if (canvas._clickBound) return;
    canvas._clickBound = true;
    canvas.addEventListener("click", function (ev) {
      var reg = chartRegistry[canvas.id];
      if (!reg || !reg.hitTest) return;
      var rect = canvas.getBoundingClientRect();
      var hit = reg.hitTest(ev.clientX - rect.left, ev.clientY - rect.top);
      if (hit && hit.onClick) hit.onClick();
    });
  }

  function drawEmpty(canvas, message) {
    delete chartRegistry[canvas.id];
    var s = chartScale(canvas);
    s.ctx.fillStyle = "#8b949e";
    s.ctx.font = "12px sans-serif";
    s.ctx.textAlign = "center";
    s.ctx.fillText(message, s.w / 2, s.h / 2);
    s.ctx.textAlign = "left";
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

  function drawLineChartCore(s, series, lines, band, hoverIndex) {
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

    // faixa esperada do baseline — preenchimento + contorno tracejado, senão
    // some visualmente quando é bem menor que o pico do tráfego real
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
      ctx.strokeStyle = "rgba(88,166,255,0.55)";
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      series.forEach(function (pt, i) {
        var yy = y(pt[band.upperKey] || 0);
        if (i === 0) ctx.moveTo(x(i), yy);
        else ctx.lineTo(x(i), yy);
      });
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // preenchimento sob a primeira linha (normalmente "entrada") — dá noção
    // de volume, não só de tendência
    var mainLine = lines[0];
    if (mainLine) {
      var grad = ctx.createLinearGradient(0, s.padding.top, 0, s.padding.top + plotH);
      grad.addColorStop(0, mainLine.color + "33");
      grad.addColorStop(1, mainLine.color + "00");
      ctx.fillStyle = grad;
      ctx.beginPath();
      series.forEach(function (pt, i) {
        var yy = y(pt[mainLine.key] || 0);
        if (i === 0) ctx.moveTo(x(i), yy);
        else ctx.lineTo(x(i), yy);
      });
      ctx.lineTo(x(series.length - 1), y(0));
      ctx.lineTo(x(0), y(0));
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

    if (hoverIndex != null && series[hoverIndex]) {
      var hx = x(hoverIndex);
      ctx.strokeStyle = "rgba(201,209,217,0.4)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(hx, s.padding.top);
      ctx.lineTo(hx, s.padding.top + plotH);
      ctx.stroke();
      lines.forEach(function (l) {
        var hy = y(series[hoverIndex][l.key] || 0);
        ctx.fillStyle = l.color;
        ctx.beginPath();
        ctx.arc(hx, hy, 3.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = CHART_BG;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      });
    }

    drawTimeAxis(s, series[0].ts, series[series.length - 1].ts);
  }

  function chartHitIndex(canvas, series, mouseX) {
    var padding = { left: 55, right: 10 };
    var w = canvas.clientWidth;
    var plotW = w - padding.left - padding.right;
    if (mouseX < padding.left - 4 || mouseX > w - padding.right + 4) return null;
    var frac = (mouseX - padding.left) / plotW;
    frac = Math.max(0, Math.min(1, frac));
    return Math.round(frac * (series.length - 1));
  }

  function drawLineChart(canvas, series, lines, band) {
    if (!series || series.length < 2) {
      drawEmpty(canvas, "Sem dados suficientes na janela selecionada.");
      return;
    }
    function render(hoverIndex) {
      drawLineChartCore(chartScale(canvas), series, lines, band, hoverIndex);
    }
    render(null);
    registerChartHover(canvas, {
      hitTest: function (mouseX) {
        var idx = chartHitIndex(canvas, series, mouseX);
        if (idx == null) return null;
        var pt = series[idx];
        var rows = lines.map(function (l) {
          return '<div class="fg-tt-row"><span><i class="fg-tt-swatch" style="background:' + l.color + '"></i>' +
            escapeHtml(l.label || l.key) + "</span><span>" + fmtBps(pt[l.key] || 0) + "</span></div>";
        }).join("");
        return { index: idx, tooltip: '<div class="fg-tt-title">' + fmtDateTime(pt.ts) + "</div>" + rows };
      },
      redraw: function (hoverIndex) { render(hoverIndex); },
    });
  }

  function drawStackedAreaCore(s, series, keys, colors, hoverIndex) {
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
    var boundaries = [];
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
      if (ki < keys.length - 1) boundaries.push(cumulative.slice());
    });

    // gap de 2px entre segmentos empilhados — sem isso as cores colam sem
    // separação visual, principalmente entre tons próximos
    ctx.strokeStyle = CHART_BG;
    ctx.lineWidth = 2;
    boundaries.forEach(function (cum) {
      ctx.beginPath();
      cum.forEach(function (v, i) {
        var yy = y(v);
        if (i === 0) ctx.moveTo(x(i), yy);
        else ctx.lineTo(x(i), yy);
      });
      ctx.stroke();
    });

    if (hoverIndex != null && series[hoverIndex]) {
      var hx = x(hoverIndex);
      ctx.strokeStyle = "rgba(201,209,217,0.4)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(hx, s.padding.top);
      ctx.lineTo(hx, s.padding.top + plotH);
      ctx.stroke();
    }

    drawTimeAxis(s, series[0].ts, series[series.length - 1].ts);
  }

  function drawStackedArea(canvas, series, keys, colors, labels) {
    if (!series || series.length < 2) {
      drawEmpty(canvas, "Sem dados suficientes na janela selecionada.");
      return;
    }
    function render(hoverIndex) {
      drawStackedAreaCore(chartScale(canvas), series, keys, colors, hoverIndex);
    }
    render(null);
    registerChartHover(canvas, {
      hitTest: function (mouseX) {
        var idx = chartHitIndex(canvas, series, mouseX);
        if (idx == null) return null;
        var pt = series[idx];
        var rows = keys.map(function (k, ki) {
          return '<div class="fg-tt-row"><span><i class="fg-tt-swatch" style="background:' + colors[ki] + '"></i>' +
            escapeHtml((labels && labels[ki]) || k.toUpperCase()) + "</span><span>" + fmtBps(pt[k] || 0) + "</span></div>";
        }).join("");
        return { index: idx, tooltip: '<div class="fg-tt-title">' + fmtDateTime(pt.ts) + "</div>" + rows };
      },
      redraw: function (hoverIndex) { render(hoverIndex); },
    });
  }

  function drawTimelineCore(s, attacks, windowS, hoverId) {
    var ctx = s.ctx;
    var plotW = s.w - s.padding.left - s.padding.right;
    var rowH = (s.h - s.padding.top - s.padding.bottom) / SEV_ROWS.length;
    var now = Math.floor(Date.now() / 1000);
    var since = now - windowS;
    var hitboxes = [];

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
      var barH = rowH * 0.6;
      var yy = s.padding.top + row * rowH + (rowH - barH) / 2;
      var w = Math.max(x2 - x1, 4);
      var isHover = hoverId != null && a.id === hoverId;
      ctx.globalAlpha = isHover ? 1 : 0.85;
      ctx.fillStyle = SEV_COLORS[a.severity] || "#8b949e";
      ctx.fillRect(x1, yy, w, barH);
      ctx.globalAlpha = 1;
      if (isHover) {
        ctx.strokeStyle = "#c9d1d9";
        ctx.lineWidth = 1.5;
        ctx.strokeRect(x1, yy, w, barH);
      }
      hitboxes.push({ x1: x1 - 2, x2: x1 + w + 2, y1: yy - 3, y2: yy + barH + 3, attack: a });
    });

    drawTimeAxis(s, since, now);
    return hitboxes;
  }

  function drawTimeline(canvas, attacks, windowS) {
    if (!attacks || !attacks.length) {
      drawEmpty(canvas, "Nenhum ataque no período selecionado.");
      return;
    }
    var hitboxes = [];
    function render(hoverId) {
      hitboxes = drawTimelineCore(chartScale(canvas), attacks, windowS, hoverId);
    }
    render(null);
    registerChartHover(canvas, {
      hitTest: function (mouseX, mouseY) {
        for (var i = 0; i < hitboxes.length; i++) {
          var h = hitboxes[i];
          if (mouseX >= h.x1 && mouseX <= h.x2 && mouseY >= h.y1 && mouseY <= h.y2) {
            var a = h.attack;
            var dur = a.ts_end ? fmtUptime(a.ts_end - a.ts_start) : "em andamento";
            var html =
              '<div class="fg-tt-title">' + escapeHtml(a.dst_prefix || "-") +
              (a.customer ? " — " + escapeHtml(a.customer) : "") + "</div>" +
              '<div class="fg-tt-row"><span>severidade</span><span>' + escapeHtml(a.severity || "-") + "</span></div>" +
              '<div class="fg-tt-row"><span>início</span><span>' + fmtDateTime(a.ts_start) + "</span></div>" +
              '<div class="fg-tt-row"><span>duração</span><span>' + dur + "</span></div>" +
              '<div class="fg-tt-row"><span style="color:#8b949e">clique para ver detalhes →</span></div>';
            return { index: a.id, pointer: true, tooltip: html, onClick: function () { jumpToAttack(a); } };
          }
        }
        return null;
      },
      redraw: function (hoverId) { render(hoverId); },
    });
  }

  // pulado da timeline de ataques (Gráficos) direto pro histórico filtrado da
  // aba Ataques — evita o usuário ter que trocar de aba e refazer o filtro manualmente
  function jumpToAttack(attack) {
    state.attacksView = "history";
    state.attacksWindow = "7d";
    state.filter.attacksPrefix = attack.dst_prefix || "";
    document.querySelectorAll(".fg-tab-btn").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-tab") === "attacks");
    });
    document.querySelectorAll(".fg-tab-panel").forEach(function (p) {
      p.classList.toggle("active", p.getAttribute("data-tab") === "attacks");
    });
    var viewToggle = document.getElementById("fg-attacks-view-toggle");
    if (viewToggle) {
      viewToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-view") === "history");
      });
    }
    var windowToggle = document.getElementById("fg-attacks-window");
    if (windowToggle) {
      windowToggle.hidden = false;
      windowToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-window") === "7d");
      });
    }
    var prefixFilter = document.getElementById("fg-attacks-prefix-filter");
    if (prefixFilter) prefixFilter.value = attack.dst_prefix || "";
    hideChartTooltip();
    loadAttacks();
  }

  function populateChartPrefixSelect(prefixes) {
    var select = document.getElementById("fg-chart-prefix");
    if (!select || state.chart.prefixesLoaded) return;
    var meta = {};
    var options = prefixes.map(function (p) {
      meta[p.prefix] = { customer: p.customer || "", capacity_mbps: p.capacity_mbps || 0 };
      return '<option value="' + escapeHtml(p.prefix) + '">' + escapeHtml(p.prefix) + (p.customer ? " — " + escapeHtml(p.customer) : "") + "</option>";
    });
    select.innerHTML = '<option value="__all__">Todos os barramentos</option>' + options.join("");
    state.chart.prefixMeta = meta;
    // default continua sendo um prefixo individual (carrega rápido) — "Todos"
    // fica disponível mas não é a visão inicial: em bases com tráfego pesado
    // (ex.: prefixo sob simulação de ataque grande), a query agregada de todos
    // os prefixos de uma vez pode levar bem mais que um prefixo isolado.
    if (!state.chart.prefix && prefixes.length) {
      state.chart.prefix = prefixes[0].prefix;
    }
    select.value = state.chart.prefix;
    state.chart.prefixesLoaded = true;
  }

  // legenda dos gráficos de linha é montada em JS (não estática no HTML) porque
  // no modo "Todos" o número de itens e as cores dependem de quantos barramentos
  // existem, e no modo individual ela ganha um item extra ("capacidade
  // contratada") só quando o prefixo tem capacity_mbps configurado.
  function renderChartLegend(el, items) {
    el.innerHTML = items
      .map(function (it) { return '<span><i style="background:' + it.color + '"></i> ' + escapeHtml(it.label) + "</span>"; })
      .join("");
  }

  function computePeakAvg(series, key) {
    var peak = 0, sum = 0, n = 0;
    series.forEach(function (pt) {
      var v = pt[key] || 0;
      if (v > peak) peak = v;
      sum += v;
      n++;
    });
    return { peak: peak, avg: n ? sum / n : 0 };
  }

  // tabela-resumo (pico/média/% de utilização da capacidade contratada) por
  // barramento — 1 linha no modo individual, N ordenadas por pico no modo
  // "Todos". % usa a mesma fórmula já usada no flowguard-cli.py.
  function renderChartSummary(el, rows) {
    if (!rows.length) {
      el.innerHTML = '<p class="fg-kpi-sub">Sem barramentos monitorados.</p>';
      return;
    }
    rows = rows.slice().sort(function (a, b) { return b.peakBps - a.peakBps; });
    var body = rows
      .map(function (r) {
        var pctStr = "—";
        if (r.capacityMbps) {
          var pct = (r.peakBps / 1e6 / r.capacityMbps) * 100;
          pctStr = pct.toFixed(1) + "% de " + r.capacityMbps + " Mbps";
        }
        return (
          "<tr><td>" + escapeHtml(r.prefix) + "</td><td>" + escapeHtml(r.customer || "-") + "</td><td>" +
          fmtBps(r.peakBps) + "</td><td>" + fmtBps(r.avgBps) + "</td><td>" + pctStr + "</td></tr>"
        );
      })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>Barramento</th><th>Cliente</th><th>Pico (in)</th><th>Média (in)</th><th>Utilização</th></tr></thead><tbody>" +
      body + "</tbody></table>";
  }

  // marca um placeholder de "carregando" em cada gráfico assim que a aba é
  // aberta/filtrada — sem isso, uma consulta lenta (histórico grande) deixa o
  // canvas em branco por vários segundos e parece quebrado, não lento.
  function chartLoadingPlaceholders(requestToken) {
    ["fg-chart-traffic", "fg-chart-protocol", "fg-chart-timeline"].forEach(function (id) {
      var c = document.getElementById(id);
      if (c) drawEmpty(c, "Carregando…");
    });
    var topHostsEl = document.getElementById("flowguard-top-hosts");
    if (topHostsEl) topHostsEl.innerHTML = "Carregando...";

    setTimeout(function () {
      if (state.chart._requestSeq !== requestToken) return; // outra chamada já substituiu essa
      ["fg-chart-traffic", "fg-chart-protocol", "fg-chart-timeline"].forEach(function (id) {
        if (state.chart._resolved[id]) return;
        var c = document.getElementById(id);
        if (c) drawEmpty(c, "Ainda carregando — o histórico é grande, pode levar até 1 minuto.");
      });
      if (!state.chart._resolved["flowguard-top-hosts"] && topHostsEl) {
        topHostsEl.innerHTML = "Ainda carregando — o histórico é grande, pode levar até 1 minuto.";
      }
    }, 4000);
  }

  function loadCharts() {
    if (!state.chart.prefix) return;
    var windowName = state.chart.window;
    var isAll = state.chart.prefix === "__all__";
    var requestToken = ++state.chart._requestSeq;
    state.chart._resolved = {};
    chartLoadingPlaceholders(requestToken);

    var trafficTitle = document.getElementById("fg-chart-traffic-title");
    if (trafficTitle) {
      trafficTitle.textContent = isAll
        ? "Tráfego de entrada por barramento — comparação"
        : "Tráfego — entrada x saída (com faixa de baseline)";
    }
    var hostsTitle = document.getElementById("fg-chart-hosts-title");
    if (hostsTitle) {
      hostsTitle.textContent = isAll ? "Top hosts" : "Top hosts no prefixo (quem está consumindo mais)";
    }

    getJson(HISTORY_ENDPOINT + "?metric=prefix&prefix=" + encodeURIComponent(state.chart.prefix) + "&window=" + windowName)
      .then(function (data) {
        if (state.chart._requestSeq !== requestToken) return;
        state.chart._resolved["fg-chart-traffic"] = true;
        var canvas = document.getElementById("fg-chart-traffic");
        var legendEl = document.getElementById("fg-chart-traffic-legend");
        var summaryEl = document.getElementById("fg-chart-summary");
        if (!canvas) return;
        if (!data.ok) {
          drawEmpty(canvas, data.error || "erro ao carregar");
          if (legendEl) legendEl.innerHTML = "";
          if (summaryEl) showError(summaryEl, data.error || "erro ao carregar");
          return;
        }

        if (data.mode === "all") {
          var prefixes = data.prefixes || [];
          var lines = prefixes.map(function (p, i) {
            var color = i < CHART_PREFIX_COLORS.length ? CHART_PREFIX_COLORS[i] : CHART_OTHER_COLOR;
            return { key: p.prefix, color: color, label: p.prefix + (p.customer ? " — " + p.customer : "") };
          });
          drawLineChart(canvas, data.series, lines, null);
          if (legendEl) renderChartLegend(legendEl, lines);
          if (summaryEl) {
            var rows = prefixes.map(function (p) {
              var stats = computePeakAvg(data.series, p.prefix);
              return { prefix: p.prefix, customer: p.customer, peakBps: stats.peak, avgBps: stats.avg, capacityMbps: p.capacity_mbps };
            });
            renderChartSummary(summaryEl, rows);
          }
        } else {
          var series = data.series.map(function (pt) {
            var withExtra = { ts: pt.ts, bps_in: pt.bps_in, bps_out: pt.bps_out };
            if (data.baseline) {
              withExtra.baseline_mean = data.baseline.bps_mean;
              withExtra.baseline_upper = data.baseline.bps_upper;
            }
            if (data.capacity_mbps) withExtra.capacity_line = data.capacity_mbps * 1e6;
            return withExtra;
          });
          var chartLines = [
            { key: "bps_in", color: "#58a6ff", label: "entrada (in)" },
            { key: "bps_out", color: "#ffa657", label: "saída (out)" },
          ];
          var legendItems = [
            { color: "#58a6ff", label: "entrada (in)" },
            { color: "#ffa657", label: "saída (out)" },
          ];
          var band = null;
          if (data.baseline) {
            chartLines.push({ key: "baseline_mean", color: "#8b949e", dashed: true, label: "baseline (média, in)" });
            legendItems.push({ color: "#8b949e", label: "baseline (média, in)" });
            band = { upperKey: "baseline_upper" };
            legendItems.push({ color: "rgba(88,166,255,0.25)", label: "faixa esperada (in)" });
          }
          if (data.capacity_mbps) {
            var capLabel = "capacidade contratada (" + data.capacity_mbps + " Mbps)";
            chartLines.push({ key: "capacity_line", color: "#f85149", dashed: true, label: capLabel });
            legendItems.push({ color: "#f85149", label: capLabel });
          }
          drawLineChart(canvas, series, chartLines, band);
          if (legendEl) renderChartLegend(legendEl, legendItems);
          if (summaryEl) {
            var stats = computePeakAvg(series, "bps_in");
            var meta = state.chart.prefixMeta[state.chart.prefix] || {};
            renderChartSummary(summaryEl, [
              { prefix: state.chart.prefix, customer: meta.customer, peakBps: stats.peak, avgBps: stats.avg, capacityMbps: data.capacity_mbps },
            ]);
          }
        }
      });

    var prefixParam = isAll ? "" : "&prefix=" + encodeURIComponent(state.chart.prefix);

    getJson(HISTORY_ENDPOINT + "?metric=protocol&window=" + windowName + prefixParam).then(function (data) {
      if (state.chart._requestSeq !== requestToken) return;
      state.chart._resolved["fg-chart-protocol"] = true;
      var canvas = document.getElementById("fg-chart-protocol");
      if (!canvas) return;
      if (!data.ok) { drawEmpty(canvas, data.error || "erro ao carregar"); return; }
      drawStackedArea(canvas, data.series, ["tcp", "udp", "icmp", "other"], ["#58a6ff", "#3fb950", "#d29922", "#8b949e"], ["TCP", "UDP", "ICMP", "Outro"]);
    });

    getJson(HISTORY_ENDPOINT + "?metric=attacks&window=" + windowName + prefixParam).then(function (data) {
      if (state.chart._requestSeq !== requestToken) return;
      state.chart._resolved["fg-chart-timeline"] = true;
      var canvas = document.getElementById("fg-chart-timeline");
      if (!canvas) return;
      if (!data.ok) { drawEmpty(canvas, data.error || "erro ao carregar"); return; }
      var windowSeconds = { "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800 }[windowName] || 21600;
      drawTimeline(canvas, data.attacks, windowSeconds);
    });

    if (isAll) {
      state.chart._resolved["flowguard-top-hosts"] = true;
      var topHostsEl = document.getElementById("flowguard-top-hosts");
      if (topHostsEl) topHostsEl.innerHTML = '<p class="fg-kpi-sub">Selecione um barramento específico para ver hosts individuais.</p>';
    } else {
      getJson(HISTORY_ENDPOINT + "?metric=hosts&prefix=" + encodeURIComponent(state.chart.prefix) + "&window=" + windowName)
        .then(function (data) {
          if (state.chart._requestSeq !== requestToken) return;
          state.chart._resolved["flowguard-top-hosts"] = true;
          var el = document.getElementById("flowguard-top-hosts");
          if (!el) return;
          if (!data.ok) { showError(el, data.error || "erro ao carregar"); return; }
          renderTopHosts(el, data.hosts || []);
        });
    }
  }

  function renderTopHosts(el, hosts) {
    if (!hosts.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum host individual identificado na janela selecionada.</p>';
      return;
    }
    var max = hosts.reduce(function (m, h) { return Math.max(m, h.occurrences); }, 1);
    var rows = hosts
      .map(function (h) {
        var pct = Math.max(2, Math.round((h.occurrences / max) * 100));
        return "<tr><td>" + escapeHtml(h.ip) + "/32</td><td>" +
          '<div class="fg-hbar-wrap"><div class="fg-hbar" style="width:' + pct + '%"></div>' +
          '<span class="fg-hbar-label">' + h.occurrences + " ciclo(s)</span></div>" +
          "</td></tr>";
      })
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

  // --- Alertas via WhatsApp (Evolution API) --------------------------------

  var waCurrentDest = null;
  var waQrPollTimer = null;

  function onWaDestTypeChange() {
    var checked = document.querySelector('input[name="fg-wa-dest-type"]:checked');
    var type = checked ? checked.value : "group";
    document.getElementById("fg-wa-dest-group-wrap").style.display = type === "group" ? "flex" : "none";
    document.getElementById("fg-wa-dest-number-wrap").style.display = type === "number" ? "flex" : "none";
  }

  function stopWaQrPolling() {
    if (waQrPollTimer) { clearInterval(waQrPollTimer); waQrPollTimer = null; }
    var wrap = document.getElementById("fg-wa-qr-wrap");
    if (wrap) wrap.style.display = "none";
  }

  function renderWaStatus(data) {
    var statusEl = document.getElementById("fg-wa-status");
    if (!statusEl) return;
    if (!data.ok) {
      statusEl.innerHTML = '<span class="fg-dot fg-dot-down"></span>indisponível: ' + escapeHtml(data.error || "erro desconhecido");
      return;
    }
    var st = data.state;
    var label = st === "open"
      ? '<span class="fg-dot fg-dot-up"></span>Conectado'
      : '<span class="fg-dot fg-dot-down"></span>Desconectado (não pareado)';
    if (data.number) label += " — número " + escapeHtml(data.number);
    statusEl.innerHTML = label;

    var connectBtn = document.getElementById("fg-wa-connect-btn");
    var logoutBtn = document.getElementById("fg-wa-logout-btn");
    if (connectBtn) connectBtn.style.display = st === "open" ? "none" : "inline-block";
    if (logoutBtn) logoutBtn.style.display = st === "open" ? "inline-block" : "none";
    if (st === "open") stopWaQrPolling();

    waCurrentDest = data.dest || null;
    var destEl = document.getElementById("fg-wa-dest-current");
    if (destEl) {
      destEl.textContent = (waCurrentDest && waCurrentDest.dest)
        ? "Destino atual: " + (waCurrentDest.dest_label || waCurrentDest.dest) + " (" + (waCurrentDest.dest_type === "group" ? "grupo" : "número direto") + ")"
        : "Nenhum destino configurado ainda.";
      if (waCurrentDest && waCurrentDest.dest_type) {
        var radio = document.querySelector('input[name="fg-wa-dest-type"][value="' + waCurrentDest.dest_type + '"]');
        if (radio) radio.checked = true;
        onWaDestTypeChange();
        if (waCurrentDest.dest_type === "number") {
          document.getElementById("fg-wa-dest-number-input").value = waCurrentDest.dest.split("@")[0];
        }
      }
    }
    if (st === "open") loadWaGroups();
  }

  function loadWaStatus() {
    if (!getToken()) return;
    getJson(WHATSAPP_ENDPOINT + "?action=status").then(renderWaStatus).catch(function (err) {
      console.error("flowguard.js:", err);
    });
  }

  function loadWaGroups() {
    getJson(WHATSAPP_ENDPOINT + "?action=groups").then(function (data) {
      var sel = document.getElementById("fg-wa-dest-group-select");
      if (!sel) return;
      if (!data.ok) {
        sel.innerHTML = '<option value="">' + escapeHtml(data.error || "erro ao listar grupos") + "</option>";
        return;
      }
      var current = waCurrentDest && waCurrentDest.dest_type === "group" ? waCurrentDest.dest : null;
      sel.innerHTML = '<option value="">selecione um grupo...</option>' + data.groups.map(function (g) {
        return '<option value="' + escapeHtml(g.id) + '"' + (g.id === current ? " selected" : "") + ">" + escapeHtml(g.subject) + "</option>";
      }).join("");
    }).catch(function (err) { console.error("flowguard.js:", err); });
  }

  function loadWaQr() {
    getJson(WHATSAPP_ENDPOINT + "?action=qrcode").then(function (data) {
      if (!data.ok || !data.base64) {
        showToast(data.error || "falha ao gerar QR code", "error");
        return;
      }
      document.getElementById("fg-wa-qr-img").src = data.base64;
      document.getElementById("fg-wa-qr-wrap").style.display = "block";
      if (!waQrPollTimer) waQrPollTimer = setInterval(loadWaStatus, 3000);
    }).catch(function (err) {
      showToast("falha ao gerar QR code", "error");
      console.error("flowguard.js:", err);
    });
  }

  function onWaSaveDestClick() {
    var checked = document.querySelector('input[name="fg-wa-dest-type"]:checked');
    var type = checked ? checked.value : "group";
    var payload = { action: "set_dest", dest_type: type };
    if (type === "group") {
      var sel = document.getElementById("fg-wa-dest-group-select");
      if (!sel.value) { showToast("selecione um grupo", "error"); return; }
      payload.dest = sel.value;
      payload.dest_label = sel.options[sel.selectedIndex].textContent;
    } else {
      var num = document.getElementById("fg-wa-dest-number-input").value.trim();
      if (!num) { showToast("informe um número", "error"); return; }
      payload.dest = num;
    }
    var btn = document.getElementById("fg-wa-save-dest-btn");
    btn.disabled = true;
    postJson(WHATSAPP_ENDPOINT, payload).then(function (resp) {
      showToast(resp.ok ? "Destino salvo" : (resp.error || "falha ao salvar destino"), resp.ok ? "success" : "error");
      if (resp.ok) loadWaStatus();
    }).catch(function (err) {
      showToast("falha ao salvar destino", "error");
      console.error("flowguard.js:", err);
    }).finally(function () { btn.disabled = false; });
  }

  function onWaTestClick() {
    var btn = document.getElementById("fg-wa-test-btn");
    btn.disabled = true;
    postJson(WHATSAPP_ENDPOINT, { action: "test" }).then(function (resp) {
      showToast(resp.ok ? "Mensagem de teste enviada" : (resp.error || "falha ao enviar teste"), resp.ok ? "success" : "error");
    }).catch(function (err) {
      showToast("falha ao enviar teste", "error");
      console.error("flowguard.js:", err);
    }).finally(function () { btn.disabled = false; });
  }

  function onWaLogoutClick() {
    if (!window.confirm("Desconectar o WhatsApp atual? Vai ser preciso escanear um QR novo pra reconectar.")) return;
    postJson(WHATSAPP_ENDPOINT, { action: "logout" }).then(function (resp) {
      showToast(resp.ok ? "Desconectado" : (resp.error || "falha ao desconectar"), resp.ok ? "success" : "error");
      loadWaStatus();
    }).catch(function (err) { console.error("flowguard.js:", err); });
  }

  // --- Funções de detecção (toggles) + limpar hosts suspeitos --------------

  function renderFgToggles(toggles) {
    var el = document.getElementById("fg-toggles");
    if (!el) return;
    el.innerHTML = FG_TOGGLE_META.map(function (meta) {
      var enabled = toggles[meta.key] !== false; // ausente = habilitado, mesmo default do backend
      var id = "fg-toggle-" + meta.key;
      return (
        '<div class="fg-toggle-item' + (enabled ? "" : " disabled") + '" data-key="' + meta.key + '">' +
        '<input type="checkbox" id="' + id + '"' + (enabled ? " checked" : "") + ">" +
        '<label for="' + id + '"><div class="fg-toggle-name">' + escapeHtml(meta.label) + "</div>" +
        '<div class="fg-toggle-desc">' + escapeHtml(meta.desc) + "</div></label></div>"
      );
    }).join("");
  }

  function loadFgToggles() {
    if (!getToken()) return;
    getJson(TOGGLES_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("fg-toggles"), data.error || "erro desconhecido");
        return;
      }
      state.fgTogglesLoaded = data.toggles;
      state.fgTogglesPending = {};
      updateTogglesApplyBtn("fg-toggles-apply-btn", 0);
      renderFgToggles(data.toggles);
    }).catch(function (err) {
      showError(document.getElementById("fg-toggles"), "falha ao consultar funções de detecção");
      console.error("flowguard.js:", err);
    });
  }

  // Checkbox só marca a mudança como pendente (feedback visual imediato) — o valor só
  // é enviado ao daemon quando o usuário clica em "Aplicar novas configurações", pra
  // permitir mexer em vários tipos de ataque de uma vez e confirmar tudo junto. Se o
  // usuário desmarcar e remarcar (voltar ao valor já salvo), a chave sai de "pendente".
  function onFgTogglesChange(ev) {
    var checkbox = ev.target.closest("input[type='checkbox']");
    if (!checkbox) return;
    var item = checkbox.closest(".fg-toggle-item[data-key]");
    if (!item) return;
    var key = item.getAttribute("data-key");
    var value = checkbox.checked;
    item.classList.toggle("disabled", !value);
    var original = state.fgTogglesLoaded[key] !== false;
    if (value === original) {
      delete state.fgTogglesPending[key];
    } else {
      state.fgTogglesPending[key] = value;
    }
    updateTogglesApplyBtn("fg-toggles-apply-btn", Object.keys(state.fgTogglesPending).length);
  }

  function onFgTogglesApplyClick() {
    var pending = state.fgTogglesPending;
    var keys = Object.keys(pending);
    if (!keys.length) return;
    var btn = document.getElementById("fg-toggles-apply-btn");
    btn.disabled = true;
    // 1 requisição só com todas as mudanças (não 1 por checkbox) — mais barato (1
    // reload_config no daemon em vez de N) e atômico do lado do backend.
    postJson(TOGGLES_ENDPOINT, { toggles: pending }).then(function (resp) {
      showToast(resp.ok ? "Configurações aplicadas" : (resp.error || "falha ao aplicar configurações"),
                resp.ok ? "success" : "error");
      loadFgToggles(); // resincroniza com o estado real do daemon (limpa pendências)
    }).catch(function (err) {
      showToast("falha ao aplicar configurações", "error");
      console.error("flowguard.js:", err);
      btn.disabled = false;
    });
  }

  // --- Mitigação: estratégia/intensidade sugerida por tipo de ataque -------

  function renderFgMitigation(profiles) {
    var el = document.getElementById("fg-mitigation-cfg");
    if (!el) return;
    var rows = FG_TOGGLE_META.map(function (meta) {
      var p = profiles[meta.key] || {};
      var kind = p.kind || "discard";
      var kindOptions = MITIGATION_KIND_KEYS.map(function (k) {
        return '<option value="' + k + '"' + (k === kind ? " selected" : "") + '>' + MITIGATION_KIND_LABELS[k] + "</option>";
      }).join("");
      var pktCell = MITIGATION_PKT_LEN_TYPES[meta.key]
        ? "<td><input type=\"number\" min=\"1\" step=\"1\" data-field=\"pkt_len_min\" value=\"" +
          (p.pkt_len_min != null ? p.pkt_len_min : "") + "\"> bytes</td>"
        : '<td class="fg-muted">— (não se aplica)</td>';
      return (
        '<tr data-attack-type="' + meta.key + '">' +
        "<td>" + escapeHtml(meta.label) + "</td>" +
        '<td><select data-field="kind">' + kindOptions + "</select></td>" +
        pktCell +
        '<td><input type="number" min="1" step="1" data-field="rate_limit_mbps" value="' +
        (p.rate_limit_mbps != null ? p.rate_limit_mbps : "") + '"> Mbps</td>' +
        "</tr>"
      );
    }).join("");
    el.innerHTML =
      "<table><thead><tr><th>Tipo de ataque</th><th>Estratégia</th><th>Limiar de pacote</th>" +
      "<th>Limite de banda</th></tr></thead><tbody>" + rows + "</tbody></table>";
  }

  function loadFgMitigation() {
    if (!getToken()) return;
    getJson(MITIGATION_CFG_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("fg-mitigation-cfg"), data.error || "erro desconhecido");
        return;
      }
      state.fgMitigationLoaded = data.profiles;
      state.fgMitigationPending = {};
      var saveBtn = document.getElementById("fg-mitigation-save-btn");
      if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = "Salvar configurações de mitigação"; }
      renderFgMitigation(data.profiles);
    }).catch(function (err) {
      showError(document.getElementById("fg-mitigation-cfg"), "falha ao consultar configurações de mitigação");
      console.error("flowguard.js:", err);
    });
  }

  // Um tipo de ataque só entra em "pendente" se pelo menos 1 campo dele mudou de
  // verdade em relação ao que veio do servidor — evita mandar um "não-muda-nada"
  // quando o usuário mexe no campo e volta pro valor original.
  function onFgMitigationChange(ev) {
    var field = ev.target.getAttribute("data-field");
    if (!field) return;
    var row = ev.target.closest("tr[data-attack-type]");
    if (!row) return;
    var attackType = row.getAttribute("data-attack-type");
    var raw = ev.target.value;
    if (field !== "kind" && raw === "") return; // campo numérico vazio: ignora até digitar algo
    var value = field === "kind" ? raw : Number(raw);
    if (field !== "kind" && isNaN(value)) return;

    var original = state.fgMitigationLoaded[attackType] || {};
    var originalValue = field === "kind" ? (original.kind || "discard") : original[field];

    var pendingForType = state.fgMitigationPending[attackType] || {};
    if (value === originalValue) {
      delete pendingForType[field];
    } else {
      pendingForType[field] = value;
    }
    if (Object.keys(pendingForType).length) {
      state.fgMitigationPending[attackType] = pendingForType;
    } else {
      delete state.fgMitigationPending[attackType];
    }

    var pendingCount = Object.keys(state.fgMitigationPending).length;
    var saveBtn = document.getElementById("fg-mitigation-save-btn");
    if (saveBtn) {
      saveBtn.disabled = pendingCount === 0;
      saveBtn.textContent = pendingCount > 0
        ? "Salvar " + pendingCount + " " + (pendingCount === 1 ? "tipo alterado" : "tipos alterados")
        : "Salvar configurações de mitigação";
    }
  }

  function onFgMitigationSaveClick() {
    var pending = state.fgMitigationPending;
    var types = Object.keys(pending);
    if (!types.length) return;
    var btn = document.getElementById("fg-mitigation-save-btn");
    btn.disabled = true;
    postJson(MITIGATION_CFG_ENDPOINT, { profiles: pending }).then(function (resp) {
      showToast(resp.ok ? "Configurações de mitigação salvas" : (resp.error || "falha ao salvar"),
                resp.ok ? "success" : "error");
      loadFgMitigation(); // resincroniza com o estado real do daemon (limpa pendências)
    }).catch(function (err) {
      showToast("falha ao salvar configurações de mitigação", "error");
      console.error("flowguard.js:", err);
      btn.disabled = false;
    });
  }

  function onClearSuspiciousClick() {
    if (!window.confirm("Marcar TODOS os ataques ativos como dispensados? Eles somem da lista/contagem de Ativos (o histórico continua intacto). Isso não pode ser desfeito.")) {
      return;
    }
    var btn = document.getElementById("fg-clear-suspicious-btn");
    btn.disabled = true;
    postJson(ATTACKS_ENDPOINT, { action: "dismiss_all" }).then(function (resp) {
      showToast(resp.ok ? resp.cleared + " ataque(s) ativo(s) dispensado(s)" : resp.error, resp.ok ? "success" : "error");
      loadAttacks();
    }).finally(function () { btn.disabled = false; });
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
    initWarmode();
    initRouterCfg();

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

    var blockSubmitBtn = document.getElementById("fg-block-submit");
    if (blockSubmitBtn) blockSubmitBtn.addEventListener("click", onBlockSubmit);

    var cfgEl = document.getElementById("flowguard-cfg");
    if (cfgEl) {
      cfgEl.addEventListener("click", onCfgClick);
      cfgEl.addEventListener("submit", onCfgSubmit);
      loadCfg();
    }

    var fgTogglesEl = document.getElementById("fg-toggles");
    if (fgTogglesEl) {
      fgTogglesEl.addEventListener("change", onFgTogglesChange);
      loadFgToggles();
    }

    var fgMitigationEl = document.getElementById("fg-mitigation-cfg");
    if (fgMitigationEl) {
      fgMitigationEl.addEventListener("change", onFgMitigationChange);
      fgMitigationEl.addEventListener("input", onFgMitigationChange);
      loadFgMitigation();
    }

    var fgMitigationSaveBtn = document.getElementById("fg-mitigation-save-btn");
    if (fgMitigationSaveBtn) fgMitigationSaveBtn.addEventListener("click", onFgMitigationSaveClick);

    var waConnectBtn = document.getElementById("fg-wa-connect-btn");
    if (waConnectBtn) waConnectBtn.addEventListener("click", loadWaQr);

    var waQrRefreshBtn = document.getElementById("fg-wa-qr-refresh-btn");
    if (waQrRefreshBtn) waQrRefreshBtn.addEventListener("click", loadWaQr);

    var waLogoutBtn = document.getElementById("fg-wa-logout-btn");
    if (waLogoutBtn) waLogoutBtn.addEventListener("click", onWaLogoutClick);

    document.querySelectorAll('input[name="fg-wa-dest-type"]').forEach(function (radio) {
      radio.addEventListener("change", onWaDestTypeChange);
    });

    var waSaveDestBtn = document.getElementById("fg-wa-save-dest-btn");
    if (waSaveDestBtn) waSaveDestBtn.addEventListener("click", onWaSaveDestClick);

    var waTestBtn = document.getElementById("fg-wa-test-btn");
    if (waTestBtn) waTestBtn.addEventListener("click", onWaTestClick);

    if (document.getElementById("fg-wa-status")) loadWaStatus();

    var fgTogglesApplyBtn = document.getElementById("fg-toggles-apply-btn");
    if (fgTogglesApplyBtn) fgTogglesApplyBtn.addEventListener("click", onFgTogglesApplyClick);

    var clearSuspiciousBtn = document.getElementById("fg-clear-suspicious-btn");
    if (clearSuspiciousBtn) clearSuspiciousBtn.addEventListener("click", onClearSuspiciousClick);

    var cgTopEl = document.getElementById("cg-top");
    if (cgTopEl) cgTopEl.addEventListener("click", onCgTopClick);

    var cgClientDetailEl = document.getElementById("cg-client-detail");
    if (cgClientDetailEl) cgClientDetailEl.addEventListener("click", onCgClientDetailClick);

    initCgTopWindowControls();

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

    var cgBlockSubmitBtn = document.getElementById("cg-block-submit");
    if (cgBlockSubmitBtn) cgBlockSubmitBtn.addEventListener("click", onCgBlockSubmit);

    var cgBlocksEl = document.getElementById("cg-blocks");
    if (cgBlocksEl) cgBlocksEl.addEventListener("click", onCgBlocksClick);

    var cgTogglesEl = document.getElementById("cg-toggles");
    if (cgTogglesEl) cgTogglesEl.addEventListener("change", onCgTogglesChange);

    var cgTogglesApplyBtn = document.getElementById("cg-toggles-apply-btn");
    if (cgTogglesApplyBtn) cgTogglesApplyBtn.addEventListener("click", onCgTogglesApplyClick);

    var cgClearSuspiciousBtn = document.getElementById("cg-clear-suspicious-btn");
    if (cgClearSuspiciousBtn) cgClearSuspiciousBtn.addEventListener("click", onCgClearSuspiciousClick);

    if (getToken()) { loadClientGuardCfg(); loadCgBlocks(); }

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
