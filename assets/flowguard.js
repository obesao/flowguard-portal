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
  var SCAN_CFG_ENDPOINT = "/cgi-bin/flowguard-scan-cfg.sh";
  var SCAN_OFFENDERS_ENDPOINT = "/cgi-bin/flowguard-scan-offenders.sh";
  var COORDINATED_CFG_ENDPOINT = "/cgi-bin/flowguard-coordinated-cfg.sh";
  var COORDINATED_OFFENDERS_ENDPOINT = "/cgi-bin/flowguard-coordinated-offenders.sh";
  var ESCALATION_CFG_ENDPOINT = "/cgi-bin/flowguard-escalation-cfg.sh";
  var AI_ENDPOINT = "/cgi-bin/flowguard-ai.sh";
  var HISTORY_ENDPOINT = "/cgi-bin/flowguard-history.sh";
  var LOGIN_ENDPOINT = "/cgi-bin/flowguard-login.sh";
  var LOGOUT_ENDPOINT = "/cgi-bin/flowguard-logout.sh";
  var CG_STATUS_ENDPOINT = "/cgi-bin/clientguard-status.sh";
  var CG_SUSPICIOUS_ENDPOINT = "/cgi-bin/clientguard-suspicious.sh";
  var CG_CFG_ENDPOINT = "/cgi-bin/clientguard-cfg.sh";
  var CG_TOP_ENDPOINT = "/cgi-bin/clientguard-top.sh";
  var CG_CLIENT_DETAIL_ENDPOINT = "/cgi-bin/clientguard-client-detail.sh";
  var CG_NETWORK_SERIES_ENDPOINT = "/cgi-bin/clientguard-network-series.sh";
  var CG_BLOCK_ENDPOINT = "/cgi-bin/clientguard-block.sh";
  var CG_TOGGLES_ENDPOINT = "/cgi-bin/clientguard-toggles.sh";
  var CG_EDGE_ENDPOINT = "/cgi-bin/clientguard-edge.sh";
  var CG_EDGE_CFG_ENDPOINT = "/cgi-bin/clientguard-edge-cfg.sh";
  var CG_FLOWSPEC_CFG_ENDPOINT = "/cgi-bin/clientguard-flowspec-cfg.sh";
  var CG_ESCALATION_CFG_ENDPOINT = "/cgi-bin/clientguard-escalation-cfg.sh";
  var WARMODE_ENDPOINT = "/cgi-bin/flowguard-warmode.sh";
  var WARMODE_AUTH_ENDPOINT = "/cgi-bin/flowguard-warmode-auth.sh";
  var WARMODE_CFG_ENDPOINT = "/cgi-bin/flowguard-warmode-cfg.sh";
  var ROUTERCFG_ENDPOINT = "/cgi-bin/flowguard-routercfg.sh";
  var WHATSAPP_ENDPOINT = "/cgi-bin/flowguard-whatsapp.sh";

  var warmodeToken = null; // em memória só — some ao recarregar a página (relock)
  var warmodeExecMode = "apply"; // "apply" ou "revert" — mesmo modal, endpoints/rótulos trocam conforme o modo
  var warmodeActive = false; // estado real (vem do servidor via loadWarmodeStatus, polling) — botão único: liga se false, abre reversão se true
  var warmodeStartedAt = null; // epoch (s) — base do timer digital no topo da página
  var warmodeTickTimer = null;
  var rcTemplates = [];
  var rcCountdownTimer = null;
  var rcDiscovery = null; // cache em memória do último "Ler configuração atual (BGP)"

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
    { key: "syn_flood", label: "SYN flood", desc: "proporção de pacotes SYN puro (sem ACK) sobre o total de TCP do prefixo acima do limiar, só considerada com volume mínimo de tráfego TCP." },
    { key: "anomalia_baseline", label: "Anomalia de baseline", desc: "desvio estatístico (EWMA) do tráfego normal do prefixo — pega ataques pequenos demais pro limiar fixo global." },
  ];

  var MITIGATION_KIND_LABELS = {
    rtbh: "RTBH (bloqueio total)",
    discard: "Descartar (FlowSpec)",
    rate_limit: "Limitar banda (FlowSpec)",
  };
  var MITIGATION_KIND_KEYS = ["rtbh", "discard", "rate_limit"];
  // chave global (não por tipo de ataque) dentro do mesmo objeto "profiles" —
  // mesmo nome reservado do backend (collector.configio.RTBH_TTL_KEY)
  var RTBH_TTL_KEY = "rtbh_default_ttl_s";
  // só esses 2 tipos têm limiar de tamanho de pacote configurável — nos outros o
  // tamanho do pacote nunca fez parte do match (ver bgp/flowspec.py no backend)
  var MITIGATION_PKT_LEN_TYPES = { dns_amp: true, ntp_amp: true };

  var MITIGATION_AUTO_MODE_LABELS = {
    off: "Desligado",
    suggestion: "Automático (Aplicar Sugestão)",
    rtbh: "Automático (Mitigar / RTBH)",
  };
  var MITIGATION_AUTO_MODE_KEYS = ["off", "suggestion", "rtbh"];

  var state = {
    topPrefixes: [],
    flows: [],
    attacks: [],
    attacksView: "active",
    attacksWindow: "24h",
    attacksGroupBy: false,
    attacksSelectMode: false,
    attacksSelected: {},
    attacksCollapsedGroups: {},
    incidentsApp: "flowguard",
    incidents: { openAttacks: 0, openSignals: 0, openScans: 0, openCoordinated: 0 },
    scanView: "active",
    scanOffenders: [],
    coordinatedView: "active",
    coordinatedOffenders: [],
    status: null,
    cgStatus: null,
    cockpitEditing: false,
    sort: {
      topPrefixes: { key: "bps", dir: "desc" },
      flows: { key: "bps", dir: "desc" },
    },
    filter: {
      topPrefixes: "",
      flows: "",
      attacksSeverities: [],
      attacksPrefix: "",
      rulesHost: "",
      rulesType: "",
      rulesWindow: "",
      cgTop: "",
      cgSuspicious: "",
      cgSuspiciousSeverities: [],
    },
    page: {
      topPrefixes: 1,
      flows: 1,
      attacks: 1,
      cgEdgeMitigations: 1,
      scanOffenders: 1,
      coordinatedOffenders: 1,
    },
    chart: {
      window: "6h",
      prefix: null,
      prefixMeta: {},
      prefixesLoaded: false,
      cgNetworksAppended: false,
      _requestSeq: 0,
      _resolved: {},
    },
    cgCustomers: [],
    kpiHistory: { bps: [], pps: [] },
    cgSuspiciousView: "open",
    cgSuspiciousGroupBy: false,
    cgSuspiciousSelectMode: false,
    cgSuspiciousSelected: {},
    cgSuspiciousCollapsedGroups: {},
    cgSuspicious: [],
    cgTop: [],
    cgTopWindow: 21600,
    cgTogglesLoaded: {},
    cgTogglesPending: {},
    cgEdgeAutoLoaded: {},
    cgEdgeAutoPending: {},
    cgDetectionCfg: {},
    cgDetectionTemplates: {},
    rulesApp: "flowguard",
    rulesView: "active",
    blockSource: "flowguard",
    cfgApp: "flowguard",
    rulesFgData: [],
    rulesCgEdgeData: [],
    fgTogglesLoaded: {},
    fgTogglesPending: {},
    fgMitigationLoaded: {},
    fgMitigationPending: {},
    fgDetectionCfg: {},
    fgDetectionTemplates: {},
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

  // pedido do usuário: "ativo"/"aberto" sozinho não diz se está REALMENTE
  // acontecendo agora — um ataque/sinal fica "ativo" enquanto o atacante mandar
  // tráfego (correto), mas nada avisava quando isso já tinha parado há muito
  // tempo e o registro só ainda não fechou sozinho (ver close_stale_attacks/
  // resolve_stale_signals no backend, que fecham depois de horas sem
  // reconfirmação). ts_last_seen é atualizado a cada ciclo em que a condição
  // ainda bate de verdade — janela "fresca" de 90s cobre ~3 ciclos de agregação
  // (30s padrão nos dois daemons), com folga pra jitter.
  var ACTIVITY_FRESH_WINDOW_S = 90;
  function fmtActivityFreshness(tsLastSeen) {
    if (!tsLastSeen) return "";
    var ageS = Math.floor(Date.now() / 1000) - tsLastSeen;
    if (ageS < ACTIVITY_FRESH_WINDOW_S) {
      return '<div class="fg-kpi-sub" style="color:var(--fg-success)" title="Última reconfirmação há ' +
        ageS + 's">🟢 em andamento</div>';
    }
    return '<div class="fg-kpi-sub" style="color:var(--fg-warning)" title="Sem reconfirmação desde ' +
      fmtDateTime(tsLastSeen) + '">🟡 sem atividade há ' + fmtUptime(ageS) + "</div>";
  }

  // pedido do usuário: se o ataque/sinal já não está mais acontecendo de
  // verdade (🟡 sem atividade — ver fmtActivityFreshness acima), o selo de
  // mitigação não deve mais gritar "⚠ sem proteção" (isso é alarme de "ainda
  // te atacando sem bloqueio", não de "já te atacou uma vez sem bloqueio").
  // "genuinamente ativo" = mesmo critério do 🟢 da função acima, não só
  // ts_end/resolved nulo — closed vem de a.ts_end ou r.resolved.
  function isGenuinelyActive(closed, tsLastSeen) {
    if (closed || !tsLastSeen) return false;
    return (Math.floor(Date.now() / 1000) - tsLastSeen) < ACTIVITY_FRESH_WINDOW_S;
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
      if (key === "cgEdgeMitigations") applyRulesFilter();
      if (key === "scanOffenders") renderFgScanOffenders(state.scanOffenders);
      if (key === "coordinatedOffenders") renderFgCoordinatedOffenders(state.coordinatedOffenders);
    });
  }

  // --- menus de ação (dropdown compacto) -------------------------------------

  function initActionMenus() {
    document.addEventListener("click", function (ev) {
      // clicar no campo de duração do RTBH não deve fechar o menu (senão não dá
      // pra nem focar o campo pra digitar)
      if (ev.target.closest(".fg-menu-list input")) return;
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

  // --- painéis colapsáveis --------------------------------------------------
  // Genérico: não exige tocar em cada uma das 19 seções (.fg-panel-section)
  // espalhadas pelas abas — no init, cada uma ganha um botão no <h2> e tudo
  // depois dele vira o "corpo" que colapsa. Populações futuras por innerHTML
  // continuam funcionando normal (são feitas em elementos por id, que só
  // ficaram um nível mais fundo no DOM). Estado persistido em localStorage
  // por chave estável (aba + texto do h2), sobrevive a reload/poll.

  function panelStorageKey(section) {
    var tab = section.closest(".fg-tab-panel");
    var tabName = tab ? tab.getAttribute("data-tab") : "global";
    var h2 = section.querySelector(":scope > h2");
    var title = h2 ? h2.textContent.trim() : "";
    return "fg-panel-collapsed::" + tabName + "::" + title;
  }

  function setPanelCollapsed(section, collapsed) {
    var body = section.querySelector(":scope > .fg-panel-body");
    var btn = section.querySelector(":scope > h2 .fg-panel-collapse-btn");
    if (!body) return;
    body.hidden = collapsed;
    section.classList.toggle("fg-panel-collapsed", collapsed);
    if (btn) btn.textContent = collapsed ? "▸" : "▾";
  }

  // usado por jumpToAttack (clique num ataque no gráfico) — se o operador
  // tinha colapsado "Ataques" antes, o salto pra lá precisa expandir de novo,
  // senão a lista/filtro aplicado fica invisível
  function expandPanelSectionsIn(tabPanelEl) {
    if (!tabPanelEl) return;
    tabPanelEl.querySelectorAll(".fg-panel-section.fg-panel-collapsed").forEach(function (section) {
      setPanelCollapsed(section, false);
      localStorage.setItem(panelStorageKey(section), "0");
    });
  }

  function initCollapsiblePanels() {
    document.querySelectorAll("section.fg-panel-section").forEach(function (section) {
      var h2 = section.querySelector(":scope > h2");
      if (!h2 || h2.querySelector(".fg-panel-collapse-btn")) return;

      var body = document.createElement("div");
      body.className = "fg-panel-body";
      while (h2.nextSibling) body.appendChild(h2.nextSibling);
      section.appendChild(body);

      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "fg-panel-collapse-btn";
      btn.setAttribute("aria-label", "Recolher ou expandir este painel");
      btn.textContent = "▾";
      h2.appendChild(btn);
      h2.classList.add("fg-panel-h2-collapsible");

      var key = panelStorageKey(section);
      if (localStorage.getItem(key) === "1") setPanelCollapsed(section, true);

      h2.addEventListener("click", function () {
        var collapsed = !body.hidden;
        setPanelCollapsed(section, collapsed);
        localStorage.setItem(key, collapsed ? "1" : "0");
      });
    });
  }

  // botão "Recolher/Expandir tudo" por aba — só nas abas com 2+ painéis (não
  // vale a pena numa aba com 1 seção só). Roda depois de initCollapsiblePanels
  // (precisa do .fg-panel-body já existir). Pega qualquer profundidade
  // (querySelectorAll sem :scope) porque a aba Configuração aninha as seções
  // do ClientGuard dentro de um wrapper [data-cfg-app] pro toggle.
  function initCollapseAllControls() {
    document.querySelectorAll(".fg-tab-panel").forEach(function (tabPanel) {
      var sections = tabPanel.querySelectorAll("section.fg-panel-section");
      if (sections.length < 2) return;

      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "fg-btn fg-collapse-all-btn";

      function refreshLabel() {
        var anyExpanded = Array.prototype.some.call(
          tabPanel.querySelectorAll("section.fg-panel-section"),
          function (s) { return !s.classList.contains("fg-panel-collapsed"); }
        );
        btn.textContent = anyExpanded ? "Recolher tudo" : "Expandir tudo";
        return anyExpanded;
      }

      btn.addEventListener("click", function () {
        var anyExpanded = refreshLabel();
        tabPanel.querySelectorAll("section.fg-panel-section").forEach(function (s) {
          setPanelCollapsed(s, anyExpanded);
          localStorage.setItem(panelStorageKey(s), anyExpanded ? "1" : "0");
        });
        refreshLabel();
      });

      refreshLabel();
      tabPanel.insertBefore(btn, tabPanel.firstChild);
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
      var wasIncidents = document.querySelector('.fg-tab-btn[data-tab="attacks"]').classList.contains("active");
      document.querySelectorAll(".fg-tab-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
      document.querySelectorAll(".fg-tab-panel").forEach(function (p) { p.classList.toggle("active", p.getAttribute("data-tab") === tab); });
      // saindo da aba Incidentes: marca "visto até aqui" — o que chegar depois
      // disso aparece com o selo "novo" na próxima vez que a aba for aberta
      if (wasIncidents && tab !== "attacks") {
        window.localStorage.setItem(INCIDENTS_LAST_VISIT_KEY, String(Math.floor(Date.now() / 1000)));
      }
      if (tab === "charts") loadCharts();
      if (tab === "clientguard") loadClientGuard();
    });
  }

  // toggle FlowGuard/ClientGuard dentro da aba Incidentes — mesmo padrão de
  // setRulesApp()/#rules-app-toggle, só que aqui os dois lados são sistemas de
  // detecção diferentes (ataque por prefixo vs sinal por cliente), não a mesma
  // lista filtrada por origem.
  function setIncidentsApp(app) {
    state.incidentsApp = app;
    var appToggle = document.getElementById("incidents-app-toggle");
    if (appToggle) {
      appToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-app") === app);
      });
    }
    document.querySelectorAll("[data-incidents-app]").forEach(function (p) {
      p.hidden = p.getAttribute("data-incidents-app") !== app;
    });
  }

  function initIncidentsControls() {
    var appToggle = document.getElementById("incidents-app-toggle");
    if (appToggle) {
      appToggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        setIncidentsApp(btn.getAttribute("data-app"));
      });
    }
    // barra "Ir para" — pula pra subseção (mesmo padrão de scroll suave do
    // jumpToAttack); se a subseção está no outro lado do toggle
    // FlowGuard/ClientGuard, troca o lado primeiro e depois rola
    var nav = document.getElementById("fg-incidents-nav");
    if (nav) {
      nav.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-incident-nav-btn");
        if (!btn) return;
        var app = btn.getAttribute("data-jump-app");
        if (app && state.incidentsApp !== app) setIncidentsApp(app);
        var target = document.getElementById(btn.getAttribute("data-jump-target"));
        if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
  }

  // aba Incidentes mostra 1 badge só, soma dos dois lados (ataques ativos do
  // FlowGuard + sinais abertos do ClientGuard) — cada lado atualiza sua
  // contagem em state.incidents e updateIncidentsBadge() soma na hora de exibir
  var INCIDENTS_LAST_VISIT_KEY = "fg_incidents_last_visit";
  function isNewIncident(ts) {
    if (!ts) return false;
    var lastVisit = Number(window.localStorage.getItem(INCIDENTS_LAST_VISIT_KEY) || 0);
    return ts > lastVisit;
  }

  // badge com contagem de itens ativos: >0 vira o fg-badge vermelho padrão,
  // 0 vira o neutro cinza (em vez de sumir) — assim os títulos de subseção e
  // a barra "Ir para" não ficam mudando de largura a cada ciclo de poll
  function setIncidentCountBadge(el, count) {
    if (!el) return;
    el.textContent = count;
    el.classList.toggle("fg-badge-neutral", count === 0);
  }

  // ids dos badges por subseção (ao lado de cada <h3> da aba Incidentes) —
  // mesmas chaves de state.incidents usadas na soma do badge da aba e nas
  // contagens da barra "Ir para" (data-nav-count), zero fetch extra
  var INCIDENT_SUBSECTION_BADGES = {
    openAttacks: "fg-sub-attacks-badge",
    openScans: "fg-sub-scanners-badge",
    openCoordinated: "fg-sub-coordinated-badge",
    openSignals: "cg-sub-suspicious-badge",
  };

  function updateIncidentsBadge() {
    var counts = {
      openAttacks: state.incidents.openAttacks || 0,
      openSignals: state.incidents.openSignals || 0,
      openScans: state.incidents.openScans || 0,
      openCoordinated: state.incidents.openCoordinated || 0,
    };
    var badge = document.getElementById("fg-attacks-badge");
    if (badge) {
      var count = counts.openAttacks + counts.openSignals + counts.openScans + counts.openCoordinated;
      if (count > 0) {
        badge.style.display = "inline-block";
        badge.textContent = count;
      } else {
        badge.style.display = "none";
      }
    }
    Object.keys(INCIDENT_SUBSECTION_BADGES).forEach(function (key) {
      setIncidentCountBadge(document.getElementById(INCIDENT_SUBSECTION_BADGES[key]), counts[key]);
    });
    document.querySelectorAll("#fg-incidents-nav [data-nav-count]").forEach(function (el) {
      setIncidentCountBadge(el, counts[el.getAttribute("data-nav-count")] || 0);
    });
  }

  function updateAttacksBadge(count) {
    state.incidents.openAttacks = count;
    updateIncidentsBadge();
  }

  function updateRulesBadge(count) {
    var badge = document.getElementById("fg-rules-badge");
    if (!badge) return;
    if (count > 0) {
      badge.style.display = "inline-block";
      badge.textContent = count;
    } else {
      badge.style.display = "none";
    }
  }

  // badges por lista da aba Regras (ao lado de cada <h3> e na barra "Ir para"
  // #fg-rules-nav) — irmã do updateRulesBadge acima, mesmo padrão do
  // INCIDENT_SUBSECTION_BADGES. Diferença deliberada: aqui o badge fica SEMPRE
  // neutro (regra ativa é estado normal de operação, não um alerta — mesma
  // decisão do fg-badge-neutral do fg-rules-badge da aba). Conta itens ATIVOS
  // "de verdade" a partir do estado bruto (mesmos recortes por lista do
  // applyRulesFilter: origin pro FlowSpec, mechanism pro SSH/ACL), ignorando
  // filtros de host/tipo/janela e o toggle Ativas/Inativas do usuário.
  var RULES_SUBSECTION_BADGES = {
    fgRules: "rules-sub-fg-badge",
    cgFlowspec: "rules-sub-cg-flowspec-badge",
    cgEdge: "rules-sub-cg-edge-badge",
  };

  function setRuleCountBadge(el, count) {
    if (el) el.textContent = count;
  }

  function updateRulesSubsectionBadges() {
    var counts = { fgRules: 0, cgFlowspec: 0, cgEdge: 0 };
    (state.rulesFgData || []).forEach(function (r) {
      if (!r.active) return;
      if (r.origin === "clientguard") counts.cgFlowspec++;
      else counts.fgRules++;
    });
    (state.rulesCgEdgeData || []).forEach(function (m) {
      if (m.mechanism !== "flowspec" && m.status === "active") counts.cgEdge++;
    });
    Object.keys(RULES_SUBSECTION_BADGES).forEach(function (key) {
      setRuleCountBadge(document.getElementById(RULES_SUBSECTION_BADGES[key]), counts[key]);
    });
    document.querySelectorAll("#fg-rules-nav [data-nav-count]").forEach(function (el) {
      setRuleCountBadge(el, counts[el.getAttribute("data-nav-count")] || 0);
    });
  }

  // --- cockpit (aba Visão Geral, customizável) ------------------------------
  // Regra de ouro: nenhum widget dispara fetch próprio — só lê o que o poll()
  // de 5s já trouxe (state.status/state.attacks/state.rulesFgData/
  // state.rulesCgEdgeData/state.cgStatus/warmodeActive). "traffic" e
  // "topPrefixes" reaproveitam os elementos/renderers que já existiam nessa
  // aba (renderSparklines, renderTopPrefixesFiltered) — só mudaram de moldura.

  var COCKPIT_STORAGE_KEY = "fg-cockpit-layout";

  var COCKPIT_WIDGETS = [
    { id: "traffic", title: "Tráfego em Tempo Real", size: "lg", accent: "var(--fg-accent)" },
    // hint: mesmo contador do KPI global "Ataques Ativos" (barra do topo,
    // sempre visível) — o card acrescenta o detalhe por severidade e pode
    // ser ocultado/reordenado; o tooltip só deixa a redundância explícita
    { id: "attacks", title: "Ataques Ativos", size: "sm", accent: "var(--fg-danger)", hint: "Mesmo contador do indicador “Ataques Ativos” da barra do topo — aqui com o detalhe por severidade." },
    { id: "bgp", title: "BGP (ExaBGP)", size: "sm", accent: "var(--fg-success)" },
    { id: "mitigations", title: "Mitigações de Borda", size: "sm", accent: "var(--fg-orange)" },
    { id: "warmode", title: "Modo Guerra", size: "sm", accent: "var(--fg-danger)" },
    { id: "clientguard", title: "ClientGuard", size: "md", accent: "#a371f7" },
    { id: "topPrefixes", title: "Meus Prefixos", size: "lg", accent: "var(--fg-accent)" },
    { id: "rules", title: "Regras Ativas (FlowSpec/RTBH)", size: "sm", accent: "var(--fg-warning)" },
    { id: "daemon", title: "Daemon", size: "sm", accent: "var(--fg-success)" },
  ];

  // cards com destino de navegação — clique fora do modo edição pula pra
  // aba/subseção correspondente (mesmo padrão de scroll do jumpToAttack /
  // fg-rules-nav / fg-incidents-nav), pra não deixar "Regras Ativas" e
  // "ClientGuard" como número solto sem link pro detalhe
  var COCKPIT_JUMP_TARGETS = {
    rules: { tab: "rules", target: "rules-sub-fg", setApp: function () { setRulesApp("flowguard"); } },
    clientguard: { tab: "attacks", target: "cg-sub-suspicious", setApp: function () { setIncidentsApp("clientguard"); } },
  };

  function cockpitJumpToWidget(id) {
    var jump = COCKPIT_JUMP_TARGETS[id];
    if (!jump) return;
    document.querySelectorAll(".fg-tab-btn").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-tab") === jump.tab);
    });
    document.querySelectorAll(".fg-tab-panel").forEach(function (p) {
      p.classList.toggle("active", p.getAttribute("data-tab") === jump.tab);
    });
    if (jump.setApp) jump.setApp();
    var target = document.getElementById(jump.target);
    if (!target) return;
    // alvo na aba Regras vive dentro de uma seção colapsável (diferente da
    // aba Incidentes) — expande antes de rolar, mesmo tratamento do fg-rules-nav
    var section = target.closest("section.fg-panel-section");
    if (section && section.classList.contains("fg-panel-collapsed")) {
      setPanelCollapsed(section, false);
      localStorage.setItem(panelStorageKey(section), "0");
    }
    target.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function cockpitLoadLayout() {
    var fallback = COCKPIT_WIDGETS.map(function (w) { return { id: w.id, visible: true, size: null }; });
    try {
      var saved = JSON.parse(localStorage.getItem(COCKPIT_STORAGE_KEY) || "null");
      if (!Array.isArray(saved) || !saved.length) return fallback;
      var known = COCKPIT_WIDGETS.map(function (w) { return w.id; });
      var savedIds = saved.map(function (s) { return s.id; });
      // reconcilia com o catálogo atual: widget novo no código (ainda não
      // salvo) entra visível no fim; id órfão (widget removido) é descartado
      var ordered = saved.filter(function (s) { return known.indexOf(s.id) !== -1; });
      known.forEach(function (id) {
        if (savedIds.indexOf(id) === -1) ordered.push({ id: id, visible: true, size: null });
      });
      return ordered.length ? ordered : fallback;
    } catch (e) {
      return fallback;
    }
  }

  function cockpitPersistCurrentOrder() {
    var grid = document.getElementById("fg-cockpit-grid");
    if (!grid) return;
    var layout = Array.prototype.map.call(grid.querySelectorAll(".fg-cockpit-card"), function (card) {
      return {
        id: card.getAttribute("data-widget-id"),
        visible: !card.classList.contains("fg-cockpit-hidden"),
        size: card.getAttribute("data-size"),
      };
    });
    localStorage.setItem(COCKPIT_STORAGE_KEY, JSON.stringify(layout));
  }

  function cockpitWidgetBodyHtml(id) {
    if (id === "traffic") return '<div id="flowguard-sparklines"></div>';
    if (id === "topPrefixes") {
      return (
        '<div class="fg-toolbar"><input type="text" id="fg-top-prefixes-search" placeholder="filtrar por prefixo..."></div>' +
        '<div id="flowguard-top-prefixes"><div class="fg-skeleton-lines"><span class="fg-skeleton-line"></span>' +
        '<span class="fg-skeleton-line"></span><span class="fg-skeleton-line"></span></div></div>'
      );
    }
    return (
      '<div id="fg-cockpit-body-' + id + '"><span class="fg-skeleton-lines fg-skeleton-sm">' +
      '<span class="fg-skeleton-line"></span></span></div>'
    );
  }

  function cockpitCardHtml(w, size, visible) {
    // "oculto" é uma CLASSE (fg-cockpit-hidden), não o atributo [hidden]
    // nativo: o CSS só some com o card fora do modo edição — durante a
    // edição ele fica esmaecido, com o checkbox acessível pra reexibir
    var jumpable = !!COCKPIT_JUMP_TARGETS[w.id];
    return (
      '<div class="fg-cockpit-card' + (visible ? "" : " fg-cockpit-hidden") + (jumpable ? " fg-cockpit-clickable" : "") + '" data-widget-id="' + w.id + '" data-size="' + size + '" style="--cockpit-accent:' + w.accent + '"' +
      (jumpable ? ' title="Clique para ver o detalhe"' : "") + ">" +
      '<div class="fg-cockpit-card-head">' +
      '<label class="fg-cockpit-visibility" hidden><input type="checkbox"' + (visible ? " checked" : "") + '></label>' +
      '<span class="fg-cockpit-drag-handle" hidden>⠿</span>' +
      "<h3" + (w.hint ? ' title="' + escapeHtml(w.hint) + '"' : "") + ">" + escapeHtml(w.title) + "</h3>" +
      "</div>" +
      '<div class="fg-cockpit-card-body">' + cockpitWidgetBodyHtml(w.id) + "</div>" +
      "</div>"
    );
  }

  function cockpitEnableDragForCard(card) {
    card.addEventListener("dragstart", function (ev) {
      ev.dataTransfer.setData("text/plain", card.getAttribute("data-widget-id"));
      ev.dataTransfer.effectAllowed = "move";
      card.classList.add("fg-cockpit-dragging");
    });
    card.addEventListener("dragend", function () {
      card.classList.remove("fg-cockpit-dragging");
    });
    card.addEventListener("dragover", function (ev) {
      if (!state.cockpitEditing) return;
      ev.preventDefault();
      card.classList.add("fg-cockpit-dragover");
    });
    card.addEventListener("dragleave", function () {
      card.classList.remove("fg-cockpit-dragover");
    });
    card.addEventListener("drop", function (ev) {
      ev.preventDefault();
      card.classList.remove("fg-cockpit-dragover");
      if (!state.cockpitEditing) return;
      var draggedId = ev.dataTransfer.getData("text/plain");
      var grid = document.getElementById("fg-cockpit-grid");
      var draggedCard = grid.querySelector('.fg-cockpit-card[data-widget-id="' + draggedId + '"]');
      if (!draggedCard || draggedCard === card) return;
      var cards = Array.prototype.slice.call(grid.querySelectorAll(".fg-cockpit-card"));
      var draggedIndex = cards.indexOf(draggedCard);
      var targetIndex = cards.indexOf(card);
      if (draggedIndex < targetIndex) grid.insertBefore(draggedCard, card.nextSibling);
      else grid.insertBefore(draggedCard, card);
      cockpitPersistCurrentOrder();
    });
  }

  function cockpitSetEditing(editing) {
    state.cockpitEditing = editing;
    var grid = document.getElementById("fg-cockpit-grid");
    if (!grid) return;
    grid.classList.toggle("fg-cockpit-editing-mode", editing);
    grid.querySelectorAll(".fg-cockpit-card").forEach(function (card) {
      card.draggable = editing;
      var vis = card.querySelector(".fg-cockpit-visibility");
      var handle = card.querySelector(".fg-cockpit-drag-handle");
      if (vis) vis.hidden = !editing;
      if (handle) handle.hidden = !editing;
    });
    // troca só o texto do span de rótulo — setar textContent no botão
    // inteiro apagava o ícone SVG na primeira alternância
    var btnLabel = document.getElementById("fg-cockpit-customize-label");
    if (btnLabel) btnLabel.textContent = editing ? "Concluir personalização" : "Personalizar";
    var resetBtn = document.getElementById("fg-cockpit-reset-btn");
    if (resetBtn) resetBtn.hidden = !editing;
    var hint = document.getElementById("fg-cockpit-edit-hint");
    if (hint) hint.hidden = !editing;
    if (!editing) cockpitPersistCurrentOrder();
  }

  // (re)monta os cards do grid a partir de um layout (salvo ou padrão) e
  // religa o drag&drop de cada card — extraído do initCockpit pra que o
  // "Restaurar layout padrão" reuse sem recarregar a página
  function cockpitRenderGrid(layout) {
    var grid = document.getElementById("fg-cockpit-grid");
    if (!grid) return;
    var widgetsById = {};
    COCKPIT_WIDGETS.forEach(function (w) { widgetsById[w.id] = w; });

    grid.innerHTML = layout
      .map(function (entry) {
        var w = widgetsById[entry.id];
        if (!w) return "";
        return cockpitCardHtml(w, entry.size || w.size, entry.visible !== false);
      })
      .join("");

    grid.querySelectorAll(".fg-cockpit-card").forEach(cockpitEnableDragForCard);
  }

  function initCockpit() {
    var grid = document.getElementById("fg-cockpit-grid");
    if (!grid) return;
    cockpitRenderGrid(cockpitLoadLayout());

    grid.addEventListener("change", function (ev) {
      var checkbox = ev.target.closest(".fg-cockpit-visibility input");
      if (!checkbox) return;
      var card = checkbox.closest(".fg-cockpit-card");
      // classe própria em vez de card.hidden: em modo edição o CSS mantém o
      // card visível (esmaecido) pra dar como desfazer; ele só some de fato
      // quando o usuário conclui a personalização
      card.classList.toggle("fg-cockpit-hidden", !checkbox.checked);
      cockpitPersistCurrentOrder();
    });

    // clique no card (fora do modo edição, fora do checkbox/handle) pula pra
    // aba/subseção do detalhe — só cards em COCKPIT_JUMP_TARGETS respondem
    grid.addEventListener("click", function (ev) {
      if (state.cockpitEditing) return;
      if (ev.target.closest(".fg-cockpit-visibility") || ev.target.closest(".fg-cockpit-drag-handle")) return;
      var card = ev.target.closest(".fg-cockpit-card");
      if (!card) return;
      cockpitJumpToWidget(card.getAttribute("data-widget-id"));
    });

    // delegação no grid (não no input direto) porque o "Restaurar layout
    // padrão" recria o innerHTML — um listener no input morreria junto
    grid.addEventListener("input", function (ev) {
      if (!ev.target || ev.target.id !== "fg-top-prefixes-search") return;
      state.filter.topPrefixes = ev.target.value;
      state.page.topPrefixes = 1;
      renderTopPrefixesFiltered();
    });

    var customizeBtn = document.getElementById("fg-cockpit-customize-btn");
    if (customizeBtn) {
      customizeBtn.addEventListener("click", function () { cockpitSetEditing(!state.cockpitEditing); });
    }

    var resetBtn = document.getElementById("fg-cockpit-reset-btn");
    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        localStorage.removeItem(COCKPIT_STORAGE_KEY);
        cockpitRenderGrid(cockpitLoadLayout()); // sem layout salvo → catálogo padrão
        cockpitSetEditing(state.cockpitEditing); // reaplica controles/draggable nos cards novos
        // repopula na hora com o que o poll já trouxe (senão ficaria em
        // skeleton até o próximo ciclo de 5s)
        if (state.status && state.status.ok) {
          renderSparklines(state.status.protocol_series);
          renderTopPrefixesFiltered();
        }
        cockpitRefreshAll();
      });
    }

    cockpitRefreshAll();
  }

  function cockpitSetBody(id, html) {
    var el = document.getElementById("fg-cockpit-body-" + id);
    if (el) el.innerHTML = html;
  }

  function cockpitRenderAttacks() {
    var s = state.status;
    var total = s && s.ok && s.stats ? s.stats.active_attacks : null;
    var body =
      '<div class="fg-cockpit-big-number ' + (total ? "fg-sev-critical" : "fg-ok") + '">' + (total == null ? "-" : total) + "</div>" +
      '<div class="fg-kpi-sub">' + (total ? "requer atenção" : "tudo normal") + "</div>";
    // detalhe por severidade só é confiável quando o snapshot em state.attacks
    // é mesmo da view "active" (o filtro é compartilhado com a aba Ataques,
    // não é exclusivo do cockpit) — na "Histórico" simplesmente omite, pra
    // não mostrar severidade de um recorte que não é o de ataques ativos
    if (state.attacksView === "active" && state.attacks && state.attacks.length) {
      var counts = { critical: 0, high: 0, medium: 0, info: 0 };
      state.attacks.forEach(function (a) { if (counts[a.severity] != null) counts[a.severity]++; });
      var order = ["critical", "high", "medium", "info"];
      var sevLabels = { critical: "crítico", high: "alto", medium: "médio", info: "info" };
      var breakdown = order
        .filter(function (sv) { return counts[sv] > 0; })
        .map(function (sv) { return '<span class="fg-sev-' + sv + '">' + counts[sv] + " " + sevLabels[sv] + "</span>"; })
        .join(" · ");
      if (breakdown) body += '<div class="fg-cockpit-sev-row">' + breakdown + "</div>";
    }
    cockpitSetBody("attacks", body);
  }

  function cockpitRenderBgp() {
    var s = state.status;
    if (!s || !s.ok) { cockpitSetBody("bgp", '<p class="fg-kpi-sub">sem dado</p>'); return; }
    var bgpMain = s.bgp || {};
    var bgpPppoe = s.bgp_pppoe || {};
    var pppoeConfigured = bgpPppoe.peer_state && bgpPppoe.peer_state !== "unconfigured";
    var html = bgpPeerRow("NE8000BGP", bgpMain);
    if (pppoeConfigured) html += bgpPeerRow("NE8000-PPPOE", bgpPppoe);
    cockpitSetBody("bgp", html);
  }

  function cockpitRenderMitigations() {
    var active = (state.rulesCgEdgeData || []).filter(function (m) { return m.status === "active"; }).length;
    cockpitSetBody("mitigations",
      '<div class="fg-cockpit-big-number' + (active ? " fg-sev-high" : " fg-ok") + '">' + active + "</div>" +
      '<div class="fg-kpi-sub">ClientGuard · FlowSpec/SSH</div>');
  }

  function cockpitRenderWarmode() {
    var html = warmodeActive
      ? '<div class="fg-cockpit-big-number fg-sev-critical">ATIVO</div><div class="fg-kpi-sub">há ' +
        fmtWarmodeElapsed(Date.now() / 1000 - (warmodeStartedAt || Date.now() / 1000)) + "</div>"
      : '<div class="fg-cockpit-big-number fg-ok">desligado</div>';
    cockpitSetBody("warmode", html);
  }

  function cockpitRenderClientGuard() {
    var s = state.cgStatus;
    if (!s) { cockpitSetBody("clientguard", '<p class="fg-kpi-sub">carregando...</p>'); return; }
    cockpitSetBody("clientguard",
      '<div class="fg-cockpit-big-number' + (s.open_signals ? " fg-sev-high" : " fg-ok") + '">' + s.open_signals +
      '</div><div class="fg-kpi-sub">sinais abertos</div>');
  }

  function cockpitRenderRules() {
    var active = (state.rulesFgData || []).filter(function (r) { return r.active; }).length;
    cockpitSetBody("rules", '<div class="fg-cockpit-big-number">' + active + '</div><div class="fg-kpi-sub">FlowSpec/RTBH</div>');
  }

  function cockpitRenderDaemon() {
    var s = state.status;
    if (!s || !s.ok || !s.daemon || !s.daemon.alive) {
      cockpitSetBody("daemon", '<span class="fg-dot fg-dot-down"></span>indisponível');
      return;
    }
    cockpitSetBody("daemon",
      '<span class="fg-dot fg-dot-up"></span>ativo<div class="fg-kpi-sub">uptime ' +
      fmtUptime(s.daemon.uptime_s) + " · pid " + s.daemon.pid + "</div>");
  }

  function cockpitRefreshAll() {
    if (!document.getElementById("fg-cockpit-grid")) return;
    cockpitRenderAttacks();
    cockpitRenderBgp();
    cockpitRenderMitigations();
    cockpitRenderWarmode();
    cockpitRenderClientGuard();
    cockpitRenderRules();
    cockpitRenderDaemon();
  }

  // --- KPIs ---------------------------------------------------------------

  function kpiCard(label, valueHtml, sub, trendHtml, danger) {
    return (
      '<div class="fg-card' + (danger ? " fg-card-danger" : "") + '"><div class="fg-kpi-label">' + escapeHtml(label) + '</div>' +
      '<div class="fg-kpi-value">' + valueHtml + '</div>' +
      '<div class="fg-kpi-sub">' + escapeHtml(sub || "") + (trendHtml || "") + '</div></div>'
    );
  }

  // seta de tendência comparando o valor atual com a média da primeira
  // metade do minuto de histórico em memória (suaviza ruído de um poll só) —
  // só aparece depois de ter buffer suficiente e quando a variação é notável
  // Uma sessão BGP por linha dentro do card "BGP (ExaBGP)" — hoje temos 2
  // sessões simultâneas no mesmo exabgp.conf (main = NE8000BGP, pppoe =
  // NE8000-PPPOE), cada uma com seu próprio estado (mesmo padrão já usado por
  // flowguard-cli.py status). 'unconfigured' (peer sem bgp.peer_ip_<nome> no
  // config.yaml) não aparece — não é uma sessão que deveria existir.
  function bgpPeerRow(label, peer) {
    var state = (peer || {}).peer_state;
    var dotClass = state === "up" ? "fg-dot-up" : "fg-dot-down";
    var stateText = state === "up" ? "Up" : "Down/Idle";
    return '<div class="fg-bgp-peer"><span class="fg-dot ' + dotClass + '"></span><strong>' +
      escapeHtml(label) + "</strong> " + stateText + "</div>";
  }

  function bgpPeerSubText(label, peer) {
    var detail = peer.peer_state === "up" ? peer.peer_ip : (peer.detail || peer.reason || peer.peer_ip);
    return detail ? label + ": " + detail : "";
  }

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

    var bgpMain = data.bgp || {};
    var bgpPppoe = data.bgp_pppoe || {};
    var pppoeConfigured = bgpPppoe.peer_state && bgpPppoe.peer_state !== "unconfigured";

    var bgpHtml = bgpPeerRow("NE8000BGP", bgpMain);
    var bgpSubParts = [bgpPeerSubText("NE8000BGP", bgpMain)];
    var bgpAnyDown = bgpMain.peer_state !== "up";
    if (pppoeConfigured) {
      bgpHtml += bgpPeerRow("NE8000-PPPOE", bgpPppoe);
      bgpSubParts.push(bgpPeerSubText("NE8000-PPPOE", bgpPppoe));
      bgpAnyDown = bgpAnyDown || bgpPppoe.peer_state !== "up";
    }
    var bgpSub = bgpSubParts.filter(Boolean).join(" · ");

    var bpsTrend = kpiTrend("bps", s.bps);
    var ppsTrend = kpiTrend("pps", s.pps);

    var activeEdgeMitigations = state.rulesCgEdgeData.filter(function (m) { return m.status === "active"; }).length;

    // entrada + saída na MESMA caixa (pedido do usuário, 2026-07-10) — o KPI só
    // mostrava entrada, causando confusão comparando com ferramentas externas
    // (Grafana/SNMP) que podem somar/mostrar direção diferente. Deixar as duas
    // explícitas evita esse tipo de comparação ambígua de novo.
    var trafficValueHtml =
      fmtBps(s.bps) + ' <span style="font-size:0.5em; opacity:0.7;">↓ entrada</span><br>' +
      fmtBps(s.bps_out || 0) + ' <span style="font-size:0.5em; opacity:0.7;">↑ saída</span>';

    el.innerHTML =
      kpiCard("Tráfego", trafficValueHtml, s.flows + " flows/s", bpsTrend) +
      kpiCard("Pacotes/s", Number(s.pps).toLocaleString("pt-BR"), "", ppsTrend) +
      kpiCard("Ataques Ativos", s.active_attacks, s.active_attacks > 0 ? "requer atenção" : "tudo normal") +
      kpiCard("Regras FlowSpec", s.active_rules, "", null, s.active_rules > 0) +
      kpiCard("Mitigações de Borda", activeEdgeMitigations, "ClientGuard · FlowSpec/SSH", null, activeEdgeMitigations > 0) +
      kpiCard("BGP (ExaBGP)", bgpHtml, bgpSub, null, bgpAnyDown) +
      kpiCard("Daemon", daemonHtml, daemonSub);

    updateAttacksBadge(s.active_attacks);
    updateRulesBadge(s.active_rules);
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

  var SEV_RANK = { critical: 0, high: 1, medium: 2, info: 3 };

  function attackRowHtml(a) {
    var sevClass = "fg-sev-" + a.severity;
    var suggestion = a.suggested_mitigation;
    var suggestionMenuItem = suggestion
      ? '<span class="fg-menu-hint">' + escapeHtml(suggestion.label) + "</span>" +
        '<button data-action="apply_suggestion">Aplicar sugestão</button>'
      : "";
    var targetHtml = a.target_host
      ? escapeHtml(a.target_host) + "/32" + '<br><span class="fg-kpi-sub">' + escapeHtml(a.dst_prefix) + "</span>"
      : escapeHtml(a.dst_prefix);
    var checkboxCell = state.attacksSelectMode
      ? '<td><input type="checkbox" class="fg-attack-select"' + (state.attacksSelected[a.id] ? " checked" : "") + "></td>"
      : "";
    var newBadge = isNewIncident(a.ts_start) ? ' <span class="fg-badge" title="novo desde a última visita à aba">novo</span>' : "";
    return (
      '<tr data-attack-id="' + a.id + '" data-prefix="' + escapeHtml(a.dst_prefix) + '">' +
      checkboxCell +
      "<td>" + fmtDateTime(a.ts_start) + newBadge + "</td>" +
      "<td>" + fmtAttackDuration(a) + (a.ts_end ? "" : fmtActivityFreshness(a.ts_last_seen)) + "</td>" +
      '<td class="fg-wrap-cell">' + targetHtml + "</td>" +
      "<td>" + escapeHtml(a.customer || "-") + "</td>" +
      "<td>" + escapeHtml(a.attack_type) + "</td>" +
      "<td class=\"" + sevClass + "\">" + escapeHtml(a.severity) + "</td>" +
      "<td>" + fmtBps(a.bps_peak || 0) + "</td>" +
      "<td>" + (a.pps_peak || 0).toLocaleString("pt-BR") + " pps</td>" +
      "<td>" + fgAttackMitigationBadgeHtml(a.mitigation, isGenuinelyActive(a.ts_end, a.ts_last_seen)) + "</td>" +
      '<td><div class="fg-menu">' +
      '<button class="fg-btn" data-menu-toggle>Ações ▾</button>' +
      '<div class="fg-menu-list" hidden>' +
      '<button data-action="detail">Detalhes</button>' +
      '<button data-action="analyze">Detalhes IA</button>' +
      '<input type="number" class="fg-mitigate-ttl-min" min="1" step="1" ' +
      'placeholder="min RTBH (padrão)" title="Duração do bloqueio RTBH em minutos — deixe em branco para usar o padrão configurado (aba Configuração > Mitigação)">' +
      '<button data-action="mitigate">Mitigar</button>' +
      '<button data-action="release">Liberar</button>' +
      suggestionMenuItem +
      "</div></div></td></tr>"
    );
  }

  var ATTACKS_TABLE_HEAD =
    "<th>Início</th><th>Duração</th><th>Alvo</th><th>Cliente</th><th>Tipo</th><th>Severidade</th>" +
    "<th>Pico (bps)</th><th>Pico (pps)</th><th>Mitigação</th><th>Ações</th>";

  // agrupamento por prefixo (botão "Agrupar por prefixo") — grupo com pior
  // severidade abaixo de high começa colapsado, igual ao padrão da aba
  // Incidentes do poxflow v2. Paginação não se aplica nesse modo (é outra
  // forma de navegar a mesma lista, não faz sentido cortar por página).
  function renderAttacksGrouped(rows) {
    var groups = {};
    var order = [];
    rows.forEach(function (a) {
      var key = a.dst_prefix || "-";
      if (!groups[key]) { groups[key] = []; order.push(key); }
      groups[key].push(a);
    });
    var colspan = (state.attacksSelectMode ? 1 : 0) + 10;
    var body = order.map(function (key) {
      var items = groups[key].slice().sort(function (a, b) { return (SEV_RANK[a.severity] || 9) - (SEV_RANK[b.severity] || 9); });
      var worst = items[0].severity;
      var collapsed = state.attacksCollapsedGroups[key];
      if (collapsed === undefined) collapsed = SEV_RANK[worst] > 1;
      var rowsHtml = collapsed ? "" : items.map(attackRowHtml).join("");
      return (
        '<tr class="fg-group-head" data-group-key="' + escapeHtml(key) + '">' +
        '<td colspan="' + colspan + '" class="fg-sev-' + worst + '" style="cursor:pointer;">' +
        (collapsed ? "▸ " : "▾ ") + escapeHtml(key) + " — " + items.length +
        (items.length === 1 ? " incidente" : " incidentes") + " · pior: " + escapeHtml(worst) +
        "</td></tr>" + rowsHtml
      );
    }).join("");
    return (
      "<table><thead><tr>" + (state.attacksSelectMode ? "<th></th>" : "") + ATTACKS_TABLE_HEAD + "</tr></thead><tbody>" +
      body + "</tbody></table>"
    );
  }

  function refreshAttacksBulkBar() {
    var bar = document.getElementById("fg-attacks-bulkbar");
    if (!bar) return;
    var n = Object.keys(state.attacksSelected).length;
    bar.hidden = !state.attacksSelectMode || n === 0;
    var countEl = document.getElementById("fg-attacks-bulk-count");
    if (countEl) countEl.textContent = n + " selecionado(s)";
  }

  function renderAttacks(attacks) {
    var el = document.getElementById("flowguard-attacks");
    if (!el) return;

    if (!attacks.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum ataque encontrado para o filtro atual.</p>';
      refreshAttacksBulkBar();
      return;
    }

    if (state.attacksGroupBy) {
      el.innerHTML = renderAttacksGrouped(attacks);
      refreshAttacksBulkBar();
      return;
    }

    var p = paginate(attacks, "attacks");
    var rows = p.pageRows.map(attackRowHtml).join("");

    el.innerHTML =
      "<table><thead><tr>" + (state.attacksSelectMode ? "<th></th>" : "") + ATTACKS_TABLE_HEAD + "</tr></thead><tbody>" +
      rows +
      "</tbody></table>" +
      paginationHtml("attacks", p.page, p.totalPages, p.total);
    refreshAttacksBulkBar();
  }

  function renderAttacksFiltered() {
    var rows = state.attacks;
    if (state.filter.attacksSeverities.length) {
      rows = rows.filter(function (a) { return state.filter.attacksSeverities.indexOf(a.severity) !== -1; });
    }
    rows = filterRows(rows, state.filter.attacksPrefix, ["dst_prefix", "customer"]);
    renderAttacks(rows);
  }

  // linha do tempo vertical do incidente (detecção/mitigação/encerramento) —
  // mesma ideia do componente Timeline do poxflow v2, construída só com dados
  // que o V1 já tem (sem endpoint novo). Reaproveitada tanto no painel de
  // detalhe quanto no dossiê exportado, pra não duplicar a lógica dos itens.
  function buildAttackTimelineItems(a) {
    var items = [{ ts: a.ts_start, icon: "🚨", label: "Detecção — " + a.attack_type + " (" + a.severity + ")" }];
    if (a.mitigation && a.mitigation.created_at) {
      var actionLabel = FG_MITIGATION_ACTION_LABELS[a.mitigation.action] || a.mitigation.action || "-";
      items.push({ ts: a.mitigation.created_at, icon: "🛡", label: "Mitigação " + (a.mitigation.active ? "aplicada" : "registrada") + " (" + actionLabel + ")" });
    }
    if (a.ts_end) {
      items.push({ ts: a.ts_end, icon: "✅", label: "Encerrado" });
    } else if (a.ts_last_seen) {
      items.push({ ts: a.ts_last_seen, icon: "🔎", label: "Última confirmação da condição" });
    }
    items.sort(function (x, y) { return (x.ts || 0) - (y.ts || 0); });
    return items;
  }

  function timelineItemsToHtml(items) {
    return '<ul class="fg-timeline">' + items.map(function (it) {
      return "<li>" + it.icon + " <strong>" + fmtDateTime(it.ts) + "</strong> — " + escapeHtml(it.label) + "</li>";
    }).join("") + "</ul>";
  }

  function downloadTextFile(filename, text) {
    var blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function fgNoteKey(attackId) {
    return "fg_note_fg-" + attackId;
  }

  function doExportAttackDossier(prefix, attack, resp) {
    var note = window.localStorage.getItem(fgNoteKey(attack.id)) || "";
    var summary = resp.summary || {};
    var lines = [
      "Dossiê de incidente — FlowGuard",
      "Alvo: " + prefix + (attack.target_host ? " (host " + attack.target_host + "/32)" : ""),
      "Cliente: " + (attack.customer || "-"),
      "Tipo: " + attack.attack_type + " · Severidade: " + attack.severity,
      "Início: " + fmtDateTime(attack.ts_start),
      "Fim: " + (attack.ts_end ? fmtDateTime(attack.ts_end) : "em andamento"),
      "Pico: " + fmtBps(attack.bps_peak || 0) + " / " + (attack.pps_peak || 0) + " pps",
      "Duração: " + fmtUptime(summary.duration_s || 0),
      "",
      "Linha do tempo:",
    ];
    buildAttackTimelineItems(attack).forEach(function (it) { lines.push("  " + fmtDateTime(it.ts) + " — " + it.label); });
    lines.push("");
    lines.push("Nota do operador:");
    lines.push(note || "(sem nota)");
    downloadTextFile("incidente-fg-" + attack.id + ".txt", lines.join("\n"));
  }

  function renderAttackDetail(prefix, resp, attack) {
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
    var timelineHtml = attack ? "<h5>Linha do tempo do incidente</h5>" + timelineItemsToHtml(buildAttackTimelineItems(attack)) : "";
    var noteKey = attack ? fgNoteKey(attack.id) : null;
    var savedNote = noteKey ? (window.localStorage.getItem(noteKey) || "") : "";
    var noteHtml = noteKey
      ? "<h5>Nota do operador</h5>" +
        '<textarea id="fg-attack-note" rows="3" style="width:100%;" placeholder="nota interna, salva só neste navegador...">' +
        escapeHtml(savedNote) + "</textarea>" +
        '<div class="fg-toolbar" style="margin-top:0.4rem;"><button class="fg-btn" id="fg-attack-export-btn">Exportar dossiê (.txt)</button></div>'
      : "";
    el.innerHTML =
      '<div class="fg-ai-panel"><div class="fg-panel-header"><h4>Detalhes — ' + escapeHtml(prefix) + "</h4>" +
      '<button class="fg-btn" data-action="close-detail">Fechar</button></div>' +
      '<p class="fg-kpi-sub">' + summaryLine + "</p>" +
      timelineHtml +
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
      noteHtml +
      "</div>";
    var canvas = document.getElementById("fg-attack-detail-chart");
    if (canvas) {
      drawLineChart(canvas, series, [{ key: "bps", color: "#58a6ff", label: "tráfego (bps)" }]);
    }
    if (noteKey) {
      var noteEl = document.getElementById("fg-attack-note");
      if (noteEl) {
        noteEl.addEventListener("input", function () { window.localStorage.setItem(noteKey, noteEl.value); });
      }
      var exportBtn = document.getElementById("fg-attack-export-btn");
      if (exportBtn) {
        exportBtn.addEventListener("click", function () { doExportAttackDossier(prefix, attack, resp); });
      }
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

  function onAttacksBulkReleaseClick() {
    var ids = Object.keys(state.attacksSelected);
    if (!ids.length) return;
    var preview = ids.slice(0, 8).join(", ") + (ids.length > 8 ? "…" : "");
    if (!window.confirm("Liberar " + ids.length + " ataque(s) selecionado(s)? IDs: " + preview)) return;
    var btn = document.getElementById("fg-attacks-bulk-release-btn");
    btn.disabled = true;
    Promise.all(ids.map(function (id) {
      return postJson(ATTACKS_ENDPOINT, { action: "release", attack_id: Number(id) });
    })).then(function () {
      showToast(ids.length + " ataque(s) liberado(s)", "success");
      state.attacksSelected = {};
      state.attacksSelectMode = false;
      var selectBtn = document.getElementById("fg-attacks-select-btn");
      if (selectBtn) selectBtn.classList.remove("active");
      loadAttacks();
    }).catch(function () {
      showToast("falha ao liberar ataques em lote", "error");
    }).finally(function () { btn.disabled = false; });
  }

  function onAttacksClick(ev) {
    var groupHead = ev.target.closest("tr.fg-group-head");
    if (groupHead) {
      var key = groupHead.getAttribute("data-group-key");
      state.attacksCollapsedGroups[key] = !state.attacksCollapsedGroups[key];
      renderAttacksFiltered();
      return;
    }

    var checkbox = ev.target.closest("input.fg-attack-select");
    if (checkbox) {
      var selRow = checkbox.closest("tr[data-attack-id]");
      var selId = Number(selRow.getAttribute("data-attack-id"));
      if (checkbox.checked) state.attacksSelected[selId] = true;
      else delete state.attacksSelected[selId];
      refreshAttacksBulkBar();
      return;
    }

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
      var attackMeta = (state.attacks || []).filter(function (x) { return x.id === attackId; })[0] || null;
      getJson(ATTACKS_ENDPOINT + "?detail=" + attackId).then(function (resp) {
        renderAttackDetail(prefix, resp, attackMeta);
        done();
      }).catch(done);
      return;
    }

    var successLabel = {
      mitigate: "Mitigação solicitada para ",
      release: "Liberação solicitada para ",
      apply_suggestion: "Mitigação sugerida aplicada para ",
    }[action] || "Ação aplicada para ";

    var body = { action: action, attack_id: attackId };
    if (action === "mitigate") {
      var ttlInput = row.querySelector(".fg-mitigate-ttl-min");
      var ttlMin = ttlInput && ttlInput.value ? Number(ttlInput.value) : NaN;
      if (!isNaN(ttlMin) && ttlMin > 0) body.ttl_s = Math.round(ttlMin * 60);
    }

    postJson(ATTACKS_ENDPOINT, body).then(function (resp) {
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
    var sevChips = document.getElementById("fg-attacks-severity-chips");
    if (sevChips) {
      sevChips.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        var sev = btn.getAttribute("data-sev");
        var idx = state.filter.attacksSeverities.indexOf(sev);
        if (idx === -1) { state.filter.attacksSeverities.push(sev); btn.classList.add("active"); }
        else { state.filter.attacksSeverities.splice(idx, 1); btn.classList.remove("active"); }
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
    var groupBtn = document.getElementById("fg-attacks-group-btn");
    if (groupBtn) {
      groupBtn.addEventListener("click", function () {
        state.attacksGroupBy = !state.attacksGroupBy;
        groupBtn.classList.toggle("active", state.attacksGroupBy);
        renderAttacksFiltered();
      });
    }
    var selectBtn = document.getElementById("fg-attacks-select-btn");
    if (selectBtn) {
      selectBtn.addEventListener("click", function () {
        state.attacksSelectMode = !state.attacksSelectMode;
        selectBtn.classList.toggle("active", state.attacksSelectMode);
        if (!state.attacksSelectMode) state.attacksSelected = {};
        renderAttacksFiltered();
      });
    }
    var bulkReleaseBtn = document.getElementById("fg-attacks-bulk-release-btn");
    if (bulkReleaseBtn) bulkReleaseBtn.addEventListener("click", onAttacksBulkReleaseClick);
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

  // --- regras: histórico unificado (FlowGuard BGP + ClientGuard SSH/ACL) ----
  // Uma única fonte pro FlowGuard/ClientGuard-via-proxy (RULES_ENDPOINT, que já
  // devolve todo mundo — a separação por app é o campo `origin`, ver
  // collector/storage.py do FlowGuard) e outra pra mitigação direta do
  // ClientGuard (CG_EDGE_ENDPOINT, já usada na aba ClientGuard). Filtro de
  // app/ativas-histórico é 100% client-side (a lista de regras nunca chega
  // perto do volume de flow_aggs/client_flow_aggs, não precisa filtrar no
  // backend pra cada combinação).

  function fmtRuleType(r) {
    if (r.action === "rtbh") return "RTBH (blackhole)";
    if (r.action === "discard") return "FlowSpec: descarte";
    if (String(r.action || "").indexOf("rate-limit") === 0) return "FlowSpec: rate-limit";
    if (String(r.action || "").indexOf("redirect") === 0) return "FlowSpec: redirect";
    return r.action || "-";
  }

  function fmtRuleStatus(r) {
    if (r.active) return '<span class="fg-mitigation-badge active">ativa</span>';
    var now = Math.floor(Date.now() / 1000);
    var label = r.expires_at && r.expires_at <= now ? "expirada" : "removida";
    return '<span class="fg-mitigation-badge inactive">' + label + "</span>";
  }

  // pedido do usuário: mostrar em qual equipamento a regra foi anunciada e se
  // foi disparada automaticamente (engine de detecção) ou manualmente (operador)
  function fmtRuleDevice(r) {
    return escapeHtml(r.device_name || "-");
  }

  // "ClientGuard auto: port_scan_vertical" -> "scan vertical" (reaproveita
  // CG_SIGNAL_LABELS, mesmo texto amigável já usado na aba Sinais Suspeitos);
  // rótulos do FlowGuard ("ban 177.86.17.0/24") não têm ":", caem no fallback
  // e continuam mostrando o rótulo cru, sem mudança pra essa tabela.
  function fmtRuleLabel(r) {
    var label = r.label || "";
    if (!label) return "-";
    var key = label.indexOf(":") >= 0 ? label.split(":").pop().trim() : null;
    return escapeHtml((key && CG_SIGNAL_LABELS[key]) || label);
  }

  function fmtRuleTrigger(r) {
    return r.trigger_type === "auto" ? "automático" : "manual";
  }

  function fmtRulePorts(r) {
    var parts = [];
    if (r.src_port) parts.push("origem:" + r.src_port);
    if (r.dst_port) parts.push("destino:" + r.dst_port);
    return parts.length ? parts.join(", ") : "-";
  }

  function renderFlowspecRulesTable(rules, elId) {
    var el = document.getElementById(elId);
    if (!el) return;
    if (!rules.length) {
      el.innerHTML = '<p class="fg-ok">Nenhuma regra encontrada.</p>';
      return;
    }
    var rows = rules
      .map(function (r) {
        var delBtn = r.active ? '<button class="fg-btn" data-action="del-flowspec-rule">Remover</button>' : "-";
        return (
          '<tr data-rule-id="' + r.id + '"><td>' + r.id + "</td><td>" + fmtDateTime(r.created_at) + "</td><td>" +
          fmtRuleType(r) + "</td><td>" + escapeHtml(r.src_prefix || "-") + "</td><td>" +
          escapeHtml(r.dst_prefix || "-") + "</td><td>" + escapeHtml(String(r.protocol || "-")) + "</td><td>" +
          fmtRulePorts(r) + "</td><td>" + fmtRuleDevice(r) + "</td><td>" + fmtRuleTrigger(r) + "</td><td>" +
          fmtRuleLabel(r) + "</td><td>" +
          (r.attack_id ? "#" + r.attack_id : "-") + "</td><td>" + fmtRuleStatus(r) + "</td><td>" +
          (r.expires_at ? new Date(r.expires_at * 1000).toLocaleString() : "-") + "</td><td>" +
          '<button class="fg-btn" data-action="detail-flowspec-rule">Detalhes</button> ' + delBtn + "</td></tr>"
        );
      })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>ID</th><th>Criada em</th><th>Tipo</th><th>Origem</th><th>Destino</th>" +
      "<th>Protocolo</th><th>Portas</th><th>Equipamento</th><th>Gatilho</th><th>Rótulo</th><th>Ataque</th>" +
      "<th>Status</th><th>Expira</th><th>Ação</th></tr></thead><tbody>" + rows + "</tbody></table>";
  }

  // --- verificação ao vivo no roteador (SSH, só leitura) --------------------
  // "Detalhes" por si só só reformata o que já está gravado localmente — isso
  // aqui de fato consulta o equipamento (mesmas credenciais do Modo Guerra)
  // pra confirmar que a regra está mesmo anunciada, achado real desta base:
  // já existiu regra marcada "revertida"/"falhou" no banco que continuava
  // ativa de verdade na borda.
  var VERIFY_STATUS_LABELS = {
    found: "🟢 confirmado no roteador",
    found_mismatch: "🟡 encontrado, mas com diferenças (veja o detalhe abaixo)",
    not_found: "🔴 não encontrado no roteador",
    inconclusive: "⚪ inconclusivo — saída do equipamento não reconhecida pelo parser",
    error: "⚪ falha ao consultar o roteador",
  };

  function verifyPanelHtml(ruleId, note) {
    return (
      '<div class="rule-verify-panel" data-rule-id="' + ruleId + '">' +
      '<p class="fg-kpi-sub">' + note + "</p>" +
      '<button class="fg-btn" data-action="verify-rule">Verificar no roteador</button>' +
      '<div class="rule-verify-result"></div></div>'
    );
  }

  function renderVerifyResult(el, resp) {
    if (!resp.ok) {
      el.innerHTML = '<p class="fg-error">' + escapeHtml(resp.error || "falha ao verificar") + "</p>";
      return;
    }
    var check = resp.router_check || {};
    var bgp = resp.bgp_session || {};
    var statusLabel = VERIFY_STATUS_LABELS[check.match_status] || (check.match_status || "-");
    var bgpLine = (bgp.peer_state === "up" ? "🟢 Up" : "🔴 Down/Idle") +
      (bgp.peer_ip ? " (" + escapeHtml(bgp.peer_ip) + ")" : "");
    el.innerHTML =
      "<table><tbody>" +
      "<tr><td>Resultado</td><td>" + escapeHtml(statusLabel) + "</td></tr>" +
      "<tr><td>Detalhe</td><td>" + escapeHtml(check.detail || "-") + "</td></tr>" +
      "<tr><td>Equipamento consultado</td><td>" + escapeHtml(resp.device_name || "-") +
      " (peer " + escapeHtml(resp.peer || "-") + ")</td></tr>" +
      "<tr><td>Sessão BGP (ExaBGP)</td><td>" + bgpLine + "</td></tr>" +
      "</tbody></table>" +
      (check.command ? "<h4>Comando executado no roteador</h4><pre>" + escapeHtml(check.command) + "</pre>" : "") +
      (check.raw_output ? "<h4>Saída bruta do roteador</h4><pre>" + escapeHtml(check.raw_output) + "</pre>" : "");
  }

  function onVerifyRuleClick(btn) {
    var panel = btn.closest(".rule-verify-panel");
    if (!panel) return;
    var ruleId = Number(panel.getAttribute("data-rule-id"));
    var resultEl = panel.querySelector(".rule-verify-result");
    btn.disabled = true;
    resultEl.innerHTML = '<p class="fg-kpi-sub">Consultando o roteador via SSH — pode levar até 20-30s...</p>';
    postJson(RULES_ENDPOINT, { verify_id: ruleId })
      .then(function (resp) { renderVerifyResult(resultEl, resp); })
      .catch(function (err) {
        resultEl.innerHTML = '<p class="fg-error">falha ao verificar</p>';
        console.error("flowguard.js:", err);
      })
      .finally(function () { btn.disabled = false; });
  }

  function renderFlowspecRuleDetail(r) {
    var el = document.getElementById("rules-detail");
    el.innerHTML =
      '<div class="fg-card"><h3>Detalhes da regra #' + r.id + "</h3>" +
      "<table><tbody>" +
      "<tr><td>Tipo</td><td>" + fmtRuleType(r) + "</td></tr>" +
      "<tr><td>Equipamento</td><td>" + fmtRuleDevice(r) + "</td></tr>" +
      "<tr><td>Gatilho</td><td>" + fmtRuleTrigger(r) + "</td></tr>" +
      "<tr><td>Origem</td><td>" + escapeHtml(r.src_prefix || "-") + "</td></tr>" +
      "<tr><td>Destino</td><td>" + escapeHtml(r.dst_prefix || "-") + "</td></tr>" +
      "<tr><td>Protocolo</td><td>" + escapeHtml(String(r.protocol || "-")) + "</td></tr>" +
      "<tr><td>Portas</td><td>" + fmtRulePorts(r) + "</td></tr>" +
      "<tr><td>TCP flags</td><td>" + escapeHtml(r.tcp_flags || "-") + "</td></tr>" +
      "<tr><td>Tamanho de pacote</td><td>" + escapeHtml(r.pkt_len || "-") + "</td></tr>" +
      "<tr><td>Rótulo</td><td>" + fmtRuleLabel(r) + "</td></tr>" +
      "<tr><td>Aplicação de origem</td><td>" + (r.origin === "clientguard" ? "ClientGuard" : "FlowGuard") + "</td></tr>" +
      "<tr><td>Ataque associado</td><td>" + (r.attack_id ? "#" + r.attack_id : "-") + "</td></tr>" +
      "<tr><td>Criada em</td><td>" + fmtDateTime(r.created_at) + "</td></tr>" +
      "<tr><td>Expira em</td><td>" + (r.expires_at ? new Date(r.expires_at * 1000).toLocaleString() : "-") + "</td></tr>" +
      "<tr><td>Status</td><td>" + fmtRuleStatus(r) + "</td></tr>" +
      "</tbody></table>" +
      verifyPanelHtml(r.id, "Conecta via SSH no roteador (mesmas credenciais do Modo Guerra) e confere se " +
        "esta regra está de fato anunciada — não confia só no que está gravado aqui.") +
      '<button class="fg-btn" id="rules-detail-close-btn">Fechar</button></div>';
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  var RULES_EDGE_STATUS_LABELS = { active: "ativa", reverted: "revertida", failed: "falhou" };
  var RULES_EDGE_STATUS_BADGE_CLASS = { active: "active", reverted: "inactive", failed: "failed" };

  // "o que aconteceu": match_json.label vem tipo "ClientGuard auto: port_scan_vertical"
  // — extrai a chave do detector e reusa os mesmos nomes amigáveis já usados na
  // lista de toggles (CG_SIGNAL_LABELS), em vez de mostrar o label cru ou nada
  function edgeMitigationReason(m) {
    if (!m.match_json) return null;
    var rule;
    try { rule = JSON.parse(m.match_json); } catch (e) { return null; }
    var label = rule && rule.label;
    if (!label) return null;
    var key = label.split(":").pop().trim();
    return CG_SIGNAL_LABELS[key] || label;
  }

  function renderRulesCgEdgeTable(mitigations, elId) {
    var el = document.getElementById(elId);
    if (!el) return;
    if (!mitigations.length) {
      el.innerHTML = '<p class="fg-ok">Nenhuma mitigação de borda registrada.</p>';
      return;
    }
    var pageKey = "cgEdgeMitigations";
    var p = paginate(mitigations, pageKey);
    var rows = p.pageRows
      .map(function (m) {
        var revertBtn = m.status === "active"
          ? '<button class="fg-btn" data-action="revert-edge-mitigation">Reverter</button>' : "";
        var mechanism = m.mechanism || "ssh";
        var badgeCls = RULES_EDGE_STATUS_BADGE_CLASS[m.status] || "none";
        var badgeTitle = m.status === "failed" && m.error ? ' title="' + escapeHtml(m.error) + '"' : "";
        var when = m.status === "active" && m.ts_expires
          ? "expira " + fmtDateTime(m.ts_expires)
          : (m.ts_reverted ? "revertida " + fmtDateTime(m.ts_reverted) : "");
        var reason = edgeMitigationReason(m) || (m.trigger_type === "auto" ? "-" : "bloqueio manual");
        return (
          '<tr data-mitigation-id="' + m.id + '">' +
          '<td><span class="fg-mitigation-badge ' + badgeCls + '"' + badgeTitle + '>' +
          (RULES_EDGE_STATUS_LABELS[m.status] || m.status) + "</span></td>" +
          "<td>" + escapeHtml(m.src_ip) + "</td>" +
          "<td>" + escapeHtml(reason) + "</td>" +
          "<td>" + (mechanism === "flowspec" ? "FlowSpec" : "SSH (legado)") + "</td>" +
          "<td>" + escapeHtml(m.device_name || "-") + "</td>" +
          "<td>" + (m.trigger_type === "auto" ? "automático" : "manual") + "</td>" +
          "<td>" + fmtDateTime(m.ts_applied) + (when ? '<div class="fg-kpi-sub">' + escapeHtml(when) + "</div>" : "") + "</td>" +
          "<td>" + '<button class="fg-btn" data-action="detail-edge-mitigation">Detalhes</button> ' + revertBtn + "</td></tr>"
        );
      })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>Status</th><th>Cliente</th><th>Motivo</th><th>Mecanismo</th><th>Equipamento</th>" +
      "<th>Gatilho</th><th>Aplicada em</th><th></th></tr></thead><tbody>" + rows + "</tbody></table>" +
      paginationHtml(pageKey, p.page, p.totalPages, p.total);
  }

  function renderEdgeMitigationDetail(m) {
    var el = document.getElementById("rules-detail");
    var mechanism = m.mechanism || "ssh"; // linhas antigas não têm a coluna preenchida
    var baseRows =
      "<tr><td>Motivo</td><td>" + escapeHtml(edgeMitigationReason(m) || "-") + "</td></tr>" +
      "<tr><td>Mecanismo</td><td>" + (mechanism === "flowspec" ? "BGP FlowSpec" : "SSH/ACL (legado)") + "</td></tr>" +
      "<tr><td>Equipamento</td><td>" + escapeHtml(m.device_name || "-") + "</td></tr>" +
      "<tr><td>IP mitigado</td><td>" + escapeHtml(m.src_ip) + "</td></tr>" +
      "<tr><td>Status</td><td>" + (RULES_EDGE_STATUS_LABELS[m.status] || m.status) + "</td></tr>" +
      "<tr><td>Gatilho</td><td>" + (m.trigger_type === "auto" ? "automático" : "manual") + "</td></tr>" +
      "<tr><td>Sinal associado</td><td>" + (m.signal_id ? "#" + m.signal_id : "-") + "</td></tr>" +
      "<tr><td>Aplicada em</td><td>" + fmtDateTime(m.ts_applied) + "</td></tr>" +
      "<tr><td>Expira em</td><td>" + (m.status === "active" && m.ts_expires ? new Date(m.ts_expires * 1000).toLocaleString() : "-") + "</td></tr>" +
      "<tr><td>Revertida em</td><td>" + (m.ts_reverted ? fmtDateTime(m.ts_reverted) : "-") + "</td></tr>" +
      "<tr><td>Erro</td><td>" + escapeHtml(m.error || "-") + "</td></tr>";

    var detailHtml;
    if (mechanism === "flowspec") {
      var rule = m.match_json ? JSON.parse(m.match_json) : null;
      var matchDesc = rule
        ? Object.keys(rule).filter(function (k) { return k !== "action" && k !== "label"; })
            .map(function (k) { return k + "=" + rule[k]; }).join(", ")
        : "-";
      detailHtml =
        "<table><tbody>" + baseRows +
        "<tr><td>Regra FlowSpec (id no FlowGuard)</td><td>" + (m.flowspec_rule_id || "-") + "</td></tr>" +
        "<tr><td>Match</td><td>" + escapeHtml(matchDesc) + "</td></tr>" +
        "<tr><td>Ação</td><td>" + (m.rate_limit_bps ? "Limitar banda a " + fmtBps(m.rate_limit_bps) : "Descartar") + "</td></tr>" +
        "</tbody></table>" +
        (m.flowspec_rule_id
          ? verifyPanelHtml(m.flowspec_rule_id, "Confere no roteador a regra FlowSpec #" + m.flowspec_rule_id +
              " no FlowGuard — é o mesmo mecanismo, o ClientGuard só pede pro FlowGuard anunciar.")
          : "");
    } else {
      var applyCommands = m.apply_commands ? JSON.parse(m.apply_commands) : null;
      var revertCommands = m.revert_commands ? JSON.parse(m.revert_commands) : null;
      detailHtml =
        "<table><tbody>" + baseRows + "</tbody></table>" +
        "<h4>Comandos enviados ao aplicar</h4>" +
        "<pre>" + escapeHtml(applyCommands ? applyCommands.join("\n") : "(sem registro)") + "</pre>" +
        "<h4>Saída do equipamento (aplicar)</h4>" +
        "<pre>" + escapeHtml(m.apply_output || "(sem saída registrada)") + "</pre>" +
        (revertCommands ? "<h4>Comandos enviados ao reverter</h4><pre>" + escapeHtml(revertCommands.join("\n")) + "</pre>" : "") +
        (m.revert_output ? "<h4>Saída do equipamento (reverter)</h4><pre>" + escapeHtml(m.revert_output) + "</pre>" : "");
    }

    el.innerHTML =
      '<div class="fg-card"><h3>Detalhes da mitigação #' + m.id + "</h3>" + detailHtml +
      '<button class="fg-btn" id="rules-detail-close-btn">Fechar</button></div>';
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // categoria de tipo pro filtro "Tipo" — mesmo agrupamento usado em
  // fmtRuleType, mas devolvendo a chave curta usada no <select> em vez do
  // rótulo pra exibição
  function ruleTypeCategory(action) {
    if (action === "rtbh") return "rtbh";
    var a = String(action || "");
    if (a.indexOf("rate-limit") === 0) return "rate-limit";
    if (a.indexOf("redirect") === 0) return "redirect";
    return "discard";
  }

  var RULES_WINDOW_SECONDS = { "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800 };

  // filtro de janela de tempo é sobre created_at/ts_applied — puramente
  // client-side, igual ao resto do filtro da aba Regras (ver nota acima)
  function withinRulesWindow(ts) {
    var windowKey = state.filter.rulesWindow;
    if (!windowKey || !ts) return true;
    var secs = RULES_WINDOW_SECONDS[windowKey];
    return !secs || (Math.floor(Date.now() / 1000) - ts) <= secs;
  }

  // rulesView agora é tri-state (active/inactive/all) — antes só existia
  // active/history(=tudo), sem jeito de ver só o que já saiu do ar
  function ruleStatusMatches(active) {
    if (state.rulesView === "active") return !!active;
    if (state.rulesView === "inactive") return !active;
    return true;
  }

  function edgeStatusMatches(status) {
    if (state.rulesView === "active") return status === "active";
    if (state.rulesView === "inactive") return status !== "active";
    return true;
  }

  function applyRulesFilter() {
    var fgSection = document.querySelector('[data-rules-app="flowguard"]');
    var cgSection = document.querySelector('[data-rules-app="clientguard"]');
    var hostNeedle = state.filter.rulesHost;
    var typeFilter = state.filter.rulesType;

    if (state.rulesApp === "clientguard") {
      if (fgSection) fgSection.hidden = true;
      if (cgSection) cgSection.hidden = false;

      var cgFlowspec = state.rulesFgData.filter(function (r) { return r.origin === "clientguard"; });
      cgFlowspec = cgFlowspec.filter(function (r) { return ruleStatusMatches(r.active); });
      if (typeFilter) cgFlowspec = cgFlowspec.filter(function (r) { return ruleTypeCategory(r.action) === typeFilter; });
      cgFlowspec = filterRows(cgFlowspec, hostNeedle, ["src_prefix", "dst_prefix"]);
      cgFlowspec = cgFlowspec.filter(function (r) { return withinRulesWindow(r.created_at); });
      renderFlowspecRulesTable(cgFlowspec, "rules-cg-flowspec-list");

      // mechanism='flowspec' aqui é a MESMA regra já listada acima (em
      // rules-cg-flowspec-list, vinda de flowspec_rules) — mostrar de novo
      // duplicava toda mitigação automática via FlowSpec nas duas tabelas.
      // Esta tabela agora é só o que não tem equivalente lá: SSH/ACL legado.
      // (filtro "Tipo" não se aplica aqui — mecanismo é sempre SSH)
      var cgEdge = state.rulesCgEdgeData.filter(function (m) { return m.mechanism !== "flowspec"; });
      cgEdge = cgEdge.filter(function (m) { return edgeStatusMatches(m.status); });
      cgEdge = filterRows(cgEdge, hostNeedle, ["src_ip"]);
      cgEdge = cgEdge.filter(function (m) { return withinRulesWindow(m.ts_applied); });
      renderRulesCgEdgeTable(cgEdge, "rules-cg-edge-list");
    } else {
      if (fgSection) fgSection.hidden = false;
      if (cgSection) cgSection.hidden = true;

      var fgRules = state.rulesFgData.filter(function (r) { return r.origin !== "clientguard"; });
      fgRules = fgRules.filter(function (r) { return ruleStatusMatches(r.active); });
      if (typeFilter) fgRules = fgRules.filter(function (r) { return ruleTypeCategory(r.action) === typeFilter; });
      fgRules = filterRows(fgRules, hostNeedle, ["src_prefix", "dst_prefix"]);
      fgRules = fgRules.filter(function (r) { return withinRulesWindow(r.created_at); });
      renderFlowspecRulesTable(fgRules, "rules-fg-list");
    }
    // roda no mesmo ciclo que re-renderiza as listas (todo load do poll e todo
    // toggle/filtro passam por aqui), mas conta a partir do estado bruto — os
    // filtros acima não mexem na contagem dos badges
    updateRulesSubsectionBadges();
  }

  function loadRulesUnified() {
    getJson(RULES_ENDPOINT + "?history=1").then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("rules-fg-list"), data.error || "erro desconhecido");
        return;
      }
      state.rulesFgData = data.rules;
      applyRulesFilter();
      cockpitRefreshAll();
    }).catch(function (err) {
      showError(document.getElementById("rules-fg-list"), "falha ao consultar regras");
      console.error("flowguard.js:", err);
    });

    getJson(CG_EDGE_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("rules-cg-edge-list"), data.error || "erro desconhecido");
        return;
      }
      state.rulesCgEdgeData = data.mitigations;
      applyRulesFilter();
      cockpitRefreshAll();
    }).catch(function (err) {
      showError(document.getElementById("rules-cg-edge-list"), "falha ao consultar mitigações de borda");
      console.error("flowguard.js:", err);
    });
  }

  function onRulesUnifiedClick(ev) {
    var delBtn = ev.target.closest("button[data-action='del-flowspec-rule']");
    if (delBtn) {
      var row = delBtn.closest("tr[data-rule-id]");
      if (!row) return;
      delBtn.disabled = true;
      postJson(RULES_ENDPOINT, { id: Number(row.getAttribute("data-rule-id")) }).then(function (resp) {
        showToast(resp.ok ? "Regra removida" : resp.error, resp.ok ? "success" : "error");
        loadRulesUnified();
      });
      return;
    }
    var revertBtn = ev.target.closest("button[data-action='revert-edge-mitigation']");
    if (revertBtn) {
      var row2 = revertBtn.closest("tr[data-mitigation-id]");
      if (!row2) return;
      revertBtn.disabled = true;
      postJson(CG_EDGE_ENDPOINT, { id: Number(row2.getAttribute("data-mitigation-id")) }).then(function (resp) {
        showToast(resp.ok ? "Mitigação revertida" : resp.error, resp.ok ? "success" : "error");
        loadRulesUnified();
      });
      return;
    }
    var detailFgBtn = ev.target.closest("button[data-action='detail-flowspec-rule']");
    if (detailFgBtn) {
      var row3 = detailFgBtn.closest("tr[data-rule-id]");
      if (!row3) return;
      var ruleId = Number(row3.getAttribute("data-rule-id"));
      var rule = state.rulesFgData.filter(function (r) { return r.id === ruleId; })[0];
      if (rule) renderFlowspecRuleDetail(rule);
      return;
    }
    var detailEdgeBtn = ev.target.closest("button[data-action='detail-edge-mitigation']");
    if (detailEdgeBtn) {
      var row4 = detailEdgeBtn.closest("tr[data-mitigation-id]");
      if (!row4) return;
      var mitigationId = Number(row4.getAttribute("data-mitigation-id"));
      var mitigation = state.rulesCgEdgeData.filter(function (m) { return m.id === mitigationId; })[0];
      if (mitigation) renderEdgeMitigationDetail(mitigation);
      return;
    }
    var closeDetailBtn = ev.target.closest("#rules-detail-close-btn");
    if (closeDetailBtn) {
      document.getElementById("rules-detail").innerHTML = "";
      return;
    }
    var verifyBtn = ev.target.closest("button[data-action='verify-rule']");
    if (verifyBtn) {
      onVerifyRuleClick(verifyBtn);
    }
  }

  function onRulesDelAllClick() {
    var btn = document.getElementById("fg-rules-del-all-btn");
    var activeCount = state.rulesFgData.filter(function (r) { return r.active; }).length;
    if (!activeCount) {
      showToast("Nenhuma regra ativa pra apagar", "error");
      return;
    }
    if (!window.confirm(
      "Apagar TODAS as " + activeCount + " regra(s) FlowSpec/RTBH ativas (FlowGuard + ClientGuard)? " +
      "Isso retira o bloqueio/limite de banda de todo mundo imediatamente e não pode ser desfeito.",
    )) {
      return;
    }
    btn.disabled = true;
    postJson(RULES_ENDPOINT, { clear_all: true })
      .then(function (resp) {
        if (resp.ok) {
          showToast(resp.removed + " regra(s) removida(s)" + (resp.failed ? ", " + resp.failed + " falharam (veja detalhes)" : ""), "success");
        } else {
          showToast(resp.error || "falha ao apagar regras", "error");
        }
        loadRulesUnified();
      })
      .catch(function (err) {
        showToast("falha ao apagar regras", "error");
        console.error("flowguard.js:", err);
      })
      .finally(function () { btn.disabled = false; });
  }

  // usado tanto pelo clique no toggle quanto por onBlockSubmit — sem isso, um
  // bloqueio manual via "ClientGuard" ficava invisível no Histórico logo
  // abaixo até o usuário clicar manualmente no toggle correspondente.
  function setRulesApp(app) {
    state.rulesApp = app;
    var appToggle = document.getElementById("rules-app-toggle");
    if (appToggle) {
      appToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-app") === app);
      });
    }
    applyRulesFilter();
  }

  function initRulesControls() {
    var appToggle = document.getElementById("rules-app-toggle");
    if (appToggle) {
      appToggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        setRulesApp(btn.getAttribute("data-app"));
      });
    }
    // barra "Ir para" — mesmo padrão do fg-incidents-nav: troca o lado do
    // toggle FlowGuard/ClientGuard se preciso e rola até o título. Diferença:
    // esta barra fica FORA das seções colapsáveis, então o alvo pode estar
    // dentro de uma seção recolhida — expande antes de rolar (mesmos helpers
    // do initCollapsiblePanels/jumpToAttack)
    var nav = document.getElementById("fg-rules-nav");
    if (nav) {
      nav.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-incident-nav-btn");
        if (!btn) return;
        var app = btn.getAttribute("data-jump-app");
        if (app && state.rulesApp !== app) setRulesApp(app);
        var target = document.getElementById(btn.getAttribute("data-jump-target"));
        if (!target) return;
        var section = target.closest("section.fg-panel-section");
        if (section && section.classList.contains("fg-panel-collapsed")) {
          setPanelCollapsed(section, false);
          localStorage.setItem(panelStorageKey(section), "0");
        }
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
    var viewToggle = document.getElementById("rules-view-toggle");
    if (viewToggle) {
      viewToggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        state.rulesView = btn.getAttribute("data-view");
        viewToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
        applyRulesFilter();
      });
    }
    var delAllBtn = document.getElementById("fg-rules-del-all-btn");
    if (delAllBtn) delAllBtn.addEventListener("click", onRulesDelAllClick);
    var cgRevertAllBtn = document.getElementById("rules-cg-edge-revert-all-btn");
    if (cgRevertAllBtn) cgRevertAllBtn.addEventListener("click", onRulesCgEdgeRevertAllClick);

    var hostFilter = document.getElementById("rules-host-filter");
    if (hostFilter) {
      hostFilter.addEventListener("input", function () {
        state.filter.rulesHost = hostFilter.value.trim();
        applyRulesFilter();
      });
    }
    var typeFilter = document.getElementById("rules-type-filter");
    if (typeFilter) {
      typeFilter.addEventListener("change", function () {
        state.filter.rulesType = typeFilter.value;
        applyRulesFilter();
      });
    }
    var windowFilter = document.getElementById("rules-window-filter");
    if (windowFilter) {
      windowFilter.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        state.filter.rulesWindow = btn.getAttribute("data-window");
        windowFilter.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
        applyRulesFilter();
      });
    }

    var blockSourceToggle = document.getElementById("fg-block-source-toggle");
    if (blockSourceToggle) {
      blockSourceToggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        state.blockSource = btn.getAttribute("data-source");
        blockSourceToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
      });
    }
  }

  // formulário único (ex-duplicado: FlowGuard tinha o seu, ClientGuard tinha
  // uma cópia quase idêntica) — o seletor de origem só decide qual endpoint
  // recebe o POST; nos dois casos é a MESMA sessão BGP FlowSpec real, e o
  // resultado aparece no histórico unificado da própria aba Regras
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
    var request = state.blockSource === "clientguard"
      ? postJson(CG_BLOCK_ENDPOINT, { ip: ip, ttl_s: Number(ttlSelect.value) })
      : postJson(RULES_ENDPOINT, { src_prefix: ip, action: "discard", ttl_s: Number(ttlSelect.value) });
    request
      .then(function (resp) {
        showToast(resp.ok ? "IP bloqueado: " + ip : resp.error, resp.ok ? "success" : "error");
        if (resp.ok) {
          input.value = "";
          // troca o Histórico pra mostrar a aplicação/aba certa (e "Ativas"),
          // senão o bloqueio some do campo de visão até um clique manual
          setRulesApp(state.blockSource);
          var viewToggle = document.getElementById("rules-view-toggle");
          if (viewToggle) {
            state.rulesView = "active";
            viewToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) {
              b.classList.toggle("active", b.getAttribute("data-view") === "active");
            });
          }
        }
        loadRulesUnified();
      })
      .finally(function () { btn.disabled = false; });
  }

  function initCfgAppToggle() {
    var appToggle = document.getElementById("cfg-app-toggle");
    if (!appToggle) return;
    appToggle.addEventListener("click", function (ev) {
      var btn = ev.target.closest(".fg-toggle-btn");
      if (!btn) return;
      state.cfgApp = btn.getAttribute("data-app");
      appToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
      var fgSection = document.querySelector('[data-cfg-app="flowguard"]');
      var cgSection = document.querySelector('[data-cfg-app="clientguard"]');
      if (fgSection) fgSection.hidden = state.cfgApp !== "flowguard";
      if (cgSection) cgSection.hidden = state.cfgApp !== "clientguard";
    });
  }

  // --- modo guerra: SSH em vários equipamentos de uma vez -----------------

  function renderWarmodeDevices(data) {
    var el = document.getElementById("fg-warmode-devices");
    var confirmBtn = document.getElementById("fg-warmode-confirm-btn");
    var countField = warmodeExecMode === "revert" ? "n_revert_commands" : "n_commands";
    var noCmdLabel = warmodeExecMode === "revert" ? "0 comandos de reversão — nada vai rodar aqui" : "0 comandos — nada vai rodar aqui";
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
    // desativado (fg-wm-enabled=false na Configuração do Modo Guerra) aparece
    // esmaecido aqui, com o motivo, em vez de simplesmente sumir da lista —
    // evita o operador se perguntar "cadê meu equipamento" em cima da hora
    var enabledDevices = data.devices.filter(function (d) { return d.enabled !== false; });
    var enabledWithoutCommands = enabledDevices.filter(function (d) { return !d[countField]; });
    el.innerHTML = data.devices
      .map(function (d) {
        if (d.enabled === false) {
          return '<div class="fg-warmode-device-row fg-warmode-device-disabled"><span>' + escapeHtml(d.name) + " (" +
            escapeHtml(d.host || "-") + ", " + escapeHtml(d.device_type || "-") +
            ')</span><span class="fg-kpi-sub">desativado — não vai rodar</span></div>';
        }
        var n = d[countField];
        var cmdLabel = n ? n + " comando(s)" : '<span class="fg-error">' + noCmdLabel + '</span>';
        return '<div class="fg-warmode-device-row"><span>' + escapeHtml(d.name) + " (" + escapeHtml(d.host || "-") +
          ", " + escapeHtml(d.device_type || "-") + ")</span><span>" + cmdLabel + "</span></div>";
      })
      .join("");
    confirmBtn.disabled = !enabledDevices.length || enabledWithoutCommands.length === enabledDevices.length;
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

  function openWarmodeModal(mode) {
    warmodeExecMode = mode === "revert" ? "revert" : "apply";
    var isRevert = warmodeExecMode === "revert";
    // só o texto troca — o ícone (span.fg-icon) fica intacto; setar textContent
    // no <h2> inteiro apagaria o SVG (bug real, corrigido aqui)
    document.getElementById("fg-warmode-title-text").textContent = isRevert ? "Sair do Modo Guerra" : "Modo Guerra";
    document.getElementById("fg-warmode-title").style.color = isRevert ? "" : "#f85149";
    document.getElementById("fg-warmode-exec-desc").textContent = isRevert
      ? "Roda os comandos de reversão configurados via SSH, em paralelo, em todos os equipamentos abaixo — desfaz o que o Modo Guerra aplicou. Reais, agora, sem confirmação adicional depois do próximo clique."
      : "Executa os comandos configurados via SSH, em paralelo, em todos os equipamentos abaixo — reais, agora, sem confirmação adicional depois do próximo clique.";
    var confirmBtn = document.getElementById("fg-warmode-confirm-btn");
    confirmBtn.textContent = isRevert ? "Confirmar e reverter agora" : "Confirmar e executar agora";
    confirmBtn.className = isRevert ? "fg-btn" : "fg-btn fg-btn-danger";
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

  // --- modo guerra: botão único (liga/desliga) + timer digital no topo -----

  function fmtWarmodeElapsed(totalSeconds) {
    var s = Math.max(0, Math.floor(totalSeconds));
    var hh = Math.floor(s / 3600);
    var mm = Math.floor((s % 3600) / 60);
    var ss = s % 60;
    function pad(n) { return n < 10 ? "0" + n : "" + n; }
    return pad(hh) + ":" + pad(mm) + ":" + pad(ss);
  }

  function tickWarmodeTimer() {
    var el = document.getElementById("fg-warmode-timer");
    if (!el || warmodeStartedAt == null) return;
    el.textContent = fmtWarmodeElapsed(Date.now() / 1000 - warmodeStartedAt);
  }

  function updateWarmodeUi() {
    var btn = document.getElementById("fg-warmode-open-btn");
    var timerEl = document.getElementById("fg-warmode-timer");
    var badgeEl = document.getElementById("fg-warmode-badge");
    var topbarEl = document.querySelector(".fg-topbar");
    if (btn) {
      btn.classList.toggle("is-warmode-active", warmodeActive);
      btn.title = warmodeActive ? "Clique para sair do Modo Guerra" : "Clique para ativar o Modo Guerra";
    }
    if (timerEl) timerEl.hidden = !warmodeActive;
    if (badgeEl) {
      badgeEl.textContent = warmodeActive ? "WARMODE-ON" : "WARMODE-OFF";
      badgeEl.classList.toggle("on", warmodeActive);
      badgeEl.classList.toggle("off", !warmodeActive);
      badgeEl.title = warmodeActive
        ? "Modo Guerra ATIVO — mitigação de emergência em andamento nos equipamentos"
        : "Modo Guerra desativado — operação normal";
    }
    if (topbarEl) topbarEl.classList.toggle("is-warmode-active", warmodeActive);

    if (warmodeActive && warmodeStartedAt != null) {
      if (!warmodeTickTimer) {
        tickWarmodeTimer();
        warmodeTickTimer = setInterval(tickWarmodeTimer, 1000);
      }
    } else if (warmodeTickTimer) {
      clearInterval(warmodeTickTimer);
      warmodeTickTimer = null;
    }
  }

  function loadWarmodeStatus() {
    return getJson(WARMODE_ENDPOINT + "?status=1").then(function (data) {
      if (!data.ok) return;
      warmodeActive = !!data.active;
      warmodeStartedAt = data.started_at || null;
      updateWarmodeUi();
      cockpitRefreshAll();
    }).catch(function (err) {
      console.error("flowguard.js:", err);
    });
  }

  function initWarmode() {
    var openBtn = document.getElementById("fg-warmode-open-btn");
    if (openBtn) openBtn.addEventListener("click", function () { openWarmodeModal(warmodeActive ? "revert" : "apply"); });
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

  // badge de última execução (audit log, via last_run vindo do backend) —
  // "nunca executado" pra equipamento novo/nunca rodado, senão ok/falhou +
  // há-quanto-tempo, com data/hora exata e erro (se houve) só no title
  function warmodeLastRunBadge(lastRun) {
    if (!lastRun) return '<span class="fg-wm-lastrun fg-wm-lastrun-none">nunca executado</span>';
    var cls = lastRun.ok ? "fg-wm-lastrun-ok" : "fg-wm-lastrun-fail";
    var verb = lastRun.mode === "revert" ? "reversão" : "execução";
    var ago = fmtUptime(Math.floor(Date.now() / 1000) - lastRun.ts) + " atrás";
    var label = (lastRun.ok ? "ok" : "falhou") + " — última " + verb + " " + ago;
    var title = fmtDateTime(lastRun.ts) + (lastRun.error ? " — " + lastRun.error : "");
    return '<span class="fg-wm-lastrun ' + cls + '" title="' + escapeHtml(title) + '">' + escapeHtml(label) + "</span>";
  }

  function warmodeDeviceCardHtml(d, expanded) {
    var isNew = !d;
    d = d || {
      name: "", host: "", port: 22, device_type: "", username: "", has_password: false,
      enable_mode: false, enabled: true, commands: [], revert_commands: [], last_run: null,
    };
    expanded = expanded || isNew;
    var nCommands = (d.commands || []).length;
    var nRevert = (d.revert_commands || []).length;
    var meta = (d.host || "sem host") + " · " + (d.device_type || "sem tipo") + " · " +
      nCommands + " comando(s) / " + nRevert + " reversão";
    return (
      '<div class="fg-wm-device' + (d.enabled === false ? " fg-wm-device-disabled" : "") + '">' +
      '<div class="fg-wm-row-top">' +
      '<label class="fg-wm-enabled-toggle" title="Participa do próximo lote (ligar ou reverter o Modo Guerra)">' +
      '<input type="checkbox" class="fg-wm-enabled"' + (d.enabled === false ? "" : " checked") + '></label>' +
      '<div class="fg-wm-summary" data-action="toggle-expand">' +
      "<strong>" + (d.name ? escapeHtml(d.name) : "(novo equipamento)") + "</strong>" +
      '<span class="fg-wm-summary-meta">' + escapeHtml(meta) +
      (nCommands === 0 ? ' <span class="fg-wm-warn">· sem comandos</span>' : "") + "</span>" +
      warmodeLastRunBadge(d.last_run) +
      "</div>" +
      '<div class="fg-wm-row-actions">' +
      '<button type="button" class="fg-btn" data-action="duplicate-device">Duplicar</button>' +
      '<button type="button" class="fg-btn" data-action="remove-device">Remover</button>' +
      '<button type="button" class="fg-btn fg-wm-chevron-btn" data-action="toggle-expand">' + (expanded ? "▴" : "▾") + "</button>" +
      "</div>" +
      "</div>" +
      '<div class="fg-wm-body"' + (expanded ? "" : " hidden") + ">" +
      '<div class="fg-wm-device-grid">' +
      '<div><label>Nome</label><input type="text" class="fg-wm-name" value="' + escapeHtml(d.name) + '" placeholder="ex: NE8000BGP"></div>' +
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
      '<label>Comandos de reversão (um por linha) — rodados no 2º clique do botão único do Modo Guerra, pra desfazer os comandos acima</label>' +
      '<textarea class="fg-wm-revert-commands" placeholder="ex: system-view / undo acl number 3006 / quit">' + escapeHtml((d.revert_commands || []).join("\n")) + "</textarea>" +
      '<div class="fg-wm-test-row">' +
      '<button type="button" class="fg-btn" data-action="test-device">Testar conexão</button>' +
      '<span class="fg-kpi-sub">só autentica por SSH, nenhum comando é enviado</span>' +
      '<span class="fg-wm-test-result"></span>' +
      "</div>" +
      "</div>" +
      "</div>"
    );
  }

  function renderWarmodeCfgDevices(devices) {
    var el = document.getElementById("fg-warmode-cfg-devices");
    el.innerHTML = devices.map(function (d) { return warmodeDeviceCardHtml(d, false); }).join("") ||
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

  function warmodeCollectOneDevice(card) {
    var commandsRaw = card.querySelector(".fg-wm-commands").value;
    var revertCommandsRaw = card.querySelector(".fg-wm-revert-commands").value;
    return {
      name: card.querySelector(".fg-wm-name").value.trim(),
      host: card.querySelector(".fg-wm-host").value.trim(),
      port: Number(card.querySelector(".fg-wm-port").value) || 22,
      device_type: card.querySelector(".fg-wm-device-type").value.trim(),
      username: card.querySelector(".fg-wm-username").value.trim(),
      password: card.querySelector(".fg-wm-password").value,
      enable_mode: card.querySelector(".fg-wm-enable-mode").checked,
      enabled: card.querySelector(".fg-wm-enabled").checked,
      commands: commandsRaw.split("\n").map(function (c) { return c.trim(); }).filter(Boolean),
      revert_commands: revertCommandsRaw.split("\n").map(function (c) { return c.trim(); }).filter(Boolean),
    };
  }

  function collectWarmodeCfgDevices() {
    return Array.prototype.map.call(document.querySelectorAll("#fg-warmode-cfg-devices .fg-wm-device"), warmodeCollectOneDevice);
  }

  function onWarmodeTestDevice(btn) {
    var card = btn.closest(".fg-wm-device");
    var resultEl = card.querySelector(".fg-wm-test-result");
    var device = warmodeCollectOneDevice(card);
    if (!device.host || !device.device_type) {
      resultEl.className = "fg-wm-test-result fail";
      resultEl.textContent = "preencha host e tipo antes de testar";
      return;
    }
    btn.disabled = true;
    resultEl.className = "fg-wm-test-result";
    resultEl.textContent = "testando conexão...";
    warmodePostJson(WARMODE_CFG_ENDPOINT, {
      warmode_token: warmodeToken,
      action: "test",
      device: {
        host: device.host, port: device.port, device_type: device.device_type,
        username: device.username, password: device.password, enable_mode: device.enable_mode,
      },
    }).then(function (r) {
      if (r.status === 401) {
        resultEl.className = "fg-wm-test-result fail";
        resultEl.textContent = "sessão do Modo Guerra expirada — feche e desbloqueie de novo";
        return;
      }
      if (r.data.ok) {
        resultEl.className = "fg-wm-test-result ok";
        resultEl.textContent = "✔ conexão OK (" + r.data.elapsed_s + "s)";
      } else {
        resultEl.className = "fg-wm-test-result fail";
        resultEl.textContent = "✘ " + (r.data.error || "falha desconhecida");
      }
    }).catch(function (err) {
      resultEl.className = "fg-wm-test-result fail";
      resultEl.textContent = "falha ao testar conexão";
      console.error("flowguard.js:", err);
    }).finally(function () { btn.disabled = false; });
  }

  function onWarmodeAddDevice() {
    var el = document.getElementById("fg-warmode-cfg-devices");
    // se a lista estava vazia, o placeholder "Nenhum equipamento..." não é
    // um .fg-wm-device — precisa sumir, senão fica junto do card novo
    if (!el.querySelector(".fg-wm-device")) el.innerHTML = "";
    el.insertAdjacentHTML("beforeend", warmodeDeviceCardHtml(null, true));
  }

  // toggle "enabled" só mexe no checkbox por padrão — sem isso o esmaecimento
  // visual (.fg-wm-device-disabled) ficaria "preso" no estado de quando a
  // lista carregou, só atualizando de verdade depois de salvar e recarregar
  function onWarmodeCfgDevicesChange(ev) {
    if (!ev.target.classList.contains("fg-wm-enabled")) return;
    var card = ev.target.closest(".fg-wm-device");
    if (card) card.classList.toggle("fg-wm-device-disabled", !ev.target.checked);
  }

  function onWarmodeCfgDevicesClick(ev) {
    var toggleEl = ev.target.closest("[data-action='toggle-expand']");
    if (toggleEl) {
      var card = toggleEl.closest(".fg-wm-device");
      var body = card.querySelector(".fg-wm-body");
      var chevronBtn = card.querySelector(".fg-wm-chevron-btn");
      body.hidden = !body.hidden;
      if (chevronBtn) chevronBtn.textContent = body.hidden ? "▾" : "▴";
      return;
    }

    var removeBtn = ev.target.closest("button[data-action='remove-device']");
    if (removeBtn) {
      var removeCard = removeBtn.closest(".fg-wm-device");
      var nameInput = removeCard.querySelector(".fg-wm-name");
      var label = (nameInput && nameInput.value.trim()) || "este equipamento";
      if (confirm('Remover "' + label + '" da lista? Só efetiva de verdade depois de clicar em "Salvar".')) {
        removeCard.remove();
      }
      return;
    }

    var dupBtn = ev.target.closest("button[data-action='duplicate-device']");
    if (dupBtn) {
      var srcCard = dupBtn.closest(".fg-wm-device");
      var data = warmodeCollectOneDevice(srcCard);
      data.name = data.name ? data.name + " (cópia)" : "";
      data.password = ""; // nunca duplica senha — cópia sempre pede uma nova
      data.has_password = false;
      data.last_run = null;
      srcCard.insertAdjacentHTML("afterend", warmodeDeviceCardHtml(data, true));
      return;
    }

    var testBtn = ev.target.closest("button[data-action='test-device']");
    if (testBtn) {
      onWarmodeTestDevice(testBtn);
    }
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
    if (devicesEl) devicesEl.addEventListener("change", onWarmodeCfgDevicesChange);
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
    var isRevert = warmodeExecMode === "revert";
    btn.disabled = true;
    document.getElementById("fg-warmode-results").innerHTML = '<p class="fg-kpi-sub">' +
      (isRevert ? "Revertendo" : "Executando") + " em paralelo em todos os equipamentos...</p>";
    warmodePostJson(WARMODE_ENDPOINT, { warmode_token: warmodeToken, action: warmodeExecMode })
      .then(function (r) {
        if (r.status === 401) {
          warmodeToken = null;
          warmodeExecShowStep("lock");
          document.getElementById("fg-warmode-exec-unlock-status").textContent = r.data.error || "sessão expirada, desbloqueie de novo";
          return;
        }
        renderWarmodeResults(r.data);
        var okMsg = isRevert ? "Sair do Modo Guerra executado" : "Modo Guerra executado";
        showToast(r.data.ok ? okMsg : r.data.error, r.data.ok ? "success" : "error");
        if (r.data.ok) loadWarmodeStatus(); // reflete o botão/timer na hora, sem esperar o próximo poll
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

  function rcPeerOptionLabel(p) {
    var label = p.peer_ip;
    if (p.remote_as) label += " — AS" + p.remote_as;
    if (p.description) label += " — " + p.description;
    label += " (" + (p.state === "up" ? "up" : "down/ignore") + ")";
    return label;
  }

  function rcInterfaceOptionLabel(i) {
    var label = i.name;
    if (i.ip) label += " — " + i.ip;
    label += " (" + i.physical + (i.admin_down ? "/admin-down" : "") + ")";
    return label;
  }

  function rcDiscoveryFieldOverride(f, template) {
    if (!template) return null;
    var id = "fg-rc-field-" + f.name;

    // select genérico de interface — vale pra QUALQUER template com um campo
    // desse tipo (não só os de BGP), já que a descoberta de interfaces não é
    // específica de nenhum template.
    if (f.type === "interface_name" && rcDiscovery && rcDiscovery.interfaces && rcDiscovery.interfaces.length) {
      var ifOpts = rcDiscovery.interfaces
        .map(function (i) { return '<option value="' + escapeHtml(i.name) + '">' + escapeHtml(rcInterfaceOptionLabel(i)) + "</option>"; })
        .join("");
      return '<select id="' + id + '" data-field="' + escapeHtml(f.name) + '"><option value="" disabled selected>selecione a interface...</option>' + ifOpts + "</select>";
    }

    var isBgpTemplate = template.id === "bgp_peer_toggle" || template.id === "bgp_prefix_advertise";
    if (!isBgpTemplate) return null;

    if (f.name === "as_number") {
      var asVal = rcDiscovery && rcDiscovery.local_as ? rcDiscovery.local_as : "";
      var readonlyAttr = asVal ? " readonly" : "";
      return '<input type="text" id="' + id + '" data-field="as_number" value="' + escapeHtml(asVal) +
        '" placeholder="AS local (use \'Ler configuração atual\' pra preencher)"' + readonlyAttr + ">";
    }
    if (template.id === "bgp_peer_toggle" && f.name === "peer_ip") {
      if (rcDiscovery && rcDiscovery.peers && rcDiscovery.peers.length) {
        var peerOpts = rcDiscovery.peers
          .map(function (p) { return '<option value="' + escapeHtml(p.peer_ip) + '">' + escapeHtml(rcPeerOptionLabel(p)) + "</option>"; })
          .join("");
        return '<select id="' + id + '" data-field="peer_ip"><option value="" disabled selected>selecione o peer...</option>' + peerOpts + "</select>";
      }
      return (
        '<p class="fg-kpi-sub">Clique em "Ler configuração atual (BGP)" acima pra escolher o peer.</p>' +
        '<input type="text" id="' + id + '" data-field="peer_ip" placeholder="ou digite o IP do peer">'
      );
    }
    if (template.id === "bgp_prefix_advertise" && f.name === "prefix") {
      if (rcDiscovery && rcDiscovery.networks && rcDiscovery.networks.length) {
        var netOpts = rcDiscovery.networks
          .map(function (n) { return '<option value="' + escapeHtml(n.cidr) + '">' + escapeHtml(n.cidr) + "</option>"; })
          .join("");
        return '<select id="' + id + '" data-field="prefix"><option value="" disabled selected>selecione o prefixo...</option>' + netOpts + "</select>";
      }
      return (
        '<p class="fg-kpi-sub">Clique em "Ler configuração atual (BGP)" acima pra escolher o prefixo.</p>' +
        '<input type="text" id="' + id + '" data-field="prefix" placeholder="ou digite o CIDR manualmente">'
      );
    }
    return null;
  }

  function rcFieldInputHtml(f, template) {
    var override = rcDiscoveryFieldOverride(f, template);
    if (override) return override;

    var id = "fg-rc-field-" + f.name;
    if (f.type === "enum") {
      var placeholderOpt = f.default == null ? '<option value="" disabled selected>selecione...</option>' : "";
      var opts = (f.options || [])
        .map(function (o) {
          var sel = f.default === o ? " selected" : "";
          return '<option value="' + escapeHtml(o) + '"' + sel + ">" + escapeHtml(o) + "</option>";
        })
        .join("");
      return '<select id="' + id + '" data-field="' + escapeHtml(f.name) + '">' + placeholderOpt + opts + "</select>";
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
        return "<label>" + escapeHtml(f.label) + (f.required ? " *" : "") + rcFieldInputHtml(f, template) + "</label>";
      })
      .join("");
  }

  function renderRcDiscoverySummary(d) {
    var el = document.getElementById("fg-rc-discovery-summary");
    if (!d) { el.innerHTML = ""; return; }
    var peersRows = d.peers
      .map(function (p) {
        var estado = p.state === "up" ? '<span class="fg-ok">up</span>' : '<span class="fg-error">down (ignore)</span>';
        return (
          "<tr><td>" + escapeHtml(p.peer_ip) + "</td><td>" + escapeHtml(p.remote_as || "-") + "</td><td>" +
          escapeHtml(p.description || "-") + "</td><td>" + estado + "</td><td>" +
          '<button class="fg-btn" data-rc-peer-routes="' + escapeHtml(p.peer_ip) + '">Ver rotas</button></td></tr>'
        );
      })
      .join("");
    var netsRows = d.networks.map(function (n) { return "<tr><td>" + escapeHtml(n.cidr) + "</td></tr>"; }).join("");
    var ifRows = (d.interfaces || [])
      .map(function (i) {
        var phy = i.physical === "up" ? '<span class="fg-ok">up</span>' : (i.admin_down ? '<span class="fg-error">admin-down</span>' : '<span class="fg-error">down</span>');
        return "<tr><td>" + escapeHtml(i.name) + "</td><td>" + escapeHtml(i.ip || "-") + "</td><td>" + phy + "</td><td>" + escapeHtml(i.protocol) + "</td></tr>";
      })
      .join("");
    var vlanRows = (d.vlans || [])
      .map(function (v) {
        return "<tr><td>" + escapeHtml(v.vlan_id) + "</td><td>" + escapeHtml(v.name || "-") + "</td><td>" + escapeHtml(v.status) + "</td><td>" + escapeHtml(v.ports || "-") + "</td></tr>";
      })
      .join("");
    el.innerHTML =
      '<p class="fg-kpi-sub">AS local: <strong>' + escapeHtml(d.local_as || "?") + "</strong></p>" +
      "<h4>Peers BGP (" + d.peers.length + ")</h4>" +
      "<table><thead><tr><th>IP</th><th>AS remoto</th><th>Descrição</th><th>Estado</th><th></th></tr></thead><tbody>" +
      (peersRows || '<tr><td colspan="5">nenhum peer encontrado</td></tr>') + "</tbody></table>" +
      '<div id="fg-rc-peer-routes"></div>' +
      "<h4>Prefixos anunciados (" + d.networks.length + ")</h4>" +
      "<table><thead><tr><th>CIDR</th></tr></thead><tbody>" +
      (netsRows || '<tr><td>nenhum</td></tr>') + "</tbody></table>" +
      "<h4>Interfaces (" + (d.interfaces || []).length + ")</h4>" +
      "<table><thead><tr><th>Nome</th><th>IP</th><th>Físico</th><th>Protocolo</th></tr></thead><tbody>" +
      (ifRows || '<tr><td colspan="4">nenhuma interface encontrada</td></tr>') + "</tbody></table>" +
      "<h4>VLANs (" + (d.vlans || []).length + ")</h4>" +
      "<table><thead><tr><th>VID</th><th>Nome</th><th>Status</th><th>Portas</th></tr></thead><tbody>" +
      (vlanRows || '<tr><td colspan="4">nenhuma VLAN encontrada</td></tr>') + "</tbody></table>";
  }

  function renderPeerRoutesPanel(peerIp, direction, data) {
    var el = document.getElementById("fg-rc-peer-routes");
    if (!el) return;
    var dirLabel = direction === "received" ? "recebidas de" : "anunciadas para";
    var toggle =
      '<div class="fg-toggle-group" style="margin:0.4rem 0;">' +
      '<button class="fg-toggle-btn' + (direction === "advertised" ? " active" : "") + '" data-rc-routes-dir="advertised" data-rc-routes-peer="' + escapeHtml(peerIp) + '">Anunciadas</button>' +
      '<button class="fg-toggle-btn' + (direction === "received" ? " active" : "") + '" data-rc-routes-dir="received" data-rc-routes-peer="' + escapeHtml(peerIp) + '">Recebidas</button>' +
      "</div>";
    if (!data) {
      el.innerHTML = '<div class="fg-rc-job"><strong>Rotas ' + dirLabel + " " + escapeHtml(peerIp) + "</strong>" + toggle + '<p class="fg-kpi-sub">Consultando...</p></div>';
      return;
    }
    var items = data.prefixes.map(function (p) { return "<li>" + escapeHtml(p) + "</li>"; }).join("");
    var totalNote = data.total_reported != null ? " (equipamento reporta " + data.total_reported + ")" : "";
    el.innerHTML =
      '<div class="fg-rc-job"><strong>Rotas ' + dirLabel + " " + escapeHtml(peerIp) + "</strong>" + toggle +
      '<p class="fg-kpi-sub">' + data.prefixes.length + " prefixo(s)" + totalNote + "</p>" +
      "<ul>" + (items || "<li>nenhum</li>") + "</ul></div>";
  }

  function loadPeerRoutes(peerIp, direction) {
    renderPeerRoutesPanel(peerIp, direction, null);
    warmodePostJson(ROUTERCFG_ENDPOINT, { warmode_token: warmodeToken, action: "peer_routes", peer_ip: peerIp, direction: direction })
      .then(function (r) {
        if (r.status === 401) { warmodeToken = null; rcShowStep("lock"); return; }
        var el = document.getElementById("fg-rc-peer-routes");
        if (!r.data.ok) {
          showError(el, r.data.error || "falha ao consultar rotas");
          return;
        }
        renderPeerRoutesPanel(peerIp, direction, r.data.routes);
      })
      .catch(function (err) {
        showError(document.getElementById("fg-rc-peer-routes"), "falha ao consultar rotas");
        console.error("flowguard.js:", err);
      });
  }

  function onRcDiscoverySummaryClick(ev) {
    var routesBtn = ev.target.closest("[data-rc-peer-routes]");
    if (routesBtn) {
      loadPeerRoutes(routesBtn.getAttribute("data-rc-peer-routes"), "advertised");
      return;
    }
    var dirBtn = ev.target.closest("[data-rc-routes-dir]");
    if (dirBtn) {
      loadPeerRoutes(dirBtn.getAttribute("data-rc-routes-peer"), dirBtn.getAttribute("data-rc-routes-dir"));
    }
  }

  function loadRcDiscovery() {
    var btn = document.getElementById("fg-rc-discover-btn");
    var summary = document.getElementById("fg-rc-discovery-summary");
    btn.disabled = true;
    summary.innerHTML = '<p class="fg-kpi-sub">Consultando o roteador via SSH...</p>';
    warmodePostJson(ROUTERCFG_ENDPOINT, { warmode_token: warmodeToken, action: "discover" })
      .then(function (r) {
        btn.disabled = false;
        if (r.status === 401) { warmodeToken = null; rcShowStep("lock"); return; }
        if (!r.data.ok) {
          showError(summary, r.data.error || "falha ao consultar o roteador");
          return;
        }
        rcDiscovery = r.data.discovery;
        renderRcDiscoverySummary(rcDiscovery);
        var template = rcSelectedTemplate();
        if (template) renderRcFields(template);
      })
      .catch(function (err) {
        btn.disabled = false;
        showError(summary, "falha ao consultar o roteador");
        console.error("flowguard.js:", err);
      });
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
      renderRcDiscoverySummary(rcDiscovery);
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
    var discoverBtn = document.getElementById("fg-rc-discover-btn");
    if (discoverBtn) discoverBtn.addEventListener("click", loadRcDiscovery);
    var discoverySummaryEl = document.getElementById("fg-rc-discovery-summary");
    if (discoverySummaryEl) discoverySummaryEl.addEventListener("click", onRcDiscoverySummaryClick);
  }

  // --- ajuste fino dos limiares de detecção (config.yaml::detection) ------

  // type "mbps" converte bps<->Mbps só na exibição/edição (mesma conveniência já
  // usada em fg-monitor-form::ddos_bps_threshold_mbps); "boolean" vira <select>.
  var FG_DETECTION_CFG_FIELDS = [
    { key: "ddos_bps_threshold", label: "DDoS — limiar de tráfego (Mbps)", type: "mbps", desc: "Tráfego agregado do prefixo (megabits por segundo) acima disso conta como ataque volumétrico. Campo já converte pra bps internamente — digite direto em Mbps (ex: 500 = meio giga)." },
    { key: "ddos_pps_threshold", label: "DDoS — limiar de pacotes por segundo (pps)", type: "number", desc: "Pacotes/segundo agregados do prefixo acima disso conta como ataque volumétrico (alternativa ao limiar de tráfego — qualquer um dos dois dispara)." },
    { key: "amp_bps_threshold", label: "Amplificação — limiar de tráfego (Mbps)", type: "mbps", desc: "Tráfego de resposta (dns/ntp/ssdp/memcached/cldap), em megabits por segundo, acima disso conta como amplificação — limiar SEPARADO do volumétrico acima, tipicamente bem menor (ataques de amplificação real costumam ter volume menor que um DDoS volumétrico puro)." },
    { key: "syn_ratio_threshold", label: "SYN flood — proporção mínima (0 a 1, ex: 0.9 = 90%)", type: "number", desc: "Proporção de pacotes SYN puro (SYN sem ACK) sobre o total de TCP do prefixo — acima disso conta como SYN flood. 0.9 = 90% do tráfego TCP sendo SYN puro." },
    { key: "syn_min_pps_floor", label: "SYN flood — piso de tráfego TCP total (pps)", type: "number", desc: "A proporção de SYN só é avaliada quando o TRÁFEGO TCP TOTAL do prefixo (em pacotes/segundo) já passou desse piso — evita disparo com pouquíssimo tráfego (ex: 2 SYN em 2 pacotes = 100%, mas não é ataque)." },
    { key: "min_attack_duration_s", label: "Duração mínima pra abrir ataque (segundos)", type: "number", desc: "Tráfego precisa ficar sustentado acima do limiar por esse tempo (em segundos) antes de virar um ataque registrado — filtra picos curtos e legítimos." },
    { key: "attack_stale_close_s", label: "Fechamento automático por inatividade (segundos)", type: "number", desc: "Rede de segurança: fecha sozinho um ataque que ficou esse tempo (em segundos) sem nenhuma reconfirmação de tráfego — cobre o caso do prefixo sair de monitoramento ou o daemon reiniciar no meio do ataque." },
    { key: "baseline_min_duration_s", label: "Baseline — duração mínima da anomalia (segundos)", type: "number", desc: "Igual ao campo acima, mas só pra anomalia de baseline (mais ruidosa por natureza — reage a desvio estatístico, não a um limiar fixo óbvio) — exige mais tempo sustentado (em segundos) antes de abrir ataque." },
    { key: "baseline_enabled", label: "Anomalia de baseline — habilitada (sim/não)", type: "boolean", desc: "Liga/desliga a detecção por desvio estatístico (EWMA) do tráfego normal do prefixo — pega ataques relevantes pra um cliente PEQUENO, que nunca bateria o limiar fixo global." },
    { key: "baseline_window_minutes", label: "Baseline — janela de cálculo (minutos)", type: "number", desc: "Quantos minutos de histórico são usados pra calcular a média/desvio-padrão do tráfego \"normal\" do prefixo (EWMA — mais peso pro tráfego recente que pro antigo)." },
    { key: "baseline_min_samples", label: "Baseline — amostras mínimas (nº de ciclos de agregação)", type: "number", desc: "Quantos CICLOS de agregação (não segundos — cada ciclo é o intervalo configurado em database.aggregate_interval_s, tipicamente 30s) precisam se acumular antes da baseline ser considerada confiável o bastante pra detectar anomalia." },
    { key: "baseline_sigma", label: "Baseline — sensibilidade (nº de desvios-padrão, ex: 4)", type: "number", desc: "Tráfego acima da média + N desvios-padrão conta como anomalia — número MAIOR = menos sensível (exige desvio maior pra disparar), número MENOR = mais sensível (mais falso positivo)." },
    { key: "baseline_min_bps", label: "Baseline — piso mínimo de tráfego (Mbps)", type: "mbps", desc: "Anomalia de baseline só dispara acima desse piso de tráfego real (em megabits por segundo) — evita marcar como \"ataque\" uma variação estatística sobre um prefixo que mal tem tráfego." },
  ];

  function renderFgDetectionCfg(detection) {
    var el = document.getElementById("fg-detection-cfg");
    if (!el) return;
    state.fgDetectionCfg = detection || {};
    el.innerHTML = FG_DETECTION_CFG_FIELDS.map(function (f) {
      var val = state.fgDetectionCfg[f.key];
      var fieldHtml;
      if (f.type === "boolean") {
        fieldHtml = '<select data-detection-key="' + f.key + '" data-detection-type="boolean">' +
          '<option value="true"' + (val !== false ? " selected" : "") + ">sim</option>" +
          '<option value="false"' + (val === false ? " selected" : "") + ">não</option></select>";
      } else {
        var inputVal = f.type === "mbps" ? (val != null ? val / 1e6 : "") : (val != null ? val : "");
        fieldHtml = '<input type="text" data-detection-key="' + f.key + '" data-detection-type="' + f.type +
          '" value="' + escapeHtml(String(inputVal)) + '">';
      }
      return (
        '<div style="margin-bottom:0.7rem;">' +
        '<label style="display:block; font-weight:600; margin-bottom:0.15rem;">' + escapeHtml(f.label) + "</label>" +
        '<p class="fg-kpi-sub" style="margin:0 0 0.3rem;">' + escapeHtml(f.desc) + "</p>" +
        fieldHtml +
        "</div>"
      );
    }).join("");
  }

  function onFgDetectionCfgSaveClick() {
    var el = document.getElementById("fg-detection-cfg");
    var btn = document.getElementById("fg-detection-cfg-save-btn");
    if (!el || !btn) return;
    var changes = {};
    var invalid = false;
    el.querySelectorAll("[data-detection-key]").forEach(function (input) {
      var key = input.getAttribute("data-detection-key");
      var type = input.getAttribute("data-detection-type");
      var original = state.fgDetectionCfg[key];
      if (type === "boolean") {
        var boolVal = input.value === "true";
        if (boolVal !== (original !== false)) changes[key] = boolVal;
        return;
      }
      var raw = input.value.trim();
      if (!raw) {
        // campo vazio sem valor original (chave ainda sem valor em config.yaml,
        // ex: removida/nunca setada) não é uma edição — não deve travar o resto
        // do formulário; só é erro se havia um valor antes e o operador o apagou.
        if (original == null) return;
        invalid = true;
        return;
      }
      var n = Number(raw);
      if (!Number.isFinite(n) || n <= 0) { invalid = true; return; }
      var resolved = type === "mbps" ? Math.round(n * 1e6) : n;
      if (resolved !== original) changes[key] = resolved;
    });
    if (invalid) {
      showToast("Valores inválidos — confira os campos numéricos", "error");
      return;
    }
    if (!Object.keys(changes).length) {
      showToast("Nenhum limiar foi alterado");
      return;
    }
    btn.disabled = true;
    postJson(CFG_ENDPOINT, { cmd: "detection_cfg_set", changes: changes })
      .then(function (resp) {
        showToast(resp.ok ? "Limiares atualizados" : resp.error, resp.ok ? "success" : "error");
        if (resp.ok) renderFgDetectionCfg(resp.detection);
      })
      .finally(function () { btn.disabled = false; });
  }

  // --- templates de detecção (perfis reutilizáveis por tipo de rede) ------

  function populateFgTemplateSelects() {
    var names = Object.keys(state.fgDetectionTemplates || {});
    var optionsHtml = '<option value="">sem template</option>' +
      names.map(function (n) { return '<option value="' + escapeHtml(n) + '">' + escapeHtml(n) + "</option>"; }).join("");
    document.querySelectorAll(".fg-template-select").forEach(function (sel) {
      var current = sel.value;
      sel.innerHTML = optionsHtml;
      if (names.indexOf(current) !== -1) sel.value = current;
    });
  }

  function renderFgDetectionTemplates(templates) {
    var el = document.getElementById("fg-detection-templates");
    if (!el) return;
    state.fgDetectionTemplates = templates || {};
    populateFgTemplateSelects();
    var names = Object.keys(state.fgDetectionTemplates);
    if (!names.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum template cadastrado — todo prefixo usa o limiar global.</p>';
      return;
    }
    var rows = names.map(function (name) {
      var t = state.fgDetectionTemplates[name];
      return (
        '<tr data-template-name="' + escapeHtml(name) + '"><td>' + escapeHtml(name) + "</td><td>" +
        (t.ddos_bps_threshold != null ? fmtBps(t.ddos_bps_threshold) : "-") + "</td><td>" +
        (t.ddos_pps_threshold != null ? t.ddos_pps_threshold.toLocaleString("pt-BR") + " pps" : "-") + "</td><td>" +
        (t.amp_bps_threshold != null ? fmtBps(t.amp_bps_threshold) : "-") + "</td><td>" +
        escapeHtml(t.description || "-") + "</td>" +
        '<td><button class="fg-btn" data-action="edit-template">Editar</button> ' +
        '<button class="fg-btn fg-btn-danger" data-action="del-template">Remover</button></td></tr>'
      );
    }).join("");
    el.innerHTML =
      "<table><thead><tr><th>Nome</th><th>Limiar DDoS</th><th>Limiar pps</th><th>Limiar amplificação</th><th>Descrição</th><th></th></tr></thead><tbody>" +
      rows + "</tbody></table>";
  }

  function onFgDetectionTemplateEditClick(name) {
    var t = (state.fgDetectionTemplates || {})[name];
    var form = document.getElementById("fg-detection-template-form");
    if (!t || !form) return;
    form.name.value = name;
    form.ddos_bps_threshold_mbps.value = t.ddos_bps_threshold != null ? t.ddos_bps_threshold / 1e6 : "";
    form.ddos_pps_threshold.value = t.ddos_pps_threshold != null ? t.ddos_pps_threshold : "";
    form.amp_bps_threshold_mbps.value = t.amp_bps_threshold != null ? t.amp_bps_threshold / 1e6 : "";
    form.description.value = t.description || "";
    form.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function onFgDetectionTemplatesClick(ev) {
    var btn = ev.target.closest("button[data-action]");
    if (!btn) return;
    var action = btn.getAttribute("data-action");
    var row = btn.closest("tr[data-template-name]");
    if (!row) return;
    var name = row.getAttribute("data-template-name");
    if (action === "edit-template") {
      onFgDetectionTemplateEditClick(name);
    } else if (action === "del-template") {
      if (!window.confirm("Remover o template '" + name + "'? Prefixos que usam esse template voltam pro limiar global.")) return;
      postJson(CFG_ENDPOINT, { cmd: "detection_templates_del", name: name }).then(function (resp) {
        showToast(resp.ok ? "Template removido" : resp.error, resp.ok ? "success" : "error");
        loadCfg();
      });
    }
  }

  function onFgDetectionTemplateFormSubmit(ev) {
    ev.preventDefault();
    var form = ev.target;
    var values = { ddos_bps_threshold: Math.round(Number(form.ddos_bps_threshold_mbps.value) * 1e6) };
    if (form.ddos_pps_threshold.value.trim()) values.ddos_pps_threshold = Number(form.ddos_pps_threshold.value);
    if (form.amp_bps_threshold_mbps.value.trim()) {
      values.amp_bps_threshold = Math.round(Number(form.amp_bps_threshold_mbps.value) * 1e6);
    }
    postJson(CFG_ENDPOINT, {
      cmd: "detection_templates_set", name: form.name.value.trim(), values: values,
      description: form.description.value.trim(),
    }).then(function (resp) {
      showToast(resp.ok ? "Template salvo" : resp.error, resp.ok ? "success" : "error");
      if (resp.ok) { form.reset(); loadCfg(); }
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
    // templates ANTES da tabela de prefixos — o <select> de cada linha usa os
    // nomes de template já carregados.
    renderFgDetectionTemplates(data.detection_templates);
    renderFgDetectionCfg(data.detection);
    // guardado pra edit-monitor ler o valor RAW (bps) na hora de editar — ler de
    // volta o texto já formatado da célula ("35.0 Gbps") seria perda de precisão
    // e, pior, monitor_set SUBSTITUI a entrada inteira (não faz merge): sem
    // prefilar aqui, editar qualquer outro campo (ex: só o cliente) apagava o
    // limiar customizado do prefixo em silêncio.
    state.fgProtectedPrefixes = data.protected_prefixes;

    var prefixRows = data.protected_prefixes
      .map(function (p) {
        var th = p.thresholds || {};
        return (
          '<tr data-prefix="' + escapeHtml(p.prefix) + '">' +
          "<td>" + escapeHtml(p.prefix) + "</td><td>" + escapeHtml(p.customer || "-") + "</td><td>" +
          (p.capacity_mbps || 0) + " Mbps</td><td>" + (p.auto_mitigate ? "sim" : "não") + "</td><td>" +
          (th.ddos_bps_threshold ? fmtBps(th.ddos_bps_threshold) : "-") + "</td>" +
          "<td>" + (th.amp_bps_threshold ? fmtBps(th.amp_bps_threshold) : "-") + "</td>" +
          "<td>" + (p.template ? escapeHtml(p.template) : "-") + "</td>" +
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
      "<table><thead><tr><th>Prefixo</th><th>Cliente</th><th>Capacidade</th><th>Auto-mitigar</th><th>Limiar bps</th><th>Limiar amplif.</th><th>Template</th><th></th></tr></thead><tbody>" +
      prefixRows +
      "</tbody></table>" +
      '<form id="fg-monitor-form" class="fg-form">' +
      '<input name="prefix" placeholder="prefixo (ex: 177.86.30.0/24)" required>' +
      '<input name="customer" placeholder="cliente">' +
      '<input name="capacity_mbps" type="number" placeholder="capacidade (Mbps)">' +
      '<input name="ddos_bps_threshold_mbps" type="number" placeholder="limiar DDoS (Mbps)">' +
      '<input name="amp_bps_threshold_mbps" type="number" placeholder="limiar amplificação (Mbps)">' +
      '<select name="template" class="fg-template-select"><option value="">sem template</option></select>' +
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
    populateFgTemplateSelects();
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
      // lê do estado (dado RAW já carregado), não da célula formatada ("35.0
      // Gbps") — monitor_set SUBSTITUI a entrada inteira (sem merge), então
      // qualquer campo aqui esquecido de prefilar é apagado em silêncio no
      // próximo "Salvar" (bug real corrigido: notify_wa/thresholds sumiam ao
      // editar só o cliente, por exemplo).
      var entry = (state.fgProtectedPrefixes || []).filter(function (p) { return p.prefix === prefix; })[0] || {};
      var th = entry.thresholds || {};
      form.prefix.value = prefix;
      form.prefix.readOnly = true;
      form.customer.value = entry.customer || "";
      form.capacity_mbps.value = entry.capacity_mbps || "";
      form.ddos_bps_threshold_mbps.value = th.ddos_bps_threshold ? th.ddos_bps_threshold / 1e6 : "";
      form.amp_bps_threshold_mbps.value = th.amp_bps_threshold ? th.amp_bps_threshold / 1e6 : "";
      form.auto_mitigate.checked = !!entry.auto_mitigate;
      form.notify_wa.checked = !!entry.notify_wa;
      form.template.value = entry.template || "";
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
      var ampMbps = Number(form.amp_bps_threshold_mbps.value);
      if (ampMbps > 0) thresholds.amp_bps_threshold = Math.round(ampMbps * 1e6);
      postJson(CFG_ENDPOINT, {
        cmd: "monitor_set",
        prefix: form.prefix.value,
        customer: form.customer.value,
        capacity_mbps: Number(form.capacity_mbps.value) || 0,
        auto_mitigate: form.auto_mitigate.checked,
        notify_wa: form.notify_wa.checked,
        thresholds: thresholds,
        template: form.template.value,
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

  var CG_MITIGATION_MECHANISM_LABELS = { flowspec: "FlowSpec", ssh: "SSH/ACL" };

  // "esse cliente já participa de alguma mitigação, e está em vigor agora?" —
  // pedido do usuário. "encerrada" cobre TTL vencido, revert manual e a
  // reconciliação automática com o FlowGuard (ver flowspec_mitigation.
  // reconcile_with_flowguard, no backend) — didaticamente é sempre "não está
  // bloqueando mais", a causa exata não importa pro operador aqui.
  // rowOpen = o sinal está GENUINAMENTE em andamento agora (ver
  // isGenuinelyActive) — não basta resolved=0: um sinal aberto mas sem
  // reconfirmação recente (🟡, já "acabou" na prática) não deve mostrar o
  // alarme "sem proteção", só "encerrada" mesmo (mesma ideia do equivalente
  // no FlowGuard, fgAttackMitigationBadgeHtml).
  function cgMitigationBadgeHtml(mitigation, rowOpen) {
    if (!mitigation) {
      return '<span class="fg-mitigation-badge none">sem mitigação</span>';
    }
    var mech = CG_MITIGATION_MECHANISM_LABELS[mitigation.mechanism] || mitigation.mechanism;
    var since = "desde " + fmtDateTime(mitigation.ts_applied);
    if (mitigation.status === "active") {
      return '<span class="fg-mitigation-badge active" title="Mitigação ativa (' + since +
        ')">🛡 ativa (' + escapeHtml(mech) + ")</span>";
    }
    if (mitigation.status === "failed") {
      return '<span class="fg-mitigation-badge failed" title="Última tentativa de mitigação falhou (' + since +
        ')">✖ falhou (' + escapeHtml(mech) + ")</span>";
    }
    if (rowOpen) {
      return '<span class="fg-mitigation-badge failed" title="Mitigação encerrada (' + since +
        ') mas o sinal continua aberto — sem proteção agora">⚠ sem proteção (' + escapeHtml(mech) + ")</span>";
    }
    return '<span class="fg-mitigation-badge inactive" title="Já teve mitigação, não está mais em vigor (' +
      since + ')">encerrada (' + escapeHtml(mech) + ")</span>";
  }

  // Equivalente ao badge acima, pro lado FlowGuard (aba Ataques) — mesma ideia
  // ("esse ataque já tem regra de mitigação, e está em vigor agora?"), mas o
  // formato de mitigation vem de storage.get_latest_flowspec_rule_for_attack
  // (action/active/created_at em vez de status/mechanism/ts_applied do
  // ClientGuard) — o FlowGuard não persiste tentativa "failed" hoje (só grava
  // uma regra quando o anúncio BGP dá certo), por isso não existe esse estado
  // aqui, diferente do ClientGuard.
  var FG_MITIGATION_ACTION_LABELS = { rtbh: "RTBH" };
  // rowOpen = o ataque está GENUINAMENTE em andamento agora (ver
  // isGenuinelyActive) — não basta ts_end NULL: um ataque tecnicamente "ativo"
  // mas sem reconfirmação recente (🟡, já "acabou" na prática, só não fechou
  // sozinho ainda) não deve mostrar o alarme "sem proteção", só "encerrada".
  function fgAttackMitigationBadgeHtml(mitigation, rowOpen) {
    if (!mitigation) {
      return '<span class="fg-mitigation-badge none">sem mitigação</span>';
    }
    var actionLabel = FG_MITIGATION_ACTION_LABELS[mitigation.action] ||
      (mitigation.action && mitigation.action.startsWith("rate-limit:")
        ? "limitado a " + Math.round(parseInt(mitigation.action.split(":")[1], 10) / 1e6) + " Mbps"
        : "discard");
    var since = "desde " + fmtDateTime(mitigation.created_at);
    if (mitigation.active) {
      return '<span class="fg-mitigation-badge active" title="Mitigação ativa (' + since +
        ')">🛡 ativa (' + escapeHtml(actionLabel) + ")</span>";
    }
    if (rowOpen) {
      return '<span class="fg-mitigation-badge failed" title="Mitigação encerrada (' + since +
        ') mas o ataque continua ativo — sem proteção agora">⚠ sem proteção (' + escapeHtml(actionLabel) + ")</span>";
    }
    return '<span class="fg-mitigation-badge inactive" title="Já teve mitigação, não está mais em vigor (' +
      since + ')">encerrada (' + escapeHtml(actionLabel) + ")</span>";
  }

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

  // ajuste fino de config.yaml::detection (aplicado via detection_overrides.yaml,
  // sem reiniciar o daemon) — type "ports" vira lista (input de texto, vírgula-separado)
  var CG_DETECTION_CFG_FIELDS = [
    { key: "scan_horizontal_hosts", label: "Scan horizontal — hosts distintos (nº de hosts)", type: "number", desc: "Cliente falando com esse número de destinos DIFERENTES, na MESMA porta, dentro da janela — conta como scan horizontal (reconhecimento de rede)." },
    { key: "scan_vertical_ports", label: "Scan vertical — portas distintas (nº de portas)", type: "number", desc: "Cliente falando com esse número de portas DIFERENTES no MESMO destino, dentro da janela — conta como scan vertical (varredura de portas)." },
    { key: "scan_max_avg_bytes", label: "Scan — máximo de bytes médios por destino (bytes)", type: "number", desc: "Média de bytes por destino/porta ACIMA disso é tráfego real (P2P/torrent transferindo dado de verdade), não sonda de reconhecimento (que manda pacotes pequenos) — protege contra falso positivo." },
    { key: "amplifier_min_bps", label: "Amplificador — tráfego de resposta mínimo (bps, valor cru — 5000000 = 5 Mbps)", type: "number", desc: "Tráfego de RESPOSTA (não de pergunta) do cliente pra fora, em bits por segundo, acima disso conta como amplificador hospedado — ATENÇÃO: campo em bps cru, não Mbps (5000000 = 5 Mbps, não digite só \"5\")." },
    { key: "spam_min_distinct_dest", label: "Spam — destinos distintos (nº de destinos)", type: "number", desc: "Cliente conectando em portas de e-mail (25/465/587) pra esse número de destinos DIFERENTES dentro da janela — conta como spam bot." },
    { key: "coordinated_min_clients", label: "Destino coordenado — clientes distintos (nº de clientes)", type: "number", desc: "Esse número de clientes MEUS distintos falando com o MESMO destino externo ao mesmo tempo (fora portas web/DNS comuns) — indício de botnet/C2 atingindo vários clientes juntos." },
    { key: "dns_tunneling_min_queries", label: "Túnel DNS — queries mínimas (nº de queries, já ajustado pelo sampling)", type: "number", desc: "Queries DNS (já multiplicadas pela taxa de amostragem do NetFlow) pro MESMO resolver externo, dentro da janela, acima disso conta como túnel DNS/exfiltração." },
    { key: "amplifier_ports", label: "Portas de amplificação (lista separada por vírgula)", type: "ports", desc: "Portas UDP de serviço monitoradas pelo detector de amplificador — ex: 53 (DNS), 123 (NTP), 1900 (SSDP)." },
    { key: "spam_ports", label: "Portas de e-mail / spam (lista separada por vírgula)", type: "ports", desc: "Portas TCP monitoradas pelo detector de spam bot — ex: 25 (SMTP), 465/587 (SMTP com TLS)." },
    { key: "common_service_ports", label: "Portas de serviço comum / exceção (lista separada por vírgula)", type: "ports", desc: "Portas de app popular (CDN/VoIP/push/jogos/etc — ex: 443, 3478, 5223) EXCLUÍDAS do scan horizontal e do destino coordenado, pra não confundir uso normal (todo mundo usando o mesmo app) com abuso de verdade." },
  ];

  function updateCgBadge(count) {
    state.incidents.openSignals = count;
    updateIncidentsBadge();
  }

  function renderCgKpis(status) {
    var el = document.getElementById("cg-kpis");
    if (!el) return;
    if (!status || !status.ok) {
      el.innerHTML = kpiCard("Daemon", '<span class="fg-dot fg-dot-down"></span>indisponível', (status && status.error) || "");
      return;
    }
    el.innerHTML =
      kpiCard("Sinais abertos", status.open_signals, status.open_signals > 0 ? "requer atenção" : "tudo normal") +
      kpiCard("Mitigações ativas", status.active_mitigations, "FlowSpec + SSH legado", null, status.active_mitigations > 0) +
      kpiCard("Redes cadastradas", status.n_customers, "") +
      kpiCard("Whitelist", status.n_whitelist, "") +
      kpiCard("Daemon", '<span class="fg-dot fg-dot-up"></span>ativo', "uptime " + fmtUptime(status.uptime_s) + " · pid " + status.pid);
  }

  function loadClientGuardStatus() {
    getJson(CG_STATUS_ENDPOINT).then(function (data) {
      state.cgStatus = data.ok ? data.status : null; // reaproveitado pelo widget ClientGuard do cockpit
      renderCgKpis(state.cgStatus);
      cockpitRefreshAll();
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
      el.innerHTML = '<p class="fg-ok">' +
        (state.filter.cgTop ? "Nenhum cliente encontrado para o filtro atual." : "Nenhum tráfego na janela selecionada.") +
        "</p>";
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
      state.cgTop = data.top || [];
      renderCgTopFiltered();
    }).catch(function (err) {
      showError(document.getElementById("cg-top"), "falha ao consultar top clientes");
      console.error("flowguard.js:", err);
    });
  }

  function renderCgTopFiltered() {
    renderCgTop(filterRows(state.cgTop, state.filter.cgTop, ["src_ip", "customer_prefix"]));
  }

  function initCgTopWindowControls() {
    var toggle = document.getElementById("cg-top-window");
    var search = document.getElementById("cg-top-search");
    if (search) {
      search.addEventListener("input", function () {
        state.filter.cgTop = search.value.trim();
        renderCgTopFiltered();
      });
    }
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

  // severidade do sinal ClientGuard é derivada da confiança (não existe
  // campo próprio no backend) — só pra exibição/filtro/agrupamento, mesmo
  // corte usado pelo poxflow v2 (signalSeverity)
  function signalSeverity(r) {
    var c = r.confidence || 0;
    if (c >= 0.8) return "high";
    if (c >= 0.5) return "medium";
    return "watch";
  }
  var CG_SEV_RANK = { high: 0, medium: 1, watch: 2 };
  function signalSevClass(sev) {
    return "fg-sev-" + (sev === "watch" ? "info" : sev);
  }

  function cgSuspiciousRowHtml(r) {
    var sev = signalSeverity(r);
    var resolveBtn = state.cgSuspiciousView === "open"
      ? '<button class="fg-btn" data-action="resolve">Resolver</button> '
      : "";
    var edgeBtn = state.cgSuspiciousView === "open"
      ? '<button class="fg-btn" data-action="edge-apply" title="Bloquear src_ip direto na borda via SSH/ACL">Aplicar na borda</button> '
      : "";
    var checkboxCell = state.cgSuspiciousSelectMode
      ? '<td><input type="checkbox" class="fg-cg-select"' + (state.cgSuspiciousSelected[r.id] ? " checked" : "") + "></td>"
      : "";
    var newBadge = isNewIncident(r.ts_detected) ? ' <span class="fg-badge" title="novo desde a última visita à aba">novo</span>' : "";
    return (
      '<tr data-signal-id="' + r.id + '" data-src-ip="' + escapeHtml(r.src_ip) + '">' +
      checkboxCell +
      "<td>" + escapeHtml(r.src_ip) + "</td><td>" + escapeHtml(r.customer_prefix || "-") + "</td><td>" +
      escapeHtml(CG_SIGNAL_LABELS[r.signal_type] || r.signal_type) + "</td><td class=\"" + signalSevClass(sev) + "\">" +
      Math.round((r.confidence || 0) * 100) + "% (" + sev + ")</td><td>" + fmtDateTime(r.ts_detected) + newBadge + "</td><td>" +
      fmtDateTime(r.ts_last_seen) + (r.resolved ? "" : fmtActivityFreshness(r.ts_last_seen)) + "</td><td>" +
      cgMitigationBadgeHtml(r.mitigation, isGenuinelyActive(r.resolved, r.ts_last_seen)) + "</td>" +
      "<td>" + resolveBtn + edgeBtn + '<button class="fg-btn" data-action="detail">Detalhes</button></td></tr>'
    );
  }

  var CG_SUSPICIOUS_TABLE_HEAD =
    "<th>src_ip</th><th>Cliente</th><th>Sinal</th><th>Confiança</th><th>Detectado</th>" +
    "<th>Última vez</th><th>Mitigação</th><th>Ações</th>";

  function renderCgSuspiciousGrouped(rows) {
    var groups = {};
    var order = [];
    rows.forEach(function (r) {
      var key = r.customer_prefix || r.src_ip;
      if (!groups[key]) { groups[key] = []; order.push(key); }
      groups[key].push(r);
    });
    var colspan = (state.cgSuspiciousSelectMode ? 1 : 0) + 8;
    var body = order.map(function (key) {
      var items = groups[key].slice().sort(function (a, b) { return CG_SEV_RANK[signalSeverity(a)] - CG_SEV_RANK[signalSeverity(b)]; });
      var worst = signalSeverity(items[0]);
      var collapsed = state.cgSuspiciousCollapsedGroups[key];
      if (collapsed === undefined) collapsed = CG_SEV_RANK[worst] > 0;
      var rowsHtml = collapsed ? "" : items.map(cgSuspiciousRowHtml).join("");
      return (
        '<tr class="fg-group-head" data-group-key="' + escapeHtml(key) + '">' +
        '<td colspan="' + colspan + '" class="' + signalSevClass(worst) + '" style="cursor:pointer;">' +
        (collapsed ? "▸ " : "▾ ") + escapeHtml(key) + " — " + items.length +
        (items.length === 1 ? " sinal" : " sinais") + " · pior: " + worst +
        "</td></tr>" + rowsHtml
      );
    }).join("");
    return (
      "<table><thead><tr>" + (state.cgSuspiciousSelectMode ? "<th></th>" : "") + CG_SUSPICIOUS_TABLE_HEAD + "</tr></thead><tbody>" +
      body + "</tbody></table>"
    );
  }

  function refreshCgSuspiciousBulkBar() {
    var bar = document.getElementById("cg-suspicious-bulkbar");
    if (!bar) return;
    var n = Object.keys(state.cgSuspiciousSelected).length;
    bar.hidden = !state.cgSuspiciousSelectMode || n === 0;
    var countEl = document.getElementById("cg-suspicious-bulk-count");
    if (countEl) countEl.textContent = n + " selecionado(s)";
  }

  function renderCgSuspicious(rows) {
    var el = document.getElementById("cg-suspicious");
    if (!el) return;
    if (!rows.length) {
      var emptyMsg = state.filter.cgSuspicious
        ? "Nenhum sinal encontrado para o filtro atual."
        : "Nenhum sinal " + (state.cgSuspiciousView === "open" ? "aberto" : "resolvido") + ".";
      el.innerHTML = '<p class="fg-ok">' + emptyMsg + "</p>";
      refreshCgSuspiciousBulkBar();
      return;
    }
    if (state.cgSuspiciousGroupBy) {
      el.innerHTML = renderCgSuspiciousGrouped(rows);
      refreshCgSuspiciousBulkBar();
      return;
    }
    var body = rows.map(cgSuspiciousRowHtml).join("");
    el.innerHTML =
      "<table><thead><tr>" + (state.cgSuspiciousSelectMode ? "<th></th>" : "") + CG_SUSPICIOUS_TABLE_HEAD + "</tr></thead><tbody>" +
      body + "</tbody></table>";
    refreshCgSuspiciousBulkBar();
  }

  function loadClientGuardSuspicious() {
    var url = state.cgSuspiciousView === "history" ? CG_SUSPICIOUS_ENDPOINT + "?history=1" : CG_SUSPICIOUS_ENDPOINT;
    getJson(url).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("cg-suspicious"), data.error || "erro desconhecido");
        return;
      }
      state.cgSuspicious = data.suspicious;
      // contagem do badge é sobre o total não filtrado (a busca é só uma
      // lente sobre a mesma lista, não deve mudar quantos sinais existem)
      if (state.cgSuspiciousView === "open") updateCgBadge(data.suspicious.length);
      renderCgSuspiciousFiltered();
    }).catch(function (err) {
      showError(document.getElementById("cg-suspicious"), "falha ao consultar sinais suspeitos");
      console.error("flowguard.js:", err);
    });
  }

  function renderCgSuspiciousFiltered() {
    var rows = state.cgSuspicious;
    if (state.filter.cgSuspiciousSeverities.length) {
      rows = rows.filter(function (r) { return state.filter.cgSuspiciousSeverities.indexOf(signalSeverity(r)) !== -1; });
    }
    rows = filterRows(rows, state.filter.cgSuspicious, ["src_ip", "customer_prefix", "signal_type"]);
    renderCgSuspicious(rows);
  }

  // evidência formatada campo-a-campo (bps/ts/número/texto), em vez de um
  // "k=v, k=v" cru — mesma ideia do formatEvidenceValue() do poxflow v2
  function formatEvidenceField(key, value) {
    if (value == null) return "-";
    if (/bps$/i.test(key) && typeof value === "number") return fmtBps(value);
    if (/^ts_|_ts$|^ts$/i.test(key) && typeof value === "number") return fmtDateTime(value);
    if (typeof value === "number") return value.toLocaleString("pt-BR");
    return String(value);
  }

  function formatEvidenceHtml(rawEvidence) {
    var parsed = rawEvidence;
    try {
      parsed = typeof rawEvidence === "string" ? JSON.parse(rawEvidence) : rawEvidence;
    } catch (e) {
      return escapeHtml(String(rawEvidence));
    }
    if (!parsed || typeof parsed !== "object") return escapeHtml(String(rawEvidence));
    var keys = Object.keys(parsed);
    if (!keys.length) return "<em>sem evidência registrada</em>";
    return "<table>" + keys.map(function (k) {
      return "<tr><td>" + escapeHtml(k) + "</td><td>" + escapeHtml(formatEvidenceField(k, parsed[k])) + "</td></tr>";
    }).join("") + "</table>";
  }

  function buildSignalTimelineItems(row) {
    var items = [{ ts: row.ts_detected, icon: "🚨", label: "Detecção — " + (CG_SIGNAL_LABELS[row.signal_type] || row.signal_type) }];
    if (row.mitigation && row.mitigation.ts_applied) {
      var mech = CG_MITIGATION_MECHANISM_LABELS[row.mitigation.mechanism] || row.mitigation.mechanism || "-";
      items.push({ ts: row.mitigation.ts_applied, icon: "🛡", label: "Mitigação " + (row.mitigation.status === "active" ? "aplicada" : "registrada") + " (" + mech + ")" });
    }
    if (row.resolved) {
      items.push({ ts: row.ts_last_seen, icon: "✅", label: "Resolvido" });
    } else if (row.ts_last_seen) {
      items.push({ ts: row.ts_last_seen, icon: "🔎", label: "Última confirmação da condição" });
    }
    items.sort(function (x, y) { return (x.ts || 0) - (y.ts || 0); });
    return items;
  }

  function cgNoteKey(signalId) {
    return "fg_note_cg-" + signalId;
  }

  function doExportSignalDossier(row) {
    var note = window.localStorage.getItem(cgNoteKey(row.id)) || "";
    var lines = [
      "Dossiê de incidente — ClientGuard",
      "src_ip: " + row.src_ip + " · Cliente: " + (row.customer_prefix || "-"),
      "Sinal: " + (CG_SIGNAL_LABELS[row.signal_type] || row.signal_type) + " · Confiança: " + Math.round((row.confidence || 0) * 100) + "% (" + signalSeverity(row) + ")",
      "Detectado: " + fmtDateTime(row.ts_detected),
      "Última vez: " + fmtDateTime(row.ts_last_seen),
      "Status: " + (row.resolved ? "resolvido" : "aberto"),
      "",
      "Linha do tempo:",
    ];
    buildSignalTimelineItems(row).forEach(function (it) { lines.push("  " + fmtDateTime(it.ts) + " — " + it.label); });
    lines.push("");
    lines.push("Nota do operador:");
    lines.push(note || "(sem nota)");
    downloadTextFile("incidente-cg-" + row.id + ".txt", lines.join("\n"));
  }

  function renderCgSuspiciousDetail(row) {
    var el = document.getElementById("cg-suspicious-detail");
    if (!el) return;
    var aiHtml = row.ai_explanation
      ? "<h5>Explicação (IA)</h5><pre>" + escapeHtml(row.ai_explanation) + "</pre>"
      : '<p class="fg-kpi-sub">sem explicação de IA registrada para este sinal</p>';
    var noteKey = cgNoteKey(row.id);
    var savedNote = window.localStorage.getItem(noteKey) || "";
    el.innerHTML =
      '<div class="fg-ai-panel"><div class="fg-panel-header"><h4>Sinal #' + row.id + " — " + escapeHtml(row.src_ip) + "</h4>" +
      '<button class="fg-btn" data-action="close-detail">Fechar</button></div>' +
      '<p class="fg-kpi-sub">Tipo: ' + escapeHtml(CG_SIGNAL_LABELS[row.signal_type] || row.signal_type) +
      " · Confiança: " + Math.round((row.confidence || 0) * 100) + "% (" + signalSeverity(row) + ")</p>" +
      '<p class="fg-kpi-sub">Mitigação: ' + cgMitigationBadgeHtml(row.mitigation, isGenuinelyActive(row.resolved, row.ts_last_seen)) + "</p>" +
      "<h5>Linha do tempo do incidente</h5>" + timelineItemsToHtml(buildSignalTimelineItems(row)) +
      "<h5>Reincidência (7 dias)</h5>" +
      '<p class="fg-kpi-sub" id="cg-recidivism-line">calculando...</p>' +
      "<h5>Evidência</h5>" + formatEvidenceHtml(row.evidence) +
      aiHtml +
      "<h5>Nota do operador</h5>" +
      '<textarea id="cg-signal-note" rows="3" style="width:100%;" placeholder="nota interna, salva só neste navegador...">' + escapeHtml(savedNote) + "</textarea>" +
      '<div class="fg-toolbar" style="margin-top:0.4rem;"><button class="fg-btn" id="cg-signal-export-btn">Exportar dossiê (.txt)</button></div>' +
      "</div>";
    var noteEl = document.getElementById("cg-signal-note");
    if (noteEl) noteEl.addEventListener("input", function () { window.localStorage.setItem(noteKey, noteEl.value); });
    var exportBtn = document.getElementById("cg-signal-export-btn");
    if (exportBtn) exportBtn.addEventListener("click", function () { doExportSignalDossier(row); });
    el.scrollIntoView({ behavior: "smooth", block: "start" });

    // reincidência: sem endpoint dedicado, degrada pra contagem de
    // ocorrências do mesmo src_ip no histórico dos últimos 7 dias (ver
    // prompt de origem — fallback explicitamente aceito quando o backend
    // não recorta por IP/janela)
    getJson(CG_SUSPICIOUS_ENDPOINT + "?history=1").then(function (data) {
      var line = document.getElementById("cg-recidivism-line");
      if (!line) return;
      if (!data.ok) { line.textContent = "não foi possível calcular."; return; }
      var since = Math.floor(Date.now() / 1000) - 7 * 86400;
      var count = (data.suspicious || []).filter(function (r) { return r.src_ip === row.src_ip && r.ts_detected >= since; }).length;
      line.textContent = count + " ocorrência(s) deste IP nos últimos 7 dias.";
    }).catch(function () {
      var line = document.getElementById("cg-recidivism-line");
      if (line) line.textContent = "não foi possível calcular.";
    });
  }

  function onCgSuspiciousBulkResolveClick() {
    var ids = Object.keys(state.cgSuspiciousSelected);
    if (!ids.length) return;
    var preview = ids.slice(0, 8).join(", ") + (ids.length > 8 ? "…" : "");
    if (!window.confirm("Resolver " + ids.length + " sinal(is) selecionado(s)? IDs: " + preview)) return;
    var btn = document.getElementById("cg-suspicious-bulk-resolve-btn");
    btn.disabled = true;
    Promise.all(ids.map(function (id) {
      return postJson(CG_SUSPICIOUS_ENDPOINT, { id: Number(id) });
    })).then(function () {
      showToast(ids.length + " sinal(is) resolvido(s)", "success");
      state.cgSuspiciousSelected = {};
      state.cgSuspiciousSelectMode = false;
      var selectBtn = document.getElementById("cg-suspicious-select-btn");
      if (selectBtn) selectBtn.classList.remove("active");
      loadClientGuardSuspicious();
    }).catch(function () {
      showToast("falha ao resolver sinais em lote", "error");
    }).finally(function () { btn.disabled = false; });
  }

  function onCgSuspiciousClick(ev) {
    var groupHead = ev.target.closest("tr.fg-group-head");
    if (groupHead) {
      var key = groupHead.getAttribute("data-group-key");
      state.cgSuspiciousCollapsedGroups[key] = !state.cgSuspiciousCollapsedGroups[key];
      renderCgSuspiciousFiltered();
      return;
    }

    var checkbox = ev.target.closest("input.fg-cg-select");
    if (checkbox) {
      var selRow = checkbox.closest("tr[data-signal-id]");
      var selId = Number(selRow.getAttribute("data-signal-id"));
      if (checkbox.checked) state.cgSuspiciousSelected[selId] = true;
      else delete state.cgSuspiciousSelected[selId];
      refreshCgSuspiciousBulkBar();
      return;
    }

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

    if (action === "edge-apply") {
      var srcIp = row.getAttribute("data-src-ip");
      if (!window.confirm("Bloquear " + srcIp + " direto na borda via SSH/ACL?")) return;
      btn.disabled = true;
      postJson(CG_EDGE_ENDPOINT, { ip: srcIp, signal_id: signalId })
        .then(function (resp) {
          showToast(resp.ok
            ? (resp.already_active ? srcIp + " já tinha mitigação ativa (TTL renovado)" : srcIp + " bloqueado na borda")
            : (resp.error || "falha ao aplicar mitigação"), resp.ok ? "success" : "error");
          loadRulesUnified();
        })
        .finally(function () { btn.disabled = false; });
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
    if (toggle) {
      toggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        state.cgSuspiciousView = btn.getAttribute("data-view");
        toggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
        loadClientGuardSuspicious();
      });
    }
    var sevChips = document.getElementById("cg-suspicious-severity-chips");
    if (sevChips) {
      sevChips.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        var sev = btn.getAttribute("data-sev");
        var idx = state.filter.cgSuspiciousSeverities.indexOf(sev);
        if (idx === -1) { state.filter.cgSuspiciousSeverities.push(sev); btn.classList.add("active"); }
        else { state.filter.cgSuspiciousSeverities.splice(idx, 1); btn.classList.remove("active"); }
        renderCgSuspiciousFiltered();
      });
    }
    var search = document.getElementById("cg-suspicious-search");
    if (search) {
      search.addEventListener("input", function () {
        state.filter.cgSuspicious = search.value.trim();
        renderCgSuspiciousFiltered();
      });
    }
    var groupBtn = document.getElementById("cg-suspicious-group-btn");
    if (groupBtn) {
      groupBtn.addEventListener("click", function () {
        state.cgSuspiciousGroupBy = !state.cgSuspiciousGroupBy;
        groupBtn.classList.toggle("active", state.cgSuspiciousGroupBy);
        renderCgSuspiciousFiltered();
      });
    }
    var selectBtn = document.getElementById("cg-suspicious-select-btn");
    if (selectBtn) {
      selectBtn.addEventListener("click", function () {
        state.cgSuspiciousSelectMode = !state.cgSuspiciousSelectMode;
        selectBtn.classList.toggle("active", state.cgSuspiciousSelectMode);
        if (!state.cgSuspiciousSelectMode) state.cgSuspiciousSelected = {};
        renderCgSuspiciousFiltered();
      });
    }
    var bulkResolveBtn = document.getElementById("cg-suspicious-bulk-resolve-btn");
    if (bulkResolveBtn) bulkResolveBtn.addEventListener("click", onCgSuspiciousBulkResolveClick);
  }

  // --- ClientGuard: ajuste fino dos limiares de detecção --------------------

  function renderCgDetectionCfg(detection) {
    var el = document.getElementById("cg-detection-cfg");
    if (!el) return;
    state.cgDetectionCfg = detection || {};
    el.innerHTML = CG_DETECTION_CFG_FIELDS.map(function (f) {
      var val = state.cgDetectionCfg[f.key];
      var inputVal = f.type === "ports"
        ? (Array.isArray(val) ? val.join(", ") : "")
        : (val != null ? val : "");
      return (
        '<div style="margin-bottom:0.7rem;">' +
        '<label style="display:block; font-weight:600; margin-bottom:0.15rem;">' + escapeHtml(f.label) + "</label>" +
        '<p class="fg-kpi-sub" style="margin:0 0 0.3rem;">' + escapeHtml(f.desc) + "</p>" +
        '<input type="text" data-detection-key="' + f.key + '" data-detection-type="' + f.type +
        '" value="' + escapeHtml(String(inputVal)) + '">' +
        "</div>"
      );
    }).join("");
  }

  // só manda ao backend as chaves que REALMENTE mudaram em relação ao valor
  // carregado (state.cgDetectionCfg) — mandar o formulário inteiro a cada save
  // materializaria TODO detection.* dentro de detection_overrides.yaml, e a
  // partir daí uma mudança futura direto em config.yaml nunca mais teria efeito
  // (override sempre venceria, mesmo em campos que o operador nunca quis fixar).
  function onCgDetectionCfgSaveClick() {
    var el = document.getElementById("cg-detection-cfg");
    var btn = document.getElementById("cg-detection-cfg-save-btn");
    if (!el || !btn) return;
    var changes = {};
    var invalid = false;
    el.querySelectorAll("[data-detection-key]").forEach(function (input) {
      var key = input.getAttribute("data-detection-key");
      var type = input.getAttribute("data-detection-type");
      var raw = input.value.trim();
      var original = state.cgDetectionCfg[key];
      if (type === "ports") {
        var nums = raw ? raw.split(",").map(function (s) { return Number(s.trim()); }) : [];
        if (nums.some(function (n) { return !Number.isInteger(n) || n < 0; })) { invalid = true; return; }
        var originalArr = Array.isArray(original) ? original : [];
        var changed = nums.length !== originalArr.length || nums.some(function (n, i) { return n !== originalArr[i]; });
        if (changed) changes[key] = nums;
      } else {
        var n = Number(raw);
        if (!raw || !Number.isFinite(n) || n <= 0) { invalid = true; return; }
        var rounded = Math.round(n);
        if (rounded !== original) changes[key] = rounded;
      }
    });
    if (invalid) {
      showToast("Valores inválidos — confira os campos numéricos e as listas de porta", "error");
      return;
    }
    if (!Object.keys(changes).length) {
      showToast("Nenhum limiar foi alterado");
      return;
    }
    btn.disabled = true;
    postJson(CG_CFG_ENDPOINT, { cmd: "detection_cfg_set", changes: changes })
      .then(function (resp) {
        showToast(resp.ok ? "Limiares atualizados" : resp.error, resp.ok ? "success" : "error");
        if (resp.ok) renderCgDetectionCfg(resp.detection);
      })
      .finally(function () { btn.disabled = false; });
  }

  // --- ClientGuard: templates de detecção (perfis reutilizáveis por rede) --

  function populateCgTemplateSelects() {
    var names = Object.keys(state.cgDetectionTemplates || {});
    var optionsHtml = '<option value="">sem template</option>' +
      names.map(function (n) { return '<option value="' + escapeHtml(n) + '">' + escapeHtml(n) + "</option>"; }).join("");
    document.querySelectorAll(".cg-template-select").forEach(function (sel) {
      var current = sel.value;
      sel.innerHTML = optionsHtml;
      if (names.indexOf(current) !== -1) sel.value = current;
    });
  }

  function renderCgDetectionTemplates(templates) {
    var el = document.getElementById("cg-detection-templates");
    if (!el) return;
    state.cgDetectionTemplates = templates || {};
    populateCgTemplateSelects();
    var names = Object.keys(state.cgDetectionTemplates);
    if (!names.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum template cadastrado — toda rede usa o limiar global.</p>';
      return;
    }
    var rows = names.map(function (name) {
      var t = state.cgDetectionTemplates[name];
      return (
        '<tr data-template-name="' + escapeHtml(name) + '"><td>' + escapeHtml(name) + "</td><td>" +
        (t.scan_horizontal_hosts != null ? t.scan_horizontal_hosts : "-") + "</td><td>" +
        (t.scan_vertical_ports != null ? t.scan_vertical_ports : "-") + "</td><td>" +
        escapeHtml(t.description || "-") + "</td>" +
        '<td><button class="fg-btn" data-action="edit-template">Editar</button> ' +
        '<button class="fg-btn fg-btn-danger" data-action="del-template">Remover</button></td></tr>'
      );
    }).join("");
    el.innerHTML =
      "<table><thead><tr><th>Nome</th><th>Hosts (horizontal)</th><th>Portas (vertical)</th><th>Descrição</th><th></th></tr></thead><tbody>" +
      rows + "</tbody></table>";
  }

  function onCgDetectionTemplateEditClick(name) {
    var t = (state.cgDetectionTemplates || {})[name];
    var form = document.getElementById("cg-detection-template-form");
    if (!t || !form) return;
    form.name.value = name;
    form.scan_horizontal_hosts.value = t.scan_horizontal_hosts != null ? t.scan_horizontal_hosts : "";
    form.scan_vertical_ports.value = t.scan_vertical_ports != null ? t.scan_vertical_ports : "";
    form.description.value = t.description || "";
    form.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  // --- ClientGuard: redes de clientes + whitelist --------------------------

  function renderCgCustomers(customers) {
    var el = document.getElementById("cg-customers");
    if (!el) return;
    if (!customers.length) {
      el.innerHTML = '<p class="fg-ok">Nenhuma rede cadastrada.</p>';
      return;
    }
    var templateNames = Object.keys(state.cgDetectionTemplates || {});
    var rows = customers
      .map(function (c) {
        var options = '<option value="">sem template</option>' +
          templateNames.map(function (n) {
            return '<option value="' + escapeHtml(n) + '"' + (c.template === n ? " selected" : "") + ">" + escapeHtml(n) + "</option>";
          }).join("");
        return (
          '<tr data-network="' + escapeHtml(c.network) + '"><td>' + escapeHtml(c.network) + "</td><td>" +
          escapeHtml(c.prefix) + "</td><td>" + escapeHtml(c.name || "-") + "</td>" +
          '<td><select class="cg-template-select">' + options + "</select></td>" +
          '<td><input type="number" min="1" class="cg-multiplier-input" style="width:5rem;" ' +
          'value="' + (c.client_multiplier || "") + '" placeholder="1"></td>' +
          '<td><button class="fg-btn" data-action="save-customer">Salvar</button> ' +
          '<button class="fg-btn fg-btn-danger" data-action="del-customer">Remover</button></td></tr>'
        );
      })
      .join("");
    el.innerHTML =
      "<table><thead><tr><th>Rede</th><th>Rótulo</th><th>Nome</th><th>Template</th><th>Multiplicador</th><th></th></tr></thead><tbody>" +
      rows + "</tbody></table>";
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
      // templates ANTES de customers — a tabela de redes usa os nomes de template
      // já carregados pra montar o <select> de cada linha.
      renderCgDetectionTemplates(data.detection_templates);
      renderCgCustomers(data.customers);
      renderCgWhitelist(data.whitelist);
      renderCgDetectionCfg(data.detection);
      state.cgCustomers = data.customers || [];
      appendCgNetworksToChartSelect();
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
    } else if (action === "save-customer") {
      var row3 = btn.closest("tr[data-network]");
      if (!row3) return;
      var select = row3.querySelector(".cg-template-select");
      var multInput = row3.querySelector(".cg-multiplier-input");
      postJson(CG_CFG_ENDPOINT, {
        cmd: "customers_edit", network: row3.getAttribute("data-network"),
        template: select ? select.value : "", client_multiplier: multInput ? multInput.value.trim() : "",
      }).then(function (resp) {
        showToast(resp.ok ? "Rede atualizada" : resp.error, resp.ok ? "success" : "error");
        loadClientGuardCfg();
      });
    } else if (action === "edit-template") {
      var row4 = btn.closest("tr[data-template-name]");
      if (!row4) return;
      onCgDetectionTemplateEditClick(row4.getAttribute("data-template-name"));
    } else if (action === "del-template") {
      var row5 = btn.closest("tr[data-template-name]");
      if (!row5) return;
      var name = row5.getAttribute("data-template-name");
      if (!window.confirm("Remover o template '" + name + "'? Redes que usam esse template voltam pro limiar global.")) return;
      postJson(CG_CFG_ENDPOINT, { cmd: "detection_templates_del", name: name }).then(function (resp) {
        showToast(resp.ok ? "Template removido" : resp.error, resp.ok ? "success" : "error");
        loadClientGuardCfg();
      });
    }
  }

  function onCgCfgSubmit(ev) {
    var form = ev.target;
    if (form.id === "cg-customers-form") {
      ev.preventDefault();
      postJson(CG_CFG_ENDPOINT, {
        cmd: "customers_add", network: form.network.value.trim(), prefix: form.prefix.value.trim(), name: form.name.value.trim(),
        template: form.template.value, client_multiplier: form.client_multiplier.value.trim(),
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
    } else if (form.id === "cg-detection-template-form") {
      ev.preventDefault();
      postJson(CG_CFG_ENDPOINT, {
        cmd: "detection_templates_set", name: form.name.value.trim(),
        values: {
          scan_horizontal_hosts: Number(form.scan_horizontal_hosts.value),
          scan_vertical_ports: Number(form.scan_vertical_ports.value),
        },
        description: form.description.value.trim(),
      }).then(function (resp) {
        showToast(resp.ok ? "Template salvo" : resp.error, resp.ok ? "success" : "error");
        if (resp.ok) { form.reset(); loadClientGuardCfg(); }
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

  // --- ClientGuard: mitigação automática por detector (BGP FlowSpec) --------
  // painel reaproveita os IDs antigos (cg-edge-auto/cg-edge-default-ttl/
  // cg-edge-auto-apply-btn) — o gatilho automático inteiro migrou de SSH/ACL
  // pra FlowSpec (flowspec_mitigation.py). A lista de mitigações (ativas +
  // histórico, SSH legado e FlowSpec juntos) vive só na aba Regras →
  // ClientGuard (renderRulesCgEdgeTable) — ver nota mais abaixo.

  var CG_FLOWSPEC_ACTION_LABELS = { discard: "Descartar (só o destino/porta identificado)", rate_limit: "Limitar banda (dinâmico)", "off": "Desligado" };

  function renderCgEdgeAuto(autoMitigate) {
    var el = document.getElementById("cg-edge-auto");
    if (!el) return;
    el.innerHTML = Object.keys(CG_SIGNAL_LABELS).map(function (key) {
      var action = autoMitigate[key] || "off";
      var id = "cg-edge-auto-" + key;
      var options = Object.keys(CG_FLOWSPEC_ACTION_LABELS).map(function (opt) {
        return '<option value="' + opt + '"' + (opt === action ? " selected" : "") + ">" +
          escapeHtml(CG_FLOWSPEC_ACTION_LABELS[opt]) + "</option>";
      }).join("");
      return (
        '<div class="fg-toggle-item' + (action === "off" ? " disabled" : "") + '" data-key="' + key + '">' +
        '<label for="' + id + '"><div class="fg-toggle-name">' + escapeHtml(CG_SIGNAL_LABELS[key]) + "</div>" +
        '<div class="fg-toggle-desc">ação automática via FlowSpec a cada sinal novo desse tipo</div></label>' +
        '<select id="' + id + '" class="fg-toggle-select">' + options + "</select></div>"
      );
    }).join("");
  }

  function loadCgEdgeAuto() {
    if (!getToken()) return;
    getJson(CG_FLOWSPEC_CFG_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("cg-edge-auto"), data.error || "erro desconhecido");
        return;
      }
      state.cgEdgeAutoLoaded = data.config.auto_mitigate || {};
      state.cgEdgeAutoPending = {};
      updateTogglesApplyBtn("cg-edge-auto-apply-btn", 0);
      renderCgEdgeAuto(state.cgEdgeAutoLoaded);
      var ttlSelect = document.getElementById("cg-edge-default-ttl");
      if (ttlSelect && data.config.default_ttl_s) ttlSelect.value = String(data.config.default_ttl_s);
    }).catch(function (err) {
      showError(document.getElementById("cg-edge-auto"), "falha ao consultar configuração de mitigação automática");
      console.error("flowguard.js:", err);
    });
  }

  function onCgEdgeAutoChange(ev) {
    var select = ev.target.closest("select.fg-toggle-select");
    if (!select) return;
    var item = select.closest(".fg-toggle-item[data-key]");
    if (!item) return;
    var key = item.getAttribute("data-key");
    var value = select.value;
    item.classList.toggle("disabled", value === "off");
    var original = state.cgEdgeAutoLoaded[key] || "off";
    if (value === original) {
      delete state.cgEdgeAutoPending[key];
    } else {
      state.cgEdgeAutoPending[key] = value;
    }
    updateTogglesApplyBtn("cg-edge-auto-apply-btn", Object.keys(state.cgEdgeAutoPending).length);
  }

  function onCgEdgeAutoApplyClick() {
    var pending = state.cgEdgeAutoPending;
    if (!Object.keys(pending).length) return;
    var btn = document.getElementById("cg-edge-auto-apply-btn");
    btn.disabled = true;
    var ttlSelect = document.getElementById("cg-edge-default-ttl");
    postJson(CG_FLOWSPEC_CFG_ENDPOINT, { auto_mitigate: pending, default_ttl_s: Number(ttlSelect.value) })
      .then(function (resp) {
        showToast(resp.ok ? "Configurações aplicadas" : (resp.error || "falha ao aplicar configurações"),
                  resp.ok ? "success" : "error");
        loadCgEdgeAuto();
      })
      .catch(function (err) {
        showToast("falha ao aplicar configurações", "error");
        console.error("flowguard.js:", err);
        btn.disabled = false;
      });
  }

  // --- bloqueio progressivo por reincidência (comum aos 7 detectores) -------

  var CG_ESCALATION_CFG_FIELDS = [
    { key: "enabled", label: "Escalonamento ativo", type: "bool", desc: "Desligado: toda mitigação usa a duração fixa de Mitigação FlowSpec (default_ttl_s)." },
    { key: "tracking_window_s", label: "Janela de reincidência (s)", type: "number", desc: "Mitigações do MESMO cliente dentro dessa janela contam como reincidência." },
    { key: "base_ttl_s", label: "Duração base (s) — vazio usa default_ttl_s", type: "number", nullable: true, desc: "Duração da 1ª ofensa. Deixe vazio pra usar o TTL padrão de Mitigação FlowSpec." },
    { key: "factor", label: "Fator de multiplicação", type: "number", float: true, desc: "Cada reincidência multiplica a duração da mitigação por isso." },
    { key: "max_ttl_s", label: "Duração máxima (s)", type: "number", desc: "Teto — a duração nunca ultrapassa isso, não importa quantas reincidências." },
    { key: "max_steps", label: "Reincidências até o teto", type: "number", desc: "Depois de N reincidências dentro da janela, trava na duração máxima." },
  ];

  function renderKvFields(containerId, fields, values) {
    var el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = fields.map(function (f) {
      if (f.type === "bool") {
        var checked = values[f.key] ? "checked" : "";
        return (
          '<div class="fg-toggle-item" style="margin-bottom:0.6rem;">' +
          '<label><input type="checkbox" data-kv-key="' + f.key + '" data-kv-type="bool" ' + checked + "> " +
          escapeHtml(f.label) + "</label>" +
          '<p class="fg-kpi-sub" style="margin:0.15rem 0 0;">' + escapeHtml(f.desc) + "</p></div>"
        );
      }
      var val = values[f.key];
      var inputVal = val != null ? val : "";
      return (
        '<div style="margin-bottom:0.7rem;">' +
        '<label style="display:block; font-weight:600; margin-bottom:0.15rem;">' + escapeHtml(f.label) + "</label>" +
        '<p class="fg-kpi-sub" style="margin:0 0 0.3rem;">' + escapeHtml(f.desc) + "</p>" +
        '<input type="text" data-kv-key="' + f.key + '" data-kv-type="number" value="' + escapeHtml(String(inputVal)) + '"></div>'
      );
    }).join("");
  }

  function collectKvChanges(containerId, fields, original) {
    var el = document.getElementById(containerId);
    var result = { changes: {}, invalid: false };
    if (!el) return result;
    el.querySelectorAll("[data-kv-key]").forEach(function (input) {
      var key = input.getAttribute("data-kv-key");
      var type = input.getAttribute("data-kv-type");
      var meta = fields.filter(function (f) { return f.key === key; })[0] || {};
      if (type === "bool") {
        if (input.checked !== !!original[key]) result.changes[key] = input.checked;
        return;
      }
      var raw = input.value.trim();
      if (meta.nullable && raw === "") {
        if (original[key] != null) result.changes[key] = null;
        return;
      }
      var n = Number(raw);
      if (!raw || !Number.isFinite(n) || n <= 0) { result.invalid = true; return; }
      if (!meta.float) n = Math.round(n);
      if (n !== original[key]) result.changes[key] = n;
    });
    return result;
  }

  function renderCgEscalationCfg(cfg) {
    state.cgEscalationLoaded = cfg || {};
    renderKvFields("cg-escalation-cfg", CG_ESCALATION_CFG_FIELDS, state.cgEscalationLoaded);
  }

  function loadCgEscalationCfg() {
    if (!getToken()) return;
    getJson(CG_ESCALATION_CFG_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("cg-escalation-cfg"), data.error || "erro desconhecido");
        return;
      }
      renderCgEscalationCfg(data.escalation);
    }).catch(function (err) {
      showError(document.getElementById("cg-escalation-cfg"), "falha ao consultar bloqueio progressivo");
      console.error("flowguard.js:", err);
    });
  }

  function onCgEscalationSaveClick() {
    var btn = document.getElementById("cg-escalation-save-btn");
    var result = collectKvChanges("cg-escalation-cfg", CG_ESCALATION_CFG_FIELDS, state.cgEscalationLoaded || {});
    if (result.invalid) {
      showToast("Valores inválidos — confira os campos numéricos", "error");
      return;
    }
    if (!Object.keys(result.changes).length) {
      showToast("Nenhum campo foi alterado");
      return;
    }
    btn.disabled = true;
    postJson(CG_ESCALATION_CFG_ENDPOINT, { changes: result.changes })
      .then(function (resp) {
        showToast(resp.ok ? "Bloqueio progressivo atualizado" : (resp.error || "falha ao salvar"), resp.ok ? "success" : "error");
        if (resp.ok) renderCgEscalationCfg(resp.escalation);
      })
      .finally(function () { btn.disabled = false; });
  }

  // a lista completa (ativas + histórico) desse mesmo dado já vive na aba
  // Regras → ClientGuard (renderRulesCgEdgeTable/rules-cg-edge-list, com
  // toggle Ativas/Histórico e paginação) — não duplicar aqui

  // Botão único agora (só existe na aba Regras — a cópia da aba ClientGuard
  // foi removida junto com a lista duplicada, ver nota acima).
  function onRulesCgEdgeRevertAllClick() {
    var btn = document.getElementById("rules-cg-edge-revert-all-btn");
    if (!window.confirm(
      "Reverter TODAS as mitigações ativas do ClientGuard (FlowSpec + SSH legado)? " +
      "Isso libera imediatamente todos os clientes atualmente bloqueados/limitados e não pode ser desfeito.",
    )) {
      return;
    }
    btn.disabled = true;
    postJson(CG_EDGE_ENDPOINT, { revert_all: true })
      .then(function (resp) {
        if (resp.ok) {
          showToast(resp.reverted + " mitigação(ões) revertida(s)" + (resp.failed ? ", " + resp.failed + " falharam" : ""), "success");
        } else {
          showToast(resp.error || "falha ao reverter mitigações", "error");
        }
        loadClientGuardStatus();
        loadRulesUnified();
      })
      .catch(function (err) {
        showToast("falha ao reverter mitigações", "error");
        console.error("flowguard.js:", err);
      })
      .finally(function () { btn.disabled = false; });
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
    loadCgToggles();
    loadCgEdgeAuto();
    loadCgEscalationCfg();
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

  function drawLineChartCore(s, series, lines, band, hoverIndex, attacksOverlay) {
    var ctx = s.ctx;
    var plotW = s.w - s.padding.left - s.padding.right;
    var plotH = s.h - s.padding.top - s.padding.bottom;
    var sinceTs = series[0].ts;
    var nowTs = series[series.length - 1].ts;

    function tsToX(ts) {
      var span = nowTs - sinceTs || 1;
      var frac = Math.max(0, Math.min(1, (ts - sinceTs) / span));
      return s.padding.left + frac * plotW;
    }

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

    // faixas de anomalia por severidade (estilo WANGuard) — atrás de tudo,
    // um retângulo translúcido por ataque cobrindo [ts_start, ts_end||agora];
    // ataques sobrepostos escurecem naturalmente por empilhar alpha
    if (attacksOverlay && attacksOverlay.length) {
      attacksOverlay.forEach(function (a) {
        var startTs = Math.max(a.ts_start, sinceTs);
        var endTs = Math.min(a.ts_end || nowTs, nowTs);
        if (endTs < startTs) return;
        var x1 = tsToX(startTs);
        var x2 = tsToX(endTs);
        ctx.globalAlpha = 0.14;
        ctx.fillStyle = SEV_COLORS[a.severity] || "#8b949e";
        ctx.fillRect(x1, s.padding.top, Math.max(x2 - x1, 2), plotH);
        ctx.globalAlpha = 1;
      });
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

    // marcadores de evento (início de cada incidente) — linha tracejada +
    // círculo no topo, estilo TimeChart do poxflow v2; hitboxes devolvidas
    // pra drawLineChart() priorizar no hover/click sobre o crosshair normal
    var eventHitboxes = [];
    if (attacksOverlay && attacksOverlay.length) {
      attacksOverlay.forEach(function (a) {
        if (a.ts_start < sinceTs || a.ts_start > nowTs) return;
        var ex = tsToX(a.ts_start);
        var color = SEV_COLORS[a.severity] || "#8b949e";
        ctx.strokeStyle = color;
        ctx.lineWidth = 1;
        ctx.setLineDash([2, 3]);
        ctx.beginPath();
        ctx.moveTo(ex, s.padding.top);
        ctx.lineTo(ex, s.padding.top + plotH);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(ex, s.padding.top, 4, 0, Math.PI * 2);
        ctx.fill();
        eventHitboxes.push({ x: ex, attack: a });
      });
    }

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

    drawTimeAxis(s, sinceTs, nowTs);
    return eventHitboxes;
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

  function drawLineChart(canvas, series, lines, band, attacksOverlay) {
    if (!series || series.length < 2) {
      drawEmpty(canvas, "Sem dados suficientes na janela selecionada.");
      return;
    }
    var eventHitboxes = [];
    function render(hoverIndex) {
      eventHitboxes = drawLineChartCore(chartScale(canvas), series, lines, band, hoverIndex, attacksOverlay) || [];
    }
    render(null);
    registerChartHover(canvas, {
      hitTest: function (mouseX, mouseY) {
        // marcador de evento (início de ataque) tem prioridade se o mouse
        // estiver perto o bastante dele, perto do topo do gráfico
        for (var i = 0; i < eventHitboxes.length; i++) {
          var eh = eventHitboxes[i];
          if (Math.abs(mouseX - eh.x) <= 6 && mouseY <= 26) {
            var a = eh.attack;
            var dur = a.ts_end ? fmtUptime(a.ts_end - a.ts_start) : "em andamento";
            var html =
              '<div class="fg-tt-title">' + escapeHtml(a.dst_prefix || "-") + (a.customer ? " — " + escapeHtml(a.customer) : "") + "</div>" +
              '<div class="fg-tt-row"><span>tipo</span><span>' + escapeHtml(a.attack_type || "-") + "</span></div>" +
              '<div class="fg-tt-row"><span>severidade</span><span>' + escapeHtml(a.severity || "-") + "</span></div>" +
              '<div class="fg-tt-row"><span>início</span><span>' + fmtDateTime(a.ts_start) + "</span></div>" +
              '<div class="fg-tt-row"><span>duração</span><span>' + dur + "</span></div>" +
              '<div class="fg-tt-row"><span style="color:#8b949e">clique para ver detalhes →</span></div>';
            return { index: null, pointer: true, tooltip: html, onClick: function () { jumpToAttack(a); } };
          }
        }
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
    setIncidentsApp("flowguard");
    expandPanelSectionsIn(document.querySelector('.fg-tab-panel[data-tab="attacks"]'));
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
    appendCgNetworksToChartSelect();
  }

  // redes do ClientGuard (ex: CGNAT) somadas ao MESMO seletor de barramento
  // da aba Gráficos — chamada tanto de populateChartPrefixSelect() quanto de
  // loadClientGuardCfg(), porque as duas listas carregam em paralelo e não dá
  // pra saber qual chega primeiro; só efetiva quando as duas já existem, pra
  // não ser sobrescrita pelo innerHTML de populateChartPrefixSelect() nem
  // tentar anexar antes da lista de customers existir.
  function appendCgNetworksToChartSelect() {
    var select = document.getElementById("fg-chart-prefix");
    if (!select || !state.chart.prefixesLoaded || state.chart.cgNetworksAppended) return;
    if (!state.cgCustomers.length) return;
    var options = state.cgCustomers.map(function (c) {
      var value = "cg:" + c.prefix;
      var label = c.name ? c.name + " (" + c.prefix + ")" : c.prefix;
      return '<option value="' + escapeHtml(value) + '">' + escapeHtml(label) + "</option>";
    }).join("");
    var group = document.createElement("optgroup");
    group.label = "ClientGuard — redes de clientes";
    group.innerHTML = options;
    select.appendChild(group);
    state.chart.cgNetworksAppended = true;
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

  var CHART_WINDOW_SECONDS = { "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800 };

  // rede do ClientGuard (ex: CGNAT) selecionada no mesmo dropdown do FlowGuard
  // — só tráfego agregado (client_flow_aggs não separa in/out nem protocolo
  // por bucket, e não existe conceito de "ataque"/Gantt do lado ClientGuard),
  // então os painéis de protocolo e linha do tempo de ataques ficam com aviso
  // de "não aplicável" nesse modo; Top hosts é substituído pelos top clientes
  // da própria rede, reaproveitando o endpoint que a aba Clientes já usa.
  function loadCgNetworkChart(customerPrefix, windowName, requestToken) {
    var trafficTitle = document.getElementById("fg-chart-traffic-title");
    if (trafficTitle) trafficTitle.textContent = "Tráfego agregado da rede (ClientGuard)";
    var hostsTitle = document.getElementById("fg-chart-hosts-title");
    if (hostsTitle) hostsTitle.textContent = "Top clientes da rede (quem está consumindo mais)";

    // trava defensiva: mesmo que algo chame com windowName=24h/7d (ex: estado
    // salvo antes desta mudança), nunca manda pro backend uma janela que a
    // gente sabe que não termina nesse banco sem índice dedicado.
    var windowSeconds = Math.min(CHART_WINDOW_SECONDS[windowName] || 21600, CHART_WINDOW_SECONDS["6h"]);

    getJson(CG_NETWORK_SERIES_ENDPOINT + "?customer_prefix=" + encodeURIComponent(customerPrefix) + "&window_s=" + windowSeconds)
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
        var series = data.timeseries || [];
        drawLineChart(canvas, series, [{ key: "bps", color: "#58a6ff", label: "tráfego agregado" }]);
        if (legendEl) renderChartLegend(legendEl, [{ color: "#58a6ff", label: "tráfego agregado (sem separação in/out)" }]);
        if (summaryEl) {
          var stats = computePeakAvg(series, "bps");
          renderChartSummary(summaryEl, [{ prefix: customerPrefix, customer: "", peakBps: stats.peak, avgBps: stats.avg, capacityMbps: 0 }]);
        }
      })
      .catch(function (err) {
        if (state.chart._requestSeq !== requestToken) return;
        var canvas = document.getElementById("fg-chart-traffic");
        if (canvas) drawEmpty(canvas, "falha ao consultar série da rede");
        console.error("flowguard.js:", err);
      });

    ["fg-chart-protocol", "fg-chart-timeline"].forEach(function (id) {
      var c = document.getElementById(id);
      if (c) {
        state.chart._resolved[id] = true;
        drawEmpty(c, "não aplicável a redes do ClientGuard");
      }
    });

    getJson(CG_TOP_ENDPOINT + "?window_s=" + windowSeconds + "&limit=200").then(function (data) {
      if (state.chart._requestSeq !== requestToken) return;
      state.chart._resolved["flowguard-top-hosts"] = true;
      var el = document.getElementById("flowguard-top-hosts");
      if (!el) return;
      if (!data.ok) { showError(el, data.error || "erro ao carregar"); return; }
      var rows = (data.top || []).filter(function (r) { return r.customer_prefix === customerPrefix; });
      renderCgNetworkTopClients(el, rows);
    }).catch(function (err) {
      if (state.chart._requestSeq !== requestToken) return;
      var el = document.getElementById("flowguard-top-hosts");
      if (el) showError(el, "falha ao consultar top clientes da rede");
      console.error("flowguard.js:", err);
    });
  }

  function renderCgNetworkTopClients(el, rows) {
    if (!rows.length) {
      el.innerHTML = '<p class="fg-ok">Nenhum cliente com tráfego nessa rede na janela selecionada.</p>';
      return;
    }
    rows = rows.slice().sort(function (a, b) { return (b.bytes || 0) - (a.bytes || 0); }).slice(0, 20);
    var max = rows.reduce(function (m, r) { return Math.max(m, r.bytes || 0); }, 1);
    var body = rows.map(function (r) {
      var pct = Math.max(2, Math.round(((r.bytes || 0) / max) * 100));
      return "<tr><td>" + escapeHtml(r.src_ip) + "</td><td>" +
        '<div class="fg-hbar-wrap"><div class="fg-hbar" style="width:' + pct + '%"></div>' +
        '<span class="fg-hbar-label">' + fmtBytes(r.bytes || 0) + "</span></div>" +
        "</td></tr>";
    }).join("");
    el.innerHTML =
      "<table><thead><tr><th>Cliente (src_ip)</th><th>Tráfego na janela</th></tr></thead><tbody>" + body + "</tbody></table>";
  }

  function loadCharts() {
    if (!state.chart.prefix) return;
    updateChartWindowAvailability();
    var windowName = state.chart.window;
    var requestToken = ++state.chart._requestSeq;
    state.chart._resolved = {};
    chartLoadingPlaceholders(requestToken);

    if (state.chart.prefix.indexOf("cg:") === 0) {
      loadCgNetworkChart(state.chart.prefix.slice(3), windowName, requestToken);
      return;
    }

    var isAll = state.chart.prefix === "__all__";

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

    var prefixParam = isAll ? "" : "&prefix=" + encodeURIComponent(state.chart.prefix);
    // buscada 1x, reaproveitada tanto pro overlay de eventos/faixas do
    // gráfico de tráfego principal quanto pelo Gantt de severidade abaixo —
    // evita disparar a mesma query metric=attacks duas vezes por load
    var attacksPromise = getJson(HISTORY_ENDPOINT + "?metric=attacks&window=" + windowName + prefixParam);
    var trafficPromise = getJson(HISTORY_ENDPOINT + "?metric=prefix&prefix=" + encodeURIComponent(state.chart.prefix) + "&window=" + windowName);

    Promise.all([trafficPromise, attacksPromise])
      .then(function (results) {
        var data = results[0];
        var attacksData = results[1];
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
          var attacksOverlay = attacksData && attacksData.ok ? attacksData.attacks : [];
          if (attacksOverlay.length) {
            legendItems.push({ color: SEV_COLORS.critical, label: "faixas = incidentes por severidade" });
          }
          drawLineChart(canvas, series, chartLines, band, attacksOverlay);
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

    getJson(HISTORY_ENDPOINT + "?metric=protocol&window=" + windowName + prefixParam).then(function (data) {
      if (state.chart._requestSeq !== requestToken) return;
      state.chart._resolved["fg-chart-protocol"] = true;
      var canvas = document.getElementById("fg-chart-protocol");
      if (!canvas) return;
      if (!data.ok) { drawEmpty(canvas, data.error || "erro ao carregar"); return; }
      drawStackedArea(canvas, data.series, ["tcp", "udp", "icmp", "other"], ["#58a6ff", "#3fb950", "#d29922", "#8b949e"], ["TCP", "UDP", "ICMP", "Outro"]);
    });

    attacksPromise.then(function (data) {
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

  // redes do ClientGuard (client_flow_aggs, 280M+ linhas, sem índice dedicado
  // por customer_prefix — ver achado de 2026-07-08) só suportam janelas
  // curtas por enquanto: 24h já não termina em minutos sem esse índice, e
  // construir o índice numa tabela desse tamanho ao vivo trava as escritas
  // do daemon por um tempo não estimado. Enquanto isso não é resolvido à
  // parte, 24h/7d ficam desabilitadas nesse modo (volta pra 6h sozinho).
  function updateChartWindowAvailability() {
    var windowToggle = document.getElementById("fg-chart-window");
    if (!windowToggle) return;
    var isCg = (state.chart.prefix || "").indexOf("cg:") === 0;
    var longButtons = windowToggle.querySelectorAll('.fg-toggle-btn[data-window="24h"], .fg-toggle-btn[data-window="7d"]');
    longButtons.forEach(function (b) {
      b.disabled = isCg;
      b.title = isCg ? "Janelas longas ainda não são suportadas pra redes do ClientGuard (tabela grande demais sem índice dedicado)" : "";
    });
    if (isCg && (state.chart.window === "24h" || state.chart.window === "7d")) {
      state.chart.window = "6h";
      windowToggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-window") === "6h");
      });
    }
  }

  function initChartControls() {
    var select = document.getElementById("fg-chart-prefix");
    if (select) {
      select.addEventListener("change", function () {
        state.chart.prefix = select.value;
        updateChartWindowAvailability();
        loadCharts();
      });
    }
    var windowToggle = document.getElementById("fg-chart-window");
    if (windowToggle) {
      windowToggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn || btn.disabled) return;
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
      state.status = data; // reaproveitado pelo cockpit (bgp/daemon/active_attacks) sem fetch novo
      renderKpis(data);
      if (data.ok) {
        state.topPrefixes = data.top_prefixes;
        renderSparklines(data.protocol_series);
        renderTopPrefixesFiltered();
      } else {
        showError(document.getElementById("flowguard-top-prefixes"), data.error);
      }
      cockpitRefreshAll();
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
      cockpitRefreshAll();
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
      var autoMode = p.auto_mode || "off";
      var autoOptions = MITIGATION_AUTO_MODE_KEYS.map(function (k) {
        return '<option value="' + k + '"' + (k === autoMode ? " selected" : "") + '>' + MITIGATION_AUTO_MODE_LABELS[k] + "</option>";
      }).join("");
      return (
        '<tr data-attack-type="' + meta.key + '">' +
        "<td>" + escapeHtml(meta.label) + "</td>" +
        '<td><select data-field="kind">' + kindOptions + "</select></td>" +
        pktCell +
        '<td><input type="number" min="1" step="1" data-field="rate_limit_mbps" value="' +
        (p.rate_limit_mbps != null ? p.rate_limit_mbps : "") + '"> Mbps</td>' +
        '<td><select data-field="auto_mode">' + autoOptions + "</select></td>" +
        "</tr>"
      );
    }).join("");
    var rtbhTtlMin = Math.round((profiles[RTBH_TTL_KEY] || 3600) / 60);
    el.innerHTML =
      "<table><thead><tr><th>Tipo de ataque</th><th>Estratégia</th><th>Limiar de pacote</th>" +
      "<th>Limite de banda</th><th>Automático</th></tr></thead><tbody>" + rows + "</tbody></table>" +
      '<p class="fg-rtbh-ttl-row"><label>Duração padrão do bloqueio RTBH (botão "Mitigar" e ' +
      'automático): <input type="number" min="1" step="1" id="fg-rtbh-ttl-input" value="' +
      rtbhTtlMin + '"> minutos</label> <span class="fg-kpi-sub">(pode ser sobrescrita pontualmente ' +
      'no campo ao lado do botão "Mitigar", na aba Ataques)</span></p>';
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

  function updateFgMitigationSaveBtn() {
    var pendingCount = Object.keys(state.fgMitigationPending).length;
    var saveBtn = document.getElementById("fg-mitigation-save-btn");
    if (saveBtn) {
      saveBtn.disabled = pendingCount === 0;
      saveBtn.textContent = pendingCount > 0
        ? "Salvar " + pendingCount + " " + (pendingCount === 1 ? "alteração" : "alterações")
        : "Salvar configurações de mitigação";
    }
  }

  // Um tipo de ataque (ou a duração padrão do RTBH, chave global RTBH_TTL_KEY)
  // só entra em "pendente" se o valor mudou de verdade em relação ao que veio
  // do servidor — evita mandar um "não-muda-nada" quando o usuário mexe no
  // campo e volta pro valor original.
  function onFgMitigationChange(ev) {
    if (ev.target.id === "fg-rtbh-ttl-input") {
      var minutes = Number(ev.target.value);
      var originalTtlS = state.fgMitigationLoaded[RTBH_TTL_KEY] || 3600;
      if (!ev.target.value || isNaN(minutes) || minutes <= 0) {
        delete state.fgMitigationPending[RTBH_TTL_KEY];
      } else {
        var ttlS = Math.round(minutes * 60);
        if (ttlS === originalTtlS) delete state.fgMitigationPending[RTBH_TTL_KEY];
        else state.fgMitigationPending[RTBH_TTL_KEY] = ttlS;
      }
      updateFgMitigationSaveBtn();
      return;
    }

    var field = ev.target.getAttribute("data-field");
    if (!field) return;
    var row = ev.target.closest("tr[data-attack-type]");
    if (!row) return;
    var attackType = row.getAttribute("data-attack-type");
    var raw = ev.target.value;
    var isTextField = field === "kind" || field === "auto_mode";
    if (!isTextField && raw === "") return; // campo numérico vazio: ignora até digitar algo
    var value = isTextField ? raw : Number(raw);
    if (!isTextField && isNaN(value)) return;

    var original = state.fgMitigationLoaded[attackType] || {};
    var originalValue = field === "kind" ? (original.kind || "discard")
      : field === "auto_mode" ? (original.auto_mode || "off")
      : original[field];

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

    updateFgMitigationSaveBtn();
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

  // --- detecção de port scan (fora pra dentro) + bloqueio progressivo -------

  var FG_SCAN_CFG_FIELDS = [
    { key: "enabled", label: "Detecção de scan ativa", type: "bool", desc: "Liga/desliga o detector inteiro (horizontal + vertical)." },
    { key: "horizontal_enabled", label: "Scan horizontal ativo", type: "bool", desc: "1 IP externo -> N hosts distintos do prefixo, mesma porta (varredura de rede)." },
    { key: "vertical_enabled", label: "Scan vertical ativo", type: "bool", desc: "1 IP externo -> N portas distintas do mesmo host (varredura de portas)." },
    { key: "horizontal_hosts", label: "Scan horizontal — hosts distintos", type: "number", desc: "N hosts distintos (mesma porta) pra contar como scan horizontal. Placeholder — calibrar com tráfego real." },
    { key: "vertical_ports", label: "Scan vertical — portas distintas", type: "number", desc: "N portas distintas (mesmo host) pra contar como scan vertical. Placeholder — calibrar com tráfego real." },
    { key: "horizontal_max_avg_bytes", label: "Horizontal — máx. bytes médios por host (vazio desativa)", type: "number", nullable: true, desc: "Acima disso é tráfego real (ex: CDN respondendo vários clientes), não sonda de reconhecimento. Achado real: sem isso, Google/YouTube podiam ser bloqueados por engano." },
    { key: "vertical_max_avg_bytes", label: "Vertical — máx. bytes médios por porta (vazio desativa)", type: "number", nullable: true, desc: "Acima disso é tráfego real (ex: streaming/CDN abrindo várias conexões paralelas), não sonda de reconhecimento. Achado real: sem isso, Google/YouTube podiam ser bloqueados por engano." },
    { key: "max_tracked_src_ips_per_cycle", label: "Limite de IPs rastreados/ciclo", type: "number", desc: "Proteção de memória — acima disso, novos IPs externos não são rastreados até o próximo ciclo." },
    { key: "auto_block", label: "Bloqueio automático", type: "bool", desc: "Bloqueia via FlowSpec sozinho ao detectar. Também precisa de Mitigação > port_scan_horizontal/vertical com Automático != desligado." },
  ];

  var FG_ESCALATION_CFG_FIELDS = [
    { key: "enabled", label: "Escalonamento ativo", type: "bool", desc: "Desligado: todo bloqueio de scanner usa a duração base fixa." },
    { key: "tracking_window_s", label: "Janela de reincidência (s)", type: "number", desc: "Bloqueios do MESMO IP dentro dessa janela contam como reincidência." },
    { key: "base_ttl_s", label: "Duração base (s)", type: "number", desc: "Duração do 1º bloqueio." },
    { key: "factor", label: "Fator de multiplicação", type: "number", float: true, desc: "Cada reincidência multiplica a duração do próximo bloqueio por isso." },
    { key: "max_ttl_s", label: "Duração máxima (s)", type: "number", desc: "Teto — a duração nunca ultrapassa isso." },
    { key: "max_steps", label: "Reincidências até o teto", type: "number", desc: "Depois de N reincidências dentro da janela, trava na duração máxima." },
  ];

  function renderFgScanCfg(cfg) {
    state.fgScanCfgLoaded = cfg || {};
    renderKvFields("fg-scan-cfg", FG_SCAN_CFG_FIELDS, state.fgScanCfgLoaded);
  }

  function loadFgScanCfg() {
    getJson(SCAN_CFG_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("fg-scan-cfg"), data.error || "erro desconhecido");
        return;
      }
      renderFgScanCfg(data.scan_detection);
    }).catch(function (err) {
      showError(document.getElementById("fg-scan-cfg"), "falha ao consultar detecção de scan");
      console.error("flowguard.js:", err);
    });
  }

  function onFgScanCfgSaveClick() {
    var btn = document.getElementById("fg-scan-cfg-save-btn");
    var result = collectKvChanges("fg-scan-cfg", FG_SCAN_CFG_FIELDS, state.fgScanCfgLoaded || {});
    if (result.invalid) {
      showToast("Valores inválidos — confira os campos numéricos", "error");
      return;
    }
    if (!Object.keys(result.changes).length) {
      showToast("Nenhum campo foi alterado");
      return;
    }
    btn.disabled = true;
    postJson(SCAN_CFG_ENDPOINT, { changes: result.changes }).then(function (resp) {
      showToast(resp.ok ? "Detecção de scan atualizada" : (resp.error || "falha ao salvar"), resp.ok ? "success" : "error");
      if (resp.ok) renderFgScanCfg(resp.scan_detection);
    }).finally(function () { btn.disabled = false; });
  }

  function renderFgEscalationCfg(cfg) {
    state.fgEscalationLoaded = cfg || {};
    renderKvFields("fg-escalation-cfg", FG_ESCALATION_CFG_FIELDS, state.fgEscalationLoaded);
  }

  function loadFgEscalationCfg() {
    getJson(ESCALATION_CFG_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("fg-escalation-cfg"), data.error || "erro desconhecido");
        return;
      }
      renderFgEscalationCfg(data.escalation);
    }).catch(function (err) {
      showError(document.getElementById("fg-escalation-cfg"), "falha ao consultar bloqueio progressivo");
      console.error("flowguard.js:", err);
    });
  }

  function onFgEscalationSaveClick() {
    var btn = document.getElementById("fg-escalation-save-btn");
    var result = collectKvChanges("fg-escalation-cfg", FG_ESCALATION_CFG_FIELDS, state.fgEscalationLoaded || {});
    if (result.invalid) {
      showToast("Valores inválidos — confira os campos numéricos", "error");
      return;
    }
    if (!Object.keys(result.changes).length) {
      showToast("Nenhum campo foi alterado");
      return;
    }
    btn.disabled = true;
    postJson(ESCALATION_CFG_ENDPOINT, { changes: result.changes }).then(function (resp) {
      showToast(resp.ok ? "Bloqueio progressivo atualizado" : (resp.error || "falha ao salvar"), resp.ok ? "success" : "error");
      if (resp.ok) renderFgEscalationCfg(resp.escalation);
    }).finally(function () { btn.disabled = false; });
  }

  // port scan não tem severidade própria no backend (port_scan_offenders não
  // tem coluna severity) — estimada aqui só pra exibição, pela contagem de
  // hosts/portas distintos (dst_count). Cortes arbitrários, documentados na
  // UI ("estimada"), não vêm de nenhum limiar configurado.
  function scanSeverity(o) {
    if (o.dst_count >= 100) return "high";
    if (o.dst_count >= 20) return "medium";
    return "info";
  }

  function renderFgScanOffenders(offenders) {
    var el = document.getElementById("fg-scan-offenders");
    if (!el) return;
    if (!offenders.length) {
      el.innerHTML = '<p class="fg-ok">' +
        (state.scanView === "active" ? "Nenhum scanner detectado no momento." : "Nenhum scanner no histórico.") +
        "</p>";
      return;
    }
    // histórico pode vir com milhares de linhas (sem limite no backend) —
    // paginação client-side, mesmo padrão de flowguard-attacks/flows/top prefixos
    var p = paginate(offenders, "scanOffenders");
    var rows = p.pageRows.map(function (o) {
      var sev = scanSeverity(o);
      var newBadge = isNewIncident(o.ts_start) ? ' <span class="fg-badge" title="novo desde a última visita à aba">novo</span>' : "";
      var blockBtn = o.mitigated
        ? ""
        : '<button class="fg-btn" data-action="block" title="Cria um bloqueio manual de 1h via FlowSpec (mesma ação da aba Regras) — não atualiza este status sozinho">Bloquear</button>';
      return (
        '<tr data-offender-id="' + o.id + '" data-src-ip="' + escapeHtml(o.src_ip) + '">' +
        "<td>" + fmtDateTime(o.ts_start) + newBadge + "</td>" +
        "<td>" + escapeHtml(o.dst_prefix) + "</td><td>" + escapeHtml(o.src_ip) + "</td><td>" +
        (o.scan_type === "horizontal" ? "Horizontal" : "Vertical") + "</td>" +
        "<td class=\"fg-sev-" + sev + "\">" + sev + " (estimada)</td>" +
        "<td>" + o.dst_count + "</td><td>" + (o.pps_peak || 0).toLocaleString("pt-BR") + " pps</td><td>" +
        (o.mitigated ? '<span class="fg-mitigation-badge active">🛡 bloqueado</span>' : '<span class="fg-mitigation-badge none">detectando</span>') +
        "</td><td>" + blockBtn + "</td></tr>"
      );
    }).join("");
    el.innerHTML =
      "<table><thead><tr><th>Início</th><th>Prefixo</th><th>Src IP</th><th>Tipo</th><th>Severidade</th>" +
      "<th>Contagem</th><th>Pico (pps)</th><th>Status</th><th>Ações</th></tr></thead><tbody>" +
      rows + "</tbody></table>" +
      paginationHtml("scanOffenders", p.page, p.totalPages, p.total);
  }

  function loadFgScanOffenders() {
    var url = state.scanView === "history" ? SCAN_OFFENDERS_ENDPOINT + "?history=1" : SCAN_OFFENDERS_ENDPOINT;
    getJson(url).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("fg-scan-offenders"), data.error || "erro desconhecido");
        return;
      }
      state.scanOffenders = data.offenders || [];
      if (state.scanView === "active") {
        state.incidents.openScans = state.scanOffenders.filter(function (o) { return !o.mitigated; }).length;
        updateIncidentsBadge();
      }
      renderFgScanOffenders(state.scanOffenders);
    }).catch(function (err) {
      showError(document.getElementById("fg-scan-offenders"), "falha ao consultar scanners detectados");
      console.error("flowguard.js:", err);
    });
  }

  function onFgScanOffendersClick(ev) {
    var btn = ev.target.closest("button[data-action='block']");
    if (!btn) return;
    var row = btn.closest("tr[data-offender-id]");
    if (!row) return;
    var srcIp = row.getAttribute("data-src-ip");
    if (!window.confirm("Bloquear " + srcIp + " por 1h via FlowSpec (bloqueio manual, mesmo mecanismo da aba Regras)?")) return;
    btn.disabled = true;
    postJson(RULES_ENDPOINT, { src_prefix: srcIp, action: "discard", ttl_s: 3600 }).then(function (resp) {
      showToast(resp.ok ? srcIp + " bloqueado por 1h" : (resp.error || "falha ao bloquear"), resp.ok ? "success" : "error");
      loadRulesUnified();
    }).finally(function () { btn.disabled = false; });
  }

  function initFgScanControls() {
    var toggle = document.getElementById("fg-scan-view-toggle");
    if (toggle) {
      toggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        state.scanView = btn.getAttribute("data-view");
        state.page.scanOffenders = 1;
        toggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
        loadFgScanOffenders();
      });
    }
    var el = document.getElementById("fg-scan-offenders");
    if (el) el.addEventListener("click", onFgScanOffendersClick);
  }

  // --- detecção de destino coordenado (N src externos -> 1 host/porta protegido) ---

  var FG_COORDINATED_CFG_FIELDS = [
    { key: "enabled", label: "Detecção de destino coordenado ativa", type: "bool", desc: "Liga/desliga o detector inteiro." },
    { key: "min_distinct_sources", label: "Fontes distintas mínimas", type: "number", desc: "N IPs externos distintos convergindo no mesmo host/porta pra disparar. Placeholder — calibrar com tráfego real." },
    { key: "max_tracked_keys_per_cycle", label: "Limite de destinos rastreados/ciclo", type: "number", desc: "Proteção de memória — acima disso, novos destinos não são rastreados até o próximo ciclo." },
    { key: "auto_block", label: "Bloqueio automático", type: "bool", desc: "Sem efeito nesta versão — não existe mitigation_profiles.coordinated_destination ainda (detecção/alerta apenas)." },
  ];

  function renderFgCoordinatedCfg(cfg) {
    state.fgCoordinatedCfgLoaded = cfg || {};
    renderKvFields("fg-coordinated-cfg", FG_COORDINATED_CFG_FIELDS, state.fgCoordinatedCfgLoaded);
  }

  function loadFgCoordinatedCfg() {
    getJson(COORDINATED_CFG_ENDPOINT).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("fg-coordinated-cfg"), data.error || "erro desconhecido");
        return;
      }
      renderFgCoordinatedCfg(data.coordinated_destination);
    }).catch(function (err) {
      showError(document.getElementById("fg-coordinated-cfg"), "falha ao consultar detecção de destino coordenado");
      console.error("flowguard.js:", err);
    });
  }

  function onFgCoordinatedCfgSaveClick() {
    var btn = document.getElementById("fg-coordinated-cfg-save-btn");
    var result = collectKvChanges("fg-coordinated-cfg", FG_COORDINATED_CFG_FIELDS, state.fgCoordinatedCfgLoaded || {});
    if (result.invalid) {
      showToast("Valores inválidos — confira os campos numéricos", "error");
      return;
    }
    if (!Object.keys(result.changes).length) {
      showToast("Nenhum campo foi alterado");
      return;
    }
    btn.disabled = true;
    postJson(COORDINATED_CFG_ENDPOINT, { changes: result.changes }).then(function (resp) {
      showToast(resp.ok ? "Detecção de destino coordenado atualizada" : (resp.error || "falha ao salvar"), resp.ok ? "success" : "error");
      if (resp.ok) renderFgCoordinatedCfg(resp.coordinated_destination);
    }).finally(function () { btn.disabled = false; });
  }

  // sem coluna severity no backend (mesma limitação do scan) — estimada aqui
  // pela contagem de fontes distintas convergindo no mesmo destino
  function coordinatedSeverity(o) {
    if (o.src_count >= 100) return "high";
    if (o.src_count >= 20) return "medium";
    return "info";
  }

  function renderFgCoordinatedOffenders(offenders) {
    var el = document.getElementById("fg-coordinated-offenders");
    if (!el) return;
    if (!offenders.length) {
      el.innerHTML = '<p class="fg-ok">' +
        (state.coordinatedView === "active" ? "Nenhum destino coordenado detectado no momento." : "Nenhum destino coordenado no histórico.") +
        "</p>";
      return;
    }
    var p = paginate(offenders, "coordinatedOffenders");
    var rows = p.pageRows.map(function (o) {
      var sev = coordinatedSeverity(o);
      var newBadge = isNewIncident(o.ts_start) ? ' <span class="fg-badge" title="novo desde a última visita à aba">novo</span>' : "";
      return (
        "<tr><td>" + fmtDateTime(o.ts_start) + newBadge + "</td>" +
        "<td>" + escapeHtml(o.dst_prefix) + "</td><td>" + escapeHtml(o.dst_ip) + "</td><td>" +
        o.dst_port + "</td><td>" + protoName(o.protocol) + "</td>" +
        "<td class=\"fg-sev-" + sev + "\">" + sev + " (estimada)</td>" +
        "<td>" + o.src_count + "</td><td>" + (o.pps_peak || 0).toLocaleString("pt-BR") + " pps</td><td>" +
        (o.mitigated ? '<span class="fg-mitigation-badge active">🛡 bloqueado</span>' : '<span class="fg-mitigation-badge none">detectando</span>') +
        "</td></tr>"
      );
    }).join("");
    el.innerHTML =
      "<table><thead><tr><th>Início</th><th>Prefixo</th><th>Dst IP</th><th>Porta</th><th>Protocolo</th>" +
      "<th>Severidade</th><th>Fontes</th><th>Pico (pps)</th><th>Status</th></tr></thead><tbody>" +
      rows + "</tbody></table>" +
      paginationHtml("coordinatedOffenders", p.page, p.totalPages, p.total);
  }

  function loadFgCoordinatedOffenders() {
    var url = state.coordinatedView === "history" ? COORDINATED_OFFENDERS_ENDPOINT + "?history=1" : COORDINATED_OFFENDERS_ENDPOINT;
    getJson(url).then(function (data) {
      if (!data.ok) {
        showError(document.getElementById("fg-coordinated-offenders"), data.error || "erro desconhecido");
        return;
      }
      state.coordinatedOffenders = data.offenders || [];
      if (state.coordinatedView === "active") {
        state.incidents.openCoordinated = state.coordinatedOffenders.filter(function (o) { return !o.mitigated; }).length;
        updateIncidentsBadge();
      }
      renderFgCoordinatedOffenders(state.coordinatedOffenders);
    }).catch(function (err) {
      showError(document.getElementById("fg-coordinated-offenders"), "falha ao consultar destinos coordenados");
      console.error("flowguard.js:", err);
    });
  }

  function initFgCoordinatedControls() {
    var toggle = document.getElementById("fg-coordinated-view-toggle");
    if (toggle) {
      toggle.addEventListener("click", function (ev) {
        var btn = ev.target.closest(".fg-toggle-btn");
        if (!btn) return;
        state.coordinatedView = btn.getAttribute("data-view");
        state.page.coordinatedOffenders = 1;
        toggle.querySelectorAll(".fg-toggle-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
        loadFgCoordinatedOffenders();
      });
    }
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
    loadRulesUnified();
    loadWarmodeStatus();
    // status do ClientGuard não era polado fora da própria aba dele — o
    // widget do cockpit precisa disso mesmo se o operador nunca abrir a aba
    loadClientGuardStatus();
    // sinais suspeitos agora vivem dentro da aba Incidentes (lado ClientGuard)
    // — precisam ficar vivos por poll, igual aos ataques, pro badge somado
    // não ficar bolorento enquanto o operador está no lado FlowGuard
    loadClientGuardSuspicious();
    // scanners detectados agora vivem dentro da aba Incidentes — mesmo
    // motivo acima, precisam ficar vivos por poll (antes só carregava 1x ao
    // abrir a extinta seção em Configuração, nunca era repolado)
    loadFgScanOffenders();
    loadFgCoordinatedOffenders();
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
    initCollapsiblePanels();
    initCollapseAllControls();
    initTabs();
    initIncidentsControls();
    initSortHandlers();
    initAttacksControls();
    initPaginationHandlers();
    initActionMenus();
    initWarmode();
    initRouterCfg();
    initCockpit();

    // (busca de "Meus Prefixos" é delegada no grid do cockpit — ver
    // initCockpit — pra sobreviver ao rebuild do "Restaurar layout padrão")

    var flowsSearch = document.getElementById("fg-flows-search");
    if (flowsSearch) flowsSearch.addEventListener("input", function () { state.filter.flows = flowsSearch.value; state.page.flows = 1; renderFlowsFiltered(); });

    var attacksEl = document.getElementById("flowguard-attacks");
    if (attacksEl) attacksEl.addEventListener("click", onAttacksClick);

    var attackDetailEl = document.getElementById("flowguard-attack-detail");
    if (attackDetailEl) attackDetailEl.addEventListener("click", onAttackDetailClick);

    var rulesFgListEl = document.getElementById("rules-fg-list");
    if (rulesFgListEl) rulesFgListEl.addEventListener("click", onRulesUnifiedClick);

    var rulesCgFlowspecListEl = document.getElementById("rules-cg-flowspec-list");
    if (rulesCgFlowspecListEl) rulesCgFlowspecListEl.addEventListener("click", onRulesUnifiedClick);

    var rulesCgEdgeListEl = document.getElementById("rules-cg-edge-list");
    if (rulesCgEdgeListEl) rulesCgEdgeListEl.addEventListener("click", onRulesUnifiedClick);

    var rulesDetailEl = document.getElementById("rules-detail");
    if (rulesDetailEl) rulesDetailEl.addEventListener("click", onRulesUnifiedClick);

    initRulesControls();
    initCfgAppToggle();

    var blockSubmitBtn = document.getElementById("fg-block-submit");
    if (blockSubmitBtn) blockSubmitBtn.addEventListener("click", onBlockSubmit);

    var cfgEl = document.getElementById("flowguard-cfg");
    if (cfgEl) {
      cfgEl.addEventListener("click", onCfgClick);
      cfgEl.addEventListener("submit", onCfgSubmit);
      loadCfg();
    }

    var fgDetectionCfgSaveBtn = document.getElementById("fg-detection-cfg-save-btn");
    if (fgDetectionCfgSaveBtn) fgDetectionCfgSaveBtn.addEventListener("click", onFgDetectionCfgSaveClick);

    var fgDetectionTemplatesEl = document.getElementById("fg-detection-templates");
    if (fgDetectionTemplatesEl) fgDetectionTemplatesEl.addEventListener("click", onFgDetectionTemplatesClick);

    var fgDetectionTemplateForm = document.getElementById("fg-detection-template-form");
    if (fgDetectionTemplateForm) fgDetectionTemplateForm.addEventListener("submit", onFgDetectionTemplateFormSubmit);

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

    if (document.getElementById("fg-scan-cfg")) loadFgScanCfg();
    var fgScanCfgSaveBtn = document.getElementById("fg-scan-cfg-save-btn");
    if (fgScanCfgSaveBtn) fgScanCfgSaveBtn.addEventListener("click", onFgScanCfgSaveClick);

    if (document.getElementById("fg-coordinated-cfg")) loadFgCoordinatedCfg();
    var fgCoordinatedCfgSaveBtn = document.getElementById("fg-coordinated-cfg-save-btn");
    if (fgCoordinatedCfgSaveBtn) fgCoordinatedCfgSaveBtn.addEventListener("click", onFgCoordinatedCfgSaveClick);

    if (document.getElementById("fg-escalation-cfg")) loadFgEscalationCfg();
    var fgEscalationSaveBtn = document.getElementById("fg-escalation-save-btn");
    if (fgEscalationSaveBtn) fgEscalationSaveBtn.addEventListener("click", onFgEscalationSaveClick);

    if (document.getElementById("fg-scan-offenders")) { initFgScanControls(); loadFgScanOffenders(); }
    if (document.getElementById("fg-coordinated-offenders")) { initFgCoordinatedControls(); loadFgCoordinatedOffenders(); }

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

    var cgDetectionTemplateForm = document.getElementById("cg-detection-template-form");
    if (cgDetectionTemplateForm) cgDetectionTemplateForm.addEventListener("submit", onCgCfgSubmit);

    var cgDetectionTemplatesEl = document.getElementById("cg-detection-templates");
    if (cgDetectionTemplatesEl) cgDetectionTemplatesEl.addEventListener("click", onCgCfgClick);

    var cgDetectionCfgSaveBtn = document.getElementById("cg-detection-cfg-save-btn");
    if (cgDetectionCfgSaveBtn) cgDetectionCfgSaveBtn.addEventListener("click", onCgDetectionCfgSaveClick);

    var cgTogglesEl = document.getElementById("cg-toggles");
    if (cgTogglesEl) cgTogglesEl.addEventListener("change", onCgTogglesChange);

    var cgTogglesApplyBtn = document.getElementById("cg-toggles-apply-btn");
    if (cgTogglesApplyBtn) cgTogglesApplyBtn.addEventListener("click", onCgTogglesApplyClick);

    var cgClearSuspiciousBtn = document.getElementById("cg-clear-suspicious-btn");
    if (cgClearSuspiciousBtn) cgClearSuspiciousBtn.addEventListener("click", onCgClearSuspiciousClick);

    var cgEdgeAutoEl = document.getElementById("cg-edge-auto");
    if (cgEdgeAutoEl) cgEdgeAutoEl.addEventListener("change", onCgEdgeAutoChange);

    var cgEdgeAutoApplyBtn = document.getElementById("cg-edge-auto-apply-btn");
    if (cgEdgeAutoApplyBtn) cgEdgeAutoApplyBtn.addEventListener("click", onCgEdgeAutoApplyClick);

    var cgEscalationSaveBtn = document.getElementById("cg-escalation-save-btn");
    if (cgEscalationSaveBtn) cgEscalationSaveBtn.addEventListener("click", onCgEscalationSaveClick);

    if (getToken()) { loadClientGuardCfg(); loadCgToggles(); loadCgEdgeAuto(); loadCgEscalationCfg(); }

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
