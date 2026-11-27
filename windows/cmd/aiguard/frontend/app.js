// AIGuard Windows 界面逻辑。所有数据来自 Go 侧 UIService（经命名管道转发给守护服务，或直接查 mihomo 控制接口）。
// 节点名、域名、订阅名都来自外部，渲染时一律转义。
import { Call, Events } from "/wails/runtime.js";

const api = (method, ...args) => Call.ByName(`main.UIService.${method}`, ...args);

const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const icon = (name, cls = "icon") => `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const errText = (e) => (e && (e.message || e.error)) || String(e);

const state = {
  page: "overview",
  ui: null, // UIService.State() 的结果
  meta: null, // 版本、地区表、AI 名单分类
  settings: null,
  events: [],
  eventsCursor: 0,
  eventsGeneration: null,
  unreadCritical: 0,
  nodes: null,
  conns: null,
  connFilter: "",
  eventFilter: { level: "all", q: "" },
  traffic: [],
  lastTotals: null,
  busy: new Set(),
};

// ---------- 通用 ----------

function fmtBytes(n) {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}
const fmtRate = (n) => `${fmtBytes(n)}/s`;
function fmtTime(ms, withDate = false) {
  if (!ms) return "—";
  const d = new Date(ms);
  const t = d.toLocaleTimeString("zh-CN", { hour12: false });
  return withDate ? `${d.toLocaleDateString("zh-CN")} ${t}` : t;
}
function fmtAgo(ms) {
  if (!ms) return "从未";
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return "刚刚";
  if (s < 3600) return `${Math.floor(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时前`;
  return `${Math.floor(s / 86400)} 天前`;
}
function region(code) {
  if (!code) return "未知";
  const r = state.meta?.regions?.find((x) => x.code === code);
  return r ? r.name : code;
}

let toastTimer;
function toast(message, tone = "ok") {
  const el = $("#toast");
  const ic = tone === "danger" ? "warn" : tone === "warn" ? "warn" : "check";
  el.className = `toast show tone-${tone}`;
  el.innerHTML = `${icon(ic)}<div>${esc(message)}</div>`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), tone === "danger" ? 7000 : 3500);
}

// 原生 <dialog>：按钮列表的第一个是默认按钮，Esc 等于取消
function confirmDialog({ title, text, ok = "确定", cancel = "取消", danger = false }) {
  return new Promise((resolve) => {
    const d = $("#dialog");
    $("#dialog-title").textContent = title;
    $("#dialog-text").textContent = text;
    $("#dialog-actions").innerHTML =
      `<button class="btn ${danger ? "danger" : "primary"}" value="ok">${esc(ok)}</button>` +
      (cancel ? `<button class="btn" value="cancel">${esc(cancel)}</button>` : "");
    d.returnValue = "cancel";
    d.addEventListener("close", () => resolve(d.returnValue === "ok"), { once: true });
    d.showModal();
  });
}

// 同一个动作执行中不重复触发，按钮显示转圈
async function run(key, fn, okMessage) {
  if (state.busy.has(key)) return;
  state.busy.add(key);
  renderBusy();
  try {
    const r = await fn();
    if (r && r.ok === false) throw new Error(r.error || "操作失败");
    if (okMessage) toast(okMessage);
    return r;
  } catch (e) {
    toast(errText(e), "danger");
  } finally {
    state.busy.delete(key);
    renderBusy();
    refresh();
  }
}
function renderBusy() {
  document.querySelectorAll("[data-busy]").forEach((b) => {
    const on = state.busy.has(b.dataset.busy);
    b.toggleAttribute("disabled", on);
    b.setAttribute("aria-busy", on ? "true" : "false");
  });
}

// ---------- 导航 ----------

function showPage(page) {
  state.page = page;
  document.querySelectorAll(".nav button[data-page]").forEach((b) => {
    if (b.dataset.page === page) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  document.querySelectorAll(".page").forEach((p) => { p.hidden = p.id !== `page-${page}`; });
  if (page === "events") { state.unreadCritical = 0; renderBadge(); }
  renderPage(true);
  $("#main").scrollTop = 0;
}

document.querySelectorAll(".nav button[data-page]").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));

// ---------- 状态解读 ----------

function phaseView(ui) {
  const st = ui.status;
  const svc = ui.service;
  if (!svc.installed) return { tone: "idle", icon: "shield-off", title: "未安装防护服务", sub: "需要先安装系统服务才能接管网络" };
  if (!svc.running || !st) return { tone: "danger", icon: "shield-x", title: "防护服务未运行", sub: svc.error || "服务停止期间防火墙规则仍然有效，网络可能处于断开状态" };
  switch (st.phase) {
    case "protected":
      return st.effectiveMode === "proxy"
        ? { tone: "ok", icon: "shield", title: "已受保护", sub: `AI 流量经代理出境，出口 ${region(st.exit?.trace?.country)}` }
        : { tone: "ok", icon: "shield", title: "直连阻断 AI", sub: "没有可用订阅：只放行大陆网站，所有 AI 服务被拒绝" };
    case "tripped": {
      const hard = st.fuse?.hard;
      return { tone: "danger", icon: "bolt", title: hard ? "已熔断：全部断网" : "已熔断：只放行大陆", sub: ui.reasonTitle || "等待线路恢复" };
    }
    case "starting":
      return { tone: "info", icon: "shield", title: "正在启动保护", sub: "内核与线路就绪前只放行大陆网站" };
    case "disabled":
      return { tone: "warn", icon: "shield-off", title: "守护已关闭", sub: "防火墙、TUN、DNS 锁定已撤销，AI 不受保护" };
    default:
      return { tone: "danger", icon: "shield-x", title: "防护异常", sub: st.lastError || "防火墙或内核出现问题，查看事件页了解原因" };
  }
}

// ---------- 页面渲染 ----------

function renderPage(force = false) {
  const ui = state.ui;
  const appEl = $("#app");
  const setupEl = $("#setup");
  if (ui && (!ui.service.installed || ui.service.outdated)) {
    appEl.hidden = true;
    setupEl.hidden = false;
    renderSetup();
    return;
  }
  appEl.hidden = false;
  setupEl.hidden = true;
  if (!ui) return;
  const fn = renderers[state.page];
  if (fn) fn(force);
}

function renderSetup() {
  const ui = state.ui;
  const outdated = ui.service.outdated;
  const el = $("#setup");
  el.innerHTML = `
    <div class="setup tone-${outdated ? "info" : "ok"}">
      <div class="hero-ring">${icon("shield")}</div>
      <h1>${outdated ? `升级防护服务到 ${esc(ui.version)}` : "安装防护服务"}</h1>
      <p>${outdated
        ? `已安装的防护服务是 ${esc(ui.service.version || "旧版")}，这个界面是 ${esc(ui.version)}。升级会短暂断网几秒，设置和订阅都会保留。`
        : "TUN 全局接管、WFP 防火墙熔断和 DNS/IPv6 防泄漏都需要一个常驻的系统服务。安装时 Windows 会弹出用户账户控制确认。"}</p>
      <button class="btn primary" data-busy="install">${icon("download")}${outdated ? "升级并重启服务" : "安装并启动"}</button>
      <ol class="steps card">
        <li>运行前请退出 Clash Verge、v2rayN 等其他代理软件，两个 TUN 会抢路由</li>
        <li>服务会锁定各网卡的 DNS、关闭 IPv6，关闭守护或卸载时恢复</li>
        <li>服务停止或崩溃时防火墙仍然生效（宁可断网也不泄漏）</li>
      </ol>
      ${ui.service.error ? `<p class="faint">${esc(ui.service.error)}</p>` : ""}
    </div>`;
  $("button[data-busy=install]", el).addEventListener("click", () =>
    run("install", () => api("InstallService"), outdated ? "防护服务已升级" : "防护服务已安装"));
  renderBusy();
}

// ----- 总览 -----

let latencyChart;
let trafficChart;

function chartTheme() {
  const css = getComputedStyle(document.documentElement);
  return {
    text: css.getPropertyValue("--text-2").trim(),
    grid: css.getPropertyValue("--stroke").trim(),
    accent: css.getPropertyValue("--accent").trim(),
    danger: css.getPropertyValue("--danger").trim(),
    info: css.getPropertyValue("--info").trim(),
    font: css.getPropertyValue("--font").trim(),
  };
}

function baseChart(el) {
  const c = echarts.init(el, null, { renderer: "svg" });
  new ResizeObserver(() => c.resize()).observe(el);
  return c;
}

function renderOverview(force) {
  const el = $("#page-overview");
  const ui = state.ui;
  const st = ui.status;
  if (force || !$("#ov-hero", el)) {
    el.innerHTML = `
      <div class="page-head"><div><h1 id="h-overview">总览</h1></div></div>
      <div id="ov-banners"></div>
      <div class="card hero" id="ov-hero"></div>
      <div class="stats" id="ov-stats"></div>
      <h2>长连接心跳延迟</h2>
      <div class="card"><div class="chart" id="ov-latency" role="img" aria-label="最近的心跳延迟，失败用红点标出"></div></div>
      <h2>实时流量</h2>
      <div class="card"><div class="chart" id="ov-traffic" role="img" aria-label="最近一分钟的上下行速率"></div></div>
      <h2>防护链路</h2>
      <div class="card chain" id="ov-chain"></div>`;
    latencyChart?.dispose();
    trafficChart?.dispose();
    latencyChart = baseChart($("#ov-latency", el));
    trafficChart = baseChart($("#ov-traffic", el));
  }

  // 提示条：游戏模式、冲突软件、服务异常
  const banners = [];
  if (st?.gameMode) {
    const manual = st.gameReason === "手动开启";
    banners.push(`<div class="banner tone-info">${icon("game")}<div class="banner-body"><div class="banner-title">游戏模式（${esc(st.gameReason || "")}）</div>
      <div class="muted">AI 服务一律禁止：AI 程序被关闭并禁止联网（已拉黑 ${st.gameBlockedApps} 个），浏览器里的 AI 网站全部拒绝。其余流量直连不走代理，游戏与加速器不受影响。${manual ? "" : "游戏退出 1 分钟后自动恢复。"}</div></div>
      ${manual ? `<div class="banner-actions"><button class="btn" data-busy="game" data-act="gameOff">退出游戏模式</button></div>` : ""}</div>`);
  }
  if (st?.conflicts?.length) {
    banners.push(`<div class="banner tone-warn">${icon("warn")}<div class="banner-body"><div class="banner-title">检测到其他代理软件：${esc(st.conflicts.join("、"))}</div>
      <div class="muted">两个 TUN 会抢占路由，可能导致流量绕开本软件。请退出它们（或关闭其 TUN/虚拟网卡模式）。用游戏加速器时请开启游戏模式。</div></div>
      <div class="banner-actions"><button class="btn" data-busy="restart" data-act="restart">重启内核</button></div></div>`);
  }
  if (ui.service.newer) {
    banners.push(`<div class="banner tone-info">${icon("info")}<div class="banner-body"><div class="banner-title">这个界面比防护服务旧</div>
      <div class="muted">已安装的服务是 ${esc(ui.service.version)}，界面是 ${esc(ui.version)}。请改用新版界面，不要用旧版重新安装，否则会降级。</div></div></div>`);
  }
  $("#ov-banners", el).innerHTML = banners.join("");

  // 主状态
  const v = phaseView(ui);
  const fuse = st?.fuse;
  const recovering = st?.phase === "tripped" && fuse?.recoverNeeded > 0;
  const hold = st?.fuseHoldRemainingMs ? Math.ceil(st.fuseHoldRemainingMs / 1000) : 0;
  let detail = "";
  if (st?.phase === "tripped") {
    if (st.fuseLatched) detail = "手动熔断已锁定，需要手动解除";
    else if (hold) detail = `至少再保持 ${hold} 秒`;
    else if (recovering) detail = `恢复验证 ${fuse.recoverProgress}/${fuse.recoverNeeded}${fuse.geoVerified ? "，出口已确认" : ""}`;
  }
  if (st?.captiveUntil) detail = `酒店 Wi-Fi 登录模式，${fmtTime(st.captiveUntil)} 结束（AI 仍被拒绝）`;
  const tripped = st?.phase === "tripped";
  const hero = $("#ov-hero", el);
  hero.className = `card hero tone-${v.tone}`;
  hero.innerHTML = `
    <div class="hero-ring">${icon(v.icon)}</div>
    <div>
      <div class="hero-title">${esc(v.title)}</div>
      <div class="hero-sub">${esc(v.sub)}</div>
      ${detail ? `<div class="faint" style="margin-top:4px">${esc(detail)}</div>` : ""}
      ${recovering && !st.fuseLatched ? `<div class="progress"><div style="width:${Math.round((fuse.recoverProgress / fuse.recoverNeeded) * 100)}%"></div></div>` : ""}
    </div>
    <div class="hero-actions">
      ${!ui.service.running ? `<button class="btn primary" data-busy="install" data-act="startService">${icon("refresh")}启动防护服务</button>` : ""}
      ${!st || st.phase === "disabled" ? "" : tripped
        ? `<button class="btn primary" data-busy="restore" data-act="restore">${icon("refresh")}重新验证</button>
           <button class="btn subtle" data-busy="force" data-act="force">跳过验证，强制恢复</button>`
        : `<button class="btn danger" data-busy="trip" data-act="trip">${icon("bolt")}立即熔断</button>`}
      ${st && st.phase !== "disabled" ? (st.captiveUntil
        ? `<button class="btn" data-busy="captive" data-act="endCaptive">结束 Wi-Fi 登录</button>`
        : `<button class="btn" data-busy="captive" data-act="captive">${icon("wifi")}酒店 Wi-Fi 登录</button>`) : ""}
      ${st && st.phase !== "disabled" && !st.gameMode ? `<button class="btn" data-busy="game" data-act="gameOn">${icon("game")}游戏模式</button>` : ""}
    </div>`;

  // 指标
  const lat = st?.latency?.filter((x) => x.ms != null) ?? [];
  const lastLat = st?.latency?.length ? st.latency[st.latency.length - 1] : null;
  const sub = st?.subscription;
  const trace = st?.exit?.trace;
  $("#ov-stats", el).innerHTML = [
    stat("globe", "出口", st?.effectiveMode !== "proxy" ? "未使用代理" : trace ? `${region(trace.country)}` : "检测中…",
      st?.effectiveMode !== "proxy" ? "直连模式不检测出口" : trace ? `${trace.ip} · ${fmtAgo(st.exit.checkedAt)}` : st?.exit?.error || ""),
    stat("pulse", "心跳延迟", st?.effectiveMode !== "proxy" ? "—" : lastLat?.ms != null ? `${lastLat.ms} ms` : st?.heartbeatAlive ? "…" : "失败",
      lat.length ? `近 ${st.latency.length} 次平均 ${Math.round(lat.reduce((a, b) => a + b.ms, 0) / lat.length)} ms` : ""),
    stat("nodes", "出站模式", st?.effectiveMode === "proxy" ? (st.routing === "global" ? "全局代理" : "智能分流") : "直连阻断 AI",
      st?.nodeCount != null ? `${st.nodeCount} 个可用节点` : ""),
    stat("cpu", "内核", st?.coreRunning ? "运行中" : "未运行", [st?.coreVersion, st?.coreRestarts ? `重启 ${st.coreRestarts} 次` : ""].filter(Boolean).join(" · ")),
  ].join("");
  if (sub == null && st?.effectiveMode !== "proxy") {
    // 没有订阅时指标里提示去导入
    $("#ov-stats .stat:nth-child(3) .stat-note", el).innerHTML = `<a href="#" data-goto="subscription">去导入订阅</a>`;
  }

  // 防护链路
  const chain = [
    item(st?.firewallPolicy && st.firewallPolicy !== "none" ? (st.firewallPolicy === "basic" ? "warn" : "ok") : "danger", "WFP 防火墙", policyName(st?.firewallPolicy)),
    item(st?.tunUp ? "ok" : st?.gameMode ? "warn" : "danger", "TUN 接管", st?.tunUp ? (st?.gameMode ? "游戏模式：AI 网站拒绝，其余直连" : "默认路由经 AIGuard 网卡") : (st?.gameMode ? "部分路由被加速器接管，AI 程序仍被禁止联网" : "TUN 未接管路由")),
    item(st?.systemDnsLocked ? "ok" : "warn", "DNS 防泄漏", st?.systemDnsLocked ? "各网卡 DNS 已锁到内核" : "DNS 未锁定，仅靠防火墙拦截明文 DNS"),
    item(st?.ipv6Blocked === false ? "danger" : st?.ipv6Blocked ? "ok" : "idle", "IPv6 封锁", st?.ipv6Blocked == null ? "尚未检测" : st.ipv6Blocked ? `已封锁${st.ipv6DisabledInterfaces ? `，${st.ipv6DisabledInterfaces} 块网卡已关闭 IPv6` : ""}` : "能直连公网 IPv6"),
    item(st?.effectiveMode !== "proxy" ? "idle" : st?.heartbeatAlive ? "ok" : "danger", "长连接心跳", st?.effectiveMode !== "proxy" ? "直连模式不需要" : st?.heartbeatAlive ? "线路畅通" : "心跳失败"),
    item(sub ? (sub.lastError ? "warn" : "ok") : "idle", "订阅", sub ? `${esc(sub.name || "已导入")} · 更新于 ${fmtAgo(sub.lastUpdated)}` : "未导入"),
  ];
  $("#ov-chain", el).innerHTML = chain.join("");

  updateLatencyChart(st);
  updateTrafficChart();
}

function stat(ic, label, value, note) {
  return `<div class="card stat"><div class="stat-label">${icon(ic)}${esc(label)}</div><div class="stat-value">${esc(value)}</div><div class="stat-note">${esc(note || "")}</div></div>`;
}
function item(tone, title, desc) {
  return `<div class="chain-item tone-${tone}"><span class="dot" aria-hidden="true"></span><div><div class="chain-title">${esc(title)}</div><div class="chain-desc">${desc}</div></div></div>`;
}
function policyName(p) {
  return { none: "未加载", leakGuard: "防泄漏：普通程序只能经 TUN 出站", basic: "仅 IPv6 与 DNS 防泄漏", whitelist: "熔断：只放行大陆 IP", lockdown: "熔断：全部断网", game: "游戏模式：AI 程序禁止联网，其余放行" }[p] || "未知";
}

function updateLatencyChart(st) {
  if (!latencyChart) return;
  const t = chartTheme();
  const samples = st?.latency ?? [];
  const ok = samples.map((s) => [s.at, s.ms]);
  const failed = samples.filter((s) => s.ms == null).map((s) => [s.at, 0]);
  latencyChart.setOption({
    animation: false,
    grid: { left: 44, right: 16, top: 16, bottom: 28 },
    textStyle: { fontFamily: t.font, color: t.text },
    tooltip: { trigger: "axis", valueFormatter: (v) => (v == null ? "失败" : `${v} ms`) },
    xAxis: { type: "time", axisLine: { lineStyle: { color: t.grid } }, axisLabel: { color: t.text, hideOverlap: true }, splitLine: { show: false } },
    yAxis: { type: "value", name: "ms", nameTextStyle: { color: t.text }, axisLabel: { color: t.text }, splitLine: { lineStyle: { color: t.grid } } },
    series: [
      { name: "延迟", type: "line", data: ok, connectNulls: false, showSymbol: false, smooth: 0.2, lineStyle: { width: 2, color: t.accent }, areaStyle: { color: t.accent, opacity: 0.08 } },
      { name: "失败", type: "scatter", data: failed, symbolSize: 7, itemStyle: { color: t.danger }, tooltip: { valueFormatter: () => "失败" } },
    ],
  }, { notMerge: true });
}

function updateTrafficChart() {
  if (!trafficChart) return;
  const t = chartTheme();
  trafficChart.setOption({
    animation: false,
    grid: { left: 64, right: 16, top: 24, bottom: 28 },
    textStyle: { fontFamily: t.font, color: t.text },
    legend: { top: 0, right: 8, textStyle: { color: t.text }, itemWidth: 12, itemHeight: 8 },
    tooltip: { trigger: "axis", valueFormatter: (v) => fmtRate(v) },
    xAxis: { type: "time", axisLine: { lineStyle: { color: t.grid } }, axisLabel: { color: t.text, hideOverlap: true }, splitLine: { show: false } },
    yAxis: { type: "value", axisLabel: { color: t.text, formatter: (v) => fmtRate(v) }, splitLine: { lineStyle: { color: t.grid } } },
    series: [
      { name: "下行", type: "line", showSymbol: false, data: state.traffic.map((p) => [p.at, p.down]), lineStyle: { width: 2, color: t.accent }, itemStyle: { color: t.accent } },
      { name: "上行", type: "line", showSymbol: false, data: state.traffic.map((p) => [p.at, p.up]), lineStyle: { width: 2, color: t.info }, itemStyle: { color: t.info } },
    ],
  }, { notMerge: true });
}

$("#page-overview").addEventListener("click", (e) => {
  const go = e.target.closest("[data-goto]");
  if (go) { e.preventDefault(); showPage(go.dataset.goto); return; }
  const b = e.target.closest("[data-act]");
  if (!b) return;
  const act = b.dataset.act;
  if (act === "trip") run("trip", () => api("TripFuse"), "已熔断");
  if (act === "restore") run("restore", () => api("RestoreNetwork", false), "正在重新验证线路");
  if (act === "force") {
    confirmDialog({ title: "跳过验证强制恢复？", text: "不再等待线路与出口验证，立即放行全部流量。如果当前出口在禁区，AI 服务会看到这个 IP。", ok: "强制恢复", danger: true })
      .then((yes) => yes && run("force", () => api("RestoreNetwork", true), "已强制恢复网络"));
  }
  if (act === "restart") run("restart", () => api("RestartCore"), "内核已重启");
  if (act === "startService") run("install", () => api("InstallService"), "防护服务已启动");
  if (act === "captive") {
    confirmDialog({ title: "酒店 Wi-Fi 登录", text: "接下来 5 分钟内全部直连并使用酒店 DHCP 下发的 DNS，方便打开认证页。AI 服务仍然被拒绝。", ok: "开始" })
      .then((yes) => yes && run("captive", () => api("CaptiveLogin", 5), "已进入 Wi-Fi 登录模式"));
  }
  if (act === "endCaptive") run("captive", () => api("EndCaptiveLogin"), "已结束 Wi-Fi 登录模式");
  if (act === "gameOn") {
    confirmDialog({ title: "开启游戏模式？", text: "所有 AI 程序（Claude、ChatGPT、Cursor、Claude Code 等）会被立即关闭，游戏模式期间打开也会被关掉，并且禁止联网；浏览器里的 AI 网站全部拒绝。其余流量直连不走代理，UU、雷神等加速器可以正常使用。", ok: "开启并关闭 AI 程序", danger: true })
      .then((yes) => yes && run("game", () => api("SetGameMode", true), "已开启游戏模式，AI 程序已关闭"));
  }
  if (act === "gameOff") run("game", () => api("SetGameMode", false), "已退出游戏模式");
});

// ----- 节点 -----

async function loadNodes() {
  try { state.nodes = await api("Nodes"); } catch (e) { state.nodes = { error: errText(e) }; }
}

function renderNodes(force) {
  const el = $("#page-nodes");
  if (force) {
    el.innerHTML = `
      <div class="page-head"><div><h1 id="h-nodes">节点</h1><p class="lede">单线路：AI 与其他代理流量都走「节点选择」。出口禁区地区的节点会被自动排除。</p></div>
        <div class="toolbar"><button class="btn" data-busy="delay" id="nodes-test">${icon("pulse")}测试延迟</button></div></div>
      <div id="nodes-body"><div class="empty">正在读取节点…</div></div>`;
    $("#nodes-test", el).addEventListener("click", () => run("delay", async () => { await api("TestDelays"); await loadNodes(); renderNodes(false); }));
    loadNodes().then(() => renderNodes(false));
    renderBusy();
    return;
  }
  const body = $("#nodes-body", el);
  const n = state.nodes;
  if (!n) return;
  if (n.error) { body.innerHTML = `<div class="empty">${icon("warn")}<div>${esc(n.error)}</div></div>`; return; }
  if (!n.items?.length) {
    body.innerHTML = `<div class="empty">${icon("nodes")}<div>还没有节点</div><p class="faint">在「订阅」页导入订阅链接后，这里会列出可用节点。</p></div>`;
    return;
  }
  body.innerHTML = `<div class="nodes" role="radiogroup" aria-label="节点选择">${n.items.map((x) => `
    <button class="node" role="radio" aria-checked="${x.name === n.selected}" aria-pressed="${x.name === n.selected}" data-node="${esc(x.name)}">
      <span class="node-name" title="${esc(x.name)}">${esc(x.name)}</span>
      <span class="node-meta"><span>${esc(x.type || "")}${x.name === n.selected && n.resolved && n.resolved !== x.name ? ` → ${esc(n.resolved)}` : ""}</span>
      <span class="${x.delay == null ? "" : x.delay > 800 ? "tone-warn" : "tone-ok"}" style="color:var(--tone)">${x.alive === false ? "不可用" : x.delay != null ? `${x.delay} ms` : "—"}</span></span>
    </button>`).join("")}</div>`;
}

$("#page-nodes").addEventListener("click", (e) => {
  const b = e.target.closest("[data-node]");
  if (!b) return;
  const name = b.dataset.node;
  run("select", async () => { await api("SelectNode", name); await loadNodes(); renderNodes(false); }, `已切换到「${name}」`);
});

// ----- 连接 -----

async function loadConns() {
  try { state.conns = await api("Connections"); } catch (e) { state.conns = { error: errText(e) }; }
}

function routeTone(r) { return r === "proxy" ? "ok" : r === "reject" ? "danger" : "info"; }
function routeName(r) { return r === "proxy" ? "代理" : r === "reject" ? "拒绝" : "直连"; }

function renderConnections(force) {
  const el = $("#page-connections");
  if (force) {
    el.innerHTML = `
      <div class="page-head"><div><h1 id="h-connections">连接</h1><p class="lede">实时查看每条连接走了哪条线路、命中哪条规则。</p></div></div>
      <div class="toolbar">
        <input type="search" id="conn-q" placeholder="按域名、规则或进程筛选" aria-label="筛选连接" value="${esc(state.connFilter)}">
        <span class="grow faint" id="conn-count"></span>
        <button class="btn" data-busy="flush" id="conn-flush">${icon("x")}断开全部</button>
      </div>
      <div class="card table-wrap"><table class="table"><thead><tr><th>目标</th><th>线路</th><th>规则</th><th class="num">上传</th><th class="num">下载</th><th></th></tr></thead><tbody id="conn-body"></tbody></table></div>`;
    $("#conn-q", el).addEventListener("input", (e) => { state.connFilter = e.target.value; renderConnections(false); });
    $("#conn-flush", el).addEventListener("click", () => run("flush", () => api("FlushConnections"), "已断开全部连接"));
    renderBusy();
  }
  const c = state.conns;
  const body = $("#conn-body", el);
  if (!c) { body.innerHTML = `<tr><td colspan="6" class="muted">正在读取…</td></tr>`; return; }
  if (c.error) { body.innerHTML = `<tr><td colspan="6" class="muted">${esc(c.error)}</td></tr>`; return; }
  const q = state.connFilter.trim().toLowerCase();
  const list = (c.connections || []).filter((x) => !q || [x.host, x.rule, x.rulePayload, x.process, x.chain].join(" ").toLowerCase().includes(q));
  $("#conn-count", el).textContent = `${list.length} 条连接`;
  body.innerHTML = list.length ? list.slice(0, 400).map((x) => `
    <tr><td><div>${esc(x.host || x.destination)}</div><div class="faint">${esc([x.network, x.process].filter(Boolean).join(" · "))}</div></td>
    <td><span class="tag tone-${routeTone(x.route)}">${routeName(x.route)}</span><div class="faint">${esc(x.chain)}</div></td>
    <td class="faint">${esc(x.rule)}${x.rulePayload ? `<br>${esc(x.rulePayload)}` : ""}</td>
    <td class="num">${fmtBytes(x.upload)}</td><td class="num">${fmtBytes(x.download)}</td>
    <td><button class="btn subtle" aria-label="断开 ${esc(x.host || x.destination)}" data-close="${esc(x.id)}">${icon("x")}</button></td></tr>`).join("")
    : `<tr><td colspan="6" class="muted">没有连接</td></tr>`;
}

$("#page-connections").addEventListener("click", (e) => {
  const b = e.target.closest("[data-close]");
  if (b) run(`close-${b.dataset.close}`, () => api("CloseConnection", b.dataset.close));
});

// ----- 订阅 -----

function renderSubscription(force) {
  const el = $("#page-subscription");
  const st = state.ui.status;
  const sub = st?.subscription;
  if (force || el.dataset.sub !== JSON.stringify(sub ?? null)) {
    el.dataset.sub = JSON.stringify(sub ?? null);
    const u = sub?.usage;
    const used = u ? u.upload + u.download : 0;
    const pct = u && u.total > 0 ? Math.min(100, Math.round((used / u.total) * 100)) : null;
    el.innerHTML = `
      <div class="page-head"><div><h1 id="h-subscription">订阅</h1><p class="lede">粘贴机场的 Clash / mihomo 订阅链接。链接本身就是凭据，界面和日志只显示脱敏后的地址。</p></div></div>
      <div class="card pad">
        <label for="sub-url" class="row-title">订阅链接</label>
        <div class="input-row" style="margin-top:8px">
          <input type="url" id="sub-url" placeholder="https://…" autocomplete="off" spellcheck="false">
          <button class="btn primary" data-busy="import" id="sub-import">${icon("download")}${sub ? "替换订阅" : "导入"}</button>
        </div>
        <p class="faint" style="margin:8px 0 0">熔断期间也能下载：内核自己的直连入站不经过闸门。下载到的订阅解析出 0 个节点时自动回滚，不会覆盖能用的旧订阅。</p>
      </div>
      ${sub ? `
      <h2>当前订阅</h2>
      <div class="card">
        <div class="row"><div class="row-text"><div class="row-title">${esc(sub.name || "未命名订阅")}</div><div class="row-desc mono">${esc(state.ui.subMaskedUrl || "")}</div></div>
          <button class="btn" data-busy="refresh" id="sub-refresh">${icon("refresh")}立即更新</button>
          <button class="btn subtle" data-busy="remove" id="sub-remove">${icon("trash")}移除</button></div>
        <div class="row"><div class="row-text"><div class="row-title">节点</div><div class="row-desc">${sub.nodeCount} 个，更新于 ${fmtAgo(sub.lastUpdated)}${sub.lastError ? `；上次更新失败：${esc(sub.lastError)}` : ""}</div></div></div>
        ${u ? `<div class="row"><div class="row-text"><div class="row-title">流量</div>
          <div class="row-desc">已用 ${fmtBytes(used)}${u.total ? ` / ${fmtBytes(u.total)}` : ""}${u.expire ? `，${new Date(u.expire * 1000).toLocaleDateString("zh-CN")} 到期` : ""}</div>
          ${pct != null ? `<div class="progress ${pct > 90 ? "tone-danger" : "tone-ok"}" style="max-width:none"><div style="width:${pct}%"></div></div>` : ""}</div></div>` : ""}
        <div class="row"><div class="row-text"><div class="row-title">自动更新间隔</div><div class="row-desc">每隔这么久在后台更新一次订阅</div></div>
          <select id="sub-hours" aria-label="自动更新间隔">${[6, 12, 24, 48, 168].map((h) => `<option value="${h}" ${state.settings?.subscriptionUpdateHours === h ? "selected" : ""}>${h < 24 ? `${h} 小时` : `${h / 24} 天`}</option>`).join("")}</select></div>
      </div>` : `
      <div class="empty">${icon("sub")}<div>还没有订阅</div><p class="faint">没有订阅时处于「直连阻断 AI」：只放行大陆网站，所有 AI 服务被拒绝。</p></div>`}`;
    $("#sub-import", el).addEventListener("click", () => {
      const url = $("#sub-url", el).value.trim();
      if (!url) { toast("先粘贴订阅链接", "warn"); return; }
      run("import", async () => { const r = await api("ImportSubscription", url); $("#sub-url", el).value = ""; return r; }, "订阅已导入");
    });
    $("#sub-url", el).addEventListener("keydown", (e) => { if (e.key === "Enter") $("#sub-import", el).click(); });
    $("#sub-refresh", el)?.addEventListener("click", () => run("refresh", () => api("RefreshSubscription"), "订阅已更新"));
    $("#sub-remove", el)?.addEventListener("click", () =>
      confirmDialog({ title: "移除订阅？", text: "移除后进入「直连阻断 AI」：只放行大陆网站，所有 AI 服务被拒绝。", ok: "移除", danger: true })
        .then((yes) => yes && run("remove", () => api("RemoveSubscription"), "订阅已移除")));
    $("#sub-hours", el)?.addEventListener("change", (e) => saveSettings({ subscriptionUpdateHours: Number(e.target.value) }));
    renderBusy();
  }
}

// ----- AI 名单 -----

function listEditor(id, title, desc, key, placeholder) {
  const v = (state.settings?.[key] || []).join("\n");
  return `<div class="card pad" style="margin-top:4px">
    <label for="${id}" class="row-title">${esc(title)}</label><div class="row-desc muted" style="margin:2px 0 8px">${esc(desc)}</div>
    <textarea id="${id}" data-list="${key}" spellcheck="false" placeholder="${esc(placeholder)}">${esc(v)}</textarea>
    <div style="display:flex;justify-content:flex-end;margin-top:8px"><button class="btn" data-save-list="${id}">保存</button></div></div>`;
}

function renderRules(force) {
  const el = $("#page-rules");
  if (!force) return;
  const cats = state.meta?.categories || [];
  const off = new Set(state.settings?.disabledAICategories || []);
  el.innerHTML = `
    <div class="page-head"><div><h1 id="h-rules">AI 名单</h1><p class="lede">名单里的流量在任何模式下都不会直连：代理模式走「节点选择」，直连模式直接拒绝。宁可错杀。</p></div></div>
    <div class="card">${cats.map((c) => `
      <div class="row"><div class="row-text"><div class="row-title">${esc(c.name)}${c.strict ? ` <span class="tag tone-warn">严格</span>` : ""}</div>
        <div class="row-desc">${esc(c.note)} · ${c.ruleCount} 条规则</div></div>
        <label class="switch"><span class="state">${off.has(c.id) ? "关" : "开"}</span><input type="checkbox" role="switch" data-cat="${esc(c.id)}" ${off.has(c.id) ? "" : "checked"} aria-label="${esc(c.name)}"></label></div>`).join("")}</div>
    <h2>自定义</h2>
    ${listEditor("ai-domains", "额外的 AI 域名", "每行一个域名，含全部子域名", "customAIDomains", "example-ai.com")}
    ${listEditor("direct-domains", "直连域名", "智能分流下直连（不经代理）。AI 名单优先，不会被这里放行", "customDirectDomains", "intranet.example.com")}
    ${listEditor("proxy-domains", "强制代理域名", "纠正大陆名单误收的境外站点：这些域名在智能分流下也走代理", "customProxyDomains", "example.org")}
    ${listEditor("extra-procs", "额外的 AI 程序", "每行一个进程名，例如 myagent.exe；关键词识别不到的 AI 程序写在这里：熔断时关闭，游戏模式下禁止直连", "extraAIProcesses", "myagent.exe")}`;
}

$("#page-rules").addEventListener("change", (e) => {
  const cb = e.target.closest("[data-cat]");
  if (!cb) return;
  const off = new Set(state.settings?.disabledAICategories || []);
  if (cb.checked) off.delete(cb.dataset.cat); else off.add(cb.dataset.cat);
  cb.previousElementSibling.textContent = cb.checked ? "开" : "关";
  saveSettings({ disabledAICategories: [...off] });
});
$("#page-rules").addEventListener("click", (e) => {
  const b = e.target.closest("[data-save-list]");
  if (!b) return;
  const ta = document.getElementById(b.dataset.saveList);
  const list = ta.value.split(/[\s,，]+/).map((s) => s.trim()).filter(Boolean);
  saveSettings({ [ta.dataset.list]: list }, "已保存").then(() => {
    // 服务端会清洗非法条目，回填清洗后的结果
    ta.value = (state.settings?.[ta.dataset.list] || []).join("\n");
  });
});

// ----- 熔断与安全 -----

function toggleRow(key, title, desc, opts = {}) {
  const on = !!state.settings?.[key];
  return `<div class="row ${opts.disabled ? "disabled" : ""}"><div class="row-text"><div class="row-title">${esc(title)}</div><div class="row-desc">${esc(desc)}</div></div>
    <label class="switch"><span class="state">${on ? "开" : "关"}</span><input type="checkbox" role="switch" data-key="${key}" ${on ? "checked" : ""} ${opts.disabled ? "disabled" : ""} aria-label="${esc(title)}"></label></div>`;
}
function numberRow(key, title, desc, min, max, unit) {
  return `<div class="row"><div class="row-text"><div class="row-title">${esc(title)}</div><div class="row-desc">${esc(desc)}</div></div>
    <input type="number" data-num="${key}" min="${min}" max="${max}" value="${state.settings?.[key] ?? ""}" aria-label="${esc(title)}"><span class="muted">${esc(unit)}</span></div>`;
}
function segRow(key, title, desc, options) {
  const v = state.settings?.[key];
  return `<div class="row"><div class="row-text"><div class="row-title">${esc(title)}</div><div class="row-desc">${esc(desc)}</div></div>
    <div class="segmented" role="group" aria-label="${esc(title)}">${options.map(([val, label]) => `<button type="button" data-seg="${key}" data-val="${val}" aria-pressed="${v === val}">${esc(label)}</button>`).join("")}</div></div>`;
}

function renderSecurity(force) {
  const el = $("#page-security");
  if (!force) return;
  const s = state.settings;
  if (!s) { el.innerHTML = `<div class="empty">正在读取设置…</div>`; return; }
  const regions = state.meta?.regions || [];
  const forbidden = s.forbiddenRegions || [];
  el.innerHTML = `
    <div class="page-head"><div><h1 id="h-security">熔断与安全</h1><p class="lede">默认都是最严格的选项；放宽任何一项都会让 AI 有机会看到真实 IP。</p></div></div>
    <div class="card">
      <div class="row"><div class="row-icon">${icon("shield")}</div><div class="row-text"><div class="row-title">守护</div>
        <div class="row-desc">${s.enabled ? "TUN 接管、WFP 防火墙、DNS/IPv6 锁定都在工作" : "已关闭：网络恢复原样，AI 不受保护"}</div></div>
        <button class="btn ${s.enabled ? "danger" : "primary"}" data-busy="enable" id="sec-enable">${s.enabled ? "关闭守护" : "开启守护"}</button></div>
      ${segRow("mode", "出站模式", "没有订阅时总是直连阻断 AI", [["proxy", "代理"], ["direct", "直连阻断 AI"]])}
      ${segRow("routing", "分流方式", "智能分流：AI 走代理、大陆直连、其余走代理；全局：除局域网外全走代理", [["smart", "智能分流"], ["global", "全局代理"]])}
    </div>

    <h2>熔断</h2>
    <div class="card">
      ${toggleRow("fuseEnabled", "启用熔断", "心跳中断、节点连不上、出口落在禁区、内核或 TUN 异常、IPv6 泄漏时立即熔断")}
      ${segRow("fuseAction", "熔断方式", "大陆白名单由内核按域名、防火墙按 IP 双重把关；全部断网只留回环、局域网和 DHCP", [["whitelist", "大陆白名单"], ["cutAll", "全部断网"]])}
      ${toggleRow("autoRecover", "自动恢复", "线路恢复且出口验证通过后自动解除；关闭后需要手动解除")}
      ${toggleRow("autoSwitchUnsafeNode", "出口在禁区时自动换节点", "逐个尝试其他节点，找到出口安全的就固定下来")}
      ${toggleRow("closeAppsOnFuse", "熔断时关闭 AI 程序与浏览器", "熔断瞬间关一次浏览器；熔断期间每 3 秒清理一次 AI 进程（含 node/python 跑的 Claude Code、Codex）")}
      ${toggleRow("closeAppsOnGuardTrips", "启动、换网、唤醒时也关闭", "这类保护性熔断发生时防火墙已只放行大陆，默认不关应用，免得每次开盖都关掉浏览器", { disabled: !s.closeAppsOnFuse })}
      ${numberRow("probeIntervalSeconds", "心跳间隔", "经代理的长连接每隔多久心跳一次并校验出口国家", 1, 10, "秒")}
      ${numberRow("failureThreshold", "连续失败次数", "心跳连续失败这么多次即熔断", 1, 20, "次")}
      ${numberRow("latencyThresholdMs", "心跳超时", "单次心跳超过这个时间算失败", 300, 10000, "毫秒")}
      ${numberRow("recoverSuccesses", "恢复所需成功次数", "熔断后连续成功这么多次并验证出口才解除", 1, 30, "次")}
      ${numberRow("wakeHoldSeconds", "唤醒与换网保持", "合盖唤醒、网络切换后至少保持熔断这么久", 0, 60, "秒")}
    </div>

    <h2>出口禁区</h2>
    <div class="card pad">
      <div class="row-desc muted" style="margin-bottom:10px">出口落在这些地区就熔断，名字里带这些地区的节点也不会被自动选中。中国大陆不可移除。</div>
      <div class="chips" id="sec-regions">${forbidden.map((r) => `<span class="chip ${r === "CN" ? "locked" : ""}">${esc(region(r))}<span class="faint">${esc(r)}</span>${r === "CN" ? "" : `<button aria-label="移除 ${esc(region(r))}" data-unforbid="${esc(r)}">${icon("x")}</button>`}</span>`).join("")}</div>
      <div class="input-row" style="margin-top:12px;max-width:360px">
        <select id="sec-add-region" aria-label="添加禁区地区"><option value="">添加地区…</option>${regions.filter((r) => !forbidden.includes(r.code)).map((r) => `<option value="${esc(r.code)}">${esc(r.name)}（${esc(r.code)}）</option>`).join("")}</select>
      </div>
    </div>

    <h2>防泄漏</h2>
    <div class="card">
      ${toggleRow("leakGuard", "拦截绕过 TUN 的流量", "普通程序直连外网一律丢弃；服务崩溃时这层规则也不会撤销")}
      ${toggleRow("directOnlyMainland", "直连模式只放行大陆", "名单之外的 AI 服务也无法直连")}
      ${toggleRow("lockSystemDns", "锁定系统 DNS", "把各网卡 DNS 锁到内核，关闭守护时恢复原设置")}
      ${toggleRow("disableSystemIPv6", "关闭网卡 IPv6", "防火墙已拒绝全部 IPv6 出站；这里再关闭网卡的 IPv6 协议，关闭守护时恢复")}
    </div>

    <h2>游戏模式</h2>
    <div class="card">
      ${toggleRow("gameAutoDetect", "检测到游戏或加速器时自动开启", "默认关闭。开启后，游戏本体在运行（启动器和平台组件不算）或 UU、雷神、迅游、奇游在运行时自动进入，退出 1 分钟后自动恢复")}
      ${toggleRow("gameMode", "开启游戏模式", "一直保持，直到在这里或托盘菜单里关闭")}
      <div class="row"><div class="row-text"><div class="row-desc">游戏模式下 AI 服务一律禁止：AI 程序立即关闭、再打开也会被关掉，并且禁止联网；浏览器里的 AI 网站全部拒绝，AI 服务的 IP 段对所有程序禁止直连。其余流量直连不走代理（不加代理延迟、不耗流量），TUN 不抢加速器的路由与 DNS。</div></div></div>
    </div>
    ${listEditor("extra-games", "额外的游戏程序", "每行一个进程名，例如 mygame.exe；识别不到的游戏写在这里", "extraGameProcesses", "mygame.exe")}

    <h2>应用</h2>
    <div class="card">
      <div class="row"><div class="row-text"><div class="row-title">登录时启动界面</div><div class="row-desc">防护服务总是随系统启动；这里只控制托盘界面</div></div>
        <label class="switch"><span class="state" id="auto-state">…</span><input type="checkbox" role="switch" id="sec-autostart" aria-label="登录时启动界面"></label></div>
      <div class="row"><div class="row-text"><div class="row-title">防护服务</div><div class="row-desc">版本 ${esc(state.ui.service.version || "—")} · 防火墙 ${esc(policyName(state.ui.status?.firewallPolicy))}</div></div>
        <button class="btn" data-busy="logs" id="sec-logs">打开日志目录</button>
        <button class="btn subtle" data-busy="uninstall" id="sec-uninstall">${icon("trash")}卸载服务</button></div>
    </div>`;

  api("Autostart").then((on) => { $("#sec-autostart", el).checked = on; $("#auto-state", el).textContent = on ? "开" : "关"; }).catch(() => {});
  $("#sec-autostart", el).addEventListener("change", (e) => {
    const on = e.target.checked;
    $("#auto-state", el).textContent = on ? "开" : "关";
    run("autostart", () => api("SetAutostart", on));
  });
  $("#sec-enable", el).addEventListener("click", async () => {
    if (s.enabled) {
      const yes = await confirmDialog({ title: "关闭守护？", text: "防火墙、TUN、DNS 锁定全部撤销，AI 服务将直接看到你的真实 IP。", ok: "关闭守护", danger: true });
      if (!yes) return;
    }
    saveSettings({ enabled: !s.enabled }, s.enabled ? "守护已关闭" : "守护已开启", "enable");
  });
  $("#sec-add-region", el).addEventListener("change", (e) => {
    if (e.target.value) saveSettings({ forbiddenRegions: [...forbidden, e.target.value] });
  });
  $("#sec-logs", el).addEventListener("click", () => run("logs", () => api("OpenLogs")));
  $("#sec-uninstall", el).addEventListener("click", async () => {
    const yes = await confirmDialog({ title: "卸载防护服务？", text: "会删除防火墙规则、恢复 DNS 与 IPv6 设置并停止服务。设置和订阅保留在 C:\\ProgramData\\AIGuard，重新安装后可继续使用。", ok: "卸载", danger: true });
    if (yes) run("uninstall", () => api("UninstallService", false), "防护服务已卸载");
  });
  renderBusy();
}

$("#page-security").addEventListener("change", (e) => {
  const t = e.target;
  if (t.dataset.key) saveSettings({ [t.dataset.key]: t.checked });
  if (t.dataset.num) {
    const v = Math.round(Number(t.value));
    if (Number.isFinite(v)) saveSettings({ [t.dataset.num]: v });
  }
});
$("#page-security").addEventListener("click", (e) => {
  const seg = e.target.closest("[data-seg]");
  if (seg) saveSettings({ [seg.dataset.seg]: seg.dataset.val });
  const un = e.target.closest("[data-unforbid]");
  if (un) saveSettings({ forbiddenRegions: (state.settings.forbiddenRegions || []).filter((r) => r !== un.dataset.unforbid) });
  const save = e.target.closest("[data-save-list]");
  if (save) {
    const ta = document.getElementById(save.dataset.saveList);
    // 游戏进程名常带空格（League of Legends.exe），只按换行和逗号分隔
    const list = ta.value.split(/[\n,，]+/).map((x) => x.trim()).filter(Boolean);
    saveSettings({ [ta.dataset.list]: list }, "已保存");
  }
});

// 设置统一走这里：基于最新设置打补丁，提交后用服务端清洗过的结果回填并重绘
async function saveSettings(patch, okMessage, busyKey = "settings") {
  if (!state.settings) return;
  const next = { ...state.settings, ...patch };
  const r = await run(busyKey, () => api("SaveSettings", next), okMessage);
  if (r?.settings) state.settings = r.settings;
  else await loadSettings();
  renderPage(true);
}

async function loadSettings() {
  try { state.settings = await api("Settings"); } catch { /* 服务未运行时保留旧值 */ }
}

// ----- 事件 -----

const levelName = { info: "信息", warning: "警告", critical: "严重" };
const levelTone = { info: "info", warning: "warn", critical: "danger" };

async function loadEvents() {
  try {
    const r = await api("Events", state.eventsCursor);
    if (r.eventsGeneration !== state.eventsGeneration) {
      // 服务重启或清空过，旧游标作废
      state.eventsGeneration = r.eventsGeneration;
      state.events = [];
      state.eventsCursor = 0;
    }
    const fresh = r.events || [];
    if (fresh.length) {
      const known = new Set(state.events.map((x) => x.id));
      const added = fresh.filter((x) => !known.has(x.id));
      state.events = [...state.events, ...added].slice(-500);
      state.eventsCursor = Math.max(state.eventsCursor, ...fresh.map((x) => x.id));
      if (state.page !== "events" && state.events.length !== added.length) {
        state.unreadCritical += added.filter((x) => x.level === "critical").length;
      }
      renderBadge();
      if (state.page === "events") renderEvents(false);
    }
  } catch { /* 服务未运行 */ }
}

function renderBadge() {
  const b = $("#events-badge");
  b.hidden = state.unreadCritical === 0;
  b.textContent = state.unreadCritical > 99 ? "99+" : String(state.unreadCritical);
}

function renderEvents(force) {
  const el = $("#page-events");
  if (force) {
    el.innerHTML = `
      <div class="page-head"><div><h1 id="h-events">事件</h1><p class="lede">熔断与恢复、节点切换、出口变化、订阅更新都记在这里。</p></div></div>
      <div class="toolbar">
        <div class="segmented" role="group" aria-label="级别">${[["all", "全部"], ["warning", "警告及以上"], ["critical", "严重"]].map(([v, l]) => `<button type="button" data-level="${v}" aria-pressed="${state.eventFilter.level === v}">${l}</button>`).join("")}</div>
        <input type="search" id="ev-q" placeholder="搜索事件" aria-label="搜索事件" value="${esc(state.eventFilter.q)}">
        <span class="grow"></span>
        <button class="btn" id="ev-copy">${icon("copy")}复制</button>
        <button class="btn subtle" data-busy="clear" id="ev-clear">${icon("trash")}清空</button>
      </div>
      <div class="card"><ul class="events" id="ev-list" aria-live="polite"></ul></div>`;
    $("#ev-q", el).addEventListener("input", (e) => { state.eventFilter.q = e.target.value; renderEvents(false); });
    el.querySelectorAll("[data-level]").forEach((b) => b.addEventListener("click", () => { state.eventFilter.level = b.dataset.level; renderEvents(true); }));
    $("#ev-copy", el).addEventListener("click", () => {
      const text = filteredEvents().map((x) => `${fmtTime(x.at, true)} [${levelName[x.level]}] ${x.message}`).join("\n");
      navigator.clipboard.writeText(text).then(() => toast("已复制到剪贴板"), () => toast("复制失败", "danger"));
    });
    $("#ev-clear", el).addEventListener("click", async () => {
      const yes = await confirmDialog({ title: "清空事件？", text: "事件页和服务保存的事件列表会一起清空，无法恢复；C:\\ProgramData\\AIGuard\\logs 下的运行日志不受影响。", ok: "清空", danger: true });
      if (yes) run("clear", async () => { await api("ClearEvents"); state.events = []; renderEvents(false); }, "事件已清空");
    });
    renderBusy();
  }
  const list = filteredEvents();
  $("#ev-list", el).innerHTML = list.length ? list.slice().reverse().map((x) => `
    <li class="tone-${levelTone[x.level]}"><span class="dot" aria-label="${levelName[x.level]}"></span><time datetime="${new Date(x.at).toISOString()}">${fmtTime(x.at, true)}</time><span>${esc(x.message)}</span></li>`).join("")
    : `<li style="display:block"><div class="empty">${icon("list")}<div>${state.events.length ? "没有符合条件的事件" : "还没有事件"}</div></div></li>`;
}

function filteredEvents() {
  const { level, q } = state.eventFilter;
  const rank = { info: 0, warning: 1, critical: 2 };
  const min = level === "all" ? 0 : rank[level];
  const needle = q.trim().toLowerCase();
  return state.events.filter((x) => rank[x.level] >= min && (!needle || x.message.toLowerCase().includes(needle)));
}

const renderers = {
  overview: renderOverview,
  nodes: renderNodes,
  connections: renderConnections,
  subscription: renderSubscription,
  rules: renderRules,
  security: renderSecurity,
  events: renderEvents,
};

// ---------- 轮询 ----------

let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const prev = state.ui;
    state.ui = await api("State");
    const becameReady = state.ui.service.running && !(prev?.service.running);
    if (becameReady || !state.settings) await loadSettings();
    if (!state.meta) state.meta = await api("Meta");
    $("#brand-version").textContent = `v${state.ui.version}`;
    if (becameReady && state.page !== "overview") renderPage(true);
    else renderPage(!prev || prev.service.installed !== state.ui.service.installed || prev.service.outdated !== state.ui.service.outdated);
  } catch (e) {
    state.ui = state.ui || null;
  } finally {
    refreshing = false;
  }
}

async function pollTraffic() {
  if (state.page !== "overview" && state.page !== "connections") return;
  if (!state.ui?.status?.coreRunning) return;
  await loadConns();
  const c = state.conns;
  if (c && !c.error) {
    const now = Date.now();
    if (state.lastTotals) {
      const dt = (now - state.lastTotals.at) / 1000;
      if (dt > 0) {
        state.traffic.push({ at: now, up: Math.max(0, (c.uploadTotal - state.lastTotals.up) / dt), down: Math.max(0, (c.downloadTotal - state.lastTotals.down) / dt) });
        state.traffic = state.traffic.slice(-60);
      }
    }
    state.lastTotals = { at: now, up: c.uploadTotal, down: c.downloadTotal };
  }
  if (state.page === "connections") renderConnections(false);
  else updateTrafficChart();
}

// 窗口被系统主题切换时重绘图表配色
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => renderPage(true));

// Go 侧检测不到 Mica（Windows 10）时通知页面用实色背景
Events.On("aiguard:no-mica", () => document.body.classList.add("no-mica"));
Events.On("aiguard:show", (ev) => { if (ev?.data) showPage(ev.data); });

refresh().then(() => renderPage(true));
setInterval(refresh, 1000);
setInterval(pollTraffic, 1000);
setInterval(loadEvents, 2000);
loadEvents();
