import AIGuardCore
import ServiceManagement
import SwiftUI

struct SecurityView: View {
    @Environment(GuardStore.self) private var store
    @State private var confirmDisable = false

    var body: some View {
        ScrollView {
            if let s = store.settings {
                VStack(alignment: .leading, spacing: 16) {
                    GlassCard(tint: s.fuseEnabled ? nil : Palette.caution) {
                        VStack(alignment: .leading, spacing: 14) {
                            Toggle(isOn: bind(\.fuseEnabled)) {
                                SectionHeader(title: "熔断模式", subtitle: "长连接心跳中断、合盖唤醒、切换网络、出口落在禁区、内核/TUN 异常、IPv6 泄漏时自动断网")
                            }
                            .toggleStyle(.switch)
                            Picker("熔断时", selection: bind(\.fuseAction)) {
                                Text("大陆白名单：只放行大陆域名和 IP（推荐）").tag(FuseAction.whitelist)
                                Text("切断全部网络").tag(FuseAction.cutAll)
                            }
                            .pickerStyle(.radioGroup)
                            Text("白名单由内核按域名、防火墙按 IP 双重把关：内核或 TUN 出故障时防火墙仍只放行大陆 IP。内核只额外保留连节点和订阅服务器的权限，用于恢复和更新订阅。")
                                .font(.caption).foregroundStyle(.secondary)
                            switchRow("线路恢复稳定后自动解除熔断", \.autoRecover)
                            switchRow("出口落在禁区时自动寻找安全节点", \.autoSwitchUnsafeNode)
                            switchRow("熔断时关闭 AI 进程和浏览器（熔断期间持续清理 AI 进程）", \.closeAppsOnFuse)
                            switchRow("合盖唤醒、换网、启动这类保护性熔断也关闭", \.closeAppsOnGuardTrips)
                                .disabled(!s.closeAppsOnFuse)
                            Text("保护性熔断发生时防火墙已全部断网，默认不关应用，免得每次开盖都关掉浏览器。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        .disabled(store.busy.contains("settings"))
                    }

                    GlassCard {
                        VStack(alignment: .leading, spacing: 12) {
                            SectionHeader(title: "判定阈值", subtitle: "数值越保守越安全，但误判断网也越多")
                            stepper("长连接每 \(s.probeIntervalSeconds) 秒心跳一次（同时校验出口）", \.probeIntervalSeconds, 1...10)
                            stepper("心跳连续失败 \(s.failureThreshold) 次即熔断", \.failureThreshold, 1...20)
                            stepper("心跳超过 \(s.latencyThresholdMs) ms 视为失败", \.latencyThresholdMs, 300...10000, step: 100)
                            stepper("恢复前需连续成功 \(s.recoverSuccesses) 次", \.recoverSuccesses, 1...30)
                            stepper("唤醒后至少保持断网 \(s.wakeHoldSeconds) 秒", \.wakeHoldSeconds, 0...120)
                        }
                    }

                    GlassCard {
                        VStack(alignment: .leading, spacing: 12) {
                            SectionHeader(title: "出口禁区", subtitle: "出口国家落在这里即熔断，这些地区的节点也不会被自动选中。中国大陆始终包含在内。")
                            RegionEditor(title: "禁区", regions: s.forbiddenRegions) { r in
                                store.updateSettings { $0.forbiddenRegions = r }
                            }
                        }
                    }

                    GlassCard {
                        VStack(alignment: .leading, spacing: 12) {
                            Toggle(isOn: bind(\.leakGuard)) {
                                SectionHeader(title: "防泄漏防火墙", subtitle: "平时就用 pf 拦截绕过 TUN 的直连流量；IPv6 与明文 DNS 不论开关始终封锁；守护进程崩溃时规则仍然保留")
                            }
                            .toggleStyle(.switch)
                            switchRow("直连模式只放行大陆网站（名单外的 AI 也无法直连）", \.directOnlyMainland)
                            switchRow("守护开启时关闭系统 IPv6（关闭守护或卸载时恢复）", \.disableSystemIPv6)
                            switchRow("守护开启时锁定系统 DNS 到 TUN（关闭守护或卸载时恢复）", \.lockSystemDNS)
                            HStack {
                                Text("本地代理端口")
                                Spacer()
                                TextField("", value: bind(\.mixedPort), format: .number.grouping(.never))
                                    .frame(width: 80).textFieldStyle(.roundedBorder)
                                Button("复制终端代理命令") { store.copyTerminalProxy() }.buttonStyle(.glass)
                            }
                        }
                    }

                    LaunchAtLoginCard()

                    GlassCard(tint: Palette.danger) {
                        HStack {
                            SectionHeader(title: "关闭全部守护", subtitle: "停止内核、撤销 TUN 和防火墙。出差期间不建议关闭。")
                            Spacer()
                            if s.enabled {
                                Button("关闭守护", role: .destructive) { confirmDisable = true }.buttonStyle(.glass)
                            } else {
                                Button("开启守护") { store.updateSettings { $0.enabled = true } }.buttonStyle(.glassProminent)
                            }
                        }
                    }
                }
                .padding(24)
            }
        }
        .navigationTitle("熔断与安全")
        .confirmationDialog("关闭后 AI 服务将不再受保护，可能直接暴露真实 IP。确定关闭吗？", isPresented: $confirmDisable) {
            Button("关闭守护", role: .destructive) { store.updateSettings { $0.enabled = false } }
        }
    }

    private func bind<T>(_ key: WritableKeyPath<GuardSettings, T>) -> Binding<T> {
        Binding(get: { store.settings![keyPath: key] }, set: { v in store.updateSettings { $0[keyPath: key] = v } })
    }

    private func stepper(_ label: String, _ key: WritableKeyPath<GuardSettings, Int>, _ range: ClosedRange<Int>, step: Int = 1) -> some View {
        HStack {
            Text(label).monospacedDigit()
            Spacer()
            Stepper(label, value: bind(key), in: range, step: step).labelsHidden()
        }
    }

    private func switchRow(_ label: String, _ key: WritableKeyPath<GuardSettings, Bool>) -> some View {
        HStack {
            Text(label)
            Spacer()
            Toggle(label, isOn: bind(key)).toggleStyle(.switch).labelsHidden()
        }
    }
}

private struct LaunchAtLoginCard: View {
    @Environment(GuardStore.self) private var store

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 10) {
                Toggle(isOn: Binding(get: { store.launchAtLogin == .enabled || store.launchAtLogin == .requiresApproval },
                                     set: { store.setLaunchAtLogin($0) })) {
                    SectionHeader(title: "登录时启动",
                                  subtitle: "登录后自动在菜单栏运行，随时看到防护状态。守护进程和熔断保护本来就随开机运行，关掉这里不影响保护。")
                }
                .toggleStyle(.switch)
                if store.launchAtLogin == .requiresApproval {
                    HStack(spacing: 10) {
                        Label("需要在系统设置里允许", systemImage: "exclamationmark.triangle")
                            .font(.callout).foregroundStyle(Palette.caution)
                        Button("打开登录项设置") { SMAppService.openSystemSettingsLoginItems() }
                            .buttonStyle(.glass)
                    }
                }
            }
        }
        // 用户可能刚在系统设置里改过，回到页面时重新读一次
        .onAppear { store.refreshLaunchAtLogin() }
    }
}

private struct RegionEditor: View {
    var title: String
    var regions: [String]
    var save: ([String]) -> Void
    @State private var input = ""

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            Text(title).frame(width: 96, alignment: .leading)
            ForEach(regions, id: \.self) { r in
                HStack(spacing: 4) {
                    Text("\(RegionNames.flag(r)) \(RegionNames.name(r))").font(.callout)
                    if r != "CN" {
                        Button { save(regions.filter { $0 != r }) } label: { Image(systemName: "xmark.circle.fill") }
                            .buttonStyle(.plain).foregroundStyle(.secondary)
                            .accessibilityLabel("移除 \(RegionNames.name(r))")
                    }
                }
                .padding(.horizontal, 10).padding(.vertical, 5)
                .glassEffect(.regular, in: .capsule)
            }
            TextField("国家代码，如 RU", text: $input)
                .textFieldStyle(.roundedBorder)
                .frame(width: 130)
                .onSubmit {
                    let code = input.trimmingCharacters(in: .whitespaces).uppercased()
                    if code.count == 2, !regions.contains(code) { save(regions + [code]) }
                    input = ""
                }
            Spacer()
        }
    }
}

struct EventsView: View {
    @Environment(GuardStore.self) private var store
    @State private var level: EventFilter = .all
    @State private var search = ""
    @State private var confirmClear = false

    private var filtered: [GuardEvent] {
        store.events.reversed().filter { e in
            level.includes(e.level) && (search.isEmpty || e.message.localizedCaseInsensitiveContains(search))
        }
    }

    var body: some View {
        let list = filtered
        let sections = Self.groupByDay(list)
        VStack(alignment: .leading, spacing: 14) {
            header(shown: list.count)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 18, pinnedViews: []) {
                    ForEach(sections, id: \.day) { section in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(Self.dayTitle(section.day)).font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                                .accessibilityAddTraits(.isHeader)
                            // 同一天的事件放在一张卡片里，用分隔线区分，避免满屏玻璃块
                            VStack(spacing: 0) {
                                ForEach(Array(section.events.enumerated()), id: \.element.id) { i, e in
                                    if i > 0 { Divider().opacity(0.5).padding(.leading, 44) }
                                    EventRow(event: e)
                                }
                            }
                            .glassEffect(.regular, in: .rect(cornerRadius: 16))
                        }
                    }
                }
                .padding(.bottom, 24)
            }
            .overlay {
                if list.isEmpty { emptyState }
            }
        }
        .padding([.horizontal, .top], 24)
        .navigationTitle("事件")
        .toolbarBackgroundVisibility(.hidden, for: .windowToolbar)
        .searchable(text: $search, placement: .toolbar, prompt: "搜索事件内容")
        .confirmationDialog("清空全部 \(store.events.count) 条事件记录？", isPresented: $confirmClear) {
            Button("清空", role: .destructive) { Task { await store.clearEvents() } }
        } message: {
            Text("事件页和守护进程保存的事件列表会一起清空，无法恢复；/Library/Logs/AIGuard 下的运行日志不受影响。之后的新事件会照常记录。")
        }
    }

    private func header(shown: Int) -> some View {
        let warn = store.events.filter { $0.level == .warning }.count
        let crit = store.events.filter { $0.level == .critical }.count
        return HStack(spacing: 12) {
            Picker("级别", selection: $level) {
                ForEach(EventFilter.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            Text("共 \(store.events.count) 条 · 警告 \(warn) · 严重 \(crit)\(shown != store.events.count ? " · 当前显示 \(shown)" : "")")
                .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
            Spacer(minLength: 0)
            GlassEffectContainer(spacing: 8) {
                HStack(spacing: 8) {
                    Button {
                        copy(filtered)
                    } label: { Label("复制", systemImage: "doc.on.doc") }
                        .buttonStyle(.glass)
                        .disabled(shown == 0)
                        .help("复制当前显示的事件，方便反馈问题")
                    Button(role: .destructive) { confirmClear = true } label: {
                        Label("清空", systemImage: "trash")
                    }
                    .buttonStyle(.glass)
                    .disabled(store.events.isEmpty || store.busy.contains("events"))
                }
            }
        }
    }

    @ViewBuilder private var emptyState: some View {
        if store.events.isEmpty {
            ContentUnavailableView {
                Label("还没有事件", systemImage: "checkmark.seal")
            } description: {
                Text("熔断与恢复、节点切换、出口变化、订阅更新等都会记在这里。")
            }
        } else {
            ContentUnavailableView {
                Label("没有符合条件的事件", systemImage: "line.3.horizontal.decrease.circle")
            } description: {
                Text("换个关键词，或把级别切回「全部」。")
            }
        }
    }

    private func copy(_ list: [GuardEvent]) {
        let text = list.map { "\($0.at.formatted(date: .numeric, time: .standard)) [\(EventRow.levelTitle($0.level))] \($0.message)" }
            .joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        store.notice = .init(text: "已复制 \(list.count) 条事件", isError: false)
    }

    struct DaySection {
        var day: Date
        var events: [GuardEvent]
    }

    /// 输入已按时间倒序，保持顺序按自然日分组
    static func groupByDay(_ list: [GuardEvent]) -> [DaySection] {
        let cal = Calendar.current
        var out: [DaySection] = []
        for e in list {
            let day = cal.startOfDay(for: e.at)
            if out.last?.day == day { out[out.count - 1].events.append(e) } else { out.append(DaySection(day: day, events: [e])) }
        }
        return out
    }

    static func dayTitle(_ day: Date) -> String {
        let cal = Calendar.current
        if cal.isDateInToday(day) { return "今天" }
        if cal.isDateInYesterday(day) { return "昨天" }
        return day.formatted(.dateTime.month().day().weekday(.wide))
    }
}

private enum EventFilter: String, CaseIterable, Identifiable {
    case all, warnings, critical
    var id: String { rawValue }
    var title: String {
        switch self {
        case .all: return "全部"
        case .warnings: return "警告及以上"
        case .critical: return "仅严重"
        }
    }
    func includes(_ l: EventLevel) -> Bool {
        switch self {
        case .all: return true
        case .warnings: return l != .info
        case .critical: return l == .critical
        }
    }
}

private struct EventRow: View {
    var event: GuardEvent

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: Self.icon(event.level))
                .foregroundStyle(Self.color(event.level))
                .frame(width: 18)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(event.message).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                if event.level != .info {
                    Text(Self.levelTitle(event.level)).font(.caption2.weight(.bold)).foregroundStyle(Self.color(event.level))
                }
            }
            Spacer(minLength: 8)
            Text(event.at.formatted(date: .omitted, time: .standard))
                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(.rect)
        .contextMenu {
            Button("复制这条事件") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(event.message, forType: .string)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(Self.levelTitle(event.level))，\(event.message)，\(event.at.formatted(date: .abbreviated, time: .standard))")
    }

    static func levelTitle(_ l: EventLevel) -> String {
        switch l {
        case .info: return "信息"
        case .warning: return "警告"
        case .critical: return "严重"
        }
    }

    static func icon(_ l: EventLevel) -> String {
        switch l {
        case .info: return "info.circle"
        case .warning: return "exclamationmark.triangle.fill"
        case .critical: return "bolt.shield.fill"
        }
    }

    static func color(_ l: EventLevel) -> Color {
        switch l {
        case .info: return .secondary
        case .warning: return Palette.caution
        case .critical: return Palette.danger
        }
    }
}

struct MenuBarPanel: View {
    @Environment(GuardStore.self) private var store
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let s = store.status, store.daemonReachable {
                let tone = Palette.tone(for: s.phase)
                HStack(spacing: 12) {
                    Image(systemName: s.symbol).font(.largeTitle).foregroundStyle(tone)
                        .contentTransition(.symbolEffect(.replace))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(s.headline).font(.headline)
                        Text(s.fuse.reason?.title ?? (s.effectiveMode == .proxy ? (s.routing == .smart ? "智能分流" : "全局代理") : "直连阻断 AI"))
                            .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                    }
                }
                if s.effectiveMode == .proxy {
                    HStack {
                        exit("出口", s.exit)
                        Spacer()
                        Text(Format.ms(s.latency.last?.ms)).foregroundStyle(Format.delayColor(s.latency.last?.ms))
                    }
                    .font(.callout.monospacedDigit())
                }
                GlassEffectContainer(spacing: 8) {
                    HStack(spacing: 8) {
                        if s.fuse.tripped {
                            Button("重新验证") {
                                Task {
                                    await store.verify()
                                    // 菜单栏面板放不下确认框：验证失败直接打开主窗口询问
                                    if store.askRestartCore {
                                        openWindow(id: "main")
                                        NSApp.activate()
                                    }
                                }
                            }.buttonStyle(.glassProminent)
                            Button("重启内核") { Task { await store.restartCore() } }.buttonStyle(.glass)
                        } else {
                            Button("立即熔断", role: .destructive) { Task { await store.tripFuse() } }.buttonStyle(.glass)
                        }
                        Button("Wi-Fi 登录") { Task { await store.captiveLogin() } }.buttonStyle(.glass)
                    }
                }
            } else {
                Label("守护进程未运行", systemImage: "shield.slash").font(.headline)
            }
            Divider()
            HStack {
                Button("打开主窗口") {
                    openWindow(id: "main")
                    NSApp.activate()
                }
                Spacer()
                Button("退出界面") { NSApp.terminate(nil) }
                    .help("只退出界面，守护进程和熔断保护继续运行")
            }
            .buttonStyle(.borderless)
        }
        .padding(16)
        .frame(width: 320)
    }

    private func exit(_ label: String, _ e: ExitStatus) -> some View {
        Text("\(label) \(e.trace.map { "\(RegionNames.flag($0.country)) \($0.country)" } ?? "—")")
    }
}
