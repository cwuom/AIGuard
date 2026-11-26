import AIGuardCore
import Charts
import SwiftUI

struct OverviewView: View {
    @Environment(GuardStore.self) private var store

    var body: some View {
        ScrollView {
            if let s = store.status {
                VStack(spacing: 16) {
                    HeroCard(status: s)
                    ModePicker(status: s)
                    GlassEffectContainer(spacing: 16) {
                        HStack(alignment: .top, spacing: 16) {
                            ExitCard(title: "出口", symbol: "globe", exit: s.exit,
                                     forbidden: store.settings?.forbiddenRegions ?? ["CN", "HK", "MO"],
                                     active: s.effectiveMode == .proxy, heartbeat: s.heartbeatAlive)
                            TrafficCard()
                        }
                    }
                    HStack(alignment: .top, spacing: 16) {
                        LatencyCard(samples: s.latency, threshold: store.settings?.latencyThresholdMs ?? 3000)
                        HealthCard(status: s)
                            .frame(width: 300)
                    }
                    if !s.conflicts.isEmpty { ConflictCard(names: s.conflicts) }
                }
                .padding(24)
            } else {
                ProgressView("正在连接守护进程…").padding(80)
            }
        }
        .navigationTitle("总览")
        .onAppear { store.startTraffic() }
        .onDisappear { store.stopTraffic() }
        .task {
            // 总览只需要连接数，3 秒刷新一次足够
            while !Task.isCancelled {
                await store.loadConnections()
                try? await Task.sleep(for: .seconds(3))
            }
        }
    }
}

private struct HeroCard: View {
    @Environment(GuardStore.self) private var store
    var status: GuardStatus

    var body: some View {
        let tone = Palette.tone(for: status.phase)
        GlassCard(padding: 24, tint: tone) {
            HStack(spacing: 22) {
                Image(systemName: status.symbol)
                    .font(.system(size: 56, weight: .medium))
                    .foregroundStyle(tone)
                    .contentTransition(.symbolEffect(.replace))
                    .symbolEffect(.pulse, isActive: status.phase == .tripped || status.phase == .starting)
                    .frame(width: 72)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 6) {
                    Text(status.headline).font(.system(.largeTitle, design: .rounded).weight(.bold))
                    Text(subtitle).font(.callout).foregroundStyle(.secondary)
                    if status.fuse.tripped, status.fuse.recoverNeeded > 0 {
                        ProgressView(value: Double(status.fuse.recoverProgress), total: Double(status.fuse.recoverNeeded)) {
                            Text(recoveryText).font(.caption).foregroundStyle(.secondary)
                        }
                        .tint(tone)
                        .frame(maxWidth: 360)
                    }
                }
                Spacer()
                actions
            }
        }
    }

    private var subtitle: String {
        if let until = status.captiveUntil {
            return "Wi-Fi 登录模式：直连，AI 仍被阻断，\(Format.relative(until))结束"
        }
        if status.fuse.tripped, let r = status.fuse.reason {
            return r.title + (status.fuseLatched ? " · 需要手动解除" : "")
        }
        switch status.effectiveMode {
        case .proxy:
            return status.routing == .smart ? "智能分流：AI 强制走代理，大陆直连，其余代理" : "全局代理：除局域网外全部走代理"
        case .direct:
            let scope = store.settings?.directOnlyMainland == false ? "全部直连" : "只放行大陆网站"
            return status.subscription == nil ? "尚未导入订阅：\(scope)，所有 AI 服务已屏蔽" : "直连阻断：\(scope)，所有 AI 服务已屏蔽"
        }
    }

    private var recoveryText: String {
        var parts = ["线路验证 \(status.fuse.recoverProgress)/\(status.fuse.recoverNeeded)"]
        parts.append(status.fuse.geoVerified ? "出口已验证" : "等待出口验证")
        if let hold = status.fuse.holdUntil, hold > Date() { parts.append("保持期 \(Format.relative(hold))结束") }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder private var actions: some View {
        VStack(alignment: .trailing, spacing: 10) {
            if status.fuse.tripped {
                Button {
                    Task { await store.verify() }
                } label: {
                    if store.busy.contains("verify") {
                        ProgressView().controlSize(.small)
                    } else {
                        Label(status.fuseLatched ? "解锁并验证" : "立即重新验证", systemImage: "arrow.clockwise.shield")
                    }
                }
                    .buttonStyle(.glassProminent)
                    .disabled(store.busy.contains("verify"))
                Menu {
                    Button("重启内核") { Task { await store.restartCore() } }
                    Button("跳过验证，强制恢复网络", role: .destructive) { Task { await store.restore(force: true) } }
                } label: { Text("更多") }
                    .menuStyle(.button)
                    .buttonStyle(.glass)
                    .fixedSize()
            } else if status.phase == .protected {
                Button(role: .destructive) {
                    Task { await store.tripFuse() }
                } label: { Label("立即熔断", systemImage: "bolt.slash") }
                    .buttonStyle(.glass)
            }
            if !status.fuse.tripped {
                Button {
                    Task { await store.restartCore() }
                } label: { Label("重启内核", systemImage: "arrow.triangle.2.circlepath") }
                    .buttonStyle(.glass)
                    .help("其他代理软件破坏路由、或线路异常时使用。重启前会先关闭 AI 进程")
            }
            if status.captiveUntil != nil {
                Button("结束 Wi-Fi 登录") { Task { await store.endCaptive() } }.buttonStyle(.glass)
            } else {
                Button {
                    Task { await store.captiveLogin() }
                } label: { Label("酒店 Wi-Fi 登录", systemImage: "wifi.exclamationmark") }
                    .buttonStyle(.glass)
                    .help("5 分钟内全部直连以便打开认证页，AI 服务仍然被屏蔽")
            }
        }
        .disabled(store.busy.contains("fuse") || store.busy.contains("captive"))
    }
}

private struct ModePicker: View {
    @Environment(GuardStore.self) private var store
    var status: GuardStatus

    private enum Choice: CaseIterable { case smart, global, direct }

    private var current: Choice {
        guard let s = store.settings else { return .smart }
        if s.mode == .direct { return .direct }
        return s.routing == .smart ? .smart : .global
    }

    var body: some View {
        GlassEffectContainer(spacing: 12) {
            HStack(spacing: 12) {
                ForEach(Choice.allCases, id: \.self) { c in
                    tile(c)
                }
            }
        }
    }

    private func tile(_ c: Choice) -> some View {
        let (title, detail, symbol): (String, String, String) = switch c {
        case .smart: ("智能分流", "大陆直连省流量，AI 强制走代理", "arrow.triangle.branch")
        case .global: ("全局代理", "除局域网外全部走代理", "globe.asia.australia")
        case .direct: ("直连阻断 AI", "不走代理，只放行大陆，屏蔽 AI", "nosign")
        }
        let selected = current == c
        let needsSub = c != .direct && status.subscription == nil
        return Button {
            store.updateSettings { s in
                switch c {
                case .smart: s.mode = .proxy; s.routing = .smart
                case .global: s.mode = .proxy; s.routing = .global
                case .direct: s.mode = .direct
                }
            }
        } label: {
            HStack(spacing: 12) {
                Image(systemName: symbol).font(.title2).frame(width: 30)
                    .foregroundStyle(selected ? Palette.accent : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.headline)
                    Text(needsSub ? "需要先导入订阅" : detail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer(minLength: 0)
                if selected { Image(systemName: "checkmark.circle.fill").foregroundStyle(Palette.accent) }
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .glassEffect(selected ? .regular.tint(Palette.accent.opacity(0.22)).interactive() : .regular.interactive(),
                     in: .rect(cornerRadius: 18))
        .accessibilityAddTraits(selected ? .isSelected : [])
        .disabled(store.busy.contains("settings"))
    }
}

private struct ExitCard: View {
    var title: String
    var symbol: String
    var exit: ExitStatus
    var forbidden: [String]
    var active: Bool
    var heartbeat: Bool

    var body: some View {
        let country = exit.trace?.country
        let unsafe = country.map { forbidden.contains($0) } ?? false
        GlassCard(tint: unsafe ? Palette.danger : nil) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Label(title, systemImage: symbol).font(.callout.weight(.semibold)).foregroundStyle(.secondary)
                    Spacer()
                    if active {
                        Label(heartbeat ? "长连接在线" : "长连接中断", systemImage: heartbeat ? "dot.radiowaves.left.and.right" : "bolt.horizontal.circle")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(heartbeat ? Palette.safe : Palette.danger)
                            .symbolEffect(.variableColor.iterative, isActive: heartbeat)
                    }
                }
                if !active {
                    Text("未使用代理").font(.title2.weight(.semibold)).foregroundStyle(.secondary)
                    Text("直连模式不检测出口").font(.caption).foregroundStyle(.secondary)
                } else if let t = exit.trace {
                    HStack(spacing: 8) {
                        Text(RegionNames.flag(t.country)).font(.title)
                        Text(RegionNames.name(t.country)).font(.title2.weight(.semibold))
                            .foregroundStyle(unsafe ? Palette.danger : .primary)
                    }
                    Text(t.ip).font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                    Text(exit.error ?? "检测于 \(Format.relative(exit.checkedAt))").font(.caption)
                        .foregroundStyle(exit.error == nil ? Color.secondary : Palette.caution)
                } else {
                    Text("检测中…").font(.title2.weight(.semibold)).foregroundStyle(.secondary)
                    Text(exit.error ?? "等待第一次检测").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

private struct TrafficCard: View {
    @Environment(GuardStore.self) private var store

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 8) {
                Label("实时流量", systemImage: "arrow.up.arrow.down").font(.callout.weight(.semibold)).foregroundStyle(.secondary)
                HStack(spacing: 14) {
                    VStack(alignment: .leading) {
                        Text("↑ " + Format.rate(store.traffic.up)).foregroundStyle(Palette.upload)
                        Text("↓ " + Format.rate(store.traffic.down)).foregroundStyle(Palette.download)
                    }
                    .font(.system(.callout, design: .rounded).weight(.semibold))
                    .monospacedDigit()
                    Spacer()
                    VStack(alignment: .trailing) {
                        Text("\(store.connections?.connections.count ?? 0)")
                            .font(.system(.title2, design: .rounded).weight(.bold)).monospacedDigit()
                        Text("活动连接").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Chart(store.trafficHistory) { p in
                    AreaMark(x: .value("时间", p.at), y: .value("下行", p.down))
                        .foregroundStyle(Palette.download.opacity(0.35))
                    LineMark(x: .value("时间", p.at), y: .value("上行", p.up))
                        .foregroundStyle(Palette.upload)
                }
                .chartXAxis(.hidden)
                .chartYAxis(.hidden)
                .frame(height: 44)
                .accessibilityLabel("最近一分钟流量趋势")
            }
        }
    }
}

private struct LatencyCard: View {
    var samples: [LatencySample]
    var threshold: Int

    private var yMax: Int {
        let peak = samples.compactMap(\.ms).max() ?? 0
        return max(400, Int(Double(peak) * 1.4))
    }

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("长连接心跳延迟", systemImage: "waveform.path.ecg").font(.callout.weight(.semibold)).foregroundStyle(.secondary)
                    Spacer()
                    if let last = samples.last {
                        Text(Format.ms(last.ms)).foregroundStyle(Format.delayColor(last.ms))
                    }
                }
                .font(.callout.monospacedDigit())
                if samples.isEmpty {
                    Text("代理模式下经长连接每 2 秒心跳一次").font(.caption).foregroundStyle(.secondary).frame(height: 140)
                } else {
                    Chart {
                        ForEach(samples, id: \.at) { s in
                            if let v = s.ms {
                                LineMark(x: .value("时间", s.at), y: .value("毫秒", v))
                                    .foregroundStyle(Palette.accent)
                                    .interpolationMethod(.monotone)
                            } else {
                                PointMark(x: .value("时间", s.at), y: .value("毫秒", 0))
                                    .foregroundStyle(Palette.danger)
                                    .symbolSize(30)
                            }
                        }
                        // 阈值远高于实际延迟时不画，免得把曲线压成一条线
                        if threshold <= yMax {
                            RuleMark(y: .value("阈值", threshold))
                                .foregroundStyle(Palette.danger.opacity(0.4))
                                .lineStyle(StrokeStyle(lineWidth: 1, dash: [4, 4]))
                        }
                    }
                    .chartYScale(domain: 0...yMax)
                    .frame(height: 140)
                    .accessibilityLabel("最近 \(samples.count) 次延迟探测，红点表示失败")
                }
            }
        }
    }
}

private struct HealthCard: View {
    var status: GuardStatus

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 10) {
                Label("防护链路", systemImage: "checklist").font(.callout.weight(.semibold)).foregroundStyle(.secondary)
                StatusDot(ok: status.coreRunning, label: "代理内核", detail: status.coreRestarts > 0 ? "重启 \(status.coreRestarts) 次" : nil)
                StatusDot(ok: status.tunUp, label: "TUN 全局接管", detail: status.tunInterface)
                StatusDot(ok: status.pfPolicy != "none", label: "防火墙", detail: pfLabel)
                StatusDot(ok: status.ipv6Blocked != false, label: "IPv6 已封锁",
                          detail: status.ipv6Blocked == false ? "泄漏"
                            : (status.ipv6DisabledServices > 0 ? "系统已关 \(status.ipv6DisabledServices) 个" : (status.ipv6Blocked == nil ? "检测中" : "防火墙")))
                StatusDot(ok: status.conflicts.isEmpty, label: "无冲突软件", detail: status.conflicts.isEmpty ? nil : "\(status.conflicts.count) 个")
                StatusDot(ok: status.dnsLockedServices > 0 || status.pfPolicy != "none", label: "DNS 防泄漏",
                          detail: status.dnsLockedServices > 0 ? "已锁定 \(status.dnsLockedServices) 个" : "防火墙")
                if status.fuse.tripped {
                    StatusDot(ok: status.pfPolicy == "whitelist" || status.pfPolicy == "lockdown",
                              label: status.pfPolicy == "lockdown" ? "全部断网" : "大陆白名单",
                              detail: status.pfPolicy == "whitelist" || status.pfPolicy == "lockdown" ? "生效中" : "未生效")
                }
                if let n = status.nodeCount {
                    StatusDot(ok: n > 0, label: "可用节点", detail: "\(n) 个")
                }
                if let e = status.lastError {
                    Text(e).font(.caption).foregroundStyle(Palette.caution).lineLimit(3)
                }
            }
        }
    }

    private var pfLabel: String {
        switch status.pfPolicy {
        case "lockdown": return "全部断网"
        case "leakGuard": return "防泄漏"
        case "basic": return "IPv6+DNS"
        case "whitelist": return "大陆白名单"
        default: return "未启用"
        }
    }
}

private struct ConflictCard: View {
    var names: [String]

    var body: some View {
        GlassCard(tint: Palette.caution) {
            HStack(spacing: 14) {
                Image(systemName: "exclamationmark.triangle.fill").font(.title2).foregroundStyle(Palette.caution)
                VStack(alignment: .leading, spacing: 4) {
                    Text("检测到其他代理软件：\(names.joined(separator: "、"))").font(.headline)
                    Text("两个 TUN 会抢占路由，可能导致流量绕开本软件。请退出它们（或关闭其 TUN/增强模式）。")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// 验证失败后询问是否重启内核
struct RestartCorePrompt: ViewModifier {
    @Environment(GuardStore.self) private var store

    func body(content: Content) -> some View {
        @Bindable var store = store
        content.alert("验证没有通过", isPresented: $store.askRestartCore) {
            Button("重启内核") { Task { await store.restartCore() } }
            Button("暂不", role: .cancel) {}
        } message: {
            Text("线路或出口仍未通过验证（\(store.status?.fuse.reason?.title ?? "原因未知")）。\n常见原因是其他代理软件改坏了路由。重启内核会先关闭所有 AI 进程，再重新建立 TUN 并验证线路。")
        }
    }
}
