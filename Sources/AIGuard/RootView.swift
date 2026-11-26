import AIGuardCore
import SwiftUI

enum Pane: String, CaseIterable, Identifiable {
    case overview, nodes, connections, subscription, rules, security, logs
    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: return "总览"
        case .nodes: return "节点"
        case .connections: return "连接"
        case .subscription: return "订阅"
        case .rules: return "AI 名单"
        case .security: return "熔断与安全"
        case .logs: return "事件"
        }
    }

    var symbol: String {
        switch self {
        case .overview: return "gauge.with.dots.needle.67percent"
        case .nodes: return "point.3.connected.trianglepath.dotted"
        case .connections: return "link"
        case .subscription: return "link.badge.plus"
        case .rules: return "brain.head.profile"
        case .security: return "bolt.shield"
        case .logs: return "list.bullet.rectangle"
        }
    }
}

struct RootView: View {
    @Environment(GuardStore.self) private var store
    @Environment(\.scenePhase) private var scenePhase
    @State private var pane: Pane? = .overview

    var body: some View {
        NavigationSplitView {
            List(Pane.allCases, selection: $pane) { p in
                Label(p.title, systemImage: p.symbol).tag(p)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
            .safeAreaInset(edge: .bottom) { SidebarStatus().padding(12) }
        } detail: {
            ZStack {
                AmbientBackground(tone: Palette.tone(for: store.daemonReachable ? store.status?.phase : .error))
                if !store.daemonReachable {
                    OnboardingView()
                } else {
                    detail
                }
            }
            .overlay(alignment: .bottom) { NoticeBanner() }
        }
        .onChange(of: scenePhase) { _, phase in store.windowVisible = phase == .active }
        .modifier(RestartCorePrompt())
    }

    @ViewBuilder private var detail: some View {
        switch pane ?? .overview {
        case .overview: OverviewView()
        case .nodes: NodesView()
        case .connections: ConnectionsView()
        case .subscription: SubscriptionView()
        case .rules: RulesView()
        case .security: SecurityView()
        case .logs: EventsView()
        }
    }
}

struct SidebarStatus: View {
    @Environment(GuardStore.self) private var store

    var body: some View {
        let tone = Palette.tone(for: store.daemonReachable ? store.status?.phase : .error)
        HStack(spacing: 10) {
            Image(systemName: store.daemonReachable ? (store.status?.symbol ?? "shield") : "shield.slash")
                .font(.title2)
                .foregroundStyle(tone)
                .contentTransition(.symbolEffect(.replace))
            VStack(alignment: .leading, spacing: 1) {
                Text(store.daemonReachable ? (store.status?.headline ?? "连接中") : "守护进程未运行")
                    .font(.callout.weight(.semibold))
                Text(store.status?.coreVersion.map { "mihomo \($0)" } ?? "AI 出差管家 \(AIGuardVersion)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .glassEffect(.regular.tint(tone.opacity(0.15)), in: .rect(cornerRadius: 14))
        .accessibilityElement(children: .combine)
    }
}

struct NoticeBanner: View {
    @Environment(GuardStore.self) private var store

    var body: some View {
        if let n = store.notice {
            HStack(spacing: 10) {
                Image(systemName: n.isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    .foregroundStyle(n.isError ? Palette.danger : Palette.safe)
                Text(n.text).font(.callout).lineLimit(3)
                Button("关闭", systemImage: "xmark") { store.notice = nil }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .glassEffect(.regular, in: .capsule)
            .padding(.bottom, 18)
            .transition(.move(edge: .bottom).combined(with: .opacity))
            .task(id: n) {
                try? await Task.sleep(for: .seconds(n.isError ? 8 : 4))
                if store.notice == n { withAnimation { store.notice = nil } }
            }
        }
    }
}

struct OnboardingView: View {
    @Environment(GuardStore.self) private var store

    var body: some View {
        VStack(spacing: 22) {
            Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                .font(.system(size: 64, weight: .regular))
                .foregroundStyle(Palette.accent)
                .symbolEffect(.breathe)
            VStack(spacing: 6) {
                Text(store.daemonOutdated ? "升级守护进程" : (store.daemonInstalled ? "守护进程没有响应" : "安装守护进程"))
                    .font(.largeTitle.weight(.semibold))
                Text("TUN 全局接管、防火墙熔断和防泄漏都需要一个常驻的系统级守护进程。\n安装时 macOS 会弹出授权窗口，请输入你的登录密码。")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            }
            Button {
                Task { await store.installDaemon() }
            } label: {
                Label(store.daemonOutdated ? "升级到 \(AIGuardVersion)" : (store.daemonInstalled ? "重新安装" : "安装并启动"),
                      systemImage: "lock.shield")
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
            }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
            .disabled(store.busy.contains("install"))

            if store.busy.contains("install") { ProgressView().controlSize(.small) }
            if let e = store.lastIPCError, store.daemonInstalled, !store.daemonOutdated {
                Text("连接错误：\(e)").font(.caption).foregroundStyle(.secondary)
            }
            GlassCard {
                VStack(alignment: .leading, spacing: 6) {
                    Text("也可以在终端手动安装").font(.callout.weight(.semibold))
                    Text("sudo /Applications/AIGuard.app/Contents/Resources/install.sh --uid \(getuid())")
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            .frame(maxWidth: 560)
        }
        .padding(40)
    }
}
