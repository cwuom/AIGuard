import AIGuardCore
import AppKit
import SwiftUI

/// 连接列表。不用 Table：它按理想列宽排版，窗口稍窄就横向溢出、表头被圆角裁掉，
/// 这里按可用宽度自己分配列宽，窄窗口时收起次要列
struct ConnectionsView: View {
    @Environment(GuardStore.self) private var store
    @State private var filter = ""
    @State private var scope: RouteScope = .all
    @State private var sort: ConnSortKey = .download
    @State private var ascending = false
    @State private var paused = false
    @State private var confirmCloseAll = false
    @State private var width: CGFloat = 800

    private var all: [MihomoAPI.Connection] { store.connections?.connections ?? [] }

    private var rows: [MihomoAPI.Connection] {
        let scoped = scope == .all ? all : all.filter { $0.route == scope.kind }
        let filtered = filter.isEmpty ? scoped : scoped.filter {
            $0.host.localizedCaseInsensitiveContains(filter) || $0.destination.contains(filter)
                || $0.chain.localizedCaseInsensitiveContains(filter) || $0.rule.localizedCaseInsensitiveContains(filter)
        }
        return filtered.sorted { a, b in
            let r = sort.compare(a, b)
            // 并列时按 id 稳定排序，避免每 2 秒刷新时行来回跳
            if r == .orderedSame { return a.id < b.id }
            return ascending ? r == .orderedAscending : r == .orderedDescending
        }
    }

    private var layout: ConnLayout { ConnLayout(width: width) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            summary
            controls
            listCard
        }
        .padding(24)
        .navigationTitle("连接")
        // 列表的滚动视图不在窗口顶端，AppKit 会给工具栏画白底；这里和其他页一样保持透明
        .toolbarBackgroundVisibility(.hidden, for: .windowToolbar)
        .searchable(text: $filter, placement: .toolbar, prompt: "筛选域名、IP、线路或规则")
        .confirmationDialog("断开全部 \(all.count) 条连接？", isPresented: $confirmCloseAll) {
            Button("断开全部", role: .destructive) { Task { await store.closeAllConnections() } }
        } message: {
            Text("正在进行的下载和通话会中断，应用一般会自动重连。")
        }
        .task(id: paused) {
            // 只在页面可见且未暂停时刷新，2 秒一次
            while !paused && !Task.isCancelled {
                await store.loadConnections()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    // MARK: - 顶部

    private var summary: some View {
        let proxied = all.filter { $0.route == .proxy }.count
        let direct = all.filter { $0.route == .direct }.count
        let rejected = all.count - proxied - direct
        let detail = "代理 \(proxied) · 直连 \(direct)" + (rejected > 0 ? " · 拒绝 \(rejected)" : "")
        return GlassEffectContainer(spacing: 12) {
            HStack(spacing: 12) {
                metric("活动连接", "\(all.count)", detail: detail, symbol: "link")
                metric("本次累计下载", Format.bytes(store.connections?.downloadTotal ?? 0), symbol: "arrow.down.circle")
                metric("本次累计上传", Format.bytes(store.connections?.uploadTotal ?? 0), symbol: "arrow.up.circle")
                Spacer(minLength: 0)
            }
        }
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Picker("线路", selection: $scope) {
                ForEach(RouteScope.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            if paused {
                Label("已暂停刷新", systemImage: "pause.circle").font(.callout).foregroundStyle(Palette.caution)
            }
            Spacer(minLength: 0)
            GlassEffectContainer(spacing: 8) {
                HStack(spacing: 8) {
                    Button {
                        paused.toggle()
                    } label: {
                        Label(paused ? "继续刷新" : "暂停刷新", systemImage: paused ? "play.fill" : "pause.fill")
                    }
                    .buttonStyle(.glass)
                    .help(paused ? "恢复每 2 秒自动刷新" : "暂停自动刷新，方便查看和复制")
                    Button(role: .destructive) { confirmCloseAll = true } label: {
                        Label("断开全部", systemImage: "xmark.circle")
                    }
                    .buttonStyle(.glass)
                    .disabled(all.isEmpty)
                }
            }
        }
    }

    // MARK: - 列表

    private var listCard: some View {
        let rows = rows
        return VStack(spacing: 0) {
            header
            Divider()
            if rows.isEmpty {
                ContentUnavailableView {
                    Label(all.isEmpty ? "暂无连接" : "没有匹配的连接", systemImage: "link")
                } description: {
                    Text(all.isEmpty ? "有程序联网时，这里会实时列出每条连接走的线路和命中的规则。" : "换个关键词，或切回「全部」试试。")
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(rows) { c in
                            ConnectionRow(connection: c, layout: layout) {
                                Task { await store.closeConnection(c.id) }
                            }
                            Divider().opacity(0.5)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width = $0 }
        .clipShape(.rect(cornerRadius: 18))
        .glassEffect(.regular, in: .rect(cornerRadius: 18))
    }

    private var header: some View {
        HStack(spacing: ConnLayout.spacing) {
            headerButton("目标", .target).frame(maxWidth: .infinity, alignment: .leading)
            headerButton("线路 / 命中规则", .route).frame(width: layout.route, alignment: .leading)
            if layout.showsNetwork { Text("协议").frame(width: ConnLayout.network, alignment: .leading) }
            headerButton("下载", .download).frame(width: ConnLayout.bytes, alignment: .trailing)
            headerButton("上传", .upload).frame(width: ConnLayout.bytes, alignment: .trailing)
            if layout.showsDuration { headerButton("时长", .duration).frame(width: ConnLayout.duration, alignment: .trailing) }
            Color.clear.frame(width: ConnLayout.close, height: 1)
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(.secondary)
        .padding(.horizontal, ConnLayout.inset)
        .padding(.vertical, 10)
    }

    private func headerButton(_ title: String, _ key: ConnSortKey) -> some View {
        Button {
            if sort == key {
                ascending.toggle()
            } else {
                sort = key
                ascending = key.defaultAscending
            }
        } label: {
            HStack(spacing: 3) {
                Text(title).lineLimit(1)
                if sort == key {
                    Image(systemName: ascending ? "chevron.up" : "chevron.down").font(.caption2.weight(.bold))
                }
            }
            .foregroundStyle(sort == key ? Color.primary : Color.secondary)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityLabel("按\(title)排序")
        .accessibilityValue(sort == key ? (ascending ? "升序" : "降序") : "")
    }

    private func metric(_ title: String, _ value: String, detail: String? = nil, symbol: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).font(.title3).foregroundStyle(Palette.accent)
            VStack(alignment: .leading, spacing: 1) {
                Text(value).font(.system(.title3, design: .rounded).weight(.semibold)).monospacedDigit()
                Text(detail.map { "\(title) · \($0)" } ?? title).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .glassEffect(.regular, in: .rect(cornerRadius: 14))
        .accessibilityElement(children: .combine)
    }
}

// MARK: - 行

private struct ConnectionRow: View {
    var connection: MihomoAPI.Connection
    var layout: ConnLayout
    var close: () -> Void
    @State private var hovering = false

    var body: some View {
        let c = connection
        HStack(spacing: ConnLayout.spacing) {
            VStack(alignment: .leading, spacing: 2) {
                Text(c.displayTarget).lineLimit(1).truncationMode(.middle)
                if !c.host.isEmpty {
                    Text(c.destination).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            VStack(alignment: .leading, spacing: 2) {
                route.lineLimit(1).truncationMode(.middle)
                Text(c.rule.isEmpty ? "—" : c.rule).font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            .frame(width: layout.route, alignment: .leading)
            .help(c.rule.isEmpty ? c.chain : "\(c.chain)\n命中规则：\(c.rule)")

            if layout.showsNetwork {
                Text(c.network).font(.caption.monospaced()).foregroundStyle(.secondary)
                    .frame(width: ConnLayout.network, alignment: .leading)
            }
            Text(Format.bytes(c.download)).monospacedDigit().frame(width: ConnLayout.bytes, alignment: .trailing)
            Text(Format.bytes(c.upload)).monospacedDigit().foregroundStyle(.secondary)
                .frame(width: ConnLayout.bytes, alignment: .trailing)
            if layout.showsDuration {
                Text(Self.duration(c.start)).monospacedDigit().foregroundStyle(.secondary)
                    .frame(width: ConnLayout.duration, alignment: .trailing)
            }
            Button(action: close) { Image(systemName: "xmark.circle.fill") }
                .buttonStyle(.plain)
                .foregroundStyle(hovering ? Palette.danger : Color.secondary.opacity(0.5))
                .frame(width: ConnLayout.close)
                .help("断开这条连接")
                .accessibilityLabel("断开 \(c.displayTarget)")
        }
        .font(.callout)
        .padding(.horizontal, ConnLayout.inset)
        .padding(.vertical, 7)
        .background(hovering ? Color.primary.opacity(0.05) : .clear)
        .contentShape(.rect)
        .onHover { hovering = $0 }
        .contextMenu {
            if !c.host.isEmpty { Button("复制域名") { copy(c.host) } }
            Button("复制目标地址") { copy(c.destination) }
            if !c.rule.isEmpty { Button("复制命中规则") { copy(c.rule) } }
            Divider()
            Button("断开这条连接", role: .destructive, action: close)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(c.displayTarget)，\(c.routeDescription)，下载 \(Format.bytes(c.download))，上传 \(Format.bytes(c.upload))")
    }

    @ViewBuilder private var route: some View {
        let c = connection
        switch c.route {
        case .direct: Label("直连", systemImage: "arrow.right").foregroundStyle(.secondary)
        case .reject: Label("已拒绝", systemImage: "nosign").foregroundStyle(Palette.danger)
        case .proxy:
            let parts = c.chain.components(separatedBy: " → ")
            if parts.count > 1, let leaf = parts.last {
                let path = parts.dropLast().joined(separator: " → ")
                Text("\(Text(path + " → ").foregroundStyle(.secondary))\(Text(leaf))")
            } else {
                Text(c.chain)
            }
        }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }

    static func duration(_ start: Date?) -> String {
        guard let start else { return "—" }
        let s = max(0, Int(Date().timeIntervalSince(start)))
        if s < 60 { return "\(s) 秒" }
        if s < 3600 { return "\(s / 60) 分" }
        return "\(s / 3600) 时 \(s % 3600 / 60) 分"
    }
}

// MARK: - 布局与排序

private struct ConnLayout {
    static let spacing: CGFloat = 12
    static let inset: CGFloat = 16
    static let network: CGFloat = 40
    static let bytes: CGFloat = 72
    static let duration: CGFloat = 64
    static let close: CGFloat = 22

    var width: CGFloat
    var showsNetwork: Bool { width >= 760 }
    var showsDuration: Bool { width >= 640 }
    /// 线路列随窗口变宽，目标列吃掉剩余空间
    var route: CGFloat { min(max(width * 0.30, 160), 300) }
}

enum RouteScope: String, CaseIterable, Identifiable {
    case all, proxy, direct
    var id: String { rawValue }
    var title: String {
        switch self {
        case .all: return "全部"
        case .proxy: return "走代理"
        case .direct: return "直连"
        }
    }
    var kind: MihomoAPI.Connection.RouteKind? {
        switch self {
        case .all: return nil
        case .proxy: return .proxy
        case .direct: return .direct
        }
    }
}

private enum ConnSortKey {
    case target, route, download, upload, duration

    /// 文字列默认升序，数值列默认从大到小
    var defaultAscending: Bool { self == .target || self == .route }

    func compare(_ a: MihomoAPI.Connection, _ b: MihomoAPI.Connection) -> ComparisonResult {
        switch self {
        case .target: return a.displayTarget.localizedStandardCompare(b.displayTarget)
        case .route: return a.chain.localizedStandardCompare(b.chain)
        case .download: return cmp(a.download, b.download)
        case .upload: return cmp(a.upload, b.upload)
        // 时长越长 = 开始时间越早
        case .duration: return cmp(b.start ?? .distantFuture, a.start ?? .distantFuture)
        }
    }

    private func cmp<T: Comparable>(_ a: T, _ b: T) -> ComparisonResult {
        a < b ? .orderedAscending : (a > b ? .orderedDescending : .orderedSame)
    }
}

extension MihomoAPI.Connection {
    var displayTarget: String { host.isEmpty ? destination : host }

    var routeDescription: String {
        switch route {
        case .direct: return "直连"
        case .reject: return "已拒绝"
        case .proxy: return "经 \(chain)"
        }
    }
}
