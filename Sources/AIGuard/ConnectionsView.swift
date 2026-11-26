import AIGuardCore
import SwiftUI

struct ConnectionsView: View {
    @Environment(GuardStore.self) private var store
    @State private var filter = ""
    @State private var sortOrder = [KeyPathComparator(\MihomoAPI.Connection.download, order: .reverse)]
    @State private var confirmCloseAll = false

    private var rows: [MihomoAPI.Connection] {
        let all = store.connections?.connections ?? []
        let filtered = filter.isEmpty ? all : all.filter {
            $0.host.localizedCaseInsensitiveContains(filter) || $0.destination.contains(filter)
                || $0.chain.localizedCaseInsensitiveContains(filter) || $0.rule.localizedCaseInsensitiveContains(filter)
        }
        return filtered.sorted(using: sortOrder)
    }

    var body: some View {
        VStack(spacing: 14) {
            GlassEffectContainer(spacing: 12) {
                HStack(spacing: 12) {
                    metric("活动连接", "\(store.connections?.connections.count ?? 0)", symbol: "link")
                    metric("累计下载", Format.bytes(store.connections?.downloadTotal ?? 0), symbol: "arrow.down.circle")
                    metric("累计上传", Format.bytes(store.connections?.uploadTotal ?? 0), symbol: "arrow.up.circle")
                    Spacer(minLength: 0)
                    Button(role: .destructive) { confirmCloseAll = true } label: {
                        Label("断开全部", systemImage: "xmark.circle")
                    }
                    .buttonStyle(.glass)
                    .disabled((store.connections?.connections.isEmpty ?? true))
                }
            }

            Table(rows, sortOrder: $sortOrder) {
                TableColumn("目标", value: \.host) { c in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(c.host.isEmpty ? c.destination : c.host).lineLimit(1).truncationMode(.middle)
                        if !c.host.isEmpty {
                            Text(c.destination).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                }
                .width(min: 180, ideal: 260)
                TableColumn("协议", value: \.network) { c in Text(c.network).font(.caption.monospaced()) }
                    .width(48)
                TableColumn("线路", value: \.chain) { c in
                    Text(c.chain.isEmpty ? "—" : c.chain).lineLimit(1)
                        .foregroundStyle(c.chain.contains("DIRECT") ? Color.secondary : Palette.accent)
                }
                .width(min: 100, ideal: 160)
                TableColumn("命中规则", value: \.rule) { c in
                    Text(c.rule).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                .width(min: 100, ideal: 180)
                TableColumn("下载", value: \.download) { c in Text(Format.bytes(c.download)).monospacedDigit() }
                    .width(76)
                TableColumn("上传", value: \.upload) { c in Text(Format.bytes(c.upload)).monospacedDigit() }
                    .width(76)
                TableColumn("时长") { c in Text(duration(c.start)).monospacedDigit().foregroundStyle(.secondary) }
                    .width(60)
                TableColumn("") { c in
                    Button {
                        Task { await store.closeConnection(c.id) }
                    } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain)
                        .foregroundStyle(.secondary)
                        .help("断开这条连接")
                        .accessibilityLabel("断开 \(c.host.isEmpty ? c.destination : c.host)")
                }
                .width(28)
            }
            .scrollContentBackground(.hidden)
            .glassEffect(.regular, in: .rect(cornerRadius: 18))
            .overlay {
                if rows.isEmpty {
                    ContentUnavailableView(filter.isEmpty ? "暂无连接" : "没有匹配的连接", systemImage: "link")
                }
            }
        }
        .padding(24)
        .navigationTitle("连接")
        .searchable(text: $filter, placement: .toolbar, prompt: "筛选域名、IP、线路或规则")
        .confirmationDialog("断开全部连接？应用会自动重连。", isPresented: $confirmCloseAll) {
            Button("断开全部", role: .destructive) { Task { await store.closeAllConnections() } }
        }
        .task {
            // 只在页面可见时刷新，2 秒一次
            while !Task.isCancelled {
                await store.loadConnections()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private func metric(_ title: String, _ value: String, symbol: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).font(.title3).foregroundStyle(Palette.accent)
            VStack(alignment: .leading, spacing: 1) {
                Text(value).font(.system(.title3, design: .rounded).weight(.semibold)).monospacedDigit()
                Text(title).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .glassEffect(.regular, in: .rect(cornerRadius: 14))
    }

    private func duration(_ start: Date?) -> String {
        guard let start else { return "—" }
        let s = Int(Date().timeIntervalSince(start))
        if s < 60 { return "\(s)s" }
        if s < 3600 { return "\(s / 60)m" }
        return "\(s / 3600)h"
    }
}
