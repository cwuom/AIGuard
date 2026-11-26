import AIGuardCore
import SwiftUI

struct NodesView: View {
    @Environment(GuardStore.self) private var store
    @State private var filter = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if store.status?.subscription == nil {
                    GlassCard {
                        Label("还没有导入订阅，导入后这里会出现节点。", systemImage: "link.badge.plus")
                    }
                } else {
                    GroupSection(group: GroupName.proxy, title: "节点选择",
                                 note: "单线路：AI 与其余代理流量都走这里（智能分流下大陆网站直连，不耗代理流量）。已自动排除出口禁区和回国节点；推荐「自动选择」，只在节点失效时才换线，出口 IP 最稳定。",
                                 filter: filter)
                }
            }
            .padding(24)
        }
        .navigationTitle("节点")
        .searchable(text: $filter, placement: .toolbar, prompt: "筛选节点")
        .task {
            while !Task.isCancelled {
                await store.loadProxies()
                try? await Task.sleep(for: .seconds(4))
            }
        }
    }
}

private struct GroupSection: View {
    @Environment(GuardStore.self) private var store
    var group: String
    var title: String
    var note: String
    var filter: String

    var body: some View {
        let info = store.proxies[group]
        let members = (info?.all ?? []).filter { filter.isEmpty || $0.localizedCaseInsensitiveContains(filter) }
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                SectionHeader(title: title, subtitle: note)
                Spacer()
                Button {
                    Task { await store.testGroup(group) }
                } label: {
                    if store.testingGroup == group { ProgressView().controlSize(.small) } else { Label("测速", systemImage: "speedometer") }
                }
                .buttonStyle(.glass)
                .disabled(store.testingGroup != nil)
            }
            if let now = info?.now {
                Text("当前：\(now)\(resolved(now).map { " → \($0)" } ?? "")")
                    .font(.callout).foregroundStyle(.secondary)
            }
            GlassEffectContainer(spacing: 10) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 10)], spacing: 10) {
                    ForEach(members, id: \.self) { name in
                        NodeTile(name: name, delay: delay(of: name), selected: info?.now == name,
                                 isGroup: store.proxies[name]?.all.isEmpty == false) {
                            Task { await store.select(group: group, node: name) }
                        }
                    }
                }
            }
            if info != nil, info?.all.isEmpty == true || info?.all == [GroupName.auto] {
                Text("没有可用节点。若订阅只有禁区（如香港）节点，代理会保持阻断。")
                    .font(.callout).foregroundStyle(Palette.caution)
            }
        }
    }

    private func resolved(_ name: String) -> String? {
        guard let sub = store.proxies[name], let now = sub.now, !sub.all.isEmpty else { return nil }
        return resolved(now) ?? now
    }

    private func delay(of name: String) -> Int? {
        if let p = store.proxies[name], let d = p.lastDelay { return d }
        if let r = resolved(name) { return store.proxies[r]?.lastDelay }
        return nil
    }
}

private struct NodeTile: View {
    var name: String
    var delay: Int?
    var selected: Bool
    var isGroup: Bool
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if isGroup { Image(systemName: "sparkles").foregroundStyle(Palette.accent) }
                Text(name).font(.callout.weight(selected ? .semibold : .regular)).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 4)
                Text(delay.map { "\($0)" } ?? "—")
                    .font(.caption.monospacedDigit().weight(.semibold))
                    .foregroundStyle(delay == nil ? Color.secondary : Format.delayColor(delay))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .glassEffect(selected ? .regular.tint(Palette.accent.opacity(0.25)).interactive() : .regular.interactive(),
                     in: .rect(cornerRadius: 12))
        .accessibilityLabel("\(name)，\(delay.map { "延迟 \($0) 毫秒" } ?? "未测速")")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}
