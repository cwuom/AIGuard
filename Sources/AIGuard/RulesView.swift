import AIGuardCore
import SwiftUI

struct RulesView: View {
    @Environment(GuardStore.self) private var store
    @State private var newAI = ""
    @State private var newDirect = ""
    @State private var newProxy = ""
    @State private var expanded: Set<String> = []

    var body: some View {
        ScrollView {
            if let s = store.settings {
                VStack(alignment: .leading, spacing: 16) {
                    GlassCard {
                        VStack(alignment: .leading, spacing: 6) {
                            SectionHeader(title: "AI 服务识别名单",
                                          subtitle: "代理模式下这些域名只走 AI 线路（绝不直连）；直连模式下全部屏蔽。按「宁可错杀」原则合并了社区名单和第三方关联服务。")
                            Text("共 \(AIRuleCatalog.ruleLines(disabled: s.disabledAICategories, custom: s.customAIDomains).count) 条规则生效")
                                .font(.callout.monospacedDigit()).foregroundStyle(Palette.accent)
                        }
                    }
                    ForEach(AIRuleCatalog.all) { c in
                        CategoryRow(category: c, enabled: !s.disabledAICategories.contains(c.id),
                                    expanded: expanded.contains(c.id)) { on in
                            store.updateSettings { st in
                                st.disabledAICategories.removeAll { $0 == c.id }
                                if !on { st.disabledAICategories.append(c.id) }
                            }
                        } toggleExpand: {
                            if expanded.contains(c.id) { expanded.remove(c.id) } else { expanded.insert(c.id) }
                        }
                    }
                    DomainEditor(title: "自定义 AI 域名", subtitle: "按后缀匹配，如 example.ai 会同时覆盖所有子域名",
                                 items: s.customAIDomains, input: $newAI) { list in
                        store.updateSettings { $0.customAIDomains = list }
                    }
                    DomainEditor(title: "强制走代理域名",
                                 subtitle: "大陆名单偶尔会误收境外网站，导致它们直连、看到你的真实 IP。把这类网站加在这里，智能分流下也一律走代理，DNS 同样经代理解析。已内置 \(ForceProxyCatalog.suffixes.count) 个 IP 与泄漏检测站点（如 browserleaks.com）。",
                                 items: s.customProxyDomains, input: $newProxy) { list in
                        store.updateSettings { $0.customProxyDomains = list }
                    }
                    DomainEditor(title: "强制直连域名", subtitle: "公司内网、国内服务等。AI 规则优先，写在这里也不会让 AI 直连；与「强制走代理」重复时以直连为准。",
                                 items: s.customDirectDomains, input: $newDirect) { list in
                        store.updateSettings { $0.customDirectDomains = list }
                    }
                }
                .padding(24)
            }
        }
        .navigationTitle("AI 名单")
    }
}

private struct CategoryRow: View {
    var category: AIRuleCategory
    var enabled: Bool
    var expanded: Bool
    var toggle: @MainActor @Sendable (Bool) -> Void
    var toggleExpand: () -> Void

    var body: some View {
        GlassCard(padding: 14) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    Button(action: toggleExpand) {
                        Image(systemName: "chevron.right")
                            .rotationEffect(.degrees(expanded ? 90 : 0))
                            .animation(.snappy, value: expanded)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(expanded ? "收起" : "展开")
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(category.name).font(.headline)
                            if category.strict {
                                Text("严格").font(.caption2.weight(.bold)).padding(.horizontal, 6).padding(.vertical, 2)
                                    .glassEffect(.regular.tint(Palette.caution.opacity(0.3)), in: .capsule)
                            }
                        }
                        Text("\(category.note) · \(category.ruleCount) 条").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(get: { enabled }, set: toggle))
                        .toggleStyle(.switch)
                        .labelsHidden()
                        .accessibilityLabel("启用 \(category.name)")
                }
                if expanded {
                    let items = category.suffixes.map { "*.\($0)" } + category.domains + category.keywords.map { "含「\($0)」" }
                        + category.regexes.map { "正则 \($0)" } + category.ipCIDRs
                        + category.ruleSets.map { "规则集 \($0)" } + category.extraRules
                    Text(items.joined(separator: "   "))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
        }
    }
}

private struct DomainEditor: View {
    var title: String
    var subtitle: String
    var items: [String]
    @Binding var input: String
    var save: ([String]) -> Void

    var body: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: title, subtitle: subtitle)
                HStack {
                    TextField("example.com", text: $input).textFieldStyle(.roundedBorder).onSubmit(add)
                    Button("添加", action: add).buttonStyle(.glass).disabled(input.isEmpty)
                }
                if !items.isEmpty {
                    FlowTags(items: items) { d in save(items.filter { $0 != d }) }
                }
            }
        }
    }

    private func add() {
        let cleaned = DomainSanitizer.clean(input.components(separatedBy: CharacterSet(charactersIn: ", \n")))
        guard !cleaned.isEmpty else { return }
        save(items + cleaned)
        input = ""
    }
}

private struct FlowTags: View {
    var items: [String]
    var remove: (String) -> Void

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 160), spacing: 8)], alignment: .leading, spacing: 8) {
            ForEach(items, id: \.self) { d in
                HStack(spacing: 6) {
                    Text(d).font(.callout.monospaced()).lineLimit(1)
                    Spacer(minLength: 0)
                    Button { remove(d) } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(.secondary)
                        .accessibilityLabel("删除 \(d)")
                }
                .padding(.horizontal, 10).padding(.vertical, 6)
                .glassEffect(.regular, in: .capsule)
            }
        }
    }
}
