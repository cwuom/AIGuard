import AIGuardCore
import SwiftUI

struct SubscriptionView: View {
    @Environment(GuardStore.self) private var store
    @State private var url = ""
    @State private var confirmRemove = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GlassCard {
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "导入订阅", subtitle: "支持 Clash/mihomo YAML 与 Base64 节点链接。只取节点，分流规则由本软件接管。")
                        HStack {
                            SecureField("https://… 订阅链接", text: $url)
                                .textFieldStyle(.roundedBorder)
                                .onSubmit(importNow)
                            Button(action: importNow) {
                                if store.busy.contains("subscription") { ProgressView().controlSize(.small) } else { Text("导入") }
                            }
                            .buttonStyle(.glassProminent)
                            .disabled(url.isEmpty || store.busy.contains("subscription"))
                        }
                        Text("订阅链接等同密码，只保存在本机 root 目录（权限 600），界面中只显示脱敏版本。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }

                if let sub = store.status?.subscription {
                    GlassCard {
                        VStack(alignment: .leading, spacing: 14) {
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(sub.name ?? "我的订阅").font(.title2.weight(.semibold))
                                    Text(sub.maskedURL).font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button {
                                    Task { await store.refreshSubscription() }
                                } label: { Label("立即更新", systemImage: "arrow.triangle.2.circlepath") }
                                    .buttonStyle(.glass)
                                    .disabled(store.busy.contains("subscription"))
                                Button(role: .destructive) { confirmRemove = true } label: { Label("移除", systemImage: "trash") }
                                    .buttonStyle(.glass)
                            }
                            HStack(spacing: 28) {
                                metric("节点", "\(sub.nodeCount)")
                                metric("可用（排除禁区）", store.status?.nodeCount.map(String.init) ?? "—")
                                metric("上次更新", Format.relative(sub.lastUpdated))
                                if let exp = sub.usage?.expire {
                                    metric("到期", exp.formatted(date: .abbreviated, time: .omitted))
                                }
                            }
                            if let u = sub.usage, u.total > 0 {
                                let used = u.used
                                ProgressView(value: min(Double(used), Double(u.total)), total: Double(u.total)) {
                                    Text("已用 \(Format.bytes(used)) / \(Format.bytes(u.total))").font(.callout)
                                }
                                .tint(Double(used) / Double(u.total) > 0.85 ? Palette.danger : Palette.accent)
                            }
                            if let e = sub.lastError {
                                Label("上次更新失败（继续使用旧节点）：\(e)", systemImage: "exclamationmark.triangle")
                                    .font(.callout).foregroundStyle(Palette.caution)
                            }
                            if let s = store.settings {
                                Stepper(value: Binding(get: { s.subscriptionUpdateHours },
                                                       set: { v in store.updateSettings { $0.subscriptionUpdateHours = v } }),
                                        in: 1...168) {
                                    Text("每 \(s.subscriptionUpdateHours) 小时自动更新（失败时保留旧节点）")
                                }
                            }
                        }
                    }
                }
            }
            .padding(24)
        }
        .navigationTitle("订阅")
        .confirmationDialog("移除订阅后将进入直连阻断模式，确定吗？", isPresented: $confirmRemove) {
            Button("移除订阅", role: .destructive) { Task { await store.removeSubscription() } }
        }
    }

    private func importNow() {
        let u = url
        Task {
            if await store.importSubscription(u) { url = "" }
        }
    }

    private func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(.title3, design: .rounded).weight(.semibold)).monospacedDigit()
        }
    }
}
