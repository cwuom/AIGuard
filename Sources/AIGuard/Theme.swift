import AIGuardCore
import SwiftUI

/// 颜色令牌：全部从这里取，深浅色由系统动态色自动适配
enum Palette {
    static let safe = Color(nsColor: .init(name: nil) { $0.isDark ? .init(srgbRed: 0.30, green: 0.85, blue: 0.62, alpha: 1)
                                                                 : .init(srgbRed: 0.05, green: 0.56, blue: 0.40, alpha: 1) })
    static let caution = Color(nsColor: .init(name: nil) { $0.isDark ? .init(srgbRed: 1.00, green: 0.76, blue: 0.30, alpha: 1)
                                                                    : .init(srgbRed: 0.72, green: 0.45, blue: 0.00, alpha: 1) })
    static let danger = Color(nsColor: .init(name: nil) { $0.isDark ? .init(srgbRed: 1.00, green: 0.42, blue: 0.40, alpha: 1)
                                                                   : .init(srgbRed: 0.78, green: 0.14, blue: 0.16, alpha: 1) })
    static let idle = Color.secondary
    /// 品牌色：冰川青，避开常见的紫色渐变
    static let accent = Color(nsColor: .init(name: nil) { $0.isDark ? .init(srgbRed: 0.35, green: 0.80, blue: 0.92, alpha: 1)
                                                                   : .init(srgbRed: 0.00, green: 0.47, blue: 0.62, alpha: 1) })
    static let upload = Color(nsColor: .systemOrange)
    static let download = accent

    static func tone(for phase: GuardPhase?) -> Color {
        switch phase {
        case .protected: return safe
        case .tripped: return danger
        case .starting: return caution
        case .error: return danger
        case .disabled, .none: return idle
        }
    }
}

private extension NSAppearance {
    var isDark: Bool { bestMatch(from: [.darkAqua, .aqua]) == .darkAqua }
}

extension GuardStatus {
    var headline: String {
        switch phase {
        case .protected: return effectiveMode == .proxy ? "已受保护" : "直连 · AI 已阻断"
        case .tripped: return fuse.hard ? "已熔断 · 全部断网" : "已熔断 · AI 已阻断"
        case .starting: return "正在启动保护"
        case .error: return "保护异常"
        case .disabled: return "守护已关闭"
        }
    }

    var symbol: String {
        switch phase {
        case .protected: return "checkmark.shield.fill"
        case .tripped: return "bolt.shield.fill"
        case .starting: return "shield.lefthalf.filled"
        case .error: return "exclamationmark.shield.fill"
        case .disabled: return "shield.slash"
        }
    }
}

/// 背景：随状态变色的柔和网格渐变，给玻璃材质提供可折射的底色
struct AmbientBackground: View {
    var tone: Color

    var body: some View {
        MeshGradient(width: 3, height: 3, points: [
            [0, 0], [0.5, 0], [1, 0],
            [0, 0.5], [0.6, 0.45], [1, 0.5],
            [0, 1], [0.5, 1], [1, 1],
        ], colors: [
            tone.opacity(0.28), Palette.accent.opacity(0.18), .clear,
            Palette.accent.opacity(0.10), tone.opacity(0.12), Palette.accent.opacity(0.08),
            .clear, tone.opacity(0.10), Palette.accent.opacity(0.16),
        ])
        .background(Color(nsColor: .windowBackgroundColor))
        .ignoresSafeArea()
        .animation(.smooth(duration: 0.8), value: tone)
    }
}

struct GlassCard<Content: View>: View {
    var padding: CGFloat = 18
    var tint: Color?
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassEffect(tint.map { Glass.regular.tint($0.opacity(0.18)) } ?? .regular, in: .rect(cornerRadius: 22))
    }
}

struct SectionHeader: View {
    var title: String
    var subtitle: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.title3.weight(.semibold))
            if let subtitle { Text(subtitle).font(.callout).foregroundStyle(.secondary) }
        }
    }
}

struct StatusDot: View {
    var ok: Bool
    var label: String
    var detail: String?

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                .foregroundStyle(ok ? Palette.safe : Palette.danger)
                .accessibilityHidden(true)
            Text(label)
            Spacer(minLength: 8)
            if let detail { Text(detail).foregroundStyle(.secondary).monospacedDigit() }
        }
        .font(.callout)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label)：\(ok ? "正常" : "异常")\(detail.map { "，\($0)" } ?? "")")
    }
}

enum Format {
    static func bytes(_ v: Int64) -> String {
        let f = ByteCountFormatter()
        f.countStyle = .binary
        // 默认会把 0 写成 "Zero KB"
        f.allowsNonnumericFormatting = false
        return f.string(fromByteCount: v)
    }

    static func rate(_ v: Int64) -> String { bytes(v) + "/s" }

    static func ms(_ v: Int?) -> String { v.map { "\($0) ms" } ?? "超时" }

    static func relative(_ d: Date?) -> String {
        guard let d else { return "从未" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f.localizedString(for: d, relativeTo: Date())
    }

    static func delayColor(_ ms: Int?) -> Color {
        guard let ms else { return Palette.danger }
        if ms < 300 { return Palette.safe }
        if ms < 800 { return Palette.caution }
        return Palette.danger
    }
}
