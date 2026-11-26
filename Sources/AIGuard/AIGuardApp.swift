import AIGuardCore
import SwiftUI

@main
struct AIGuardApp: App {
    @State private var store = GuardStore()

    var body: some Scene {
        Window("AI 出差管家", id: "main") {
            RootView()
                .environment(store)
                .frame(minWidth: 900, minHeight: 620)
                .onAppear { store.start() }
        }
        .windowToolbarStyle(.unified)
        .defaultSize(width: 1080, height: 720)

        MenuBarExtra {
            MenuBarPanel()
                .environment(store)
                .onAppear { store.start() }
        } label: {
            MenuBarIcon(status: store.status, reachable: store.daemonReachable)
        }
        .menuBarExtraStyle(.window)
    }
}

struct MenuBarIcon: View {
    var status: GuardStatus?
    var reachable: Bool

    var body: some View {
        let symbol = reachable ? (status?.symbol ?? "shield") : "shield.slash"
        Image(systemName: symbol)
            .accessibilityLabel(reachable ? (status?.headline ?? "AI 出差管家") : "守护进程未运行")
    }
}
