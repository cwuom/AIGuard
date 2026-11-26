import AIGuardCore
import AppKit
import SwiftUI

@main
struct AIGuardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var store: GuardStore

    init() {
        let s = GuardStore()
        _store = State(initialValue: s)
        // 登录时只在菜单栏运行、主窗口不出现，状态轮询不能依赖窗口的 onAppear
        s.start()
        s.applyLaunchAtLoginDefault()
    }

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

/// 被系统作为登录项打开时不弹主窗口，只留菜单栏图标
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        guard Self.launchedAsLoginItem else { return }
        DispatchQueue.main.async {
            // 菜单栏面板是 NSPanel，不能关；主窗口此时可能还没显示，不按可见性筛
            for window in NSApp.windows where !(window is NSPanel) && window.canBecomeMain {
                window.close()
            }
        }
    }

    /// LaunchServices 以登录项启动时，打开事件里带 keyAELaunchedAsLogInItem
    private static var launchedAsLoginItem: Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent,
              event.eventID == AEEventID(kAEOpenApplication) else { return false }
        return event.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue == OSType(keyAELaunchedAsLogInItem)
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
