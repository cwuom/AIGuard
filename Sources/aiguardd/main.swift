import AIGuardCore
import Darwin
import Foundation

// 用法：aiguardd --uid 501 [--uid 502] [--helper-dir 路径] [--support-dir 路径]
var allowedUIDs = Set<uid_t>()
var helperDir = AIGuardPaths.helperDir
var supportDir = AIGuardPaths.supportDir
var devMode = false
var args = CommandLine.arguments.dropFirst().makeIterator()
while let a = args.next() {
    switch a {
    case "--uid": if let v = args.next(), let u = uid_t(v) { allowedUIDs.insert(u) }
    case "--helper-dir": if let v = args.next() { helperDir = v }
    case "--support-dir": if let v = args.next() { supportDir = v }
    // 开发模式：不需要 root，不碰 pf、不开 TUN，用于在本机验证内核联动与界面
    case "--dev": devMode = true
    case "--version":
        print(AIGuardVersion)
        exit(0)
    default: break
    }
}

if devMode {
    if supportDir == AIGuardPaths.supportDir {
        supportDir = FileManager.default.homeDirectoryForCurrentUser.path + "/Library/Application Support/AIGuard-dev"
    }
    allowedUIDs.insert(getuid())
}
let socketPath = devMode ? supportDir + "/dev.sock" : AIGuardPaths.socket
let logDir = devMode ? supportDir + "/logs" : AIGuardPaths.logDir

guard devMode || geteuid() == 0 else {
    FileHandle.standardError.write(Data("aiguardd 需要以 root 运行（由 LaunchDaemon 启动）\n".utf8))
    exit(1)
}

umask(0o077)
signal(SIGPIPE, SIG_IGN)
Log.open(dir: logDir)

let guardianPaths = DaemonPaths(helperDir: helperDir, supportDir: supportDir, logDir: logDir)
let guardian = Guardian(paths: guardianPaths, allowedUIDs: allowedUIDs, dev: devMode)

/// 从回调线程同步等待 actor 完成，用于睡眠前断网这类必须先完成的动作
func blocking(timeout: TimeInterval, _ work: @escaping @Sendable () async -> Void) {
    let sem = DispatchSemaphore(value: 0)
    Task {
        await work()
        sem.signal()
    }
    _ = sem.wait(timeout: .now() + timeout)
}

let ipc = IPCServer(path: socketPath, allowedUIDs: allowedUIDs) { req in
    await guardian.handle(req)
}

let power = PowerMonitor(
    // 先不经 actor 直接断网（actor 可能正卡在配置校验上），再通知状态机
    onWillSleep: {
        guardian.pf.forceLockdown()
        blocking(timeout: 3) { await guardian.prepareForSleep() }
    },
    onWake: { Task { await guardian.didWake() } }
)
// 换网时同样先不经 actor 直接断网，赶在应用重连之前
let network = NetworkMonitor { primary in
    if !devMode { guardian.pf.forceLockdown() }
    Task { await guardian.networkChanged(primary: primary) }
}

var signalSources: [DispatchSourceSignal] = []
for sig in [SIGTERM, SIGINT] {
    signal(sig, SIG_IGN)
    let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
    src.setEventHandler {
        // 先停网络回调、直接处理防火墙（不等 actor）。普通退出撤掉规则，保证不残留断网；
        // 升级交接时保持全部断网，否则新版启动前的几秒里应用会绕过代理直连
        network.stop()
        let hold = !devMode && guardianPaths.upgradeHoldActive()
        if hold { guardian.pf.holdLockdownOnExit() } else { guardian.pf.teardown() }
        blocking(timeout: 10) { await guardian.shutdown(holdNetwork: hold) }
        ipc.stop()
        exit(0)
    }
    src.resume()
    signalSources.append(src)
}

Task {
    await guardian.boot()
    do {
        try ipc.start()
    } catch {
        Log.write("控制通道启动失败：\(error)")
    }
    power.start()
    network.start()
}

RunLoop.main.run()
