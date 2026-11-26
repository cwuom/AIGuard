import AIGuardCore
import Darwin
import Foundation

/// mihomo 子进程管理：配置校验、启动、崩溃重启、清理残留
final class CoreProcess: @unchecked Sendable {
    let binary: String
    let home: String
    private let lock = NSLock()
    private var process: Process?
    private(set) var restarts = 0
    var onExit: (@Sendable (Int32) -> Void)?

    private let logDir: String

    init(binary: String, home: String, logDir: String) {
        self.binary = binary
        self.home = home
        self.logDir = logDir
    }

    var configPath: String { home + "/config.yaml" }
    var pidPath: String { home + "/mihomo.pid" }

    var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return process?.isRunning == true
    }

    var pid: pid_t? {
        lock.lock()
        defer { lock.unlock() }
        return process?.isRunning == true ? process?.processIdentifier : nil
    }

    func version() -> String? {
        let r = Shell.run(binary, ["-v"], timeout: 5)
        return r.stdout.split(separator: " ").dropFirst(2).first.map(String.init)
    }

    /// 先写临时文件让内核自己校验，通过后再原子替换，避免坏配置让内核起不来
    func writeConfig(_ yaml: String) throws {
        let tmp = home + "/config.pending.yaml"
        try yaml.write(toFile: tmp, atomically: true, encoding: .utf8)
        chmod(tmp, 0o600)
        let r = Shell.run(binary, ["-t", "-d", home, "-f", tmp], timeout: 20)
        guard r.status == 0 else {
            let msg = (r.stdout + r.stderr).split(separator: "\n").suffix(3).joined(separator: " ")
            throw NSError(domain: "AIGuard", code: 1, userInfo: [NSLocalizedDescriptionKey: "内核拒绝了配置：\(msg)"])
        }
        if rename(tmp, configPath) != 0 { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
    }

    /// 守护进程崩溃后留下的孤儿内核会占住 TUN 和端口
    func killStale() {
        guard let s = try? String(contentsOfFile: pidPath, encoding: .utf8), let pid = pid_t(s.trimmingCharacters(in: .whitespacesAndNewlines)),
              pid > 1 else { return }
        var name = [CChar](repeating: 0, count: 1024)
        if proc_name(pid, &name, UInt32(name.count)) > 0, cString(name).hasPrefix("mihomo") {
            Log.write("清理残留内核进程 \(pid)")
            kill(pid, SIGTERM)
            for _ in 0..<30 where kill(pid, 0) == 0 { usleep(100_000) }
            if kill(pid, 0) == 0 { kill(pid, SIGKILL) }
        }
        try? FileManager.default.removeItem(atPath: pidPath)
    }

    func start() throws {
        lock.lock()
        defer { lock.unlock() }
        if process?.isRunning == true { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: binary)
        p.arguments = ["-d", home, "-f", configPath]
        p.currentDirectoryURL = URL(fileURLWithPath: home)
        let logPath = logDir + "/mihomo.log"
        Log.rotate(logPath, maxBytes: 10 * 1024 * 1024)
        FileManager.default.createFile(atPath: logPath, contents: nil)
        if let h = FileHandle(forWritingAtPath: logPath) {
            h.seekToEndOfFile()
            p.standardOutput = h
            p.standardError = h
        }
        p.standardInput = FileHandle.nullDevice
        p.terminationHandler = { [weak self] proc in
            self?.onExit?(proc.terminationStatus)
        }
        try p.run()
        process = p
        try? String(p.processIdentifier).write(toFile: pidPath, atomically: true, encoding: .utf8)
        Log.write("内核已启动 pid=\(p.processIdentifier)")
    }

    func noteRestart() {
        lock.lock()
        restarts += 1
        lock.unlock()
    }

    func stop() {
        lock.lock()
        let p = process
        process = nil
        lock.unlock()
        guard let p, p.isRunning else { return }
        p.terminationHandler = nil
        p.terminate()
        for _ in 0..<50 where p.isRunning { usleep(100_000) }
        if p.isRunning { kill(p.processIdentifier, SIGKILL) }
        try? FileManager.default.removeItem(atPath: pidPath)
        Log.write("内核已停止")
    }
}
