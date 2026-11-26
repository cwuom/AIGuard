import AIGuardCore
import Darwin
import Foundation
import IOKit
import IOKit.pwr_mgt
import Network

/// 系统睡眠/唤醒通知。睡眠前必须同步完成断网再放行睡眠
final class PowerMonitor: @unchecked Sendable {
    // IOKit 头文件里的宏 Swift 导入不了，手动定义
    private static let canSleep: UInt32 = 0xE000_0270
    private static let willSleep: UInt32 = 0xE000_0280
    private static let hasPoweredOn: UInt32 = 0xE000_0300

    private var rootPort: io_connect_t = 0
    private var notifier: io_object_t = 0
    private var notifyPort: IONotificationPortRef?
    private let onWillSleep: () -> Void
    private let onWake: () -> Void

    init(onWillSleep: @escaping () -> Void, onWake: @escaping () -> Void) {
        self.onWillSleep = onWillSleep
        self.onWake = onWake
    }

    func start() {
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        rootPort = IORegisterForSystemPower(ctx, &notifyPort, { refcon, _, messageType, argument in
            guard let refcon else { return }
            let me = Unmanaged<PowerMonitor>.fromOpaque(refcon).takeUnretainedValue()
            me.handle(messageType: messageType, argument: argument)
        }, &notifier)
        guard rootPort != 0, let notifyPort else {
            Log.write("注册电源通知失败")
            return
        }
        CFRunLoopAddSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(notifyPort).takeUnretainedValue(), .commonModes)
    }

    private func handle(messageType: UInt32, argument: UnsafeMutableRawPointer?) {
        let notificationID = Int(bitPattern: argument)
        switch messageType {
        case Self.canSleep:
            IOAllowPowerChange(rootPort, notificationID)
        case Self.willSleep:
            onWillSleep()
            IOAllowPowerChange(rootPort, notificationID)
        case Self.hasPoweredOn:
            onWake()
        default:
            break
        }
    }
}

/// 物理网络变化（换 Wi-Fi、插拔网线、IP 变化）。忽略 utun，自己的 TUN 起落不算网络切换
final class NetworkMonitor: @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "aiguard.network")
    private var lastSignature: String?
    private var pending: DispatchWorkItem?
    private let onChange: (_ primary: String?) -> Void

    init(onChange: @escaping (_ primary: String?) -> Void) {
        self.onChange = onChange
    }

    func start() {
        monitor.pathUpdateHandler = { [weak self] path in self?.handle(path) }
        monitor.start(queue: queue)
    }

    static func signature(path: NWPath) -> (String, String?) {
        let physical = path.availableInterfaces.filter {
            $0.type == .wifi || $0.type == .wiredEthernet || $0.type == .cellular
        }
        let addrs = RouteInspector.interfaces()
        let parts = physical.map { iface in
            let ips = addrs.filter { $0.name == iface.name }.map(\.ipv4).sorted().joined(separator: ",")
            return "\(iface.name)=\(ips)"
        }
        return ("\(path.status == .satisfied)|" + parts.joined(separator: ";"), physical.first?.name)
    }

    /// 不做防抖：网卡变化立刻触发断网，赶在应用重连之前。
    /// 1.5 秒后再核对一次，捕捉随后才分配到的 IP（换 Wi-Fi 时 IP 往往晚于链路就绪）
    private func handle(_ path: NWPath) {
        check(path)
        pending?.cancel()
        let item = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.check(self.monitor.currentPath)
        }
        pending = item
        queue.asyncAfter(deadline: .now() + 1.5, execute: item)
    }

    private func check(_ path: NWPath) {
        let (sig, primary) = Self.signature(path: path)
        defer { lastSignature = sig }
        guard let last = lastSignature, last != sig else { return }
        onChange(primary)
    }

    func stop() {
        monitor.cancel()
        pending?.cancel()
    }

    var primaryInterface: String? {
        Self.signature(path: monitor.currentPath).1
    }
}

/// 本地控制通道：只接受 root 和安装时登记的用户
final class IPCServer: @unchecked Sendable {
    private let path: String
    private let allowedUIDs: Set<uid_t>
    private let handler: @Sendable (IPCRequest) async -> IPCResponse
    private var listenFD: Int32 = -1
    private var source: DispatchSourceRead?
    private let queue = DispatchQueue(label: "aiguard.ipc", attributes: .concurrent)

    init(path: String, allowedUIDs: Set<uid_t>, handler: @escaping @Sendable (IPCRequest) async -> IPCResponse) {
        self.path = path
        self.allowedUIDs = allowedUIDs
        self.handler = handler
    }

    func start() throws {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            buf.copyBytes(from: bytes)
            buf[bytes.count] = 0
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else {
            close(fd)
            throw POSIXError(.init(rawValue: errno) ?? .EADDRINUSE)
        }
        // 套接字本身对所有人可连，真正的鉴权在 getpeereid
        chmod(path, 0o666)
        guard listen(fd, 16) == 0 else {
            close(fd)
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        listenFD = fd
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        src.setEventHandler { [weak self] in self?.accept() }
        src.resume()
        source = src
    }

    private func accept() {
        let client = Darwin.accept(listenFD, nil, nil)
        guard client >= 0 else { return }
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(client, &uid, &gid) == 0, uid == 0 || allowedUIDs.contains(uid) else {
            Log.write("拒绝未授权的控制连接 uid=\(uid)")
            close(client)
            return
        }
        var tv = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let handler = self.handler
        queue.async {
            let response: IPCResponse
            do {
                let line = try UnixSocketIO.readLine(fd: client)
                let req = try IPCCodec.decoder().decode(IPCRequest.self, from: line)
                let sem = DispatchSemaphore(value: 0)
                let box = ResponseBox()
                Task {
                    box.value = await handler(req)
                    sem.signal()
                }
                sem.wait()
                response = box.value ?? .failure("内部错误")
            } catch {
                response = .failure("请求格式错误：\(error.localizedDescription)")
            }
            if var data = try? IPCCodec.encoder().encode(response) {
                data.append(0x0A)
                try? UnixSocketIO.writeAll(fd: client, data: data)
            }
            close(client)
        }
    }

    func stop() {
        source?.cancel()
        if listenFD >= 0 { close(listenFD) }
        unlink(path)
    }
}

private final class ResponseBox: @unchecked Sendable {
    var value: IPCResponse?
}
