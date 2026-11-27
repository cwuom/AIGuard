package com.aiguard.daemon

import android.system.OsConstants
import com.aiguard.core.AIGuardJson
import com.aiguard.core.CoreRuntime
import com.aiguard.core.ProcessMatch
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import java.io.File
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket

/** 网卡与路由状态（每秒读一次，全是本地系统调用） */
object NetInspector {
    data class Iface(val name: String, val ipv4: List<String>)

    /** 不算物理网络的接口：回环、TUN（含本软件和其他 VPN）、虚拟网卡 */
    private val virtualPrefixes = listOf("lo", "tun", "dummy", "ifb", "p2p", "sit", "ip6tnl", "ip_vti", "ip6_vti", "gre", "erspan", "bond", "veth")

    fun interfaces(): List<Iface> = runCatching {
        NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            .filter { runCatching { it.isUp }.getOrDefault(false) }
            .map { ni -> Iface(ni.name, ni.inetAddresses.toList().filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress }) }
    }.getOrDefault(emptyList())

    fun isPhysical(name: String): Boolean = name != CoreRuntime.TUN_DEVICE && virtualPrefixes.none { name.startsWith(it) }

    /** 物理网络指纹：网卡或 IPv4 地址变化即视为换网 */
    fun fingerprint(list: List<Iface>): String =
        list.filter { isPhysical(it.name) && it.ipv4.isNotEmpty() }
            .sortedBy { it.name }.joinToString(";") { "${it.name}=${it.ipv4.sorted().joinToString(",")}" }

    /** 主网卡：Wi-Fi/有线优先，其次蜂窝 */
    fun primary(list: List<Iface>): String? {
        val phys = list.filter { isPhysical(it.name) && it.ipv4.isNotEmpty() }
        return phys.firstOrNull { it.name.startsWith("wlan") || it.name.startsWith("eth") }?.name ?: phys.firstOrNull()?.name
    }

    fun tunInterface(list: List<Iface>): String? =
        list.firstOrNull { it.name == CoreRuntime.TUN_DEVICE && CoreRuntime.TUN_ADDRESS in it.ipv4 }?.name

    /** 普通 App 访问外网实际走的网卡（按 uid 查策略路由） */
    fun routeInterface(uid: Int): String? {
        val r = Shell.run("/system/bin/ip", "-4", "route", "get", "1.1.1.1", "uid", "$uid", timeoutMs = 3000)
        if (!r.ok) return null
        return Regex("""\bdev (\S+)""").find(r.out)?.groupValues?.get(1)
    }

    /** 其他 TUN（VPN App、别的代理模块）会抢路由 */
    fun foreignTuns(list: List<Iface>): List<String> =
        list.map { it.name }.filter { it != CoreRuntime.TUN_DEVICE && (it.startsWith("tun") || File("/sys/class/net/$it/tun_flags").exists()) }
}

/** 主动尝试直连公网 IPv6：连得上说明 IPv6 封锁失效 */
object Ipv6Probe {
    fun canReachInternet(timeoutMs: Int = 2000): Boolean =
        listOf("2606:4700:4700::1111", "2001:4860:4860::8888").any { addr ->
            runCatching { Socket().use { it.connect(InetSocketAddress(addr, 443), timeoutMs); true } }.getOrDefault(false)
        }
}

/**
 * 关闭 Wi-Fi/有线网卡的 IPv6（sysctl disable_ipv6），关闭守护时按备份恢复。
 * 蜂窝网卡不动：纯 IPv6 网络靠 464XLAT 上 IPv4，关掉会整机断网；这类网卡的 IPv6 只靠防火墙拒绝
 */
class Ipv6Switch(private val backupFile: File) {
    private val serializer = MapSerializer(String.serializer(), String.serializer())
    private var backup: MutableMap<String, String> = runCatching {
        AIGuardJson.decodeFromString(serializer, backupFile.readText()).toMutableMap()
    }.getOrDefault(mutableMapOf())

    val disabledCount: Int get() = backup.size

    private fun target(name: String) = listOf("wlan", "eth", "usb", "rndis").any { name.startsWith(it) }

    private fun conf(name: String) = File("/proc/sys/net/ipv6/conf/$name/disable_ipv6")

    /** 返回无法修改的网卡 */
    fun disableAll(ifaces: List<String>): List<String> {
        val failed = mutableListOf<String>()
        for (name in ifaces.filter(::target)) {
            val f = conf(name)
            val cur = runCatching { f.readText().trim() }.getOrNull() ?: continue
            if (cur == "1") continue
            backup.putIfAbsent(name, cur)
            save()
            if (runCatching { f.writeText("1") }.isFailure) failed.add(name)
        }
        return failed
    }

    fun restoreAll() {
        for ((name, value) in backup) runCatching { conf(name).takeIf { it.exists() }?.writeText(value) }
        backup.clear()
        save()
    }

    private fun save() {
        runCatching { writeAtomic(backupFile, AIGuardJson.encodeToString(serializer, backup)) }
    }
}

/** 系统「私人 DNS」（DoT）会绕开 TUN 的 DNS 劫持：守护开启时关掉，关闭守护时恢复原设置 */
class PrivateDnsLock(private val backupFile: File) {
    private val serializer = MapSerializer(String.serializer(), String.serializer())

    val locked: Boolean get() = backupFile.isFile

    private fun get(key: String): String? {
        val r = Shell.run("/system/bin/settings", "get", "global", key, timeoutMs = 8000)
        return if (r.ok) r.out.lines().lastOrNull()?.trim() else null
    }

    private fun put(key: String, value: String?): Boolean {
        val cmd = if (value == null || value == "null") listOf("/system/bin/settings", "delete", "global", key)
        else listOf("/system/bin/settings", "put", "global", key, value)
        return Shell.run(cmd, timeoutMs = 8000).ok
    }

    /** 返回 true 表示这次真的改动了设置（用户手动改回来过） */
    fun lock(): Boolean {
        val mode = get("private_dns_mode") ?: return false
        if (mode == "off") {
            if (!locked) writeBackup(mapOf("mode" to "off"))
            return false
        }
        if (!locked) writeBackup(mapOf("mode" to mode, "specifier" to (get("private_dns_specifier") ?: "null")))
        return put("private_dns_mode", "off")
    }

    fun restore() {
        if (!locked) return
        val b = runCatching { AIGuardJson.decodeFromString(serializer, backupFile.readText()) }.getOrNull()
        if (b != null) {
            b["specifier"]?.let { put("private_dns_specifier", it) }
            put("private_dns_mode", b["mode"])
        }
        backupFile.delete()
    }

    private fun writeBackup(map: Map<String, String>) {
        runCatching { writeAtomic(backupFile, AIGuardJson.encodeToString(serializer, map)) }
    }
}

/**
 * 熔断时关闭 AI App、浏览器与 AI 命令行进程。
 * 先 SIGKILL 让它们立刻断开，再 am force-stop 取消闹钟和任务，防止被系统马上拉起
 */
class AppCloser(private val selfPackage: String) {
    enum class Kind { AI, BROWSER }

    private var packagesCache: Map<String, Int> = emptyMap()
    private var packagesAt = 0L

    /** /data/system/packages.list：包名 → appId */
    private fun installed(): Map<String, Int> {
        val now = System.currentTimeMillis()
        if (now - packagesAt < 5 * 60_000 && packagesCache.isNotEmpty()) return packagesCache
        packagesCache = runCatching {
            File("/data/system/packages.list").readLines().mapNotNull { line ->
                val parts = line.split(' ')
                val uid = parts.getOrNull(1)?.toIntOrNull() ?: return@mapNotNull null
                parts[0] to uid
            }.toMap()
        }.getOrDefault(emptyMap())
        packagesAt = now
        return packagesCache
    }

    /** stillWanted 在动手前再确认一次（例如熔断已经解除就不关了）。返回被关闭的名字 */
    fun close(kinds: Set<Kind>, extraPackages: List<String>, appUid: Int?, stillWanted: () -> Boolean): List<String> {
        val pkgs = installed()
        val targets = ProcessMatch.targetPackages(pkgs.keys, extraPackages, Kind.BROWSER in kinds, selfPackage)
        val byAppId = pkgs.entries.groupBy({ it.value }, { it.key })
        // 共享 uid 的包里只要有一个不在目标里，就不按 uid 杀进程（交给 force-stop 按包名处理）
        val killableIds = targets.mapNotNull { pkgs[it] }.filter { id -> id >= 10000 && byAppId[id].orEmpty().all { it in targets } }.toSet()
        val running = linkedSetOf<String>()
        val victims = mutableListOf<Int>()
        val cliNames = linkedSetOf<String>()
        for (p in Procs.list()) {
            val appId = p.uid % 100_000
            if (appId < 10000 || p.uid == appUid) continue
            val argv0 = p.argv.firstOrNull() ?: continue
            val pkg = argv0.substringBefore(':')
            if (pkg in targets) {
                running.add(pkg)
                if (appId in killableIds) victims.add(p.pid)
            } else if (ProcessMatch.isAICommandLine(p.argv)) {
                victims.add(p.pid)
                cliNames.add(argv0.substringAfterLast('/') + (ProcessMatch.entryPoint(p.argv)?.let { " ${it.substringAfterLast('/')}" } ?: ""))
            }
        }
        if (victims.isEmpty() && running.isEmpty()) return emptyList()
        if (!stillWanted()) return emptyList()
        victims.forEach { Procs.kill(it, OsConstants.SIGKILL) }
        for (pkg in running) Shell.run("/system/bin/am", "force-stop", "--user", "all", pkg, timeoutMs = 8000)
        return (running + cliNames).toList()
    }
}

/** 其他代理软件：别的 TUN 网卡或常见代理内核进程 */
object ConflictScanner {
    private val names = mapOf(
        "sing-box" to "sing-box", "xray" to "Xray", "v2ray" to "V2Ray", "clash" to "Clash", "mihomo" to "mihomo（其他实例）",
        "hysteria" to "Hysteria", "tuic-client" to "TUIC", "naive" to "NaiveProxy", "tun2socks" to "tun2socks",
    )

    fun scan(excludePids: Set<Int>, ownBinary: String): List<String> {
        val found = linkedSetOf<String>()
        NetInspector.foreignTuns(NetInspector.interfaces()).forEach { found.add("其他 VPN/TUN：$it") }
        for (p in Procs.list()) {
            if (p.pid in excludePids) continue
            val exe = p.argv.firstOrNull() ?: continue
            if (exe == ownBinary) continue
            val base = exe.substringAfterLast('/').lowercase()
            names[base]?.let { found.add(it) }
        }
        return found.toList()
    }
}
