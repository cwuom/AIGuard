package com.aiguard.daemon

import com.aiguard.core.FirewallBuilder
import com.aiguard.core.FirewallContext
import com.aiguard.core.FirewallPolicy
import java.io.File

/**
 * 执行 iptables 规则。主链挂在 OUTPUT 第一条，策略切换用 iptables-restore 原子提交；
 * 大陆 IP 链只在规则库变化时重建。netd 重启会清空 OUTPUT，所以要定期核对挂载点
 */
class Firewall(private val cnFile: File) {
    var current: FirewallPolicy = FirewallPolicy.None
        private set
    var lastError: String? = null
        private set

    var context = FirewallContext(appUid = null)

    private val applied = HashMap<String, String>()
    private var cnLoadedSize = -1L

    private data class Hook(val bin: String, val restore: String, val table: String, val chain: String)

    private val hooks = listOf(
        Hook(IPTABLES, IPTABLES_RESTORE, "filter", FirewallBuilder.CHAIN),
        Hook(IP6TABLES, IP6TABLES_RESTORE, "filter", FirewallBuilder.CHAIN6),
        Hook(IPTABLES, IPTABLES_RESTORE, "nat", FirewallBuilder.DNS_CHAIN),
    )

    /** 返回 false 表示有规则没能加载（此时只剩内核闸门一层） */
    fun apply(policy: FirewallPolicy, force: Boolean = false): Boolean {
        if (policy == FirewallPolicy.None) {
            teardown()
            return true
        }
        val errors = mutableListOf<String>()
        if (!ensureCnChain()) errors.add("大陆 IP 链加载失败")
        val texts = listOf(
            hooks[0] to FirewallBuilder.filter4(policy, context),
            hooks[1] to FirewallBuilder.filter6(policy),
            hooks[2] to FirewallBuilder.nat4(policy, context),
        )
        var changed = force || current == FirewallPolicy.None
        for ((hook, text) in texts) {
            text ?: continue
            val key = "${hook.bin}:${hook.table}"
            if (!force && applied[key] == text) continue
            changed = true
            val r = Shell.run(listOf(hook.restore, "-w", "--noflush"), stdin = text)
            if (r.ok) applied[key] = text else {
                applied.remove(key)
                errors.add("${hook.table}/${hook.chain}: ${r.out.take(200)}")
            }
        }
        // 规则没变时不必每秒核对挂载点（每次都要跑 iptables -S），由 verify() 定期检查
        if (changed) for (hook in hooks) if (!ensureHook(hook)) errors.add("无法挂载 ${hook.chain}")
        current = policy
        lastError = errors.takeIf { it.isNotEmpty() }?.joinToString("；")
        return errors.isEmpty()
    }

    /** 核对主链仍挂在 OUTPUT 第一条（netd 重启或其他防火墙软件会改动），被挪走就重新挂上。返回问题描述 */
    fun verify(): String? {
        if (current == FirewallPolicy.None) return null
        val broken = hooks.filter { !hookOnTop(it) }
        if (broken.isEmpty()) return null
        val names = broken.joinToString("、") { it.chain }
        // 链本身可能也被清空了，按当前策略强制重装
        applied.clear()
        cnLoadedSize = -1
        apply(current, force = true)
        return "防火墙挂载点被移除（$names），已重新挂载"
    }

    fun teardown() {
        hooks.forEach(::unhook)
        for (hook in hooks) {
            Shell.run(hook.bin, "-w", "-t", hook.table, "-F", hook.chain)
            Shell.run(hook.bin, "-w", "-t", hook.table, "-X", hook.chain)
        }
        Shell.run(IPTABLES, "-w", "-F", FirewallBuilder.CN_CHAIN)
        Shell.run(IPTABLES, "-w", "-X", FirewallBuilder.CN_CHAIN)
        applied.clear()
        cnLoadedSize = -1
        current = FirewallPolicy.None
        lastError = null
    }

    private fun ensureCnChain(): Boolean {
        val size = cnFile.length()
        if (size > 0 && size == cnLoadedSize && chainExists(FirewallBuilder.CN_CHAIN)) return true
        val cidrs = runCatching { cnFile.readLines().map { it.trim() }.filter { it.isNotEmpty() } }.getOrDefault(emptyList())
        if (cidrs.size < 1000) return false
        val r = Shell.run(listOf(IPTABLES_RESTORE, "-w", "--noflush"), stdin = FirewallBuilder.cnChain(cidrs), timeoutMs = 60_000)
        if (r.ok) cnLoadedSize = size
        return r.ok
    }

    private fun chainExists(chain: String): Boolean = Shell.run(IPTABLES, "-w", "-S", chain, "1").ok

    private fun hookOnTop(hook: Hook): Boolean {
        val r = Shell.run(hook.bin, "-w", "-t", hook.table, "-S", "OUTPUT")
        if (!r.ok) return false
        val first = r.out.lines().firstOrNull { it.startsWith("-A OUTPUT") }
        return first == "-A OUTPUT -j ${hook.chain}"
    }

    private fun ensureHook(hook: Hook): Boolean {
        if (hookOnTop(hook)) return true
        unhook(hook)
        return Shell.run(hook.bin, "-w", "-t", hook.table, "-I", "OUTPUT", "1", "-j", hook.chain).ok
    }

    /** 删掉所有挂载点（可能被重复挂过），最多删 5 次防止死循环 */
    private fun unhook(hook: Hook) {
        var attempts = 0
        while (attempts < 5) {
            attempts++
            if (!Shell.run(hook.bin, "-w", "-t", hook.table, "-D", "OUTPUT", "-j", hook.chain).ok) break
        }
    }

    companion object {
        const val IPTABLES = "/system/bin/iptables"
        const val IP6TABLES = "/system/bin/ip6tables"
        const val IPTABLES_RESTORE = "/system/bin/iptables-restore"
        const val IP6TABLES_RESTORE = "/system/bin/ip6tables-restore"
    }
}
