package com.aiguard.daemon

import android.system.Os
import android.system.OsConstants
import com.aiguard.core.BundledRuleSets
import java.io.File
import java.io.IOException
import java.util.zip.ZipFile
import kotlin.concurrent.thread

/** mihomo 内核进程（root 运行）。onExit 只对仍是当前进程的退出回调，旧进程的退出不算 */
class CoreProcess(private val binary: File, private val home: File, private val config: File, private val logDir: File) {
    @Volatile
    private var process: Process? = null

    @Volatile
    var restarts = 0
        private set

    var onExit: ((Int) -> Unit)? = null

    val isRunning: Boolean get() = process?.isAlive == true

    /** 当前内核的 pid（Android 的 Process 没有公开 pid，按可执行文件路径从 /proc 找） */
    fun pids(): Set<Int> = Procs.list().filter { it.uid == 0 && it.argv.firstOrNull() == binary.path }.map { it.pid }.toSet()

    fun version(): String? {
        val r = Shell.run(binary.path, "-v", timeoutMs = 5000)
        if (!r.ok) return null
        return Regex("v\\d+\\.\\d+\\.\\d+").find(r.out)?.value
    }

    fun writeConfig(yaml: String) = writeAtomic(config, yaml)

    /** 上一个守护进程留下的内核（守护进程被杀时内核不会跟着退出） */
    fun killStale() {
        val stale = Procs.list().filter { it.uid == 0 && it.argv.firstOrNull() == binary.path }
        stale.forEach { Procs.kill(it.pid, OsConstants.SIGTERM) }
        repeat(30) {
            if (stale.none { Procs.alive(it.pid) }) return
            Thread.sleep(100)
        }
        stale.forEach { Procs.kill(it.pid, OsConstants.SIGKILL) }
    }

    fun start() {
        if (isRunning) return
        val log = File(logDir, "mihomo.log")
        Log.rotate(log, 10L shl 20)
        val p = ProcessBuilder(binary.path, "-d", home.path, "-f", config.path)
            .directory(home)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.appendTo(log))
            .start()
        process = p
        thread(name = "mihomo-wait", isDaemon = true) {
            val code = runCatching { p.waitFor() }.getOrDefault(-1)
            if (process === p) onExit?.invoke(code)
        }
    }

    fun noteRestart() {
        restarts++
    }

    fun stop() {
        val p = process ?: return
        process = null
        p.destroy()
        if (!runCatching { p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) }.getOrDefault(false)) p.destroyForcibly()
    }
}

/**
 * 从守护进程自己的 APK 里同步内核与规则库：界面升级后只需替换 APK，文件内容按 CRC 判断是否变化。
 * 先写临时文件再改名，正在运行的内核不会因为覆盖而出错
 */
object AssetSync {
    fun sync(apk: File): List<String> {
        val changed = mutableListOf<String>()
        ZipFile(apk).use { zip ->
            fun extract(entryName: String, dst: File, mode: Int) {
                val e = zip.getEntry(entryName) ?: throw IOException("APK 缺少 $entryName")
                val stamp = File(dst.parentFile, ".${dst.name}.crc")
                val want = "${e.crc}:${e.size}"
                if (dst.isFile && dst.length() == e.size && stamp.takeIf { it.isFile }?.readText() == want) return
                dst.parentFile?.mkdirs()
                val tmp = File(dst.parentFile, ".${dst.name}.tmp")
                zip.getInputStream(e).use { input -> tmp.outputStream().use { input.copyTo(it) } }
                Os.chmod(tmp.path, mode)
                if (!tmp.renameTo(dst)) throw IOException("无法替换 ${dst.path}")
                stamp.writeText(want)
                changed.add(dst.name)
            }
            extract("assets/core/mihomo", Paths.mihomo, "700".toInt(8))
            for (f in BundledRuleSets.files) extract("assets/rules/$f", File(Paths.coreRules, f), "600".toInt(8))
            extract("assets/rules/${BundledRuleSets.CN_TABLE}", Paths.cnTable, "600".toInt(8))
        }
        return changed
    }
}
