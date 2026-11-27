package com.aiguard.daemon

import android.system.Os
import com.aiguard.core.DaemonPaths
import java.io.File
import java.io.IOException
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** 守护进程在 /data/adb/aiguard 下的文件布局（只有 root 可读写） */
object Paths {
    val root = File(DaemonPaths.ROOT)
    val apk = File(DaemonPaths.APK)
    val bin = File(root, "bin")
    val mihomo = File(bin, "mihomo")
    val coreHome = File(root, "core")
    val coreConfig = File(coreHome, "config.yaml")
    val providerFile = File(coreHome, "providers/sub.yaml")
    val coreRules = File(coreHome, "rules")
    val cnTable = File(root, "rules/cn4.txt")
    val settings = File(root, "settings.json")
    val runtime = File(root, "runtime.json")
    val events = File(root, "events.json")
    val state = File(root, "state")
    val logs = File(root, "logs")
    val token = File(DaemonPaths.TOKEN)
    val appUid = File(DaemonPaths.APP_UID)
    val uninstallFlag = File(DaemonPaths.UNINSTALL_FLAG)

    fun ensureDirs() {
        for (d in listOf(root, bin, coreHome, File(coreHome, "providers"), coreRules, cnTable.parentFile!!, state, logs)) {
            d.mkdirs()
            runCatching { Os.chmod(d.path, "700".toInt(8)) }
        }
    }
}

/** 先写临时文件再改名：写一半断电不会留下损坏的文件；权限固定 0600 */
fun writeAtomic(file: File, bytes: ByteArray, mode: Int = "600".toInt(8)) {
    val tmp = File(file.parentFile, ".${file.name}.tmp")
    tmp.outputStream().use {
        it.write(bytes)
        it.fd.sync()
    }
    Os.chmod(tmp.path, mode)
    if (!tmp.renameTo(file)) {
        tmp.delete()
        throw IOException("无法写入 ${file.path}")
    }
}

fun writeAtomic(file: File, text: String) = writeAtomic(file, text.toByteArray())

object Secrets {
    private val rng = SecureRandom()
    fun random(bytes: Int = 24): String {
        val b = ByteArray(bytes)
        rng.nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }
}

/** 调用系统命令（守护进程本身就是 root，不经过 su）。stdout 与 stderr 合并，超时强杀 */
object Shell {
    data class Result(val code: Int, val out: String) {
        val ok: Boolean get() = code == 0
    }

    fun run(vararg cmd: String, stdin: String? = null, timeoutMs: Long = 15_000): Result = run(cmd.toList(), stdin, timeoutMs)

    fun run(cmd: List<String>, stdin: String? = null, timeoutMs: Long = 15_000): Result {
        val p = try {
            ProcessBuilder(cmd).redirectErrorStream(true).start()
        } catch (e: IOException) {
            return Result(-1, e.message ?: "无法启动 ${cmd.first()}")
        }
        // 输出必须并发读取：iptables-restore 出错时会回显大量内容，管道写满会卡死
        val out = StringBuilder()
        val reader = thread(name = "shell-out") {
            runCatching { p.inputStream.bufferedReader().use { r -> r.lineSequence().forEach { if (out.length < 64 * 1024) out.appendLine(it) } } }
        }
        runCatching {
            p.outputStream.use { os -> if (stdin != null) os.write(stdin.toByteArray()) }
        }
        val finished = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        if (!finished) {
            p.destroyForcibly()
            reader.join(500)
            return Result(-2, "${cmd.first()} 超时")
        }
        reader.join(2000)
        return Result(p.exitValue(), out.toString().trim())
    }
}

/** 守护进程日志：/data/adb/aiguard/logs/daemon.log，超过 5 MB 轮转一份 */
object Log {
    private val file get() = File(Paths.logs, "daemon.log")
    private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.ROOT)

    @Synchronized
    fun write(message: String) {
        runCatching {
            rotate(file, 5L shl 20)
            file.appendText("${fmt.format(Date())} $message\n")
        }
    }

    fun rotate(f: File, maxBytes: Long) {
        if (f.length() > maxBytes) {
            val old = File(f.path + ".1")
            old.delete()
            f.renameTo(old)
        }
    }
}

/** /proc 下的进程枚举 */
object Procs {
    data class Proc(val pid: Int, val uid: Int, val argv: List<String>)

    fun list(): List<Proc> {
        val dirs = File("/proc").listFiles() ?: return emptyList()
        return dirs.mapNotNull { d ->
            val pid = d.name.toIntOrNull() ?: return@mapNotNull null
            val uid = runCatching { Os.stat(d.path).st_uid }.getOrNull() ?: return@mapNotNull null
            val argv = runCatching { com.aiguard.core.ProcessMatch.parseCmdline(File(d, "cmdline").readBytes()) }.getOrNull()
                ?: return@mapNotNull null
            Proc(pid, uid, argv)
        }
    }

    fun kill(pid: Int, signal: Int) {
        runCatching { Os.kill(pid, signal) }
    }

    fun alive(pid: Int): Boolean = File("/proc/$pid").exists()
}
