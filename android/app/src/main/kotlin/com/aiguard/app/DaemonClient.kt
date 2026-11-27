package com.aiguard.app

import android.content.Context
import android.os.Process
import androidx.core.content.edit
import com.aiguard.core.AIGuardJson
import com.aiguard.core.IpcEnvelope
import com.aiguard.core.IpcRequest
import com.aiguard.core.IpcResponse
import com.aiguard.core.Ports
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

/** 守护进程连不上（没装、没启动、被防火墙拦） */
class DaemonUnreachable(message: String) : IOException(message)

/** 本机 TCP 控制通道客户端；token 只存在 App 私有目录与 root 目录里 */
class DaemonClient(context: Context) {
    private val prefs = context.getSharedPreferences("daemon", Context.MODE_PRIVATE)

    val token: String? get() = prefs.getString(KEY_TOKEN, null)

    /** 每次安装守护进程都换新 token，旧 token 立即作废 */
    fun newToken(): String {
        val b = ByteArray(24)
        SecureRandom().nextBytes(b)
        // 同步落盘：随后 root 会拿这个 token 覆盖守护进程那一份，两边必须一致
        return b.joinToString("") { "%02x".format(it) }.also { prefs.edit(commit = true) { putString(KEY_TOKEN, it) } }
    }

    suspend fun request(req: IpcRequest, timeoutMs: Int = 20_000): IpcResponse = withContext(Dispatchers.IO) {
        val t = token ?: throw DaemonUnreachable("尚未安装守护进程")
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress("127.0.0.1", Ports.DAEMON), 1500)
                s.soTimeout = timeoutMs
                val out = s.getOutputStream()
                out.write(AIGuardJson.encodeToString(IpcEnvelope.serializer(), IpcEnvelope(t, req)).toByteArray())
                out.write('\n'.code)
                out.flush()
                val line = s.getInputStream().bufferedReader().readLine() ?: throw DaemonUnreachable("守护进程没有响应")
                AIGuardJson.decodeFromString(IpcResponse.serializer(), line)
            }
        } catch (e: ConnectException) {
            throw DaemonUnreachable("守护进程未运行")
        }
    }

    companion object {
        private const val KEY_TOKEN = "token"
    }
}

/** 通过 su 安装、升级、卸载守护进程 */
class RootInstaller(private val context: Context, private val client: DaemonClient) {
    data class Outcome(val ok: Boolean, val log: String)

    private suspend fun su(command: String, timeoutMs: Long = 60_000): Outcome = withContext(Dispatchers.IO) {
        val p = try {
            ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
        } catch (e: IOException) {
            return@withContext Outcome(false, "找不到 su：${e.message}")
        }
        val out = StringBuilder()
        val reader = Thread { runCatching { p.inputStream.bufferedReader().forEachLine { out.appendLine(it) } } }.apply { start() }
        val done = p.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        if (!done) p.destroyForcibly()
        reader.join(1000)
        Outcome(done && p.exitValue() == 0, out.toString().trim())
    }

    suspend fun checkRoot(): Outcome {
        val r = su("id", 15_000)
        return r.copy(ok = r.ok && "uid=0" in r.log)
    }

    suspend fun install(): Outcome = withContext(Dispatchers.IO) {
        val stage = File(context.filesDir, "stage").apply {
            deleteRecursively()
            mkdirs()
        }
        try {
            for (name in listOf("install.sh", "uninstall.sh", "watchdog.sh", "service.sh")) {
                context.assets.open("scripts/$name").use { input -> File(stage, name).outputStream().use { input.copyTo(it) } }
            }
            File(stage, "token").writeText(client.newToken())
            val apk = context.applicationInfo.sourceDir
            // 路径会拼进 shell 命令，只接受系统安装目录下的普通路径
            if (!apk.startsWith("/data/app/") || apk.any { it == '\'' || it == '\n' || it == '"' }) {
                return@withContext Outcome(false, "APK 路径异常：$apk")
            }
            val r = su("sh '${stage.path}/install.sh' '$apk' ${Process.myUid()} '${stage.path}'")
            r.copy(ok = r.ok && "AIGUARD_INSTALL_OK" in r.log)
        } finally {
            File(stage, "token").delete()
        }
    }

    suspend fun uninstall(purge: Boolean): Outcome {
        val r = su("sh /data/adb/aiguard/uninstall.sh${if (purge) " --purge" else ""}", 90_000)
        return r.copy(ok = r.ok && "AIGUARD_UNINSTALL_OK" in r.log)
    }
}
