package com.aiguard.daemon

import android.system.Os
import com.aiguard.app.BuildConfig
import com.aiguard.core.AIGuardJson
import com.aiguard.core.IpcEnvelope
import com.aiguard.core.IpcResponse
import com.aiguard.core.Ports
import kotlinx.coroutines.runBlocking
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.concurrent.Executors
import kotlin.system.exitProcess

/**
 * root 守护进程入口，由看门狗脚本这样启动：
 * `CLASSPATH=/data/adb/aiguard/aiguard.apk app_process /system/bin --nice-name=aiguardd com.aiguard.daemon.DaemonMain`
 */
object DaemonMain {
    @JvmStatic
    fun main(args: Array<String>) {
        if (Os.getuid() != 0) {
            System.err.println("AIGuard 守护进程需要 root")
            exitProcess(1)
        }
        when (args.firstOrNull()) {
            "--version" -> {
                println(BuildConfig.VERSION_NAME)
                return
            }
            "--teardown" -> {
                teardown()
                return
            }
        }
        Paths.ensureDirs()
        Log.write("[info] ===== aiguardd ${BuildConfig.VERSION_NAME} 启动（pid ${Os.getpid()}）=====")
        val guardian = Guardian(BuildConfig.APPLICATION_ID, BuildConfig.VERSION_NAME)
        val server = try {
            ServerSocket(Ports.DAEMON, 16, InetAddress.getByName("127.0.0.1")).apply { reuseAddress = true }
        } catch (e: IOException) {
            // 端口被占用多半是旧守护进程还活着，交给看门狗退避重试
            Log.write("[critical] 控制端口 ${Ports.DAEMON} 无法监听：${e.message}")
            exitProcess(2)
        }
        guardian.start()
        IpcServer(server, guardian).serve()
    }

    /** 卸载时调用：撤销防火墙、恢复 IPv6 与私人 DNS、停掉内核 */
    private fun teardown() {
        CoreProcess(Paths.mihomo, Paths.coreHome, Paths.coreConfig, Paths.logs).killStale()
        Firewall(Paths.cnTable).teardown()
        Ipv6Switch(File(Paths.state, "ipv6.json")).restoreAll()
        PrivateDnsLock(File(Paths.state, "private_dns.json")).restore()
        println("teardown ok")
    }
}

/** 本机 TCP 控制通道：一行 JSON 请求、一行 JSON 响应。防火墙只允许 root 与界面 App 连接，另外校验 token */
class IpcServer(private val server: ServerSocket, private val guardian: Guardian) {
    private val pool = Executors.newFixedThreadPool(4)

    @Volatile
    private var token: Pair<Long, ByteArray>? = null

    /** token 文件在重装守护进程时会更新，按修改时间重新读取 */
    private fun currentToken(): ByteArray? {
        val f = Paths.token
        val mtime = f.lastModified()
        token?.let { (m, t) -> if (m == mtime) return t }
        val t = runCatching { f.readText().trim().toByteArray() }.getOrNull()?.takeIf { it.size >= 16 } ?: return null
        token = mtime to t
        return t
    }

    fun serve() {
        while (true) {
            val s = try {
                server.accept()
            } catch (e: IOException) {
                Log.write("[error] 控制通道 accept 失败：${e.message}")
                Thread.sleep(200)
                continue
            }
            pool.execute { handle(s) }
        }
    }

    private fun handle(s: Socket) {
        s.use { sock ->
            runCatching {
                sock.soTimeout = 15_000
                val line = readLine(sock) ?: return
                val response = try {
                    val env = AIGuardJson.decodeFromString(IpcEnvelope.serializer(), line)
                    val want = currentToken()
                    if (want == null || !MessageDigest.isEqual(want, env.token.toByteArray())) {
                        IpcResponse.failure("认证失败：请在 App 里重新安装守护进程")
                    } else {
                        runBlocking { guardian.handle(env.request) }
                    }
                } catch (e: kotlinx.serialization.SerializationException) {
                    IpcResponse.failure("请求格式错误：${e.message?.take(120)}")
                }
                val out = sock.getOutputStream()
                out.write(AIGuardJson.encodeToString(IpcResponse.serializer(), response).toByteArray())
                out.write('\n'.code)
                out.flush()
            }.onFailure { if (it !is IOException) Log.write("[error] 控制请求处理失败：${it.javaClass.simpleName}: ${it.message}") }
        }
    }

    private fun readLine(sock: Socket): String? {
        val input = sock.getInputStream().buffered()
        val buf = java.io.ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b < 0) break
            if (b == '\n'.code) break
            buf.write(b)
            if (buf.size() > IpcResponse.MAX_MESSAGE_BYTES) return null
        }
        return buf.toString(Charsets.UTF_8.name()).takeIf { it.isNotBlank() }
    }
}
