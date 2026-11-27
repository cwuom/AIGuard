package com.aiguard.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import okhttp3.ConnectionPool
import okhttp3.Credentials
import okhttp3.Dispatcher
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.time.Instant
import java.util.concurrent.TimeUnit

private val jsonType = "application/json".toMediaType()

internal fun JsonElement?.obj(): JsonObject? = this as? JsonObject
internal fun JsonElement?.str(): String? = (this as? JsonPrimitive)?.takeIf { it.isString }?.content
internal fun JsonElement?.int(): Int? = (this as? JsonPrimitive)?.intOrNull
internal fun JsonElement?.long(): Long? = (this as? JsonPrimitive)?.longOrNull
internal fun JsonElement?.bool(): Boolean? = (this as? JsonPrimitive)?.booleanOrNull
internal fun JsonElement?.arr(): JsonArray? = this as? JsonArray

/** mihomo RESTful API 客户端（只连 127.0.0.1，不走任何代理） */
class MihomoApi(val baseUrl: String, private val secret: String) {
    private val client = OkHttpClient.Builder()
        .proxy(Proxy.NO_PROXY)
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .build()

    /** 最近一次重载失败时内核返回的信息，方便写日志 */
    @Volatile
    var lastReloadError: String? = null
        private set

    private fun url(vararg segments: String, query: Map<String, String> = emptyMap()): HttpUrl {
        // 策略组名包含中文和空格，必须逐段编码
        val b = baseUrl.toHttpUrl().newBuilder()
        segments.forEach { b.addPathSegment(it) }
        query.forEach { (k, v) -> b.addQueryParameter(k, v) }
        return b.build()
    }

    private suspend fun call(
        url: HttpUrl, method: String = "GET", body: String? = null, timeoutMs: Long = 5000,
    ): Pair<Int, String>? = withContext(Dispatchers.IO) {
        val rb: RequestBody? = body?.toRequestBody(jsonType) ?: if (method == "PUT") ByteArray(0).toRequestBody() else null
        val req = Request.Builder().url(url).method(method, rb).header("Authorization", "Bearer $secret").build()
        val c = client.newCall(req)
        c.timeout().timeout(timeoutMs, TimeUnit.MILLISECONDS)
        try {
            c.execute().use { r -> r.code to r.body.string() }
        } catch (_: IOException) {
            null
        }
    }

    private suspend fun json(url: HttpUrl, timeoutMs: Long = 5000): JsonObject? {
        val (code, text) = call(url, timeoutMs = timeoutMs) ?: return null
        if (code != 200) return null
        return runCatching { AIGuardJson.parseToJsonElement(text).obj() }.getOrNull()
    }

    suspend fun version(): String? = json(url("version"), 2000)?.get("version").str()

    /** 经指定策略组测一次延迟（不经过规则和闸门），失败返回 null */
    suspend fun delay(proxy: String, testUrl: String, timeoutMs: Int): Int? {
        val o = json(url("proxies", proxy, "delay", query = mapOf("url" to testUrl, "timeout" to "$timeoutMs")), timeoutMs + 2000L)
        return o?.get("delay").int()?.takeIf { it > 0 }
    }

    suspend fun select(group: String, proxy: String): Boolean {
        val body = AIGuardJson.encodeToString(JsonObject.serializer(), JsonObject(mapOf("name" to JsonPrimitive(proxy))))
        val code = call(url("proxies", group), "PUT", body)?.first
        return code == 204 || code == 200
    }

    data class GroupInfo(val now: String?, val all: List<String>)

    suspend fun group(name: String): GroupInfo? {
        val o = json(url("proxies", name)) ?: return null
        return GroupInfo(o["now"].str(), o["all"].arr()?.mapNotNull { it.str() }.orEmpty())
    }

    /** 内核对这个节点的最新健康判断（null 表示查询失败） */
    suspend fun isAlive(name: String): Boolean? = json(url("proxies", name))?.get("alive").bool()

    suspend fun reloadConfig(path: String): Boolean {
        val body = AIGuardJson.encodeToString(JsonObject.serializer(), JsonObject(mapOf("path" to JsonPrimitive(path))))
        val (code, text) = call(url("configs", query = mapOf("force" to "true")), "PUT", body, 20_000) ?: return false
        if (code != 204 && code != 200) lastReloadError = text.take(300)
        return code == 204 || code == 200
    }

    suspend fun reloadProvider(name: String): Boolean {
        val code = call(url("providers", "proxies", name), "PUT", null, 20_000)?.first
        return code == 204 || code == 200
    }

    suspend fun providerCount(name: String): Int? = json(url("providers", "proxies", name))?.get("proxies").arr()?.size

    data class ProxyItem(
        val name: String,
        val type: String,
        val now: String?,
        val all: List<String>,
        val lastDelay: Int?,
        val alive: Boolean,
        /** 测过至少一次；配合 lastDelay == null 区分「超时」和「未测速」 */
        val tested: Boolean,
    )

    /**
     * 全部节点与策略组（界面列表用）。订阅节点来自 proxy-provider，/proxies 里没有，必须再合并 /providers/proxies。
     * 两个接口任一失败都返回空，调用方保留上一份完整快照，避免节点延迟被半份结果抹掉
     */
    suspend fun proxies(): Map<String, ProxyItem> {
        val (c1, t1) = call(url("proxies")) ?: return emptyMap()
        val (c2, t2) = call(url("providers", "proxies")) ?: return emptyMap()
        if (c1 != 200 || c2 != 200) return emptyMap()
        return parseProxies(t1, t2)
    }

    suspend fun groupDelay(name: String, testUrl: String, timeoutMs: Int): Map<String, Int>? {
        val o = json(url("group", name, "delay", query = mapOf("url" to testUrl, "timeout" to "$timeoutMs")), timeoutMs + 10_000L)
            ?: return null
        return o.mapNotNull { (k, v) -> v.int()?.let { k to it } }.toMap()
    }

    data class Connection(
        val id: String,
        val host: String,
        val destination: String,
        val network: String,
        val chain: String,
        val rule: String,
        val upload: Long,
        val download: Long,
        val start: Long?,
        /** 链路实际出口（内核 chains 数组的第一项），节点名本身可能含「→」，不能从 chain 文本里切 */
        val leaf: String,
    ) {
        enum class Route { PROXY, DIRECT, REJECT }

        /** 只认内置出站的精确名字，节点名以 REJECT/DIRECT 开头也按代理算 */
        val route: Route
            get() = when (leaf) {
                "DIRECT" -> Route.DIRECT
                "REJECT", "REJECT-DROP" -> Route.REJECT
                else -> Route.PROXY
            }
    }

    data class ConnectionsSnapshot(val connections: List<Connection>, val uploadTotal: Long, val downloadTotal: Long)

    suspend fun connections(): ConnectionsSnapshot? = json(url("connections"))?.let(::parseConnections)

    suspend fun closeConnection(id: String) {
        call(url("connections", id), "DELETE")
    }

    /** 返回内核是否确认已断开全部连接 */
    suspend fun flushConnections(): Boolean {
        val code = call(url("connections"), "DELETE")?.first
        return code == 204 || code == 200
    }

    companion object {
        /** providers 不为 null 却解析不出结构时整体返回空：半份快照会抹掉订阅节点的测速结果 */
        fun parseProxies(proxiesJson: String, providersJson: String?): Map<String, ProxyItem> {
            val map = runCatching { AIGuardJson.parseToJsonElement(proxiesJson).obj()?.get("proxies").obj() }.getOrNull()
                ?: return emptyMap()
            val out = LinkedHashMap<String, ProxyItem>()
            for ((name, p) in map) p.obj()?.let { out[name] = item(name, it) }
            if (providersJson != null) {
                val pmap = runCatching { AIGuardJson.parseToJsonElement(providersJson).obj()?.get("providers").obj() }.getOrNull()
                    ?: return emptyMap()
                for ((_, prov) in pmap) {
                    for (p in prov.obj()?.get("proxies").arr().orEmpty()) {
                        val o = p.obj() ?: continue
                        val name = o["name"].str() ?: continue
                        // 顶层同名项（策略组、DIRECT 等）以 /proxies 为准
                        if (name !in out) out[name] = item(name, o)
                    }
                }
            }
            return out
        }

        private fun item(name: String, p: JsonObject): ProxyItem {
            val history = p["history"].arr().orEmpty()
            val last = history.lastOrNull().obj()?.get("delay").int()?.takeIf { it > 0 }
            return ProxyItem(
                name = name, type = p["type"].str().orEmpty(), now = p["now"].str(),
                all = p["all"].arr()?.mapNotNull { it.str() }.orEmpty(), lastDelay = last,
                alive = p["alive"].bool() ?: true, tested = history.isNotEmpty(),
            )
        }

        fun parseConnections(o: JsonObject): ConnectionsSnapshot {
            val list = o["connections"].arr().orEmpty().mapNotNull { it.obj() }.map { c ->
                val m = c["metadata"].obj() ?: JsonObject(emptyMap())
                val host = m["host"].str()?.takeIf { it.isNotEmpty() } ?: m["sniffHost"].str().orEmpty()
                val dst = "${m["destinationIP"].str().orEmpty()}:${m["destinationPort"].str() ?: m["destinationPort"].int()?.toString().orEmpty()}"
                val rawChains = c["chains"].arr()?.mapNotNull { it.str() }.orEmpty()
                val chains = rawChains.filterNot { it.startsWith(GroupName.INTERNAL_PREFIX) }
                val rule = listOfNotNull(c["rule"].str(), c["rulePayload"].str()).filter { it.isNotEmpty() }.joinToString(" · ")
                val start = c["start"].str()?.let { runCatching { Instant.parse(it).toEpochMilli() }.getOrNull() }
                Connection(
                    id = c["id"].str() ?: "", host = host, destination = dst,
                    network = m["network"].str().orEmpty().uppercase(), chain = chains.reversed().joinToString(" → "),
                    rule = rule, upload = c["upload"].long() ?: 0, download = c["download"].long() ?: 0, start = start,
                    leaf = rawChains.firstOrNull().orEmpty(),
                )
            }.filter { it.id.isNotEmpty() }
            return ConnectionsSnapshot(list, o["uploadTotal"].long() ?: 0, o["downloadTotal"].long() ?: 0)
        }
    }
}

/** 经本机带认证的 HTTP 代理入站发请求（心跳、出口检测、订阅下载） */
class ProxiedFetcher(private val user: String, private val password: String) {
    private val clients = HashMap<Int, OkHttpClient>()
    private val base = OkHttpClient.Builder()
        .followRedirects(true)
        .retryOnConnectionFailure(false)
        .build()

    @Synchronized
    private fun client(port: Int?): OkHttpClient {
        val key = port ?: 0
        clients[key]?.let { return it }
        // 每个端口独立连接池：重置探测长连接时不能连带掐断其他入站的请求
        val b = base.newBuilder().connectionPool(ConnectionPool()).dispatcher(Dispatcher())
        if (port != null) {
            b.proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port)))
            b.proxyAuthenticator { _, response ->
                if (response.request.header("Proxy-Authorization") != null) null
                else response.request.newBuilder().header("Proxy-Authorization", Credentials.basic(user, password)).build()
            }
        } else {
            b.proxy(Proxy.NO_PROXY)
        }
        return b.build().also { clients[key] = it }
    }

    /** 丢弃某个端口的长连接：节点切换后旧连接还连着旧节点，必须重建 */
    @Synchronized
    fun reset(port: Int?) {
        clients.remove(port ?: 0)?.let {
            it.connectionPool.evictAll()
            it.dispatcher.cancelAll()
        }
    }

    @Synchronized
    fun resetAll() {
        clients.values.forEach { it.connectionPool.evictAll() }
        clients.clear()
    }

    class FetchResult(val code: Int, val body: ByteArray, val headers: Map<String, String>)

    /** 带大小上限的下载（订阅用）：守护进程以 root 常驻，不能被超大响应撑爆内存 */
    suspend fun fetch(
        url: String, port: Int?, timeoutMs: Long, maxBytes: Int = 1 shl 20, headers: Map<String, String> = emptyMap(),
    ): FetchResult = withContext(Dispatchers.IO) {
        val rb = Request.Builder().url(url).header("Cache-Control", "no-cache")
        headers.forEach { (k, v) -> rb.header(k, v) }
        val call = client(port).newCall(rb.build())
        call.timeout().timeout(timeoutMs, TimeUnit.MILLISECONDS)
        call.execute().use { r -> FetchResult(r.code, readLimited(r, maxBytes), r.headers.toMap()) }
    }

    private fun readLimited(r: Response, maxBytes: Int): ByteArray {
        val body = r.body
        if (body.contentLength() > maxBytes) throw IOException("响应超过 ${maxBytes / 1024} KB 上限")
        val source = body.source()
        val buf = okio.Buffer()
        while (source.read(buf, 8192) != -1L) {
            if (buf.size > maxBytes) throw IOException("响应超过 ${maxBytes / 1024} KB 上限")
        }
        return buf.readByteArray()
    }

    private suspend fun text(url: String, port: Int?, timeoutMs: Long): String? = try {
        val r = fetch(url, port, timeoutMs, maxBytes = 64 * 1024)
        if (r.code == 200) String(r.body, Charsets.UTF_8) else null
    } catch (_: IOException) {
        null
    }

    /**
     * 心跳：经长连接请求一次 Cloudflare trace。客户端按端口缓存，TLS 连接保持复用，
     * 每次心跳只是在同一条长连接上发一个小请求
     */
    suspend fun heartbeat(port: Int, timeoutMs: Long): ExitTrace? =
        text(CLOUDFLARE_TRACE, port, timeoutMs)?.let(ExitTrace::parseCloudflare)

    /** 备用出口查询（心跳里 Cloudflare 失败时用，超时受心跳剩余预算限制）。必须走 HTTPS，明文结果可被链路上篡改 */
    suspend fun ipinfo(port: Int, timeoutMs: Long): ExitTrace? {
        if (timeoutMs < 200) return null
        return text(IPINFO, port, timeoutMs)?.let(ExitTrace::parseJson)
    }

    /** 先查 Cloudflare trace，失败再查 ipinfo，两个都失败返回 null */
    suspend fun exitTrace(port: Int): ExitTrace? =
        text(CLOUDFLARE_TRACE, port, 6000)?.let(ExitTrace::parseCloudflare)
            ?: text(IPINFO, port, 6000)?.let(ExitTrace::parseJson)

    /** 经内核直连入站向阿里 DNS（JSON API）查 A 记录：不依赖代理、不经过闸门，熔断时也能用 */
    suspend fun resolveDirect(name: String, port: Int): List<String> {
        val url = "https://223.5.5.5/resolve".toHttpUrl().newBuilder()
            .addQueryParameter("name", name).addQueryParameter("type", "1").build().toString()
        val t = text(url, port, 5000) ?: return emptyList()
        val answers = runCatching { AIGuardJson.parseToJsonElement(t).obj()?.get("Answer").arr() }.getOrNull().orEmpty()
        return answers.mapNotNull { a -> a.obj()?.takeIf { it["type"].int() == 1 }?.get("data").str() }
    }

    companion object {
        const val CLOUDFLARE_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
        const val IPINFO = "https://ipinfo.io/json"
    }
}
