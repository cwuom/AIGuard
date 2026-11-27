package com.aiguard.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import java.net.URI
import java.net.URLDecoder
import java.util.Base64

data class ParsedSubscription(
    val nodeCount: Int,
    /** 写给 mihomo 文件型 proxy-provider 的内容 */
    val providerContent: String,
)

class SubscriptionException(message: String) : Exception(message) {
    companion object {
        const val INVALID_URL = "订阅链接无效，只支持 http/https"
        const val EMPTY = "订阅返回了空内容"
        const val UNRECOGNIZED = "无法识别订阅格式（需要 Clash YAML 或节点链接列表）"
        const val NO_NODES = "订阅里没有可用节点"
        fun http(code: Int) = SubscriptionException("订阅服务器返回 HTTP $code")
    }
}

object SubscriptionParser {
    private val schemes = listOf(
        "ss://", "ssr://", "vmess://", "vless://", "trojan://", "hysteria://", "hysteria2://",
        "hy2://", "tuic://", "anytls://", "wireguard://", "wg://", "socks5://", "socks://", "snell://",
    )

    fun validateUrl(raw: String): URI? {
        val uri = runCatching { URI(raw.trim()) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null
        if (scheme != "https" && scheme != "http") return null
        if (uri.host.isNullOrEmpty()) return null
        return uri
    }

    fun parse(data: ByteArray): ParsedSubscription {
        val text = String(data, Charsets.UTF_8).trim()
        if (text.isEmpty()) throw SubscriptionException(SubscriptionException.EMPTY)
        parseClashYaml(text)?.let { return it }
        parseUriList(text)?.let { return it }
        decodeBase64(text)?.let { decoded -> parseUriList(decoded)?.let { return it } }
        throw SubscriptionException(SubscriptionException.UNRECOGNIZED)
    }

    /** 只抽取 proxies 段，丢弃机场自带的规则和策略组（分流由本软件负责） */
    fun parseClashYaml(text: String): ParsedSubscription? {
        val lines = text.lines()
        val start = lines.indexOfFirst { it.startsWith("proxies:") }
        if (start < 0) return null
        val section = mutableListOf(lines[start])
        var count = 0
        for (line in lines.drop(start + 1)) {
            val first = line.firstOrNull()
            if (first != null && !first.isWhitespace() && first != '-' && first != '#') break
            section.add(line)
            val t = line.trim()
            if (t.startsWith("- {") || t.startsWith("-{") || t.startsWith("- name:")) count++
        }
        // 行内写法 proxies: [ ... ] 极少见，交给内核解析
        if (count == 0 && '[' in lines[start]) count = lines[start].split("name:").size - 1
        if (count <= 0) return null
        return ParsedSubscription(count, section.joinToString("\n") + "\n")
    }

    fun parseUriList(text: String): ParsedSubscription? {
        val nodes = text.lines().map { it.trim() }.filter { line ->
            val lower = line.lowercase()
            schemes.any { lower.startsWith(it) } && line.length > 12
        }
        if (nodes.isEmpty()) return null
        return ParsedSubscription(nodes.size, nodes.joinToString("\n") + "\n")
    }

    fun decodeBase64(text: String): String? {
        var s = text.filterNot { it.isWhitespace() }.replace('-', '+').replace('_', '/')
        while (s.length % 4 != 0) s += "="
        val bytes = runCatching { Base64.getDecoder().decode(s) }.getOrNull() ?: return null
        val decoded = String(bytes, Charsets.UTF_8)
        return decoded.takeIf { '�' !in it }
    }

    private val serverPattern = Regex("""(?<![a-z-])server:\s*([^,}\s]+)""")
    private val hostChars = Regex("^[A-Za-z0-9.-]+$")

    /** 从 provider 内容里取出全部节点服务器地址（域名或 IP），用于熔断期间给内核留的窄例外 */
    fun serverHosts(providerContent: String): List<String> {
        val hosts = sortedSetOf<String>()
        fun add(raw: String) {
            val h = raw.trim('"', '\'', ' ', '[', ']')
            if (h.isNotEmpty() && h.length <= 253 && hostChars.matches(h)) hosts.add(h.lowercase())
        }
        for (line in providerContent.lines()) {
            val t = line.trim()
            val m = serverPattern.find(t)
            if (m != null) {
                add(m.groupValues[1])
                continue
            }
            val lower = t.lowercase()
            if (lower.startsWith("vmess://")) {
                val json = decodeBase64(t.drop(8))
                val obj = json?.let { runCatching { Json.parseToJsonElement(it).jsonObject }.getOrNull() }
                val addr = (obj?.get("add") as? JsonPrimitive)?.takeIf { it.isString }?.content
                if (addr != null) {
                    add(addr)
                    continue
                }
            }
            // scheme://user@host:port 形式
            if (schemes.none { lower.startsWith(it) }) continue
            val at = t.lastIndexOf('@').takeIf { it >= 0 }?.plus(1) ?: (t.indexOf("://") + 3)
            add(t.substring(at).takeWhile { it != ':' && it != '/' && it != '?' && it != '#' })
        }
        return hosts.toList()
    }

    /** `profile-title` 可能是 `base64:xxxx`；否则退回 Content-Disposition 里的文件名 */
    fun profileName(headers: Map<String, String>): String? {
        val lower = headers.entries.associate { it.key.lowercase() to it.value }
        lower["profile-title"]?.takeIf { it.isNotEmpty() }?.let { title ->
            if (title.startsWith("base64:")) {
                runCatching { String(Base64.getDecoder().decode(title.drop(7)), Charsets.UTF_8) }.getOrNull()?.let { return it }
            }
            return title
        }
        val cd = lower["content-disposition"] ?: return null
        cd.indexOf("filename*=UTF-8''").takeIf { it >= 0 }?.let { i ->
            val v = cd.substring(i + "filename*=UTF-8''".length).substringBefore(';')
            return runCatching { URLDecoder.decode(v, "UTF-8") }.getOrNull()
        }
        cd.indexOf("filename=").takeIf { it >= 0 }?.let { i ->
            return cd.substring(i + "filename=".length).substringBefore(';').trim('"', ' ')
        }
        return null
    }
}

/** Cloudflare `/cdn-cgi/trace` 返回 `ip=...\nloc=US\n...` */
@Serializable
data class ExitTrace(val ip: String, val country: String) {
    companion object {
        fun parseCloudflare(text: String): ExitTrace? {
            var ip: String? = null
            var loc: String? = null
            for (line in text.lines()) {
                val kv = line.split('=', limit = 2)
                if (kv.size != 2) continue
                if (kv[0] == "ip") ip = kv[1].trim()
                if (kv[0] == "loc") loc = kv[1].trim().uppercase()
            }
            if (ip == null || loc == null || loc.length != 2) return null
            return ExitTrace(ip, loc)
        }

        /** 备用出口查询（ipinfo.io `{"ip":..,"country":"US"}`，也兼容 ip-api 的 countryCode/query） */
        fun parseJson(text: String): ExitTrace? {
            val obj = runCatching { Json.parseToJsonElement(text) as? JsonObject }.getOrNull() ?: return null
            fun str(key: String) = (obj[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
            val c = str("country") ?: str("countryCode") ?: str("country_code")
            val ip = str("ip") ?: str("query")
            if (c == null || c.length != 2 || !c.all { it.isLetter() } || ip == null) return null
            return ExitTrace(ip, c.uppercase())
        }
    }
}
