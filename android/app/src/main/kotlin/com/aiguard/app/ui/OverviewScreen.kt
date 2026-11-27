package com.aiguard.app.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.GppBad
import androidx.compose.material.icons.rounded.HourglassTop
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aiguard.app.GuardViewModel
import com.aiguard.core.EventLevel
import com.aiguard.core.FirewallPolicy
import com.aiguard.core.GuardEvent
import com.aiguard.core.GuardPhase
import com.aiguard.core.GuardStatus
import com.aiguard.core.ProxyMode
import com.aiguard.core.RegionNames
import com.aiguard.core.RoutingMode

@Composable
fun OverviewScreen(vm: GuardViewModel, contentPadding: PaddingValues, onShowEvents: () -> Unit) {
    val s by vm.status.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val events by vm.events.collectAsStateWithLifecycle()
    val busy by vm.busy.collectAsStateWithLifecycle()
    val st = s ?: return
    var confirmForce by remember { mutableStateOf(false) }

    LazyColumn(
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = contentPadding.calculateTopPadding() + 8.dp, bottom = contentPadding.calculateBottomPadding() + 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { StatusHero(st) }
        if (vm.daemonOutdated) {
            item {
                SectionCard(container = status.warnContainer) {
                    Text("守护进程版本 ${st.version.ifEmpty { "未知" }}，App 版本 ${vm.appVersion}", style = MaterialTheme.typography.bodyMedium)
                    Button(onClick = vm::installDaemon, enabled = busy == null) { Text("升级守护进程") }
                }
            }
        }
        item { ExitCard(st, settings?.forbiddenRegions ?: listOf("CN", "HK", "MO")) }
        settings?.let { cfg ->
            item {
                SectionCard(title = "出站") {
                    val hasSub = st.subscription != null
                    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                        SegmentedButton(
                            selected = cfg.mode == ProxyMode.PROXY, onClick = { vm.updateSettings { it.copy(mode = ProxyMode.PROXY) } },
                            shape = SegmentedButtonDefaults.itemShape(0, 2), enabled = hasSub && busy == null,
                        ) { Text("代理") }
                        SegmentedButton(
                            selected = cfg.mode == ProxyMode.DIRECT || !hasSub, onClick = { vm.updateSettings { it.copy(mode = ProxyMode.DIRECT) } },
                            shape = SegmentedButtonDefaults.itemShape(1, 2), enabled = hasSub && busy == null,
                        ) { Text("直连阻断 AI") }
                    }
                    if (st.effectiveMode == ProxyMode.PROXY) {
                        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                            SegmentedButton(
                                selected = cfg.routing == RoutingMode.SMART, onClick = { vm.updateSettings { it.copy(routing = RoutingMode.SMART) } },
                                shape = SegmentedButtonDefaults.itemShape(0, 2), enabled = busy == null,
                            ) { Text("智能分流") }
                            SegmentedButton(
                                selected = cfg.routing == RoutingMode.GLOBAL, onClick = { vm.updateSettings { it.copy(routing = RoutingMode.GLOBAL) } },
                                shape = SegmentedButtonDefaults.itemShape(1, 2), enabled = busy == null,
                            ) { Text("全局代理") }
                        }
                        Text(
                            if (cfg.routing == RoutingMode.SMART) "AI 强制走代理，大陆网站直连省流量，其余走代理" else "除局域网外全部走代理",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        Text(
                            if (hasSub) "只放行大陆网站，全部 AI 服务拒绝" else "还没有导入订阅：只放行大陆网站，全部 AI 服务拒绝。到「设置 → 订阅」导入",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
        item {
            ActionsCard(st, busy != null, vm, onForce = { confirmForce = true })
        }
        item { ProtectionCard(st) }
        item {
            SectionCard(title = "最近事件") {
                val recent = events.takeLast(6).reversed()
                if (recent.isEmpty()) Text("暂无事件", color = MaterialTheme.colorScheme.onSurfaceVariant)
                recent.forEach { EventRow(it) }
                TextButton(onClick = onShowEvents) { Text("查看全部事件") }
            }
        }
    }

    if (confirmForce) {
        ConfirmDialog(
            title = "强制恢复网络？",
            text = "跳过线路与出口验证直接放行。如果此时出口在禁区，AI 服务会看到真实地区。只在确认线路正常时使用。",
            confirm = "强制恢复", danger = true,
            onConfirm = { vm.restore(force = true) }, onDismiss = { confirmForce = false },
        )
    }
}

private data class PhaseLook(val title: String, val icon: ImageVector, val color: Color, val container: Color)

@Composable
private fun phaseLook(st: GuardStatus): PhaseLook = when (st.phase) {
    GuardPhase.PROTECTED -> PhaseLook(
        if (st.effectiveMode == ProxyMode.PROXY) "已受保护" else "已受保护 · AI 阻断",
        Icons.Rounded.VerifiedUser, status.safe, status.safeContainer,
    )
    GuardPhase.TRIPPED -> PhaseLook(if (st.fuse.hard) "已熔断 · 全部断网" else "已熔断 · 只放行大陆", Icons.Rounded.GppBad, status.danger, status.dangerContainer)
    GuardPhase.STARTING -> PhaseLook("正在启动", Icons.Rounded.HourglassTop, status.info, MaterialTheme.colorScheme.secondaryContainer)
    GuardPhase.ERROR -> PhaseLook("防护异常", Icons.Rounded.ErrorOutline, status.warn, status.warnContainer)
    GuardPhase.DISABLED -> PhaseLook("守护已关闭", Icons.Rounded.PowerSettingsNew, status.muted, MaterialTheme.colorScheme.surfaceContainerHigh)
}

@Composable
private fun StatusHero(st: GuardStatus) {
    val look = phaseLook(st)
    val container by animateColorAsState(look.container, label = "hero")
    SectionCard(container = container) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(look.icon, contentDescription = null, tint = look.color, modifier = Modifier.size(40.dp))
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    look.title, style = MaterialTheme.typography.headlineSmall, color = look.color,
                    modifier = Modifier.semantics {
                        heading()
                        liveRegion = LiveRegionMode.Polite
                    },
                )
                val sub = when {
                    st.phase == GuardPhase.TRIPPED -> st.fuse.reason?.title
                    st.phase == GuardPhase.ERROR -> st.lastError ?: "防火墙层未生效，只剩内核闸门"
                    st.phase == GuardPhase.DISABLED -> "防火墙、TUN 与系统设置都已撤销，AI 不受保护"
                    else -> null
                }
                sub?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            }
        }
        if (st.phase == GuardPhase.TRIPPED) {
            val f = st.fuse
            if (f.recoverNeeded > 0) {
                LinearProgressIndicator(
                    progress = { f.recoverProgress.toFloat() / f.recoverNeeded },
                    modifier = Modifier.fillMaxWidth(), color = look.color,
                )
                Text(
                    "恢复验证：心跳 ${f.recoverProgress}/${f.recoverNeeded} · 出口${if (f.geoVerified) "已验证" else "待验证"}" +
                        (st.fuseHoldRemainingMs?.let { " · 至少再保持 ${(it + 999) / 1000} 秒" } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (st.fuseLatched) Text("已上锁：需要手动「重新验证」才会恢复", style = MaterialTheme.typography.bodySmall, color = look.color)
            st.fuseSince?.let { Text("熔断开始于 ${formatTime(it, "HH:mm:ss")}", style = MaterialTheme.typography.bodySmall) }
        }
        st.captiveUntil?.let {
            Text("Wi-Fi 登录模式：直连到 ${formatTime(it, "HH:mm:ss")}，AI 仍被阻断", style = MaterialTheme.typography.bodySmall, color = status.warn)
        }
    }
}

@Composable
private fun ExitCard(st: GuardStatus, forbiddenRegions: List<String>) {
    SectionCard(title = "出口") {
        val trace = st.exit.trace
        Row(verticalAlignment = Alignment.CenterVertically) {
            StatusDot(if (st.heartbeatAlive) status.safe else if (st.effectiveMode == ProxyMode.PROXY) status.danger else status.muted)
            Spacer(Modifier.width(8.dp))
            Text(
                when {
                    st.effectiveMode != ProxyMode.PROXY -> "直连模式不走代理"
                    st.heartbeatAlive -> "长连接心跳在线"
                    else -> "心跳中断"
                },
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.weight(1f))
            st.latency.lastOrNull()?.ms?.let { Text("$it ms", style = MonoStyle) }
        }
        if (trace != null) {
            InfoRow("出口 IP", trace.ip, mono = true)
            val forbidden = trace.country in forbiddenRegions
            InfoRow(
                "地区", "${RegionNames.flag(trace.country)} ${RegionNames.name(trace.country)}（${trace.country}）",
                valueColor = if (forbidden) status.danger else MaterialTheme.colorScheme.onSurface,
            )
            st.exit.checkedAt?.let { InfoRow("校验时间", relativeTime(it)) }
        } else if (st.effectiveMode == ProxyMode.PROXY) {
            Text(st.exit.error ?: "还没测到出口", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (st.effectiveMode == ProxyMode.PROXY) LatencySparkline(st.latency)
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ActionsCard(st: GuardStatus, busy: Boolean, vm: GuardViewModel, onForce: () -> Unit) {
    if (st.phase == GuardPhase.DISABLED) return
    SectionCard(title = "操作") {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (st.fuse.tripped) {
                Button(onClick = { vm.restore(force = false) }, enabled = !busy) {
                    Icon(Icons.Rounded.Shield, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("重新验证")
                }
                OutlinedButton(onClick = onForce, enabled = !busy) { Text("强制恢复") }
            } else {
                Button(
                    onClick = vm::tripFuse, enabled = !busy,
                    colors = ButtonDefaults.buttonColors(containerColor = status.danger, contentColor = status.onDanger),
                ) {
                    Icon(Icons.Rounded.Bolt, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("手动熔断")
                }
            }
            FilledTonalButton(onClick = vm::restartCore, enabled = !busy) {
                Icon(Icons.Rounded.RestartAlt, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text("重启内核")
            }
            if (st.captiveUntil == null) {
                FilledTonalButton(onClick = { vm.captiveLogin(5) }, enabled = !busy) {
                    Icon(Icons.Rounded.Wifi, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("酒店 Wi-Fi 登录")
                }
            } else {
                FilledTonalButton(onClick = vm::endCaptiveLogin, enabled = !busy) { Text("结束 Wi-Fi 登录") }
            }
        }
    }
}

@Composable
private fun ProtectionCard(st: GuardStatus) {
    SectionCard(title = "防护层") {
        val fw = when (st.firewallPolicy) {
            FirewallPolicy.Lockdown.name -> "全部断网（仅局域网与内核）"
            "whitelist" -> "大陆白名单"
            "leakGuard" -> "防泄漏：只允许经 TUN 出站"
            "basic" -> "基础：只封 IPv6 与明文 DNS"
            else -> "未加载"
        }
        InfoRow("防火墙", fw, valueColor = if (st.firewallPolicy == "none") status.warn else MaterialTheme.colorScheme.onSurface)
        InfoRow("TUN", if (st.tunUp) "${st.tunInterface} · 路由正常" else "未接管", valueColor = if (st.tunUp) status.safe else status.warn)
        InfoRow(
            "IPv6",
            when (st.ipv6Blocked) {
                true -> "已封锁" + if (st.ipv6DisabledInterfaces > 0) "（${st.ipv6DisabledInterfaces} 个网卡已关闭）" else ""
                false -> "能直连公网！"
                null -> "检测中"
            },
            valueColor = if (st.ipv6Blocked == false) status.danger else MaterialTheme.colorScheme.onSurface,
        )
        InfoRow("私人 DNS", if (st.privateDnsLocked) "已关闭，DNS 交给内核" else "未锁定")
        InfoRow("内核", "${st.coreVersion ?: "未知"}${if (st.coreRunning) "" else "（未运行）"} · 重启 ${st.coreRestarts} 次")
        st.primaryInterface?.let { InfoRow("当前网络", it, mono = true) }
        st.nodeCount?.let { InfoRow("可用节点", "$it 个（已排除出口禁区）") }
        if (st.conflicts.isNotEmpty()) {
            InfoRow("冲突软件", st.conflicts.joinToString("、"), valueColor = status.warn)
        }
    }
}

@Composable
fun EventRow(e: GuardEvent) {
    val color = when (e.level) {
        EventLevel.CRITICAL -> status.danger
        EventLevel.WARNING -> status.warn
        EventLevel.INFO -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.Top) {
        StatusDot(color, Modifier.padding(top = 6.dp))
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(e.message, style = MaterialTheme.typography.bodyMedium)
            Text(formatTime(e.at), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
fun EventsScreen(vm: GuardViewModel, contentPadding: PaddingValues) {
    val events by vm.events.collectAsStateWithLifecycle()
    var confirm by remember { mutableStateOf(false) }
    LazyColumn(
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = contentPadding.calculateTopPadding() + 8.dp, bottom = contentPadding.calculateBottomPadding() + 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("共 ${events.size} 条", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                TextButton(onClick = { confirm = true }, enabled = events.isNotEmpty()) { Text("清空") }
            }
        }
        if (events.isEmpty()) item { EmptyHint("暂无事件") }
        items(events.reversed(), key = { it.id }) { EventRow(it) }
    }
    if (confirm) {
        ConfirmDialog("清空事件记录？", "清空后无法恢复。", "清空", onConfirm = vm::clearEvents, onDismiss = { confirm = false }, danger = true)
    }
}
