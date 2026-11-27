package com.aiguard.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aiguard.app.GuardViewModel
import com.aiguard.core.AIRuleCatalog
import com.aiguard.core.FuseAction
import com.aiguard.core.RegionNames

private fun padding(contentPadding: PaddingValues) = PaddingValues(
    start = 16.dp, end = 16.dp,
    top = contentPadding.calculateTopPadding() + 8.dp,
    bottom = contentPadding.calculateBottomPadding() + 16.dp,
)

@Composable
fun RulesScreen(vm: GuardViewModel, contentPadding: PaddingValues) {
    val cfg by vm.settings.collectAsStateWithLifecycle()
    val s = cfg ?: return
    LazyColumn(contentPadding = padding(contentPadding), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            SectionCard {
                Text("AI 名单「宁可错杀」", style = MaterialTheme.typography.titleMedium)
                Text(
                    "命中的流量永远只走代理，熔断或直连模式下直接拒绝，任何模式都不会直连。标「严格」的类别会顺带覆盖账号、风控相关的大域名。",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        item {
            SectionCard(title = "类别") {
                AIRuleCatalog.all.forEachIndexed { i, c ->
                    if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    SwitchRow(
                        title = c.name + if (c.strict) " · 严格" else "",
                        subtitle = "${c.note}（${c.ruleCount} 条）",
                        checked = c.id !in s.disabledAICategories,
                        onChange = { on ->
                            vm.updateSettings { cur ->
                                cur.copy(disabledAICategories = if (on) cur.disabledAICategories - c.id else (cur.disabledAICategories + c.id).distinct())
                            }
                        },
                    )
                }
            }
        }
        item {
            SectionCard(title = "自定义") {
                ListEditor("追加 AI 域名（按后缀匹配）", s.customAIDomains, "例如 example-ai.com") { list -> vm.updateSettings { it.copy(customAIDomains = list) } }
                ListEditor("强制代理（纠正大陆名单误收的境外站）", s.customProxyDomains, "例如 leak-test.example") { list -> vm.updateSettings { it.copy(customProxyDomains = list) } }
                ListEditor("强制直连（优先级最高，AI 名单除外）", s.customDirectDomains, "例如 intranet.example.com") { list -> vm.updateSettings { it.copy(customDirectDomains = list) } }
                ListEditor("熔断时额外关闭的 App（包名）", s.extraAIPackages, "例如 com.example.aichat") { list -> vm.updateSettings { it.copy(extraAIPackages = list) } }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(vm: GuardViewModel, contentPadding: PaddingValues, onShowEvents: () -> Unit) {
    val cfg by vm.settings.collectAsStateWithLifecycle()
    val st by vm.status.collectAsStateWithLifecycle()
    val busy by vm.busy.collectAsStateWithLifecycle()
    val s = cfg ?: return
    var confirmDisable by remember { mutableStateOf(false) }
    var confirmRemoveSub by remember { mutableStateOf(false) }
    var confirmUninstall by remember { mutableStateOf(false) }

    LazyColumn(contentPadding = padding(contentPadding), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            SectionCard(title = "守护") {
                SwitchRow(
                    "启用守护", s.enabled,
                    onChange = { on -> if (on) vm.updateSettings { it.copy(enabled = true) } else confirmDisable = true },
                    subtitle = "关闭后撤销防火墙、TUN、IPv6 与私人 DNS 锁定，AI 不再受保护",
                    enabled = busy == null,
                )
            }
        }
        item { SubscriptionCard(vm, busy != null, onRemove = { confirmRemoveSub = true }) }
        item {
            SectionCard(title = "熔断") {
                SwitchRow("启用熔断", s.fuseEnabled, { on -> vm.updateSettings { it.copy(fuseEnabled = on) } }, "关闭后线路异常也不拦截，强烈不建议")
                Text("熔断方式", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    SegmentedButton(
                        selected = s.fuseAction == FuseAction.WHITELIST, onClick = { vm.updateSettings { it.copy(fuseAction = FuseAction.WHITELIST) } },
                        shape = SegmentedButtonDefaults.itemShape(0, 2),
                    ) { Text("只放行大陆") }
                    SegmentedButton(
                        selected = s.fuseAction == FuseAction.CUT_ALL, onClick = { vm.updateSettings { it.copy(fuseAction = FuseAction.CUT_ALL) } },
                        shape = SegmentedButtonDefaults.itemShape(1, 2),
                    ) { Text("全部断网") }
                }
                SwitchRow("线路恢复后自动解除", s.autoRecover, { on -> vm.updateSettings { it.copy(autoRecover = on) } }, "关闭后心跳失败、出口违规的熔断要手动解除")
                SwitchRow("出口违规时自动换节点", s.autoSwitchUnsafeNode, { on -> vm.updateSettings { it.copy(autoSwitchUnsafeNode = on) } })
                SwitchRow("熔断时关闭 AI App 与浏览器", s.closeAppsOnFuse, { on -> vm.updateSettings { it.copy(closeAppsOnFuse = on) } }, "强行停止 Claude、ChatGPT、Gemini、浏览器，以及 Termux 里的 AI 命令行")
                SwitchRow(
                    "启动、换网时也关闭", s.closeAppsOnGuardTrips, { on -> vm.updateSettings { it.copy(closeAppsOnGuardTrips = on) } },
                    "这类保护性熔断期间防火墙已只放行大陆，默认不关", enabled = s.closeAppsOnFuse,
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                StepperRow("心跳间隔", s.probeIntervalSeconds, 1..10, unit = " 秒", subtitle = "同时校验出口国家；每次约 1 KB，全天约 ${86400 / s.probeIntervalSeconds / 1024} MB 代理流量（估算）") { v -> vm.updateSettings { it.copy(probeIntervalSeconds = v) } }
                StepperRow("连续失败熔断", s.failureThreshold, 1..20, unit = " 次") { v -> vm.updateSettings { it.copy(failureThreshold = v) } }
                StepperRow("延迟上限", s.latencyThresholdMs, 300..10_000, step = 250, unit = "ms") { v -> vm.updateSettings { it.copy(latencyThresholdMs = v) } }
                StepperRow("恢复需要成功", s.recoverSuccesses, 1..30, unit = " 次") { v -> vm.updateSettings { it.copy(recoverSuccesses = v) } }
                StepperRow("换网后保持", s.networkHoldSeconds, 0..60, unit = " 秒") { v -> vm.updateSettings { it.copy(networkHoldSeconds = v) } }
            }
        }
        item {
            SectionCard(title = "出口禁区") {
                Text("出口落在这些地区立即熔断，这些地区的节点也不会被自动选中。中国大陆不可移除。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    s.forbiddenRegions.forEach { code ->
                        AssistChip(
                            onClick = { if (code != "CN") vm.updateSettings { it.copy(forbiddenRegions = it.forbiddenRegions - code) } },
                            enabled = code != "CN",
                            label = { Text("${RegionNames.flag(code)} ${RegionNames.name(code)}${if (code != "CN") "  ✕" else ""}") },
                        )
                    }
                }
                RegionAdder { code -> vm.updateSettings { it.copy(forbiddenRegions = (it.forbiddenRegions + code).distinct()) } }
            }
        }
        item {
            SectionCard(title = "防泄漏") {
                SwitchRow("禁止绕过 TUN", s.leakGuard, { on -> vm.updateSettings { it.copy(leakGuard = on) } }, "普通 App 只能经 TUN 出站；IPv6 与明文 DNS 封锁始终生效")
                SwitchRow("直连模式只放行大陆", s.directOnlyMainland, { on -> vm.updateSettings { it.copy(directOnlyMainland = on) } }, "名单之外的 AI 服务也无法直连")
                SwitchRow("关闭 Wi-Fi 的 IPv6", s.disableSystemIPv6, { on -> vm.updateSettings { it.copy(disableSystemIPv6 = on) } }, "蜂窝网卡保留 IPv6（464XLAT 需要），只靠防火墙封锁")
                SwitchRow("关闭系统「私人 DNS」", s.lockPrivateDns, { on -> vm.updateSettings { it.copy(lockPrivateDns = on) } }, "DoT 会绕过内核的 DNS 劫持；关闭守护时恢复原设置")
            }
        }
        item {
            SectionCard(title = "记录") {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("熔断、换网、节点切换等事件", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                    FilledTonalButton(onClick = onShowEvents) { Text("查看事件") }
                }
            }
        }
        item {
            SectionCard(title = "守护进程") {
                InfoRow("App 版本", vm.appVersion)
                InfoRow("守护进程", st?.version?.ifEmpty { null } ?: "未知")
                InfoRow("mihomo", st?.coreVersion ?: "未知")
                InfoRow("运行位置", "/data/adb/aiguard（root）", mono = true)
                Text(
                    "守护进程以 root 常驻，由 KernelSU 开机脚本拉起并有看门狗重启；关掉这个界面不影响守护。",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilledTonalButton(onClick = vm::installDaemon, enabled = busy == null) { Text(if (vm.daemonOutdated) "升级守护进程" else "重新安装") }
                    OutlinedButton(onClick = { confirmUninstall = true }, enabled = busy == null) { Text("卸载", color = status.danger) }
                }
            }
        }
    }

    if (confirmDisable) {
        ConfirmDialog(
            "关闭守护？", "防火墙、TUN、IPv6 与私人 DNS 锁定会全部撤销，AI 服务将直接看到当前网络的真实 IP。",
            "关闭守护", danger = true,
            onConfirm = { vm.updateSettings { it.copy(enabled = false) } }, onDismiss = { confirmDisable = false },
        )
    }
    if (confirmRemoveSub) {
        ConfirmDialog(
            "移除订阅？", "移除后进入「直连阻断 AI」：只放行大陆网站，全部 AI 服务拒绝。",
            "移除", danger = true, onConfirm = vm::removeSubscription, onDismiss = { confirmRemoveSub = false },
        )
    }
    if (confirmUninstall) UninstallDialog(onDismiss = { confirmUninstall = false }, onConfirm = vm::uninstallDaemon)
}

@Composable
private fun SubscriptionCard(vm: GuardViewModel, busy: Boolean, onRemove: () -> Unit) {
    val st by vm.status.collectAsStateWithLifecycle()
    var url by rememberSaveable { mutableStateOf("") }
    SectionCard(title = "订阅") {
        val sub = st?.subscription
        if (sub != null) {
            Text(sub.name ?: "订阅", style = MaterialTheme.typography.bodyLarge)
            InfoRow("链接", sub.maskedUrl, mono = true)
            InfoRow("节点", "${sub.nodeCount} 个")
            sub.lastUpdated?.let { InfoRow("更新", relativeTime(it)) }
            sub.usage?.let { u ->
                if (u.total > 0) {
                    LinearProgressIndicator(progress = { (u.used.toDouble() / u.total).coerceIn(0.0, 1.0).toFloat() }, modifier = Modifier.fillMaxWidth())
                }
                InfoRow("流量", "${formatBytes(u.used)} / ${if (u.total > 0) formatBytes(u.total) else "不限"}")
                u.expire?.let { InfoRow("到期", formatTime(it * 1000, "yyyy-MM-dd")) }
            }
            sub.lastError?.let { InfoRow("上次失败", it, valueColor = status.warn) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(onClick = vm::refreshSubscription, enabled = !busy) { Text("立即更新") }
                OutlinedButton(onClick = onRemove, enabled = !busy) { Text("移除") }
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
        OutlinedTextField(
            value = url, onValueChange = { url = it }, modifier = Modifier.fillMaxWidth(),
            label = { Text(if (sub == null) "订阅链接" else "替换为新的订阅链接") },
            placeholder = { Text("https://…") }, singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
        )
        Text("支持 Clash YAML 与节点链接列表；只取节点，分流规则由本软件负责。订阅链接本身是凭据，界面只显示脱敏后的地址。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Button(onClick = {
            vm.importSubscription(url)
            url = ""
        }, enabled = !busy && url.isNotBlank()) { Text("导入") }
    }
}

@Composable
private fun RegionAdder(onAdd: (String) -> Unit) {
    var code by rememberSaveable { mutableStateOf("") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(
            value = code, onValueChange = { v -> code = v.filter { it.isLetter() }.take(2).uppercase() },
            modifier = Modifier.weight(1f), singleLine = true, label = { Text("国家代码") }, placeholder = { Text("例如 US") },
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, autoCorrectEnabled = false),
        )
        Spacer(Modifier.width(8.dp))
        FilledTonalButton(onClick = {
            onAdd(code)
            code = ""
        }, enabled = code.length == 2) { Text("加入禁区") }
    }
}

@Composable
private fun UninstallDialog(onDismiss: () -> Unit, onConfirm: (Boolean) -> Unit) {
    var purge by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("卸载守护进程？") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("会停止守护与内核，撤销防火墙，恢复 IPv6 与私人 DNS，并删除开机脚本。之后 AI 服务不再受保护。")
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = purge, onCheckedChange = { purge = it })
                    Text("同时删除设置、订阅和日志")
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onDismiss()
                onConfirm(purge)
            }) { Text("卸载", color = status.danger) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}
