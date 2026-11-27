package com.aiguard.app.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.CompareArrows
import androidx.compose.material.icons.rounded.Checklist
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aiguard.app.DaemonState
import com.aiguard.app.GuardViewModel

private enum class Tab(val label: String, val icon: ImageVector) {
    OVERVIEW("概览", Icons.Rounded.Shield),
    NODES("节点", Icons.Rounded.Public),
    CONNECTIONS("连接", Icons.AutoMirrored.Rounded.CompareArrows),
    RULES("名单", Icons.Rounded.Checklist),
    SETTINGS("设置", Icons.Rounded.Tune),
}

@Composable
fun AppRoot(vm: GuardViewModel) {
    val daemon by vm.daemon.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(Unit) { vm.messages.collect { snackbar.showSnackbar(it) } }
    if (daemon == DaemonState.Connected && vm.status.collectAsStateWithLifecycle().value != null) {
        MainScaffold(vm, snackbar)
    } else {
        SetupScreen(vm, daemon, snackbar)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScaffold(vm: GuardViewModel, snackbar: SnackbarHostState) {
    var tab by rememberSaveable { mutableStateOf(Tab.OVERVIEW) }
    var showEvents by rememberSaveable { mutableStateOf(false) }
    val busy by vm.busy.collectAsStateWithLifecycle()
    BackHandler(enabled = showEvents) { showEvents = false }
    BackHandler(enabled = !showEvents && tab != Tab.OVERVIEW) { tab = Tab.OVERVIEW }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = { Text(if (showEvents) "事件记录" else if (tab == Tab.OVERVIEW) "AI 出差管家" else tab.label) },
                    navigationIcon = {
                        if (showEvents) IconButton(onClick = { showEvents = false }) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = "返回") }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
                )
                if (busy != null) LinearProgressIndicator(Modifier.fillMaxWidth())
            }
        },
        bottomBar = {
            if (!showEvents) {
                NavigationBar(containerColor = MaterialTheme.colorScheme.surfaceContainerLow) {
                    Tab.entries.forEach { t ->
                        NavigationBarItem(
                            selected = tab == t, onClick = { tab = t },
                            icon = { Icon(t.icon, contentDescription = null) }, label = { Text(t.label) },
                        )
                    }
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { inner ->
        if (showEvents) {
            EventsScreen(vm, inner)
        } else {
            when (tab) {
                Tab.OVERVIEW -> OverviewScreen(vm, inner, onShowEvents = { showEvents = true })
                Tab.NODES -> NodesScreen(vm, inner)
                Tab.CONNECTIONS -> ConnectionsScreen(vm, inner)
                Tab.RULES -> RulesScreen(vm, inner)
                Tab.SETTINGS -> SettingsScreen(vm, inner, onShowEvents = { showEvents = true })
            }
        }
    }
}

@Composable
private fun SetupScreen(vm: GuardViewModel, daemon: DaemonState, snackbar: SnackbarHostState) {
    val busy by vm.busy.collectAsStateWithLifecycle()
    val log by vm.installLog.collectAsStateWithLifecycle()
    Scaffold(snackbarHost = { SnackbarHost(snackbar) }, containerColor = MaterialTheme.colorScheme.background) { inner ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(inner)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Rounded.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(44.dp))
                Spacer(Modifier.width(12.dp))
                Column {
                    Text("AI 出差管家", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
                    Text("绝不让 AI 服务看到大陆或港澳 IP", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            when (daemon) {
                DaemonState.Checking -> Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(12.dp))
                    Text("正在连接守护进程…")
                }
                DaemonState.AuthFailed -> SectionCard(container = status.warnContainer) {
                    Text("守护进程在运行，但认证失败（App 数据可能被清除过）。重新安装守护进程即可，设置和订阅会保留。")
                }
                is DaemonState.Unreachable -> SectionCard(container = status.warnContainer) {
                    Text("连不上守护进程：${daemon.reason}")
                    Text("刚开机可能还在启动；如果一直连不上，重新安装会拉起看门狗。", style = MaterialTheme.typography.bodySmall)
                }
                else -> Unit
            }
            SectionCard(title = "工作方式") {
                Bullet("守护进程以 root 常驻（KernelSU 开机脚本拉起，看门狗自动重启），关掉这个界面、被系统清后台都不影响防护。")
                Bullet("内置 mihomo 内核，TUN 接管全部流量；iptables 拒绝任何绕过 TUN 的直连、IPv6 和明文 DNS。")
                Bullet("长连接心跳每 2 秒校验出口国家，异常立即熔断：只放行大陆网站，并强行停止 AI App 与浏览器。")
                Bullet("运行前请关闭其他 VPN 与代理模块，两个 TUN 会抢路由。")
            }
            SectionCard(title = "安装") {
                Text("1. 在 KernelSU 管理器 →「超级用户」里允许「AI 出差管家」", style = MaterialTheme.typography.bodyMedium)
                Text("2. 点下面的按钮安装守护进程（会写入 /data/adb/aiguard 与 /data/adb/service.d/aiguard.sh）", style = MaterialTheme.typography.bodyMedium)
                Button(onClick = vm::installDaemon, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
                    if (busy != null) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                        Spacer(Modifier.width(8.dp))
                        Text(busy ?: "")
                    } else {
                        Text(if (daemon == DaemonState.NotInstalled) "安装守护进程" else "重新安装守护进程")
                    }
                }
            }
            log?.let {
                SectionCard(container = status.dangerContainer) {
                    Text(it, style = MonoStyle)
                    TextButton(onClick = vm::dismissInstallLog) { Text("知道了") }
                }
            }
        }
    }
}

@Composable
private fun Bullet(text: String) {
    Row {
        Text("•", color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(end = 8.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}
