package com.aiguard.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aiguard.app.GuardViewModel
import com.aiguard.core.GroupName
import com.aiguard.core.MihomoApi
import com.aiguard.core.MihomoConfigBuilder
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
private fun delayColor(ms: Int?, tested: Boolean): Color = when {
    !tested -> MaterialTheme.colorScheme.onSurfaceVariant
    ms == null -> status.danger
    ms < 300 -> status.safe
    ms < 800 -> status.warn
    else -> status.danger
}

@Composable
fun NodesScreen(vm: GuardViewModel, contentPadding: PaddingValues) {
    val st by vm.status.collectAsStateWithLifecycle()
    var proxies by remember { mutableStateOf<Map<String, MihomoApi.ProxyItem>>(emptyMap()) }
    var testing by remember { mutableStateOf(false) }
    var tick by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(tick) {
        while (true) {
            // 任一接口失败时返回空，保留上一份完整快照
            vm.proxies().takeIf { it.isNotEmpty() }?.let { proxies = it }
            delay(3000)
        }
    }

    val group = proxies[GroupName.PROXY]
    val auto = proxies[GroupName.AUTO]
    LazyColumn(
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = contentPadding.calculateTopPadding() + 8.dp, bottom = contentPadding.calculateBottomPadding() + 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (st?.subscription == null) {
            item { EmptyHint("还没有导入订阅。到「设置 → 订阅」粘贴订阅链接") }
            return@LazyColumn
        }
        item {
            SectionCard {
                Text("单线路：AI 与其余代理流量共用「${GroupName.PROXY}」", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "出口禁区（${vm.settings.value?.forbiddenRegions?.joinToString("、") ?: "CN、HK、MO"}）的节点按名字自动排除。默认「${GroupName.AUTO}」只在节点失效时换线，出口 IP 最稳定；它每 ${MihomoConfigBuilder.AUTO_CHECK_INTERVAL_SECONDS / 60} 分钟体检一次节点（省流量），心跳失败时立即体检换线。",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("当前：${group?.now ?: "-"}${if (group?.now == GroupName.AUTO) " → ${auto?.now ?: "-"}" else ""}", modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    FilledTonalButton(
                        onClick = {
                            testing = true
                            scope.launch {
                                vm.testGroup(GroupName.PROXY)
                                testing = false
                                tick++
                            }
                        },
                        enabled = !testing,
                    ) {
                        if (testing) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp) else Icon(Icons.Rounded.Speed, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("全部测速")
                    }
                }
            }
        }
        if (group == null) {
            item { EmptyHint("正在读取节点…") }
        } else {
            items(group.all, key = { it }) { name ->
                val p = proxies[name]
                NodeRow(
                    name = name,
                    type = p?.type.orEmpty(),
                    delay = p?.lastDelay,
                    tested = p?.tested == true,
                    selected = group.now == name,
                    detail = if (name == GroupName.AUTO) auto?.now?.let { "当前 $it" } else null,
                    onClick = {
                        scope.launch {
                            if (vm.selectNode(name)) tick++
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun NodeRow(name: String, type: String, delay: Int?, tested: Boolean, selected: Boolean, detail: String?, onClick: () -> Unit) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainer,
        ),
        modifier = Modifier
            .fillMaxWidth()
            .semantics { this.selected = selected }
            .clickable(role = Role.RadioButton, onClick = onClick),
    ) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(listOfNotNull(type.takeIf { it.isNotEmpty() }, detail).joinToString(" · "), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(
                when {
                    !tested -> "未测速"
                    delay == null -> "超时"
                    else -> "$delay ms"
                },
                style = MonoStyle, color = delayColor(delay, tested),
            )
            if (selected) {
                Spacer(Modifier.width(8.dp))
                Icon(Icons.Rounded.CheckCircle, contentDescription = "当前使用", tint = MaterialTheme.colorScheme.primary)
            }
        }
    }
}

@Composable
fun ConnectionsScreen(vm: GuardViewModel, contentPadding: PaddingValues) {
    var snap by remember { mutableStateOf<MihomoApi.ConnectionsSnapshot?>(null) }
    var query by rememberSaveable { mutableStateOf("") }
    var confirmAll by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        while (true) {
            vm.connections()?.let { snap = it }
            delay(2000)
        }
    }

    val list = snap?.connections.orEmpty()
        .filter { query.isBlank() || it.host.contains(query, true) || it.destination.contains(query) || it.chain.contains(query, true) || it.rule.contains(query, true) }
        .sortedByDescending { it.start ?: 0 }
    val now = System.currentTimeMillis()

    LazyColumn(
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = contentPadding.calculateTopPadding() + 8.dp, bottom = contentPadding.calculateBottomPadding() + 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            OutlinedTextField(
                value = query, onValueChange = { query = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
                placeholder = { Text("搜索域名、IP、线路或规则") },
            )
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "${list.size} 条连接 · ↑ ${formatBytes(snap?.uploadTotal ?: 0)} ↓ ${formatBytes(snap?.downloadTotal ?: 0)}",
                    style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f),
                )
                OutlinedButton(onClick = { confirmAll = true }, enabled = list.isNotEmpty()) { Text("全部断开") }
            }
        }
        if (snap == null) item { EmptyHint("内核未运行或正在连接…") }
        else if (list.isEmpty()) item { EmptyHint("没有连接") }
        items(list, key = { it.id }) { c ->
            val routeColor = when (c.route) {
                MihomoApi.Connection.Route.PROXY -> status.safe
                MihomoApi.Connection.Route.DIRECT -> status.info
                MihomoApi.Connection.Route.REJECT -> status.danger
            }
            Card(shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
                Row(Modifier.padding(start = 16.dp, top = 10.dp, bottom = 10.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    StatusDot(routeColor)
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(c.host.ifEmpty { c.destination }, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            "${c.network} · ${c.chain.ifEmpty { c.leaf }}",
                            style = MaterialTheme.typography.bodySmall, color = routeColor, maxLines = 1, overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            listOfNotNull(c.rule.takeIf { it.isNotEmpty() }, "↑${formatBytes(c.upload)} ↓${formatBytes(c.download)}", c.start?.let { formatDuration(now - it) })
                                .joinToString(" · "),
                            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 2, overflow = TextOverflow.Ellipsis,
                        )
                    }
                    IconButton(onClick = {
                        scope.launch {
                            vm.closeConnection(c.id)
                            vm.connections()?.let { snap = it }
                        }
                    }) { Icon(Icons.Rounded.Close, contentDescription = "断开 ${c.host.ifEmpty { c.destination }}") }
                }
            }
        }
    }
    if (confirmAll) {
        ConfirmDialog("断开全部连接？", "正在进行的下载和会话会中断，App 会自动重连。", "全部断开", onConfirm = vm::flushConnections, onDismiss = { confirmAll = false })
    }
}
