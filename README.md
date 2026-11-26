# 🛡️ AI 出差管家（AIGuard）

macOS 专用的代理 + AI 防泄漏守护。目标只有一个：**出差时绝不让 Claude / ChatGPT / Gemini 等 AI 服务看到中国大陆或港澳 IP**。

- 内置 mihomo（Clash Meta）内核，导入订阅即可用，TUN 全局接管
- **单线路**：AI 与其余代理流量走同一个「节点选择」，自动排除出口禁区（默认中国大陆/香港/澳门）节点
- 智能分流：AI 强制走代理、大陆域名/IP 直连省流量、其余走代理；也可切全局
- **长连接心跳**：经代理保持一条 TLS 长连接，每 2 秒心跳一次并同时校验出口国家，连续 2 次失败即熔断
- 熔断：心跳中断、节点连不上、合盖/唤醒、换网络、出口落在禁区、内核或 TUN 异常、IPv6 泄漏 → 只放行大陆白名单（域名 + IP 双重把关），关闭 AI 进程与浏览器
- DNS 与 IPv6 防泄漏：系统 DNS 锁到 TUN，明文 DNS 不准绕过；系统 IPv6 关闭
- 无代理阻断：没有订阅或切到「直连阻断 AI」时，只放行大陆网站，全部 AI 服务拒绝
- 连接列表：实时查看/断开每条连接、走了哪条线路、命中哪条规则
- 原生 SwiftUI + Liquid Glass 界面，常驻菜单栏

系统要求：macOS 26 及以上、Apple Silicon。

## 🚀 安装

```bash
./scripts/make-dmg.sh
```

打开 `build/AIGuard-<版本>.dmg`，把 App 拖进「应用程序」后打开，点「安装并启动」（升级时显示「升级到 x.y.z」），在系统授权窗口输入密码。然后在「订阅」页粘贴订阅链接导入。**运行前请退出 V2rayU / Clash Verge 等其他代理软件**，两个 TUN 会抢路由（App 会检测并提示）。

也可以在终端手动安装：

```bash
sudo /Applications/AIGuard.app/Contents/Resources/install.sh --uid $(id -u)
```

## 🧭 三种出站模式

| 模式 | AI 流量 | 大陆流量 | 其余流量 |
|---|---|---|---|
| 智能分流（默认） | 节点选择 | 直连 | 节点选择 |
| 全局代理 | 节点选择 | 节点选择 | 节点选择 |
| 直连阻断 AI | **拒绝** | 直连 | **拒绝**（可在设置里改为直连） |

- 出口禁区默认 CN/HK/MO（中国大陆不可移除），禁区地区的节点按名字自动排除。默认用「自动选择」（fallback：只在节点失效时换线，出口 IP 最稳定）。
- 任何模式下 AI 规则都不会指向 DIRECT。
- 酒店 Wi-Fi 需要网页认证时，点「酒店 Wi-Fi 登录」：5 分钟内全部直连并使用酒店 DHCP 下发的 DNS，AI 仍被拒绝。

## ⚡ 熔断规则

| 触发 | 处置 | 解除 |
|---|---|---|
| 启动 / 切换模式 | 大陆白名单 | 连续 4 次心跳成功 + 出口验证 |
| 合盖睡眠前 | 立即全部断网（不经过任何队列），随后转为大陆白名单 | 唤醒后保持至少 8 秒，再走验证 |
| 网络切换（换 Wi-Fi、IP 变化） | 同上（无防抖） | 同上 |
| 内核退出 / 无响应、TUN 路由丢失（每秒检查） | 大陆白名单；TUN 持续丢失 8 秒自动重启内核 | 内核与 TUN 恢复 + 验证 |
| 长连接心跳连续 2 次失败、超时或节点连不上 | 大陆白名单 | 自动（可改为手动） |
| 出口落在禁区（每次心跳都校验） | 大陆白名单；可自动寻找出口安全的节点 | 新的出口检测通过 |
| 能直连公网 IPv6（封锁失效） | 大陆白名单 | IPv6 检测恢复安全 |
| 手动熔断 | 大陆白名单 | 手动解除 |

「熔断方式」可在设置里改成「切断全部网络」，此时上表所有「大陆白名单」都变为全部断网（只留回环、局域网、DHCP 和 root 内核）。

熔断时：

- **大陆白名单**（默认，可改为全部断网）：内核按域名只放行大陆网站（`geosite:cn`/`geoip:cn`），pf 防火墙按 IP 只放行 6000 多个大陆 IPv4 段。内核或 TUN 出故障时防火墙这一层仍然有效。唯一的窄例外：root 内核可以连「订阅里的节点服务器」和「订阅服务器」，用于恢复和更新订阅（例外地址由内核 DNS 每 10 分钟解析一次）。
- **关闭 AI 进程与浏览器**：熔断瞬间关一次浏览器；熔断期间每 3 秒持续清理 AI 进程。按关键词（claude、anthropic、openai、chatgpt、codex、cursor、copilot、gemini、ollama……）做完整词匹配，检查 App 路径和进程名；node/python 等解释器再看它实际运行的脚本（能抓到 Claude Code、Codex CLI、编辑器里的 Copilot），普通程序的文件参数不算（`vim ~/.claude/x` 不会被关）。只读参数不读环境变量；系统目录下的进程和 AIGuard 自身一律不碰。
- **节点连不上**：内核判定当前节点不可用时立即按心跳失败处理，不等超时。
- **其他代理软件破坏路由**：内核正常但 TUN 路由连续 8 秒丢失（常见于开着 V2rayU 等软件、或退出时路由被一起删掉），自动重启内核重建；按 1、2、4…分钟退避，同一次故障最多自动重启 5 次，之后提示手动处理。也可以随时点「重启内核」；「重新验证」12 秒内没通过会询问是否重启内核。重启前先清理 AI 进程，重启后保留手动熔断锁和睡眠保护，重新验证通过才放行。
- 熔断期间订阅仍可更新：内核自己的 DNS 和直连入站不经过闸门。
- 长连接每次心跳前核对实际出口节点，「自动选择」换线后立即重建长连接，旧节点的结果作废。
- 内核控制接口偶发一次超时不算故障（进程退出则立即熔断）；白名单熔断在闸门确认写成 REJECT 之前，连进入 TUN 的流量都不放行。

## 🔒 防泄漏

- **DNS**：守护开启时把每个网络服务的系统 DNS 锁到 TUN（`198.18.0.2`），查询全部进内核：大陆域名走国内 DoH，境外域名经代理走 DoH，AI 域名用 fake-ip 不在本地解析。pf 拒绝任何非 root 进程绕过 TUN 发出的 53/853 端口查询（含发往路由器/酒店 DNS 的）。原设置备份，关闭守护或卸载时恢复。
- **IPv6**：守护开启时对每个网络服务执行 `networksetup -setv6off`；内核关闭 IPv6；pf 拒绝全部 IPv6 出站；每 30 秒主动尝试直连公网 IPv6，连得上就熔断。
- **绕过 TUN**：普通用户进程绕过 TUN 直连外网一律丢弃；守护进程崩溃时这层规则不会被撤销。
- 任何熔断下境外流量都不会改走直连，名单外的 AI 服务也到不了。

## 🗂️ AI 名单

14 类、440+ 条规则 + 官方规则集 `geosite:anthropic`、`geosite:category-ntp`，来源：v2fly `category-ai-!cn`、blackmatrix7 规则库、你提供的 Claude 清单。包含 Claude/Anthropic、OpenAI、Gemini、Copilot、Grok、Perplexity、AI 编程工具、模型平台、AI 创作，以及「宁可错杀」的严格类：整个 Google 账号体系、X/Twitter、第三方风控/鉴权/支付/遥测（Sentry、Datadog、Statsig、Sift、Arkose、Stripe、Auth0、Intercom 等）、时间同步（NTP 域名与全部 UDP 123）。Claude 类额外包含 `keyword:sentry/datadog/sift`，关掉第三方类也不受影响。每类都能在「AI 名单」页单独关闭，也可以加自定义域名。

## 🧱 结构

```
Sources/AIGuardCore   纯逻辑：设置、AI 名单、mihomo 配置生成、pf 规则生成、熔断状态机、订阅解析、IPC
Sources/aiguardd      root 守护进程：内核管理、防火墙、长连接心跳、DNS/IPv6 锁定、关闭应用、睡眠/网络监听、Unix socket 控制通道
Sources/AIGuard       SwiftUI 界面 + 菜单栏
scripts/              fetch-core（下载并校验内核/规则）、build-app、install、uninstall
```

运行时文件：

- `/Library/PrivilegedHelperTools/com.aiguard.daemon/`：守护进程、内核、规则库
- `/Library/Application Support/AIGuard/`：设置、订阅（root 0600）、内核工作目录
- `/Library/Logs/AIGuard/`：`daemon.log`、`mihomo.log`

## 🧪 开发

```bash
swift test
```

```bash
AIGUARD_INTEGRATION=1 swift test
```

集成测试会起一个非 root 的真实 mihomo，验证节点过滤、闸门、探测入站认证和出口检测（需要联网）。

不装 root 组件也能跑完整联动（不碰 pf、不开 TUN）：

```bash
.build/debug/aiguardd --dev --helper-dir build/AIGuard.app/Contents/Resources
```

```bash
open -n --env AIGUARD_SOCKET="$HOME/Library/Application Support/AIGuard-dev/dev.sock" build/AIGuard.app
```

## 🧹 卸载

```bash
sudo /Applications/AIGuard.app/Contents/Resources/uninstall.sh --purge
```

卸载会恢复系统 DNS 与 IPv6 设置；`--purge` 会同时删除设置、订阅和日志。

## ⚠️ 已知限制

- 未做开发者签名与公证（本机 ad-hoc 签名），换机器使用需重新构建。
- 防泄漏规则按 uid 区分「root 进程」与「普通用户进程」；以 root 身份运行的程序不受防泄漏层约束（但仍走 TUN）。
- 本机以你的身份运行的恶意程序可以读取内核控制密钥（界面需要它来切节点），守护进程每 30 秒会重新下发闸门状态，但无法完全防住本机恶意程序。
- 长连接心跳每 2 秒约 1 KB，全天约 50 MB 代理流量；可在设置里调大间隔。
- 出口国家依赖 Cloudflare trace / ipinfo 的地理库，个别节点可能被误判；误判方向是多熔断而不是少熔断。
