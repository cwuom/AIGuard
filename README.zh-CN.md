# AI 出差管家（AIGuard）

[English](README.md) | 简体中文

一个只干一件事的代理客户端：人在国内出差时，Claude、ChatGPT、Gemini 这些 AI 服务一次都不能看到中国大陆或港澳的 IP。换网的时候不行，合盖醒来连上新 Wi-Fi 的那一下也不行。

内置 [mihomo](https://github.com/MetaCubeX/mihomo) 内核，用 TUN 接管流量，底下再垫一层防火墙：内核崩了或路由被别的软件抢了，结果是断网，不是泄漏。目前有三个客户端：

- macOS 26 及以上，Apple Silicon，SwiftUI，常驻菜单栏。主力版本。
- Android 10 及以上，需要 KernelSU（Magisk 的 `service.d` 也行），arm64。早期版本。
- Windows 10 21H2 及以上 / Windows 11，x64 或 ARM64。早期版本。

## 工作方式

导入订阅后，AI 和其他走代理的流量都走同一个「节点选择」，名字里带出口禁区（默认中国大陆、香港、澳门，大陆不能移除）的节点会被排除。默认用「自动选择」，它是 fallback 组，只有当前节点真的挂了才换线，出口 IP 比较稳。

经代理保持一条 TLS 长连接，每 2 秒心跳一次，顺便校验出口国家。连续失败 2 次，或者出口落进禁区，就熔断。

出站模式：

| 模式 | AI 流量 | 大陆流量 | 其余流量 |
|---|---|---|---|
| 智能分流（默认） | 代理 | 直连 | 代理 |
| 全局代理 | 代理 | 代理 | 代理 |
| 直连阻断 AI | 拒绝 | 直连 | 拒绝（可在设置里改成直连） |

任何模式下 AI 规则都不会指向 DIRECT。酒店 Wi-Fi 要网页认证时，点「酒店 Wi-Fi 登录」，5 分钟内全部直连并用 DHCP 下发的 DNS，AI 照样拒绝。

## 熔断

熔断后只能访问大陆。内核按域名只放行 `geosite:cn` / `geoip:cn`，防火墙（pf、iptables 或 WFP）再按 IP 只放行 6000 多个大陆 IPv4 段，所以内核或 TUN 出问题时白名单照样有效。唯一的例外是内核自己可以连订阅里的节点和订阅服务器，不然没法恢复。熔断方式也可以改成「全部断网」，只留回环、局域网和 DHCP。

| 触发 | 处置 | 解除 |
|---|---|---|
| 启动、切换模式 | 大陆白名单 | 连续 4 次心跳成功且出口验证通过 |
| 合盖睡眠 | 睡眠前先全部断网，之后转大陆白名单 | 唤醒后至少保持 8 秒，再走验证 |
| 换网（换 Wi-Fi、IP 变化） | 同上，不防抖 | 同上 |
| 内核退出或无响应、TUN 路由丢失 | 大陆白名单；路由丢失 8 秒后自动重启内核 | 内核与 TUN 恢复并验证通过 |
| 心跳连续 2 次失败、节点连不上 | 大陆白名单 | 自动解除（也可改成手动） |
| 出口落在禁区 | 大陆白名单，可自动换到出口安全的节点 | 新的出口检测通过 |
| 能直连公网 IPv6 | 大陆白名单 | IPv6 重新被封住 |
| 手动 | 大陆白名单 | 手动解除 |

熔断时浏览器关一次，AI 进程每 3 秒清一次，直到解除。AI 进程按关键词整词匹配（claude、anthropic、openai、chatgpt、codex、cursor、copilot、gemini、ollama 等），看 App 路径和进程名；node、python 这类解释器看它实际跑的脚本，Claude Code、Codex CLI、编辑器里的 Copilot 就是这么抓到的。普通的文件参数不算，`vim ~/.claude/x` 不会被关，系统进程一律不碰。

如果 V2rayU 之类的软件一直抢路由，内核会按 1、2、4…分钟退避重建，同一次故障最多 5 次，之后提示你手动处理。

## 防泄漏

- DNS：每个网络服务的 DNS 都锁到 TUN 地址 `198.18.0.2`。大陆域名走国内 DoH，其余经代理走 DoH，AI 域名用 fake-ip，不在本地解析。想绕过 TUN 走 53/853 的明文 DNS 一律丢弃。原设置会备份，关闭守护或卸载时恢复。
- IPv6：所有网卡关掉 IPv6，内核不用 IPv6，防火墙拒绝全部 IPv6 出站，另外每 30 秒主动试一次能不能直连公网 IPv6，连得上就熔断。
- 绕过 TUN：普通进程想绕开 TUN 直连，直接丢弃。守护进程崩溃时这层规则也不会撤掉。

## AI 名单

14 类、440 多条规则，外加 `geosite:anthropic` 和 `geosite:category-ntp`，来源是 v2fly 的 `category-ai-!cn` 和 blackmatrix7 规则库。除了 Anthropic、OpenAI、Gemini、Copilot、Grok、Perplexity、AI 编程工具、模型平台这些，还有几类是故意宁可错杀的：整个 Google 账号体系、X/Twitter、第三方风控/鉴权/支付/遥测（Sentry、Datadog、Statsig、Sift、Arkose、Stripe、Auth0、Intercom 等），以及 NTP。每一类都能单独关，也能自己加域名。

## 安装

先退出 V2rayU、Clash Verge 等其他代理软件。两个 TUN 会抢路由，App 检测到会提示。

macOS：打开 DMG，把 AIGuard 拖进「应用程序」，打开后点「安装并启动」，输入密码，再到「订阅」页粘贴订阅链接。App 是 ad-hoc 签名，第一次打开可能要在 Finder 里右键 →「打开」。

Android：装好 APK，在 KernelSU 的「超级用户」里允许「AI 出差管家」，打开 App 点「安装守护进程」，再到「设置 → 订阅」导入。

Windows：解压到只有自己能写的位置，运行 `AIGuard.exe`，点「安装并启动」，在用户账户控制窗口确认。程序装到 `C:\Program Files\AIGuard`，设置和日志在 `C:\ProgramData\AIGuard`。

## 构建

macOS：

```bash
scripts/fetch-core.sh
```

```bash
./scripts/make-dmg.sh
```

也可以在终端手动安装：

```bash
sudo /Applications/AIGuard.app/Contents/Resources/install.sh --uid $(id -u)
```

Android：

```bash
scripts/fetch-core.sh && android/scripts/fetch-core.sh
```

```bash
cd android && ./gradlew :core:test :app:testDebugUnitTest :app:lintDebug :app:assembleRelease
```

Windows（在 macOS 上交叉编译，需要 Go）：

```bash
scripts/fetch-core.sh && windows/scripts/fetch-core.sh
```

```bash
windows/scripts/build.sh
```

产物都在 `build/`。

## 开发

```bash
swift test
```

```bash
AIGUARD_INTEGRATION=1 swift test
```

集成测试会起一个非 root 的真实 mihomo，验证节点过滤、闸门、探测入站认证和出口检测，需要联网。

不装 root 组件也能把守护进程和界面跑起来（不碰 pf、不开 TUN）：

```bash
.build/debug/aiguardd --dev --helper-dir build/AIGuard.app/Contents/Resources
```

```bash
open -n --env AIGUARD_SOCKET="$HOME/Library/Application Support/AIGuard-dev/dev.sock" build/AIGuard.app
```

目录：

```
Sources/AIGuardCore   纯逻辑：设置、AI 名单、mihomo 配置、pf 规则、熔断状态机、订阅解析、IPC
Sources/aiguardd      root 守护进程：内核、防火墙、心跳、DNS/IPv6 锁定、关闭应用、睡眠与网络事件、控制通道
Sources/AIGuard       SwiftUI 界面与菜单栏
android/              Android 版（app_process 跑 root 守护进程，Compose 界面）
windows/              Windows 版（Go 服务、WFP 防火墙、Wails 界面）
scripts/              fetch-core、build-app、install、uninstall
```

macOS 上守护进程在 `/Library/PrivilegedHelperTools/com.aiguard.daemon/`，设置和订阅在 `/Library/Application Support/AIGuard/`（root，0600），日志在 `/Library/Logs/AIGuard/`。

## Android 版说明

纯逻辑（AI 名单、配置生成、熔断、订阅解析）和 macOS 版是同一套，只换了平台层。守护进程通过 `app_process` 以 root 运行，开机由 `/data/adb/service.d/aiguard.sh` 拉起，挂了有看门狗重启。pf 换成了 iptables：`OUTPUT` 最前面挂 `AIGUARD_OUT` / `AIGUARD_OUT6`，nat 表把 App 的 DNS 重定向给内核，大陆白名单是单独的 `AIGUARD_CN` 链。「私人 DNS」会被关掉，因为 DoT 能绕过重定向。Wi-Fi 和有线网卡关 IPv6，蜂窝网卡不关（464XLAT 要用），只靠 ip6tables 拦。深睡眠醒来只重建长连接，不熔断，不然每次亮屏都会把推送挡掉。

Compose 界面只是个遥控器，经 `127.0.0.1:19190` 加 token 和守护进程通信，防火墙只允许 root 和本 App 连这个端口。运行文件在 `/data/adb/aiguard/`。卸载在 App 设置里，或者：

```bash
su -c sh /data/adb/aiguard/uninstall.sh --purge
```

## Windows 版说明

同一套逻辑，用 Go 写的。守护进程是 LocalSystem 服务，崩溃 1 秒后自动重启；内核放在 Job 对象里，服务一死它也跟着死。pf 换成了 WFP，用自己的 provider 和最高权重的子层，规则是持久化的，服务停了、崩了、重启电脑都还在，每次切换策略在一个 WFP 事务里完成。真实网卡的 DNS 锁到 TUN，IPv6 绑定去掉，系统挂起回调里先断网再睡。控制管道只接受 SYSTEM、管理员和安装时的那个用户，而且客户端必须是安装目录里的 `AIGuard.exe`。

WFP 部分参考了 [wireguard-windows](https://git.zx2c4.com/wireguard-windows/) 和 [sing-tun](https://github.com/MetaCubeX/sing-tun) 的 strict-route，WFP 封装用的是 fork 过的 [tailscale/wf](https://github.com/tailscale/wf)，补了事务支持（`windows/third_party/wf`）。

Windows 版还有个游戏模式，默认关，在托盘菜单或「熔断与安全」页手动打开。也可以开启自动检测：游戏本体（不是启动器或辅助进程）或 UU、雷神这类加速器在运行时自动进入，退出一分钟后恢复。游戏模式下所有 AI 服务直接禁止，不走代理：AI 程序立刻被关掉，再打开每 1.5 秒还会被关，完全不能联网；浏览器里的 AI 网站在 TUN 里拒绝。其余流量直连，DNS 返回真实 IP，strict-route 关闭，加速器可以加自己的路由。游戏模式下熔断不会断整机网络，手动熔断还是会断。

卸载不干净导致上不了网时，在管理员命令行运行：

```bash
"C:\Program Files\AIGuard\aiguard-service.exe" firewall-reset
```

它会停掉服务、改成手动启动，并删除 AIGuard 的全部防火墙规则。之后在界面里点「启动防护服务」就能恢复。卸载：

```bash
"C:\Program Files\AIGuard\aiguard-service.exe" uninstall --purge
```

## 卸载（macOS）

```bash
sudo /Applications/AIGuard.app/Contents/Resources/uninstall.sh --purge
```

会恢复 DNS 和 IPv6 设置，`--purge` 同时删掉设置、订阅和日志。

## 已知限制

- 没有公证，也没有代码签名。Windows 上首次运行会有 SmartScreen 提示，而且安装时提权运行的是你解压出来的 `aiguard-service.exe`，所以安装包请从可信的地方拿。
- 以 root（macOS、Android）或 SYSTEM（Windows）身份运行的程序不受防泄漏层约束，不过它们的流量仍然经过 TUN。
- 以你的身份运行的恶意程序能读到内核的控制密钥（界面切节点要用）。守护进程每 30 秒会重新下发一次闸门，但防不住本机恶意程序。
- 心跳每 2 秒大约 1 KB，一天约 50 MB 代理流量，可以调大间隔。「自动选择」每 10 分钟体检一次节点，心跳失败时立刻体检。
- 出口国家来自 Cloudflare trace 和 ipinfo，判错的时候是多熔断，不会少熔断。
- Android：基带（VoLTE、短信）和 464XLAT 的流量故意不拦；热点给其他设备用的流量不在保护范围；纯 IPv6 的 Wi-Fi 会断网。
- Windows：WSL2 和 Hyper-V 的流量不经过 WFP 的 ALE 层，平时跟着 TUN 走，熔断时防火墙管不到。现代待机的机器合盖时可能不发传统的挂起通知。Defender 要是把 mihomo 隔离了，表现就是断网，把 `C:\Program Files\AIGuard` 加进排除项即可。游戏模式下，没认出来的 AI 工具在被抓到之前能连到不在 IP 名单里的 AI 服务。

## 许可证

GPL-3.0，见 [LICENSE](LICENSE)。打包进来的第三方组件（mihomo 是 MIT，meta-rules-dat 是 GPL-3.0，等等）列在 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
