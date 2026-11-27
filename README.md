# AIGuard

English | [简体中文](README.zh-CN.md)

AIGuard is a proxy client with one job: when you travel or work from mainland China, Claude, ChatGPT, Gemini and other AI services should never see a mainland China, Hong Kong or Macau IP address. Not once, not during a network switch, not when the lid wakes up on a new Wi-Fi.

It bundles the [mihomo](https://github.com/MetaCubeX/mihomo) core, takes over traffic with a TUN device, and puts a firewall underneath so that a crashed core or a stolen route fails closed instead of leaking. There are three clients:

- macOS 26+ on Apple Silicon (SwiftUI, lives in the menu bar). This is the main one.
- Android 10+ with KernelSU (or Magisk `service.d`), arm64. Early build.
- Windows 10 21H2+ / Windows 11, x64 or ARM64. Early build.

The UI is in Chinese for now.

## How it works

You import a subscription. All proxied traffic, AI included, goes through one group ("节点选择"), and nodes whose names point at a forbidden region (CN, HK, MO by default; CN can't be removed) are filtered out. The default "auto" group is a fallback group, so the exit IP only changes when the current node actually fails.

A TLS connection is kept open through the proxy and pinged every 2 seconds. Each ping also checks which country the exit is in. Two failures in a row, or an exit in a forbidden region, trips the fuse.

Routing modes:

| Mode | AI traffic | Mainland traffic | Everything else |
|---|---|---|---|
| Smart (default) | proxy | direct | proxy |
| Global | proxy | proxy | proxy |
| Direct, AI blocked | rejected | direct | rejected (can be set to direct) |

AI rules never resolve to DIRECT in any mode. If hotel Wi-Fi needs a captive portal, the "hotel Wi-Fi login" button lets everything go direct for 5 minutes using the DHCP-provided DNS; AI stays blocked during that time.

## The fuse

When the fuse trips, only mainland China is reachable. The core only lets through `geosite:cn` / `geoip:cn`, and the firewall (pf, iptables or WFP) independently allows only the ~6000 mainland IPv4 ranges, so the whitelist still holds if the core or TUN is broken. The only exception is that the core itself may reach your proxy nodes and the subscription server, so it can recover. You can switch the fuse to "cut everything" instead, which leaves only loopback, LAN and DHCP.

| Trigger | What happens | Released when |
|---|---|---|
| Startup, mode change | whitelist | 4 good heartbeats and the exit country checks out |
| Lid closed / sleep | everything cut before sleep, then whitelist | at least 8 s after wake, then the same check |
| Network change (Wi-Fi, IP) | same as sleep, no debounce | same |
| Core exits or hangs, TUN route lost | whitelist; core is restarted after 8 s of lost route | core and TUN are back and verified |
| 2 heartbeat failures in a row, node unreachable | whitelist | automatically (or manually, if you prefer) |
| Exit lands in a forbidden region | whitelist, optionally switch to a safe node | a new exit check passes |
| Public IPv6 is reachable | whitelist | IPv6 is blocked again |
| Manual | whitelist | manual release |

On a trip, browsers are closed once and AI processes are killed every 3 seconds until the fuse is released. AI processes are matched by whole-word keywords (claude, anthropic, openai, chatgpt, codex, cursor, copilot, gemini, ollama, and so on) against the app path and process name. For node and python it looks at the script actually being run, which is how Claude Code, the Codex CLI and editor Copilot get caught. File arguments don't count, so `vim ~/.claude/x` is left alone, and system processes are never touched.

If something else (V2rayU, another VPN) keeps stealing the route, the core is rebuilt with 1, 2, 4 ... minute back-off, at most 5 times per incident, and then it asks you to deal with it.

## Leak protection

- DNS: every network service's DNS is pinned to the TUN address (`198.18.0.2`). Mainland names go to domestic DoH, the rest go to DoH through the proxy, and AI domains get fake IPs and are never resolved locally. Plain DNS on 53/853 that tries to bypass the TUN is dropped. The original settings are backed up and restored when you turn the guard off or uninstall.
- IPv6: turned off on every interface, the core doesn't use it, the firewall rejects all IPv6 egress, and every 30 seconds AIGuard tries to reach the public IPv6 internet. If it gets through, the fuse trips.
- Bypassing the TUN: user processes that try to go around it are dropped. These rules stay in place if the daemon crashes.

## The AI list

14 categories, 440+ rules, plus `geosite:anthropic` and `geosite:category-ntp`, built from v2fly `category-ai-!cn` and the blackmatrix7 rule sets. Besides the obvious ones (Anthropic, OpenAI, Gemini, Copilot, Grok, Perplexity, coding tools, model hosts) there are some deliberately aggressive categories: the whole Google account system, X/Twitter, third-party risk, auth, payment and telemetry services (Sentry, Datadog, Statsig, Sift, Arkose, Stripe, Auth0, Intercom ...), and NTP. Each category can be turned off, and you can add your own domains.

## Install

Close other proxy apps first (V2rayU, Clash Verge, etc.). Two TUN devices will fight over the route, and AIGuard will warn you if it sees one.

macOS: open the DMG, drag AIGuard to Applications, open it and click "安装并启动" (install and start), then enter your password. Paste your subscription link on the "订阅" (subscription) page. The app is ad-hoc signed, so the first launch may need right-click → Open.

Android: install the APK, allow "AI 出差管家" in KernelSU's superuser list, open the app and tap "安装守护进程" (install daemon), then import the subscription under Settings.

Windows: unzip somewhere only you can write to, run `AIGuard.exe`, click "安装并启动" and accept the UAC prompt. Files go to `C:\Program Files\AIGuard`, settings and logs to `C:\ProgramData\AIGuard`.

## Build

macOS:

```bash
scripts/fetch-core.sh
```

```bash
./scripts/make-dmg.sh
```

You can also install from the terminal:

```bash
sudo /Applications/AIGuard.app/Contents/Resources/install.sh --uid $(id -u)
```

Android:

```bash
scripts/fetch-core.sh && android/scripts/fetch-core.sh
```

```bash
cd android && ./gradlew :core:test :app:testDebugUnitTest :app:lintDebug :app:assembleRelease
```

Windows (cross-compiled on macOS, needs Go):

```bash
scripts/fetch-core.sh && windows/scripts/fetch-core.sh
```

```bash
windows/scripts/build.sh
```

Output lands in `build/`.

## Development

```bash
swift test
```

```bash
AIGUARD_INTEGRATION=1 swift test
```

The integration tests start a real, non-root mihomo and check node filtering, gates, authenticated probe listeners and exit detection. They need network access.

To run the daemon and app together without root (no pf, no TUN):

```bash
.build/debug/aiguardd --dev --helper-dir build/AIGuard.app/Contents/Resources
```

```bash
open -n --env AIGUARD_SOCKET="$HOME/Library/Application Support/AIGuard-dev/dev.sock" build/AIGuard.app
```

Layout:

```
Sources/AIGuardCore   pure logic: settings, AI list, mihomo config, pf rules, fuse state machine, subscriptions, IPC
Sources/aiguardd      root daemon: core, firewall, heartbeat, DNS/IPv6 lock, app killing, sleep/network events, control socket
Sources/AIGuard       SwiftUI app and menu bar
android/              Android port (root daemon via app_process, Compose UI)
windows/              Windows port (Go service, WFP firewall, Wails UI)
scripts/              fetch-core, build-app, install, uninstall
```

On macOS the daemon lives in `/Library/PrivilegedHelperTools/com.aiguard.daemon/`, settings and the subscription in `/Library/Application Support/AIGuard/` (root, 0600), and logs in `/Library/Logs/AIGuard/`.

## Android notes

The pure logic (AI list, config generation, fuse, subscription parsing) is shared with macOS; only the platform layer differs. The daemon runs as root through `app_process`, started by `/data/adb/service.d/aiguard.sh` and restarted by a watchdog. pf is replaced by iptables: an `AIGUARD_OUT` / `AIGUARD_OUT6` chain at the top of `OUTPUT`, a nat chain that redirects app DNS to the core, and a separate `AIGUARD_CN` chain for the whitelist. Private DNS is switched off because DoT would bypass the redirect. IPv6 is disabled on Wi-Fi and Ethernet but not on cellular, where 464XLAT needs it; ip6tables blocks it there instead. Deep sleep only rebuilds the heartbeat connection rather than tripping, otherwise every wake would block push notifications.

The Compose app is only a remote control. It talks to the daemon on `127.0.0.1:19190` with a token, and the firewall only lets root and the app reach that port. Runtime files are in `/data/adb/aiguard/`. To uninstall, use the app's settings or:

```bash
su -c sh /data/adb/aiguard/uninstall.sh --purge
```

## Windows notes

Same shared logic, written in Go. The daemon is a LocalSystem service that restarts itself one second after a crash; the core runs inside a Job object, so it dies with the service. pf is replaced by WFP with its own provider and a top-weight sublayer, and the rules are persistent: they survive a stopped service, a crash and a reboot. Each policy switch happens in one WFP transaction. DNS on physical adapters is pinned to the TUN, IPv6 binding is removed from them, and the suspend callback cuts the network before the machine sleeps. The control pipe only accepts SYSTEM, administrators and the user who installed it, and the client must be the installed `AIGuard.exe`.

The WFP code borrows from [wireguard-windows](https://git.zx2c4.com/wireguard-windows/) and the strict-route code in [sing-tun](https://github.com/MetaCubeX/sing-tun). WFP access goes through a fork of [tailscale/wf](https://github.com/tailscale/wf) with transaction support added (`windows/third_party/wf`).

Windows also has a game mode, off by default and switched on from the tray or the "熔断与安全" page. Optionally it can turn on by itself when a game (not its launcher or helper processes) or an accelerator such as UU or Leigod is running, and turn off a minute after it exits. In game mode every AI service is blocked outright, not proxied: AI apps are closed right away and closed again every 1.5 s if reopened, they can't reach the network at all, and AI websites are rejected inside the TUN. Everything else goes direct, DNS returns real IPs and strict-route is off, so accelerators can install their own routes. A fuse trip no longer cuts the whole machine in game mode; a manual trip still does.

If a broken uninstall leaves you offline, run this in an admin prompt:

```bash
"C:\Program Files\AIGuard\aiguard-service.exe" firewall-reset
```

It stops the service, sets it to manual start and removes all AIGuard filters. Clicking "启动防护服务" in the app turns it back on. To uninstall:

```bash
"C:\Program Files\AIGuard\aiguard-service.exe" uninstall --purge
```

## Uninstall (macOS)

```bash
sudo /Applications/AIGuard.app/Contents/Resources/uninstall.sh --purge
```

This restores DNS and IPv6. `--purge` also deletes settings, the subscription and logs.

## Known limitations

- Nothing is notarized or code-signed. On Windows that means a SmartScreen prompt, and the installer elevates the `aiguard-service.exe` from wherever you unzipped it, so get the zip from a source you trust.
- Programs running as root (macOS, Android) or SYSTEM (Windows) aren't held by the leak layer, though they still go through the TUN.
- A malicious program running as you can read the core's controller secret, which the UI needs to switch nodes. The daemon re-applies the gates every 30 seconds, but this isn't a defense against local malware.
- The heartbeat costs roughly 1 KB every 2 seconds, about 50 MB a day of proxy traffic. You can raise the interval. The auto group checks nodes every 10 minutes, or right away when the heartbeat fails.
- Exit country comes from Cloudflare trace and ipinfo. When they're wrong, the error is in the direction of tripping too often.
- Android: baseband traffic (VoLTE, SMS) and 464XLAT are deliberately not blocked; hotspot clients aren't protected; IPv6-only Wi-Fi will be offline.
- Windows: WSL2 and Hyper-V traffic doesn't pass through WFP's ALE layer, so it follows the TUN normally but isn't held by the firewall during a trip. Modern Standby machines may not send the classic suspend notification. If Defender quarantines mihomo you'll just be offline; add `C:\Program Files\AIGuard` to the exclusions. In game mode, an AI tool that isn't recognized can reach AI services that aren't on the IP list until it's caught.

## License

GPL-3.0, see [LICENSE](LICENSE). Bundled third-party components (mihomo under MIT, meta-rules-dat under GPL-3.0, and others) are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
