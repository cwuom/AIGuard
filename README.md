# AIGuard

English | [简体中文](README.zh-CN.md)

AIGuard is a strict egress-routing client with one job: ensuring that traffic for designated AI and cloud services never leaks over the local default interface—not during a network switch, not when the lid wakes up on a new Wi-Fi, and not if the routing core crashes.

It bundles the [mihomo](https://github.com/MetaCubeX/mihomo) core, takes over traffic with a TUN device, and places an OS-level firewall underneath so that a crashed core or a hijacked route fails closed instead of leaking. There are three clients:

- macOS 26+ on Apple Silicon (SwiftUI, lives in the menu bar). This is the main one.
- Android 10+ with KernelSU (or Magisk `service.d`), arm64. Early build.
- Windows 10 21H2+ / Windows 11, x64 or ARM64. Early build.

The UI is in Chinese for now.

## How it works

You import a remote routing profile. All policy-routed traffic, designated AI services included, goes through a single outbound group ("节点选择"), and endpoints whose names match excluded regions are automatically filtered out. The default "auto" group uses a fallback strategy, so the egress IP only changes when the active endpoint actually fails.

A TLS connection is kept open through the tunnel and pinged every 2 seconds. Each probe also verifies the egress region. Two consecutive failures, or an egress IP landing in an excluded region, trips the fuse.

Routing modes:

| Mode | Designated AI traffic | Local-region traffic | Everything else |
|---|---|---|---|
| Smart (default) | routed | direct | routed |
| Global | routed | routed | routed |
| Direct, AI blocked | rejected | direct | rejected (can be set to direct) |

Designated AI rules never resolve to DIRECT in any mode. If hotel Wi-Fi requires a captive portal, the "hotel Wi-Fi login" button temporarily allows general traffic to go direct for 5 minutes using DHCP-provided DNS while keeping AI endpoints blocked.

## The fuse

When the fuse trips, only allowlisted local-region ranges remain reachable. The core only permits configured direct-route rulesets, and the firewall (pf, iptables, or WFP) independently enforces the local IPv4 allowlist (~6,000 ranges), so isolation still holds even if the core or TUN fails. The only exception is allowing the core itself to reach your configured outbound endpoints and profile server for recovery. You can also switch the fuse to "cut everything" mode, leaving only loopback, LAN, and DHCP.

| Trigger | What happens | Released when |
|---|---|---|
| Startup, mode change | allowlist | 4 good heartbeats and egress region check passes |
| Lid closed / sleep | everything cut before sleep, then allowlist | at least 8 s after wake, then the same check |
| Network change (Wi-Fi, IP) | same as sleep, no debounce | same |
| Core exits or hangs, TUN route lost | allowlist; core is restarted after 8 s of lost route | core and TUN are back and verified |
| 2 heartbeat failures in a row, endpoint unreachable | allowlist | automatically (or manually, if you prefer) |
| Egress lands in an excluded region | allowlist, optionally switch to a compliant endpoint | a new egress check passes |
| Public IPv6 is reachable | allowlist | IPv6 is blocked again |
| Manual | allowlist | manual release |

On a trip, browsers are closed once and target AI processes are terminated every 3 seconds until the fuse is released. Processes are matched by whole-word keywords (claude, anthropic, openai, chatgpt, codex, cursor, copilot, gemini, ollama, etc.) against the app path and process name. For node and python, it inspects the script actually being executed, catching CLI tools and editor extensions without touching file arguments (e.g., `vim ~/.claude/x`) or system processes.

If another TUN client keeps hijacking the route, the core is rebuilt with 1, 2, 4 ... minute back-off, up to 5 times per incident, before prompting for manual intervention.

## Leak protection

- DNS: every network service's DNS is pinned to the TUN address (`198.18.0.2`). Local-region domains resolve via local DoH, routed domains resolve via upstream DoH through the tunnel, and designated AI domains receive fake IPs and are never resolved locally. Plain DNS on 53/853 attempting to bypass the TUN is dropped. Original settings are backed up and restored when disabled or uninstalled.
- IPv6: disabled on every interface, unused by the core, rejected at the firewall level for all egress, and probed every 30 seconds against public IPv6. If reachable, the fuse trips.
- Bypassing the TUN: user processes attempting to bypass the TUN interface are dropped. These rules persist even if the daemon crashes.

## The rule list

14 categories and 440+ rules built from community domain rulesets. Besides major AI providers, coding tools, and model hosts, it includes strict auxiliary categories: Google account services, X/Twitter, third-party risk/auth/payment/telemetry endpoints (Sentry, Datadog, Statsig, Sift, Arkose, Stripe, Auth0, Intercom, etc.), and NTP. Each category can be toggled independently, and custom domains are supported.

## Install

Close other TUN-based network clients first. Two TUN devices will conflict over the routing table, and AIGuard will warn you if a conflict is detected.

macOS: open the DMG, drag AIGuard to Applications, launch it, click "安装并启动" (install and start), and enter your password. Paste your profile URL on the "订阅" (profile) page. The app is ad-hoc signed, so the first launch may require right-click → Open.

Android: install the APK, grant root access to AIGuard in KernelSU, open the app, tap "安装守护进程" (install daemon), and import your profile under Settings.

Windows: extract to a user-writable directory, run `AIGuard.exe`, click "安装并启动", and accept the UAC prompt. Binaries install to `C:\Program Files\AIGuard`, with settings and logs in `C:\ProgramData\AIGuard`.
