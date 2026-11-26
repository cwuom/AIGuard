#!/bin/zsh
# 安装/升级 AIGuard 守护进程（需要 root）。用法：sudo ./install.sh --uid <你的 uid>
set -euo pipefail

LABEL="com.aiguard.daemon"
HELPER="/Library/PrivilegedHelperTools/$LABEL"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
SOCKET="/var/run/$LABEL.sock"
RES="${0:A:h}"
APP_SRC="${RES:h:h}"

[[ $EUID -eq 0 ]] || { echo "请用 sudo 运行" >&2; exit 1; }

TARGET_UID="${SUDO_UID:-}"
while (( $# )); do
  case "$1" in
    --uid) TARGET_UID="$2"; shift 2 ;;
    *) echo "未知参数 $1" >&2; exit 1 ;;
  esac
done
[[ "$TARGET_UID" =~ ^[0-9]+$ && "$TARGET_UID" -ge 501 ]] || { echo "需要 --uid <登录用户 uid>" >&2; exit 1; }

for f in aiguardd mihomo rules/geosite-cn.mrs rules/geoip-cn.mrs rules/geosite-anthropic.mrs rules/geosite-category-ntp.mrs rules/cn4.txt; do
  [[ -e "$RES/$f" ]] || { echo "缺少 $RES/$f，请用 scripts/build-app.sh 构建" >&2; exit 1; }
done

# App 不在 /Applications 时复制过去，方便从构建目录直接安装
if [[ "$APP_SRC" == *.app && "$APP_SRC" != "/Applications/AIGuard.app" ]]; then
  echo "==> 安装 App 到 /Applications"
  rm -rf "/Applications/AIGuard.app"
  ditto "$APP_SRC" "/Applications/AIGuard.app"
  chown -R "$TARGET_UID":staff "/Applications/AIGuard.app"
fi

echo "==> 停止旧版守护进程"
launchctl bootout "system/$LABEL" 2>/dev/null || true
for _ in {1..50}; do [[ -S "$SOCKET" ]] || break; sleep 0.1; done

echo "==> 安装守护进程到 $HELPER"
install -d -m 755 -o root -g wheel "$HELPER" "$HELPER/rules"
install -m 755 -o root -g wheel "$RES/aiguardd" "$HELPER/aiguardd"
install -m 755 -o root -g wheel "$RES/mihomo" "$HELPER/mihomo"
install -m 644 -o root -g wheel "$RES"/rules/*.mrs "$RES"/rules/cn4.txt "$HELPER/rules/"
rm -f "$HELPER/rules/us4.txt"
install -d -m 755 -o root -g wheel /Library/Logs/AIGuard

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$HELPER/aiguardd</string>
    <string>--uid</string><string>$TARGET_UID</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>3</integer>
  <key>ProcessType</key><string>Interactive</string>
  <key>SoftResourceLimits</key><dict><key>NumberOfFiles</key><integer>65536</integer></dict>
  <key>HardResourceLimits</key><dict><key>NumberOfFiles</key><integer>65536</integer></dict>
  <key>StandardErrorPath</key><string>/Library/Logs/AIGuard/launchd.log</string>
</dict>
</plist>
PLIST
chown root:wheel "$PLIST"
chmod 644 "$PLIST"

echo "==> 启动守护进程"
launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL"
for _ in {1..100}; do [[ -S "$SOCKET" ]] && break; sleep 0.1; done
if [[ -S "$SOCKET" ]]; then
  echo "✅ 安装完成：$("$HELPER/aiguardd" --version)"
else
  echo "⚠️ 守护进程未就绪，查看 /Library/Logs/AIGuard/daemon.log" >&2
  exit 1
fi
