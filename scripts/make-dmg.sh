#!/bin/zsh
# 打包 build/AIGuard-<版本>.dmg：App + 拖拽安装用的 Applications 快捷方式
set -euo pipefail
ROOT="${0:A:h:h}"
cd "$ROOT"
./scripts/build-app.sh
VERSION="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' build/AIGuard.app/Contents/Info.plist)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ditto build/AIGuard.app "$STAGE/AIGuard.app"
ln -s /Applications "$STAGE/Applications"
cat > "$STAGE/安装说明.txt" <<TXT
1. 先退出 V2rayU、Clash Verge 等其他代理软件（两个 TUN 会抢路由）。
2. 把 AIGuard 拖到 Applications，打开它。
3. 点「安装并启动」（已装旧版时显示「升级」），在系统授权窗口输入登录密码。
4. 在「订阅」页粘贴订阅链接导入，默认智能分流。
卸载：sudo /Applications/AIGuard.app/Contents/Resources/uninstall.sh --purge
TXT
DMG="build/AIGuard-$VERSION.dmg"
rm -f "$DMG"
hdiutil create -volname "AI 出差管家" -srcfolder "$STAGE" -fs APFS -format ULFO -ov "$DMG" >/dev/null
hdiutil verify "$DMG" >/dev/null
echo "✅ $DMG ($(du -h "$DMG" | cut -f1))"
