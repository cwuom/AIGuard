#!/bin/zsh
# 构建 build/AIGuard.app：release 编译、打包内核与规则、ad-hoc 签名
set -euo pipefail
ROOT="${0:A:h:h}"
cd "$ROOT"
APP="$ROOT/build/AIGuard.app"

[[ -x Vendor/mihomo ]] || ./scripts/fetch-core.sh

echo "==> 编译（release）"
swift build -c release --product AIGuard
swift build -c release --product aiguardd
BIN="$(swift build -c release --show-bin-path)"

echo "==> 组装 App"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/rules" "$APP/Contents/Resources/zh-Hans.lproj"
cp "$BIN/AIGuard" "$APP/Contents/MacOS/AIGuard"
cp "$BIN/aiguardd" "$APP/Contents/Resources/aiguardd"
cp Vendor/mihomo "$APP/Contents/Resources/mihomo"
cp Vendor/rules/*.mrs Vendor/rules/cn4.txt "$APP/Contents/Resources/rules/"
cp scripts/install.sh scripts/uninstall.sh "$APP/Contents/Resources/"
cp LICENSE THIRD_PARTY_NOTICES.md "$APP/Contents/Resources/"
chmod 755 "$APP/Contents/Resources/"{aiguardd,mihomo,install.sh,uninstall.sh}

ICONSET="$ROOT/build/AppIcon.iconset"
rm -rf "$ICONSET"
swift scripts/make-icon.swift "$ICONSET"
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$ICONSET"

VERSION="$(sed -n 's/^public let AIGuardVersion = "\(.*\)"/\1/p' Sources/AIGuardCore/IPC.swift)"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.aiguard.app</string>
  <key>CFBundleDevelopmentRegion</key><string>zh-Hans</string>
  <key>CFBundleLocalizations</key><array><string>zh-Hans</string></array>
  <key>CFBundleName</key><string>AIGuard</string>
  <key>CFBundleDisplayName</key><string>AI 出差管家</string>
  <key>CFBundleExecutable</key><string>AIGuard</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>26.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSAppleEventsUsageDescription</key><string>安装守护进程时需要请求管理员授权。</string>
</dict>
</plist>
PLIST

echo "==> ad-hoc 签名"
codesign --force -s - --options runtime "$APP/Contents/Resources/mihomo"
codesign --force -s - --options runtime "$APP/Contents/Resources/aiguardd"
codesign --force -s - "$APP"
codesign --verify --deep --strict "$APP"
echo "✅ $APP"
