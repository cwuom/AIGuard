#!/bin/zsh
# 下载并校验 Android 版 mihomo 内核，产物放在 Vendor/android/（Gradle 打包进 APK 的 assets）。
# 分流规则库与 macOS 共用 Vendor/rules，由仓库根目录的 scripts/fetch-core.sh 下载
set -euo pipefail

MIHOMO_VERSION="v1.19.34"
MIHOMO_ASSET="mihomo-android-arm64-v8-${MIHOMO_VERSION}.gz"
MIHOMO_SHA256="48a71fc6a68e2909587176e0ab7185d8f2fac298fa96ccdacf30ea86ab2359b5"

ROOT="${0:A:h:h:h}"
OUT="$ROOT/Vendor/android"
mkdir -p "$OUT"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ ! -f "$OUT/mihomo" || "$(cat "$OUT/VERSION" 2>/dev/null)" != "$MIHOMO_VERSION" ]]; then
  echo "==> 下载 $MIHOMO_ASSET"
  curl -fL --retry 3 -m 300 -o "$TMP/$MIHOMO_ASSET" \
    "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${MIHOMO_ASSET}"
  echo "$MIHOMO_SHA256  $TMP/$MIHOMO_ASSET" | shasum -a 256 -c -
  gunzip -c "$TMP/$MIHOMO_ASSET" > "$OUT/mihomo"
  chmod 755 "$OUT/mihomo"
  echo "$MIHOMO_VERSION" > "$OUT/VERSION"
fi
file "$OUT/mihomo"

for f in geosite-cn.mrs geoip-cn.mrs geosite-anthropic.mrs geosite-category-ntp.mrs cn4.txt; do
  [[ -s "$ROOT/Vendor/rules/$f" ]] || { echo "缺少 Vendor/rules/$f，先运行 scripts/fetch-core.sh" >&2; exit 1; }
done
echo "==> 规则库就绪（与 macOS 共用 Vendor/rules）"
