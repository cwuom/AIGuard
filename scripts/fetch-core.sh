#!/bin/zsh
# 下载并校验 mihomo 内核与离线分流规则库，产物放在 Vendor/（构建脚本会打包进 App）
set -euo pipefail

MIHOMO_VERSION="v1.19.34"
MIHOMO_ASSET="mihomo-darwin-arm64-${MIHOMO_VERSION}.gz"
MIHOMO_SHA256="1a7a20eca63fbbaec90137717465bfde488d0db2a3a79b8fadebf9b2545b6e4c"
RULES_BASE="https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo"

ROOT="${0:A:h:h}"
VENDOR="$ROOT/Vendor"
mkdir -p "$VENDOR/rules"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ ! -x "$VENDOR/mihomo" ]] || ! "$VENDOR/mihomo" -v 2>/dev/null | grep -q "$MIHOMO_VERSION"; then
  echo "==> 下载 $MIHOMO_ASSET"
  curl -fL --retry 3 -m 300 -o "$TMP/$MIHOMO_ASSET" \
    "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${MIHOMO_ASSET}"
  echo "$MIHOMO_SHA256  $TMP/$MIHOMO_ASSET" | shasum -a 256 -c -
  gunzip -c "$TMP/$MIHOMO_ASSET" > "$VENDOR/mihomo"
  chmod 755 "$VENDOR/mihomo"
fi
"$VENDOR/mihomo" -v

# 规则库没有固定版本号，记录 sha256 便于追溯
for item in geosite/cn geoip/cn geosite/anthropic geosite/category-ntp; do
  name="${item//\//-}.mrs"
  echo "==> 下载 $item.mrs"
  curl -fL --retry 3 -m 120 -o "$TMP/$name" "$RULES_BASE/$item.mrs"
  [[ -s "$TMP/$name" ]] || { echo "空文件: $name" >&2; exit 1; }
  mv "$TMP/$name" "$VENDOR/rules/$name"
done
# 熔断时 pf 白名单放行的大陆 IPv4 段（IPv6 本来就全部封锁）
echo "==> 下载 geoip/cn.list"
curl -fL --retry 3 -m 300 -o "$TMP/cn.list" "$RULES_BASE/geoip/cn.list"
python3 -I -c '
import ipaddress, sys
nets = []
for line in open(sys.argv[1]):
    t = line.strip()
    if not t or t.startswith("#") or ":" in t:
        continue
    nets.append(ipaddress.IPv4Network(t, strict=False))
out = list(ipaddress.collapse_addresses(nets))
if len(out) < 1000:
    sys.exit("大陆 IP 段数量异常: %d" % len(out))
open(sys.argv[2], "w").write("\n".join(map(str, out)) + "\n")
print("大陆 IPv4 段:", len(out))
' "$TMP/cn.list" "$VENDOR/rules/cn4.txt"
rm -f "$VENDOR/rules/us4.txt"
(cd "$VENDOR/rules" && shasum -a 256 *.mrs cn4.txt | tee SHA256SUMS)
