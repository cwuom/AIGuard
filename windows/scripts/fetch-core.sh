#!/bin/zsh
# 下载并校验 Windows 版 mihomo 内核（amd64 用 v1 指令集版本，兼容所有 x64 CPU），产物放在 Vendor/windows/<arch>/。
# 分流规则库与 macOS 共用 Vendor/rules，由仓库根目录的 scripts/fetch-core.sh 下载
set -euo pipefail

MIHOMO_VERSION="v1.19.34"
typeset -A ASSET SHA
ASSET[amd64]="mihomo-windows-amd64-v1-${MIHOMO_VERSION}.zip"
SHA[amd64]="703e325bfeee582f874b06d054eaae55ab7c194645d1835411685aafa85da5ea"
ASSET[arm64]="mihomo-windows-arm64-${MIHOMO_VERSION}.zip"
SHA[arm64]="076cb04a21377675bcf009b8d1dd83006ce2464aa537e37bce1faf6d3504f554"

ROOT="${0:A:h:h:h}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for arch in amd64 arm64; do
  OUT="$ROOT/Vendor/windows/$arch"
  mkdir -p "$OUT"
  if [[ -f "$OUT/mihomo.exe" && "$(cat "$OUT/VERSION" 2>/dev/null)" == "$MIHOMO_VERSION" ]]; then
    echo "==> $arch 内核已是 $MIHOMO_VERSION"
    continue
  fi
  echo "==> 下载 ${ASSET[$arch]}"
  curl -fL --retry 3 -m 300 -o "$TMP/${ASSET[$arch]}" \
    "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${ASSET[$arch]}"
  echo "${SHA[$arch]}  $TMP/${ASSET[$arch]}" | shasum -a 256 -c -
  mkdir -p "$TMP/$arch"
  unzip -q -o "$TMP/${ASSET[$arch]}" -d "$TMP/$arch"
  exe=("$TMP/$arch"/*.exe(N))
  (( ${#exe} == 1 )) || { echo "压缩包里应只有一个 exe：${exe[*]}" >&2; exit 1; }
  mv "${exe[1]}" "$OUT/mihomo.exe"
  echo "$MIHOMO_VERSION" > "$OUT/VERSION"
done
file "$ROOT"/Vendor/windows/*/mihomo.exe

for f in geosite-cn.mrs geoip-cn.mrs geosite-anthropic.mrs geosite-category-ntp.mrs cn4.txt; do
  [[ -s "$ROOT/Vendor/rules/$f" ]] || { echo "缺少 Vendor/rules/$f，先运行 scripts/fetch-core.sh" >&2; exit 1; }
done
echo "==> 规则库就绪（与 macOS 共用 Vendor/rules）"
