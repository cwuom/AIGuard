#!/bin/zsh
# 在 macOS/Linux 上交叉编译 Windows 版并打成 zip：build/AIGuard-Windows-<版本>-<架构>.zip
# 先运行 scripts/fetch-core.sh（规则库）与 windows/scripts/fetch-core.sh（Windows 内核）
set -euo pipefail

VERSION="1.1.1"
ROOT="${0:A:h:h:h}"
WIN="$ROOT/windows"
OUT="$ROOT/build"
ARCHES=(${=${AIGUARD_ARCHES:-amd64 arm64}})

cd "$WIN"
echo "==> 生成图标与 exe 资源"
go run ./tools/genres -version "$VERSION" -out cmd

echo "==> 单元测试"
go test ./... -count=1 -timeout 300s

for arch in $ARCHES; do
  CORE="$ROOT/Vendor/windows/$arch/mihomo.exe"
  [[ -f "$CORE" ]] || { echo "缺少 $CORE，先运行 windows/scripts/fetch-core.sh" >&2; exit 1; }
  STAGE="$(mktemp -d)/AIGuard"
  mkdir -p "$STAGE/core" "$STAGE/rules"
  LDFLAGS="-s -w -X aiguard/internal/version.Version=$VERSION"
  echo "==> 编译 $arch"
  CGO_ENABLED=0 GOOS=windows GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" \
    -o "$STAGE/aiguard-service.exe" ./cmd/aiguard-service
  CGO_ENABLED=0 GOOS=windows GOARCH=$arch go build -trimpath -tags production -ldflags "$LDFLAGS -H windowsgui" \
    -o "$STAGE/AIGuard.exe" ./cmd/aiguard
  cp "$CORE" "$STAGE/core/mihomo.exe"
  for f in geosite-cn.mrs geoip-cn.mrs geosite-anthropic.mrs geosite-category-ntp.mrs cn4.txt; do
    cp "$ROOT/Vendor/rules/$f" "$STAGE/rules/$f"
  done
  cp "$ROOT/LICENSE" "$STAGE/LICENSE.txt"
  cp "$ROOT/THIRD_PARTY_NOTICES.md" "$STAGE/THIRD_PARTY_NOTICES.md"
  cp "$WIN/scripts/README-Windows.txt" "$STAGE/README-Windows.txt"
  mkdir -p "$OUT"
  ZIP="$OUT/AIGuard-Windows-$VERSION-$arch.zip"
  rm -f "$ZIP"
  (cd "${STAGE:h}" && zip -qr -X "$ZIP" AIGuard)
  rm -rf "${STAGE:h}"
  echo "==> $ZIP"
  (cd "$OUT" && shasum -a 256 "${ZIP:t}")
done
