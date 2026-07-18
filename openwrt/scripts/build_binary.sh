#!/bin/bash
# build_binary.sh - 交叉编译 nexa 二进制
#
# 用法:
#   build_binary.sh <GOOS> <GOARCH> <GOARM|GOMIPS(可空)> <version> <output_path>
#
# 示例:
#   build_binary.sh linux arm64 ""    1.0.0 dist/nexa-aarch64
#   build_binary.sh linux amd64 ""    1.0.0 dist/nexa-x86_64
#   build_binary.sh linux mipsle softfloat 1.0.0 dist/nexa-mipsel
set -e

GOOS="$1"
GOARCH="$2"
GOEXTRA="$3"   # GOARM 或 GOMIPS 的值，可为空
VERSION="$4"
OUT_PATH="$5"

if [ -z "$GOOS" ] || [ -z "$GOARCH" ] || [ -z "$VERSION" ] || [ -z "$OUT_PATH" ]; then
    echo "用法: $0 <GOOS> <GOARCH> <GOARM|GOMIPS> <version> <output_path>" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

mkdir -p "$(dirname "${OUT_PATH}")"

export CGO_ENABLED=0
export GOOS
export GOARCH

# mipsle/mips 用 GOMIPS，arm 用 GOARM
case "$GOARCH" in
    mips|mipsle)
        [ -n "$GOEXTRA" ] && export GOMIPS="$GOEXTRA"
        ;;
    arm)
        [ -n "$GOEXTRA" ] && export GOARM="$GOEXTRA"
        ;;
esac

echo ">>> Building nexa for GOOS=${GOOS} GOARCH=${GOARCH} ${GOEXTRA:+(${GOEXTRA})}"

cd "${REPO_ROOT}"
go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${OUT_PATH}" ./cmd/nexa

chmod 755 "${OUT_PATH}"
echo ">>> Built: ${OUT_PATH}"
file "${OUT_PATH}" || true
