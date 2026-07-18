#!/bin/bash
# build_ipk.sh - 把已编译好的 nexa 二进制 + LuCI 界面打包成单个 luci-app-nexa IPK
#
# 用法:
#   build_ipk.sh <binary_path> <opkg_arch> <version> <output_dir>
#
# 示例:
#   build_ipk.sh dist/nexa-linux-arm64 aarch64_generic 1.0.0-r1 /tmp/out
set -e

BINARY_PATH="$1"
OPKG_ARCH="$2"
VERSION="$3"
OUT_DIR="$4"

if [ -z "$BINARY_PATH" ] || [ -z "$OPKG_ARCH" ] || [ -z "$VERSION" ] || [ -z "$OUT_DIR" ]; then
    echo "用法: $0 <binary_path> <opkg_arch> <version> <output_dir>" >&2
    exit 1
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "错误: 二进制文件不存在: $BINARY_PATH" >&2
    exit 1
fi

# 提前把可能是相对路径的入参转换为绝对路径，避免后面 cd 到临时目录后失效
BINARY_PATH="$(cd "$(dirname "$BINARY_PATH")" && pwd)/$(basename "$BINARY_PATH")"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATES_DIR="${SCRIPT_DIR}/../templates"
BUILD_DIR="$(mktemp -d)"
PKG_DATA="${BUILD_DIR}/data"
PKG_CTRL="${BUILD_DIR}/ctrl"

mkdir -p "${PKG_DATA}/usr/bin"
mkdir -p "${PKG_DATA}/etc/config"
mkdir -p "${PKG_DATA}/etc/init.d"
mkdir -p "${PKG_DATA}/etc/uci-defaults"
mkdir -p "${PKG_DATA}/usr/share/luci/menu.d"
mkdir -p "${PKG_DATA}/usr/share/rpcd/acl.d"
mkdir -p "${PKG_DATA}/usr/share/rpcd/ucode"
mkdir -p "${PKG_DATA}/www/luci-static/resources/view/nexa"
mkdir -p "${PKG_CTRL}"

echo ">>> Building luci-app-nexa ${VERSION} (${OPKG_ARCH})"

# ── 二进制 ────────────────────────────────────────────────
cp "${BINARY_PATH}" "${PKG_DATA}/usr/bin/nexa"
chmod 755 "${PKG_DATA}/usr/bin/nexa"

# ── 静态文件（无需变量替换）────────────────────────────────
cp "${TEMPLATES_DIR}/config"        "${PKG_DATA}/etc/config/nexa"
cp "${TEMPLATES_DIR}/init.d.sh"     "${PKG_DATA}/etc/init.d/nexa"
cp "${TEMPLATES_DIR}/uci-defaults.sh" "${PKG_DATA}/etc/uci-defaults/luci-app-nexa"
cp "${TEMPLATES_DIR}/menu.json"     "${PKG_DATA}/usr/share/luci/menu.d/luci-app-nexa.json"
cp "${TEMPLATES_DIR}/acl.json"      "${PKG_DATA}/usr/share/rpcd/acl.d/luci-app-nexa.json"
cp "${TEMPLATES_DIR}/ucode.uc"      "${PKG_DATA}/usr/share/rpcd/ucode/luci.nexa"
cp "${TEMPLATES_DIR}/main.js"       "${PKG_DATA}/www/luci-static/resources/view/nexa/main.js"
cp "${TEMPLATES_DIR}/log.js"        "${PKG_DATA}/www/luci-static/resources/view/nexa/log.js"

# ── 权限 ──────────────────────────────────────────────────
find "${PKG_DATA}" -type f | xargs chmod 644
find "${PKG_DATA}" -type d | xargs chmod 755
chmod 755 \
    "${PKG_DATA}/usr/bin/nexa" \
    "${PKG_DATA}/etc/init.d/nexa" \
    "${PKG_DATA}/etc/uci-defaults/luci-app-nexa" \
    "${PKG_DATA}/usr/share/rpcd/ucode/luci.nexa"

# ── control（替换版本/架构/体积）───────────────────────────
INSTALLED_SIZE=$(du -sk "${PKG_DATA}" | awk '{print $1}')
sed \
    -e "s/{{VERSION}}/${VERSION}/g" \
    -e "s/{{ARCH}}/${OPKG_ARCH}/g" \
    -e "s/{{INSTALLED_SIZE}}/${INSTALLED_SIZE}/g" \
    "${TEMPLATES_DIR}/control" > "${PKG_CTRL}/control"

cp "${TEMPLATES_DIR}/postinst.sh" "${PKG_CTRL}/postinst"
cp "${TEMPLATES_DIR}/prerm.sh"    "${PKG_CTRL}/prerm"
chmod 755 "${PKG_CTRL}/postinst" "${PKG_CTRL}/prerm"

# ── 打包 IPK ──────────────────────────────────────────────
cd "${PKG_DATA}"
tar czf "${BUILD_DIR}/data.tar.gz" ./ --owner=0 --group=0

cd "${PKG_CTRL}"
tar czf "${BUILD_DIR}/control.tar.gz" ./ --owner=0 --group=0

echo "2.0" > "${BUILD_DIR}/debian-binary"

IPK_NAME="luci-app-nexa_${VERSION}_${OPKG_ARCH}.ipk"
cd "${BUILD_DIR}"
tar czf "${OUT_DIR}/${IPK_NAME}" \
    ./debian-binary ./control.tar.gz ./data.tar.gz

rm -rf "${BUILD_DIR}"

echo ">>> Built: ${OUT_DIR}/${IPK_NAME}"
echo "ipk_name=${IPK_NAME}"
