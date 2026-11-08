// Package systemuser 管理 nexa 代理核心的运行用户。
package systemuser

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

const UserName = "nexa"

// EnsureUser 确保 nexa 系统用户存在，不存在则创建。
// 返回该用户的 UID。
func EnsureUser() (uint32, error) {
	// 先检查用户是否已存在
	if u, err := user.Lookup(UserName); err == nil {
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("解析 UID 失败：%w", err)
		}
		return uint32(uid), nil
	}

	// 用户不存在，尝试创建
	if err := createUser(); err != nil {
		return 0, fmt.Errorf("创建用户 %s 失败：%w", UserName, err)
	}

	// 再次查找
	u, err := user.Lookup(UserName)
	if err != nil {
		return 0, fmt.Errorf("创建用户后查找失败：%w", err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("解析 UID 失败：%w", err)
	}
	return uint32(uid), nil
}

// createUser 创建 nexa 系统用户，按系统类型选择不同方式。
func createUser() error {
	// 方式1：useradd（大多数 Linux 发行版）
	if _, err := exec.LookPath("useradd"); err == nil {
		return run("useradd", "-r", "-s", "/usr/sbin/nologin", "-M", UserName)
	}

	// 方式2：adduser（Debian/BusyBox）
	if _, err := exec.LookPath("adduser"); err == nil {
		// BusyBox adduser 语法和 Debian 不同，尝试 BusyBox 风格
		err := run("adduser", "-D", "-s", "/usr/sbin/nologin", "-H", UserName)
		if err != nil {
			// Debian 风格
			return run("adduser", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", UserName)
		}
		return nil
	}

	// 方式3：OpenWrt - 通过 opkg 安装 shadow 然后用 useradd
	if isOpenWrt() {
		_ = run("opkg", "update")
		_ = run("opkg", "install", "shadow-useradd")
		if _, err := exec.LookPath("useradd"); err == nil {
			return run("useradd", "-r", "-s", "/usr/sbin/nologin", UserName)
		}
	}

	return fmt.Errorf("未找到 useradd 或 adduser 命令，请手动创建用户：%s", UserName)
}

// LookupUID 查找 nexa 用户的 UID，不存在返回 0。
func LookupUID() uint32 {
	u, err := user.Lookup(UserName)
	if err != nil {
		return 0
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(uid)
}

// isOpenWrt 检测是否为 OpenWrt 系统。
func isOpenWrt() bool {
	return exec.Command("test", "-f", "/etc/openwrt_release").Run() == nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s (%w)", name, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}
