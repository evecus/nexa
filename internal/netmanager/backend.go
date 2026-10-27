package netmanager

import (
	"os/exec"
	"strings"
)

// Backend 表示当前系统实际使用的防火墙后端。
type Backend int

const (
	BackendNftables Backend = iota
	BackendIptables
)

func (b Backend) String() string {
	if b == BackendNftables {
		return "nftables"
	}
	return "iptables"
}

// detectBackend 检测系统当前使用的防火墙后端：
//  1. 若 nft 命令存在，且 fw4（OpenWrt 的 nftables 防火墙）已安装并处于运行状态
//     （即 nft 中已存在 inet fw4 表，或 fw4 服务正在运行），优先使用 nftables。
//  2. 否则回退到 iptables（需要 iptables/ip6tables 命令可用）。
//
// 只在没有检测到 fw4 正在运行时才考虑回退，避免在同时装了 iptables-legacy
// 兼容层的 OpenWrt 系统上误判为 iptables。
func detectBackend() Backend {
	if hasCommand("nft") && fw4Running() {
		return BackendNftables
	}
	if hasCommand("iptables") {
		return BackendIptables
	}
	// 都不可用时，仍返回 nftables 作为默认值（沿用原行为，Apply 会在调用 nft 时报错并记录日志）。
	return BackendNftables
}

// fw4Running 判断 fw4（OpenWrt nftables 防火墙）是否已安装且正在运行：
//   - fw4 表已存在于 nft ruleset 中，说明 fw4 已经初始化过防火墙；或
//   - fw4 可执行文件存在，且 /etc/init.d/firewall 服务正在运行（running）。
func fw4Running() bool {
	if !hasCommand("nft") {
		return false
	}
	if out, err := exec.Command("nft", "list", "table", "inet", "fw4").CombinedOutput(); err == nil && len(out) > 0 {
		return true
	}
	// fw4 二进制存在且 firewall 服务处于 running 状态（OpenWrt init 脚本约定）。
	if hasCommand("fw4") {
		if out, err := exec.Command("/etc/init.d/firewall", "status").CombinedOutput(); err == nil {
			if strings.Contains(strings.ToLower(string(out)), "running") {
				return true
			}
		}
	}
	return false
}

func hasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
