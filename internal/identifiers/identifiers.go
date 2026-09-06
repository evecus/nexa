// Package identifiers 读取系统 user/group/cgroup 列表，对齐原 include.uc 的 get_users/get_groups/get_cgroups。
package identifiers

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type Identifiers struct {
	Users      []string `json:"users"`
	Groups     []string `json:"groups"`
	Cgroups    []string `json:"cgroups"`
	OSType     string   `json:"os_type"` // "openwrt" 或 "linux"
}

// Get 收集系统标识符。
func Get() *Identifiers {
	osType := detectOSType()
	return &Identifiers{
		Users:   getUsers(),
		Groups:  getGroups(),
		Cgroups: getCgroups(),
		OSType:  osType,
	}
}

// detectOSType 检测系统类型：OpenWrt 或普通 Linux。
// 判定依据：/etc/openwrt_release 存在即为 OpenWrt。
func detectOSType() string {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return "openwrt"
	}
	return "linux"
}

func getUsers() []string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ':'); i > 0 {
			out = append(out, line[:i])
		}
	}
	return out
}

func getGroups() []string {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ':'); i > 0 {
			out = append(out, line[:i])
		}
	}
	return out
}

// getCgroups 对齐 include.uc：cgroup v2 时遍历 /sys/fs/cgroup 子目录，排除 services/proxy。
func getCgroups() []string {
	if !isCgroupV2() {
		return nil
	}
	const root = "/sys/fs/cgroup/"
	var out []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(path, root)
		if rel == "" {
			return nil
		}
		if rel == "services/proxy" {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	return out
}

// isCgroupV2 对齐 include.uc get_cgroups_version()：mount 输出含 "^cgroup" 视为 v1，否则 v2。
func isCgroupV2() bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return true
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 && fields[2] == "cgroup" {
			return false
		}
	}
	return true
}
