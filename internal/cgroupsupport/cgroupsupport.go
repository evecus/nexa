// Package cgroupsupport 检测当前系统对 cgroup 防回环机制的支持程度。
// 之所以独立成包：config / core / netmanager 都需要在各自阶段读取这个判断结果
// （config 用于计算默认值，core 用于决定是否真的把核心进程放入 cgroup，
// netmanager 用于决定是否下发 cgroup 匹配规则），而这三者之间不能互相 import，
// 用一个只依赖标准库的独立包可以避免循环依赖。
package cgroupsupport

import (
	"bufio"
	"os"
	"strings"
)

// Version 表示系统支持的 cgroup 版本：0 表示都不支持，1 表示 v1（net_cls），2 表示 v2。
type Version int

const (
	None Version = 0
	V1   Version = 1
	V2   Version = 2
)

// Detect 检测当前系统实际可用的 cgroup 版本。
// 判定标准（对齐 core.go placeIntoCgroup 实际使用的路径，保证「检测到支持」和
// 「用得了」是同一套标准，不会出现检测通过但挂载失败的情况）：
//   - v2：/proc/mounts 中存在 type 为 cgroup2 的挂载，且 /sys/fs/cgroup 可写
//     （cgroup.procs 文件存在于挂载根，具备创建子目录能力）。
//   - v1：/proc/mounts 中存在 type 为 cgroup 且挂载选项包含 net_cls 的条目，
//     且该挂载点可写（net_cls.classid 可写才能真正生效）。
//   - 都不满足则返回 None。
func Detect() Version {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return None
	}
	defer f.Close()

	var v1Path, v2Path string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		mountPoint, fsType, opts := fields[1], fields[2], fields[3]
		switch fsType {
		case "cgroup2":
			if v2Path == "" {
				v2Path = mountPoint
			}
		case "cgroup":
			if strings.Contains(opts, "net_cls") && v1Path == "" {
				v1Path = mountPoint
			}
		}
	}

	// 优先 v2（现代系统主流），其次 v1；两者都要求挂载点实际可写才算真支持。
	if v2Path != "" && writable(v2Path) {
		return V2
	}
	if v1Path != "" && writable(v1Path) {
		return V1
	}
	return None
}

// Supported 是 Detect() != None 的简写，语义更直观：系统是否支持 cgroup 防回环。
func Supported() bool {
	return Detect() != None
}

// writable 粗略判断目录是否可写（尝试创建并立即删除一个探测子目录）。
// 用真实的 mkdir 探测而非仅看权限位，因为容器环境里权限位正常但内核会拒绝写入的情况并不少见。
func writable(dir string) bool {
	probe := dir + "/.nexa_cgroup_probe"
	if err := os.Mkdir(probe, 0755); err != nil {
		return false
	}
	_ = os.Remove(probe)
	return true
}
