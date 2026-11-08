// Package hosts 收集局域网主机列表（IP/IPv6/MAC），对齐原 momo include.uc 的 get_host_hints。
//
// 数据来源：
//  1. DHCP 租约文件（OpenWrt: /tmp/dhcp.leases；通用 Linux: /var/lib/misc/dnsmasq.leases）
//  2. ARP / 邻居表（ip neigh、ip -6 neigh）
//
// 合并去重后返回结构化数据，供前端「局域网代理」访问控制字段下拉选项使用。
package hosts

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Host 表示一台局域网主机。
type Host struct {
	IP    string `json:"ip"`
	IP6   string `json:"ip6"`
	MAC   string `json:"mac"`
	Name  string `json:"name"`
}

// Hosts 是 /api/hosts 返回的结构。
type Hosts struct {
	IP   []string `json:"ip"`
	IP6  []string `json:"ip6"`
	MAC  []string `json:"mac"`
	List []Host   `json:"list"`
}

// dhcpLeaseFiles 是常见的 DHCP 租约文件路径。
var dhcpLeaseFiles = []string{
	"/tmp/dhcp.leases",            // OpenWrt dnsmasq
	"/var/lib/misc/dnsmasq.leases", // Debian/Ubuntu dnsmasq
	"/var/db/dhcpd.leases",         // ISC dhcpd
}

// leaseFileCols 是 dnsmasq 租约文件每行的字段数（兼容不同版本）。
// OpenWrt: MAC IP HOSTNAME CLIENTID
// dnsmasq: TIMESTAMP MAC IP HOSTNAME CLIENTID
// dhcpd:   TIMESTAMP MAC IP HOSTNAME CLIENTID_TERMINAL

// Get 收集局域网主机信息。
func Get() *Hosts {
	h := &Hosts{IP: []string{}, IP6: []string{}, MAC: []string{}, List: []Host{}}
	// byMAC 持有独立分配的 Host 指针，避免 append 扩容导致地址失效。
	byMAC := map[string]*Host{}
	// 无 MAC 的记录（罕见，如 ip neigh 中无 lladdr 的条目）单独存放。
	var noMAC []Host

	add := func(mac, ip, name string) {
		if mac == "" && ip == "" {
			return
		}
		if mac != "" {
			if e, ok := byMAC[mac]; ok {
				if ip != "" {
					if isIPv4(ip) && e.IP == "" {
						e.IP = ip
					} else if isIPv6(ip) && e.IP6 == "" {
						e.IP6 = ip
					}
				}
				if name != "" && e.Name == "" {
					e.Name = name
				}
				return
			}
			e := &Host{MAC: mac, Name: name}
			if ip != "" {
				if isIPv4(ip) {
					e.IP = ip
				} else if isIPv6(ip) {
					e.IP6 = ip
				}
			}
			byMAC[mac] = e
			return
		}
		// 无 MAC
		e := Host{IP: ip, Name: name}
		if isIPv6(ip) {
			e.IP = ""
			e.IP6 = ip
		}
		noMAC = append(noMAC, e)
	}

	// 1. DHCP 租约
	for _, p := range dhcpLeaseFiles {
		readLeaseFile(p, add)
	}
	// 2. ARP / 邻居表（IPv4）
	readNeigh(true, add)
	// 3. 邻居表（IPv6）
	readNeigh(false, add)

	// 合并到 List
	for _, e := range byMAC {
		h.List = append(h.List, *e)
	}
	h.List = append(h.List, noMAC...)

	// 汇总 IP/IP6/MAC 列表（去重）
	seenIP := map[string]bool{}
	seenIP6 := map[string]bool{}
	seenMAC := map[string]bool{}
	for i := range h.List {
		e := &h.List[i]
		if e.IP != "" && !seenIP[e.IP] && isIPv4(e.IP) {
			seenIP[e.IP] = true
			h.IP = append(h.IP, e.IP)
		}
		if e.IP6 != "" && !seenIP6[e.IP6] && isIPv6(e.IP6) {
			seenIP6[e.IP6] = true
			h.IP6 = append(h.IP6, e.IP6)
		}
		if e.MAC != "" && !seenMAC[e.MAC] {
			seenMAC[e.MAC] = true
			h.MAC = append(h.MAC, e.MAC)
		}
	}
	return h
}

// addFn 是向集合追加一条主机记录的回调类型。
type addFn func(mac, ip, name string)

// readLeaseFile 解析 DHCP 租约文件。
// 兼容 OpenWrt /tmp/dhcp.leases 与 dnsmasq /var/lib/misc/dnsmasq.leases 两种格式。
func readLeaseFile(path string, add addFn) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// 找到 MAC 字段：形如 aa:bb:cc:dd:ee:ff
		var mac, ip, name string
		for _, fld := range fields {
			// 第一个像 MAC 的字段
			if isMAC(fld) && mac == "" {
				mac = fld
				continue
			}
		}
		// IP 字段
		for _, fld := range fields {
			if mac != "" && fld != mac && isIP(fld) {
				ip = fld
				break
			}
		}
		// hostname（含 MAC 和 IP 后的下一个非空非 IP 字段）
		for _, fld := range fields {
			if fld == mac || fld == ip || fld == "*" || isIP(fld) || isUnixTimestamp(fld) {
				continue
			}
			if name == "" {
				name = fld
			}
		}
		if mac == "" && ip == "" {
			continue
		}
		add(mac, ip, name)
	}
}

// readNeigh 执行 ip neigh 或 ip -6 neigh 解析邻居表。
func readNeigh(v4 bool, add addFn) {
	var cmd *exec.Cmd
	if v4 {
		cmd = exec.Command("ip", "neigh")
	} else {
		cmd = exec.Command("ip", "-6", "neigh")
	}
	out, err := cmd.Output()
	if err != nil {
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// 格式：<IP> dev <DEV> lladdr <MAC> [REACHABLE|STALE|DELAY|...]
		// 或 ：<IP> dev <DEV> [FAILED|INCOMPLETE]
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if ip == "" || !isIP(ip) {
			continue
		}
		// 跳过本地链路地址和本机地址
		if isLinkLocal(ip) {
			continue
		}
		var mac string
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "lladdr" && isMAC(fields[i+1]) {
				mac = fields[i+1]
				break
			}
		}
		if mac == "" {
			continue
		}
		add(mac, ip, "")
	}
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func isIPv6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isMAC(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}

// isLinkLocal 判断 IPv6 链路本地地址（fe80::/10）或 IPv4 APIPA（169.254.0.0/16）。
func isLinkLocal(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}
	return ip[0] == 0xfe && (ip[1]&0xc0) == 0x80
}

// isUnixTimestamp 判断字符串是否为纯数字时间戳（dnsmasq 行首字段）。
func isUnixTimestamp(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
