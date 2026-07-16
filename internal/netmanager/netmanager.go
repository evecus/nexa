// Package netmanager 复刻 proxy.init 的网络/防火墙配置逻辑：
// cgroup / bridge-nf / TUN 等待 / ip route+rule / fake-ip6 dummy / nft 应用 / firewall_include / cleanup。
// 全部通过 shell out 调 ip/nft/sysctl/mount，1:1 对齐原 shell 行为。
package netmanager

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/nexa-proxy/nexa/internal/config"
	"github.com/nexa-proxy/nexa/internal/logger"
	"github.com/nexa-proxy/nexa/internal/nfttemplate"
	"github.com/nexa-proxy/nexa/internal/paths"
)

type Manager struct {
	log *logger.Logger
}

func New(log *logger.Logger) *Manager {
	return &Manager{log: log}
}

// Apply 对齐 proxy.init start_service 第 146-241 行（proxy.enabled=1 时的网络配置）。
func (m *Manager) Apply(cfg *config.Config) error {
	p := &cfg.Proxy
	if !p.Enabled {
		m.log.App("代理", "已禁用，跳过防火墙设置。")
		return nil
	}
	m.log.App("代理", "已启用，配置防火墙规则。")

	tproxyEnable := p.TcpMode == "tproxy" || p.UdpMode == "tproxy"
	tunEnable := p.TcpMode == "tun" || p.UdpMode == "tun"

	// cgroupv1 兼容（对齐 proxy.init:163-167）
	if cgroupsVersion() == 1 {
		cgPath := "/sys/fs/cgroup/net_cls/" + cfg.Routing.CgroupName
		_ = os.MkdirAll(cgPath, 0755)
		_ = os.WriteFile(cgPath+"/net_cls.classid", []byte(cfg.Routing.CgroupID), 0644)
		if data, err := os.ReadFile(paths.PidFilePath); err == nil {
			_ = os.WriteFile(cgPath+"/cgroup.procs", data, 0644)
		}
	}

	// bridge-nf-call 兼容（对齐 proxy.init:170-185）
	if tproxyEnable && isModuleLoaded("br_netfilter") {
		if p.IPv4Proxy {
			if sysctlGet("net.bridge.bridge-nf-call-iptables") == "1" {
				_ = os.WriteFile(paths.BridgeNfCallIptablesFlag, nil, 0644)
				sysctlSet("net.bridge.bridge-nf-call-iptables", "0")
			}
		}
		if p.IPv6Proxy {
			if sysctlGet("net.bridge.bridge-nf-call-ip6tables") == "1" {
				_ = os.WriteFile(paths.BridgeNfCallIp6tablesFlag, nil, 0644)
				sysctlSet("net.bridge.bridge-nf-call-ip6tables", "0")
			}
		}
	}

	// TUN 设备等待（对齐 proxy.init:188-203）
	if tunEnable && p.TunDevice != "" {
		m.log.App("代理", fmt.Sprintf("等待 TUN 设备上线，超时 %d 秒...", p.TunTimeout))
		if !waitForTUN(p.TunDevice, p.TunTimeout, p.TunInterval) {
			m.log.App("代理", "超时，TUN 设备未上线，退出。")
			return fmt.Errorf("tun device %s not up", p.TunDevice)
		}
		m.log.App("代理", "TUN 设备已上线。")
	}

	// ip route / rule（对齐 proxy.init:206-226）
	r := &cfg.Routing
	if tproxyEnable {
		if p.IPv4Proxy {
			run("ip", "-4", "route", "add", "local", "default", "dev", "lo", "table", r.TproxyRouteTable)
			run("ip", "-4", "rule", "add", "pref", fmt.Sprint(r.TproxyRulePref), "fwmark", r.TproxyFwMark+"/"+r.TproxyFwMask, "table", r.TproxyRouteTable)
		}
		if p.IPv6Proxy {
			run("ip", "-6", "route", "add", "local", "default", "dev", "lo", "table", r.TproxyRouteTable)
			run("ip", "-6", "rule", "add", "pref", fmt.Sprint(r.TproxyRulePref), "fwmark", r.TproxyFwMark+"/"+r.TproxyFwMask, "table", r.TproxyRouteTable)
		}
	}
	if tunEnable && p.TunDevice != "" {
		if p.IPv4Proxy {
			run("ip", "-4", "route", "add", "unicast", "default", "dev", p.TunDevice, "table", r.TunRouteTable)
			run("ip", "-4", "rule", "add", "pref", fmt.Sprint(r.TunRulePref), "fwmark", r.TunFwMark+"/"+r.TunFwMask, "table", r.TunRouteTable)
		}
		if p.IPv6Proxy {
			run("ip", "-6", "route", "add", "unicast", "default", "dev", p.TunDevice, "table", r.TunRouteTable)
			run("ip", "-6", "rule", "add", "pref", fmt.Sprint(r.TunRulePref), "fwmark", r.TunFwMark+"/"+r.TunFwMask, "table", r.TunRouteTable)
		}
		m.FirewallInclude(cfg)
	}

	// fake-ip6 dummy（对齐 proxy.init:229-233）
	if p.FakeIP6Range != "" {
		run("ip", "link", "add", r.DummyDevice, "type", "dummy")
		run("ip", "link", "set", "dev", r.DummyDevice, "up")
		run("ip", "-6", "route", "add", p.FakeIP6Range, "dev", r.DummyDevice)
	}

	// nft 劫持规则（对齐 proxy.init:236-241）
	lanDevs := resolveLanDevices(p.LanInboundInterface)
	model := nfttemplate.Build(cfg, lanDevs, cgroupsVersion())
	// bypass 大陆 IP 时，从 geoip 文件提取 elements 注入 proxy table 集合。
	// 原 geoip 文件 table 名为 momo，与 proxy table 不匹配，此处直接注入 elements 修正。
	if p.BypassChinaMainlandIP {
		if els, err := extractGeoIPElements(paths.GeoIPCnNft); err == nil {
			model.ChinaIPElements = els
		} else {
			m.log.App("代理", "读取 geoip_cn.nft 失败："+err.Error())
		}
	}
	if p.BypassChinaMainlandIP6 {
		if els, err := extractGeoIPElements(paths.GeoIP6CnNft); err == nil {
			model.ChinaIP6Elements = els
		} else {
			m.log.App("代理", "读取 geoip6_cn.nft 失败："+err.Error())
		}
	}
	ruleset, err := nfttemplate.Render(model)
	if err != nil {
		m.log.App("代理", "nft 模板渲染失败："+err.Error())
		return err
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if err := cmd.Run(); err != nil {
		m.log.App("代理", "流量劫持失败。")
		return err
	}
	// 校验表是否存在
	if out, _ := exec.Command("nft", "list", "tables").Output(); strings.Contains(string(out), "inet proxy") {
		m.log.App("代理", "流量劫持成功。")
	} else {
		m.log.App("代理", "流量劫持失败。")
	}
	return nil
}

// FirewallInclude 对齐 firewall_include.sh：TUN 模式时往 fw4 input/forward 插 accept 规则。
func (m *Manager) FirewallInclude(cfg *config.Config) {
	p := &cfg.Proxy
	if !cfg.Config.Enabled || !p.Enabled {
		return
	}
	if p.TcpMode != "tun" && p.UdpMode != "tun" {
		return
	}
	if p.TunDevice == "" {
		return
	}
	run("nft", "insert", "rule", "inet", "fw4", "input", "iifname", p.TunDevice, "counter", "accept", "comment", "nexa")
	run("nft", "insert", "rule", "inet", "fw4", "forward", "oifname", p.TunDevice, "counter", "accept", "comment", "nexa")
	run("nft", "insert", "rule", "inet", "fw4", "forward", "iifname", p.TunDevice, "counter", "accept", "comment", "nexa")
}

// Cleanup 对齐 proxy.init cleanup()：删 rule/route/dummy、删 nft 表、删 fw4 中 comment=nexa 的规则、恢复 bridge-nf。
func (m *Manager) Cleanup(cfg *config.Config) {
	r := &cfg.Routing

	// 删 ip rule/route（忽略错误）
	for _, args := range [][]string{
		{"-4", "rule", "del", "table", r.TproxyRouteTable},
		{"-4", "rule", "del", "table", r.TunRouteTable},
		{"-6", "rule", "del", "table", r.TproxyRouteTable},
		{"-6", "rule", "del", "table", r.TunRouteTable},
		{"-4", "route", "flush", "table", r.TproxyRouteTable},
		{"-4", "route", "flush", "table", r.TunRouteTable},
		{"-6", "route", "flush", "table", r.TproxyRouteTable},
		{"-6", "route", "flush", "table", r.TunRouteTable},
	} {
		runIgnore("ip", args...)
	}
	runIgnore("ip", "link", "del", r.DummyDevice)

	// 删 nft 表
	runIgnore("nft", "delete", "table", "inet", "proxy")

	// 删 fw4 中 comment=nexa 的规则（对齐原 comment=proxy）
	deleteFw4RulesByComment("input")
	deleteFw4RulesByComment("forward")

	// 恢复 bridge-nf-call（仅当标志文件存在）
	if _, err := os.Stat(paths.BridgeNfCallIptablesFlag); err == nil {
		os.Remove(paths.BridgeNfCallIptablesFlag)
		sysctlSet("net.bridge.bridge-nf-call-iptables", "1")
	}
	if _, err := os.Stat(paths.BridgeNfCallIp6tablesFlag); err == nil {
		os.Remove(paths.BridgeNfCallIp6tablesFlag)
		sysctlSet("net.bridge.bridge-nf-call-ip6tables", "1")
	}
}

// deleteFw4RulesByComment 删除 inet fw4 <chain> 中 comment=nexa 的规则。
func deleteFw4RulesByComment(chain string) {
	out, err := exec.Command("nft", "-j", "list", "table", "inet", "fw4").Output()
	if err != nil {
		return
	}
	// 简化：用 nft 原生 delete by handle 需要 json 解析，这里用正则太脆弱。
	// 直接遍历 rule 的 handle：nft 不支持按 comment 删除，必须先 list 拿 handle。
	handles := extractHandlesForComment(out, chain, "nexa")
	for _, h := range handles {
		runIgnore("nft", "delete", "rule", "inet", "fw4", chain, "handle", fmt.Sprint(h))
	}
}

// extractHandlesForComment 从 nft -j 输出里提取指定 chain 中 comment 匹配的 rule handle。
func extractHandlesForComment(jsonOut []byte, chain, comment string) []uint64 {
	// 极简解析：逐行扫描 json 太复杂，退而用 nft 非 json + 文本匹配会更稳。
	// 这里用文本模式重新查询以保证可靠。
	out, err := exec.Command("nft", "list", "table", "inet", "fw4").Output()
	if err != nil {
		return nil
	}
	var handles []uint64
	inChain := false
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "chain "+chain+" {") {
			inChain = true
			continue
		}
		if inChain && trimmed == "}" {
			inChain = false
			continue
		}
		if inChain && strings.Contains(trimmed, "comment \""+comment+"\"") {
			// 行形如: ... counter accept comment "nexa" # handle 42
			if i := strings.LastIndex(trimmed, "handle "); i >= 0 {
				hStr := strings.TrimSpace(trimmed[i+len("handle "):])
				var h uint64
				fmt.Sscanf(hStr, "%d", &h)
				if h > 0 {
					handles = append(handles, h)
				}
			}
		}
	}
	return handles
}

// ── helpers ──────────────────────────────────────────────

// cgroupsVersion 对齐 include.uc get_cgroups_version()：mount 含 type cgroup → v1，否则 v2。
func cgroupsVersion() int {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return 2
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 && fields[2] == "cgroup" {
			return 1
		}
	}
	return 2
}

func isModuleLoaded(name string) bool {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), name+" ") {
			return true
		}
	}
	return false
}

func sysctlGet(key string) string {
	out, _ := exec.Command("sysctl", "-e", "-n", key).Output()
	return strings.TrimSpace(string(out))
}

func sysctlSet(key, val string) {
	_ = exec.Command("sysctl", "-q", "-w", key+"="+val).Run()
}

// waitForTUN 轮询 ip link show，等设备 UP。对齐 proxy.init:191-202。
func waitForTUN(dev string, timeout, interval int) bool {
	if interval <= 0 {
		interval = 1
	}
	for t := timeout; t > 0; t -= interval {
		out, err := exec.Command("ip", "-j", "link", "show", "dev", dev).Output()
		if err == nil && strings.Contains(string(out), `"UP"`) {
			return true
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
	return false
}

// resolveLanDevices 把 interface 名解析为 device 名。脱离 ubus：
// 优先 /sys/class/net/<name>；不存在则尝试 br-<name>。
func resolveLanDevices(interfaces []string) []string {
	var out []string
	for _, iface := range interfaces {
		if iface == "" {
			continue
		}
		if dirExists("/sys/class/net/" + iface) {
			out = append(out, iface)
			continue
		}
		br := "br-" + iface
		if dirExists("/sys/class/net/" + br) {
			out = append(out, br)
		}
	}
	return out
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func run(name string, args ...string) {
	_ = exec.Command(name, args...).Run()
}

func runIgnore(name string, args ...string) {
	_ = exec.Command(name, args...).Run()
}

// geoipElementsRe 匹配 nft 文件中的 `elements = { ... }` 块。
var geoipElementsRe = regexp.MustCompile(`(?s)elements\s*=\s*\{([^}]*)\}`)

// extractGeoIPElements 从 geoip_cn.nft / geoip6_cn.nft 文件中提取 elements 列表内容。
// 文件格式形如：
//
//	table inet momo {
//		set china_ip {
//			...
//			elements = {
//				1.0.1.0/24,
//				...
//			}
//		}
//	}
//
// 提取出 "1.0.1.0/24, ..." 这段文本，供模板注入到 proxy table 的集合定义。
func extractGeoIPElements(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	m := geoipElementsRe.FindSubmatch(data)
	if m == nil {
		return "", fmt.Errorf("geoip 文件 %s 未找到 elements 块", path)
	}
	// 去掉首尾空白和多余换行，保留逗号分隔的地址列表
	return strings.TrimSpace(string(m[1])), nil
}
