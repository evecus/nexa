// iptables.go 提供在没有可用 nftables(fw4) 时的回退实现，
// 使用 iptables / ip6tables（+ ipset）尽量 1:1 对齐 nfttemplate 中 hijack.ut 的行为：
// DNS 劫持、TCP 透明代理（REDIRECT/TPROXY）、TUN 放行、
// 用户/组/MAC/IP/cgroup 访问控制、DSCP/fwmark/cgroup/gid 绕过、
// 保留地址段/fake-ip 排除、中国大陆 IP 绕过、fake-ip ping 劫持等。
//
// 与 nftables(fw4) 版本相比，以下几点是 iptables 架构本身的限制，无法做到 1:1：
//   - 本机（router）流量的透明代理（tproxy 模式）：Linux 内核的 TPROXY target 只能挂在
//     PREROUTING 链上（转发流量），本机自身发出的流量走的是 OUTPUT 链，OUTPUT 上不支持 TPROXY。
//     iptables 版本对本机流量改用「打 fwmark + 复用 Apply() 中已建立的 ip rule/route 策略路由」
//     来间接实现相同效果（这也是原版 nft 模板本身对 router tproxy 采用的思路：mark + policy route），
//     语义上是等价的，只是不经过内核 TPROXY 钩子，纯靠策略路由转发到本地监听端口。
//   - cgroup 防回环：会先探测系统是否真的支持 cgroup（v1 net_cls 或 v2 且挂载点可写），
//     不支持时自动完全跳过 cgroup 规则，改用 GID 绕过（--gid-owner）兜底 —— GID 绕过是
//     nexa 唯一能自己保证生效的防回环手段（核心进程主 GID 由程序自己创建/设置），
//     不依赖任何内核 cgroup 特性，因此在所有 Linux 系统上都可用。
package netmanager

import (
	"os/exec"
	"strconv"
	"strings"

	"github.com/nexa-proxy/nexa/internal/cgroupsupport"
	"github.com/nexa-proxy/nexa/internal/config"
	"github.com/nexa-proxy/nexa/internal/logger"
	"github.com/nexa-proxy/nexa/internal/paths"
)

const nexaComment = "nexa"

const (
	ipsetChinaV4 = "nexa_china_v4"
	ipsetChinaV6 = "nexa_china_v6"
)

// iptablesChains 记录一次 Apply 建立的所有自定义链名，方便 Cleanup 时对称删除。
var iptablesChains = []string{
	"NEXA_BYPASS_R",     // router 绕过判断（cgroup/gid/mark/reserved/china/dscp/fwmark），命中则 RETURN
	"NEXA_DNS_HIJACK_R", // router dns hijack
	"NEXA_REDIRECT_R",   // router tcp redirect
	"NEXA_TPROXY_R",     // router tproxy（用 MARK 近似）
	"NEXA_TUN_BYPASS_R", // router tun 模式下的绕过判断（同 NEXA_BYPASS_R，但作用于 mangle OUTPUT，供核心自身路由参考）
	"NEXA_BYPASS_L",     // lan 绕过判断
	"NEXA_DNS_HIJACK_L", // lan dns hijack
	"NEXA_REDIRECT_L",   // lan tcp redirect
	"NEXA_TPROXY_L",     // lan tproxy（真 TPROXY target）
}

func chainTable(chain string) string {
	switch chain {
	case "NEXA_TPROXY_R", "NEXA_TPROXY_L", "NEXA_TUN_BYPASS_R":
		return "mangle"
	default:
		return "nat"
	}
}

// applyIptables 是 Apply 在检测到 iptables 后端时的实现，对齐 Apply 中 nft 分支的语义
// （bridge-nf / TUN 等待 / ip route rule / fake-ip6 dummy 已在 Apply 中通用处理，
// 这里只负责“流量劫持”部分，即原来调用 nft -f 的那一段）。
func (m *Manager) applyIptables(cfg *config.Config, lanDevs []string) error {
	p := &cfg.Proxy
	r := &cfg.Routing
	m.log.App("代理", "检测到 iptables 防火墙，使用 iptables 应用流量劫持规则。")

	// 先清理旧规则，保证幂等。
	m.cleanupIptables(cfg)

	caps := newMatchSupportCache()

	tcpMode := p.TcpMode
	udpMode := p.UdpMode
	tproxyEnable := tcpMode == "tproxy" || udpMode == "tproxy"
	tunEnable := tcpMode == "tun" || udpMode == "tun"
	markDependent := tproxyEnable || tunEnable

	// ── 能力探测：提前判断 IPv4/IPv6 各自实际可用性 ──────────────────
	// 对齐 ShellCrash fw_iptables.sh 的写法：先探测内核/iptables 是否支持某个 target
	// 的关键参数（REDIRECT --to-ports、MARK --set-mark、TPROXY --on-port），
	// 缺失时直接放弃对应协议族的规则下发并记录日志，而不是下发一条必然失败的规则。
	redirectSupported6 := caps.supportsTarget("ip6tables", "REDIRECT", "--to-ports")
	if tcpMode == "redirect" && p.IPv6Proxy && !redirectSupported6 {
		m.log.App("代理", "当前设备内核缺少 ip6tables REDIRECT 模块的 --to-ports 支持，已放弃启动 IPv6 相关规则。")
	}
	if markDependent {
		_ = exec.Command("modprobe", "xt_MARK").Run() // MARK 在多数发行版是内建的，modprobe 失败不影响后续探测
	}
	markSupported4 := caps.supportsTarget("iptables", "MARK", "--set-mark")
	markSupported6 := caps.supportsTarget("ip6tables", "MARK", "--set-mark")
	if markDependent && p.IPv4Proxy && !markSupported4 {
		m.log.App("代理", "当前设备内核可能缺少 xt_MARK 模块支持，已放弃启动 IPv4 相关规则。")
	}
	if markDependent && p.IPv6Proxy && !markSupported6 {
		m.log.App("代理", "当前设备内核可能缺少 xt_MARK 模块支持，已放弃启动 IPv6 相关规则。")
	}

	// TPROXY target 能力探测（对齐 ShellCrash：`$iptable -j TPROXY -h | grep -q '\--on-port'`），
	// 内核缺少 xt_TPROXY / nft_tproxy 模块时局域网转发流量也无法用真正的 TPROXY，
	// 退化为和本机流量一致的 MARK + 策略路由方案，而不是直接下发一条必然失败的规则。
	if tproxyEnable {
		_ = exec.Command("modprobe", "xt_TPROXY").Run() // 尝试加载，失败也无所谓，下面会实际探测
		if p.IPv4Proxy && !caps.supportsTarget("iptables", "TPROXY", "--on-port") {
			m.log.App("代理", "当前设备内核可能缺少 xt_TPROXY 模块支持，局域网 tproxy 规则改用 MARK+策略路由近似实现。")
		}
		if p.IPv6Proxy && !caps.supportsTarget("ip6tables", "TPROXY", "--on-port") {
			m.log.App("代理", "当前设备内核可能缺少 ip6tables TPROXY 模块支持，局域网 tproxy(v6) 规则改用 MARK+策略路由近似实现。")
		}
	}
	lanTproxySupported4 := tproxyEnable && caps.supportsTarget("iptables", "TPROXY", "--on-port")
	lanTproxySupported6 := tproxyEnable && caps.supportsTarget("ip6tables", "TPROXY", "--on-port")

	// 有效 IPv4/IPv6 可用性：原始开关 AND 能力探测结果。下面全程只使用这两个局部变量，
	// 不回写 cfg.Proxy，避免探测结果污染调用方持有的配置对象（该 struct 可能被其他地方复用/保存）。
	ipv4Proxy := p.IPv4Proxy && (!markDependent || markSupported4)
	ipv6Proxy := p.IPv6Proxy && (tcpMode != "redirect" || redirectSupported6) && (!markDependent || markSupported6)
	ipv4DnsHijack := p.IPv4DnsHijack
	ipv6DnsHijack := p.IPv6DnsHijack

	ipt := newIptWriter(m.log, ipv4Proxy || ipv4DnsHijack)
	ip6t := newIp6tWriter(m.log, ipv6Proxy || ipv6DnsHijack)

	// 中国大陆 IP 绕过：用 ipset 承载地址集合（对齐 nft china_ip/china_ip6 命名集合）。
	var chinaV4Ready, chinaV6Ready bool
	if p.BypassChinaMainlandIP {
		if els, err := extractGeoIPElements(paths.GeoIPCnNft); err == nil {
			if err := loadIPSet(ipsetChinaV4, "hash:net", "inet", els); err == nil {
				chinaV4Ready = true
			} else {
				m.log.App("代理", "创建 ipset "+ipsetChinaV4+" 失败："+err.Error())
			}
		} else {
			m.log.App("代理", "读取 geoip_cn.nft 失败："+err.Error())
		}
	}
	if p.BypassChinaMainlandIP6 {
		if els, err := extractGeoIPElements(paths.GeoIP6CnNft); err == nil {
			if err := loadIPSet(ipsetChinaV6, "hash:net", "inet6", els); err == nil {
				chinaV6Ready = true
			} else {
				m.log.App("代理", "创建 ipset "+ipsetChinaV6+" 失败："+err.Error())
			}
		} else {
			m.log.App("代理", "读取 geoip6_cn.nft 失败："+err.Error())
		}
	}

	// 建自定义链
	for _, c := range iptablesChains {
		if ipv4Proxy || ipv4DnsHijack {
			ipt.run("-t", chainTable(c), "-N", c)
		}
		if ipv6Proxy || ipv6DnsHijack {
			ip6t.run("-t", chainTable(c), "-N", c)
		}
	}

	coreGID := lookupNexaGID()

	// 有效防回环策略：系统不支持 cgroup 时强制启用 GID 绕过、关闭 cgroup 绕过，
	// 与 core.go Start() / nfttemplate.Build() 使用完全相同的判定标准（cgroupsupport 包），
	// 保证「不支持就自动切到 GID」这条规则在 nftables 和 iptables 两种后端下行为一致。
	cgVersion := cgroupsVersion() // 0=不支持，1=v1，2=v2
	effectiveBypassCgroup := p.BypassCgroup && cgVersion != int(cgroupsupport.None)
	effectiveBypassGid := p.BypassGid || cgVersion == int(cgroupsupport.None)

	bypassOpts := bypassOptions{
		cgroupsVersion:   cgVersion,
		cgroupID:         r.CgroupID,
		cgroupName:       r.CgroupName,
		coreGID:          coreGID,
		bypassCgroup:     effectiveBypassCgroup,
		bypassGid:        effectiveBypassGid,
		bypassMark:       p.BypassMark,
		bypassMarkValues: p.BypassMarkValues,
		bypassDscp:       p.BypassDscp,
		bypassFwmark:     p.BypassFwmark,
		reservedIP:       p.ReservedIP,
		reservedIP6:      p.ReservedIP6,
		fakeIPRange:      p.FakeIPRange,
		fakeIP6Range:     p.FakeIP6Range,
		chinaV4Ready:     chinaV4Ready,
		chinaV6Ready:     chinaV6Ready,
		caps:             caps,
	}
	if cgVersion == int(cgroupsupport.None) && p.BypassCgroup {
		m.log.App("代理", "当前系统不支持 cgroup 防回环，iptables 规则已自动改用 GID 绕过。")
	}

	// ── Router（本机流量）绕过判断 + DNS 劫持 + TCP 重定向/透明代理 ──────
	if p.RouterProxy {
		buildBypassChain(ipt, "NEXA_BYPASS_R", bypassOpts, true)
		buildBypassChain(ip6t, "NEXA_BYPASS_R", bypassOpts, false)

		for _, ac := range cfg.RouterAccessControls {
			if !ac.Enabled {
				continue
			}
			buildDNSHijackRules(ipt, "NEXA_DNS_HIJACK_R", ac.User, ac.Group, ac.Dns, p.DnsPort, ipv4DnsHijack)
			buildDNSHijackRules(ip6t, "NEXA_DNS_HIJACK_R", ac.User, ac.Group, ac.Dns, p.DnsPort, ipv6DnsHijack)

			if tcpMode == "redirect" {
				buildRedirectRules(ipt, "NEXA_REDIRECT_R", ac.User, ac.Group, ac.Proxy, p.RedirPort, ipv4Proxy)
				buildRedirectRules(ip6t, "NEXA_REDIRECT_R", ac.User, ac.Group, ac.Proxy, p.RedirPort, ipv6Proxy)
			}
			if tproxyEnable {
				buildTproxyMarkRules(ipt, "NEXA_TPROXY_R", ac.User, ac.Group, ac.Proxy, r.TproxyFwMark, ipv4Proxy)
				buildTproxyMarkRules(ip6t, "NEXA_TPROXY_R", ac.User, ac.Group, ac.Proxy, r.TproxyFwMark, ipv6Proxy)
			}
			if tunEnable {
				buildTproxyMarkRules(ipt, "NEXA_TUN_BYPASS_R", ac.User, ac.Group, ac.Proxy, r.TunFwMark, ipv4Proxy)
				buildTproxyMarkRules(ip6t, "NEXA_TUN_BYPASS_R", ac.User, ac.Group, ac.Proxy, r.TunFwMark, ipv6Proxy)
			}
		}

		// 挂载：nat OUTPUT 先过 DNS 劫持链，再走绕过判断，最后按模式分流。
		if ipv4DnsHijack || ipv4Proxy {
			ipt.run("-t", "nat", "-A", "OUTPUT", "-j", "NEXA_DNS_HIJACK_R", "-m", "comment", "--comment", nexaComment)
		}
		if ipv6DnsHijack || ipv6Proxy {
			ip6t.run("-t", "nat", "-A", "OUTPUT", "-j", "NEXA_DNS_HIJACK_R", "-m", "comment", "--comment", nexaComment)
		}
		if tcpMode == "redirect" {
			if ipv4Proxy {
				ipt.run("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", nexaComment)
				ipt.run("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "NEXA_REDIRECT_R", "-m", "comment", "--comment", nexaComment)
			}
			if ipv6Proxy {
				ip6t.run("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", nexaComment)
				ip6t.run("-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "NEXA_REDIRECT_R", "-m", "comment", "--comment", nexaComment)
			}
		}
		if tproxyEnable {
			if ipv4Proxy {
				ipt.run("-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", nexaComment)
				ipt.run("-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_TPROXY_R", "-m", "comment", "--comment", nexaComment)
			}
			if ipv6Proxy {
				ip6t.run("-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", nexaComment)
				ip6t.run("-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_TPROXY_R", "-m", "comment", "--comment", nexaComment)
			}
		}
		if tunEnable {
			// tun 模式本机流量由核心自身处理路由，这里仅打 mark 供 Apply() 中的 ip rule 分流参考，
			// 命中绕过条件的连接不打 mark（相当于直连）。
			if ipv4Proxy {
				ipt.run("-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", nexaComment)
				ipt.run("-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_TUN_BYPASS_R", "-m", "comment", "--comment", nexaComment)
			}
			if ipv6Proxy {
				ip6t.run("-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", nexaComment)
				ip6t.run("-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_TUN_BYPASS_R", "-m", "comment", "--comment", nexaComment)
			}
		}
	}

	// ── LAN（局域网转发流量）绕过判断 + DNS 劫持 + TCP 重定向/透明代理 ──
	if p.LanProxy {
		buildBypassChain(ipt, "NEXA_BYPASS_L", bypassOpts, true)
		buildBypassChain(ip6t, "NEXA_BYPASS_L", bypassOpts, false)

		for _, ac := range cfg.LanAccessControls {
			if !ac.Enabled {
				continue
			}
			buildLanDNSHijackRules(ipt, "NEXA_DNS_HIJACK_L", ac.IP, ac.Mac, ac.Dns, p.DnsPort, ipv4DnsHijack)
			buildLanDNSHijackRules(ip6t, "NEXA_DNS_HIJACK_L", ac.IP6, ac.Mac, ac.Dns, p.DnsPort, ipv6DnsHijack)

			if tcpMode == "redirect" {
				buildLanRedirectRules(ipt, "NEXA_REDIRECT_L", ac.IP, ac.Mac, ac.Proxy, p.RedirPort, ipv4Proxy)
				buildLanRedirectRules(ip6t, "NEXA_REDIRECT_L", ac.IP6, ac.Mac, ac.Proxy, p.RedirPort, ipv6Proxy)
			}
			if tproxyEnable || tunEnable {
				port := p.TproxyPort
				mark := r.TproxyFwMark
				if tunEnable {
					mark = r.TunFwMark
				}
				buildLanTproxyRules(ipt, "NEXA_TPROXY_L", ac.IP, ac.Mac, ac.Proxy, port, mark, ipv4Proxy, lanTproxySupported4)
				buildLanTproxyRules(ip6t, "NEXA_TPROXY_L", ac.IP6, ac.Mac, ac.Proxy, port, mark, ipv6Proxy, lanTproxySupported6)
			}
		}
		for _, dev := range lanDevs {
			if ipv4DnsHijack || ipv4Proxy {
				ipt.run("-t", "nat", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_DNS_HIJACK_L", "-m", "comment", "--comment", nexaComment)
			}
			if ipv6DnsHijack || ipv6Proxy {
				ip6t.run("-t", "nat", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_DNS_HIJACK_L", "-m", "comment", "--comment", nexaComment)
			}
			if tcpMode == "redirect" {
				if ipv4Proxy {
					ipt.run("-t", "nat", "-A", "PREROUTING", "-i", dev, "-p", "tcp", "-j", "NEXA_BYPASS_L", "-m", "comment", "--comment", nexaComment)
					ipt.run("-t", "nat", "-A", "PREROUTING", "-i", dev, "-p", "tcp", "-j", "NEXA_REDIRECT_L", "-m", "comment", "--comment", nexaComment)
				}
				if ipv6Proxy {
					ip6t.run("-t", "nat", "-A", "PREROUTING", "-i", dev, "-p", "tcp", "-j", "NEXA_BYPASS_L", "-m", "comment", "--comment", nexaComment)
					ip6t.run("-t", "nat", "-A", "PREROUTING", "-i", dev, "-p", "tcp", "-j", "NEXA_REDIRECT_L", "-m", "comment", "--comment", nexaComment)
				}
			}
			if tproxyEnable || tunEnable {
				if ipv4Proxy {
					ipt.run("-t", "mangle", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_BYPASS_L", "-m", "comment", "--comment", nexaComment)
					ipt.run("-t", "mangle", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_TPROXY_L", "-m", "comment", "--comment", nexaComment)
				}
				if ipv6Proxy {
					ip6t.run("-t", "mangle", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_BYPASS_L", "-m", "comment", "--comment", nexaComment)
					ip6t.run("-t", "mangle", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_TPROXY_L", "-m", "comment", "--comment", nexaComment)
				}
			}
		}
	}

	// ── TUN 模式：放行进入 TUN 设备的流量（对应 mangle_prerouting_router 的 iifname tun accept）──
	if tunEnable && p.TunDevice != "" {
		ipt.run("-t", "filter", "-I", "INPUT", "-i", p.TunDevice, "-j", "ACCEPT", "-m", "comment", "--comment", nexaComment)
		ipt.run("-t", "filter", "-I", "FORWARD", "-o", p.TunDevice, "-j", "ACCEPT", "-m", "comment", "--comment", nexaComment)
		ipt.run("-t", "filter", "-I", "FORWARD", "-i", p.TunDevice, "-j", "ACCEPT", "-m", "comment", "--comment", nexaComment)
		if ipv6Proxy {
			ip6t.run("-t", "filter", "-I", "INPUT", "-i", p.TunDevice, "-j", "ACCEPT", "-m", "comment", "--comment", nexaComment)
			ip6t.run("-t", "filter", "-I", "FORWARD", "-o", p.TunDevice, "-j", "ACCEPT", "-m", "comment", "--comment", nexaComment)
			ip6t.run("-t", "filter", "-I", "FORWARD", "-i", p.TunDevice, "-j", "ACCEPT", "-m", "comment", "--comment", nexaComment)
		}
	}

	// ── fake-ip ping 劫持 ──────────────────────────────
	if p.FakeIPPingHijack && p.FakeIPRange != "" && ipv4Proxy {
		ipt.run("-t", "nat", "-A", "PREROUTING", "-p", "icmp", "--icmp-type", "echo-request", "-d", p.FakeIPRange, "-j", "REDIRECT", "-m", "comment", "--comment", nexaComment)
	}
	if p.FakeIPPingHijack && p.FakeIP6Range != "" && ipv6Proxy {
		ip6t.run("-t", "nat", "-A", "PREROUTING", "-p", "ipv6-icmp", "--icmpv6-type", "echo-request", "-d", p.FakeIP6Range, "-j", "REDIRECT", "-m", "comment", "--comment", nexaComment)
	}

	if p.BypassChinaMainlandIP && !chinaV4Ready {
		m.log.App("代理", "警告：中国大陆 IPv4 绕过未生效（ipset 加载失败）。")
	}
	if p.BypassChinaMainlandIP6 && !chinaV6Ready {
		m.log.App("代理", "警告：中国大陆 IPv6 绕过未生效（ipset 加载失败）。")
	}
	if tproxyEnable {
		m.log.App("代理", "已应用 iptables 透明代理(TPROXY)规则；局域网转发流量使用真实 TPROXY target，本机流量使用 fwmark+策略路由近似实现；若内核未加载 xt_TPROXY 模块，该模式将不可用，请改用 redirect 或 tun 模式。")
	} else {
		m.log.App("代理", "iptables 流量劫持规则已应用。")
	}
	return nil
}

// cleanupIptables 对称删除 Apply 建立的所有规则、自定义链和 ipset（IPv4 + IPv6）。
func (m *Manager) cleanupIptables(cfg *config.Config) {
	for _, ipt := range []string{"iptables", "ip6tables"} {
		if !hasCommand(ipt) {
			continue
		}
		// 删除挂载点中带 nexa 标记的跳转规则
		deleteIptRulesByComment(ipt, "nat", "OUTPUT")
		deleteIptRulesByComment(ipt, "nat", "PREROUTING")
		deleteIptRulesByComment(ipt, "mangle", "OUTPUT")
		deleteIptRulesByComment(ipt, "mangle", "PREROUTING")
		deleteIptRulesByComment(ipt, "filter", "INPUT")
		deleteIptRulesByComment(ipt, "filter", "FORWARD")

		// 清空并删除自定义链
		for _, c := range iptablesChains {
			t := chainTable(c)
			_ = exec.Command(ipt, "-t", t, "-F", c).Run()
			_ = exec.Command(ipt, "-t", t, "-X", c).Run()
		}
	}
	// 删除 ipset（先要求没有规则引用，因此放在 iptables 规则清理之后）
	if hasCommand("ipset") {
		_ = exec.Command("ipset", "destroy", ipsetChinaV4).Run()
		_ = exec.Command("ipset", "destroy", ipsetChinaV6).Run()
	}
}

// deleteIptRulesByComment 反复查找并删除指定 table/chain 中带 nexa comment 的规则，直到没有为止。
func deleteIptRulesByComment(ipt, table, chain string) {
	for i := 0; i < 128; i++ { // 上限保护，避免异常规则集导致死循环
		out, err := exec.Command(ipt, "-t", table, "-S", chain).Output()
		if err != nil {
			return
		}
		ruleSpec, found := findCommentedRule(string(out), nexaComment)
		if !found {
			return
		}
		args := append([]string{"-t", table, "-D", chain}, ruleSpec...)
		if err := exec.Command(ipt, args...).Run(); err != nil {
			return
		}
	}
}

// findCommentedRule 从 `iptables -S <chain>` 输出中找到第一条带 --comment "nexa" 的规则，
// 返回可直接拼到 -D 后面的匹配参数（去掉开头的 -A <chain>）。
func findCommentedRule(spec string, comment string) ([]string, bool) {
	lines := strings.Split(spec, "\n")
	for _, line := range lines {
		if !strings.Contains(line, `--comment "`+comment+`"`) && !strings.Contains(line, "--comment "+comment) {
			continue
		}
		fields := splitArgs(line)
		if len(fields) < 2 || fields[0] != "-A" {
			continue
		}
		return fields[2:], true // 跳过 "-A" "<chain>"
	}
	return nil, false
}

// splitArgs 简单地按空白切分并还原带引号的参数（iptables -S 输出对含空格的值加引号）。
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ── ipset 辅助（中国大陆 IP 绕过） ─────────────────────

// loadIPSet 创建（若不存在）指定 ipset 并用 elements 覆盖其内容。
// elements 是逗号分隔的 CIDR 列表（extractGeoIPElements 的输出格式，形如 "1.0.1.0/24,\n1.0.2.0/23,..."）。
func loadIPSet(name, setType, family string, elements string) error {
	if !hasCommand("ipset") {
		return errNoIPSet
	}
	// 用临时 set + swap，避免大集合重建期间出现规则短暂失配。
	tmp := name + "_tmp"
	_ = exec.Command("ipset", "destroy", tmp).Run() // 忽略残留
	if err := exec.Command("ipset", "create", tmp, setType, "family", family, "-exist").Run(); err != nil {
		return err
	}
	cidrs := splitCIDRList(elements)
	restoreInput := buildIPSetRestore(tmp, cidrs)
	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = strings.NewReader(restoreInput)
	if err := cmd.Run(); err != nil {
		_ = exec.Command("ipset", "destroy", tmp).Run()
		return err
	}
	if err := exec.Command("ipset", "create", name, setType, "family", family, "-exist").Run(); err != nil {
		_ = exec.Command("ipset", "destroy", tmp).Run()
		return err
	}
	if err := exec.Command("ipset", "swap", tmp, name).Run(); err != nil {
		_ = exec.Command("ipset", "destroy", tmp).Run()
		return err
	}
	_ = exec.Command("ipset", "destroy", tmp).Run()
	return nil
}

// splitCIDRList 把 "1.0.1.0/24,\n1.0.2.0/23" 这种格式拆成 CIDR 列表。
func splitCIDRList(s string) []string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	fields := strings.Split(s, ",")
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func buildIPSetRestore(name string, cidrs []string) string {
	var b strings.Builder
	for _, c := range cidrs {
		b.WriteString("add ")
		b.WriteString(name)
		b.WriteString(" ")
		b.WriteString(c)
		b.WriteString(" -exist\n")
	}
	return b.String()
}

var errNoIPSet = errNoIPSetType{}

type errNoIPSetType struct{}

func (errNoIPSetType) Error() string { return "系统未安装 ipset 命令" }

// ── 绕过判断链（对齐 nft nat_output / mangle_output / dstnat / mangle_prerouting_lan 的公共前缀）──

type bypassOptions struct {
	cgroupsVersion   int
	cgroupID         string
	cgroupName       string
	coreGID          string
	bypassCgroup     bool
	bypassGid        bool
	bypassMark       bool
	bypassMarkValues []string
	bypassDscp       []string
	bypassFwmark     []string
	reservedIP       []string
	reservedIP6      []string
	fakeIPRange      string
	fakeIP6Range     string
	chinaV4Ready     bool
	chinaV6Ready     bool
	caps             matchSupportCache
}

// buildBypassChain 生成绕过判断链：命中任一条件则 RETURN（不劫持），对齐 nft 模板里
// nat_output/mangle_output/dstnat/mangle_prerouting_lan 开头的公共绕过逻辑：
// cgroup → gid → mark → 保留地址 → 中国 IP → DSCP → fwmark。
func buildBypassChain(w *iptWriter, chain string, o bypassOptions, isV4 bool) {
	if !w.enabled {
		return
	}
	// cgroup 绕过（已在上层按 cgroupsupport 探测结果决定 bypassCgroup 是否为 true；
	// 这里再探测一次 iptables 本身是否编译了对应的 xt_cgroup 匹配模块，双重保险，
	// 避免探测到内核支持 cgroup 但 iptables 版本过旧不支持 --path/--cgroup 参数时仍下发无效规则）。
	if o.bypassCgroup {
		switch o.cgroupsVersion {
		case 1:
			if o.cgroupID != "" && o.caps.supportsMatch(w.bin, "cgroup", "--cgroup") {
				w.run("-t", chainTable(chain), "-A", chain, "-m", "cgroup", "--cgroup", hexToDecimal(o.cgroupID), "-j", "RETURN")
			}
		case 2:
			if o.cgroupName != "" && o.caps.supportsMatch(w.bin, "cgroup", "--path") {
				w.run("-t", chainTable(chain), "-A", chain, "-m", "cgroup", "--path", "services/"+o.cgroupName, "-j", "RETURN")
			}
		}
	}
	// gid 绕过（核心自身进程组）
	if o.bypassGid && o.coreGID != "" {
		w.run("-t", chainTable(chain), "-A", chain, "-m", "owner", "--gid-owner", o.coreGID, "-j", "RETURN")
	}
	// 已有 fwmark 绕过（连接已被其他规则标记，直接放行，如 clash 自身出站流量常用此法防回环）
	if o.bypassMark {
		for _, mv := range o.bypassMarkValues {
			if mv == "" {
				continue
			}
			w.run("-t", chainTable(chain), "-A", chain, "-m", "mark", "--mark", mv, "-j", "RETURN")
		}
	}
	// 保留地址段 / fake-ip 排除
	if isV4 {
		for _, cidr := range o.reservedIP {
			args := []string{"-t", chainTable(chain), "-A", chain, "-d", cidr}
			if o.fakeIPRange != "" {
				args = append(args, "!", "-d", o.fakeIPRange)
			}
			args = append(args, "-j", "RETURN")
			w.run(args...)
		}
		if o.chinaV4Ready {
			w.run("-t", chainTable(chain), "-A", chain, "-m", "set", "--match-set", ipsetChinaV4, "dst", "-j", "RETURN")
		}
	} else {
		for _, cidr := range o.reservedIP6 {
			args := []string{"-t", chainTable(chain), "-A", chain, "-d", cidr}
			if o.fakeIP6Range != "" {
				args = append(args, "!", "-d", o.fakeIP6Range)
			}
			args = append(args, "-j", "RETURN")
			w.run(args...)
		}
		if o.chinaV6Ready {
			w.run("-t", chainTable(chain), "-A", chain, "-m", "set", "--match-set", ipsetChinaV6, "dst", "-j", "RETURN")
		}
	}
	// DSCP 绕过
	for _, dscp := range o.bypassDscp {
		if dscp == "" {
			continue
		}
		args := []string{"-t", chainTable(chain), "-A", chain, "-m", "dscp", "--dscp", dscp}
		if isV4 && o.fakeIPRange != "" {
			args = append(args, "!", "-d", o.fakeIPRange)
		} else if !isV4 && o.fakeIP6Range != "" {
			args = append(args, "!", "-d", o.fakeIP6Range)
		}
		args = append(args, "-j", "RETURN")
		w.run(args...)
	}
	// 指定 fwmark/mask 绕过（对齐 BypassFwmark 配置项，格式 "mark/mask"）
	for _, fm := range o.bypassFwmark {
		mark, mask := fm, "0xFFFFFFFF"
		if i := strings.IndexByte(fm, '/'); i >= 0 {
			mark = fm[:i]
			mask = fm[i+1:]
		}
		w.run("-t", chainTable(chain), "-A", chain, "-m", "mark", "--mark", mark+"/"+mask, "-j", "RETURN")
	}
}

// hexToDecimal 把 "0x07250725" 这种 net_cls classid 转成 --cgroup 需要的十进制字符串；
// 若已经是十进制或转换失败则原样返回。
func hexToDecimal(hexID string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(hexID, "0x"), "0X")
	if v, err := strconv.ParseUint(h, 16, 64); err == nil {
		return strconv.FormatUint(v, 10)
	}
	return hexID
}

// lookupNexaGID 查找 nexa 组的 GID，找不到返回空字符串（对齐 nfttemplate.lookupCoreGID）。
func lookupNexaGID() string {
	out, err := exec.Command("getent", "group", "nexa").Output()
	if err != nil {
		return ""
	}
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) >= 3 {
		return fields[2]
	}
	return ""
}

// matchSupportCache 缓存一次 applyIptables 调用内已经探测过的 (bin, module/target, flag) 组合，
// 避免同一二进制的同一模块在这一次 Apply 里被反复 fork 出去执行 `-h` 探测
// （cgroup 绕过每条链都会探测一次）。特意不做成包级全局变量：iptables 版本、内核模块加载状态
// 都可能在 nexa 进程运行期间发生变化（比如用户手动 modprobe 了模块），
// 每次 Apply 都应该重新探测一次，而不是沿用进程启动以来的第一次探测结果。
type matchSupportCache map[string]bool

func newMatchSupportCache() matchSupportCache {
	return make(matchSupportCache)
}

// supportsMatch 探测 iptables/ip6tables 是否编译了指定匹配模块的指定参数，
// 对齐 ShellCrash fw_iptables.sh 的探测写法（如 `$ip6table -j REDIRECT -h | grep -q '\--to-ports'`），
// 用 `-m <module> -h` 帮助输出里是否包含目标 flag 来判断，不依赖版本号猜测。
func (c matchSupportCache) supportsMatch(bin, module, flag string) bool {
	key := bin + "|" + module + "|" + flag
	if v, ok := c[key]; ok {
		return v
	}
	out, _ := exec.Command(bin, "-m", module, "-h").CombinedOutput()
	supported := strings.Contains(string(out), flag)
	c[key] = supported
	return supported
}

// supportsTarget 探测 iptables/ip6tables 是否支持指定 target 的指定参数
// （如 `-j TPROXY -h` 输出里是否包含 `--on-port`），用法同上。
func (c matchSupportCache) supportsTarget(bin, target, flag string) bool {
	key := bin + "|target:" + target + "|" + flag
	if v, ok := c[key]; ok {
		return v
	}
	out, _ := exec.Command(bin, "-j", target, "-h").CombinedOutput()
	supported := strings.Contains(string(out), flag)
	c[key] = supported
	return supported
}

// ── 规则构建 helper ────────────────────────────────────

// iptWriter 包装 exec，按 enabled 开关决定是否真正执行（对应 ipv4/ipv6 独立开关）。
type iptWriter struct {
	bin     string
	enabled bool
	log     *logger.Logger
}

func newIptWriter(log *logger.Logger, enabled bool) *iptWriter {
	return &iptWriter{bin: "iptables", enabled: enabled, log: log}
}

func newIp6tWriter(log *logger.Logger, enabled bool) *iptWriter {
	return &iptWriter{bin: "ip6tables", enabled: enabled, log: log}
}

func (w *iptWriter) run(args ...string) {
	if !w.enabled {
		return
	}
	if w.bin == "" {
		w.bin = "iptables"
	}
	_ = exec.Command(w.bin, args...).Run()
}

// buildDNSHijackRules 对齐 nft chain router_dns_hijack：按 user/group 分流，命中则 REDIRECT:dnsPort 或 RETURN。
func buildDNSHijackRules(w *iptWriter, chain string, users, groups []string, dns bool, dnsPort string, protoEnabled bool) {
	if !protoEnabled || !w.enabled {
		return
	}
	action := dnsAction(dns)
	if len(users) == 0 && len(groups) == 0 {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "nat", "-A", chain, "-p", proto, "--dport", "53", "-j", action}
			args = append(args, jArg(dns, dnsPort)...)
			w.run(args...)
		}
		return
	}
	if len(users) > 0 {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "nat", "-A", chain, "-p", proto, "--dport", "53",
				"-m", "owner", "--uid-owner", strings.Join(users, ",")}
			args = append(args, "-j", action)
			args = append(args, jArg(dns, dnsPort)...)
			w.run(args...)
		}
	}
	if len(groups) > 0 {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "nat", "-A", chain, "-p", proto, "--dport", "53",
				"-m", "owner", "--gid-owner", strings.Join(groups, ",")}
			args = append(args, "-j", action)
			args = append(args, jArg(dns, dnsPort)...)
			w.run(args...)
		}
	}
}

// buildLanDNSHijackRules 对齐 lan_dns_hijack：按源 IP / MAC 分流。
func buildLanDNSHijackRules(w *iptWriter, chain string, ips, macs []string, dns bool, dnsPort string, protoEnabled bool) {
	if !protoEnabled || !w.enabled {
		return
	}
	action := dnsAction(dns)
	if len(ips) == 0 && len(macs) == 0 {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "nat", "-A", chain, "-p", proto, "--dport", "53", "-j", action}
			args = append(args, jArg(dns, dnsPort)...)
			w.run(args...)
		}
		return
	}
	for _, ip := range ips {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "nat", "-A", chain, "-p", proto, "--dport", "53", "-s", ip, "-j", action}
			args = append(args, jArg(dns, dnsPort)...)
			w.run(args...)
		}
	}
	for _, mac := range macs {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "nat", "-A", chain, "-p", proto, "--dport", "53",
				"-m", "mac", "--mac-source", mac, "-j", action}
			args = append(args, jArg(dns, dnsPort)...)
			w.run(args...)
		}
	}
}

// buildRedirectRules 对齐 router_redirect：TCP REDIRECT 到 redirPort。
func buildRedirectRules(w *iptWriter, chain string, users, groups []string, proxy bool, redirPort string, protoEnabled bool) {
	if !protoEnabled || !w.enabled || !proxy {
		return
	}
	if len(users) == 0 && len(groups) == 0 {
		w.run("-t", "nat", "-A", chain, "-p", "tcp", "-j", "REDIRECT", "--to-ports", redirPort)
		return
	}
	if len(users) > 0 {
		w.run("-t", "nat", "-A", chain, "-p", "tcp", "-m", "owner", "--uid-owner", strings.Join(users, ","),
			"-j", "REDIRECT", "--to-ports", redirPort)
	}
	if len(groups) > 0 {
		w.run("-t", "nat", "-A", chain, "-p", "tcp", "-m", "owner", "--gid-owner", strings.Join(groups, ","),
			"-j", "REDIRECT", "--to-ports", redirPort)
	}
}

// buildLanRedirectRules 对齐 lan_redirect：按源 IP / MAC 分流 TCP REDIRECT。
func buildLanRedirectRules(w *iptWriter, chain string, ips, macs []string, proxy bool, redirPort string, protoEnabled bool) {
	if !protoEnabled || !w.enabled || !proxy {
		return
	}
	if len(ips) == 0 && len(macs) == 0 {
		w.run("-t", "nat", "-A", chain, "-p", "tcp", "-j", "REDIRECT", "--to-ports", redirPort)
		return
	}
	for _, ip := range ips {
		w.run("-t", "nat", "-A", chain, "-p", "tcp", "-s", ip, "-j", "REDIRECT", "--to-ports", redirPort)
	}
	for _, mac := range macs {
		w.run("-t", "nat", "-A", chain, "-p", "tcp", "-m", "mac", "--mac-source", mac,
			"-j", "REDIRECT", "--to-ports", redirPort)
	}
}

// buildTproxyMarkRules 用于本机（router）流量：真实 TPROXY target 无法挂在 OUTPUT 链，
// 因此改为打 fwmark，配合 Apply() 中已建立的 ip rule/route 策略路由转发到本地监听端口
// （tproxy 模式转发到 TproxyPort，tun 模式则交给 TUN 设备的默认路由）。
func buildTproxyMarkRules(w *iptWriter, chain string, users, groups []string, proxy bool, fwmark string, protoEnabled bool) {
	if !protoEnabled || !w.enabled || !proxy {
		return
	}
	if len(users) == 0 && len(groups) == 0 {
		w.run("-t", "mangle", "-A", chain, "-p", "tcp", "-j", "MARK", "--set-mark", fwmark)
		w.run("-t", "mangle", "-A", chain, "-p", "udp", "-j", "MARK", "--set-mark", fwmark)
		return
	}
	if len(users) > 0 {
		w.run("-t", "mangle", "-A", chain, "-m", "owner", "--uid-owner", strings.Join(users, ","),
			"-j", "MARK", "--set-mark", fwmark)
	}
	if len(groups) > 0 {
		w.run("-t", "mangle", "-A", chain, "-m", "owner", "--gid-owner", strings.Join(groups, ","),
			"-j", "MARK", "--set-mark", fwmark)
	}
}

// buildLanTproxyRules 对齐 lan_tproxy：在 PREROUTING 用真正的 TPROXY target（局域网转发流量可用）；
// tun 模式下（useTproxyTarget=false）改用 MARK，交给 TUN 设备路由。
func buildLanTproxyRules(w *iptWriter, chain string, ips, macs []string, proxy bool, port, fwmark string, protoEnabled, useTproxyTarget bool) {
	if !protoEnabled || !w.enabled || !proxy {
		return
	}
	target := func(proto string) []string {
		if useTproxyTarget {
			return []string{"-j", "TPROXY", "--tproxy-mark", fwmark, "--on-port", port}
		}
		return []string{"-j", "MARK", "--set-mark", fwmark}
	}
	if len(ips) == 0 && len(macs) == 0 {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "mangle", "-A", chain, "-p", proto}
			args = append(args, target(proto)...)
			w.run(args...)
		}
		return
	}
	for _, ip := range ips {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "mangle", "-A", chain, "-p", proto, "-s", ip}
			args = append(args, target(proto)...)
			w.run(args...)
		}
	}
	for _, mac := range macs {
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-t", "mangle", "-A", chain, "-p", proto, "-m", "mac", "--mac-source", mac}
			args = append(args, target(proto)...)
			w.run(args...)
		}
	}
}

func dnsAction(dns bool) string {
	if dns {
		return "REDIRECT"
	}
	return "RETURN"
}

func jArg(dns bool, dnsPort string) []string {
	if dns {
		return []string{"--to-ports", dnsPort}
	}
	return nil
}
