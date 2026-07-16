// Package nfttemplate 把原 hijack.ut 的 nftables 规则 1:1 翻译成 Go text/template。
// 规则文本与原 ucode 模板逐条一致，仅控制流换成 Go 模板语法。
package nfttemplate

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"github.com/nexa-proxy/nexa/internal/config"
)

// Model 渲染模板所需的数据。
type Model struct {
	DnsHijackNFProto   []string
	ProxyNFProto       []string
	ReservedIP         []string
	ReservedIP6        []string
	LanInboundDevice   []string
	ProxyDport         []string // 形如 "tcp . 0-65535"
	BypassDscp         []string
	BypassFwmark       []Fwmark

	RouterProxy          bool
	RouterAccessControls []AccessControlView
	LanProxy             bool
	LanAccessControls    []AccessControlView

	RedirPort    string
	TproxyPort   string
	TunDevice    string
	DnsPort      string
	FakeIPRange  string
	FakeIP6Range string

	TcpMode string
	UdpMode string

	FakeIPPingHijack bool

	CgroupsVersion int // 1 或 2
	CgroupID       string
	CgroupName     string

	TproxyFwMark   string
	TproxyFwMask   string
	TproxyFwUmask  string
	TunFwMark      string
	TunFwMask      string
	TunFwUmask     string

	BypassChinaMainlandIP   bool
	BypassChinaMainlandIP6  bool

	// ChinaIPElements / ChinaIP6Elements：bypass 开启时从 geoip 文件提取的 elements 列表，
	// 注入到 proxy table 的 china_ip / china_ip6 集合，修复原 geoip 文件 table 名（momo）与
	// hijack 模板 table 名（proxy）不匹配导致 @china_ip 引用为空的问题。
	ChinaIPElements  string
	ChinaIP6Elements string

	// helper：dns_hijack / proxy 是否启用对应协议族，对齐原 ipv4_dns_hijack/ipv4_proxy 布尔判断
	DnsHijackNFProtoHas4 bool
	DnsHijackNFProtoHas6 bool
	ProxyNFProtoHas4     bool
	ProxyNFProtoHas6     bool
}

// AccessControlView 访问控制视图（统一 router/lan）。
type AccessControlView struct {
	Enabled bool
	User    []string
	Group   []string
	Cgroup  []string
	IP      []string
	IP6     []string
	Mac     []string
	Dns     bool
	Proxy   bool
}

// Fwmark bypass_fwmark 解析后的 mark/mask。
type Fwmark struct {
	Mark string
	Mask string
}

// Build 按 cfg + lanInboundDevice + cgroupsVersion 构造 Model。
func Build(cfg *config.Config, lanInboundDevice []string, cgroupsVersion int) *Model {
	p := &cfg.Proxy

	var dnsNF, proxyNF []string
	if p.IPv4DnsHijack {
		dnsNF = append(dnsNF, "ipv4")
	}
	if p.IPv6DnsHijack {
		dnsNF = append(dnsNF, "ipv6")
	}
	if p.IPv4Proxy {
		proxyNF = append(proxyNF, "ipv4")
	}
	if p.IPv6Proxy {
		proxyNF = append(proxyNF, "ipv6")
	}

	// proxy_dport
	var proxyDport []string
	for _, port := range splitSpace(p.ProxyTcpDport) {
		proxyDport = append(proxyDport, fmt.Sprintf("tcp . %s", port))
	}
	for _, port := range splitSpace(p.ProxyUdpDport) {
		proxyDport = append(proxyDport, fmt.Sprintf("udp . %s", port))
	}

	// bypass_fwmark
	var fwmarks []Fwmark
	for _, fm := range p.BypassFwmark {
		mark, mask := fm, "0xFFFFFFFF"
		if i := strings.IndexByte(fm, '/'); i >= 0 {
			mark = fm[:i]
			mask = fm[i+1:]
		}
		fwmarks = append(fwmarks, Fwmark{Mark: mark, Mask: mask})
	}

	return &Model{
		DnsHijackNFProto:       dnsNF,
		ProxyNFProto:           proxyNF,
		ReservedIP:             p.ReservedIP,
		ReservedIP6:            p.ReservedIP6,
		LanInboundDevice:       lanInboundDevice,
		ProxyDport:             proxyDport,
		BypassDscp:             p.BypassDscp,
		BypassFwmark:           fwmarks,
		RouterProxy:            p.RouterProxy,
		RouterAccessControls:   buildRouterViews(cfg),
		LanProxy:               p.LanProxy,
		LanAccessControls:      buildLanViews(cfg),
		RedirPort:              p.RedirPort,
		TproxyPort:             p.TproxyPort,
		TunDevice:              p.TunDevice,
		DnsPort:                p.DnsPort,
		FakeIPRange:            p.FakeIPRange,
		FakeIP6Range:           p.FakeIP6Range,
		TcpMode:                p.TcpMode,
		UdpMode:                p.UdpMode,
		FakeIPPingHijack:       p.FakeIPPingHijack,
		CgroupsVersion:         cgroupsVersion,
		CgroupID:               cfg.Routing.CgroupID,
		CgroupName:             cfg.Routing.CgroupName,
		TproxyFwMark:           cfg.Routing.TproxyFwMark,
		TproxyFwMask:           cfg.Routing.TproxyFwMask,
		TproxyFwUmask:          umask(cfg.Routing.TproxyFwMask),
		TunFwMark:              cfg.Routing.TunFwMark,
		TunFwMask:              cfg.Routing.TunFwMask,
		TunFwUmask:             umask(cfg.Routing.TunFwMask),
		BypassChinaMainlandIP:    p.BypassChinaMainlandIP,
		BypassChinaMainlandIP6:   p.BypassChinaMainlandIP6,
		DnsHijackNFProtoHas4:     p.IPv4DnsHijack,
		DnsHijackNFProtoHas6:     p.IPv6DnsHijack,
		ProxyNFProtoHas4:         p.IPv4Proxy,
		ProxyNFProtoHas6:         p.IPv6Proxy,
	}
}

func buildRouterViews(cfg *config.Config) []AccessControlView {
	var out []AccessControlView
	for _, ac := range cfg.RouterAccessControls {
		if !ac.Enabled {
			continue
		}
		out = append(out, AccessControlView{
			Enabled: ac.Enabled,
			User:    ac.User,
			Group:   ac.Group,
			Cgroup:  ac.Cgroup,
			Dns:     ac.Dns,
			Proxy:   ac.Proxy,
		})
	}
	return out
}

func buildLanViews(cfg *config.Config) []AccessControlView {
	var out []AccessControlView
	for _, ac := range cfg.LanAccessControls {
		if !ac.Enabled {
			continue
		}
		out = append(out, AccessControlView{
			Enabled: ac.Enabled,
			IP:      ac.IP,
			IP6:     ac.IP6,
			Mac:     ac.Mac,
			Dns:     ac.Dns,
			Proxy:   ac.Proxy,
		})
	}
	return out
}

// umask 对齐 fw4.hex(~mask & 0xFFFFFFFF)。
func umask(maskHex string) string {
	maskHex = strings.TrimPrefix(maskHex, "0x")
	if maskHex == "" {
		return "0xFFFFFFFF"
	}
	v, err := strconv.ParseUint(maskHex, 16, 32)
	if err != nil {
		return "0xFFFFFFFF"
	}
	return fmt.Sprintf("0x%08X", ^v&0xFFFFFFFF)
}

func splitSpace(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// Render 渲染完整 nft 规则。
func Render(m *Model) (string, error) {
	tmpl, err := template.New("hijack").Funcs(template.FuncMap{
		"join":     func(sep string, arr []string) string { return strings.Join(arr, sep) },
		"qjoin":    qjoin,
		"clen":     func(s string) int { return len(strings.Split(s, "/")) },
		"hasLen":   func(arr []string, n int) bool { return len(arr) > 0 },
		"lenGt0":   func(arr []string) bool { return len(arr) > 0 },
		"lenEq0":   func(arr []string) bool { return len(arr) == 0 },
		"quoteArr": func(arr []string) []string {
			out := make([]string, 0, len(arr))
			for _, s := range arr {
				out = append(out, fmt.Sprintf("%q", s))
			}
			return out
		},
	}).Parse(tmplText)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, m); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func qjoin(arr []string) string {
	out := make([]string, 0, len(arr))
	for _, s := range arr {
		out = append(out, fmt.Sprintf("%q", s))
	}
	return strings.Join(out, ", ")
}
