// Package config 定义 nexa 的全部配置模型，字段 1:1 对齐原 UCI proxy 配置。
package config

// Config 顶层配置容器，对应原 /etc/config/proxy 的所有 section。
type Config struct {
	Config                ConfigSection         `json:"config"`
	Procd                 ProcdSection          `json:"procd"`
	Proxy                 ProxySection          `json:"proxy"`
	RouterAccessControls  []RouterAccessControl `json:"router_access_controls"`
	LanAccessControls     []LanAccessControl    `json:"lan_access_controls"`
	Routing               RoutingSection        `json:"routing"`
	Log                   LogSection            `json:"log"`
}

// ConfigSection 对应 UCI section 'config'
type ConfigSection struct {
	Enabled               bool   `json:"enabled"`
	Profile               string `json:"profile"`
	RunBinary             string `json:"run_binary"`
	RunArgs               string `json:"run_args"`
	StartDelay            int    `json:"start_delay"`
	ScheduledRestart      bool   `json:"scheduled_restart"`
	ScheduledRestartCron  string `json:"scheduled_restart_cron"`
}

// ProcdSection 对应 UCI section 'procd'
type ProcdSection struct {
	FastReload bool `json:"fast_reload"`
}

// ProxySection 对应 UCI section 'proxy'
type ProxySection struct {
	Enabled              bool     `json:"enabled"`
	IPv4DnsHijack        bool     `json:"ipv4_dns_hijack"`
	IPv6DnsHijack        bool     `json:"ipv6_dns_hijack"`
	IPv4Proxy            bool     `json:"ipv4_proxy"`
	IPv6Proxy            bool     `json:"ipv6_proxy"`
	FakeIPPingHijack     bool     `json:"fake_ip_ping_hijack"`
	TcpMode              string   `json:"tcp_mode"` // redirect | tproxy | tun
	UdpMode              string   `json:"udp_mode"` // redirect | tproxy | tun
	RouterProxy          bool     `json:"router_proxy"`
	LanProxy             bool     `json:"lan_proxy"`
	LanInboundInterface  []string `json:"lan_inbound_interface"`
	DnsPort              string   `json:"dns_port"`
	RedirPort            string   `json:"redir_port"`
	TproxyPort           string   `json:"tproxy_port"`
	TunDevice            string   `json:"tun_device"`
	UIPort               string   `json:"ui_port"`
	UIPath               string   `json:"ui_path"`
	FakeIPRange          string   `json:"fake_ip_range"`
	FakeIP6Range         string   `json:"fake_ip6_range"`
	ReservedIP           []string `json:"reserved_ip"`
	ReservedIP6          []string `json:"reserved_ip6"`
	BypassChinaMainlandIP  bool   `json:"bypass_china_mainland_ip"`
	BypassChinaMainlandIP6 bool   `json:"bypass_china_mainland_ip6"`
	ProxyTcpDport        string   `json:"proxy_tcp_dport"`
	ProxyUdpDport        string   `json:"proxy_udp_dport"`
	BypassDscp           []string `json:"bypass_dscp"`
	BypassFwmark         []string `json:"bypass_fwmark"`
	TunTimeout           int      `json:"tun_timeout"`
	TunInterval          int      `json:"tun_interval"`
}

// RouterAccessControl 对应 UCI section 'router_access_control'（多实例）
type RouterAccessControl struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	User    []string `json:"user"`
	Group   []string `json:"group"`
	Cgroup  []string `json:"cgroup"`
	Dns     bool     `json:"dns"`
	Proxy   bool     `json:"proxy"`
}

// LanAccessControl 对应 UCI section 'lan_access_control'（多实例）
type LanAccessControl struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	IP      []string `json:"ip"`
	IP6     []string `json:"ip6"`
	Mac     []string `json:"mac"`
	Dns     bool     `json:"dns"`
	Proxy   bool     `json:"proxy"`
}

// RoutingSection 对应 UCI section 'routing'
type RoutingSection struct {
	TproxyFwMark     string `json:"tproxy_fw_mark"`
	TproxyFwMask     string `json:"tproxy_fw_mask"`
	TunFwMark        string `json:"tun_fw_mark"`
	TunFwMask        string `json:"tun_fw_mask"`
	TproxyRulePref   int    `json:"tproxy_rule_pref"`
	TunRulePref      int    `json:"tun_rule_pref"`
	TproxyRouteTable string `json:"tproxy_route_table"`
	TunRouteTable    string `json:"tun_route_table"`
	CgroupID         string `json:"cgroup_id"`
	CgroupName       string `json:"cgroup_name"`
	DummyDevice      string `json:"dummy_device"`
}

// LogSection 对应 UCI section 'log'
type LogSection struct {
	ScheduledClear              bool   `json:"scheduled_clear"`
	ScheduledClearCron          string `json:"scheduled_clear_cron"`
	ScheduledClearSizeLimit     int    `json:"scheduled_clear_size_limit"`
	ScheduledClearSizeLimitUnit string `json:"scheduled_clear_size_limit_unit"` // B|KB|MB|GB
}

// Default 返回与原 proxy.conf 默认值完全一致的配置。
func Default() *Config {
	return &Config{
		Config: ConfigSection{
			Enabled:              false,
			Profile:              "",
			RunBinary:            "",
			RunArgs:              "",
			StartDelay:           0,
			ScheduledRestart:     false,
			ScheduledRestartCron: "0 3 * * *",
		},
		Procd: ProcdSection{FastReload: false},
		Proxy: ProxySection{
			Enabled:                true,
			IPv4DnsHijack:          true,
			IPv6DnsHijack:          true,
			IPv4Proxy:              true,
			IPv6Proxy:              true,
			FakeIPPingHijack:       true,
			TcpMode:                "redirect",
			UdpMode:                "tun",
			RouterProxy:            true,
			LanProxy:               true,
			LanInboundInterface:    []string{"lan"},
			DnsPort:                "1053",
			RedirPort:              "7892",
			TproxyPort:             "7893",
			TunDevice:              "tun0",
			UIPort:                 "9090",
			UIPath:                 "ui",
			FakeIPRange:            "198.18.0.0/15",
			FakeIP6Range:           "fc00::/18",
			ReservedIP: []string{
				"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "100.64.0.0/10",
				"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
				"224.0.0.0/4", "240.0.0.0/4",
			},
			ReservedIP6: []string{
				"::/128", "::1/128", "::ffff:0:0/96", "100::/64", "64:ff9b::/96",
				"2001::/32", "2001:10::/28", "2001:20::/28", "2001:db8::/32",
				"2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
			},
			BypassChinaMainlandIP:   false,
			BypassChinaMainlandIP6:  false,
			ProxyTcpDport:           "0-65535",
			ProxyUdpDport:           "0-65535",
			BypassDscp:              []string{"4"},
			TunTimeout:              30,
			TunInterval:             1,
		},
		RouterAccessControls: []RouterAccessControl{
			{
				ID: "router-default-bypass", Enabled: true,
				User: []string{"dnsmasq", "ftp", "logd", "nobody", "ntp", "ubus"},
				Group: []string{"dnsmasq", "ftp", "logd", "nogroup", "ntp", "ubus"},
				Cgroup: []string{
					"services/adguardhome", "services/aria2", "services/dnsmasq",
					"services/netbird", "services/qbittorrent", "services/sysntpd",
					"services/tailscale", "services/zerotier",
				},
				Dns: false, Proxy: false,
			},
			{
				ID: "router-default-proxy", Enabled: true,
				Dns: true, Proxy: true,
			},
		},
		LanAccessControls: []LanAccessControl{
			{
				ID: "lan-default", Enabled: true,
				Dns: true, Proxy: true,
			},
		},
		Routing: RoutingSection{
			TproxyFwMark:     "0x80",
			TproxyFwMask:     "0xFF",
			TunFwMark:        "0x81",
			TunFwMask:        "0xFF",
			TproxyRulePref:   1024,
			TunRulePref:      1025,
			TproxyRouteTable: "80",
			TunRouteTable:    "81",
			CgroupID:         "0x07250725",
			CgroupName:       "proxy",
			DummyDevice:      "proxy-dummy",
		},
		Log: LogSection{
			ScheduledClear:              true,
			ScheduledClearCron:          "*/5 * * * *",
			ScheduledClearSizeLimit:     1,
			ScheduledClearSizeLimitUnit: "MB",
		},
	}
}
