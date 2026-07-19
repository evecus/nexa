//! 配置模型，字段 1:1 对齐原 UCI proxy 配置。

use serde::{Deserialize, Serialize};

/// Config 顶层配置容器，对应原 /etc/config/proxy 的所有 section。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub config: ConfigSection,
    pub procd: ProcdSection,
    pub proxy: ProxySection,
    #[serde(default)]
    pub router_access_controls: Vec<RouterAccessControl>,
    #[serde(default)]
    pub lan_access_controls: Vec<LanAccessControl>,
    pub routing: RoutingSection,
    pub log: LogSection,
}

/// ConfigSection 对应 UCI section 'config'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub run_binary: String,
    #[serde(default)]
    pub run_args: String,
    #[serde(default)]
    pub start_delay: i64,
    #[serde(default)]
    pub scheduled_restart: bool,
    #[serde(default = "default_scheduled_restart_cron")]
    pub scheduled_restart_cron: String,
}

fn default_scheduled_restart_cron() -> String {
    "0 3 * * *".to_string()
}

/// ProcdSection 对应 UCI section 'procd'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcdSection {
    #[serde(default)]
    pub fast_reload: bool,
}

/// ProxySection 对应 UCI section 'proxy'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub ipv4_dns_hijack: bool,
    #[serde(default = "default_true")]
    pub ipv6_dns_hijack: bool,
    #[serde(default = "default_true")]
    pub ipv4_proxy: bool,
    #[serde(default = "default_true")]
    pub ipv6_proxy: bool,
    #[serde(default = "default_true")]
    pub fake_ip_ping_hijack: bool,
    #[serde(default = "default_tcp_mode")]
    pub tcp_mode: String, // redirect | tproxy | tun
    #[serde(default = "default_udp_mode")]
    pub udp_mode: String, // redirect | tproxy | tun
    #[serde(default = "default_true")]
    pub router_proxy: bool,
    #[serde(default = "default_true")]
    pub lan_proxy: bool,
    #[serde(default = "default_lan_inbound_interface")]
    pub lan_inbound_interface: Vec<String>,
    #[serde(default = "default_dns_port")]
    pub dns_port: String,
    #[serde(default = "default_redir_port")]
    pub redir_port: String,
    #[serde(default = "default_tproxy_port")]
    pub tproxy_port: String,
    #[serde(default = "default_tun_device")]
    pub tun_device: String,
    #[serde(default = "default_ui_port")]
    pub ui_port: String,
    #[serde(default = "default_ui_path")]
    pub ui_path: String,
    #[serde(default = "default_fake_ip_range")]
    pub fake_ip_range: String,
    #[serde(default = "default_fake_ip6_range")]
    pub fake_ip6_range: String,
    #[serde(default = "default_reserved_ip")]
    pub reserved_ip: Vec<String>,
    #[serde(default = "default_reserved_ip6")]
    pub reserved_ip6: Vec<String>,
    #[serde(default)]
    pub bypass_china_mainland_ip: bool,
    #[serde(default)]
    pub bypass_china_mainland_ip6: bool,
    #[serde(default = "default_proxy_tcp_dport")]
    pub proxy_tcp_dport: String,
    #[serde(default = "default_proxy_udp_dport")]
    pub proxy_udp_dport: String,
    #[serde(default = "default_bypass_dscp")]
    pub bypass_dscp: Vec<String>,
    #[serde(default = "default_true")]
    pub bypass_cgroup: bool,
    #[serde(default)]
    pub bypass_gid: bool,
    #[serde(default)]
    pub bypass_mark: bool,
    #[serde(default)]
    pub bypass_mark_values: Vec<String>,
    #[serde(default)]
    pub bypass_fwmark: Vec<String>,
    #[serde(default = "default_tun_timeout")]
    pub tun_timeout: i64,
    #[serde(default = "default_tun_interval")]
    pub tun_interval: i64,
}

fn default_true() -> bool {
    true
}
fn default_tcp_mode() -> String {
    "redirect".to_string()
}
fn default_udp_mode() -> String {
    "tun".to_string()
}
fn default_dns_port() -> String {
    "1053".to_string()
}
fn default_redir_port() -> String {
    "7892".to_string()
}
fn default_tproxy_port() -> String {
    "7893".to_string()
}
fn default_tun_device() -> String {
    "tun0".to_string()
}
fn default_ui_port() -> String {
    "9090".to_string()
}
fn default_ui_path() -> String {
    "ui".to_string()
}
fn default_fake_ip_range() -> String {
    "198.18.0.0/15".to_string()
}
fn default_fake_ip6_range() -> String {
    "fc00::/18".to_string()
}
fn default_proxy_tcp_dport() -> String {
    "0-65535".to_string()
}
fn default_proxy_udp_dport() -> String {
    "0-65535".to_string()
}
fn default_tun_timeout() -> i64 {
    30
}
fn default_tun_interval() -> i64 {
    1
}
fn default_bypass_dscp() -> Vec<String> {
    vec!["4".to_string()]
}
fn default_reserved_ip() -> Vec<String> {
    vec![
        "0.0.0.0/8".into(),
        "10.0.0.0/8".into(),
        "127.0.0.0/8".into(),
        "100.64.0.0/10".into(),
        "169.254.0.0/16".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
        "224.0.0.0/4".into(),
        "240.0.0.0/4".into(),
    ]
}
fn default_reserved_ip6() -> Vec<String> {
    vec![
        "::/128".into(),
        "::1/128".into(),
        "::ffff:0:0/96".into(),
        "100::/64".into(),
        "64:ff9b::/96".into(),
        "2001::/32".into(),
        "2001:10::/28".into(),
        "2001:20::/28".into(),
        "2001:db8::/32".into(),
        "2002::/16".into(),
        "fc00::/7".into(),
        "fe80::/10".into(),
        "ff00::/8".into(),
    ]
}

/// RouterAccessControl 对应 UCI section 'router_access_control'（多实例）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterAccessControl {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub user: Vec<String>,
    #[serde(default)]
    pub group: Vec<String>,
    #[serde(default)]
    pub cgroup: Vec<String>,
    #[serde(default)]
    pub dns: bool,
    #[serde(default)]
    pub proxy: bool,
}

/// LanAccessControl 对应 UCI section 'lan_access_control'（多实例）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanAccessControl {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub ip6: Vec<String>,
    #[serde(default)]
    pub mac: Vec<String>,
    #[serde(default)]
    pub dns: bool,
    #[serde(default)]
    pub proxy: bool,
}

/// RoutingSection 对应 UCI section 'routing'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingSection {
    #[serde(default = "default_tproxy_fw_mark")]
    pub tproxy_fw_mark: String,
    #[serde(default = "default_tproxy_fw_mask")]
    pub tproxy_fw_mask: String,
    #[serde(default = "default_tun_fw_mark")]
    pub tun_fw_mark: String,
    #[serde(default = "default_tun_fw_mask")]
    pub tun_fw_mask: String,
    #[serde(default = "default_tproxy_rule_pref")]
    pub tproxy_rule_pref: i64,
    #[serde(default = "default_tun_rule_pref")]
    pub tun_rule_pref: i64,
    #[serde(default = "default_tproxy_route_table")]
    pub tproxy_route_table: String,
    #[serde(default = "default_tun_route_table")]
    pub tun_route_table: String,
    #[serde(default = "default_cgroup_id")]
    pub cgroup_id: String,
    #[serde(default = "default_cgroup_name")]
    pub cgroup_name: String,
    #[serde(default = "default_dummy_device")]
    pub dummy_device: String,
}

fn default_tproxy_fw_mark() -> String {
    "0x80".to_string()
}
fn default_tproxy_fw_mask() -> String {
    "0xFF".to_string()
}
fn default_tun_fw_mark() -> String {
    "0x81".to_string()
}
fn default_tun_fw_mask() -> String {
    "0xFF".to_string()
}
fn default_tproxy_rule_pref() -> i64 {
    1024
}
fn default_tun_rule_pref() -> i64 {
    1025
}
fn default_tproxy_route_table() -> String {
    "80".to_string()
}
fn default_tun_route_table() -> String {
    "81".to_string()
}
fn default_cgroup_id() -> String {
    "0x07250725".to_string()
}
fn default_cgroup_name() -> String {
    "proxy".to_string()
}
fn default_dummy_device() -> String {
    "proxy-dummy".to_string()
}

/// LogSection 对应 UCI section 'log'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSection {
    #[serde(default = "default_true")]
    pub scheduled_clear: bool,
    #[serde(default = "default_scheduled_clear_cron")]
    pub scheduled_clear_cron: String,
    #[serde(default = "default_scheduled_clear_size_limit")]
    pub scheduled_clear_size_limit: i64,
    #[serde(default = "default_scheduled_clear_size_limit_unit")]
    pub scheduled_clear_size_limit_unit: String, // B|KB|MB|GB
}

fn default_scheduled_clear_cron() -> String {
    "*/5 * * * *".to_string()
}
fn default_scheduled_clear_size_limit() -> i64 {
    1
}
fn default_scheduled_clear_size_limit_unit() -> String {
    "MB".to_string()
}

/// Default 返回与原 proxy.conf 默认值完全一致的配置。
pub fn default_config() -> Config {
    Config {
        config: ConfigSection {
            enabled: false,
            profile: String::new(),
            run_binary: String::new(),
            run_args: String::new(),
            start_delay: 0,
            scheduled_restart: false,
            scheduled_restart_cron: "0 3 * * *".to_string(),
        },
        procd: ProcdSection { fast_reload: false },
        proxy: ProxySection {
            enabled: true,
            ipv4_dns_hijack: true,
            ipv6_dns_hijack: true,
            ipv4_proxy: true,
            ipv6_proxy: true,
            fake_ip_ping_hijack: true,
            tcp_mode: "redirect".to_string(),
            udp_mode: "tun".to_string(),
            router_proxy: true,
            lan_proxy: true,
            lan_inbound_interface: default_lan_inbound_interface(),
            dns_port: "1053".to_string(),
            redir_port: "7892".to_string(),
            tproxy_port: "7893".to_string(),
            tun_device: "tun0".to_string(),
            ui_port: "9090".to_string(),
            ui_path: "ui".to_string(),
            fake_ip_range: "198.18.0.0/15".to_string(),
            fake_ip6_range: "fc00::/18".to_string(),
            reserved_ip: default_reserved_ip(),
            reserved_ip6: default_reserved_ip6(),
            bypass_china_mainland_ip: false,
            bypass_china_mainland_ip6: false,
            proxy_tcp_dport: "0-65535".to_string(),
            proxy_udp_dport: "0-65535".to_string(),
            bypass_dscp: vec!["4".to_string()],
            bypass_cgroup: true,
            bypass_gid: false,
            bypass_mark: false,
            bypass_mark_values: vec![],
            bypass_fwmark: vec![],
            tun_timeout: 30,
            tun_interval: 1,
        },
        router_access_controls: default_router_access_controls(),
        lan_access_controls: vec![LanAccessControl {
            id: "lan-default".to_string(),
            enabled: true,
            ip: vec![],
            ip6: vec![],
            mac: vec![],
            dns: true,
            proxy: true,
        }],
        routing: RoutingSection {
            tproxy_fw_mark: "0x80".to_string(),
            tproxy_fw_mask: "0xFF".to_string(),
            tun_fw_mark: "0x81".to_string(),
            tun_fw_mask: "0xFF".to_string(),
            tproxy_rule_pref: 1024,
            tun_rule_pref: 1025,
            tproxy_route_table: "80".to_string(),
            tun_route_table: "81".to_string(),
            cgroup_id: "0x07250725".to_string(),
            cgroup_name: "proxy".to_string(),
            dummy_device: "proxy-dummy".to_string(),
        },
        log: LogSection {
            scheduled_clear: true,
            scheduled_clear_cron: "*/5 * * * *".to_string(),
            scheduled_clear_size_limit: 1,
            scheduled_clear_size_limit_unit: "MB".to_string(),
        },
    }
}

/// isOpenWrt 检测当前系统是否为 OpenWrt。
pub fn is_openwrt() -> bool {
    std::path::Path::new("/etc/openwrt_release").exists()
}

/// defaultLanInboundInterface 根据系统类型返回局域网入站接口默认值。
/// OpenWrt 用 br-lan/lan；普通 Linux 自动探测活动物理网卡。
pub fn default_lan_inbound_interface() -> Vec<String> {
    if is_openwrt() {
        return vec!["lan".to_string()];
    }
    // 普通 Linux：探测活动网卡
    let result = crate::sysutil::list_active_physical_ifaces();
    if result.is_empty() {
        vec!["eth0".to_string()]
    } else {
        result
    }
}

/// defaultRouterAccessControls 根据系统类型返回本机代理默认规则。
fn default_router_access_controls() -> Vec<RouterAccessControl> {
    if is_openwrt() {
        vec![
            RouterAccessControl {
                id: "router-default-bypass".to_string(),
                enabled: true,
                user: vec![
                    "dnsmasq".into(),
                    "ftp".into(),
                    "logd".into(),
                    "nobody".into(),
                    "ntp".into(),
                    "ubus".into(),
                ],
                group: vec![
                    "dnsmasq".into(),
                    "ftp".into(),
                    "logd".into(),
                    "nogroup".into(),
                    "ntp".into(),
                    "ubus".into(),
                ],
                cgroup: vec![
                    "services/adguardhome".into(),
                    "services/aria2".into(),
                    "services/dnsmasq".into(),
                    "services/netbird".into(),
                    "services/qbittorrent".into(),
                    "services/sysntpd".into(),
                    "services/tailscale".into(),
                    "services/zerotier".into(),
                ],
                dns: false,
                proxy: false,
            },
            RouterAccessControl {
                id: "router-default-proxy".to_string(),
                enabled: true,
                user: vec![],
                group: vec![],
                cgroup: vec![],
                dns: true,
                proxy: true,
            },
        ]
    } else {
        // 普通 Linux (systemd)
        vec![
            RouterAccessControl {
                id: "router-default-bypass".to_string(),
                enabled: true,
                user: vec![
                    "nobody".into(),
                    "systemd-network".into(),
                    "systemd-resolve".into(),
                ],
                group: vec![
                    "nogroup".into(),
                    "systemd-network".into(),
                    "systemd-resolve".into(),
                ],
                cgroup: vec![
                    "system.slice/systemd-resolved.service".into(),
                    "system.slice/systemd-networkd.service".into(),
                    "system.slice/NetworkManager.service".into(),
                    "system.slice/sshd.service".into(),
                ],
                dns: false,
                proxy: false,
            },
            RouterAccessControl {
                id: "router-default-proxy".to_string(),
                enabled: true,
                user: vec![],
                group: vec![],
                cgroup: vec![],
                dns: true,
                proxy: true,
            },
        ]
    }
}
