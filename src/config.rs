//! 配置模型，1:1 对齐 Go 版 internal/config（原 UCI proxy 配置）。

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::cgroupsupport;
use crate::identifiers;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub config: ConfigSection,
    #[serde(default)]
    pub procd: ProcdSection,
    #[serde(default)]
    pub proxy: ProxySection,
    #[serde(default)]
    pub router_access_controls: Vec<RouterAccessControl>,
    #[serde(default)]
    pub lan_access_controls: Vec<LanAccessControl>,
    #[serde(default)]
    pub routing: RoutingSection,
    #[serde(default)]
    pub log: LogSection,
}

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
    /// 候选列表：设置页以 chip 形式展开展示、可删除、可添加；启动配置页下拉选项与之同源。
    /// null 表示用户从未修改过（前端展示动态默认值）；[] 表示用户已清空（保持为空）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_list: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_list: Option<Vec<String>>,
    /// 运行目录，空 = 默认 <数据目录>/run；非空必须为绝对路径
    #[serde(default)]
    pub run_dir: String,
    #[serde(default)]
    pub start_delay: i32,
    #[serde(default)]
    pub scheduled_restart: bool,
    #[serde(default)]
    pub scheduled_restart_cron: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcdSection {
    #[serde(default)]
    pub fast_reload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ipv4_dns_hijack: bool,
    #[serde(default)]
    pub ipv6_dns_hijack: bool,
    #[serde(default)]
    pub ipv4_proxy: bool,
    #[serde(default)]
    pub ipv6_proxy: bool,
    #[serde(default)]
    pub fake_ip_ping_hijack: bool,
    #[serde(default)]
    pub tcp_mode: String, // redirect | tproxy | tun
    #[serde(default)]
    pub udp_mode: String,
    #[serde(default)]
    pub router_proxy: bool,
    #[serde(default)]
    pub lan_proxy: bool,
    #[serde(default)]
    pub lan_inbound_interface: Vec<String>,
    #[serde(default)]
    pub dns_port: String,
    #[serde(default)]
    pub redir_port: String,
    #[serde(default)]
    pub tproxy_port: String,
    #[serde(default)]
    pub tun_device: String,
    #[serde(default)]
    pub ui_port: String,
    #[serde(default)]
    pub ui_path: String,
    #[serde(default)]
    pub fake_ip_range: String,
    #[serde(default)]
    pub fake_ip6_range: String,
    #[serde(default)]
    pub reserved_ip: Vec<String>,
    #[serde(default)]
    pub reserved_ip6: Vec<String>,
    #[serde(default)]
    pub bypass_china_mainland_ip: bool,
    #[serde(default)]
    pub bypass_china_mainland_ip6: bool,
    #[serde(default)]
    pub proxy_tcp_dport: String,
    #[serde(default)]
    pub proxy_udp_dport: String,
    #[serde(default)]
    pub bypass_dscp: Vec<String>,
    #[serde(default)]
    pub bypass_fwmark: Vec<String>,
    #[serde(default)]
    pub bypass_cgroup: bool,
    #[serde(default)]
    pub bypass_gid: bool,
    #[serde(default)]
    pub bypass_mark: bool,
    #[serde(default)]
    pub bypass_mark_values: Vec<String>,
    #[serde(default)]
    pub tun_timeout: i32,
    #[serde(default)]
    pub tun_interval: i32,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingSection {
    #[serde(default)]
    pub tproxy_fw_mark: String,
    #[serde(default)]
    pub tproxy_fw_mask: String,
    #[serde(default)]
    pub tun_fw_mark: String,
    #[serde(default)]
    pub tun_fw_mask: String,
    #[serde(default)]
    pub tproxy_rule_pref: i32,
    #[serde(default)]
    pub tun_rule_pref: i32,
    #[serde(default)]
    pub tproxy_route_table: String,
    #[serde(default)]
    pub tun_route_table: String,
    #[serde(default)]
    pub cgroup_id: String,
    #[serde(default)]
    pub cgroup_name: String,
    #[serde(default)]
    pub dummy_device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSection {
    #[serde(default)]
    pub scheduled_clear: bool,
    #[serde(default)]
    pub scheduled_clear_cron: String,
    #[serde(default)]
    pub scheduled_clear_size_limit: i32,
    #[serde(default)]
    pub scheduled_clear_size_limit_unit: String, // B|KB|MB|GB
}

// ── 默认值 ────────────────────────────────────────────

impl Default for Config {
    fn default() -> Self {
        Self {
            config: ConfigSection::default(),
            procd: ProcdSection { fast_reload: false },
            proxy: ProxySection::default(),
            router_access_controls: default_router_access_controls(),
            lan_access_controls: vec![LanAccessControl {
                id: "lan-default".into(),
                enabled: true,
                ip: Vec::new(),
                ip6: Vec::new(),
                mac: Vec::new(),
                dns: true,
                proxy: true,
            }],
            routing: RoutingSection::default(),
            log: LogSection::default(),
        }
    }
}

impl Default for ConfigSection {
    fn default() -> Self {
        Self {
            enabled: false,
            profile: String::new(),
            run_binary: String::new(),
            run_args: String::new(),
            binary_list: None,
            args_list: None,
            run_dir: String::new(),
            start_delay: 0,
            scheduled_restart: false,
            scheduled_restart_cron: "0 3 * * *".into(),
        }
    }
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            enabled: true,
            ipv4_dns_hijack: true,
            ipv6_dns_hijack: true,
            ipv4_proxy: true,
            ipv6_proxy: true,
            fake_ip_ping_hijack: true,
            tcp_mode: "tproxy".into(),
            udp_mode: "tproxy".into(),
            router_proxy: true,
            lan_proxy: true,
            lan_inbound_interface: default_lan_inbound_interface(),
            dns_port: "5353".into(),
            redir_port: "7876".into(),
            tproxy_port: "7878".into(),
            tun_device: "tun0".into(),
            ui_port: "9090".into(),
            ui_path: "ui".into(),
            fake_ip_range: "198.18.0.0/15".into(),
            fake_ip6_range: "fc00::/18".into(),
            reserved_ip: vec![
                "0.0.0.0/8",
                "10.0.0.0/8",
                "127.0.0.0/8",
                "100.64.0.0/10",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "224.0.0.0/4",
                "240.0.0.0/4",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            reserved_ip6: vec![
                "::/128",
                "::1/128",
                "::ffff:0:0/96",
                "100::/64",
                "64:ff9b::/96",
                "2001::/32",
                "2001:10::/28",
                "2001:20::/28",
                "2001:db8::/32",
                "2002::/16",
                "fc00::/7",
                "fe80::/10",
                "ff00::/8",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            bypass_china_mainland_ip: false,
            bypass_china_mainland_ip6: false,
            proxy_tcp_dport: "0-65535".into(),
            proxy_udp_dport: "0-65535".into(),
            bypass_dscp: vec!["4".into()],
            bypass_fwmark: Vec::new(),
            bypass_cgroup: default_bypass_cgroup(),
            bypass_gid: default_bypass_gid(),
            bypass_mark: false,
            bypass_mark_values: Vec::new(),
            tun_timeout: 30,
            tun_interval: 1,
        }
    }
}

impl Default for RoutingSection {
    fn default() -> Self {
        Self {
            tproxy_fw_mark: "0x80".into(),
            tproxy_fw_mask: "0xFF".into(),
            tun_fw_mark: "0x81".into(),
            tun_fw_mask: "0xFF".into(),
            tproxy_rule_pref: 1024,
            tun_rule_pref: 1025,
            tproxy_route_table: "80".into(),
            tun_route_table: "81".into(),
            cgroup_id: "0x07250725".into(),
            cgroup_name: "proxy".into(),
            dummy_device: "proxy-dummy".into(),
        }
    }
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            scheduled_clear: true,
            scheduled_clear_cron: "*/5 * * * *".into(),
            scheduled_clear_size_limit: 1,
            scheduled_clear_size_limit_unit: "MB".into(),
        }
    }
}

/// 根据系统类型返回本机代理默认规则。
fn default_router_access_controls() -> Vec<RouterAccessControl> {
    if identifiers::is_openwrt() {
        return vec![
            RouterAccessControl {
                id: "router-default-bypass".into(),
                enabled: true,
                user: vec!["dnsmasq", "ftp", "logd", "nobody", "ntp", "ubus"]
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect(),
                group: vec!["dnsmasq", "ftp", "logd", "nogroup", "ntp", "ubus"]
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect(),
                cgroup: vec![
                    "services/adguardhome",
                    "services/aria2",
                    "services/dnsmasq",
                    "services/netbird",
                    "services/qbittorrent",
                    "services/sysntpd",
                    "services/tailscale",
                    "services/zerotier",
                ]
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
                dns: false,
                proxy: false,
            },
            RouterAccessControl {
                id: "router-default-proxy".into(),
                enabled: true,
                user: Vec::new(),
                group: Vec::new(),
                cgroup: Vec::new(),
                dns: true,
                proxy: true,
            },
        ];
    }
    // 普通 Linux (systemd)
    vec![
        RouterAccessControl {
            id: "router-default-bypass".into(),
            enabled: true,
            user: vec!["nobody", "systemd-network", "systemd-resolve", "_chrony", "sshd"]
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
            group: vec!["nogroup", "systemd-network", "systemd-resolve", "_chrony", "_ssh"]
                .into_iter()
                .map(|s| s.to_string())
                .collect(),
            cgroup: vec![
                "system.slice/systemd-resolved.service",
                "system.slice/systemd-networkd.service",
                "system.slice/NetworkManager.service",
                "system.slice/sshd.service",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
            dns: false,
            proxy: false,
        },
        RouterAccessControl {
            id: "router-default-proxy".into(),
            enabled: true,
            user: Vec::new(),
            group: Vec::new(),
            cgroup: Vec::new(),
            dns: true,
            proxy: true,
        },
    ]
}

/// 仅当系统实际支持 cgroup（v1 net_cls 或 v2 且挂载点可写）时才默认开启，
/// 与 default_bypass_gid 互补：cgroup 不支持的系统上，防回环完全依赖 GID 绕过。
fn default_bypass_cgroup() -> bool {
    cgroupsupport::supported()
}

/// GID 绕过是程序唯一可完全控制、且所有 Linux 系统都支持的防回环方式
/// （核心进程主 GID 由 nexa 自己创建的系统组决定，不依赖内核 cgroup 特性）。
/// 系统不支持 cgroup 时必须默认打开；支持时默认关闭，避免叠加两套冗余规则。
fn default_bypass_gid() -> bool {
    !cgroupsupport::supported()
}

/// 根据系统类型返回局域网入站接口默认值。
/// OpenWrt 用 lan；普通 Linux 自动探测活动物理网卡。
fn default_lan_inbound_interface() -> Vec<String> {
    if identifiers::is_openwrt() {
        return vec!["lan".into()];
    }
    let entries = match std::fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return vec!["eth0".into()],
    };
    let mut result = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        // 跳过已知的虚拟接口
        if ["docker", "br-", "veth", "virbr", "tun", "wg", "lo"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        // 跳过 loopback（type == 772）
        if let Ok(t) = std::fs::read_to_string(path.join("type")) {
            if t.trim() == "772" {
                continue;
            }
        }
        // 跳过未启用的接口（flags & IFF_UP）
        let up = std::fs::read_to_string(path.join("flags"))
            .map(|s| parse_hex_u32(s.trim()) & 0x1 != 0)
            .unwrap_or(false);
        if !up {
            continue;
        }
        result.push(name);
    }
    result.sort();
    if result.is_empty() {
        return vec!["eth0".into()];
    }
    result
}

fn parse_hex_u32(s: &str) -> u32 {
    u32::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0)
}

#[allow(dead_code)]
fn path_exists(p: &str) -> bool {
    Path::new(p).exists()
}
