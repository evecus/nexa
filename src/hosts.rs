//! 局域网主机收集（IP/IPv6/MAC），对齐 Go 版 internal/hosts（原 momo include.uc 的 get_host_hints）。
//!
//! 数据来源：
//!  1. DHCP 租约文件（OpenWrt: /tmp/dhcp.leases；通用 Linux: /var/lib/misc/dnsmasq.leases；ISC dhcpd: /var/db/dhcpd.leases）
//!  2. ARP / 邻居表（ip neigh、ip -6 neigh）
//!
//! 合并去重后返回结构化数据，供前端「局域网代理」访问控制字段下拉选项使用。

use serde::Serialize;
use std::fs;
use std::net::IpAddr;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Host {
    pub ip: String,
    pub ip6: String,
    pub mac: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Hosts {
    pub ip: Vec<String>,
    pub ip6: Vec<String>,
    pub mac: Vec<String>,
    pub list: Vec<Host>,
}

/// 常见的 DHCP 租约文件路径。
const DHCP_LEASE_FILES: &[&str] = &[
    "/tmp/dhcp.leases",             // OpenWrt dnsmasq
    "/var/lib/misc/dnsmasq.leases", // Debian/Ubuntu dnsmasq
    "/var/db/dhcpd.leases",         // ISC dhcpd
];

pub fn collect() -> Hosts {
    let mut by_mac: Vec<(String, Host)> = Vec::new(); // 保持插入顺序，同时按 MAC 归并
    let mut no_mac: Vec<Host> = Vec::new();

    let mut add = |mac: &str, ip: &str, name: &str| {
        if mac.is_empty() && ip.is_empty() {
            return;
        }
        if !mac.is_empty() {
            if let Some((_, e)) = by_mac.iter_mut().find(|(m, _)| m == mac) {
                if !ip.is_empty() {
                    if is_ipv4(ip) && e.ip.is_empty() {
                        e.ip = ip.to_string();
                    } else if is_ipv6(ip) && e.ip6.is_empty() {
                        e.ip6 = ip.to_string();
                    }
                }
                if !name.is_empty() && e.name.is_empty() {
                    e.name = name.to_string();
                }
                return;
            }
            let mut e = Host {
                mac: mac.to_string(),
                name: name.to_string(),
                ..Default::default()
            };
            if !ip.is_empty() {
                if is_ipv4(ip) {
                    e.ip = ip.to_string();
                } else if is_ipv6(ip) {
                    e.ip6 = ip.to_string();
                }
            }
            by_mac.push((mac.to_string(), e));
            return;
        }
        // 无 MAC 的记录（罕见，如 ip neigh 中无 lladdr 的条目）单独存放。
        let mut e = Host {
            ip: ip.to_string(),
            name: name.to_string(),
            ..Default::default()
        };
        if is_ipv6(ip) {
            e.ip.clear();
            e.ip6 = ip.to_string();
        }
        no_mac.push(e);
    };

    for p in DHCP_LEASE_FILES {
        read_lease_file(p, &mut add);
    }
    read_neigh(true, &mut add);
    read_neigh(false, &mut add);

    let mut h = Hosts::default();
    for (_, e) in by_mac {
        h.list.push(e);
    }
    for e in no_mac {
        h.list.push(e);
    }

    // 汇总 IP/IP6/MAC 列表（去重）
    for e in &h.list {
        if !e.ip.is_empty() && is_ipv4(&e.ip) && !h.ip.contains(&e.ip) {
            h.ip.push(e.ip.clone());
        }
        if !e.ip6.is_empty() && is_ipv6(&e.ip6) && !h.ip6.contains(&e.ip6) {
            h.ip6.push(e.ip6.clone());
        }
        if !e.mac.is_empty() && !h.mac.contains(&e.mac) {
            h.mac.push(e.mac.clone());
        }
    }
    h
}

/// 解析 DHCP 租约文件，兼容 OpenWrt /tmp/dhcp.leases 与 dnsmasq /var/lib/misc/dnsmasq.leases 两种格式。
fn read_lease_file(path: &str, add: &mut dyn FnMut(&str, &str, &str)) {
    let data = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return,
    };
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let mut mac = "";
        for fld in &fields {
            if is_mac(fld) && mac.is_empty() {
                mac = fld;
            }
        }
        let mut ip = "";
        if !mac.is_empty() {
            for fld in &fields {
                if *fld != mac && is_ip(fld) {
                    ip = fld;
                    break;
                }
            }
        }
        let mut name = "";
        for fld in &fields {
            if *fld == mac || *fld == ip || *fld == "*" || is_ip(fld) || is_unix_timestamp(fld) {
                continue;
            }
            if name.is_empty() {
                name = fld;
            }
        }
        if mac.is_empty() && ip.is_empty() {
            continue;
        }
        add(mac, ip, name);
    }
}

/// 执行 ip neigh 或 ip -6 neigh 解析邻居表。
fn read_neigh(v4: bool, add: &mut dyn FnMut(&str, &str, &str)) {
    let args: &[&str] = if v4 { &["neigh"] } else { &["-6", "neigh"] };
    let out = match Command::new("ip").args(args).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return,
    };
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 格式：<IP> dev <DEV> lladdr <MAC> [REACHABLE|STALE|DELAY|...]
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let ip = fields[0];
        if ip.is_empty() || !is_ip(ip) {
            continue;
        }
        // 跳过本地链路地址和本机地址
        if is_link_local(ip) {
            continue;
        }
        let mut mac = "";
        for i in 0..fields.len().saturating_sub(1) {
            if fields[i] == "lladdr" && is_mac(fields[i + 1]) {
                mac = fields[i + 1];
                break;
            }
        }
        if mac.is_empty() {
            continue;
        }
        add(mac, ip, "");
    }
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok()
}

fn is_ipv4(s: &str) -> bool {
    matches!(parse_ip(s), Some(IpAddr::V4(_)))
}

fn is_ipv6(s: &str) -> bool {
    matches!(parse_ip(s), Some(IpAddr::V6(_)))
}

fn is_ip(s: &str) -> bool {
    parse_ip(s).is_some()
}

fn is_mac(s: &str) -> bool {
    // Go 的 net.ParseMAC 接受 "aa:bb:cc:dd:ee:ff"（也可接受带 '-' 的 EUI-48）
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// 判断 IPv6 链路本地地址（fe80::/10）或 IPv4 APIPA（169.254.0.0/16）。
fn is_link_local(s: &str) -> bool {
    match parse_ip(s) {
        Some(IpAddr::V4(v4)) => {
            let o = v4.octets();
            o[0] == 169 && o[1] == 254
        }
        Some(IpAddr::V6(v6)) => {
            let o = v6.octets();
            o[0] == 0xfe && (o[1] & 0xc0) == 0x80
        }
        None => false,
    }
}

/// 判断字符串是否为纯数字时间戳（dnsmasq 行首字段）。
fn is_unix_timestamp(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}
