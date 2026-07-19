//! 收集局域网主机列表（IP/IPv6/MAC），对齐原 momo include.uc 的 get_host_hints。

use std::net::IpAddr;
use std::process::Command;

use serde::Serialize;

/// Host 表示一台局域网主机。
#[derive(Debug, Serialize, Clone, Default)]
pub struct Host {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub ip6: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub name: String,
}

/// Hosts 是 /api/hosts 返回的结构。
#[derive(Debug, Serialize)]
pub struct Hosts {
    pub ip: Vec<String>,
    pub ip6: Vec<String>,
    pub mac: Vec<String>,
    pub list: Vec<Host>,
}

/// dhcpLeaseFiles 是常见的 DHCP 租约文件路径。
const DHCP_LEASE_FILES: &[&str] = &[
    "/tmp/dhcp.leases",            // OpenWrt dnsmasq
    "/var/lib/misc/dnsmasq.leases", // Debian/Ubuntu dnsmasq
    "/var/db/dhcpd.leases",         // ISC dhcpd
];

/// Get 收集局域网主机信息。
pub fn get() -> Hosts {
    let mut h = Hosts {
        ip: vec![],
        ip6: vec![],
        mac: vec![],
        list: vec![],
    };
    let mut by_mac: std::collections::HashMap<String, Host> = std::collections::HashMap::new();
    let mut no_mac: Vec<Host> = vec![];

    // 1. DHCP 租约
    for p in DHCP_LEASE_FILES {
        read_lease_file(p, add_host, &mut by_mac, &mut no_mac);
    }
    // 2. ARP / 邻居表（IPv4）
    read_neigh(true, add_host, &mut by_mac, &mut no_mac);
    // 3. 邻居表（IPv6）
    read_neigh(false, add_host, &mut by_mac, &mut no_mac);

    // 合并到 List
    for (_, e) in by_mac.into_iter() {
        h.list.push(e);
    }
    h.list.append(&mut no_mac);

    // 汇总 IP/IP6/MAC 列表（去重）
    let mut seen_ip = std::collections::HashSet::new();
    let mut seen_ip6 = std::collections::HashSet::new();
    let mut seen_mac = std::collections::HashSet::new();
    for e in &h.list {
        if !e.ip.is_empty() && !seen_ip.contains(&e.ip) && is_ipv4(&e.ip) {
            seen_ip.insert(e.ip.clone());
            h.ip.push(e.ip.clone());
        }
        if !e.ip6.is_empty() && !seen_ip6.contains(&e.ip6) && is_ipv6(&e.ip6) {
            seen_ip6.insert(e.ip6.clone());
            h.ip6.push(e.ip6.clone());
        }
        if !e.mac.is_empty() && !seen_mac.contains(&e.mac) {
            seen_mac.insert(e.mac.clone());
            h.mac.push(e.mac.clone());
        }
    }
    h
}

type AddFn = fn(&str, &str, &str, &mut std::collections::HashMap<String, Host>, &mut Vec<Host>);

/// addHost 把一条 (mac, ip, name) 合并到 by_mac / no_mac。
/// 不捕获任何环境，故可作 fn 指针传递。
fn add_host(
    mac: &str,
    ip: &str,
    name: &str,
    by_mac: &mut std::collections::HashMap<String, Host>,
    no_mac: &mut Vec<Host>,
) {
    if mac.is_empty() && ip.is_empty() {
        return;
    }
    if !mac.is_empty() {
        if let Some(e) = by_mac.get_mut(mac) {
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
        by_mac.insert(mac.to_string(), e);
        return;
    }
    // 无 MAC
    let mut e = Host {
        ip: ip.to_string(),
        name: name.to_string(),
        ..Default::default()
    };
    if is_ipv6(ip) {
        e.ip = String::new();
        e.ip6 = ip.to_string();
    }
    no_mac.push(e);
}

fn read_lease_file(path: &str, add: AddFn, by_mac: &mut std::collections::HashMap<String, Host>, no_mac: &mut Vec<Host>) {
    let data = match std::fs::read_to_string(path) {
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
        let mut mac = String::new();
        let mut ip = String::new();
        let mut name = String::new();
        // 找到 MAC 字段
        for f in &fields {
            if is_mac(f) && mac.is_empty() {
                mac = f.to_string();
                break;
            }
        }
        // IP 字段
        for f in &fields {
            if !mac.is_empty() && *f != mac && is_ip(f) {
                ip = f.to_string();
                break;
            }
        }
        // hostname
        for f in &fields {
            if *f == mac || *f == ip || *f == "*" || is_ip(f) || is_unix_timestamp(f) {
                continue;
            }
            if name.is_empty() {
                name = f.to_string();
            }
        }
        if mac.is_empty() && ip.is_empty() {
            continue;
        }
        add(&mac, &ip, &name, by_mac, no_mac);
    }
}

fn read_neigh(v4: bool, add: AddFn, by_mac: &mut std::collections::HashMap<String, Host>, no_mac: &mut Vec<Host>) {
    let out = if v4 {
        Command::new("ip").arg("neigh").output()
    } else {
        Command::new("ip").args(["-6", "neigh"]).output()
    };
    let out = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return,
    };
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let ip = fields[0];
        if ip.is_empty() || !is_ip(ip) {
            continue;
        }
        if is_link_local(ip) {
            continue;
        }
        let mut mac = String::new();
        for i in 0..fields.len().saturating_sub(1) {
            if fields[i] == "lladdr" && is_mac(fields[i + 1]) {
                mac = fields[i + 1].to_string();
                break;
            }
        }
        if mac.is_empty() {
            continue;
        }
        add(&mac, ip, "", by_mac, no_mac);
    }
}

fn is_ipv4(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => true,
        _ => false,
    }
}

fn is_ipv6(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => true,
        _ => false,
    }
}

fn is_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

fn is_mac(s: &str) -> bool {
    // 简单校验：xx:xx:xx:xx:xx:xx
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// isLinkLocal 判断 IPv6 链路本地地址（fe80::/10）或 IPv4 APIPA（169.254.0.0/16）。
fn is_link_local(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let o = v4.octets();
            o[0] == 169 && o[1] == 254
        }
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            s[0] & 0xffc0 == 0xfe80
        }
        Err(_) => false,
    }
}

/// isUnixTimestamp 判断字符串是否为纯数字时间戳。
fn is_unix_timestamp(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}
