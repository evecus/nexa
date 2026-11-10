//! nftables 劫持表生成，规则文本 1:1 对齐 Go 版 internal/nfttemplate（原 hijack.ut）。
//!
//! 原实现用 Go text/template；这里改为直接拼字符串，行为保持一致。

use crate::config::Config;

use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct Model {
    pub dns_hijack_nfproto: Vec<String>,
    pub proxy_nfproto: Vec<String>,
    pub reserved_ip: Vec<String>,
    pub reserved_ip6: Vec<String>,
    pub lan_inbound_device: Vec<String>,
    /// 形如 "tcp . 0-65535"
    pub proxy_dport: Vec<String>,
    pub bypass_dscp: Vec<String>,
    pub bypass_fwmark: Vec<Fwmark>,

    pub router_proxy: bool,
    pub router_access_controls: Vec<AccessControlView>,
    pub lan_proxy: bool,
    pub lan_access_controls: Vec<AccessControlView>,

    pub redir_port: String,
    pub tproxy_port: String,
    pub tun_device: String,
    pub dns_port: String,
    pub fake_ip_range: String,
    pub fake_ip6_range: String,

    pub tcp_mode: String,
    pub udp_mode: String,

    pub fake_ip_ping_hijack: bool,

    /// 1 或 2
    pub cgroups_version: i32,
    pub cgroup_id: String,
    pub cgroup_name: String,
    /// 核心进程的 GID，用于 BypassGid
    pub core_gid: String,

    pub bypass_cgroup: bool,
    pub bypass_gid: bool,
    pub bypass_mark: bool,
    pub bypass_mark_values: Vec<String>,

    pub tproxy_fw_mark: String,
    pub tproxy_fw_mask: String,
    pub tproxy_fw_umask: String,
    pub tun_fw_mark: String,
    /// 原模板未使用 tun mask（tun 模式不经过 tproxy 的 mark 匹配链），保留字段对齐 Go 版 Model。
    #[allow(dead_code)]
    pub tun_fw_mask: String,
    pub tun_fw_umask: String,

    /// bypass 开启时从 geoip 文件提取的 elements 列表，注入 china_ip / china_ip6 集合。
    pub china_ip_elements: String,
    pub china_ip6_elements: String,

    /// dns_hijack / proxy 是否启用对应协议族（对齐原 ipv4_dns_hijack/ipv4_proxy 布尔判断）
    pub dns_hijack_nfproto_has4: bool,
    pub dns_hijack_nfproto_has6: bool,
    pub proxy_nfproto_has4: bool,
    pub proxy_nfproto_has6: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AccessControlView {
    /// 原模板只消费过滤后的规则（Build 里已按 enabled 过滤），字段保留对齐 Go 版 Model。
    #[allow(dead_code)]
    pub enabled: bool,
    pub user: Vec<String>,
    pub group: Vec<String>,
    pub cgroup: Vec<String>,
    pub ip: Vec<String>,
    pub ip6: Vec<String>,
    pub mac: Vec<String>,
    pub dns: bool,
    pub proxy: bool,
}

#[derive(Debug, Clone)]
pub struct Fwmark {
    pub mark: String,
    pub mask: String,
}

/// 按 cfg + lan 设备 + cgroup 版本构造 Model（对齐 Go 版 Build）。
pub fn build(cfg: &Config, lan_inbound_device: &[String], cgroups_version: i32) -> Model {
    let p = &cfg.proxy;

    let mut dns_nf = Vec::new();
    if p.ipv4_dns_hijack {
        dns_nf.push("ipv4".into());
    }
    if p.ipv6_dns_hijack {
        dns_nf.push("ipv6".into());
    }
    let mut proxy_nf = Vec::new();
    if p.ipv4_proxy {
        proxy_nf.push("ipv4".into());
    }
    if p.ipv6_proxy {
        proxy_nf.push("ipv6".into());
    }

    // proxy_dport
    let mut proxy_dport = Vec::new();
    for port in split_space(&p.proxy_tcp_dport) {
        proxy_dport.push(format!("tcp . {}", port));
    }
    for port in split_space(&p.proxy_udp_dport) {
        proxy_dport.push(format!("udp . {}", port));
    }

    // bypass_fwmark
    let mut fwmarks = Vec::new();
    for fm in &p.bypass_fwmark {
        let (mark, mask) = match fm.find('/') {
            Some(i) => (fm[..i].to_string(), fm[i + 1..].to_string()),
            None => (fm.clone(), "0xFFFFFFFF".to_string()),
        };
        fwmarks.push(Fwmark { mark, mask });
    }

    Model {
        dns_hijack_nfproto: dns_nf,
        proxy_nfproto: proxy_nf,
        reserved_ip: p.reserved_ip.clone(),
        reserved_ip6: p.reserved_ip6.clone(),
        lan_inbound_device: lan_inbound_device.to_vec(),
        proxy_dport,
        bypass_dscp: p.bypass_dscp.clone(),
        bypass_fwmark: fwmarks,
        router_proxy: p.router_proxy,
        router_access_controls: build_router_views(cfg),
        lan_proxy: p.lan_proxy,
        lan_access_controls: build_lan_views(cfg),
        redir_port: p.redir_port.clone(),
        tproxy_port: p.tproxy_port.clone(),
        tun_device: p.tun_device.clone(),
        dns_port: p.dns_port.clone(),
        fake_ip_range: p.fake_ip_range.clone(),
        fake_ip6_range: p.fake_ip6_range.clone(),
        tcp_mode: p.tcp_mode.clone(),
        udp_mode: p.udp_mode.clone(),
        fake_ip_ping_hijack: p.fake_ip_ping_hijack,
        cgroups_version,
        cgroup_id: cfg.routing.cgroup_id.clone(),
        cgroup_name: cfg.routing.cgroup_name.clone(),
        core_gid: lookup_core_gid(),
        bypass_cgroup: p.bypass_cgroup && cgroups_version != 0,
        bypass_gid: p.bypass_gid || cgroups_version == 0,
        bypass_mark: p.bypass_mark,
        bypass_mark_values: p.bypass_mark_values.clone(),
        tproxy_fw_mark: cfg.routing.tproxy_fw_mark.clone(),
        tproxy_fw_mask: cfg.routing.tproxy_fw_mask.clone(),
        tproxy_fw_umask: umask(&cfg.routing.tproxy_fw_mask),
        tun_fw_mark: cfg.routing.tun_fw_mark.clone(),
        tun_fw_mask: cfg.routing.tun_fw_mask.clone(),
        tun_fw_umask: umask(&cfg.routing.tun_fw_mask),
        dns_hijack_nfproto_has4: p.ipv4_dns_hijack,
        dns_hijack_nfproto_has6: p.ipv6_dns_hijack,
        proxy_nfproto_has4: p.ipv4_proxy,
        proxy_nfproto_has6: p.ipv6_proxy,
        china_ip_elements: String::new(),
        china_ip6_elements: String::new(),
    }
}

/// 返回核心进程防回环用的固定数字 GID（对齐 Go 版 lookupCoreGID）。
/// 不再查找/创建系统组：内核 skgid 匹配只需要数字。
pub fn lookup_core_gid() -> String {
    crate::config::CORE_BYPASS_GID.to_string()
}

fn build_router_views(cfg: &Config) -> Vec<AccessControlView> {
    cfg.router_access_controls
        .iter()
        .filter(|ac| ac.enabled)
        .map(|ac| AccessControlView {
            enabled: true,
            user: filter_existing_users(&ac.user),
            group: filter_existing_groups(&ac.group),
            cgroup: filter_existing_cgroups(&ac.cgroup),
            dns: ac.dns,
            proxy: ac.proxy,
            ..Default::default()
        })
        .collect()
}

fn build_lan_views(cfg: &Config) -> Vec<AccessControlView> {
    cfg.lan_access_controls
        .iter()
        .filter(|ac| ac.enabled)
        .map(|ac| AccessControlView {
            enabled: true,
            ip: ac.ip.clone(),
            ip6: ac.ip6.clone(),
            mac: ac.mac.clone(),
            dns: ac.dns,
            proxy: ac.proxy,
            ..Default::default()
        })
        .collect()
}

/// 过滤掉 /sys/fs/cgroup/ 下不存在的 cgroup 路径，避免 nft 加载时因 cgroupv2 path 不存在而失败。
fn filter_existing_cgroups(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| !p.is_empty())
        .filter(|p| {
            let full = format!("/sys/fs/cgroup/{}", p.trim_start_matches('/'));
            Path::new(&full).is_dir()
        })
        .cloned()
        .collect()
}

fn filter_existing_users(users: &[String]) -> Vec<String> {
    users
        .iter()
        .filter(|u| !u.is_empty() && nss_user_exists(u))
        .cloned()
        .collect()
}

fn filter_existing_groups(groups: &[String]) -> Vec<String> {
    groups
        .iter()
        .filter(|g| !g.is_empty() && nss_group_exists(g))
        .cloned()
        .collect()
}

/// 对齐 Go os/user.Lookup / LookupGroup：走系统 NSS（/etc/passwd、LDAP、sss 等），
/// 而不是只读 /etc/passwd /etc/group 两个文件。
#[cfg(unix)]
fn nss_lookup(name: &str, group: bool) -> bool {
    use std::ffi::CString;
    use std::os::raw::c_char;
    let cname = match CString::new(name) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut buf = vec![0u8; 16 * 1024];
    if group {
        let mut ent: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                cname.as_ptr(),
                &mut ent,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        rc == 0 && !result.is_null()
    } else {
        let mut ent: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut ent,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        rc == 0 && !result.is_null()
    }
}

#[cfg(unix)]
fn nss_user_exists(name: &str) -> bool {
    nss_lookup(name, false)
}

#[cfg(unix)]
fn nss_group_exists(name: &str) -> bool {
    nss_lookup(name, true)
}

#[cfg(not(unix))]
fn nss_user_exists(name: &str) -> bool {
    let data = match std::fs::read_to_string("/etc/passwd") {
        Ok(s) => s,
        Err(_) => return false,
    };
    data.lines().any(|l| l.split_once(':').map(|(u, _)| u) == Some(name))
}

#[cfg(not(unix))]
fn nss_group_exists(name: &str) -> bool {
    let data = match std::fs::read_to_string("/etc/group") {
        Ok(s) => s,
        Err(_) => return false,
    };
    data.lines().any(|l| l.split_once(':').map(|(g, _)| g) == Some(name))
}

/// fw4.hex(~mask & 0xFFFFFFFF)
pub fn umask(mask_hex: &str) -> String {
    // Go 版只去小写 "0x" 前缀，这里保持一致。
    let trimmed = mask_hex.trim_start_matches("0x");
    if trimmed.is_empty() {
        return "0xFFFFFFFF".into();
    }
    match u32::from_str_radix(trimmed, 16) {
        Ok(v) => format!("0x{:08X}", !v),
        Err(_) => "0xFFFFFFFF".into(),
    }
}

fn split_space(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

fn join(arr: &[String], sep: &str) -> String {
    arr.join(sep)
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn qjoin(arr: &[String]) -> String {
    arr.iter().map(|s| quote(s)).collect::<Vec<_>>().join(", ")
}

/// cgroup 路径层级数（原模板的 clen：split(s, "/") 的长度）
fn clen(s: &str) -> usize {
    s.split('/').count()
}

fn is_empty_all3(a: &[String], b: &[String], c: &[String]) -> bool {
    a.is_empty() && b.is_empty() && c.is_empty()
}

// ── 渲染 ──────────────────────────────────────────────

pub fn render(m: &Model) -> String {
    let mut o = String::new();
    o.push_str("table inet nexa {\n");

    // ── sets ──
    o.push_str(&set_block(
        "dns_hijack_nfproto",
        "nf_proto",
        false,
        &join(&m.dns_hijack_nfproto, ", "),
    ));
    o.push_str(&set_block(
        "proxy_nfproto",
        "nf_proto",
        false,
        &join(&m.proxy_nfproto, ", "),
    ));
    o.push_str(&set_block(
        "reserved_ip",
        "ipv4_addr",
        true,
        &join(&m.reserved_ip, ", "),
    ));
    o.push_str(&set_block(
        "reserved_ip6",
        "ipv6_addr",
        true,
        &join(&m.reserved_ip6, ", "),
    ));
    o.push_str(&set_block(
        "lan_inbound_device",
        "ifname",
        true,
        &qjoin(&m.lan_inbound_device),
    ));
    o.push_str(&set_block(
        "china_ip",
        "ipv4_addr",
        false,
        &m.china_ip_elements,
    ));
    o.push_str(&set_block(
        "china_ip6",
        "ipv6_addr",
        false,
        &m.china_ip6_elements,
    ));
    o.push_str(&set_block(
        "proxy_dport",
        "inet_proto . inet_service",
        true,
        &join(&m.proxy_dport, ", "),
    ));
    o.push_str(&set_block(
        "bypass_dscp",
        "dscp",
        true,
        &join(&m.bypass_dscp, ", "),
    ));

    let tproxy_enable = m.tcp_mode == "tproxy" || m.udp_mode == "tproxy";
    let tun_enable = m.tcp_mode == "tun" || m.udp_mode == "tun";

    // ── router chains ──
    if m.router_proxy {
        o.push_str("\tchain router_dns_hijack {\n");
        for ac in &m.router_access_controls {
            if is_empty_all3(&ac.user, &ac.group, &ac.cgroup) {
                o.push_str(&format!(
                    "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} th dport 53 counter {} #\n",
                    dns_action(m.dns_port.as_str(), ac.dns)
                ));
            } else {
                if !ac.user.is_empty() {
                    o.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} th dport 53 counter {} #\n",
                        join(&ac.user, ", "),
                        dns_action(m.dns_port.as_str(), ac.dns)
                    ));
                }
                if !ac.group.is_empty() {
                    o.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} th dport 53 counter {} #\n",
                        join(&ac.group, ", "),
                        dns_action(m.dns_port.as_str(), ac.dns)
                    ));
                }
                if m.cgroups_version == 2 {
                    for cg in &ac.cgroup {
                        o.push_str(&format!(
                            "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {} th dport 53 counter {} #\n",
                            clen(cg),
                            quote(cg),
                            dns_action(m.dns_port.as_str(), ac.dns)
                        ));
                    }
                }
            }
        }
        o.push_str("\t}\n\n");

        if m.tcp_mode == "redirect" {
            o.push_str("\tchain router_redirect {\n");
            for ac in &m.router_access_controls {
                if is_empty_all3(&ac.user, &ac.group, &ac.cgroup) {
                    o.push_str(&format!(
                        "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp counter {} #\n",
                        redirect_action(&m.redir_port, ac.proxy)
                    ));
                } else {
                    if !ac.user.is_empty() {
                        o.push_str(&format!(
                            "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp meta skuid {{ {} }} counter {} #\n",
                            join(&ac.user, ", "),
                            redirect_action(&m.redir_port, ac.proxy)
                        ));
                    }
                    if !ac.group.is_empty() {
                        o.push_str(&format!(
                            "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp meta skgid {{ {} }} counter {} #\n",
                            join(&ac.group, ", "),
                            redirect_action(&m.redir_port, ac.proxy)
                        ));
                    }
                    if m.cgroups_version == 2 {
                        for cg in &ac.cgroup {
                            o.push_str(&format!(
                                "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp socket cgroupv2 level {} {} counter {} #\n",
                                clen(cg),
                                quote(cg),
                                redirect_action(&m.redir_port, ac.proxy)
                            ));
                        }
                    }
                }
            }
            o.push_str("\t}\n\n");
        }

        if tproxy_enable {
            o.push_str("\tchain router_tproxy {\n");
            for ac in &m.router_access_controls {
                let mark_expr = format!(
                    "meta mark set meta mark & {} | {}",
                    m.tproxy_fw_umask, m.tproxy_fw_mark
                );
                if is_empty_all3(&ac.user, &ac.group, &ac.cgroup) {
                    if ac.dns {
                        o.push_str("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n");
                    }
                    o.push_str(&format!(
                        "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} #\n",
                        if ac.proxy {
                            format!("{} counter accept", mark_expr)
                        } else {
                            "counter return".to_string()
                        }
                    ));
                } else {
                    if !ac.user.is_empty() {
                        if ac.dns {
                            o.push_str(&format!("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} th dport 53 counter return #\n", join(&ac.user, ", ")));
                        }
                        o.push_str(&format!(
                            "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} {} #\n",
                            join(&ac.user, ", "),
                            if ac.proxy {
                                format!("{} counter accept", mark_expr)
                            } else {
                                "counter return".to_string()
                            }
                        ));
                    }
                    if !ac.group.is_empty() {
                        if ac.dns {
                            o.push_str(&format!("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} th dport 53 counter return #\n", join(&ac.group, ", ")));
                        }
                        o.push_str(&format!(
                            "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} {} #\n",
                            join(&ac.group, ", "),
                            if ac.proxy {
                                format!("{} counter accept", mark_expr)
                            } else {
                                "counter return".to_string()
                            }
                        ));
                    }
                    if m.cgroups_version == 2 {
                        for cg in &ac.cgroup {
                            if ac.dns {
                                o.push_str(&format!("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {} th dport 53 counter return #\n", clen(cg), quote(cg)));
                            }
                            o.push_str(&format!(
                                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {} {} #\n",
                                clen(cg),
                                quote(cg),
                                if ac.proxy {
                                    format!("{} counter accept", mark_expr)
                                } else {
                                    "counter return".to_string()
                                }
                            ));
                        }
                    }
                }
            }
            o.push_str("\t}\n\n");
        }

        if tun_enable {
            o.push_str("\tchain router_tun {\n");
            for ac in &m.router_access_controls {
                let mark_expr = format!(
                    "meta mark set meta mark & {} | {}",
                    m.tun_fw_umask, m.tun_fw_mark
                );
                if is_empty_all3(&ac.user, &ac.group, &ac.cgroup) {
                    if ac.dns {
                        o.push_str("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n");
                    }
                    o.push_str(&format!(
                        "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} #\n",
                        if ac.proxy {
                            format!("{} counter accept", mark_expr)
                        } else {
                            "counter return".to_string()
                        }
                    ));
                } else {
                    if !ac.user.is_empty() {
                        if ac.dns {
                            o.push_str(&format!("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} th dport 53 counter return #\n", join(&ac.user, ", ")));
                        }
                        o.push_str(&format!(
                            "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} {} #\n",
                            join(&ac.user, ", "),
                            if ac.proxy {
                                format!("{} counter accept", mark_expr)
                            } else {
                                "counter return".to_string()
                            }
                        ));
                    }
                    if !ac.group.is_empty() {
                        if ac.dns {
                            o.push_str(&format!("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} th dport 53 counter return #\n", join(&ac.group, ", ")));
                        }
                        o.push_str(&format!(
                            "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} {} #\n",
                            join(&ac.group, ", "),
                            if ac.proxy {
                                format!("{} counter accept", mark_expr)
                            } else {
                                "counter return".to_string()
                            }
                        ));
                    }
                    if m.cgroups_version == 2 {
                        for cg in &ac.cgroup {
                            if ac.dns {
                                o.push_str(&format!("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {} th dport 53 counter return #\n", clen(cg), quote(cg)));
                            }
                            o.push_str(&format!(
                                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {} {} #\n",
                                clen(cg),
                                quote(cg),
                                if ac.proxy {
                                    format!("{} counter accept", mark_expr)
                                } else {
                                    "counter return".to_string()
                                }
                            ));
                        }
                    }
                }
            }
            o.push_str("\t}\n\n");
        }
    }

    // ── lan chains ──
    if m.lan_proxy {
        o.push_str("\tchain lan_dns_hijack {\n");
        for ac in &m.lan_access_controls {
            if is_empty_all3(&ac.ip, &ac.ip6, &ac.mac) {
                o.push_str(&format!(
                    "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} th dport 53 counter {} #\n",
                    dns_action(&m.dns_port, ac.dns)
                ));
            } else {
                if !ac.ip.is_empty() && m.dns_hijack_nfproto_has4 {
                    o.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} th dport 53 counter {} #\n",
                        join(&ac.ip, ", "),
                        dns_action(&m.dns_port, ac.dns)
                    ));
                }
                if !ac.ip6.is_empty() && m.dns_hijack_nfproto_has6 {
                    o.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} th dport 53 counter {} #\n",
                        join(&ac.ip6, ", "),
                        dns_action(&m.dns_port, ac.dns)
                    ));
                }
                if !ac.mac.is_empty() {
                    o.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} th dport 53 counter {} #\n",
                        join(&ac.mac, ", "),
                        dns_action(&m.dns_port, ac.dns)
                    ));
                }
            }
        }
        o.push_str("\t}\n\n");

        if m.tcp_mode == "redirect" {
            o.push_str("\tchain lan_redirect {\n");
            for ac in &m.lan_access_controls {
                if is_empty_all3(&ac.ip, &ac.ip6, &ac.mac) {
                    o.push_str(&format!(
                        "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp counter {} #\n",
                        // 对齐原模板：else 分支是 "counter return"（多一个 counter）
                        if ac.proxy {
                            format!("redirect to :{}", m.redir_port)
                        } else {
                            "counter return".to_string()
                        }
                    ));
                } else {
                    if !ac.ip.is_empty() && m.proxy_nfproto_has4 {
                        o.push_str(&format!(
                            "\t\tmeta l4proto tcp ip saddr {{ {} }} counter {} #\n",
                            join(&ac.ip, ", "),
                            redirect_action(&m.redir_port, ac.proxy)
                        ));
                    }
                    if !ac.ip6.is_empty() && m.proxy_nfproto_has6 {
                        o.push_str(&format!(
                            "\t\tmeta l4proto tcp ip6 saddr {{ {} }} counter {} #\n",
                            join(&ac.ip6, ", "),
                            redirect_action(&m.redir_port, ac.proxy)
                        ));
                    }
                    if !ac.mac.is_empty() {
                        o.push_str(&format!(
                            "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp ether saddr {{ {} }} counter {} #\n",
                            join(&ac.mac, ", "),
                            redirect_action(&m.redir_port, ac.proxy)
                        ));
                    }
                }
            }
            o.push_str("\t}\n\n");
        }

        if tproxy_enable {
            o.push_str("\tchain lan_tproxy {\n");
            for ac in &m.lan_access_controls {
                let mark_expr = format!(
                    "meta mark set meta mark & {} | {}",
                    m.tproxy_fw_umask, m.tproxy_fw_mark
                );
                let proxy_expr = if ac.proxy {
                    format!("{} tproxy to :{} counter accept", mark_expr, m.tproxy_port)
                } else {
                    "counter return".to_string()
                };
                if is_empty_all3(&ac.ip, &ac.ip6, &ac.mac) {
                    if ac.dns {
                        o.push_str("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n");
                    }
                    o.push_str(&format!(
                        "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} #\n",
                        proxy_expr
                    ));
                } else {
                    if !ac.ip.is_empty() {
                        if ac.dns && m.dns_hijack_nfproto_has4 {
                            o.push_str(&format!("\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} th dport 53 counter return #\n", join(&ac.ip, ", ")));
                        }
                        if m.proxy_nfproto_has4 {
                            let expr = if ac.proxy {
                                format!(
                                    "{} tproxy ip to :{} counter accept",
                                    mark_expr, m.tproxy_port
                                )
                            } else {
                                "counter return".to_string()
                            };
                            o.push_str(&format!(
                                "\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} {} #\n",
                                join(&ac.ip, ", "),
                                expr
                            ));
                        }
                    }
                    if !ac.ip6.is_empty() {
                        if ac.dns && m.dns_hijack_nfproto_has6 {
                            o.push_str(&format!("\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} th dport 53 counter return #\n", join(&ac.ip6, ", ")));
                        }
                        if m.proxy_nfproto_has6 {
                            let expr = if ac.proxy {
                                format!(
                                    "{} tproxy ip6 to :{} counter accept",
                                    mark_expr, m.tproxy_port
                                )
                            } else {
                                "counter return".to_string()
                            };
                            o.push_str(&format!(
                                "\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} {} #\n",
                                join(&ac.ip6, ", "),
                                expr
                            ));
                        }
                    }
                    if !ac.mac.is_empty() {
                        if ac.dns {
                            o.push_str(&format!("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} th dport 53 counter return #\n", join(&ac.mac, ", ")));
                        }
                        o.push_str(&format!(
                            "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} {} #\n",
                            join(&ac.mac, ", "),
                            proxy_expr
                        ));
                    }
                }
            }
            o.push_str("\t}\n\n");
        }

        if tun_enable {
            o.push_str("\tchain lan_tun {\n");
            for ac in &m.lan_access_controls {
                let mark_expr = format!(
                    "meta mark set meta mark & {} | {}",
                    m.tun_fw_umask, m.tun_fw_mark
                );
                let proxy_expr = if ac.proxy {
                    format!("{} counter accept", mark_expr)
                } else {
                    "counter return".to_string()
                };
                if is_empty_all3(&ac.ip, &ac.ip6, &ac.mac) {
                    if ac.dns {
                        o.push_str("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n");
                    }
                    o.push_str(&format!(
                        "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} #\n",
                        proxy_expr
                    ));
                } else {
                    if !ac.ip.is_empty() {
                        if ac.dns && m.dns_hijack_nfproto_has4 {
                            o.push_str(&format!("\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} th dport 53 counter return #\n", join(&ac.ip, ", ")));
                        }
                        if m.proxy_nfproto_has4 {
                            o.push_str(&format!(
                                "\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} {} #\n",
                                join(&ac.ip, ", "),
                                proxy_expr
                            ));
                        }
                    }
                    if !ac.ip6.is_empty() {
                        if ac.dns && m.dns_hijack_nfproto_has6 {
                            o.push_str(&format!("\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} th dport 53 counter return #\n", join(&ac.ip6, ", ")));
                        }
                        if m.proxy_nfproto_has6 {
                            o.push_str(&format!(
                                "\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} {} #\n",
                                join(&ac.ip6, ", "),
                                proxy_expr
                            ));
                        }
                    }
                    if !ac.mac.is_empty() {
                        if ac.dns {
                            o.push_str(&format!("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} th dport 53 counter return #\n", join(&ac.mac, ", ")));
                        }
                        o.push_str(&format!(
                            "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} {} #\n",
                            join(&ac.mac, ", "),
                            proxy_expr
                        ));
                    }
                }
            }
            o.push_str("\t}\n\n");
        }
    }

    // ── 本机（router）挂载链 ──
    if m.router_proxy {
        o.push_str("\tchain nat_output {\n");
        o.push_str("\t\ttype nat hook output priority filter; policy accept;\n");
        o.push_str(&bypass_prefix(m));
        o.push_str("\t\tjump router_dns_hijack\n");
        if m.tcp_mode == "redirect" {
            o.push_str(&common_returns(m));
            o.push_str("\t\tjump router_redirect\n");
        }
        o.push_str(&fake_ip_ping_hijack(m));
        o.push_str("\t}\n\n");

        o.push_str("\tchain mangle_output {\n");
        o.push_str("\t\ttype route hook output priority mangle; policy accept;\n");
        o.push_str(&bypass_prefix(m));
        o.push_str(&common_returns(m));
        let vmap = |mode: &str| -> &'static str {
            match mode {
                "tproxy" => "jump router_tproxy",
                "tun" => "jump router_tun",
                _ => "continue",
            }
        };
        // 对齐 Go text/template 的输出：各分支自带尾随空格，逗号前有一个空格。
        o.push_str(&format!(
            "\t\tmeta l4proto vmap {{ tcp: {} , udp: {} }}\n",
            vmap(&m.tcp_mode),
            vmap(&m.udp_mode)
        ));
        o.push_str("\t}\n\n");

        o.push_str("\tchain mangle_prerouting_router {\n");
        o.push_str("\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n");
        if tproxy_enable {
            o.push_str(&format!(
                "\t\tiifname lo meta l4proto {{ tcp, udp }} meta mark & {} == {} tproxy to :{} counter accept\n",
                m.tproxy_fw_mask, m.tproxy_fw_mark, m.tproxy_port
            ));
        }
        if tun_enable {
            o.push_str(&format!(
                "\t\tiifname {} meta l4proto {{ icmp, tcp, udp }} counter accept\n",
                quote(&m.tun_device)
            ));
        }
        o.push_str("\t}\n\n");
    }

    // ── 局域网（lan）挂载链 ──
    if m.lan_proxy {
        o.push_str("\tchain dstnat {\n");
        o.push_str("\t\ttype nat hook prerouting priority dstnat - 10; policy accept;\n");
        o.push_str("\t\tiifname @lan_inbound_device jump lan_dns_hijack\n");
        if m.tcp_mode == "redirect" {
            o.push_str(&common_returns(m));
            o.push_str("\t\tiifname @lan_inbound_device jump lan_redirect\n");
        }
        o.push_str(&fake_ip_ping_hijack(m));
        o.push_str("\t}\n\n");

        o.push_str("\tchain mangle_prerouting_lan {\n");
        o.push_str("\t\ttype filter hook prerouting priority mangle; policy accept;\n");
        o.push_str(&common_returns(m));
        let lan_vmap = |mode: &str| -> &'static str {
            match mode {
                "tproxy" => "jump lan_tproxy",
                "tun" => "jump lan_tun",
                _ => "continue",
            }
        };
        o.push_str(&format!(
            "\t\tiifname @lan_inbound_device meta l4proto vmap {{ tcp: {} , udp: {} }}\n",
            lan_vmap(&m.tcp_mode),
            lan_vmap(&m.udp_mode)
        ));
        o.push_str("\t}\n\n");
    }

    o.push_str("}\n");
    o
}

fn set_block(name: &str, ty: &str, auto_merge: bool, elements: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!("\tset {} {{\n", name));
    s.push_str(&format!("\t\ttype {}\n", ty));
    s.push_str("\t\tflags interval\n");
    if auto_merge {
        s.push_str("\t\tauto-merge\n");
    }
    if !elements.trim().is_empty() {
        s.push_str("\t\telements = {\n");
        s.push_str(&format!("\t\t\t{}\n", elements.trim()));
        s.push_str("\t\t}\n");
    }
    s.push_str("\t}\n\n");
    s
}

fn dns_action(dns_port: &str, dns: bool) -> String {
    if dns {
        format!("redirect to :{}", dns_port)
    } else {
        "return".into()
    }
}

fn redirect_action(redir_port: &str, proxy: bool) -> String {
    if proxy {
        format!("redirect to :{}", redir_port)
    } else {
        "return".into()
    }
}

/// nat_output / mangle_output 开头的防回环绕过前缀：cgroup → gid → mark。
fn bypass_prefix(m: &Model) -> String {
    let mut s = String::new();
    if m.bypass_cgroup {
        match m.cgroups_version {
            1 => s.push_str(&format!(
                "\t\tmeta cgroup {} counter return\n",
                m.cgroup_id
            )),
            2 => s.push_str(&format!(
                "\t\tsocket cgroupv2 level 2 \"services/{}\" counter return\n",
                m.cgroup_name
            )),
            _ => {}
        }
    }
    if m.bypass_gid && !m.core_gid.is_empty() {
        s.push_str(&format!("\t\tmeta skgid {} counter return\n", m.core_gid));
    }
    if m.bypass_mark && !m.bypass_mark_values.is_empty() {
        for v in &m.bypass_mark_values {
            s.push_str(&format!("\t\tmeta mark {} counter return\n", v));
        }
    }
    s
}

/// 公共绕过链：fib → ct → 保留地址 → 中国 IP → dport → dscp → fwmark。
fn common_returns(m: &Model) -> String {
    let mut s = String::new();
    let fake4 = if m.fake_ip_range.is_empty() {
        String::new()
    } else {
        format!(" ip daddr != {}", m.fake_ip_range)
    };
    let fake6 = if m.fake_ip6_range.is_empty() {
        String::new()
    } else {
        format!(" ip6 daddr != {}", m.fake_ip6_range)
    };
    s.push_str("\t\tfib daddr type { local, broadcast, anycast, multicast } counter return\n");
    s.push_str("\t\tct direction reply counter return\n");
    s.push_str(&format!(
        "\t\tip daddr @reserved_ip{} counter return\n",
        fake4
    ));
    s.push_str(&format!(
        "\t\tip6 daddr @reserved_ip6{} counter return\n",
        fake6
    ));
    s.push_str("\t\tip daddr @china_ip counter return\n");
    s.push_str("\t\tip6 daddr @china_ip6 counter return\n");
    s.push_str(&format!(
        "\t\tmeta nfproto ipv4 meta l4proto . th dport != @proxy_dport{} counter return\n",
        fake4
    ));
    s.push_str(&format!(
        "\t\tmeta nfproto ipv6 meta l4proto . th dport != @proxy_dport{} counter return\n",
        fake6
    ));
    s.push_str(&format!(
        "\t\tmeta l4proto {{ tcp, udp }} ip dscp @bypass_dscp{} counter return\n",
        fake4
    ));
    s.push_str(&format!(
        "\t\tmeta l4proto {{ tcp, udp }} ip6 dscp @bypass_dscp{} counter return\n",
        fake6
    ));
    for fm in &m.bypass_fwmark {
        s.push_str(&format!(
            "\t\tmeta mark & {} == {} counter return\n",
            fm.mask, fm.mark
        ));
    }
    s
}

fn fake_ip_ping_hijack(m: &Model) -> String {
    let mut s = String::new();
    if m.fake_ip_ping_hijack {
        if !m.fake_ip_range.is_empty() {
            s.push_str(&format!(
                "\t\ticmp type echo-request ip daddr {} counter redirect\n",
                m.fake_ip_range
            ));
        }
        if !m.fake_ip6_range.is_empty() {
            s.push_str(&format!(
                "\t\ticmpv6 type echo-request ip6 daddr {} counter redirect\n",
                m.fake_ip6_range
            ));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LanAccessControl, RouterAccessControl};

    /// 构造一份与平台探测无关的确定性配置，保证断言在任何系统上结果一致。
    fn test_cfg(tcp: &str, udp: &str) -> Config {
        let mut cfg = Config::default();
        cfg.proxy.router_proxy = true;
        cfg.proxy.lan_proxy = true;
        cfg.proxy.tcp_mode = tcp.into();
        cfg.proxy.udp_mode = udp.into();
        cfg.proxy.bypass_cgroup = true;
        cfg.proxy.bypass_gid = false;
        cfg.proxy.bypass_mark = true;
        cfg.proxy.bypass_mark_values = vec!["0xff".into()];
        cfg.proxy.bypass_fwmark = vec!["0x40/0xff".into()];
        cfg.proxy.dns_port = "5353".into();
        cfg.proxy.tproxy_port = "7878".into();
        cfg.proxy.redir_port = "7876".into();
        cfg.proxy.tun_device = "tun0".into();
        cfg.routing.cgroup_name = "proxy".into();
        cfg.routing.tproxy_fw_mark = "0x80".into();
        cfg.routing.tproxy_fw_mask = "0xFF".into();
        cfg.router_access_controls = vec![RouterAccessControl {
            id: "r1".into(),
            enabled: true,
            user: Vec::new(),
            group: Vec::new(),
            cgroup: Vec::new(),
            dns: true,
            proxy: true,
        }];
        cfg.lan_access_controls = vec![LanAccessControl {
            id: "l1".into(),
            enabled: true,
            ip: Vec::new(),
            ip6: Vec::new(),
            mac: Vec::new(),
            dns: true,
            proxy: true,
        }];
        cfg
    }

    #[test]
    fn umask_inverts_mask() {
        assert_eq!(umask("0xFF"), "0xFFFFFF00");
        assert_eq!(umask("0x80"), "0xFFFFFF7F");
        assert_eq!(umask("bogus"), "0xFFFFFFFF");
    }

    #[test]
    fn render_tproxy_mode() {
        let cfg = test_cfg("tproxy", "tproxy");
        let m = build(&cfg, &["br-lan".into()], 2);
        let s = render(&m);
        assert!(s.starts_with("table inet nexa {"));
        // 集合
        assert!(s.contains("set lan_inbound_device {"));
        assert!(s.contains("elements = {\n\t\t\t\"br-lan\"\n\t\t}"));
        // router 链
        assert!(s.contains("chain router_dns_hijack {"));
        assert!(s.contains("chain router_tproxy {"));
        assert!(!s.contains("chain router_redirect {"));
        assert!(!s.contains("chain router_tun {"));
        // lan 链
        assert!(s.contains("chain lan_dns_hijack {"));
        assert!(s.contains("chain lan_tproxy {"));
        // 挂载链
        assert!(s.contains("type nat hook output priority filter; policy accept;"));
        assert!(s.contains("type route hook output priority mangle; policy accept;"));
        assert!(s.contains("type filter hook prerouting priority mangle - 1; policy accept;"));
        assert!(s.contains("type nat hook prerouting priority dstnat - 10; policy accept;"));
        // 防回环
        assert!(s.contains("socket cgroupv2 level 2 \"services/proxy\" counter return"));
        assert!(s.contains("meta mark 0xff counter return"));
        assert!(s.contains("meta mark & 0xff == 0x40 counter return"));
        // vmap 分流
        assert!(s.contains("meta l4proto vmap { tcp: jump router_tproxy , udp: jump router_tproxy }"));
        assert!(s.contains("iifname @lan_inbound_device meta l4proto vmap { tcp: jump lan_tproxy , udp: jump lan_tproxy }"));
        // tproxy mark 计算（umask 取反：~0xFF = 0xFFFFFF00）
        assert!(s.contains("meta mark set meta mark & 0xFFFFFF00 | 0x80"));
        // fake-ip ping 劫持
        assert!(s.contains("icmp type echo-request ip daddr 198.18.0.0/15 counter redirect"));
    }

    #[test]
    fn render_redirect_mode() {
        let cfg = test_cfg("redirect", "redirect");
        let m = build(&cfg, &[], 2);
        let s = render(&m);
        assert!(s.contains("chain router_redirect {"));
        assert!(s.contains("chain lan_redirect {"));
        assert!(s.contains("jump router_redirect"));
        assert!(s.contains("iifname @lan_inbound_device jump lan_redirect"));
        assert!(!s.contains("chain router_tproxy {"));
    }

    #[test]
    fn render_tun_mode() {
        let cfg = test_cfg("tun", "tun");
        let m = build(&cfg, &["br-lan".into()], 2);
        let s = render(&m);
        assert!(s.contains("chain router_tun {"));
        assert!(s.contains("chain lan_tun {"));
        assert!(s.contains("iifname \"tun0\" meta l4proto { icmp, tcp, udp } counter accept"));
        assert!(s.contains("meta l4proto vmap { tcp: jump router_tun , udp: jump router_tun }"));
    }

    #[test]
    fn china_elements_only_when_enabled() {
        let mut cfg = test_cfg("tproxy", "tproxy");
        // 未开启 bypass：china_ip / china_ip6 集合存在但为空，不引用任何 include
        let m = build(&cfg, &[], 2);
        let s = render(&m);
        assert!(s.contains("set china_ip {"));
        assert!(s.contains("set china_ip6 {"));
        assert!(!s.contains("include \""));
        assert!(!s.contains("elements = {\n\t\t\t1.0.1.0/24"));

        // 开启 bypass 后由 netmanager 注入 elements（对齐 Go：不使用 include）
        cfg.proxy.bypass_china_mainland_ip = true;
        cfg.proxy.bypass_china_mainland_ip6 = true;
        let mut m = build(&cfg, &[], 2);
        m.china_ip_elements = "1.0.1.0/24, 1.0.2.0/23".into();
        m.china_ip6_elements = "2001:250::/30".into();
        let s = render(&m);
        assert!(!s.contains("include \""));
        assert!(s.contains("elements = {\n\t\t\t1.0.1.0/24, 1.0.2.0/23\n\t\t}"));
        assert!(s.contains("elements = {\n\t\t\t2001:250::/30\n\t\t}"));
    }

    #[test]
    fn table_name_is_nexa() {
        // nft 表名固定为 inet nexa（对齐 Go 版），不得出现 momo 等旧表名
        let m = build(&test_cfg("tproxy", "tproxy"), &[], 2);
        let s = render(&m);
        assert!(s.starts_with("table inet nexa {"));
        assert!(!s.contains("momo"));
    }
}
