//! 把原 hijack.ut 的 nftables 规则 1:1 翻译成 Rust 渲染逻辑。
//! 规则文本与原 ucode 模板逐条一致，仅控制流换成 Rust。

use std::fs;
use std::path::Path;

use crate::config::Config;

/// Model 渲染模板所需的数据。
pub struct Model {
    pub dns_hijack_nfproto: Vec<String>,
    pub proxy_nfproto: Vec<String>,
    pub reserved_ip: Vec<String>,
    pub reserved_ip6: Vec<String>,
    pub lan_inbound_device: Vec<String>,
    pub proxy_dport: Vec<String>, // 形如 "tcp . 0-65535"
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

    pub cgroups_version: i32,
    pub cgroup_id: String,
    pub cgroup_name: String,
    pub core_gid: String, // 核心进程的 GID，用于 BypassGid

    pub bypass_cgroup: bool,
    pub bypass_gid: bool,
    pub bypass_mark: bool,
    pub bypass_mark_values: Vec<String>,

    pub tproxy_fw_mark: String,
    pub tproxy_fw_mask: String,
    pub tproxy_fw_umask: String,
    pub tun_fw_mark: String,
    #[allow(dead_code)]
    pub tun_fw_mask: String,
    pub tun_fw_umask: String,

    pub bypass_china_mainland_ip: bool,
    pub bypass_china_mainland_ip6: bool,

    pub china_ip_elements: String,
    pub china_ip6_elements: String,

    pub dns_hijack_nfproto_has4: bool,
    pub dns_hijack_nfproto_has6: bool,
    pub proxy_nfproto_has4: bool,
    pub proxy_nfproto_has6: bool,
}

/// AccessControlView 访问控制视图（统一 router/lan）。
#[derive(Debug, Clone, Default)]
pub struct AccessControlView {
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

/// Fwmark bypass_fwmark 解析后的 mark/mask。
#[derive(Debug, Clone)]
pub struct Fwmark {
    pub mark: String,
    pub mask: String,
}

/// Build 按 cfg + lanInboundDevice + cgroupsVersion 构造 Model。
pub fn build(cfg: &Config, lan_inbound_device: Vec<String>, cgroups_version: i32) -> Model {
    let p = &cfg.proxy;

    let mut dns_nf = vec![];
    if p.ipv4_dns_hijack {
        dns_nf.push("ipv4".to_string());
    }
    if p.ipv6_dns_hijack {
        dns_nf.push("ipv6".to_string());
    }
    let mut proxy_nf = vec![];
    if p.ipv4_proxy {
        proxy_nf.push("ipv4".to_string());
    }
    if p.ipv6_proxy {
        proxy_nf.push("ipv6".to_string());
    }

    // proxy_dport
    let mut proxy_dport = vec![];
    for port in split_space(&p.proxy_tcp_dport) {
        proxy_dport.push(format!("tcp . {}", port));
    }
    for port in split_space(&p.proxy_udp_dport) {
        proxy_dport.push(format!("udp . {}", port));
    }

    // bypass_fwmark
    let mut fwmarks = vec![];
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
        lan_inbound_device,
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
        bypass_cgroup: p.bypass_cgroup,
        bypass_gid: p.bypass_gid,
        bypass_mark: p.bypass_mark,
        bypass_mark_values: p.bypass_mark_values.clone(),
        tproxy_fw_mark: cfg.routing.tproxy_fw_mark.clone(),
        tproxy_fw_mask: cfg.routing.tproxy_fw_mask.clone(),
        tproxy_fw_umask: umask(&cfg.routing.tproxy_fw_mask),
        tun_fw_mark: cfg.routing.tun_fw_mark.clone(),
        tun_fw_mask: cfg.routing.tun_fw_mask.clone(),
        tun_fw_umask: umask(&cfg.routing.tun_fw_mask),
        bypass_china_mainland_ip: p.bypass_china_mainland_ip,
        bypass_china_mainland_ip6: p.bypass_china_mainland_ip6,
        china_ip_elements: String::new(),
        china_ip6_elements: String::new(),
        dns_hijack_nfproto_has4: p.ipv4_dns_hijack,
        dns_hijack_nfproto_has6: p.ipv6_dns_hijack,
        proxy_nfproto_has4: p.ipv4_proxy,
        proxy_nfproto_has6: p.ipv6_proxy,
    }
}

fn lookup_core_gid() -> String {
    crate::sysutil::lookup_group_gid("nexa")
        .map(|g| g.to_string())
        .unwrap_or_default()
}

fn build_router_views(cfg: &Config) -> Vec<AccessControlView> {
    let mut out = vec![];
    for ac in &cfg.router_access_controls {
        if !ac.enabled {
            continue;
        }
        out.push(AccessControlView {
            enabled: ac.enabled,
            user: filter_existing_users(&ac.user),
            group: filter_existing_groups(&ac.group),
            cgroup: filter_existing_cgroups(&ac.cgroup),
            dns: ac.dns,
            proxy: ac.proxy,
            ..Default::default()
        });
    }
    out
}

fn filter_existing_cgroups(paths: &[String]) -> Vec<String> {
    let mut out = vec![];
    for p in paths {
        if p.is_empty() {
            continue;
        }
        let full = if let Some(stripped) = p.strip_prefix('/') {
            format!("/sys/fs/cgroup/{}", stripped)
        } else {
            format!("/sys/fs/cgroup/{}", p)
        };
        if let Ok(st) = fs::metadata(&full) {
            if st.is_dir() {
                out.push(p.clone());
            }
        }
    }
    out
}

fn filter_existing_users(users: &[String]) -> Vec<String> {
    let mut out = vec![];
    for u in users {
        if u.is_empty() {
            continue;
        }
        if crate::sysutil::user_exists(u) {
            out.push(u.clone());
        }
    }
    out
}

fn filter_existing_groups(groups: &[String]) -> Vec<String> {
    let mut out = vec![];
    for g in groups {
        if g.is_empty() {
            continue;
        }
        if crate::sysutil::group_exists(g) {
            out.push(g.clone());
        }
    }
    out
}

fn build_lan_views(cfg: &Config) -> Vec<AccessControlView> {
    let mut out = vec![];
    for ac in &cfg.lan_access_controls {
        if !ac.enabled {
            continue;
        }
        out.push(AccessControlView {
            enabled: ac.enabled,
            ip: ac.ip.clone(),
            ip6: ac.ip6.clone(),
            mac: ac.mac.clone(),
            dns: ac.dns,
            proxy: ac.proxy,
            ..Default::default()
        });
    }
    out
}

/// umask 对齐 fw4.hex(~mask & 0xFFFFFFFF)。
fn umask(mask_hex: &str) -> String {
    let mask_hex = mask_hex.strip_prefix("0x").unwrap_or(mask_hex);
    if mask_hex.is_empty() {
        return "0xFFFFFFFF".to_string();
    }
    match u32::from_str_radix(mask_hex, 16) {
        Ok(v) => format!("0x{:08X}", !v & 0xFFFFFFFF),
        Err(_) => "0xFFFFFFFF".to_string(),
    }
}

fn split_space(s: &str) -> Vec<String> {
    let s = s.trim();
    if s.is_empty() {
        return vec![];
    }
    s.split_whitespace().map(|x| x.to_string()).collect()
}

fn qjoin(arr: &[String]) -> String {
    arr.iter()
        .map(|s| format!("{:?}", s))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render 渲染完整 nft 规则。
pub fn render(m: &Model) -> String {
    let mut s = String::new();
    s.push_str("table inet nexa {\n");

    // ── sets ──
    render_nfproto_set(&mut s, "dns_hijack_nfproto", &m.dns_hijack_nfproto);
    render_nfproto_set(&mut s, "proxy_nfproto", &m.proxy_nfproto);
    render_set_interval_auto(&mut s, "reserved_ip", "ipv4_addr", &m.reserved_ip);
    render_set_interval_auto(&mut s, "reserved_ip6", "ipv6_addr", &m.reserved_ip6);

    // lan_inbound_device（quoted elements）
    s.push_str("\tset lan_inbound_device {\n");
    s.push_str("\t\ttype ifname\n");
    s.push_str("\t\tflags interval\n");
    s.push_str("\t\tauto-merge\n");
    if !m.lan_inbound_device.is_empty() {
        s.push_str("\t\telements = {\n");
        s.push_str(&format!("\t\t\t{}\n", qjoin(&m.lan_inbound_device)));
        s.push_str("\t\t}\n");
    }
    s.push_str("\t}\n");

    // china_ip
    s.push_str("\tset china_ip {\n");
    s.push_str("\t\ttype ipv4_addr\n");
    s.push_str("\t\tflags interval\n");
    if !m.china_ip_elements.is_empty() {
        s.push_str("\t\telements = {\n");
        s.push_str(&format!("\t\t\t{}\n", m.china_ip_elements));
        s.push_str("\t\t}\n");
    }
    s.push_str("\t}\n");

    // china_ip6
    s.push_str("\tset china_ip6 {\n");
    s.push_str("\t\ttype ipv6_addr\n");
    s.push_str("\t\tflags interval\n");
    if !m.china_ip6_elements.is_empty() {
        s.push_str("\t\telements = {\n");
        s.push_str(&format!("\t\t\t{}\n", m.china_ip6_elements));
        s.push_str("\t\t}\n");
    }
    s.push_str("\t}\n");

    // proxy_dport
    s.push_str("\tset proxy_dport {\n");
    s.push_str("\t\ttype inet_proto . inet_service\n");
    s.push_str("\t\tflags interval\n");
    s.push_str("\t\tauto-merge\n");
    if !m.proxy_dport.is_empty() {
        s.push_str("\t\telements = {\n");
        s.push_str(&format!("\t\t\t{}\n", m.proxy_dport.join(", ")));
        s.push_str("\t\t}\n");
    }
    s.push_str("\t}\n");

    // bypass_dscp
    s.push_str("\tset bypass_dscp {\n");
    s.push_str("\t\ttype dscp\n");
    s.push_str("\t\tflags interval\n");
    s.push_str("\t\tauto-merge\n");
    if !m.bypass_dscp.is_empty() {
        s.push_str("\t\telements = {\n");
        s.push_str(&format!("\t\t\t{}\n", m.bypass_dscp.join(", ")));
        s.push_str("\t\t}\n");
    }
    s.push_str("\t}\n");

    // ── router chains ──
    if m.router_proxy {
        render_router_dns_hijack(&mut s, m);
        if m.tcp_mode == "redirect" {
            render_router_redirect(&mut s, m);
        }
        if m.tcp_mode == "tproxy" || m.udp_mode == "tproxy" {
            render_router_tproxy(&mut s, m);
        }
        if m.tcp_mode == "tun" || m.udp_mode == "tun" {
            render_router_tun(&mut s, m);
        }
    }

    // ── lan chains ──
    if m.lan_proxy {
        render_lan_dns_hijack(&mut s, m);
        if m.tcp_mode == "redirect" {
            render_lan_redirect(&mut s, m);
        }
        if m.tcp_mode == "tproxy" || m.udp_mode == "tproxy" {
            render_lan_tproxy(&mut s, m);
        }
        if m.tcp_mode == "tun" || m.udp_mode == "tun" {
            render_lan_tun(&mut s, m);
        }
    }

    // ── nat_output / mangle_output / mangle_prerouting_router ──
    if m.router_proxy {
        render_nat_output(&mut s, m);
        render_mangle_output(&mut s, m);
        render_mangle_prerouting_router(&mut s, m);
    }

    // ── dstnat / mangle_prerouting_lan ──
    if m.lan_proxy {
        render_dstnat(&mut s, m);
        render_mangle_prerouting_lan(&mut s, m);
    }

    s.push_str("}\n");

    // includes
    if m.bypass_china_mainland_ip {
        s.push_str("include \"/etc/nexa/firewall/geoip_cn.nft\"\n");
    }
    if m.bypass_china_mainland_ip6 {
        s.push_str("include \"/etc/nexa/firewall/geoip6_cn.nft\"\n");
    }

    s
}

fn render_nfproto_set(s: &mut String, name: &str, els: &[String]) {
    s.push_str(&format!("\tset {} {{\n", name));
    s.push_str("\t\ttype nf_proto\n");
    s.push_str("\t\tflags interval\n");
    if !els.is_empty() {
        s.push_str("\t\telements = {\n");
        s.push_str(&format!("\t\t\t{}\n", els.join(", ")));
        s.push_str("\t\t}\n");
    }
    s.push_str("\t}\n");
}

fn render_set_interval_auto(s: &mut String, name: &str, ty: &str, els: &[String]) {
    s.push_str(&format!("\tset {} {{\n", name));
    s.push_str(&format!("\t\ttype {}\n", ty));
    s.push_str("\t\tflags interval\n");
    s.push_str("\t\tauto-merge\n");
    if !els.is_empty() {
        s.push_str("\t\telements = {\n");
        s.push_str(&format!("\t\t\t{}\n", els.join(", ")));
        s.push_str("\t\t}\n");
    }
    s.push_str("\t}\n");
}

// ── router chains ──

fn render_router_dns_hijack(s: &mut String, m: &Model) {
    s.push_str("\tchain router_dns_hijack {\n");
    for ac in &m.router_access_controls {
        let action = if ac.dns {
            format!("redirect to :{}", m.dns_port)
        } else {
            "return".to_string()
        };
        if ac.user.is_empty() && ac.group.is_empty() && ac.cgroup.is_empty() {
            s.push_str(&format!(
                "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} th dport 53 counter {} #\n",
                action
            ));
        } else {
            if !ac.user.is_empty() {
                s.push_str(&format!(
                    "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} th dport 53 counter {} #\n",
                    ac.user.join(", "),
                    action
                ));
            }
            if !ac.group.is_empty() {
                s.push_str(&format!(
                    "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} th dport 53 counter {} #\n",
                    ac.group.join(", "),
                    action
                ));
            }
            if m.cgroups_version == 2 && !ac.cgroup.is_empty() {
                for cg in &ac.cgroup {
                    let level = clen(cg);
                    s.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {:?} th dport 53 counter {} #\n",
                        level, cg, action
                    ));
                }
            }
        }
    }
    s.push_str("\t}\n");
}

fn render_router_redirect(s: &mut String, m: &Model) {
    s.push_str("\tchain router_redirect {\n");
    for ac in &m.router_access_controls {
        let action = if ac.proxy {
            format!("redirect to :{}", m.redir_port)
        } else {
            "return".to_string()
        };
        if ac.user.is_empty() && ac.group.is_empty() && ac.cgroup.is_empty() {
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp counter {} #\n",
                action
            ));
        } else {
            if !ac.user.is_empty() {
                s.push_str(&format!(
                    "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp meta skuid {{ {} }} counter {} #\n",
                    ac.user.join(", "),
                    action
                ));
            }
            if !ac.group.is_empty() {
                s.push_str(&format!(
                    "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp meta skgid {{ {} }} counter {} #\n",
                    ac.group.join(", "),
                    action
                ));
            }
            if m.cgroups_version == 2 && !ac.cgroup.is_empty() {
                for cg in &ac.cgroup {
                    let level = clen(cg);
                    s.push_str(&format!(
                        "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp socket cgroupv2 level {} {:?} counter {} #\n",
                        level, cg, action
                    ));
                }
            }
        }
    }
    s.push_str("\t}\n");
}

fn render_router_tproxy(s: &mut String, m: &Model) {
    s.push_str("\tchain router_tproxy {\n");
    for ac in &m.router_access_controls {
        let mark_action = if ac.proxy {
            format!(
                "meta mark set meta mark & {} | {} counter accept",
                m.tproxy_fw_umask, m.tproxy_fw_mark
            )
        } else {
            "counter return".to_string()
        };
        if ac.user.is_empty() && ac.group.is_empty() && ac.cgroup.is_empty() {
            if ac.dns {
                s.push_str("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n");
            }
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} #\n",
                mark_action
            ));
        } else {
            if !ac.user.is_empty() {
                if ac.dns {
                    s.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} th dport 53 counter return #\n",
                        ac.user.join(", ")
                    ));
                }
                s.push_str(&format!(
                    "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} {} #\n",
                    ac.user.join(", "),
                    mark_action
                ));
            }
            if !ac.group.is_empty() {
                if ac.dns {
                    s.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} th dport 53 counter return #\n",
                        ac.group.join(", ")
                    ));
                }
                s.push_str(&format!(
                    "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} {} #\n",
                    ac.group.join(", "),
                    mark_action
                ));
            }
            if m.cgroups_version == 2 && !ac.cgroup.is_empty() {
                for cg in &ac.cgroup {
                    let level = clen(cg);
                    if ac.dns {
                        s.push_str(&format!(
                            "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {:?} th dport 53 counter return #\n",
                            level, cg
                        ));
                    }
                    s.push_str(&format!(
                        "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {:?} {} #\n",
                        level, cg, mark_action
                    ));
                }
            }
        }
    }
    s.push_str("\t}\n");
}

fn render_router_tun(s: &mut String, m: &Model) {
    s.push_str("\tchain router_tun {\n");
    for ac in &m.router_access_controls {
        let mark_action = if ac.proxy {
            format!(
                "meta mark set meta mark & {} | {} counter accept",
                m.tun_fw_umask, m.tun_fw_mark
            )
        } else {
            "counter return".to_string()
        };
        if ac.user.is_empty() && ac.group.is_empty() && ac.cgroup.is_empty() {
            if ac.dns {
                s.push_str("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n");
            }
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} #\n",
                mark_action
            ));
        } else {
            if !ac.user.is_empty() {
                if ac.dns {
                    s.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} th dport 53 counter return #\n",
                        ac.user.join(", ")
                    ));
                }
                s.push_str(&format!(
                    "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} meta skuid {{ {} }} {} #\n",
                    ac.user.join(", "),
                    mark_action
                ));
            }
            if !ac.group.is_empty() {
                if ac.dns {
                    s.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} th dport 53 counter return #\n",
                        ac.group.join(", ")
                    ));
                }
                s.push_str(&format!(
                    "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} meta skgid {{ {} }} {} #\n",
                    ac.group.join(", "),
                    mark_action
                ));
            }
            if m.cgroups_version == 2 && !ac.cgroup.is_empty() {
                for cg in &ac.cgroup {
                    let level = clen(cg);
                    if ac.dns {
                        s.push_str(&format!(
                            "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {:?} th dport 53 counter return #\n",
                            level, cg
                        ));
                    }
                    s.push_str(&format!(
                        "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} socket cgroupv2 level {} {:?} {} #\n",
                        level, cg, mark_action
                    ));
                }
            }
        }
    }
    s.push_str("\t}\n");
}

// ── lan chains ──

fn render_lan_dns_hijack(s: &mut String, m: &Model) {
    s.push_str("\tchain lan_dns_hijack {\n");
    for ac in &m.lan_access_controls {
        let action = if ac.dns {
            format!("redirect to :{}", m.dns_port)
        } else {
            "return".to_string()
        };
        if ac.ip.is_empty() && ac.ip6.is_empty() && ac.mac.is_empty() {
            s.push_str(&format!(
                "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} th dport 53 counter {} #\n",
                action
            ));
        } else {
            if !ac.ip.is_empty() && m.dns_hijack_nfproto_has4 {
                s.push_str(&format!(
                    "\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} th dport 53 counter {} #\n",
                    ac.ip.join(", "),
                    action
                ));
            }
            if !ac.ip6.is_empty() && m.dns_hijack_nfproto_has6 {
                s.push_str(&format!(
                    "\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} th dport 53 counter {} #\n",
                    ac.ip6.join(", "),
                    action
                ));
            }
            if !ac.mac.is_empty() {
                s.push_str(&format!(
                    "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} th dport 53 counter {} #\n",
                    ac.mac.join(", "),
                    action
                ));
            }
        }
    }
    s.push_str("\t}\n");
}

fn render_lan_redirect(s: &mut String, m: &Model) {
    s.push_str("\tchain lan_redirect {\n");
    for ac in &m.lan_access_controls {
        let action = if ac.proxy {
            format!("redirect to :{}", m.redir_port)
        } else {
            "return".to_string()
        };
        if ac.ip.is_empty() && ac.ip6.is_empty() && ac.mac.is_empty() {
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp counter {} #\n",
                action
            ));
        } else {
            if !ac.ip.is_empty() && m.proxy_nfproto_has4 {
                s.push_str(&format!(
                    "\t\tmeta l4proto tcp ip saddr {{ {} }} counter {} #\n",
                    ac.ip.join(", "),
                    action
                ));
            }
            if !ac.ip6.is_empty() && m.proxy_nfproto_has6 {
                s.push_str(&format!(
                    "\t\tmeta l4proto tcp ip6 saddr {{ {} }} counter {} #\n",
                    ac.ip6.join(", "),
                    action
                ));
            }
            if !ac.mac.is_empty() {
                s.push_str(&format!(
                    "\t\tmeta nfproto @proxy_nfproto meta l4proto tcp ether saddr {{ {} }} counter {} #\n",
                    ac.mac.join(", "),
                    action
                ));
            }
        }
    }
    s.push_str("\t}\n");
}

fn render_lan_tproxy(s: &mut String, m: &Model) {
    s.push_str("\tchain lan_tproxy {\n");
    for ac in &m.lan_access_controls {
        let mark_action4 = if ac.proxy {
            format!(
                "meta mark set meta mark & {} | {} tproxy ip to :{} counter accept",
                m.tproxy_fw_umask, m.tproxy_fw_mark, m.tproxy_port
            )
        } else {
            "counter return".to_string()
        };
        let mark_action6 = if ac.proxy {
            format!(
                "meta mark set meta mark & {} | {} tproxy ip6 to :{} counter accept",
                m.tproxy_fw_umask, m.tproxy_fw_mark, m.tproxy_port
            )
        } else {
            "counter return".to_string()
        };
        if ac.ip.is_empty() && ac.ip6.is_empty() && ac.mac.is_empty() {
            if ac.dns {
                s.push_str("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n");
            }
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} #\n",
                if ac.proxy {
                    format!(
                        "meta mark set meta mark & {} | {} tproxy to :{} counter accept",
                        m.tproxy_fw_umask, m.tproxy_fw_mark, m.tproxy_port
                    )
                } else {
                    "counter return".to_string()
                }
            ));
        } else {
            if !ac.ip.is_empty() {
                if ac.dns && m.dns_hijack_nfproto_has4 {
                    s.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} th dport 53 counter return #\n",
                        ac.ip.join(", ")
                    ));
                }
                if m.proxy_nfproto_has4 {
                    s.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} {} #\n",
                        ac.ip.join(", "),
                        mark_action4
                    ));
                }
            }
            if !ac.ip6.is_empty() {
                if ac.dns && m.dns_hijack_nfproto_has6 {
                    s.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} th dport 53 counter return #\n",
                        ac.ip6.join(", ")
                    ));
                }
                if m.proxy_nfproto_has6 {
                    s.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} {} #\n",
                        ac.ip6.join(", "),
                        mark_action6
                    ));
                }
            }
            if !ac.mac.is_empty() {
                if ac.dns {
                    s.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} th dport 53 counter return #\n",
                        ac.mac.join(", ")
                    ));
                }
                s.push_str(&format!(
                    "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} {} #\n",
                    ac.mac.join(", "),
                    if ac.proxy {
                        format!(
                            "meta mark set meta mark & {} | {} tproxy to :{} counter accept",
                            m.tproxy_fw_umask, m.tproxy_fw_mark, m.tproxy_port
                        )
                    } else {
                        "counter return".to_string()
                    }
                ));
            }
        }
    }
    s.push_str("\t}\n");
}

fn render_lan_tun(s: &mut String, m: &Model) {
    s.push_str("\tchain lan_tun {\n");
    for ac in &m.lan_access_controls {
        let mark_action = if ac.proxy {
            format!(
                "meta mark set meta mark & {} | {} counter accept",
                m.tun_fw_umask, m.tun_fw_mark
            )
        } else {
            "counter return".to_string()
        };
        if ac.ip.is_empty() && ac.ip6.is_empty() && ac.mac.is_empty() {
            if ac.dns {
                s.push_str("\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n");
            }
            s.push_str(&format!(
                "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} {} #\n",
                mark_action
            ));
        } else {
            if !ac.ip.is_empty() {
                if ac.dns && m.dns_hijack_nfproto_has4 {
                    s.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} th dport 53 counter return #\n",
                        ac.ip.join(", ")
                    ));
                }
                if m.proxy_nfproto_has4 {
                    s.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip saddr {{ {} }} {} #\n",
                        ac.ip.join(", "),
                        mark_action
                    ));
                }
            }
            if !ac.ip6.is_empty() {
                if ac.dns && m.dns_hijack_nfproto_has6 {
                    s.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} th dport 53 counter return #\n",
                        ac.ip6.join(", ")
                    ));
                }
                if m.proxy_nfproto_has6 {
                    s.push_str(&format!(
                        "\t\tmeta l4proto {{ tcp, udp }} ip6 saddr {{ {} }} {} #\n",
                        ac.ip6.join(", "),
                        mark_action
                    ));
                }
            }
            if !ac.mac.is_empty() {
                if ac.dns {
                    s.push_str(&format!(
                        "\t\tmeta nfproto @dns_hijack_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} th dport 53 counter return #\n",
                        ac.mac.join(", ")
                    ));
                }
                s.push_str(&format!(
                    "\t\tmeta nfproto @proxy_nfproto meta l4proto {{ tcp, udp }} ether saddr {{ {} }} {} #\n",
                    ac.mac.join(", "),
                    mark_action
                ));
            }
        }
    }
    s.push_str("\t}\n");
}

// ── common bypass rules block ──

fn write_bypass_block(s: &mut String, m: &Model) {
    if m.bypass_cgroup {
        if m.cgroups_version == 1 {
            s.push_str(&format!(
                "\t\tmeta cgroup {} counter return\n",
                m.cgroup_id
            ));
        } else if m.cgroups_version == 2 {
            s.push_str(&format!(
                "\t\tsocket cgroupv2 level 2 \"services/{}\" counter return\n",
                m.cgroup_name
            ));
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
}

fn write_return_filter_block(s: &mut String, m: &Model) {
    s.push_str("\t\tfib daddr type { local, broadcast, anycast, multicast } counter return\n");
    s.push_str("\t\tct direction reply counter return\n");
    // ip reserved
    let mut line = String::from("\t\tip daddr @reserved_ip ");
    if !m.fake_ip_range.is_empty() {
        line.push_str(&format!("ip daddr != {} ", m.fake_ip_range));
    }
    line.push_str("counter return\n");
    s.push_str(&line);
    // ip6 reserved
    let mut line = String::from("\t\tip6 daddr @reserved_ip6 ");
    if !m.fake_ip6_range.is_empty() {
        line.push_str(&format!("ip6 daddr != {} ", m.fake_ip6_range));
    }
    line.push_str("counter return\n");
    s.push_str(&line);
    s.push_str("\t\tip daddr @china_ip counter return\n");
    s.push_str("\t\tip6 daddr @china_ip6 counter return\n");
    // proxy_dport v4
    let mut line = String::from("\t\tmeta nfproto ipv4 meta l4proto . th dport != @proxy_dport ");
    if !m.fake_ip_range.is_empty() {
        line.push_str(&format!("ip daddr != {} ", m.fake_ip_range));
    }
    line.push_str("counter return\n");
    s.push_str(&line);
    // proxy_dport v6
    let mut line = String::from("\t\tmeta nfproto ipv6 meta l4proto . th dport != @proxy_dport ");
    if !m.fake_ip6_range.is_empty() {
        line.push_str(&format!("ip6 daddr != {} ", m.fake_ip6_range));
    }
    line.push_str("counter return\n");
    s.push_str(&line);
    // dscp v4
    let mut line = String::from("\t\tmeta l4proto { tcp, udp } ip dscp @bypass_dscp ");
    if !m.fake_ip_range.is_empty() {
        line.push_str(&format!("ip daddr != {} ", m.fake_ip_range));
    }
    line.push_str("counter return\n");
    s.push_str(&line);
    // dscp v6
    let mut line = String::from("\t\tmeta l4proto { tcp, udp } ip6 dscp @bypass_dscp ");
    if !m.fake_ip6_range.is_empty() {
        line.push_str(&format!("ip6 daddr != {} ", m.fake_ip6_range));
    }
    line.push_str("counter return\n");
    s.push_str(&line);
    // fwmark
    for fm in &m.bypass_fwmark {
        s.push_str(&format!(
            "\t\tmeta mark & {} == {} counter return\n",
            fm.mask, fm.mark
        ));
    }
}

fn write_ping_redirect(s: &mut String, m: &Model) {
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
}

fn render_nat_output(s: &mut String, m: &Model) {
    s.push_str("\tchain nat_output {\n");
    s.push_str("\t\ttype nat hook output priority filter; policy accept;\n");
    write_bypass_block(s, m);
    s.push_str("\t\tjump router_dns_hijack\n");
    if m.tcp_mode == "redirect" {
        write_return_filter_block(s, m);
        s.push_str("\t\tjump router_redirect\n");
    }
    write_ping_redirect(s, m);
    s.push_str("\t}\n");
}

fn render_mangle_output(s: &mut String, m: &Model) {
    s.push_str("\tchain mangle_output {\n");
    s.push_str("\t\ttype route hook output priority mangle; policy accept;\n");
    write_bypass_block(s, m);
    write_return_filter_block(s, m);
    let tcp_target = match m.tcp_mode.as_str() {
        "tproxy" => "jump router_tproxy",
        "tun" => "jump router_tun",
        _ => "continue",
    };
    let udp_target = match m.udp_mode.as_str() {
        "tproxy" => "jump router_tproxy",
        "tun" => "jump router_tun",
        _ => "continue",
    };
    s.push_str(&format!(
        "\t\tmeta l4proto vmap {{ tcp: {}, udp: {} }}\n",
        tcp_target, udp_target
    ));
    s.push_str("\t}\n");
}

fn render_mangle_prerouting_router(s: &mut String, m: &Model) {
    s.push_str("\tchain mangle_prerouting_router {\n");
    s.push_str("\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n");
    if m.tcp_mode == "tproxy" || m.udp_mode == "tproxy" {
        s.push_str(&format!(
            "\t\tiifname lo meta l4proto {{ tcp, udp }} meta mark & {} == {} tproxy to :{} counter accept\n",
            m.tproxy_fw_mask, m.tproxy_fw_mark, m.tproxy_port
        ));
    }
    if m.tcp_mode == "tun" || m.udp_mode == "tun" {
        s.push_str(&format!(
            "\t\tiifname {:?} meta l4proto {{ icmp, tcp, udp }} counter accept\n",
            m.tun_device
        ));
    }
    s.push_str("\t}\n");
}

fn render_dstnat(s: &mut String, m: &Model) {
    s.push_str("\tchain dstnat {\n");
    s.push_str("\t\ttype nat hook prerouting priority dstnat - 10; policy accept;\n");
    s.push_str("\t\tiifname @lan_inbound_device jump lan_dns_hijack\n");
    if m.tcp_mode == "redirect" {
        write_return_filter_block(s, m);
        s.push_str("\t\tiifname @lan_inbound_device jump lan_redirect\n");
    }
    write_ping_redirect(s, m);
    s.push_str("\t}\n");
}

fn render_mangle_prerouting_lan(s: &mut String, m: &Model) {
    s.push_str("\tchain mangle_prerouting_lan {\n");
    s.push_str("\t\ttype filter hook prerouting priority mangle; policy accept;\n");
    write_return_filter_block(s, m);
    let tcp_target = match m.tcp_mode.as_str() {
        "tproxy" => "jump lan_tproxy",
        "tun" => "jump lan_tun",
        _ => "continue",
    };
    let udp_target = match m.udp_mode.as_str() {
        "tproxy" => "jump lan_tproxy",
        "tun" => "jump lan_tun",
        _ => "continue",
    };
    s.push_str(&format!(
        "\t\tiifname @lan_inbound_device meta l4proto vmap {{ tcp: {}, udp: {} }}\n",
        tcp_target, udp_target
    ));
    s.push_str("\t}\n");
}

/// clen 对齐 Go 的 len(strings.Split(s, "/"))，即 "/" 分隔的段数。
fn clen(s: &str) -> usize {
    s.split('/').count()
}

/// 兼容：检查路径存在（保留以备扩展使用）。
#[allow(dead_code)]
fn path_exists(p: &str) -> bool {
    Path::new(p).exists()
}
