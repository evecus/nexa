//! iptables 回退后端，1:1 对齐 Go 版 internal/netmanager/iptables.go。
//!
//! 在没有可用 nftables(fw4) 时使用 iptables / ip6tables（+ ipset），
//! 尽量对齐 nfttemplate 中 hijack.ut 的行为：DNS 劫持、TCP 透明代理（REDIRECT/TPROXY）、
//! TUN 放行、用户/组/MAC/IP/cgroup 访问控制、DSCP/fwmark/cgroup/gid 绕过、
//! 保留地址段/fake-ip 排除、中国大陆 IP 绕过、fake-ip ping 劫持。
//!
//! 与 nftables(fw4) 版本相比的架构性差异（与 Go 版一致）：
//!   - 本机流量的 tproxy：TPROXY target 只能挂在 PREROUTING 上，本机流量走 OUTPUT 不支持 TPROXY，
//!     改用「打 fwmark + 复用 Apply() 中已建立的 ip rule/route 策略路由」近似实现；
//!   - cgroup 防回环：先探测系统是否真的支持 cgroup，不支持时全部跳过，改用 GID 绕过兜底。

use std::collections::HashMap;
use std::process::Command;

use crate::config::Config;
use crate::netmanager::{run, NetManager};
use crate::paths;

pub const NEXA_COMMENT: &str = "nexa";

const IPSET_CHINA_V4: &str = "nexa_china_v4";
const IPSET_CHINA_V6: &str = "nexa_china_v6";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Nftables,
    Iptables,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Nftables => "nftables",
            Backend::Iptables => "iptables",
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一次 Apply 建立的所有自定义链名，Cleanup 时对称删除。
const CHAINS: &[&str] = &[
    "NEXA_BYPASS_R",     // router 绕过判断（cgroup/gid/mark/reserved/china/dscp/fwmark）
    "NEXA_DNS_HIJACK_R", // router dns hijack
    "NEXA_REDIRECT_R",   // router tcp redirect
    "NEXA_TPROXY_R",     // router tproxy（用 MARK 近似）
    "NEXA_TUN_BYPASS_R", // router tun 模式下的绕过判断
    "NEXA_BYPASS_L",     // lan 绕过判断
    "NEXA_DNS_HIJACK_L", // lan dns hijack
    "NEXA_REDIRECT_L",   // lan tcp redirect
    "NEXA_TPROXY_L",     // lan tproxy（真 TPROXY target）
];

fn chain_table(chain: &str) -> &'static str {
    match chain {
        "NEXA_TPROXY_R" | "NEXA_TPROXY_L" | "NEXA_TUN_BYPASS_R" => "mangle",
        _ => "nat",
    }
}

/// 检测系统当前使用的防火墙后端。
/// nft 存在且 fw4 已运行时用 nftables；否则有 iptables 就用 iptables；都没有则回退 nftables。
pub fn detect_backend() -> Backend {
    if crate::netmanager::has_command("nft") && fw4_running() {
        return Backend::Nftables;
    }
    if crate::netmanager::has_command("iptables") {
        return Backend::Iptables;
    }
    Backend::Nftables
}

fn fw4_running() -> bool {
    if !crate::netmanager::has_command("nft") {
        return false;
    }
    if let Ok(out) = Command::new("nft").args(["list", "table", "inet", "fw4"]).output() {
        if out.status.success() && !out.stdout.is_empty() {
            return true;
        }
    }
    if crate::netmanager::has_command("fw4") {
        if let Ok(out) = Command::new("/etc/init.d/firewall").arg("status").output() {
            let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
            if s.contains("running") {
                return true;
            }
        }
    }
    false
}

// ── apply / cleanup 入口 ────────────────────────────────

pub fn apply(mgr: &NetManager, cfg: &Config, lan_devs: &[String]) -> anyhow::Result<()> {
    let p = &cfg.proxy;
    let r = &cfg.routing;
    mgr.log
        .app("代理", "检测到 iptables 防火墙，使用 iptables 应用流量劫持规则。");

    // 先清理旧规则，保证幂等。
    cleanup(mgr, cfg);

    let mut caps = MatchSupportCache::new();

    let tcp_mode = p.tcp_mode.as_str();
    let udp_mode = p.udp_mode.as_str();
    let tproxy_enable = tcp_mode == "tproxy" || udp_mode == "tproxy";
    let tun_enable = tcp_mode == "tun" || udp_mode == "tun";
    let mark_dependent = tproxy_enable || tun_enable;

    // ── 能力探测：提前判断 IPv4/IPv6 各自实际可用性 ──
    let redirect_supported6 = caps.supports_target("ip6tables", "REDIRECT", "--to-ports");
    if tcp_mode == "redirect" && p.ipv6_proxy && !redirect_supported6 {
        mgr.log.app("代理", "当前设备内核缺少 ip6tables REDIRECT 模块的 --to-ports 支持，已放弃启动 IPv6 相关规则。");
    }
    if mark_dependent {
        let _ = Command::new("modprobe").arg("xt_MARK").output();
    }
    let mark_supported4 = caps.supports_target("iptables", "MARK", "--set-mark");
    let mark_supported6 = caps.supports_target("ip6tables", "MARK", "--set-mark");
    if mark_dependent && p.ipv4_proxy && !mark_supported4 {
        mgr.log.app("代理", "当前设备内核可能缺少 xt_MARK 模块支持，已放弃启动 IPv4 相关规则。");
    }
    if mark_dependent && p.ipv6_proxy && !mark_supported6 {
        mgr.log.app("代理", "当前设备内核可能缺少 xt_MARK 模块支持，已放弃启动 IPv6 相关规则。");
    }

    if tproxy_enable {
        let _ = Command::new("modprobe").arg("xt_TPROXY").output();
        if p.ipv4_proxy && !caps.supports_target("iptables", "TPROXY", "--on-port") {
            mgr.log.app("代理", "当前设备内核可能缺少 xt_TPROXY 模块支持，局域网 tproxy 规则改用 MARK+策略路由近似实现。");
        }
        if p.ipv6_proxy && !caps.supports_target("ip6tables", "TPROXY", "--on-port") {
            mgr.log.app("代理", "当前设备内核可能缺少 ip6tables TPROXY 模块支持，局域网 tproxy(v6) 规则改用 MARK+策略路由近似实现。");
        }
    }
    let lan_tproxy_supported4 = tproxy_enable && caps.supports_target("iptables", "TPROXY", "--on-port");
    let lan_tproxy_supported6 = tproxy_enable && caps.supports_target("ip6tables", "TPROXY", "--on-port");

    // 有效 IPv4/IPv6 可用性：原始开关 AND 能力探测结果（不回写 cfg）。
    let ipv4_proxy = p.ipv4_proxy && (!mark_dependent || mark_supported4);
    let ipv6_proxy = p.ipv6_proxy && (tcp_mode != "redirect" || redirect_supported6) && (!mark_dependent || mark_supported6);
    let ipv4_dns_hijack = p.ipv4_dns_hijack;
    let ipv6_dns_hijack = p.ipv6_dns_hijack;

    let mut ipt = IptWriter::new("iptables", ipv4_proxy || ipv4_dns_hijack);
    let mut ip6t = IptWriter::new("ip6tables", ipv6_proxy || ipv6_dns_hijack);

    // 中国大陆 IP 绕过：用 ipset 承载地址集合（对齐 nft china_ip/china_ip6 命名集合）。
    let mut china_v4_ready = false;
    let mut china_v6_ready = false;
    if p.bypass_china_mainland_ip {
        match crate::netmanager::extract_geoip_elements(&paths::geoip_cn_nft().to_string_lossy()) {
            Ok(els) => match load_ipset(IPSET_CHINA_V4, "hash:net", "inet", &els) {
                Ok(()) => china_v4_ready = true,
                Err(e) => mgr.log.app("代理", &format!("创建 ipset {} 失败：{}", IPSET_CHINA_V4, e)),
            },
            Err(e) => mgr.log.app("代理", &format!("读取 geoip_cn.nft 失败：{}", e)),
        }
    }
    if p.bypass_china_mainland_ip6 {
        match crate::netmanager::extract_geoip_elements(&paths::geoip6_cn_nft().to_string_lossy()) {
            Ok(els) => match load_ipset(IPSET_CHINA_V6, "hash:net", "inet6", &els) {
                Ok(()) => china_v6_ready = true,
                Err(e) => mgr.log.app("代理", &format!("创建 ipset {} 失败：{}", IPSET_CHINA_V6, e)),
            },
            Err(e) => mgr.log.app("代理", &format!("读取 geoip6_cn.nft 失败：{}", e)),
        }
    }

    // 建自定义链
    for c in CHAINS {
        if ipv4_proxy || ipv4_dns_hijack {
            ipt.run(&["-t", chain_table(c), "-N", c]);
        }
        if ipv6_proxy || ipv6_dns_hijack {
            ip6t.run(&["-t", chain_table(c), "-N", c]);
        }
    }

    let core_gid = lookup_nexa_gid();

    // 有效防回环策略：系统不支持 cgroup 时强制启用 GID 绕过、关闭 cgroup 绕过。
    let cg_version = crate::netmanager::cgroups_version(); // 0=不支持，1=v1，2=v2
    let effective_bypass_cgroup = p.bypass_cgroup && cg_version != 0;
    let effective_bypass_gid = p.bypass_gid || cg_version == 0;

    let mut opts = BypassOptions {
        cgroups_version: cg_version,
        cgroup_id: r.cgroup_id.clone(),
        cgroup_name: r.cgroup_name.clone(),
        core_gid,
        bypass_cgroup: effective_bypass_cgroup,
        bypass_gid: effective_bypass_gid,
        bypass_mark: p.bypass_mark,
        bypass_mark_values: p.bypass_mark_values.clone(),
        bypass_dscp: p.bypass_dscp.clone(),
        bypass_fwmark: p.bypass_fwmark.clone(),
        reserved_ip: p.reserved_ip.clone(),
        reserved_ip6: p.reserved_ip6.clone(),
        fake_ip_range: p.fake_ip_range.clone(),
        fake_ip6_range: p.fake_ip6_range.clone(),
        china_v4_ready,
        china_v6_ready,
        caps: &mut caps,
    };
    if cg_version == 0 && p.bypass_cgroup {
        mgr.log.app("代理", "当前系统不支持 cgroup 防回环，iptables 规则已自动改用 GID 绕过。");
    }

    // ── Router（本机流量）绕过判断 + DNS 劫持 + TCP 重定向/透明代理 ──
    if p.router_proxy {
        build_bypass_chain(&mut ipt, "NEXA_BYPASS_R", &mut opts, true);
        build_bypass_chain(&mut ip6t, "NEXA_BYPASS_R", &mut opts, false);

        for ac in &cfg.router_access_controls {
            if !ac.enabled {
                continue;
            }
            build_dns_hijack_rules(&mut ipt, "NEXA_DNS_HIJACK_R", &ac.user, &ac.group, ac.dns, &p.dns_port, ipv4_dns_hijack);
            build_dns_hijack_rules(&mut ip6t, "NEXA_DNS_HIJACK_R", &ac.user, &ac.group, ac.dns, &p.dns_port, ipv6_dns_hijack);

            if tcp_mode == "redirect" {
                build_redirect_rules(&mut ipt, "NEXA_REDIRECT_R", &ac.user, &ac.group, ac.proxy, &p.redir_port, ipv4_proxy);
                build_redirect_rules(&mut ip6t, "NEXA_REDIRECT_R", &ac.user, &ac.group, ac.proxy, &p.redir_port, ipv6_proxy);
            }
            if tproxy_enable {
                build_tproxy_mark_rules(&mut ipt, "NEXA_TPROXY_R", &ac.user, &ac.group, ac.proxy, &r.tproxy_fw_mark, ipv4_proxy);
                build_tproxy_mark_rules(&mut ip6t, "NEXA_TPROXY_R", &ac.user, &ac.group, ac.proxy, &r.tproxy_fw_mark, ipv6_proxy);
            }
            if tun_enable {
                build_tproxy_mark_rules(&mut ipt, "NEXA_TUN_BYPASS_R", &ac.user, &ac.group, ac.proxy, &r.tun_fw_mark, ipv4_proxy);
                build_tproxy_mark_rules(&mut ip6t, "NEXA_TUN_BYPASS_R", &ac.user, &ac.group, ac.proxy, &r.tun_fw_mark, ipv6_proxy);
            }
        }

        if ipv4_dns_hijack || ipv4_proxy {
            ipt.run(&["-t", "nat", "-A", "OUTPUT", "-j", "NEXA_DNS_HIJACK_R", "-m", "comment", "--comment", NEXA_COMMENT]);
        }
        if ipv6_dns_hijack || ipv6_proxy {
            ip6t.run(&["-t", "nat", "-A", "OUTPUT", "-j", "NEXA_DNS_HIJACK_R", "-m", "comment", "--comment", NEXA_COMMENT]);
        }
        if tcp_mode == "redirect" {
            if ipv4_proxy {
                ipt.run(&["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", NEXA_COMMENT]);
                ipt.run(&["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "NEXA_REDIRECT_R", "-m", "comment", "--comment", NEXA_COMMENT]);
            }
            if ipv6_proxy {
                ip6t.run(&["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", NEXA_COMMENT]);
                ip6t.run(&["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "NEXA_REDIRECT_R", "-m", "comment", "--comment", NEXA_COMMENT]);
            }
        }
        if tproxy_enable {
            if ipv4_proxy {
                ipt.run(&["-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", NEXA_COMMENT]);
                ipt.run(&["-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_TPROXY_R", "-m", "comment", "--comment", NEXA_COMMENT]);
            }
            if ipv6_proxy {
                ip6t.run(&["-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", NEXA_COMMENT]);
                ip6t.run(&["-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_TPROXY_R", "-m", "comment", "--comment", NEXA_COMMENT]);
            }
        }
        if tun_enable {
            if ipv4_proxy {
                ipt.run(&["-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", NEXA_COMMENT]);
                ipt.run(&["-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_TUN_BYPASS_R", "-m", "comment", "--comment", NEXA_COMMENT]);
            }
            if ipv6_proxy {
                ip6t.run(&["-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_BYPASS_R", "-m", "comment", "--comment", NEXA_COMMENT]);
                ip6t.run(&["-t", "mangle", "-A", "OUTPUT", "-j", "NEXA_TUN_BYPASS_R", "-m", "comment", "--comment", NEXA_COMMENT]);
            }
        }
    }

    // ── LAN（局域网转发流量）──
    if p.lan_proxy {
        build_bypass_chain(&mut ipt, "NEXA_BYPASS_L", &mut opts, true);
        build_bypass_chain(&mut ip6t, "NEXA_BYPASS_L", &mut opts, false);

        for ac in &cfg.lan_access_controls {
            if !ac.enabled {
                continue;
            }
            build_lan_dns_hijack_rules(&mut ipt, "NEXA_DNS_HIJACK_L", &ac.ip, &ac.mac, ac.dns, &p.dns_port, ipv4_dns_hijack);
            build_lan_dns_hijack_rules(&mut ip6t, "NEXA_DNS_HIJACK_L", &ac.ip6, &ac.mac, ac.dns, &p.dns_port, ipv6_dns_hijack);

            if tcp_mode == "redirect" {
                build_lan_redirect_rules(&mut ipt, "NEXA_REDIRECT_L", &ac.ip, &ac.mac, ac.proxy, &p.redir_port, ipv4_proxy);
                build_lan_redirect_rules(&mut ip6t, "NEXA_REDIRECT_L", &ac.ip6, &ac.mac, ac.proxy, &p.redir_port, ipv6_proxy);
            }
            if tproxy_enable || tun_enable {
                let port = p.tproxy_port.clone();
                let mut mark = r.tproxy_fw_mark.clone();
                if tun_enable {
                    mark = r.tun_fw_mark.clone();
                }
                build_lan_tproxy_rules(&mut ipt, "NEXA_TPROXY_L", &ac.ip, &ac.mac, ac.proxy, &port, &mark, ipv4_proxy, lan_tproxy_supported4);
                build_lan_tproxy_rules(&mut ip6t, "NEXA_TPROXY_L", &ac.ip6, &ac.mac, ac.proxy, &port, &mark, ipv6_proxy, lan_tproxy_supported6);
            }
        }
        for dev in lan_devs {
            if ipv4_dns_hijack || ipv4_proxy {
                ipt.run(&["-t", "nat", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_DNS_HIJACK_L", "-m", "comment", "--comment", NEXA_COMMENT]);
            }
            if ipv6_dns_hijack || ipv6_proxy {
                ip6t.run(&["-t", "nat", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_DNS_HIJACK_L", "-m", "comment", "--comment", NEXA_COMMENT]);
            }
            if tcp_mode == "redirect" {
                if ipv4_proxy {
                    ipt.run(&["-t", "nat", "-A", "PREROUTING", "-i", dev, "-p", "tcp", "-j", "NEXA_BYPASS_L", "-m", "comment", "--comment", NEXA_COMMENT]);
                    ipt.run(&["-t", "nat", "-A", "PREROUTING", "-i", dev, "-p", "tcp", "-j", "NEXA_REDIRECT_L", "-m", "comment", "--comment", NEXA_COMMENT]);
                }
                if ipv6_proxy {
                    ip6t.run(&["-t", "nat", "-A", "PREROUTING", "-i", dev, "-p", "tcp", "-j", "NEXA_BYPASS_L", "-m", "comment", "--comment", NEXA_COMMENT]);
                    ip6t.run(&["-t", "nat", "-A", "PREROUTING", "-i", dev, "-p", "tcp", "-j", "NEXA_REDIRECT_L", "-m", "comment", "--comment", NEXA_COMMENT]);
                }
            }
            if tproxy_enable || tun_enable {
                if ipv4_proxy {
                    ipt.run(&["-t", "mangle", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_BYPASS_L", "-m", "comment", "--comment", NEXA_COMMENT]);
                    ipt.run(&["-t", "mangle", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_TPROXY_L", "-m", "comment", "--comment", NEXA_COMMENT]);
                }
                if ipv6_proxy {
                    ip6t.run(&["-t", "mangle", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_BYPASS_L", "-m", "comment", "--comment", NEXA_COMMENT]);
                    ip6t.run(&["-t", "mangle", "-A", "PREROUTING", "-i", dev, "-j", "NEXA_TPROXY_L", "-m", "comment", "--comment", NEXA_COMMENT]);
                }
            }
        }
    }

    // ── TUN 模式：放行进入 TUN 设备的流量 ──
    if tun_enable && !p.tun_device.is_empty() {
        ipt.run(&["-t", "filter", "-I", "INPUT", "-i", &p.tun_device, "-j", "ACCEPT", "-m", "comment", "--comment", NEXA_COMMENT]);
        ipt.run(&["-t", "filter", "-I", "FORWARD", "-o", &p.tun_device, "-j", "ACCEPT", "-m", "comment", "--comment", NEXA_COMMENT]);
        ipt.run(&["-t", "filter", "-I", "FORWARD", "-i", &p.tun_device, "-j", "ACCEPT", "-m", "comment", "--comment", NEXA_COMMENT]);
        if ipv6_proxy {
            ip6t.run(&["-t", "filter", "-I", "INPUT", "-i", &p.tun_device, "-j", "ACCEPT", "-m", "comment", "--comment", NEXA_COMMENT]);
            ip6t.run(&["-t", "filter", "-I", "FORWARD", "-o", &p.tun_device, "-j", "ACCEPT", "-m", "comment", "--comment", NEXA_COMMENT]);
            ip6t.run(&["-t", "filter", "-I", "FORWARD", "-i", &p.tun_device, "-j", "ACCEPT", "-m", "comment", "--comment", NEXA_COMMENT]);
        }
    }

    // ── fake-ip ping 劫持 ──
    if p.fake_ip_ping_hijack && !p.fake_ip_range.is_empty() && ipv4_proxy {
        ipt.run(&["-t", "nat", "-A", "PREROUTING", "-p", "icmp", "--icmp-type", "echo-request", "-d", &p.fake_ip_range, "-j", "REDIRECT", "-m", "comment", "--comment", NEXA_COMMENT]);
    }
    if p.fake_ip_ping_hijack && !p.fake_ip6_range.is_empty() && ipv6_proxy {
        ip6t.run(&["-t", "nat", "-A", "PREROUTING", "-p", "ipv6-icmp", "--icmpv6-type", "echo-request", "-d", &p.fake_ip6_range, "-j", "REDIRECT", "-m", "comment", "--comment", NEXA_COMMENT]);
    }

    if p.bypass_china_mainland_ip && !china_v4_ready {
        mgr.log.app("代理", "警告：中国大陆 IPv4 绕过未生效（ipset 加载失败）。");
    }
    if p.bypass_china_mainland_ip6 && !china_v6_ready {
        mgr.log.app("代理", "警告：中国大陆 IPv6 绕过未生效（ipset 加载失败）。");
    }
    if tproxy_enable {
        mgr.log.app("代理", "已应用 iptables 透明代理(TPROXY)规则；局域网转发流量使用真实 TPROXY target，本机流量使用 fwmark+策略路由近似实现；若内核未加载 xt_TPROXY 模块，该模式将不可用，请改用 redirect 或 tun 模式。");
    } else {
        mgr.log.app("代理", "iptables 流量劫持规则已应用。");
    }
    Ok(())
}

pub fn cleanup(_mgr: &NetManager, _cfg: &Config) {
    for ipt in ["iptables", "ip6tables"] {
        if !crate::netmanager::has_command(ipt) {
            continue;
        }
        delete_ipt_rules_by_comment(ipt, "nat", "OUTPUT");
        delete_ipt_rules_by_comment(ipt, "nat", "PREROUTING");
        delete_ipt_rules_by_comment(ipt, "mangle", "OUTPUT");
        delete_ipt_rules_by_comment(ipt, "mangle", "PREROUTING");
        delete_ipt_rules_by_comment(ipt, "filter", "INPUT");
        delete_ipt_rules_by_comment(ipt, "filter", "FORWARD");

        for c in CHAINS {
            let t = chain_table(c);
            run(ipt, &["-t", t, "-F", c]);
            run(ipt, &["-t", t, "-X", c]);
        }
    }
    // 删除 ipset（先要求没有规则引用，因此放在 iptables 规则清理之后）
    if crate::netmanager::has_command("ipset") {
        run("ipset", &["destroy", IPSET_CHINA_V4]);
        run("ipset", &["destroy", IPSET_CHINA_V6]);
    }
}

/// 反复查找并删除指定 table/chain 中带 nexa comment 的规则，直到没有为止。
fn delete_ipt_rules_by_comment(ipt: &str, table: &str, chain: &str) {
    for _ in 0..128 {
        // 上限保护，避免异常规则集导致死循环
        let out = match Command::new(ipt).args(["-t", table, "-S", chain]).output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return,
        };
        let spec = match find_commented_rule(&out, NEXA_COMMENT) {
            Some(s) => s,
            None => return,
        };
        let mut args = vec!["-t".to_string(), table.to_string(), "-D".to_string(), chain.to_string()];
        args.extend(spec);
        let status = Command::new(ipt).args(&args).status();
        if status.map(|s| !s.success()).unwrap_or(true) {
            return;
        }
    }
}

/// 从 `iptables -S <chain>` 输出中找到第一条带 --comment "nexa" 的规则，
/// 返回可直接拼到 -D 后面的匹配参数（去掉开头的 -A <chain>）。
fn find_commented_rule(spec: &str, comment: &str) -> Option<Vec<String>> {
    let quoted = format!("--comment \"{}\"", comment);
    let unquoted = format!("--comment {}", comment);
    for line in spec.lines() {
        if !line.contains(&quoted) && !line.contains(&unquoted) {
            continue;
        }
        let fields = split_args(line);
        if fields.len() < 2 || fields[0] != "-A" {
            continue;
        }
        return Some(fields[2..].to_vec());
    }
    None
}

/// 简单地按空白切分并还原带引号的参数（iptables -S 输出对含空格的值加引号）。
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    for ch in s.chars() {
        match ch {
            '"' => in_quote = !in_quote,
            ' ' if !in_quote => {
                if !cur.is_empty() {
                    out.push(cur.clone());
                    cur.clear();
                }
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

// ── ipset 辅助（中国大陆 IP 绕过） ─────────────────────

fn load_ipset(name: &str, set_type: &str, family: &str, elements: &str) -> anyhow::Result<()> {
    if !crate::netmanager::has_command("ipset") {
        anyhow::bail!("系统未安装 ipset 命令");
    }
    // 用临时 set + swap，避免大集合重建期间出现规则短暂失配。
    let tmp = format!("{}_tmp", name);
    run("ipset", &["destroy", &tmp]); // 忽略残留
    must_run("ipset", &["create", &tmp, set_type, "family", family, "-exist"])?;
    let cidrs = split_cidr_list(elements);
    let restore_input = build_ipset_restore(&tmp, &cidrs);
    let child = Command::new("ipset")
        .arg("restore")
        .stdin(std::process::Stdio::piped())
        .spawn();
    match child {
        Ok(mut c) => {
            if let Some(mut stdin) = c.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(restore_input.as_bytes());
            }
            match c.wait_with_output() {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    run("ipset", &["destroy", &tmp]);
                    anyhow::bail!("ipset restore 失败: {}", String::from_utf8_lossy(&o.stderr).trim());
                }
                Err(e) => {
                    run("ipset", &["destroy", &tmp]);
                    anyhow::bail!("ipset restore 失败: {}", e);
                }
            }
        }
        Err(e) => {
            run("ipset", &["destroy", &tmp]);
            anyhow::bail!("启动 ipset restore 失败: {}", e);
        }
    }
    if let Err(e) = must_run("ipset", &["create", name, set_type, "family", family, "-exist"]) {
        run("ipset", &["destroy", &tmp]);
        return Err(e);
    }
    if let Err(e) = must_run("ipset", &["swap", &tmp, name]) {
        run("ipset", &["destroy", &tmp]);
        return Err(e);
    }
    run("ipset", &["destroy", &tmp]);
    Ok(())
}

fn must_run(name: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(name).args(args).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "{} {}: {}",
            name,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn split_cidr_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|f| f.trim())
        .filter(|f| !f.is_empty())
        .map(|f| f.to_string())
        .collect()
}

fn build_ipset_restore(name: &str, cidrs: &[String]) -> String {
    let mut b = String::new();
    for c in cidrs {
        b.push_str(&format!("add {} {} -exist\n", name, c));
    }
    b
}

// ── 绕过判断链 ──────────────────────────────────────────

struct BypassOptions<'a> {
    cgroups_version: i32,
    cgroup_id: String,
    cgroup_name: String,
    core_gid: String,
    bypass_cgroup: bool,
    bypass_gid: bool,
    bypass_mark: bool,
    bypass_mark_values: Vec<String>,
    bypass_dscp: Vec<String>,
    bypass_fwmark: Vec<String>,
    reserved_ip: Vec<String>,
    reserved_ip6: Vec<String>,
    fake_ip_range: String,
    fake_ip6_range: String,
    china_v4_ready: bool,
    china_v6_ready: bool,
    caps: &'a mut MatchSupportCache,
}

fn build_bypass_chain(w: &mut IptWriter, chain: &str, o: &mut BypassOptions, is_v4: bool) {
    if !w.enabled {
        return;
    }
    if o.bypass_cgroup {
        let supports = match o.cgroups_version {
            1 => !o.cgroup_id.is_empty() && o.caps.supports_match(&w.bin, "cgroup", "--cgroup"),
            2 => !o.cgroup_name.is_empty() && o.caps.supports_match(&w.bin, "cgroup", "--path"),
            _ => false,
        };
        if supports && o.cgroups_version == 1 {
            let cid = hex_to_decimal(&o.cgroup_id);
            w.run(&[
                "-t", chain_table(chain), "-A", chain, "-m", "cgroup", "--cgroup", &cid, "-j", "RETURN",
            ]);
        } else if supports && o.cgroups_version == 2 {
            let path = format!("services/{}", o.cgroup_name);
            w.run(&[
                "-t", chain_table(chain), "-A", chain, "-m", "cgroup", "--path", &path, "-j", "RETURN",
            ]);
        }
    }
    // gid 绕过（核心自身进程组）
    if o.bypass_gid && !o.core_gid.is_empty() {
        let gid = o.core_gid.clone();
        w.run(&[
            "-t", chain_table(chain), "-A", chain, "-m", "owner", "--gid-owner", &gid, "-j", "RETURN",
        ]);
    }
    // 已有 fwmark 绕过
    if o.bypass_mark {
        for mv in &o.bypass_mark_values.clone() {
            if mv.is_empty() {
                continue;
            }
            w.run(&["-t", chain_table(chain), "-A", chain, "-m", "mark", "--mark", mv, "-j", "RETURN"]);
        }
    }
    // 保留地址段 / fake-ip 排除
    if is_v4 {
        for cidr in &o.reserved_ip.clone() {
            let mut args: Vec<String> = vec!["-t".into(), chain_table(chain).into(), "-A".into(), chain.into(), "-d".into(), cidr.clone()];
            if !o.fake_ip_range.is_empty() {
                args.push("!".into());
                args.push("-d".into());
                args.push(o.fake_ip_range.clone());
            }
            args.push("-j".into());
            args.push("RETURN".into());
            w.run_str(&args);
        }
        if o.china_v4_ready {
            w.run(&["-t", chain_table(chain), "-A", chain, "-m", "set", "--match-set", IPSET_CHINA_V4, "dst", "-j", "RETURN"]);
        }
    } else {
        for cidr in &o.reserved_ip6.clone() {
            let mut args: Vec<String> = vec!["-t".into(), chain_table(chain).into(), "-A".into(), chain.into(), "-d".into(), cidr.clone()];
            if !o.fake_ip6_range.is_empty() {
                args.push("!".into());
                args.push("-d".into());
                args.push(o.fake_ip6_range.clone());
            }
            args.push("-j".into());
            args.push("RETURN".into());
            w.run_str(&args);
        }
        if o.china_v6_ready {
            w.run(&["-t", chain_table(chain), "-A", chain, "-m", "set", "--match-set", IPSET_CHINA_V6, "dst", "-j", "RETURN"]);
        }
    }
    // DSCP 绕过
    for dscp in &o.bypass_dscp.clone() {
        if dscp.is_empty() {
            continue;
        }
        let mut args: Vec<String> = vec!["-t".into(), chain_table(chain).into(), "-A".into(), chain.into(), "-m".into(), "dscp".into(), "--dscp".into(), dscp.clone()];
        if is_v4 && !o.fake_ip_range.is_empty() {
            args.push("!".into());
            args.push("-d".into());
            args.push(o.fake_ip_range.clone());
        } else if !is_v4 && !o.fake_ip6_range.is_empty() {
            args.push("!".into());
            args.push("-d".into());
            args.push(o.fake_ip6_range.clone());
        }
        args.push("-j".into());
        args.push("RETURN".into());
        w.run_str(&args);
    }
    // 指定 fwmark/mask 绕过
    for fm in &o.bypass_fwmark.clone() {
        let (mark, mask) = match fm.find('/') {
            Some(i) => (fm[..i].to_string(), fm[i + 1..].to_string()),
            None => (fm.clone(), "0xFFFFFFFF".to_string()),
        };
        let combined = format!("{}/{}", mark, mask);
        w.run(&["-t", chain_table(chain), "-A", chain, "-m", "mark", "--mark", &combined, "-j", "RETURN"]);
    }
}

/// 把 "0x07250725" 这种 net_cls classid 转成 --cgroup 需要的十进制字符串。
fn hex_to_decimal(hex_id: &str) -> String {
    let h = hex_id.trim_start_matches("0x").trim_start_matches("0X");
    match u64::from_str_radix(h, 16) {
        Ok(v) => v.to_string(),
        Err(_) => hex_id.to_string(),
    }
}

/// 查找 nexa 组的 GID，找不到返回空字符串（对齐 nfttemplate.lookup_core_gid）。
pub fn lookup_nexa_gid() -> String {
    match Command::new("getent").args(["group", "nexa"]).output() {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let fields: Vec<&str> = s.split(':').collect();
            if fields.len() >= 3 {
                fields[2].to_string()
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    }
}

// ── 规则构建 helper ────────────────────────────────────

/// 包装 Command，按 enabled 开关决定是否真正执行（对应 ipv4/ipv6 独立开关）。
struct IptWriter {
    bin: String,
    enabled: bool,
}

impl IptWriter {
    fn new(bin: &str, enabled: bool) -> Self {
        Self {
            bin: bin.to_string(),
            enabled,
        }
    }

    fn run(&self, args: &[&str]) {
        if !self.enabled {
            return;
        }
        run(&self.bin, args);
    }

    fn run_str(&self, args: &[String]) {
        if !self.enabled {
            return;
        }
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        run(&self.bin, &refs);
    }
}

fn dns_action(dns: bool) -> &'static str {
    if dns {
        "REDIRECT"
    } else {
        "RETURN"
    }
}

fn build_dns_hijack_rules(
    w: &mut IptWriter,
    chain: &str,
    users: &[String],
    groups: &[String],
    dns: bool,
    dns_port: &str,
    proto_enabled: bool,
) {
    if !proto_enabled || !w.enabled {
        return;
    }
    let action = dns_action(dns);
    if users.is_empty() && groups.is_empty() {
        for proto in ["tcp", "udp"] {
            let mut args = vec!["-t", "nat", "-A", chain, "-p", proto, "--dport", "53", "-j", action];
            if dns {
                args.extend(["--to-ports", dns_port]);
            }
            w.run(&args);
        }
        return;
    }
    let joined_users = users.join(",");
    let joined_groups = groups.join(",");
    if !users.is_empty() {
        for proto in ["tcp", "udp"] {
            let mut args = vec![
                "-t", "nat", "-A", chain, "-p", proto, "--dport", "53", "-m", "owner", "--uid-owner", &joined_users, "-j", action,
            ];
            if dns {
                args.extend(["--to-ports", dns_port]);
            }
            w.run(&args);
        }
    }
    if !groups.is_empty() {
        for proto in ["tcp", "udp"] {
            let mut args = vec![
                "-t", "nat", "-A", chain, "-p", proto, "--dport", "53", "-m", "owner", "--gid-owner", &joined_groups, "-j", action,
            ];
            if dns {
                args.extend(["--to-ports", dns_port]);
            }
            w.run(&args);
        }
    }
}

fn build_lan_dns_hijack_rules(
    w: &mut IptWriter,
    chain: &str,
    ips: &[String],
    macs: &[String],
    dns: bool,
    dns_port: &str,
    proto_enabled: bool,
) {
    if !proto_enabled || !w.enabled {
        return;
    }
    let action = dns_action(dns);
    if ips.is_empty() && macs.is_empty() {
        for proto in ["tcp", "udp"] {
            let mut args = vec!["-t", "nat", "-A", chain, "-p", proto, "--dport", "53", "-j", action];
            if dns {
                args.extend(["--to-ports", dns_port]);
            }
            w.run(&args);
        }
        return;
    }
    for ip in ips {
        for proto in ["tcp", "udp"] {
            let mut args = vec!["-t", "nat", "-A", chain, "-p", proto, "--dport", "53", "-s", ip, "-j", action];
            if dns {
                args.extend(["--to-ports", dns_port]);
            }
            w.run(&args);
        }
    }
    for mac in macs {
        for proto in ["tcp", "udp"] {
            let mut args = vec![
                "-t", "nat", "-A", chain, "-p", proto, "--dport", "53", "-m", "mac", "--mac-source", mac, "-j", action,
            ];
            if dns {
                args.extend(["--to-ports", dns_port]);
            }
            w.run(&args);
        }
    }
}

fn build_redirect_rules(
    w: &mut IptWriter,
    chain: &str,
    users: &[String],
    groups: &[String],
    proxy: bool,
    redir_port: &str,
    proto_enabled: bool,
) {
    if !proto_enabled || !w.enabled || !proxy {
        return;
    }
    if users.is_empty() && groups.is_empty() {
        w.run(&["-t", "nat", "-A", chain, "-p", "tcp", "-j", "REDIRECT", "--to-ports", redir_port]);
        return;
    }
    let joined_users = users.join(",");
    let joined_groups = groups.join(",");
    if !users.is_empty() {
        w.run(&["-t", "nat", "-A", chain, "-p", "tcp", "-m", "owner", "--uid-owner", &joined_users, "-j", "REDIRECT", "--to-ports", redir_port]);
    }
    if !groups.is_empty() {
        w.run(&["-t", "nat", "-A", chain, "-p", "tcp", "-m", "owner", "--gid-owner", &joined_groups, "-j", "REDIRECT", "--to-ports", redir_port]);
    }
}

fn build_lan_redirect_rules(
    w: &mut IptWriter,
    chain: &str,
    ips: &[String],
    macs: &[String],
    proxy: bool,
    redir_port: &str,
    proto_enabled: bool,
) {
    if !proto_enabled || !w.enabled || !proxy {
        return;
    }
    if ips.is_empty() && macs.is_empty() {
        w.run(&["-t", "nat", "-A", chain, "-p", "tcp", "-j", "REDIRECT", "--to-ports", redir_port]);
        return;
    }
    for ip in ips {
        w.run(&["-t", "nat", "-A", chain, "-p", "tcp", "-s", ip, "-j", "REDIRECT", "--to-ports", redir_port]);
    }
    for mac in macs {
        w.run(&["-t", "nat", "-A", chain, "-p", "tcp", "-m", "mac", "--mac-source", mac, "-j", "REDIRECT", "--to-ports", redir_port]);
    }
}

/// 本机（router）流量：真实 TPROXY 不能挂 OUTPUT，改为打 fwmark + 策略路由转发。
fn build_tproxy_mark_rules(
    w: &mut IptWriter,
    chain: &str,
    users: &[String],
    groups: &[String],
    proxy: bool,
    fwmark: &str,
    proto_enabled: bool,
) {
    if !proto_enabled || !w.enabled || !proxy {
        return;
    }
    if users.is_empty() && groups.is_empty() {
        w.run(&["-t", "mangle", "-A", chain, "-p", "tcp", "-j", "MARK", "--set-mark", fwmark]);
        w.run(&["-t", "mangle", "-A", chain, "-p", "udp", "-j", "MARK", "--set-mark", fwmark]);
        return;
    }
    let joined_users = users.join(",");
    let joined_groups = groups.join(",");
    if !users.is_empty() {
        w.run(&["-t", "mangle", "-A", chain, "-m", "owner", "--uid-owner", &joined_users, "-j", "MARK", "--set-mark", fwmark]);
    }
    if !groups.is_empty() {
        w.run(&["-t", "mangle", "-A", chain, "-m", "owner", "--gid-owner", &joined_groups, "-j", "MARK", "--set-mark", fwmark]);
    }
}

/// 局域网转发流量：PREROUTING 用真正的 TPROXY target；tun 模式改用 MARK。
#[allow(clippy::too_many_arguments)]
fn build_lan_tproxy_rules(
    w: &mut IptWriter,
    chain: &str,
    ips: &[String],
    macs: &[String],
    proxy: bool,
    port: &str,
    fwmark: &str,
    proto_enabled: bool,
    use_tproxy_target: bool,
) {
    if !proto_enabled || !w.enabled || !proxy {
        return;
    }
    let target = |_: &str| -> Vec<String> {
        if use_tproxy_target {
            vec![
                "-j".into(),
                "TPROXY".into(),
                "--tproxy-mark".into(),
                fwmark.into(),
                "--on-port".into(),
                port.into(),
            ]
        } else {
            vec!["-j".into(), "MARK".into(), "--set-mark".into(), fwmark.into()]
        }
    };
    if ips.is_empty() && macs.is_empty() {
        for proto in ["tcp", "udp"] {
            w.run_str(&base_args(chain, proto, None, None, &target(proto)));
        }
        return;
    }
    for ip in ips {
        for proto in ["tcp", "udp"] {
            w.run_str(&base_args(chain, proto, Some(ip), None, &target(proto)));
        }
    }
    for mac in macs {
        for proto in ["tcp", "udp"] {
            let mut args: Vec<String> = vec![
                "-t".into(),
                "mangle".into(),
                "-A".into(),
                chain.into(),
                "-p".into(),
                proto.into(),
                "-m".into(),
                "mac".into(),
                "--mac-source".into(),
                mac.clone(),
            ];
            args.extend(target(proto));
            w.run_str(&args);
        }
    }
}

/// 组装 `-t mangle -A <chain> -p <proto> [-s <ip>] ...` 前缀 + target 参数。
fn base_args(chain: &str, proto: &str, ip: Option<&str>, _mac: Option<&str>, target: &[String]) -> Vec<String> {
    let mut args: Vec<String> = vec!["-t".into(), "mangle".into(), "-A".into(), chain.into(), "-p".into(), proto.into()];
    if let Some(ip) = ip {
        args.push("-s".into());
        args.push(ip.to_string());
    }
    args.extend_from_slice(target);
    args
}

/// 缓存一次 apply 内已探测过的 (bin, module/target, flag) 组合，避免反复 fork 执行 `-h` 探测。
/// 特意不做成全局静态：iptables 版本、内核模块加载状态都可能在 nexa 运行期间变化，
/// 每次 Apply 都应该重新探测一次。
struct MatchSupportCache {
    map: HashMap<String, bool>,
}

impl MatchSupportCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// 探测是否编译了指定匹配模块的指定参数。
    fn supports_match(&mut self, bin: &str, module: &str, flag: &str) -> bool {
        let key = format!("{}|{}|{}", bin, module, flag);
        if let Some(v) = self.map.get(&key) {
            return *v;
        }
        let out = Command::new(bin).args(["-m", module, "-h"]).output();
        let supported = match out {
            Ok(o) => {
                let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                s.push_str(&String::from_utf8_lossy(&o.stderr));
                s.contains(flag)
            }
            Err(_) => false,
        };
        self.map.insert(key, supported);
        supported
    }

    /// 探测是否支持指定 target 的指定参数。
    fn supports_target(&mut self, bin: &str, target: &str, flag: &str) -> bool {
        let key = format!("{}|target:{}|{}", bin, target, flag);
        if let Some(v) = self.map.get(&key) {
            return *v;
        }
        let out = Command::new(bin).args(["-j", target, "-h"]).output();
        let supported = match out {
            Ok(o) => {
                let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                s.push_str(&String::from_utf8_lossy(&o.stderr));
                s.contains(flag)
            }
            Err(_) => false,
        };
        self.map.insert(key, supported);
        supported
    }
}
