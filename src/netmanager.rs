//! 复刻 proxy.init 的网络/防火墙配置逻辑：
//! cgroup / bridge-nf / TUN 等待 / ip route+rule / fake-ip6 dummy / nft 应用 / firewall_include / cleanup。
//! 全部通过 shell out 调 ip/nft/sysctl/mount，1:1 对齐原 shell 行为。

use std::fs;
use std::io::BufReader;
use std::process::Command;

use regex::Regex;

use crate::config::Config;
use crate::logger::Logger;
use crate::nfttemplate;
use crate::paths;
use std::sync::Arc;

pub struct Manager {
    log: Arc<Logger>,
}

impl Manager {
    pub fn new(log: Arc<Logger>) -> Self {
        Manager { log }
    }

    /// Apply 对齐 proxy.init start_service（proxy.enabled=1 时的网络配置）。
    pub fn apply(&self, cfg: &Config) -> anyhow::Result<()> {
        let p = &cfg.proxy;
        if !p.enabled {
            self.log.app("代理", "已禁用，跳过防火墙设置。");
            return Ok(());
        }
        self.log.app("代理", "已启用，配置防火墙规则。");

        let tproxy_enable = p.tcp_mode == "tproxy" || p.udp_mode == "tproxy";
        let tun_enable = p.tcp_mode == "tun" || p.udp_mode == "tun";

        // bridge-nf-call 兼容
        if tproxy_enable && has_bridge() && is_module_loaded("br_netfilter") {
            if p.ipv4_proxy {
                if sysctl_get("net.bridge.bridge-nf-call-iptables") == "1" {
                    let _ = fs::write(paths::BRIDGE_NF_CALL_IPTABLES_FLAG, b"");
                    sysctl_set("net.bridge.bridge-nf-call-iptables", "0");
                }
            }
            if p.ipv6_proxy {
                if sysctl_get("net.bridge.bridge-nf-call-ip6tables") == "1" {
                    let _ = fs::write(paths::BRIDGE_NF_CALL_IP6TABLES_FLAG, b"");
                    sysctl_set("net.bridge.bridge-nf-call-ip6tables", "0");
                }
            }
        }

        // TUN 设备等待
        if tun_enable && !p.tun_device.is_empty() {
            self.log.app(
                "代理",
                &format!("等待 TUN 设备上线，超时 {} 秒...", p.tun_timeout),
            );
            if !wait_for_tun(&p.tun_device, p.tun_timeout, p.tun_interval) {
                self.log.app("代理", "超时，TUN 设备未上线，退出。");
                return Err(anyhow::anyhow!("tun device {} not up", p.tun_device));
            }
            self.log.app("代理", "TUN 设备已上线。");
        }

        // ip route / rule
        let r = &cfg.routing;
        if tproxy_enable {
            if p.ipv4_proxy {
                run("ip", &["-4", "route", "add", "local", "default", "dev", "lo", "table", &r.tproxy_route_table]);
                run("ip", &["-4", "rule", "add", "pref", &r.tproxy_rule_pref.to_string(), "fwmark", &format!("{}/{}", r.tproxy_fw_mark, r.tproxy_fw_mask), "table", &r.tproxy_route_table]);
            }
            if p.ipv6_proxy {
                run("ip", &["-6", "route", "add", "local", "default", "dev", "lo", "table", &r.tproxy_route_table]);
                run("ip", &["-6", "rule", "add", "pref", &r.tproxy_rule_pref.to_string(), "fwmark", &format!("{}/{}", r.tproxy_fw_mark, r.tproxy_fw_mask), "table", &r.tproxy_route_table]);
            }
        }
        if tun_enable && !p.tun_device.is_empty() {
            if p.ipv4_proxy {
                run("ip", &["-4", "route", "add", "unicast", "default", "dev", &p.tun_device, "table", &r.tun_route_table]);
                run("ip", &["-4", "rule", "add", "pref", &r.tun_rule_pref.to_string(), "fwmark", &format!("{}/{}", r.tun_fw_mark, r.tun_fw_mask), "table", &r.tun_route_table]);
            }
            if p.ipv6_proxy {
                run("ip", &["-6", "route", "add", "unicast", "default", "dev", &p.tun_device, "table", &r.tun_route_table]);
                run("ip", &["-6", "rule", "add", "pref", &r.tun_rule_pref.to_string(), "fwmark", &format!("{}/{}", r.tun_fw_mark, r.tun_fw_mask), "table", &r.tun_route_table]);
            }
            self.firewall_include(cfg);
        }

        // fake-ip6 dummy
        if !p.fake_ip6_range.is_empty() {
            run("ip", &["link", "add", &r.dummy_device, "type", "dummy"]);
            run("ip", &["link", "set", "dev", &r.dummy_device, "up"]);
            run("ip", &["-6", "route", "add", &p.fake_ip6_range, "dev", &r.dummy_device]);
        }

        // nft 劫持规则
        let lan_devs = resolve_lan_devices(&p.lan_inbound_interface);
        let mut model = nfttemplate::build(cfg, lan_devs, netmanager_cgroups_version());
        // bypass 大陆 IP 时注入 elements
        if p.bypass_china_mainland_ip {
            match extract_geoip_elements(paths::GEOIP_CN_NFT) {
                Ok(els) => model.china_ip_elements = els,
                Err(e) => self.log.app("代理", &format!("读取 geoip_cn.nft 失败：{}", e)),
            }
        }
        if p.bypass_china_mainland_ip6 {
            match extract_geoip_elements(paths::GEOIP6_CN_NFT) {
                Ok(els) => model.china_ip6_elements = els,
                Err(e) => self.log.app("代理", &format!("读取 geoip6_cn.nft 失败：{}", e)),
            }
        }
        let ruleset = nfttemplate::render(&model);
        let output = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        match output {
            Ok(mut child) => {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all(ruleset.as_bytes());
                }
                let output = child.wait_with_output()?;
                if !output.status.success() {
                    let err = String::from_utf8_lossy(&output.stderr);
                    self.log.app("代理", &format!("流量劫持失败：{}", err.trim()));
                    return Err(anyhow::anyhow!("nft apply failed: {}", err.trim()));
                }
            }
            Err(e) => {
                self.log.app("代理", &format!("执行 nft 失败：{}", e));
                return Err(e.into());
            }
        }
        // 校验表是否存在
        if let Ok(out) = Command::new("nft").arg("list").arg("tables").output() {
            if String::from_utf8_lossy(&out.stdout).contains("inet nexa") {
                self.log.app("代理", "流量劫持成功。");
            } else {
                self.log.app("代理", "流量劫持失败。");
            }
        }
        Ok(())
    }

    /// FirewallInclude 对齐 firewall_include.sh：TUN 模式时往防火墙 input/forward 插 accept 规则。
    pub fn firewall_include(&self, cfg: &Config) {
        let p = &cfg.proxy;
        if !cfg.config.enabled || !p.enabled {
            return;
        }
        if p.tcp_mode != "tun" && p.udp_mode != "tun" {
            return;
        }
        if p.tun_device.is_empty() {
            return;
        }
        // 检测可用的防火墙表：优先 fw4（OpenWrt），回退 filter（普通 Linux）
        let mut fw_table = "fw4".to_string();
        let fw4 = Command::new("nft")
            .args(["list", "table", "inet", "fw4"])
            .output();
        match fw4 {
            Ok(o) if o.status.success() => {}
            fw4_result => {
                // fw4 不存在，尝试 inet filter
                let filter = Command::new("nft")
                    .args(["list", "table", "inet", "filter"])
                    .output();
                match filter {
                    Ok(o) if o.status.success() => {
                        fw_table = "filter".to_string();
                    }
                    filter_result => {
                        let fw4_out = fw4_result
                            .as_ref()
                            .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                            .unwrap_or_else(|e| e.to_string());
                        let filter_out = filter_result
                            .as_ref()
                            .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                            .unwrap_or_else(|e| e.to_string());
                        self.log.app(
                            "代理",
                            &format!(
                                "未检测到防火墙表(fw4/filter)，跳过 TUN 防火墙放行。fw4: {}, filter: {}",
                                fw4_out, filter_out
                            ),
                        );
                        return;
                    }
                }
            }
        }
        run("nft", &["insert", "rule", "inet", &fw_table, "input", "iifname", &p.tun_device, "counter", "accept", "comment", "nexa"]);
        run("nft", &["insert", "rule", "inet", &fw_table, "forward", "oifname", &p.tun_device, "counter", "accept", "comment", "nexa"]);
        run("nft", &["insert", "rule", "inet", &fw_table, "forward", "iifname", &p.tun_device, "counter", "accept", "comment", "nexa"]);
    }

    /// Cleanup 对齐 proxy.init cleanup()。
    pub fn cleanup(&self, cfg: &Config) {
        let r = &cfg.routing;

        // 删 ip rule/route（忽略错误）
        for args in [
            &["-4", "rule", "del", "table", &r.tproxy_route_table][..],
            &["-4", "rule", "del", "table", &r.tun_route_table][..],
            &["-6", "rule", "del", "table", &r.tproxy_route_table][..],
            &["-6", "rule", "del", "table", &r.tun_route_table][..],
            &["-4", "route", "flush", "table", &r.tproxy_route_table][..],
            &["-4", "route", "flush", "table", &r.tun_route_table][..],
            &["-6", "route", "flush", "table", &r.tproxy_route_table][..],
            &["-6", "route", "flush", "table", &r.tun_route_table][..],
        ] {
            run_ignore("ip", args);
        }
        run_ignore("ip", &["link", "del", &r.dummy_device]);

        // 删 nft 表
        run_ignore("nft", &["delete", "table", "inet", "nexa"]);

        // 删防火墙表中 comment=nexa 的规则
        delete_fw_rules_by_comment("fw4", "input");
        delete_fw_rules_by_comment("fw4", "forward");
        delete_fw_rules_by_comment("filter", "input");
        delete_fw_rules_by_comment("filter", "forward");

        // 恢复 bridge-nf-call
        if has_bridge() {
            if fs::metadata(paths::BRIDGE_NF_CALL_IPTABLES_FLAG).is_ok() {
                let _ = fs::remove_file(paths::BRIDGE_NF_CALL_IPTABLES_FLAG);
                sysctl_set("net.bridge.bridge-nf-call-iptables", "1");
            }
            if fs::metadata(paths::BRIDGE_NF_CALL_IP6TABLES_FLAG).is_ok() {
                let _ = fs::remove_file(paths::BRIDGE_NF_CALL_IP6TABLES_FLAG);
                sysctl_set("net.bridge.bridge-nf-call-ip6tables", "1");
            }
        }
    }
}

// ── helpers ──

/// netmanager 的 cgroups 版本检测：mount 输出含 type cgroup 视为 v1，否则 v2。
fn netmanager_cgroups_version() -> i32 {
    let f = match fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(_) => return 2,
    };
    for line in f.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[2] == "cgroup" {
            return 1;
        }
    }
    2
}

fn is_module_loaded(name: &str) -> bool {
    let f = match fs::read_to_string("/proc/modules") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let prefix = format!("{} ", name);
    for line in f.lines() {
        if line.starts_with(&prefix) {
            return true;
        }
    }
    false
}

fn sysctl_get(key: &str) -> String {
    Command::new("sysctl")
        .args(["-e", "-n", key])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn sysctl_set(key: &str, val: &str) {
    let _ = Command::new("sysctl")
        .args(["-q", "-w", &format!("{}={}", key, val)])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// waitForTUN 轮询 ip link show，等设备 UP。
fn wait_for_tun(dev: &str, timeout: i64, mut interval: i64) -> bool {
    if interval <= 0 {
        interval = 1;
    }
    let mut t = timeout;
    while t > 0 {
        let out = Command::new("ip")
            .args(["-j", "link", "show", "dev", dev])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout);
                if s.contains("\"UP\"") {
                    return true;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(interval as u64));
        t -= interval;
    }
    false
}

/// resolveLanDevices 把 interface 名解析为 device 名。
fn resolve_lan_devices(interfaces: &[String]) -> Vec<String> {
    let mut out = vec![];
    for iface in interfaces {
        if iface.is_empty() {
            continue;
        }
        if dir_exists(&format!("/sys/class/net/{}", iface)) {
            out.push(iface.clone());
            continue;
        }
        let br = format!("br-{}", iface);
        if dir_exists(&format!("/sys/class/net/{}", br)) {
            out.push(br);
        }
    }
    out
}

fn dir_exists(p: &str) -> bool {
    fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

/// hasBridge 检测系统是否存在网桥接口。
fn has_bridge() -> bool {
    let entries = match fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return false,
    };
    for e in entries.flatten() {
        if dir_exists(&format!("/sys/class/net/{}/bridge", e.file_name().to_string_lossy())) {
            return true;
        }
    }
    false
}

fn run(name: &str, args: &[&str]) {
    // 对齐 Go 版 runIgnore：丢弃 stdout/stderr，不污染 nexa 终端输出。
    // （std::process::Command 默认继承父进程 stdio，会打印子进程错误信息）
    let _ = Command::new(name)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn run_ignore(name: &str, args: &[&str]) {
    // 同上：cleanup 路径的 ip/nft 命令在非 root 或无对应资源时必然失败，
    // 这些是预期内的，不应打印到终端。
    let _ = Command::new(name)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn delete_fw_rules_by_comment(table: &str, chain: &str) {
    let out = Command::new("nft")
        .args(["list", "table", "inet", table])
        .output();
    let out = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return,
    };
    let handles = extract_handles_for_comment(&out, chain, "nexa");
    for h in handles {
        run_ignore(
            "nft",
            &[
                "delete",
                "rule",
                "inet",
                table,
                chain,
                "handle",
                &h.to_string(),
            ],
        );
    }
}

/// extractHandlesForComment 从 nft 输出里提取指定 chain 中 comment 匹配的 rule handle。
fn extract_handles_for_comment(out: &str, chain: &str, comment: &str) -> Vec<u64> {
    let mut handles = vec![];
    let mut in_chain = false;
    let chain_header = format!("chain {} {{", chain);
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&chain_header) {
            in_chain = true;
            continue;
        }
        if in_chain && trimmed == "}" {
            in_chain = false;
            continue;
        }
        if in_chain && trimmed.contains(&format!("comment \"{}\"", comment)) {
            if let Some(i) = trimmed.rfind("handle ") {
                let h_str = trimmed[i + "handle ".len()..].trim();
                if let Ok(h) = h_str.parse::<u64>() {
                    if h > 0 {
                        handles.push(h);
                    }
                }
            }
        }
    }
    handles
}

/// extractGeoIPElements 从 geoip_cn.nft / geoip6_cn.nft 文件中提取 elements 列表内容。
pub fn extract_geoip_elements(path: &str) -> anyhow::Result<String> {
    let data = fs::read_to_string(path)?;
    let re = Regex::new(r"(?s)elements\s*=\s*\{([^}]*)\}").unwrap();
    match re.captures(&data) {
        Some(c) => {
            if let Some(m) = c.get(1) {
                return Ok(m.as_str().trim().to_string());
            }
        }
        None => {}
    }
    Err(anyhow::anyhow!("geoip 文件 {} 未找到 elements 块", path))
}

#[allow(dead_code)]
fn unused_reader() -> BufReader<std::io::Empty> {
    BufReader::new(std::io::empty())
}
