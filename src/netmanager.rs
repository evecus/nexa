//! 网络 / 防火墙管理，1:1 对齐 Go 版 internal/netmanager：
//! bridge-nf / TUN 等待 / ip route+rule / fake-ip6 dummy / nft 应用 / firewall_include / cleanup。
//! 全部通过 shell out 调 ip/nft/sysctl，对齐原 shell 行为。

pub mod iptables;

use crate::config::Config;
use crate::cgroupsupport;
use crate::logger::Logger;
use crate::nfttemplate;
use crate::paths;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

pub struct NetManager {
    log: Arc<Logger>,
}

impl NetManager {
    pub fn new(log: Arc<Logger>) -> Self {
        Self { log }
    }

    /// 对齐 Go 版 Apply：proxy.enabled=1 时的全部网络配置下发。
    pub fn apply(&self, cfg: &Config) -> anyhow::Result<()> {
        let p = &cfg.proxy;
        if !p.enabled {
            self.log.app("代理", "已禁用，跳过防火墙设置。");
            return Ok(());
        }
        self.log.app("代理", "已启用，配置防火墙规则。");

        let tproxy_enable = p.tcp_mode == "tproxy" || p.udp_mode == "tproxy";
        let tun_enable = p.tcp_mode == "tun" || p.udp_mode == "tun";
        let r = &cfg.routing;

        // bridge-nf-call 兼容（对齐 proxy.init:170-185）
        // 仅在系统存在网桥且加载了 br_netfilter 模块时处理
        if tproxy_enable && has_bridge() && is_module_loaded("br_netfilter") {
            if p.ipv4_proxy && sysctl_get("net.bridge.bridge-nf-call-iptables") == "1" {
                let _ = std::fs::write(paths::bridge_nf_call_iptables_flag(), "");
                sysctl_set("net.bridge.bridge-nf-call-iptables", "0");
            }
            if p.ipv6_proxy && sysctl_get("net.bridge.bridge-nf-call-ip6tables") == "1" {
                let _ = std::fs::write(paths::bridge_nf_call_ip6tables_flag(), "");
                sysctl_set("net.bridge.bridge-nf-call-ip6tables", "0");
            }
        }

        // TUN 设备等待（对齐 proxy.init:188-203）
        if tun_enable && !p.tun_device.is_empty() {
            self.log.app(
                "代理",
                &format!("等待 TUN 设备上线，超时 {} 秒...", p.tun_timeout),
            );
            if !wait_for_tun(&p.tun_device, p.tun_timeout, p.tun_interval) {
                self.log.app("代理", "超时，TUN 设备未上线，退出。");
                anyhow::bail!("tun device {} not up", p.tun_device);
            }
            self.log.app("代理", "TUN 设备已上线。");
        }

        // ip route / rule（对齐 proxy.init:206-226）
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

        // fake-ip6 dummy（对齐 proxy.init:229-233）
        if !p.fake_ip6_range.is_empty() {
            run("ip", &["link", "add", &r.dummy_device, "type", "dummy"]);
            run("ip", &["link", "set", "dev", &r.dummy_device, "up"]);
            run("ip", &["-6", "route", "add", &p.fake_ip6_range, "dev", &r.dummy_device]);
        }

        // 流量劫持规则：优先 nftables（fw4 已安装且运行），否则回退 iptables（对齐 proxy.init:236-241）。
        let lan_devs = resolve_lan_devices(&p.lan_inbound_interface);
        let backend = iptables::detect_backend();
        self.log.app("代理", &format!("检测到防火墙后端：{}。", backend));
        if backend == iptables::Backend::Iptables {
            return crate::netmanager::iptables::apply(self, cfg, &lan_devs);
        }

        let mut model = nfttemplate::build(cfg, &lan_devs, cgroups_version());
        // bypass 大陆 IP 时，从 geoip 文件提取 elements 注入 nexa 表集合
        // （geoip 文件的表名也已统一为 nexa，但从不直接 include，只取其 elements）。
        if p.bypass_china_mainland_ip {
            match extract_geoip_elements(&paths::geoip_cn_nft().to_string_lossy()) {
                Ok(els) => model.china_ip_elements = els,
                Err(e) => self.log.app("代理", &format!("读取 geoip_cn.nft 失败：{}", e)),
            }
        }
        if p.bypass_china_mainland_ip6 {
            match extract_geoip_elements(&paths::geoip6_cn_nft().to_string_lossy()) {
                Ok(els) => model.china_ip6_elements = els,
                Err(e) => self.log.app("代理", &format!("读取 geoip6_cn.nft 失败：{}", e)),
            }
        }
        let ruleset = nfttemplate::render(&model);

        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(ruleset.as_bytes());
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            self.log.app("代理", &format!("流量劫持失败：{}", err));
            anyhow::bail!("nft -f - 失败: {}", err);
        }
        // 校验表是否存在
        let tables = run_out("nft", &["list", "tables"]);
        if tables.contains("inet nexa") {
            self.log.app("代理", "流量劫持成功。");
        } else {
            self.log.app("代理", "流量劫持失败。");
        }
        Ok(())
    }

    /// 对齐 firewall_include.sh：TUN 模式时往防火墙 input/forward 插 accept 规则。
    /// 优先使用 OpenWrt 的 fw4 表；若不存在则回退到 inet filter 表（普通 Linux 兼容）。
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
        // iptables 回退：TUN 放行规则已在 applyIptables 中通过 filter INPUT/FORWARD 完成，这里直接跳过。
        if iptables::detect_backend() == iptables::Backend::Iptables {
            return;
        }
        // 检测可用的防火墙表：优先 fw4（OpenWrt），回退 filter（普通 Linux）
        let mut fw_table = "fw4";
        let fw4_out = Command::new("nft").args(["list", "table", "inet", "fw4"]).output();
        if !fw4_out.as_ref().map(|o| o.status.success()).unwrap_or(false) {
            let filter_out = Command::new("nft").args(["list", "table", "inet", "filter"]).output();
            if filter_out.as_ref().map(|o| o.status.success()).unwrap_or(false) {
                fw_table = "filter";
            } else {
                // 对齐 Go：CombinedOutput（stdout + stderr）一起写进日志。
                let fmt_err = |o: &std::io::Result<std::process::Output>| match o {
                    Ok(o) => {
                        let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                        s.push_str(&String::from_utf8_lossy(&o.stderr));
                        s.trim().to_string()
                    }
                    Err(e) => e.to_string(),
                };
                self.log.app(
                    "代理",
                    &format!(
                        "未检测到防火墙表(fw4/filter)，跳过 TUN 防火墙放行。fw4: {}, filter: {}",
                        fmt_err(&fw4_out),
                        fmt_err(&filter_out)
                    ),
                );
                return;
            }
        }
        run("nft", &["insert", "rule", "inet", fw_table, "input", "iifname", &p.tun_device, "counter", "accept", "comment", "nexa"]);
        run("nft", &["insert", "rule", "inet", fw_table, "forward", "oifname", &p.tun_device, "counter", "accept", "comment", "nexa"]);
        run("nft", &["insert", "rule", "inet", fw_table, "forward", "iifname", &p.tun_device, "counter", "accept", "comment", "nexa"]);
    }

    /// 对齐 Go 版 Cleanup：删 rule/route/dummy、删 nft 表、删防火墙中 comment=nexa 的规则、恢复 bridge-nf。
    pub fn cleanup(&self, cfg: &Config) {
        let r = &cfg.routing;

        for args in [
            ["-4", "rule", "del", "table", &r.tproxy_route_table],
            ["-4", "rule", "del", "table", &r.tun_route_table],
            ["-6", "rule", "del", "table", &r.tproxy_route_table],
            ["-6", "rule", "del", "table", &r.tun_route_table],
            ["-4", "route", "flush", "table", &r.tproxy_route_table],
            ["-4", "route", "flush", "table", &r.tun_route_table],
            ["-6", "route", "flush", "table", &r.tproxy_route_table],
            ["-6", "route", "flush", "table", &r.tun_route_table],
        ] {
            run("ip", &args);
        }
        run("ip", &["link", "del", &r.dummy_device]);

        run("nft", &["delete", "table", "inet", "nexa"]);

        // 删防火墙表中 comment=nexa 的规则（兼容 OpenWrt fw4 和普通 Linux filter）
        delete_fw_rules_by_comment("fw4", "input");
        delete_fw_rules_by_comment("fw4", "forward");
        delete_fw_rules_by_comment("filter", "input");
        delete_fw_rules_by_comment("filter", "forward");

        // 清理 iptables 回退规则（无论上次用的是哪个后端都尝试一次，保证幂等）
        iptables::cleanup(self, cfg);

        // 恢复 bridge-nf-call（仅当标志文件存在且系统有网桥时）
        if has_bridge() {
            if paths::bridge_nf_call_iptables_flag().exists() {
                let _ = std::fs::remove_file(paths::bridge_nf_call_iptables_flag());
                sysctl_set("net.bridge.bridge-nf-call-iptables", "1");
            }
            if paths::bridge_nf_call_ip6tables_flag().exists() {
                let _ = std::fs::remove_file(paths::bridge_nf_call_ip6tables_flag());
                sysctl_set("net.bridge.bridge-nf-call-ip6tables", "1");
            }
        }
    }
}

/// 返回系统实际支持的 cgroup 版本（0=不支持，1=v1，2=v2）。
pub fn cgroups_version() -> i32 {
    cgroupsupport::detect() as i32
}

// ── helpers ────────────────────────────────────────────

/// 执行命令并丢弃输出（对齐 Go 的 run/runIgnore）。
pub fn run(name: &str, args: &[&str]) {
    let _ = Command::new(name).args(args).output();
}

/// 执行命令并捕获 stdout（对齐 Go exec.Cmd.Output：失败或 stderr 内容不计入）。
pub fn run_out(name: &str, args: &[&str]) -> String {
    match Command::new(name).args(args).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => String::new(),
    }
}

/// 对齐 Go exec.LookPath：只在 PATH 中查找可执行文件，不实际执行命令。
pub fn has_command(name: &str) -> bool {
    #[cfg(unix)]
    fn executable(p: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    fn executable(p: &Path) -> bool {
        p.is_file()
    }
    if name.contains('/') {
        return executable(Path::new(name));
    }
    std::env::split_paths(&std::env::var("PATH").unwrap_or_default())
        .any(|d| executable(&d.join(name)))
}

pub fn is_module_loaded(name: &str) -> bool {
    match std::fs::read_to_string("/proc/modules") {
        Ok(s) => s.lines().any(|l| l.split_whitespace().next() == Some(name)),
        Err(_) => false,
    }
}

pub fn sysctl_get(key: &str) -> String {
    run_out("sysctl", &["-e", "-n", key]).trim().to_string()
}

pub fn sysctl_set(key: &str, val: &str) {
    run("sysctl", &["-q", "-w", &format!("{}={}", key, val)]);
}

/// 轮询 `ip -j link show dev`，等设备 UP（对齐 proxy.init:191-202）。
fn wait_for_tun(dev: &str, timeout: i32, interval: i32) -> bool {
    let interval = if interval <= 0 { 1 } else { interval };
    let mut t = if timeout <= 0 { 0 } else { timeout };
    while t > 0 {
        // 对齐 Go：命令必须执行成功，且 stdout 中含 "UP"。
        let up = Command::new("ip")
            .args(["-j", "link", "show", "dev", dev])
            .output()
            .map(|o| {
                o.status.success() && String::from_utf8_lossy(&o.stdout).contains("\"UP\"")
            })
            .unwrap_or(false);
        if up {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval as u64));
        t -= interval;
    }
    false
}

/// 把 interface 名解析为 device 名。优先 /sys/class/net/<name>；不存在则尝试 br-<name>。
fn resolve_lan_devices(interfaces: &[String]) -> Vec<String> {
    let mut out = Vec::new();
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
    Path::new(p).is_dir()
}

/// 检测系统是否存在网桥接口（如 br-lan、br0 等）。
pub fn has_bridge() -> bool {
    match std::fs::read_dir("/sys/class/net") {
        Ok(entries) => entries.flatten().any(|e| e.path().join("bridge").is_dir()),
        Err(_) => false,
    }
}

/// 删除 inet <table> <chain> 中 comment=nexa 的规则。
fn delete_fw_rules_by_comment(table: &str, chain: &str) {
    for handle in extract_handles_for_comment(table, chain, "nexa") {
        run("nft", &["delete", "rule", "inet", table, chain, "handle", &handle.to_string()]);
    }
}

/// 从 `nft list table inet <table>` 输出里提取指定 chain 中 comment 匹配的 rule handle。
fn extract_handles_for_comment(table: &str, chain: &str, comment: &str) -> Vec<u64> {
    let out = match Command::new("nft").args(["list", "table", "inet", table]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Vec::new(),
    };
    let mut handles = Vec::new();
    let mut in_chain = false;
    let needle = format!("comment \"{}\"", comment);
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&format!("chain {} {{", chain)) {
            in_chain = true;
            continue;
        }
        if in_chain && trimmed == "}" {
            in_chain = false;
            continue;
        }
        if in_chain && trimmed.contains(&needle) {
            // 行形如: ... counter accept comment "nexa" # handle 42
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

/// 从 geoip_cn.nft / geoip6_cn.nft 中提取 `elements = { ... }` 块的内容。
/// 对齐 Go 版 extractGeoIPElements：逐行 trim、丢弃空行后以 ", " 重新拼接 ——
/// 捕获内容以换行开头，直接拼进模板会在 elements 块内产生空行，
/// nft 解析会报 "syntax error, unexpected newline"。
pub fn extract_geoip_elements(path: &str) -> anyhow::Result<String> {
    let data = std::fs::read_to_string(path)?;
    // 定位 "elements" 后的第一个 '{'，取到配对的 '}'
    let key = "elements";
    let mut idx = 0usize;
    while let Some(pos) = data[idx..].find(key) {
        let after = idx + pos + key.len();
        let rest = &data[after..];
        let trimmed_rest = rest.trim_start();
        if !trimmed_rest.starts_with('=') {
            idx = after;
            continue;
        }
        let after_eq = after + (rest.len() - trimmed_rest.len()) + 1;
        let rest2 = data[after_eq..].trim_start();
        if !rest2.starts_with('{') {
            idx = after;
            continue;
        }
        let after_brace = after_eq + (data[after_eq..].len() - rest2.len()) + 1;
        if let Some(end) = data[after_brace..].find('}') {
            let inner = &data[after_brace..after_brace + end];
            let entries: Vec<&str> = inner
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();
            if entries.is_empty() {
                anyhow::bail!("geoip 文件 {} elements 块为空", path);
            }
            return Ok(entries.join(", "));
        }
        anyhow::bail!("geoip 文件 {} 的 elements 块未闭合", path);
    }
    anyhow::bail!("geoip 文件 {} 未找到 elements 块", path)
}
