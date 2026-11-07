//! 路径配置，1:1 对齐 Go 版 internal/paths（原 luci-app-proxy include.sh 语义）。
//!
//! 默认值对齐原常量；通过 init() 指定自定义数据目录（-d 参数）时，
//! HomeDir 及其派生路径（profiles/run/firewall/db）一并迁移到该目录下，
//! 便于非 root / 非 OpenWrt 环境使用自定义数据目录运行。
//! 日志目录固定 /tmp/nexa（对齐 Go 版，原行为如此）。

use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use std::path::PathBuf;

/// 数据目录根，默认 /etc/nexa。
static HOME_DIR: OnceCell<PathBuf> = OnceCell::new();
/// 运行目录，默认 <数据目录>/run，可由配置里的 run_dir 覆盖。
static RUN_DIR: OnceCell<RwLock<PathBuf>> = OnceCell::new();

fn home() -> &'static PathBuf {
    HOME_DIR.get().expect("paths::init() 未调用")
}

fn run_cell() -> &'static RwLock<PathBuf> {
    RUN_DIR.get().expect("paths::init() 未调用")
}

/// 使用自定义数据目录初始化所有派生路径。dir 为空则使用默认 /etc/nexa。
/// 必须在任何使用 paths 的组件（store/logger/core）初始化之前调用。
pub fn init(dir: Option<&str>) {
    let base = match dir {
        Some(d) if !d.trim().is_empty() => PathBuf::from(d.trim()),
        _ => PathBuf::from("/etc/nexa"),
    };
    let _ = HOME_DIR.set(base);
    let _ = RUN_DIR.set(RwLock::new(home_dir().join("run")));
}

pub fn home_dir() -> PathBuf {
    home().clone()
}

pub fn profiles_dir() -> PathBuf {
    home().join("profiles")
}

pub fn nft_dir() -> PathBuf {
    home().join("firewall")
}

/// 数据库文件（redb，对齐 Go 版 paths.DBPath = <数据目录>/nexa.db）。
pub fn db_path() -> PathBuf {
    home().join("nexa.db")
}

pub fn geoip_cn_nft() -> PathBuf {
    nft_dir().join("geoip_cn.nft")
}

pub fn geoip6_cn_nft() -> PathBuf {
    nft_dir().join("geoip6_cn.nft")
}

pub fn run_dir() -> PathBuf {
    run_cell().read().clone()
}

/// 设置运行目录（对齐设置页 run_dir 配置项）。
/// 空 = 恢复默认 <数据目录>/run；非空必须为绝对路径。
pub fn set_run_dir(dir: &str) -> anyhow::Result<()> {
    let dir = dir.trim();
    if dir.is_empty() {
        *run_cell().write() = home_dir().join("run");
        return Ok(());
    }
    let p = PathBuf::from(dir);
    if !p.is_absolute() {
        anyhow::bail!("run 目录必须为绝对路径: {}", dir);
    }
    *run_cell().write() = p;
    Ok(())
}

pub fn log_dir() -> PathBuf {
    PathBuf::from("/tmp/nexa")
}

pub fn app_log_path() -> PathBuf {
    log_dir().join("app.log")
}

pub fn core_log_path() -> PathBuf {
    log_dir().join("core.log")
}

pub fn debug_log_path() -> PathBuf {
    log_dir().join("debug.log")
}

pub fn temp_dir() -> PathBuf {
    log_dir().join("run_tmp")
}

pub fn pid_file_path() -> PathBuf {
    temp_dir().join("nexa.pid")
}

/// bridge-nf 关闭/恢复的标志文件（只在 nexa 真正改过 sysctl 时落盘，Cleanup 时据此恢复）。
pub fn bridge_nf_call_iptables_flag() -> PathBuf {
    temp_dir().join("bridge_nf_call_iptables.flag")
}

pub fn bridge_nf_call_ip6tables_flag() -> PathBuf {
    temp_dir().join("bridge_nf_call_ip6tables.flag")
}

/// 确保数据目录、profiles、run、firewall、日志、临时目录都存在（对齐 app.PrepareFiles）。
pub fn ensure_dirs() -> anyhow::Result<()> {
    for d in [
        home_dir(),
        profiles_dir(),
        nft_dir(),
        log_dir(),
        temp_dir(),
        run_dir(),
    ] {
        std::fs::create_dir_all(&d).map_err(|e| anyhow::anyhow!("创建目录 {} 失败: {}", d.display(), e))?;
    }
    Ok(())
}

/// 返回给前端的路径信息（对齐原 ubus get_paths / Go api.handlePaths）。
pub fn get() -> serde_json::Value {
    serde_json::json!({
        "home_dir": home_dir(),
        "profiles_dir": profiles_dir(),
        "run_dir": run_dir(),
        "nft_dir": nft_dir(),
        "geoip_cn_nft": geoip_cn_nft(),
        "geoip6_cn_nft": geoip6_cn_nft(),
        "log_dir": log_dir(),
        "app_log_path": app_log_path(),
        "core_log_path": core_log_path(),
        "debug_log_path": debug_log_path(),
        "temp_dir": temp_dir(),
        "pid_file_path": pid_file_path(),
        "bridge_nf_call_iptables_flag_path": bridge_nf_call_iptables_flag(),
        "bridge_nf_call_ip6tables_flag_path": bridge_nf_call_ip6tables_flag(),
    })
}
