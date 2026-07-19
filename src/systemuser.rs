//! 管理 nexa 代理核心的运行用户。
//! 注意：本模块为 Go 原项目的 1:1 移植；当前主流程暂未调用，
//! 保留以备后续按需启用独立运行用户功能。

#![allow(dead_code)]

use std::process::Command;

pub const USER_NAME: &str = "nexa";

/// EnsureUser 确保 nexa 系统用户存在，不存在则创建。返回该用户的 UID。
pub fn ensure_user() -> anyhow::Result<u32> {
    // 先检查用户是否已存在
    if let Some(uid) = crate::sysutil::lookup_user_uid(USER_NAME) {
        return Ok(uid);
    }

    // 用户不存在，尝试创建
    create_user()?;

    // 再次查找
    crate::sysutil::lookup_user_uid(USER_NAME)
        .ok_or_else(|| anyhow::anyhow!("创建用户后查找失败"))
}

/// createUser 创建 nexa 系统用户，按系统类型选择不同方式。
fn create_user() -> anyhow::Result<()> {
    // 方式1：useradd（大多数 Linux 发行版）
    if which("useradd").is_some() {
        return run("useradd", &["-r", "-s", "/usr/sbin/nologin", "-M", USER_NAME]);
    }

    // 方式2：adduser（Debian/BusyBox）
    if which("adduser").is_some() {
        // BusyBox adduser 语法和 Debian 不同，尝试 BusyBox 风格
        if run("adduser", &["-D", "-s", "/usr/sbin/nologin", "-H", USER_NAME]).is_err() {
            // Debian 风格
            return run(
                "adduser",
                &[
                    "--system",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    USER_NAME,
                ],
            );
        }
        return Ok(());
    }

    // 方式3：OpenWrt - 通过 opkg 安装 shadow 然后用 useradd
    if is_openwrt() {
        let _ = run("opkg", &["update"]);
        let _ = run("opkg", &["install", "shadow-useradd"]);
        if which("useradd").is_some() {
            return run("useradd", &["-r", "-s", "/usr/sbin/nologin", USER_NAME]);
        }
    }

    Err(anyhow::anyhow!(
        "未找到 useradd 或 adduser 命令，请手动创建用户：{}",
        USER_NAME
    ))
}

/// LookupUID 查找 nexa 用户的 UID，不存在返回 0。
pub fn lookup_uid() -> u32 {
    crate::sysutil::lookup_user_uid(USER_NAME).unwrap_or(0)
}

fn is_openwrt() -> bool {
    Command::new("test")
        .args(["-f", "/etc/openwrt_release"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(name: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(name).args(args).output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "{} {}: {}",
            name,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn which(name: &str) -> Option<String> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// ensureGroup 复用 core::ensure_nexa_group，确保 nexa 系统组存在。
pub fn ensure_group() -> anyhow::Result<u32> {
    crate::core::ensure_nexa_group()
}
