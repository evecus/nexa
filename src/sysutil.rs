//! 系统 user/group/网络接口查询的纯 Rust 实现（解析 /etc/passwd、/etc/group、/sys/class/net）。
//! 避免 nix 不同版本的 feature 差异。

use std::fs;
use std::path::Path;

/// 查找用户 UID，不存在返回 None。
pub fn lookup_user_uid(name: &str) -> Option<u32> {
    let data = fs::read_to_string("/etc/passwd").ok()?;
    for line in data.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == name {
            return fields[2].parse::<u32>().ok();
        }
    }
    None
}

/// 查找用户名，不存在返回 None。
pub fn user_exists(name: &str) -> bool {
    lookup_user_uid(name).is_some()
}

/// 查找组 GID，不存在返回 None。
pub fn lookup_group_gid(name: &str) -> Option<u32> {
    let data = fs::read_to_string("/etc/group").ok()?;
    for line in data.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == name {
            return fields[2].parse::<u32>().ok();
        }
    }
    None
}

/// 查找组是否存在。
pub fn group_exists(name: &str) -> bool {
    lookup_group_gid(name).is_some()
}

/// 枚举活动非虚拟物理网卡（对齐 Go defaultLanInboundInterface 的过滤逻辑）。
pub fn list_active_physical_ifaces() -> Vec<String> {
    let mut result: Vec<String> = vec![];
    let entries = match fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return result,
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name == "lo" || name.starts_with("docker") || name.starts_with("br-")
            || name.starts_with("veth") || name.starts_with("virbr")
            || name.starts_with("tun") || name.starts_with("wg")
        {
            continue;
        }
        // 读取 flags
        let flags_path = format!("/sys/class/net/{}/flags", name);
        let flags = fs::read_to_string(&flags_path)
            .ok()
            .and_then(|s| {
                let trimmed = s.trim();
                let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
                u32::from_str_radix(stripped, 16).ok()
            })
            .unwrap_or(0);
        const IFF_UP: u32 = 0x1;
        const IFF_LOOPBACK: u32 = 0x8;
        if flags & IFF_UP == 0 || flags & IFF_LOOPBACK != 0 {
            continue;
        }
        result.push(name);
    }
    result
}

/// 检查路径是否存在（目录或文件）。
#[allow(dead_code)]
pub fn path_exists(p: &str) -> bool {
    Path::new(p).exists()
}
