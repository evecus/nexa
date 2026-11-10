//! 系统标识符收集，对齐 Go 版 internal/identifiers（原 include.uc 的 get_users/get_groups/get_cgroups）。

use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Default)]
pub struct Identifiers {
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub cgroups: Vec<String>,
    /// "openwrt" 或 "linux"
    pub os_type: String,
}

/// 是否为 OpenWrt 系统（判定依据：/etc/openwrt_release 存在）。
pub fn is_openwrt() -> bool {
    Path::new("/etc/openwrt_release").exists()
}

pub fn get() -> Identifiers {
    Identifiers {
        users: get_users(),
        groups: get_groups(),
        cgroups: get_cgroups(),
        os_type: if is_openwrt() {
            "openwrt".into()
        } else {
            "linux".into()
        },
    }
}

fn get_users() -> Vec<String> {
    let data = match fs::read_to_string("/etc/passwd") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    data.lines()
        .filter_map(|line| line.split_once(':').map(|(u, _)| u.to_string()))
        .filter(|u| !u.is_empty())
        .collect()
}

fn get_groups() -> Vec<String> {
    let data = match fs::read_to_string("/etc/group") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    data.lines()
        .filter_map(|line| line.split_once(':').map(|(g, _)| g.to_string()))
        .filter(|g| !g.is_empty())
        .collect()
}

/// 对齐 include.uc：cgroup v2 时遍历 /sys/fs/cgroup 子目录，排除 services/proxy。
/// Go 版用 filepath.Walk（字典序遍历）；Rust 的 read_dir 顺序不保证，因此最后排序，
/// 保证与 Go 一样按路径字典序返回。
fn get_cgroups() -> Vec<String> {
    if !is_cgroup_v2() {
        return Vec::new();
    }
    const ROOT: &str = "/sys/fs/cgroup/";
    let mut out = Vec::new();
    walk_dirs(Path::new(ROOT), Path::new(ROOT), &mut out);
    out.sort();
    out
}

fn walk_dirs(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        // Go 版 filepath.Walk 只跳过把 services/proxy 这个目录本身加入结果，
        // 仍会继续遍历它的子目录，这里保持一致。
        if !rel.is_empty() && rel != "services/proxy" {
            out.push(rel);
        }
        walk_dirs(root, &path, out);
    }
}

/// 对齐 include.uc get_cgroups_version()：mount 输出含 type 为 cgroup 的条目视为 v1，否则 v2。
fn is_cgroup_v2() -> bool {
    let mounts = match fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(_) => return true,
    };
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[2] == "cgroup" {
            return false;
        }
    }
    true
}
