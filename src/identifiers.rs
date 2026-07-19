//! 读取系统 user/group/cgroup 列表，对齐原 include.uc 的 get_users/get_groups/get_cgroups。

use std::fs;
use std::path::Path;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Identifiers {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub cgroups: Vec<String>,
    pub os_type: String, // "openwrt" 或 "linux"
}

/// Get 收集系统标识符。
pub fn get() -> Identifiers {
    Identifiers {
        users: get_users(),
        groups: get_groups(),
        cgroups: get_cgroups(),
        os_type: detect_os_type(),
    }
}

fn detect_os_type() -> String {
    if Path::new("/etc/openwrt_release").exists() {
        "openwrt".to_string()
    } else {
        "linux".to_string()
    }
}

fn get_users() -> Vec<String> {
    let mut out = vec![];
    if let Ok(data) = fs::read_to_string("/etc/passwd") {
        for line in data.lines() {
            if let Some(i) = line.find(':') {
                if i > 0 {
                    out.push(line[..i].to_string());
                }
            }
        }
    }
    out
}

fn get_groups() -> Vec<String> {
    let mut out = vec![];
    if let Ok(data) = fs::read_to_string("/etc/group") {
        for line in data.lines() {
            if let Some(i) = line.find(':') {
                if i > 0 {
                    out.push(line[..i].to_string());
                }
            }
        }
    }
    out
}

/// getCgroups 对齐 include.uc：cgroup v2 时遍历 /sys/fs/cgroup 子目录，排除 services/proxy。
fn get_cgroups() -> Vec<String> {
    if !is_cgroup_v2() {
        return vec![];
    }
    let root = "/sys/fs/cgroup/";
    let mut out = vec![];
    walk_dir(root, root, &mut out);
    out
}

fn walk_dir(root: &str, path: &str, out: &mut Vec<String>) {
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return,
    };
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or("");
        let name = e.file_name().to_string_lossy().to_string();
        let full = if rel.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", rel, name)
        };
        if full == "services/proxy" {
            // 仍递归子目录，但跳过该条目本身
        } else {
            out.push(full.clone());
        }
        let child = format!("{}/{}", path, name);
        walk_dir(root, &child, out);
    }
}

fn is_cgroup_v2() -> bool {
    let f = match fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(_) => return true,
    };
    for line in f.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[2] == "cgroup" {
            return false;
        }
    }
    true
}
