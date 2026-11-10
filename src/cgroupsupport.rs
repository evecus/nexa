//! cgroup 支持度检测，1:1 对齐 Go 版 internal/cgroupsupport。
//!
//! 之所以独立成模块：config / core / netmanager 都需要在各自阶段读取这个判断结果
//! （config 用于计算默认值，core 用于决定是否真的把核心进程放入 cgroup，
//! netmanager 用于决定是否下发 cgroup 匹配规则），三者不能互相依赖，抽出来避免循环依赖。

use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Version {
    /// 都不支持
    None = 0,
    /// cgroup v1（net_cls）
    V1 = 1,
    /// cgroup v2
    V2 = 2,
}

/// 检测当前系统实际可用的 cgroup 版本。
///
/// 判定标准对齐实际使用路径（保证「检测到支持」和「用得了」是同一套标准，
/// 不会出现检测通过但挂载失败的情况）：
///   - v2：/proc/mounts 中存在 type 为 cgroup2 的挂载，且挂载点可写；
///   - v1：/proc/mounts 中存在 type 为 cgroup 且挂载选项包含 net_cls 的条目，且挂载点可写；
///   - 都不满足则返回 None。
pub fn detect() -> Version {
    let mounts = match fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(_) => return Version::None,
    };
    let mut v1_path: Option<String> = None;
    let mut v2_path: Option<String> = None;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let (mount_point, fs_type, opts) = (fields[1], fields[2], fields[3]);
        match fs_type {
            "cgroup2" if v2_path.is_none() => v2_path = Some(mount_point.to_string()),
            "cgroup" if opts.contains("net_cls") && v1_path.is_none() => {
                v1_path = Some(mount_point.to_string())
            }
            _ => {}
        }
    }
    // 优先 v2（现代系统主流），其次 v1；两者都要求挂载点实际可写才算真支持。
    if let Some(p) = v2_path {
        if writable(&p) {
            return Version::V2;
        }
    }
    if let Some(p) = v1_path {
        if writable(&p) {
            return Version::V1;
        }
    }
    Version::None
}

/// 系统是否支持 cgroup 防回环。
pub fn supported() -> bool {
    detect() != Version::None
}

/// 粗略判断目录是否可写（尝试创建并立即删除一个探测子目录）。
/// 用真实的 mkdir 探测而非仅看权限位，因为容器环境里权限位正常但内核拒绝写入的情况并不少见。
fn writable(dir: &str) -> bool {
    let probe = std::path::Path::new(dir).join(".nexa_cgroup_probe");
    match fs::create_dir(&probe) {
        Ok(_) => {
            let _ = fs::remove_dir(&probe);
            true
        }
        Err(_) => false,
    }
}
