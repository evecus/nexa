//! app / core 日志文件写入 + 实时推送（对齐 Go 版 internal/logger）。

use crate::paths;
use parking_lot::Mutex;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::sync::Arc;

/// core 日志实时推送通道容量（对齐 Go 版 Subscribe 的 buffered channel 64）。
const SUB_CAPACITY: usize = 64;

pub struct Logger {
    app_file: Mutex<File>,
    core_file: Mutex<File>,
    tx: tokio::sync::broadcast::Sender<String>,
}

impl Logger {
    pub fn new() -> anyhow::Result<Arc<Self>> {
        paths::ensure_dirs()?;
        let app = open_log(&paths::app_log_path())?;
        let core = open_log(&paths::core_log_path())?;
        let (tx, _) = tokio::sync::broadcast::channel(SUB_CAPACITY);
        Ok(Arc::new(Self {
            app_file: Mutex::new(app),
            core_file: Mutex::new(core),
            tx,
        }))
    }

    /// 写一行 app 日志，格式与原 include.sh log() 一致。
    pub fn app(&self, tag: &str, msg: &str) {
        let line = format!("[{}] [{}] {}\n", now_string(), tag, msg);
        {
            let mut f = self.app_file.lock();
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
        tracing::info!(target: "nexa", "[{}] {}", tag, msg);
    }

    /// 写一行 core 日志（外部核心 stdout/stderr），并广播给订阅者。
    pub fn core(&self, line: &str) {
        {
            let mut f = self.core_file.lock();
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
        // 没有订阅者时 send 返回 Err，忽略即可
        let _ = self.tx.send(line.to_string());
    }

    /// 订阅 core 日志实时推送（SSE /api/logs/stream）。
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    pub fn read_app(&self) -> String {
        fs::read_to_string(paths::app_log_path()).unwrap_or_default()
    }

    pub fn read_core(&self) -> String {
        fs::read_to_string(paths::core_log_path()).unwrap_or_default()
    }

    pub fn clear_app(&self) -> anyhow::Result<()> {
        let mut guard = self.app_file.lock();
        let f = open_log_truncate(&paths::app_log_path())?;
        *guard = f;
        Ok(())
    }

    pub fn clear_core(&self) -> anyhow::Result<()> {
        let mut guard = self.core_file.lock();
        let f = open_log_truncate(&paths::core_log_path())?;
        *guard = f;
        Ok(())
    }

    /// 写入 debug 报告（对齐 Go 版 api.generateDebug 的简化输出结构）。
    pub fn write_debug(&self, content: &str) -> anyhow::Result<()> {
        if let Some(p) = paths::debug_log_path().parent() {
            fs::create_dir_all(p)?;
        }
        fs::write(paths::debug_log_path(), content)?;
        Ok(())
    }
}

fn open_log(p: &std::path::Path) -> anyhow::Result<File> {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(OpenOptions::new().create(true).append(true).open(p)?)
}

fn open_log_truncate(p: &std::path::Path) -> anyhow::Result<File> {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(p)?)
}

pub fn now_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_date(secs)
}

/// 本地时间格式化 `%Y-%m-%d %H:%M:%S`，对齐 Go 的 time.Format("2006-01-02 15:04:05")。
pub fn format_date(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days as i64);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, m, s)
}

pub(crate) fn days_to_ymd(mut days: i64) -> (i32, u32, u32) {
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
