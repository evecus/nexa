//! 内置 cron 调度器，替代原 proxy.init 写 /etc/crontabs/root 的做法。
//! 支持 5 字段 cron（minute hour dom month dow），每分钟整点触发一次（对齐 Go 版 internal/scheduler）。

use crate::config::Config;
use crate::core::CoreManager;
use crate::logger::Logger;
use crate::paths;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobKind {
    Restart,
    ClearLogs,
}

struct Job {
    id: &'static str,
    cron: String,
    kind: JobKind,
    /// 日志清理用的大小限制（字节），仅 ClearLogs 使用
    limit_bytes: i64,
    /// 定时重启使用的配置快照（对齐 Go Reload 闭包捕获的 cfg，不重新读库）。
    restart_cfg: Option<Config>,
}

pub struct Scheduler {
    log: Arc<Logger>,
    core: Arc<CoreManager>,
    store: Arc<crate::store::Store>,
    jobs: Mutex<Vec<Job>>,
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Scheduler {
    pub fn new(
        log: Arc<Logger>,
        core: Arc<CoreManager>,
        store: Arc<crate::store::Store>,
    ) -> Arc<Self> {
        Arc::new(Self {
            log,
            core,
            store,
            jobs: Mutex::new(Vec::new()),
            handle: Mutex::new(None),
        })
    }

    /// 启动调度循环（对齐到下一个整分钟）。
    pub fn start(self: &Arc<Self>) {
        let mut guard = self.handle.lock();
        if guard.is_some() {
            return;
        }
        let this = Arc::clone(self);
        *guard = Some(tokio::spawn(async move {
            this.loop_run().await;
        }));
    }

    pub fn stop(&self) {
        if let Some(h) = self.handle.lock().take() {
            h.abort();
        }
    }

    /// 按 cfg 重新设置任务（定时重启 + 日志清理）。
    pub fn reload(&self, cfg: &Config) {
        let mut jobs = self.jobs.lock();
        jobs.clear();

        // 定时重启（对齐 proxy.init:134-138）
        // 仅当总开关「启用」打开时，定时重启才会生效；未启用时即使勾选了定时重启也不应触发。
        if cfg.config.enabled
            && cfg.config.scheduled_restart
            && !cfg.config.scheduled_restart_cron.is_empty()
        {
            jobs.push(Job {
                id: "restart",
                cron: cfg.config.scheduled_restart_cron.clone(),
                kind: JobKind::Restart,
                limit_bytes: 0,
                restart_cfg: Some(cfg.clone()),
            });
        }

        // 日志定时清理（对齐 proxy.init:139-143 + clear_logs）
        if cfg.log.scheduled_clear && !cfg.log.scheduled_clear_cron.is_empty() {
            jobs.push(Job {
                id: "clear_logs",
                cron: cfg.log.scheduled_clear_cron.clone(),
                kind: JobKind::ClearLogs,
                limit_bytes: size_to_bytes(cfg.log.scheduled_clear_size_limit, &cfg.log.scheduled_clear_size_limit_unit),
                restart_cfg: None,
            });
        }
    }

    async fn loop_run(self: &Arc<Self>) {
        // 对齐到下一个整分钟
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let wait = 60 - (now % 60);
        tokio::time::sleep(Duration::from_secs(wait)).await;
        self.tick().await;
        // Go 用 time.NewTicker(time.Minute)，首次触发在 1 分钟后；
        // tokio::time::interval 的第一次 tick 会立即完成，必须先消费掉，
        // 否则对齐到整分钟后会在同一分钟里额外触发一次（任务被重复执行）。
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            self.tick().await;
        }
    }

    async fn tick(self: &Arc<Self>) {
        let jobs: Vec<Job> = self.jobs.lock().clone();
        if jobs.is_empty() {
            return;
        }
        // 对齐 Go time.Now()：cron 按本地时区匹配，而非 UTC。
        let (min, hour, dom, mon, dow) = crate::logger::local_cron_fields();
        for job in jobs {
            if !cron_match(&job.cron, min, hour, dom, mon, dow) {
                continue;
            }
            match job.kind {
                JobKind::Restart => {
                    self.log.app("App", "定时重启触发。");
                    // Go 版闭包直接捕获 Reload 时传入的 cfg，不重新读库。
                    let cfg = match job.restart_cfg {
                        Some(c) => c,
                        None => match self.store.load() {
                            Ok(c) => c,
                            Err(e) => {
                                self.log.app("App", &format!("定时重启失败（读取配置）：{}", e));
                                continue;
                            }
                        },
                    };
                    if let Err(e) = self.core.restart(&cfg).await {
                        self.log.app("App", &format!("定时重启失败：{}", e));
                    }
                }
                JobKind::ClearLogs => {
                    clear_logs(&self.log, job.limit_bytes);
                }
            }
        }
    }
}

// 让 Job 可以被 clone（字段都是值类型，但 Vec<Job> 直接用 clone() 需要 Clone 派生）
impl Clone for Job {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            cron: self.cron.clone(),
            kind: self.kind,
            limit_bytes: self.limit_bytes,
            restart_cfg: self.restart_cfg.clone(),
        }
    }
}

/// 对齐 proxy.init clear_logs()：日志超大小则清空。
fn clear_logs(log: &Arc<Logger>, limit: i64) {
    if limit <= 0 {
        return;
    }
    if let Ok(meta) = std::fs::metadata(paths::app_log_path()) {
        if meta.len() as i64 >= limit {
            let _ = log.clear_app();
            log.app("日志", "App 日志因超出大小限制已被定时清理。");
        }
    }
    if let Ok(meta) = std::fs::metadata(paths::core_log_path()) {
        if meta.len() as i64 >= limit {
            let _ = log.clear_core();
            log.app("日志", "核心日志因超出大小限制已被定时清理。");
        }
    }
}

fn size_to_bytes(limit: i32, unit: &str) -> i64 {
    let mul: i64 = match unit {
        "B" => 1,
        "KB" => 1024,
        "MB" => 1024 * 1024,
        "GB" => 1024 * 1024 * 1024,
        _ => 1,
    };
    limit as i64 * mul
}

// ── 5 字段 cron 匹配 ──────────────────────────────────

/// 判断 cron 表达式是否匹配（5 字段：分 时 日 月 周）。
pub fn cron_match(expr: &str, min: u32, hour: u32, dom: u32, mon: u32, dow: u32) -> bool {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return false;
    }
    match_field(fields[0], min, 0, 59)
        && match_field(fields[1], hour, 0, 23)
        && match_field(fields[2], dom, 1, 31)
        && match_field(fields[3], mon, 1, 12)
        && match_field(fields[4], dow, 0, 6)
}

/// 支持单个值、*、*/N、a-b、a-b/N、a,b 及组合。
fn match_field(field: &str, val: u32, lo: u32, hi: u32) -> bool {
    field.split(',').any(|part| match_part(part, val, lo, hi))
}

fn match_part(part: &str, val: u32, lo: u32, hi: u32) -> bool {
    // */N
    if let Some(step) = part.strip_prefix("*/") {
        let step: u32 = match step.parse() {
            Ok(s) if s > 0 => s,
            _ => return false,
        };
        let mut i = lo;
        while i <= hi {
            if i == val {
                return true;
            }
            i += step;
        }
        return false;
    }
    // a-b 或 a-b/N
    if part.contains('/') {
        let mut seg = part.splitn(2, '/');
        let base = seg.next().unwrap_or("*");
        let step: u32 = match seg.next().unwrap_or("1").parse() {
            Ok(s) if s > 0 => s,
            _ => return false,
        };
        let (lo2, hi2) = match parse_range(base, lo, hi) {
            Some(v) => v,
            None => return false,
        };
        let mut i = lo2;
        while i <= hi2 {
            if i == val {
                return true;
            }
            i += step;
        }
        return false;
    }
    // a-b
    if part != "*" {
        if let Some((lo2, hi2)) = parse_range(part, lo, hi) {
            return val >= lo2 && val <= hi2;
        }
    }
    // *
    if part == "*" {
        return val >= lo && val <= hi;
    }
    // 单值
    part.parse::<u32>().map(|n| n == val).unwrap_or(false)
}

fn parse_range(s: &str, lo: u32, hi: u32) -> Option<(u32, u32)> {
    if s == "*" {
        return Some((lo, hi));
    }
    match s.find('-') {
        Some(i) => {
            let a: u32 = s[..i].parse().ok()?;
            let b: u32 = s[i + 1..].parse().ok()?;
            Some((a, b))
        }
        None => None,
    }
}
