//! 内置 cron 调度器，替代原 proxy.init 写 /etc/crontabs/root 的做法。
//! 支持 5 字段 cron（minute hour dom month dow），每分钟整点触发一次。

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Datelike, Local, NaiveDateTime, Timelike};

use crate::config::Config;
use crate::core::Manager;
use crate::logger::Logger;
use crate::paths;

type JobFn = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone)]
struct Job {
    #[allow(dead_code)]
    id: String,
    cron: String,
    fn_: JobFn,
}

pub struct Scheduler {
    log: Arc<Logger>,
    manager: Arc<Manager>,
    state: Mutex<SchedState>,
}

struct SchedState {
    stop_rx: Option<std::sync::mpsc::Sender<()>>,
    jobs: Vec<Job>,
    running: bool,
}

impl Scheduler {
    pub fn new(log: Arc<Logger>, manager: Arc<Manager>) -> Arc<Self> {
        Arc::new(Scheduler {
            log,
            manager,
            state: Mutex::new(SchedState {
                stop_rx: None,
                jobs: vec![],
                running: false,
            }),
        })
    }

    /// Start 启动调度循环。
    pub fn start(self: &Arc<Self>) {
        let mut st = self.state.lock().unwrap();
        if st.running {
            return;
        }
        st.running = true;
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        st.stop_rx = Some(tx);
        drop(st);

        let self_arc = self.clone();
        thread::spawn(move || {
            self_arc.loop_(rx);
        });
    }

    /// Stop 停止调度。
    pub fn stop(&self) {
        let mut st = self.state.lock().unwrap();
        if !st.running {
            return;
        }
        if let Some(tx) = st.stop_rx.take() {
            let _ = tx.send(());
        }
        st.running = false;
    }

    /// Reload 按 cfg 重新设置任务。
    pub fn reload(self: &Arc<Self>, cfg: &Config) {
        {
            let mut st = self.state.lock().unwrap();
            st.jobs.clear();
        }

        // 定时重启
        if cfg.config.scheduled_restart && !cfg.config.scheduled_restart_cron.is_empty() {
            let cron = cfg.config.scheduled_restart_cron.clone();
            let mgr = self.manager.clone();
            let log = self.log.clone();
            let cfg2 = cfg.clone();
            self.add("restart", cron, move || {
                log.app("App", "定时重启触发。");
                let _ = mgr.restart(&cfg2);
            });
        }

        // 日志定时清理
        if cfg.log.scheduled_clear && !cfg.log.scheduled_clear_cron.is_empty() {
            let cron = cfg.log.scheduled_clear_cron.clone();
            let lg = self.log.clone();
            let limit = cfg.log.scheduled_clear_size_limit;
            let unit = cfg.log.scheduled_clear_size_limit_unit.clone();
            self.add("clear_logs", cron, move || {
                clear_logs(&lg, limit, &unit);
            });
        }
    }

    fn add(self: &Arc<Self>, id: &str, cron: String, fn_: impl Fn() + Send + Sync + 'static) {
        let mut st = self.state.lock().unwrap();
        st.jobs.push(Job {
            id: id.to_string(),
            cron,
            fn_: Arc::new(fn_),
        });
    }

    fn loop_(&self, rx: std::sync::mpsc::Receiver<()>) {
        // 对齐到下一个整分钟
        let now = Local::now();
        let next = now
            .with_second(0)
            .and_then(|t| t.with_nanosecond(0))
            .map(|t| t + chrono::Duration::minutes(1));
        if let Some(next) = next {
            let sleep_dur = next.signed_duration_since(now).to_std().unwrap_or(Duration::ZERO);
            // 上限 60s
            let sleep_dur = sleep_dur.min(Duration::from_secs(60));
            thread::sleep(sleep_dur);
        }
        let ticker = Instant::now();
        let mut last_tick: Option<DateTime<Local>> = None;
        loop {
            // 检查停止信号
            if rx.try_recv().is_ok() {
                return;
            }
            thread::sleep(Duration::from_secs(1));
            let now = Local::now();
            // 每分钟整点触发
            if now.second() == 0 {
                if last_tick.map(|t| t.minute() != now.minute() || t.timestamp() != now.timestamp()).unwrap_or(true) {
                    last_tick = Some(now);
                    self.tick(now);
                }
            }
            // 防止 ticker 未使用告警
            let _ = ticker;
        }
    }

    fn tick(&self, t: DateTime<Local>) {
        let jobs: Vec<Job> = self.state.lock().unwrap().jobs.clone();
        for j in jobs {
            if match_cron(&j.cron, &t) {
                let fn_ = j.fn_.clone();
                thread::spawn(move || {
                    fn_();
                });
            }
        }
    }
}

/// clearLogs 对齐 proxy.init clear_logs()：日志超大小则清空。
fn clear_logs(log: &Logger, limit: i64, unit: &str) {
    let bytes = size_to_bytes(limit, unit);
    if bytes <= 0 {
        return;
    }
    if let Ok(meta) = std::fs::metadata(paths::APP_LOG_PATH) {
        if meta.len() as i64 >= bytes {
            let _ = log.clear_app_log();
            log.app("日志", "App 日志因超出大小限制已被定时清理。");
        }
    }
    if let Ok(meta) = std::fs::metadata(paths::CORE_LOG_PATH) {
        if meta.len() as i64 >= bytes {
            let _ = log.clear_core_log();
            log.app("日志", "核心日志因超出大小限制已被定时清理。");
        }
    }
}

fn size_to_bytes(limit: i64, unit: &str) -> i64 {
    let mul: i64 = match unit {
        "B" => 1,
        "KB" => 1024,
        "MB" => 1024 * 1024,
        "GB" => 1024 * 1024 * 1024,
        _ => 1,
    };
    limit * mul
}

// ── 极简 5 字段 cron 匹配 ──

/// match 判断 cron 表达式是否匹配时间 t（5 字段：分 时 日 月 周）。
fn match_cron(expr: &str, t: &DateTime<Local>) -> bool {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return false;
    }
    match_field(fields[0], t.minute() as i32, 0, 59)
        && match_field(fields[1], t.hour() as i32, 0, 23)
        && match_field(fields[2], t.day() as i32, 1, 31)
        && match_field(fields[3], t.month() as i32, 1, 12)
        && match_field(fields[4], t.weekday().num_days_from_sunday() as i32, 0, 6)
}

/// matchField 支持单个值、*、*/N、a-b、a,b 及组合。
fn match_field(field: &str, val: i32, lo: i32, hi: i32) -> bool {
    for part in field.split(',') {
        if match_part(part, val, lo, hi) {
            return true;
        }
    }
    false
}

fn match_part(part: &str, val: i32, lo: i32, hi: i32) -> bool {
    // */N
    if let Some(rest) = part.strip_prefix("*/") {
        let step: i32 = match rest.parse() {
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
    // a-b/N 或 a/N
    if let Some(slash_pos) = part.find('/') {
        let base = &part[..slash_pos];
        let step: i32 = match part[slash_pos + 1..].parse() {
            Ok(s) if s > 0 => s,
            _ => return false,
        };
        if let Some((lo2, hi2)) = parse_range(base, lo, hi) {
            let mut i = lo2;
            while i <= hi2 {
                if i == val {
                    return true;
                }
                i += step;
            }
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
    match part.parse::<i32>() {
        Ok(n) => n == val,
        Err(_) => false,
    }
}

fn parse_range(s: &str, lo: i32, hi: i32) -> Option<(i32, i32)> {
    if s == "*" {
        return Some((lo, hi));
    }
    if let Some(dash_pos) = s.find('-') {
        let a: i32 = s[..dash_pos].parse().ok()?;
        let b: i32 = s[dash_pos + 1..].parse().ok()?;
        return Some((a, b));
    }
    None
}

#[allow(dead_code)]
fn unused(_t: &NaiveDateTime) {}
