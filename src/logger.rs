//! app/core/debug 日志的文件写入 + SSE 实时推送。

use anyhow::Result;
use chrono::Local;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::broadcast;

use crate::paths;

pub struct Logger {
    inner: Mutex<Inner>,
    tx: broadcast::Sender<String>,
    _subs: Arc<RwLock<()>>, // 仅用于显式表达订阅者存在性占位
}

struct Inner {
    app_file: Option<File>,
    core_file: Option<File>,
}

impl Logger {
    pub fn new() -> Result<Arc<Self>> {
        std::fs::create_dir_all(paths::LOG_DIR)?;
        std::fs::create_dir_all(paths::TEMP_DIR)?;
        let app = open_log(paths::APP_LOG_PATH)?;
        let core = open_log(paths::CORE_LOG_PATH)?;
        let (tx, _rx) = broadcast::channel::<String>(256);
        Ok(Arc::new(Logger {
            inner: Mutex::new(Inner {
                app_file: Some(app),
                core_file: Some(core),
            }),
            tx,
            _subs: Arc::new(RwLock::new(())),
        }))
    }

    /// App 写一行 app 日志，格式与原 include.sh log() 一致。
    pub fn app(&self, scope: &str, msg: &str) {
        let line = format!(
            "[{}] [{}] {}\n",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            scope,
            msg
        );
        let mut inner = self.inner.lock().unwrap();
        if let Some(f) = inner.app_file.as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
    }

    /// Core 写一行 core 日志（外部核心 stdout/stderr）。
    pub fn core(&self, line: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(f) = inner.core_file.as_mut() {
                let _ = f.write_all(line.as_bytes());
            }
        }
        let _ = self.tx.send(line.to_string());
    }

    /// ReadApp 读全部 app 日志。
    pub fn read_app(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(paths::APP_LOG_PATH)
    }

    /// ReadCore 读全部 core 日志。
    pub fn read_core(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(paths::CORE_LOG_PATH)
    }

    /// ClearAppLog 清空 app 日志。
    pub fn clear_app_log(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(f) = inner.app_file.take() {
            let _ = f.sync_all();
        }
        std::fs::write(paths::APP_LOG_PATH, b"")?;
        inner.app_file = Some(open_log(paths::APP_LOG_PATH)?);
        Ok(())
    }

    /// ClearCoreLog 清空 core 日志。
    pub fn clear_core_log(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(f) = inner.core_file.take() {
            let _ = f.sync_all();
        }
        std::fs::write(paths::CORE_LOG_PATH, b"")?;
        inner.core_file = Some(open_log(paths::CORE_LOG_PATH)?);
        Ok(())
    }

    /// Subscribe 订阅 core 日志实时推送，返回一个 receiver。
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }
}

fn open_log(p: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open(p)?)
}
