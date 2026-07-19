//! 用 SQLite 持久化 nexa 配置，schema 对齐 UCI sections。

use anyhow::Result;
use rusqlite::Connection;
use std::sync::Mutex;

use crate::config::Config;
use crate::paths;

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// New 打开/创建数据库并初始化 schema。
    pub fn new() -> Result<Self> {
        let conn = Connection::open(paths::DB_PATH)?;
        let store = Store {
            conn: Mutex::new(conn),
        };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> Result<()> {
        let schema = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS config_json (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    value TEXT NOT NULL
);
";
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(schema)?;
        Ok(())
    }

    /// Load 读取配置；不存在则写入默认值并返回。
    pub fn load(&self) -> Result<Config> {
        let conn = self.conn.lock().unwrap();
        let raw: Option<String> = conn
            .query_row(
                "SELECT value FROM config_json WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .ok();
        match raw {
            Some(s) => {
                let cfg: Config = serde_json::from_str(&s)?;
                Ok(cfg)
            }
            None => {
                drop(conn);
                let def = crate::config::default_config();
                self.save(&def)?;
                Ok(def)
            }
        }
    }

    /// Save 保存配置（整体覆盖）。
    pub fn save(&self, c: &Config) -> Result<()> {
        let raw = serde_json::to_string(c)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO config_json(id, value) VALUES(1, ?1)
             ON CONFLICT(id) DO UPDATE SET value = excluded.value",
            [&raw],
        )?;
        Ok(())
    }

    /// Close 关闭数据库连接。
    #[allow(dead_code)]
    pub fn close(self) -> Result<()> {
        let conn = self.conn.into_inner().unwrap();
        conn.close().map_err(|(_, e)| anyhow::anyhow!(e))?;
        Ok(())
    }

    /// Version 返回 nexa 版本。
    pub fn version(&self) -> String {
        let conn = self.conn.lock().unwrap();
        let v: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'version'", [], |row| {
                row.get(0)
            })
            .ok();
        v.filter(|s| !s.is_empty()).unwrap_or_else(|| "1.0.0".to_string())
    }

    /// SetVersion 写入版本。
    #[allow(dead_code)]
    pub fn set_version(&self, v: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [v],
        )?;
        // 顺便记个时间
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('version_set_at', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ["0"],
        )?;
        Ok(())
    }
}
