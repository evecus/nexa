//! 配置持久化（redb 单文件 KV 数据库），1:1 对齐 Go 版 internal/store。
//!
//! Go 版用 bbolt（纯 Go 单文件 KV，schema 对齐 UCI sections）；Rust 版用 redb
//! （纯 Rust、无 C 依赖的嵌入式 KV，同样是单文件 + ACID），表结构与 Go 的
//! bucket 一一对应：meta / config_json / auth，均为单行存储。
//! 选型理由同 Go 版注释：比 SQLite 轻量得多，无 schema、无 C 工具链依赖，
//! 足以承载本包极简的存储需求。

use crate::config::Config;
use crate::paths;
use anyhow::Result;
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// nexa 应用版本（对齐 bbolt meta bucket 里的 version）。
pub const APP_VERSION: &str = "1.0.0";

/// meta 表：仅存版本号（对齐 Go bucketMeta / metaVersion）。
const TABLE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// config 表：整份 Config JSON 单行存储（对齐 Go bucketConf / confRowID）。
const TABLE_CONF: TableDefinition<&str, &[u8]> = TableDefinition::new("config_json");
/// auth 表：凭据单行存储（对齐 Go bucketAuth / authRowID）。
const TABLE_AUTH: TableDefinition<&str, &[u8]> = TableDefinition::new("auth");

/// 单行 row key（对齐 Go confRowID / authRowID 的 "1"）。
const ROW_ID: &str = "1";
/// meta 表里的版本 key（对齐 Go metaVersion）。
const META_VERSION: &str = "version";

/// 认证凭据（auth 表单行存储，替代旧 auth.json）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub hash: String,          // bcrypt
    #[serde(default)]
    pub auth_disabled: bool, // true 时跳过登录校验，允许无验证访问
}

pub struct Store {
    db: Database,
}

impl Store {
    /// 打开/创建数据库并初始化 schema（表），对齐 Go Store.New。
    pub fn open() -> Result<Self> {
        let path = paths::db_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let db = Database::create(&path)?;
        {
            let wf = db.begin_write()?;
            for t in [&TABLE_META, &TABLE_CONF, &TABLE_AUTH] {
                let _ = wf.open_table(*t)?;
            }
            wf.commit()?;
        }
        let s = Self { db };
        // 对齐 Go Load：首次启动写入默认配置
        if s.load_conf_raw()?.is_none() {
            s.save(&Config::default())?;
        }
        Ok(s)
    }

    // ── auth（对齐 Go LoadAuth / SaveAuth） ──────────────

    /// 读取凭据；不存在返回 None。
    pub fn load_auth(&self) -> Result<Option<Credentials>> {
        let rn = self.db.begin_read()?;
        let raw = match rn.open_table(TABLE_AUTH)?.get(ROW_ID)? {
            Some(v) => v.value().to_vec(),
            None => return Ok(None),
        };
        Ok(Some(serde_json::from_slice(&raw)?))
    }

    /// 保存凭据（整体覆盖）。
    pub fn save_auth(&self, c: &Credentials) -> Result<()> {
        let raw = serde_json::to_vec(c)?;
        let wf = self.db.begin_write()?;
        wf.open_table(TABLE_AUTH)?.insert(ROW_ID, raw.as_slice())?;
        wf.commit()?;
        Ok(())
    }

    // ── config（对齐 Go Load / Save） ────────────────────

    fn load_conf_raw(&self) -> Result<Option<Vec<u8>>> {
        let rn = self.db.begin_read()?;
        Ok(rn
            .open_table(TABLE_CONF)?
            .get(ROW_ID)?
            .map(|v| v.value().to_vec()))
    }

    /// 读取配置；不存在则返回默认值（open 时已落库）。
    pub fn load(&self) -> Result<Config> {
        match self.load_conf_raw()? {
            Some(raw) => Ok(serde_json::from_slice(&raw)?),
            None => Ok(Config::default()),
        }
    }

    /// 保存配置（整体覆盖）。
    pub fn save(&self, cfg: &Config) -> Result<()> {
        let raw = serde_json::to_vec(cfg)?;
        let wf = self.db.begin_write()?;
        wf.open_table(TABLE_CONF)?.insert(ROW_ID, raw.as_slice())?;
        wf.commit()?;
        Ok(())
    }

    // ── version（对齐 Go Version / SetVersion） ──────────

    /// nexa 应用版本，缺省返回 APP_VERSION。
    pub fn version(&self) -> String {
        let rn = match self.db.begin_read() {
            Ok(rn) => rn,
            Err(_) => return APP_VERSION.to_string(),
        };
        let v = rn
            .open_table(TABLE_META)
            .ok()
            .and_then(|t| t.get(META_VERSION).ok().flatten())
            .map(|v| String::from_utf8_lossy(v.value()).to_string())
            .filter(|v| !v.is_empty());
        v.unwrap_or_else(|| APP_VERSION.to_string())
    }

    /// 写入版本。
    pub fn set_version(&self, v: &str) -> Result<()> {
        let wf = self.db.begin_write()?;
        wf.open_table(TABLE_META)?
            .insert(META_VERSION, v.as_bytes())?;
        wf.commit()?;
        Ok(())
    }

    // ── profiles（文件型配置，两个版本一致） ─────────────

    /// 列出 profiles 目录下的文件（含修改时间与大小），对齐 api.handleListProfiles。
    pub fn list_profiles(&self) -> Result<Vec<ProfileEntry>> {
        let dir = paths::profiles_dir();
        let mut out = Vec::new();
        if dir.exists() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let meta = entry.metadata()?;
                if !meta.is_file() {
                    continue;
                }
                let name = match entry.file_name().to_str() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                out.push(ProfileEntry {
                    name,
                    mtime,
                    size: meta.len() as i64,
                });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub fn read_profile(&self, name: &str) -> Result<String> {
        Ok(fs::read_to_string(self.profile_path(name)?)?)
    }

    pub fn write_profile(&self, name: &str, content: &str) -> Result<()> {
        fs::write(self.profile_path(name)?, content)?;
        Ok(())
    }

    pub fn delete_profile(&self, name: &str) -> Result<()> {
        fs::remove_file(self.profile_path(name)?)?;
        Ok(())
    }

    /// 重命名配置文件。目标已存在返回错误（对齐 api 的 409 冲突处理）。
    pub fn rename_profile(&self, old: &str, new: &str) -> Result<()> {
        let from = self.profile_path(old)?;
        let to = self.profile_path(new)?;
        if to.exists() {
            anyhow::bail!("同名文件已存在: {}", new);
        }
        fs::rename(from, to)?;
        Ok(())
    }

    /// 防路径穿越：只保留文件基名。
    fn profile_path(&self, name: &str) -> Result<PathBuf> {
        let base = Path::new(name)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .filter(|n| !n.is_empty());
        match base {
            Some(n) => Ok(paths::profiles_dir().join(n)),
            None => anyhow::bail!("非法的配置文件名: {}", name),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub name: String,
    pub mtime: i64,
    pub size: i64,
}
