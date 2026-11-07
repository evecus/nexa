//! 配置持久化（JSON 文件），对齐 Go 版 internal/store 的对外行为。
//!
//! Go 版用 bbolt 单文件 KV 存储；Rust 版沿用该重写已有的 JSON 文件方案，
//! 但在同一份文件里额外保存版本号（对齐 Store.Version()）。

use crate::config::Config;
use crate::paths;
use anyhow::Result;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// nexa 应用版本（对齐 bbolt meta bucket 里的 version）。
pub const APP_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoreFile {
    #[serde(default)]
    version: String,
    #[serde(default)]
    config: Config,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub name: String,
    pub mtime: i64,
    pub size: i64,
}

pub struct Store {
    path: PathBuf,
    cache: RwLock<Option<Config>>,
}

impl Store {
    pub fn open() -> Result<Self> {
        let path = paths::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let store = Self {
            path,
            cache: RwLock::new(None),
        };
        if !store.path.exists() {
            store.save(&Config::default())?;
        }
        Ok(store)
    }

    pub fn load(&self) -> Result<Config> {
        if let Some(c) = self.cache.read().as_ref() {
            return Ok(c.clone());
        }
        let buf = fs::read_to_string(&self.path)?;
        // 兼容两种形态：带 version 包装的 StoreFile，以及纯 Config JSON。
        let cfg: Config = match serde_json::from_str::<StoreFile>(&buf) {
            Ok(f) => f.config,
            Err(_) => serde_json::from_str::<Config>(&buf)?,
        };
        *self.cache.write() = Some(cfg.clone());
        Ok(cfg)
    }

    pub fn save(&self, cfg: &Config) -> Result<()> {
        // 保留已有版本号
        let version = self.version();
        let file = StoreFile {
            version,
            config: cfg.clone(),
        };
        let json = serde_json::to_string_pretty(&file)?;
        write_atomic(&self.path, &json)?;
        *self.cache.write() = Some(cfg.clone());
        Ok(())
    }

    /// nexa 应用版本，对齐 Go 版 Store.Version()。
    pub fn version(&self) -> String {
        fs::read_to_string(&self.path)
            .ok()
            .and_then(|buf| serde_json::from_str::<StoreFile>(&buf).ok())
            .map(|f| f.version)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| APP_VERSION.to_string())
    }

    pub fn set_version(&self, v: &str) -> Result<()> {
        let cfg = self.load().unwrap_or_default();
        let file = StoreFile {
            version: v.to_string(),
            config: cfg,
        };
        let json = serde_json::to_string_pretty(&file)?;
        write_atomic(&self.path, &json)?;
        Ok(())
    }

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

/// 原子写入：先写临时文件再 rename，避免写入过程中断电/中断留下半截 JSON。
fn write_atomic(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content)?;
    if let Err(e) = fs::rename(&tmp, path) {
        // rename 失败（跨设备等）退化到直接写
        let _ = fs::remove_file(&tmp);
        fs::write(path, content).map_err(|_| e)?;
    }
    Ok(())
}
