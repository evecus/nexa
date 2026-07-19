//! nexa 的依赖容器，整合 store/core/netmanager/scheduler/logger，
//! 并实现 Apply 流程（对齐 proxy.init 的 reload_service = cleanup + start）。

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;

use crate::assets::GeoIpFs;
use crate::config::Config;
use crate::core::Manager;
use crate::logger::Logger;
use crate::netmanager::Manager as NetManager;
use crate::paths;
use crate::scheduler::Scheduler;
use crate::store::Store;

pub struct App {
    pub store: Store,
    pub log: std::sync::Arc<Logger>,
    pub core: std::sync::Arc<Manager>,
    pub net: NetManager,
    pub sched: std::sync::Arc<Scheduler>,
}

impl App {
    /// New 创建并初始化所有组件。
    pub fn new() -> Result<std::sync::Arc<Self>> {
        fs::create_dir_all(paths::HOME_DIR)?;
        fs::create_dir_all(paths::PROFILES_DIR)?;
        fs::create_dir_all(paths::RUN_DIR)?;
        fs::create_dir_all(paths::NFT_DIR)?;

        let store = Store::new()?;
        let log = Logger::new()?;
        let mgr = Manager::new(log.clone());
        let net = NetManager::new(log.clone());
        let sched = Scheduler::new(log.clone(), mgr.clone());

        let app = std::sync::Arc::new(App {
            store,
            log: log.clone(),
            core: mgr.clone(),
            net,
            sched: sched.clone(),
        });

        // 核心放弃重启时自动清理网络规则
        let app_clone = app.clone();
        mgr.on_give_up(move || {
            let cfg = match app_clone.load_config() {
                Ok(c) => c,
                Err(_) => return,
            };
            app_clone.net.cleanup(&cfg);
            app_clone.log.app("App", "核心启动失败，已清理网络规则。");
        });

        Ok(app)
    }

    /// LoadConfig 读取配置。
    pub fn load_config(&self) -> Result<Config> {
        self.store.load()
    }

    /// SaveConfig 保存配置（不触发 apply）。
    pub fn save_config(&self, c: &Config) -> Result<()> {
        self.store.save(c)
    }

    /// Boot 启动时调用：先启动调度器；若 config.enabled=1 则 Apply。
    pub fn boot(&self) -> Result<()> {
        let cfg = self.load_config()?;
        self.sched.start();
        self.sched.reload(&cfg);

        if !cfg.config.enabled {
            self.log.app("App", "已禁用，退出。");
            return Ok(());
        }

        // start_delay
        if cfg.config.start_delay > 0 {
            self.log
                .app("App", &format!("延迟 {} 秒后启动。", cfg.config.start_delay));
            std::thread::sleep(Duration::from_secs(cfg.config.start_delay as u64));
        }
        self.apply(&cfg)
    }

    /// Apply：启动核心 → 应用网络规则。若核心已运行则先 Stop+Cleanup。
    pub fn apply(&self, cfg: &Config) -> Result<()> {
        if !cfg.config.enabled {
            self.log.app("App", "已禁用，停止服务。");
            return self.stop();
        }
        self.log.app("App", "已启用，启动中。");

        // 先清理旧的网络规则
        self.net.cleanup(cfg);

        // 启动核心
        self.core.start(cfg)?;

        // 应用网络/防火墙
        if cfg.proxy.enabled {
            return self.net.apply(cfg);
        }
        self.log.app("代理", "已禁用，跳过防火墙设置。");
        Ok(())
    }

    /// Stop 停止核心 + 清理网络 + 停调度。
    pub fn stop(&self) -> Result<()> {
        let cfg = self.load_config().ok();
        let _ = self.core.stop();
        if let Some(cfg) = cfg {
            self.net.cleanup(&cfg);
        }
        Ok(())
    }

    /// Reload 对齐 proxy.init reload_service = cleanup + start。
    pub fn reload(&self, cfg: &Config) -> Result<()> {
        self.sched.reload(cfg);
        if !cfg.config.enabled {
            return self.stop();
        }
        self.net.cleanup(cfg);
        self.core.restart(cfg)?;
        if cfg.proxy.enabled {
            return self.net.apply(cfg);
        }
        Ok(())
    }

    /// Restart 重启核心并重应用网络。
    pub fn restart(&self, cfg: &Config) -> Result<()> {
        self.net.cleanup(cfg);
        self.core.restart(cfg)?;
        if cfg.proxy.enabled {
            return self.net.apply(cfg);
        }
        Ok(())
    }

    /// HUPReload 仅发 HUP 信号快速重载核心。
    #[allow(dead_code)]
    pub fn hup_reload(&self) -> Result<()> {
        self.core.reload()
    }

    /// PID 返回核心 pid（无则 0）。
    pub fn pid(&self) -> u32 {
        self.core.pid()
    }

    /// PrepareFiles 确保 profile 目录等就绪，并释放内嵌的 geoip 集合文件。
    pub fn prepare_files(&self) {
        let _ = fs::create_dir_all(paths::PROFILES_DIR);
        let _ = fs::create_dir_all(paths::RUN_DIR);
        let _ = fs::create_dir_all(paths::TEMP_DIR);
        let _ = fs::create_dir_all(paths::NFT_DIR);
        release_embedded_geoip();
    }

    /// WritePid 写 nexa 自身 pid。
    pub fn write_pid(&self, pid: u32) {
        let _ = fs::write(
            format!("{}/nexa-daemon.pid", paths::TEMP_DIR),
            pid.to_string(),
        );
    }
}

/// releaseEmbeddedGeoIP 把编译时内嵌的 geoip_cn.nft / geoip6_cn.nft 释放到 /etc/nexa/firewall/。
/// 仅当目标文件不存在时释放，已存在则保留用户文件。
fn release_embedded_geoip() {
    for (embed_path, target) in [
        ("geoip_cn.nft", paths::GEOIP_CN_NFT),
        ("geoip6_cn.nft", paths::GEOIP6_CN_NFT),
    ] {
        if Path::new(target).exists() {
            continue;
        }
        if let Some(file) = GeoIpFs::get(embed_path) {
            let _ = fs::write(target, file.data.as_ref());
        }
    }
}
