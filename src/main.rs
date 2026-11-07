//! Nexa - Transparent proxy management panel (Rust rewrite)
//!
//! 独立守护进程，./nexa 即可运行，默认监听 :9990。
//! 提供 HTTP API + 内嵌 Web 面板，不依赖 luci/rpcd/ubus/UCI。
//!
//! 子命令：
//!   nexa on   - 使用磁盘中的数据配置完整的防火墙规则和策略路由，但不启动代理核心，执行后退出。
//!   nexa off  - 清理防火墙规则和策略路由，但不杀死代理核心进程，执行后退出。
//!
//! on/off 与是否指定 -p/--addr 端口参数无关，二者都只做网络规则配置/清理，不涉及 HTTP 服务。

mod auth;
mod cgroupsupport;
mod config;
mod core;
mod hosts;
mod identifiers;
mod logger;
mod netmanager;
mod nfttemplate;
mod paths;
mod scheduler;
mod store;
mod web;

use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::auth::AuthState;
use crate::config::Config;
use crate::core::CoreManager;
use crate::logger::Logger;
use crate::netmanager::NetManager;
use crate::scheduler::Scheduler;
use crate::store::Store;

#[derive(Parser, Debug)]
#[command(name = "nexa", about = "Nexa transparent proxy management panel")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:9990", help = "HTTP 监听地址（与 -p 同时指定时以 -p 为准）")]
    addr: String,
    #[arg(short = 'p', long, help = "Web 监听端口（默认 9990）")]
    port: Option<u16>,
    #[arg(short = 'd', long, help = "数据目录（默认 /etc/nexa）")]
    data_dir: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// 使用磁盘配置下发防火墙规则和策略路由（不启动核心）
    On,
    /// 清理防火墙规则和策略路由（不杀死核心）
    Off,
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub auth: Arc<AuthState>,
    pub core: Arc<CoreManager>,
    pub net: Arc<NetManager>,
    pub log: Arc<Logger>,
    pub sched: Arc<Scheduler>,
    pub version: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nexa=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    // -d 指定数据目录，替换默认的 /etc/nexa 及其派生路径（日志、运行时目录等）。
    // 必须在 Store/Logger/NetManager 等任何使用 paths 的组件初始化之前调用。
    paths::init(cli.data_dir.as_deref());
    prepare_files();

    let log = Logger::new()?;
    let store = Arc::new(Store::open()?);
    let net = Arc::new(NetManager::new(log.clone()));

    // 启动时先按配置中的 run_dir 应用运行目录（设置里为空则用默认 <数据目录>/run）。
    // 非法值（如相对路径）静默忽略，保持默认值；Apply/Reload 时会再次校验并向用户报错。
    if let Ok(cfg) = store.load() {
        let _ = paths::set_run_dir(&cfg.config.run_dir);
    }

    match cli.command {
        Some(Commands::On) => run_on(&log, &store, &net).await,
        Some(Commands::Off) => run_off(&log, &store, &net).await,
        None => run_server(cli, store, log, net).await,
    }
}

// ── 子命令 on / off ────────────────────────────────────

/// `./nexa on`：仅使用磁盘中的数据（配置文件）配置完整的防火墙规则和策略路由，
/// 不启动代理核心进程。不受 config.enabled / proxy.enabled 影响。
async fn run_on(
    log: &Arc<Logger>,
    store: &Arc<Store>,
    net: &Arc<NetManager>,
) -> anyhow::Result<()> {
    let cfg = store.load()?;
    log.app("CLI", "执行 nexa on…");

    // 先清理旧规则，避免残留导致重复插入（对齐 Apply 前的 cleanup 惯例）。
    net.cleanup(&cfg);

    // GID 绕过使用固定数字 CORE_BYPASS_GID（对齐 Go 版），无需创建系统组。
    net.apply(&cfg)?;
    log.app("CLI", "已根据磁盘配置完成防火墙规则和策略路由配置（未启动代理核心）。");
    Ok(())
}

/// `./nexa off`：仅清理防火墙规则和策略路由，不杀死代理核心进程。
async fn run_off(
    log: &Arc<Logger>,
    store: &Arc<Store>,
    net: &Arc<NetManager>,
) -> anyhow::Result<()> {
    let cfg = store.load()?;
    log.app("CLI", "执行 nexa off…");
    net.cleanup(&cfg);
    log.app("CLI", "已清理防火墙规则和策略路由（代理核心进程未被终止）。");
    Ok(())
}

// ── 常驻模式 ───────────────────────────────────────────

async fn run_server(
    cli: Cli,
    store: Arc<Store>,
    log: Arc<Logger>,
    net: Arc<NetManager>,
) -> anyhow::Result<()> {
    let auth = Arc::new(AuthState::new(store.clone())?);
    let core = Arc::new(CoreManager::new(store.clone(), log.clone()));
    let sched = Scheduler::new(log.clone(), core.clone(), store.clone());

    // 核心放弃重启时自动清理网络规则
    {
        let net2 = net.clone();
        let log2 = log.clone();
        let store2 = store.clone();
        core.set_on_give_up(move || {
            if let Ok(cfg) = store2.load() {
                net2.cleanup(&cfg);
            }
            log2.app("App", "核心启动失败，已清理网络规则。");
        });
    }

    let state = AppState {
        store: store.clone(),
        auth: auth.clone(),
        core: core.clone(),
        net: net.clone(),
        log: log.clone(),
        sched: sched.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // 写 nexa 自身 pid（区别于核心 pid）
    write_pid(std::process::id());

    sched.start();

    let mut addr: SocketAddr = cli.addr.parse()?;
    if let Some(p) = cli.port {
        addr.set_port(p);
    }

    // 启动时拉起核心（对齐 init.d boot）：在 HTTP 监听之后异步执行，避免阻塞面板启动。
    let boot_state = state.clone();
    tokio::spawn(async move {
        boot(&boot_state).await;
    });

    log.app("App", &format!("监听 http://{}（数据目录：{}）", addr, paths::home_dir().display()));
    tracing::info!("Nexa listening on http://{}", addr);

    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // 优雅退出：清理网络规则并停止核心
    let shutdown = async move {
        wait_exit_signal().await;
        log.app("App", "收到退出信号，正在清理并关闭…");
        core.request_shutdown();
        let cfg = store.load().unwrap_or_default();
        let _ = core.stop();
        net.cleanup(&cfg);
        sched.stop();
        drop(cfg);
        log.app("App", "已清理完成，退出。");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// 对齐 App.Boot：启动调度器 → 按 start_delay 延迟 → Apply（启动核心 + 网络）。
async fn boot(state: &AppState) {
    let cfg = match state.store.load() {
        Ok(c) => c,
        Err(e) => {
            state.log.app("App", &format!("启动失败：读取配置失败 {}", e));
            return;
        }
    };
    state.sched.reload(&cfg);

    if !cfg.config.enabled {
        state.log.app("App", "已禁用，不启动核心。");
        return;
    }
    // start_delay（对齐 proxy.init:17-20）
    if cfg.config.start_delay > 0 {
        state
            .log
            .app("App", &format!("延迟 {} 秒后启动。", cfg.config.start_delay));
        tokio::time::sleep(std::time::Duration::from_secs(
            cfg.config.start_delay.max(0) as u64,
        ))
        .await;
    }

    if let Err(e) = apply_boot(state, &cfg).await {
        state.log.app("App", &format!("启动失败：{}", e));
    }
}

async fn apply_boot(state: &AppState, cfg: &Config) -> anyhow::Result<()> {
    state.log.app("App", "已启用，启动中。");
    state.net.cleanup(cfg);
    crate::paths::set_run_dir(&cfg.config.run_dir)?;
    std::fs::create_dir_all(crate::paths::run_dir())?;
    state.core.start(cfg)?;
    if cfg.proxy.enabled {
        state.net.apply(cfg)?;
    } else {
        state.log.app("代理", "已禁用，跳过防火墙设置。");
    }
    Ok(())
}

// ── 路由 ───────────────────────────────────────────────

fn build_router(state: AppState) -> Router {
    use crate::web;

    // auth 不需登录的路由单独挂载；其余 API 挂 auth 中间件。
    let api = Router::new()
        .route("/api/auth/login", post(web::handle_login))
        .route("/api/auth/me", get(web::handle_me))
        .route("/api/auth/password", put(web::handle_change_password))
        .route(
            "/api/auth/no-auth",
            get(web::handle_get_auth_disabled).put(web::handle_set_auth_disabled),
        )
        .route("/api/paths", get(web::handle_paths))
        .route("/api/version", get(web::handle_version))
        .route("/api/identifiers", get(web::handle_identifiers))
        .route("/api/hosts", get(web::handle_hosts))
        .route("/api/debug", post(web::handle_debug))
        .route("/api/config", get(web::handle_get_config).put(web::handle_put_config))
        .route("/api/config/apply", post(web::handle_apply_config))
        .route("/api/status", get(web::handle_status))
        .route("/api/reload", post(web::handle_reload))
        .route("/api/restart", post(web::handle_restart))
        .route("/api/restart-core", post(web::handle_restart_core))
        .route("/api/start", post(web::handle_start))
        .route("/api/stop", post(web::handle_stop))
        .route("/api/net/on", post(web::handle_net_on))
        .route("/api/net/off", post(web::handle_net_off))
        .route(
            "/api/profiles",
            get(web::handle_list_profiles).post(web::handle_upload_profile),
        )
        .route(
            "/api/profiles/:name",
            get(web::handle_download_profile)
                .put(web::handle_write_profile)
                .delete(web::handle_delete_profile),
        )
        .route("/api/profiles/:name/rename", post(web::handle_rename_profile))
        .route("/api/logs/app", get(web::handle_app_log))
        .route("/api/logs/core", get(web::handle_core_log))
        .route("/api/logs/app/clear", post(web::handle_clear_app_log))
        .route("/api/logs/core/clear", post(web::handle_clear_core_log))
        .route("/api/logs/stream", get(web::handle_log_stream))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            web::auth_middleware,
        ));

    Router::new()
        .merge(api)
        .route("/", get(web::serve_index))
        .route("/index.html", get(web::serve_index))
        .route("/style.css", get(web::serve_style))
        .route("/app.js", get(web::serve_app_js))
        .route("/favicon.svg", get(web::serve_favicon))
        .route("/favicon-32.png", get(web::serve_favicon_32))
        .route("/apple-touch-icon.png", get(web::serve_apple_touch))
        .route("/icon-192.png", get(web::serve_icon_192))
        .route("/icon-512.png", get(web::serve_icon_512))
        .route("/manifest.webmanifest", get(web::serve_manifest))
        .route("/vendor/codemirror.min.css", get(web::serve_cm_css))
        .route("/vendor/codemirror.min.js", get(web::serve_cm_js))
        .route("/vendor/mode/yaml/yaml.min.js", get(web::serve_cm_yaml_js))
        .route(
            "/vendor/mode/javascript/javascript.min.js",
            get(web::serve_cm_javascript_js),
        )
        .fallback(get(web::serve_index))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ── helpers ────────────────────────────────────────────

/// 确保目录就绪，并释放内嵌的 geoip 集合文件（仅当目标不存在时）。
fn prepare_files() {
    let _ = paths::ensure_dirs();
    release_embedded_geoip();
}

fn release_embedded_geoip() {
    for (content, target) in [
        (web::GEOIP_CN_NFT, paths::geoip_cn_nft()),
        (web::GEOIP6_CN_NFT, paths::geoip6_cn_nft()),
    ] {
        if target.exists() {
            continue; // 已存在，不覆盖（用户可自行更新）
        }
        let _ = std::fs::write(target, content);
    }
}

fn write_pid(pid: u32) {
    let _ = std::fs::write(paths::temp_dir().join("nexa-daemon.pid"), pid.to_string());
}

/// 等待 SIGINT / SIGTERM。
async fn wait_exit_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sigint = signal(SignalKind::interrupt()).ok();
        let fut_int = async {
            match sigint.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        let fut_term = async {
            match sigterm.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = fut_int => {}
            _ = fut_term => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
