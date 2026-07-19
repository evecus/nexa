//! nexa 主程序：独立守护进程，./nexa 即可运行，默认监听 :9990。
//! 提供 HTTP API + 内嵌 Web 面板。不依赖 luci/rpcd/ubus/UCI。

mod api;
mod app;
mod assets;
mod auth;
mod config;
mod core;
mod hosts;
mod identifiers;
mod logger;
mod netmanager;
mod nfttemplate;
mod paths;
mod scheduler;
mod static_serve;
mod store;
mod systemuser;
mod sysutil;
mod web;

use std::sync::Arc;

use anyhow::Result;
use axum::routing::any;
use axum::Router;
use tokio::signal::unix::{signal, SignalKind};

use crate::api::AppState;
use crate::app::App;

#[tokio::main]
async fn main() -> Result<()> {
    // 简单参数解析：--addr :9990
    let mut addr = ":9990".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--addr" || arg == "-addr" {
            if let Some(v) = args.next() {
                addr = v;
            }
        } else if let Some(rest) = arg.strip_prefix("--addr=") {
            addr = rest.to_string();
        } else if let Some(rest) = arg.strip_prefix("-addr=") {
            addr = rest.to_string();
        }
    }

    // 规范化地址：musl libc 的 getaddrinfo 不会把空 host 当作 0.0.0.0，
    // 需显式补全，否则 ":9990" 会触发 "Name does not resolve"。
    if addr.starts_with(':') {
        addr = format!("0.0.0.0{}", addr);
    }

    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nexa=info,warn".into()),
        )
        .init();

    // version 默认 dev，可由环境变量 NEXA_VERSION 注入
    let version = std::env::var("NEXA_VERSION").unwrap_or_else(|_| "dev".to_string());
    let _ = api::VERSION.set(version.clone());

    let a = App::new()?;
    a.prepare_files();
    a.write_pid(std::process::id());

    let au = Arc::new(auth::Auth::new());
    let state = Arc::new(AppState {
        app: a.clone(),
        auth: au,
    });

    let api_router = api::build_router(state.clone());

    // 静态前端：非 /api 路径回退到内嵌 dist
    let app_router = Router::new()
        .merge(api_router)
        .fallback(any(static_serve::serve));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        "nexa 监听 {}（默认账户 admin/admin，请尽快修改）",
        addr
    );

    // 启动时拉起核心（对齐 init.d boot）
    {
        let a_boot = a.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = a_boot.boot() {
                a_boot.log.app("App", &format!("启动失败：{}", e));
            }
        });
    }

    // 信号处理：优雅关闭
    let a_shutdown = a.clone();
    let shutdown_handle = tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
        tracing::info!("收到退出信号，正在清理并关闭...");
        // 完整清理：杀核心 + 清理网络规则
        let _ = a_shutdown.stop();
        a_shutdown.sched.stop();
        tracing::info!("已清理完成，退出。");
    });

    axum::serve(listener, app_router)
        .with_graceful_shutdown(async move {
            shutdown_handle.await.ok();
        })
        .await?;

    Ok(())
}
