//! 实现 nexa 的 HTTP API + SSE，路由对齐原 ubus luci.proxy / rc / 文件操作。

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use futures::stream::Stream;
use serde::Deserialize;
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::app::App;
use crate::auth::{self, Auth};
use crate::config::Config;
use crate::{hosts, identifiers, paths};

pub struct AppState {
    pub app: Arc<App>,
    pub auth: Arc<Auth>,
}

/// 二进制版本号，由 main 在启动时设置。
pub static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn get_version() -> &'static str {
    VERSION.get().map(|s| s.as_str()).unwrap_or("dev")
}

/// 构建完整 API 路由组（已套 auth 中间件区分公开/受保护）。
pub fn build_router(state: Arc<AppState>) -> Router {
    let public = Router::new()
        .route("/api/auth/login", post(handle_login))
        .route("/api/auth/password", put(handle_change_password))
        .with_state(state.clone());

    let protected = Router::new()
        // 对齐 ubus luci.proxy
        .route("/api/paths", get(handle_paths))
        .route("/api/version", get(handle_version))
        .route("/api/identifiers", get(handle_identifiers))
        .route("/api/hosts", get(handle_hosts))
        .route("/api/debug", post(handle_debug))
        // 配置
        .route("/api/config", get(handle_get_config).put(handle_put_config))
        .route("/api/config/apply", post(handle_apply_config))
        // 状态与控制
        .route("/api/status", get(handle_status))
        .route("/api/reload", post(handle_reload))
        .route("/api/restart", post(handle_restart))
        .route("/api/restart-core", post(handle_restart_core))
        .route("/api/start", post(handle_start))
        .route("/api/stop", post(handle_stop))
        // profiles
        .route("/api/profiles", get(handle_list_profiles).post(handle_upload_profile))
        .route(
            "/api/profiles/:name",
            get(handle_download_profile)
                .put(handle_write_profile)
                .delete(handle_delete_profile),
        )
        // 无验证访问总开关
        .route("/api/auth/no-auth", get(handle_get_auth_disabled).put(handle_set_auth_disabled))
        // 日志
        .route("/api/logs/app", get(handle_app_log))
        .route("/api/logs/core", get(handle_core_log))
        .route("/api/logs/app/clear", post(handle_clear_app_log))
        .route("/api/logs/core/clear", post(handle_clear_core_log))
        .route("/api/logs/stream", get(handle_log_stream))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state);

    Router::new().merge(public).merge(protected)
}

/// auth 中间件：校验 Authorization: Bearer <token>。
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    // 总开关：无验证访问模式下直接放行，不校验 token
    if state.auth.is_auth_disabled() {
        return next.run(req).await;
    }
    let authz = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    if auth::extract_and_verify(authz) {
        return next.run(req).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

// ── auth ──

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

async fn handle_login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginBody>,
) -> Response {
    match state.auth.login(&body.username, &body.password) {
        Ok(tok) => (
            StatusCode::OK,
            Json(json!({"token": tok})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "用户名或密码错误"})),
        )
            .into_response(),
    }
}

/// handleGetAuthDisabled 返回当前"无验证访问"开关状态。
async fn handle_get_auth_disabled(State(state): State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        Json(json!({"auth_disabled": state.auth.is_auth_disabled()})),
    )
        .into_response()
}

#[derive(Deserialize)]
struct AuthDisabledBody {
    auth_disabled: bool,
}

/// handleSetAuthDisabled 打开/关闭"无验证访问"开关。
/// 注意：此接口挂在需要登录的路由组下——必须已通过认证才能打开该开关，
/// 避免未授权者主动把系统切到无验证模式。
async fn handle_set_auth_disabled(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthDisabledBody>,
) -> Response {
    state.auth.set_auth_disabled(body.auth_disabled);
    (
        StatusCode::OK,
        Json(json!({"auth_disabled": body.auth_disabled})),
    )
        .into_response()
}

async fn handle_change_password(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginBody>,
) -> Response {
    if body.username.is_empty() || body.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "用户名和密码不能为空"})),
        )
            .into_response();
    }
    match state.auth.change_password(&body.username, &body.password) {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── 对齐 ubus luci.proxy ──

async fn handle_paths() -> Response {
    (StatusCode::OK, Json(paths::get())).into_response()
}

async fn handle_version(State(state): State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "binary": get_version(),
            "app": state.app.store.version(),
        })),
    )
        .into_response()
}

async fn handle_identifiers() -> Response {
    (StatusCode::OK, Json(identifiers::get())).into_response()
}

async fn handle_hosts() -> Response {
    (StatusCode::OK, Json(hosts::get())).into_response()
}

async fn handle_debug(State(state): State<Arc<AppState>>) -> Response {
    let app = state.app.clone();
    tokio::task::spawn_blocking(move || {
        generate_debug(app);
    });
    (StatusCode::OK, Json(json!({"success": true}))).into_response()
}

// ── config ──

async fn handle_get_config(State(state): State<Arc<AppState>>) -> Response {
    match state.app.load_config() {
        Ok(cfg) => (StatusCode::OK, Json(cfg)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn handle_put_config(
    State(state): State<Arc<AppState>>,
    Json(cfg): Json<Config>,
) -> Response {
    match state.app.save_config(&cfg) {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn handle_apply_config(
    State(state): State<Arc<AppState>>,
    Json(cfg): Json<Config>,
) -> Response {
    if let Err(e) = state.app.save_config(&cfg) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    let app = state.app.clone();
    let result = tokio::task::spawn_blocking(move || app.reload(&cfg)).await;
    match result {
        Ok(Ok(_)) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── status & control ──

async fn handle_status(State(state): State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "running": state.app.core.running(),
            "pid": state.app.pid(),
        })),
    )
        .into_response()
}

async fn handle_reload(State(state): State<Arc<AppState>>) -> Response {
    let app = state.app.clone();
    let res = tokio::task::spawn_blocking(move || {
        let cfg = app.load_config()?;
        app.reload(&cfg)
    })
    .await;
    match res {
        Ok(Ok(_)) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn handle_restart(State(state): State<Arc<AppState>>) -> Response {
    let app = state.app.clone();
    let res = tokio::task::spawn_blocking(move || {
        let cfg = app.load_config()?;
        app.restart(&cfg)
    })
    .await;
    match res {
        Ok(Ok(_)) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn handle_restart_core(State(state): State<Arc<AppState>>) -> Response {
    let app = state.app.clone();
    let res = tokio::task::spawn_blocking(move || {
        let cfg = app.load_config()?;
        app.core.restart(&cfg)
    })
    .await;
    match res {
        Ok(Ok(_)) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn handle_start(State(state): State<Arc<AppState>>) -> Response {
    let app = state.app.clone();
    let res = tokio::task::spawn_blocking(move || {
        let cfg = app.load_config()?;
        app.apply(&cfg)
    })
    .await;
    match res {
        Ok(Ok(_)) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn handle_stop(State(state): State<Arc<AppState>>) -> Response {
    let app = state.app.clone();
    let res = tokio::task::spawn_blocking(move || app.stop()).await;
    match res {
        Ok(Ok(_)) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ── profiles ──

#[derive(serde::Serialize)]
struct ProfileEntry {
    name: String,
    mtime: i64,
    size: i64,
}

async fn handle_list_profiles(State(_state): State<Arc<AppState>>) -> Response {
    let mut out: Vec<ProfileEntry> = vec![];
    let entries = match std::fs::read_dir(paths::PROFILES_DIR) {
        Ok(e) => e,
        Err(_) => return (StatusCode::OK, Json(out)).into_response(),
    };
    for e in entries.flatten() {
        let meta = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        out.push(ProfileEntry {
            name: e.file_name().to_string_lossy().to_string(),
            mtime: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            size: meta.len() as i64,
        });
    }
    (StatusCode::OK, Json(out)).into_response()
}

#[derive(Deserialize)]
struct NameQuery {
    name: Option<String>,
}

async fn handle_upload_profile(
    State(_state): State<Arc<AppState>>,
    Query(q): Query<NameQuery>,
    body: axum::body::Bytes,
) -> Response {
    let name = match q.name {
        Some(n) if !n.is_empty() => n,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "缺少 name 参数"})),
            )
                .into_response()
        }
    };
    // 防路径穿越
    let name = std::path::Path::new(&name)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or(name);
    let dst = format!("{}/{}", paths::PROFILES_DIR, name);
    match std::fs::write(&dst, &body) {
        Ok(_) => (StatusCode::OK, Json(json!({"name": name}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn handle_download_profile(
    State(_state): State<Arc<AppState>>,
    AxumPath(name): AxumPath<String>,
) -> Response {
    let name = sanitize_name(&name);
    let path = format!("{}/{}", paths::PROFILES_DIR, name);
    match std::fs::read(&path) {
        Ok(data) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", name)
                    .parse()
                    .unwrap(),
            );
            headers.insert(
                header::CONTENT_TYPE,
                "application/octet-stream".parse().unwrap(),
            );
            (headers, data).into_response()
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn handle_write_profile(
    State(_state): State<Arc<AppState>>,
    AxumPath(name): AxumPath<String>,
    body: axum::body::Bytes,
) -> Response {
    let name = sanitize_name(&name);
    let path = format!("{}/{}", paths::PROFILES_DIR, name);
    match std::fs::write(&path, &body) {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn handle_delete_profile(
    State(_state): State<Arc<AppState>>,
    AxumPath(name): AxumPath<String>,
) -> Response {
    let name = sanitize_name(&name);
    let path = format!("{}/{}", paths::PROFILES_DIR, name);
    match std::fs::remove_file(&path) {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

fn sanitize_name(name: &str) -> String {
    std::path::Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| name.to_string())
}

// ── logs ──

async fn handle_app_log(State(state): State<Arc<AppState>>) -> Response {
    let data = state.app.log.read_app().unwrap_or_default();
    (StatusCode::OK, Json(String::from_utf8_lossy(&data).to_string())).into_response()
}

async fn handle_core_log(State(state): State<Arc<AppState>>) -> Response {
    let data = state.app.log.read_core().unwrap_or_default();
    (StatusCode::OK, Json(String::from_utf8_lossy(&data).to_string())).into_response()
}

async fn handle_clear_app_log(State(state): State<Arc<AppState>>) -> Response {
    let _ = state.app.log.clear_app_log();
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

async fn handle_clear_core_log(State(state): State<Arc<AppState>>) -> Response {
    let _ = state.app.log.clear_core_log();
    (StatusCode::OK, Json(json!({"ok": true}))).into_response()
}

/// handleLogStream 用 SSE 实时推送 core 日志行。
async fn handle_log_stream(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let log = state.app.log.clone();

    // 先推送当前已有日志尾部
    let initial = log.read_core().unwrap_or_default();
    let initial_str = String::from_utf8_lossy(&initial).to_string();

    let rx = log.subscribe();
    let bstream = BroadcastStream::new(rx).filter_map(|res| res.ok());

    let stream = async_stream::stream! {
        if !initial_str.is_empty() {
            yield Ok(Event::default().data(&initial_str));
        }
        for await line in bstream {
            yield Ok(Event::default().data(line));
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

// 类型别名，避免与 axum::App 概念混淆（实际就是 Arc<crate::app::App>）
type ArcApp = Arc<App>;

/// generateDebug 生成调试信息写入 debug.log。
fn generate_debug(app: ArcApp) {
    use std::io::Write;
    let mut b = String::new();
    b.push_str("# Nexa Debug Info\n\n");
    b.push_str(&format!(
        "## generated\n```\n{}\n```\n\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    b.push_str(&format!("## version\n```\n{}\n```\n\n", app.store.version()));
    if let Ok(cfg) = app.load_config() {
        if let Ok(js) = serde_json::to_string_pretty(&cfg) {
            b.push_str(&format!("## config\n```json\n{}\n```\n\n", js));
        }
    }
    let _ = std::fs::File::create(paths::DEBUG_LOG_PATH)
        .and_then(|mut f| f.write_all(b.as_bytes()));
}
