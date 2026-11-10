// Web 面板 + HTTP API 处理器，路由与返回结构对齐 Go 版 internal/api。
// 本文件被 web.rs 通过 include! 内联（不能出现 //! 内层文档注释）。

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, Query, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{sse::Event, IntoResponse, Response, Sse},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;

use crate::config::Config;
use crate::AppState;

pub type ApiResult<T> = Result<T, (StatusCode, Json<serde_json::Value>)>;

fn err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (code, Json(json!({ "error": msg.into() })))
}

// ── 静态资源 ────────────────────────────────────────────

pub async fn serve_index() -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        crate::web::INDEX_HTML,
    )
        .into_response()
}

pub async fn serve_style() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        crate::web::STYLE_CSS,
    )
        .into_response()
}

pub async fn serve_app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        crate::web::APP_JS,
    )
        .into_response()
}

pub async fn serve_favicon() -> Response {
    (
        [(header::CONTENT_TYPE, "image/svg+xml")],
        crate::web::FAVICON_SVG,
    )
        .into_response()
}

pub async fn serve_manifest() -> Response {
    (
        [(header::CONTENT_TYPE, "application/manifest+json")],
        crate::web::MANIFEST,
    )
        .into_response()
}

pub async fn serve_cm_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        crate::web::CM_CSS,
    )
        .into_response()
}

pub async fn serve_cm_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        crate::web::CM_JS,
    )
        .into_response()
}

pub async fn serve_cm_yaml_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        crate::web::CM_YAML_JS,
    )
        .into_response()
}

pub async fn serve_cm_javascript_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        crate::web::CM_JSCRIPT_JS,
    )
        .into_response()
}

macro_rules! png_handler {
    ($fn_name:ident, $const_name:ident) => {
        pub async fn $fn_name() -> Response {
            (
                [(header::CONTENT_TYPE, "image/png")],
                crate::web::$const_name,
            )
                .into_response()
        }
    };
}

png_handler!(serve_favicon_32, FAVICON_32_PNG);
png_handler!(serve_apple_touch, APPLE_TOUCH_PNG);
png_handler!(serve_icon_192, ICON_192_PNG);
png_handler!(serve_icon_512, ICON_512_PNG);

// ── 认证中间件 ──────────────────────────────────────────

pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let path = req.uri().path().to_string();
    // 对齐 Go auth.Middleware：登录与 setup 接口放行。
    if path == "/api/auth/login" || path == "/api/auth/setup" || !path.starts_with("/api/") {
        return Ok(next.run(req).await);
    }
    // 总开关：无验证访问模式下直接放行，不校验 token
    if state.auth.is_auth_disabled() {
        return Ok(next.run(req).await);
    }
    let authz = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if let Some(token) = authz.strip_prefix("Bearer ") {
        if state.auth.verify_token(token).is_ok() {
            return Ok(next.run(req).await);
        }
    }
    // 对齐 Go：401 响应体为 {"error":"unauthorized"}。
    Err(err(StatusCode::UNAUTHORIZED, "unauthorized"))
}

// ── auth ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

pub async fn handle_login(
    State(state): State<AppState>,
    Json(body): Json<LoginReq>,
) -> ApiResult<Json<serde_json::Value>> {
    match state.auth.login(&body.username, &body.password) {
        Ok(token) => Ok(Json(json!({ "token": token }))),
        Err(_) => Err(err(StatusCode::UNAUTHORIZED, "用户名或密码错误")),
    }
}

/// 返回当前登录用户名，供设置页回显真实值。
pub async fn handle_me(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({ "username": state.auth.username() }))
}

#[derive(Deserialize)]
pub struct ChangePassReq {
    username: String,
    password: String,
}

pub async fn handle_change_password(
    State(state): State<AppState>,
    Json(body): Json<ChangePassReq>,
) -> ApiResult<Json<serde_json::Value>> {
    if body.username.is_empty() || body.password.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "用户名和密码不能为空"));
    }
    match state.auth.change_password(&body.username, &body.password) {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(e) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// 返回当前「无验证访问」开关状态。
pub async fn handle_get_auth_disabled(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({ "auth_disabled": state.auth.is_auth_disabled() }))
}

#[derive(Deserialize)]
pub struct AuthDisabledReq {
    auth_disabled: bool,
}

pub async fn handle_set_auth_disabled(
    State(state): State<AppState>,
    Json(body): Json<AuthDisabledReq>,
) -> ApiResult<Json<serde_json::Value>> {
    state
        .auth
        .set_auth_disabled(body.auth_disabled)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "auth_disabled": body.auth_disabled })))
}

// ── 对齐 ubus luci.proxy ────────────────────────────────

pub async fn handle_paths() -> Json<serde_json::Value> {
    Json(crate::paths::get())
}

pub async fn handle_version(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "binary": state.version,
        "app": state.store.version(),
    }))
}

pub async fn handle_identifiers() -> Json<serde_json::Value> {
    Json(serde_json::to_value(crate::identifiers::get()).unwrap_or(json!({})))
}

pub async fn handle_hosts() -> Json<serde_json::Value> {
    Json(serde_json::to_value(crate::hosts::collect()).unwrap_or(json!({})))
}

/// 生成调试信息写入 debug.log（对齐 Go 版 api.generateDebug，异步执行不阻塞响应）。
pub async fn handle_debug(State(state): State<AppState>) -> Json<serde_json::Value> {
    tokio::spawn(async move {
        let mut b = String::new();
        b.push_str("# Nexa Debug Info\n\n");
        b.push_str(&format!("## generated\n```\n{}\n```\n\n", crate::logger::now_string()));
        b.push_str(&format!("## version\n```\n{}\n```\n\n", state.store.version()));
        if let Ok(cfg) = state.store.load() {
            if let Ok(js) = serde_json::to_string_pretty(&cfg) {
                b.push_str(&format!("## config\n```json\n{}\n```\n\n", js));
            }
        }
        let _ = state.log.write_debug(&b);
    });
    Json(json!({ "success": true }))
}

// ── config ──────────────────────────────────────────────

pub async fn handle_get_config(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    match state.store.load() {
        Ok(c) => Ok(Json(serde_json::to_value(c).unwrap_or(json!({})))),
        Err(e) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

pub async fn handle_put_config(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let cfg: Config = serde_json::from_value(body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid config: {}", e)))?;
    state
        .store
        .save(&cfg)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // 对齐 Go handlePutConfig：只保存，不刷新调度器、不写日志。
    Ok(Json(json!({ "ok": true })))
}

/// 保存并应用（对齐 LuCI handleSaveApply：保存 → apply → reload）。
pub async fn handle_apply_config(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let cfg: Config = serde_json::from_value(body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid config: {}", e)))?;
    state
        .store
        .save(&cfg)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    reload_flow(&state, &cfg)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

// ── status & control ────────────────────────────────────

pub async fn handle_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "running": state.core.is_running(),
        "pid": state.core.pid(),
    }))
}

pub async fn handle_reload(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let cfg = state
        .store
        .load()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    reload_flow(&state, &cfg)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn handle_restart(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let cfg = state
        .store
        .load()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    restart_flow(&state, &cfg)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

/// 仅重启代理核心进程，不重建防火墙规则。
pub async fn handle_restart_core(
    State(state): State<AppState>,
) -> ApiResult<Json<serde_json::Value>> {
    let cfg = state
        .store
        .load()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // 对齐 Go handleRestartCore：只重启核心，不重建运行目录 / 防火墙规则。
    state
        .core
        .restart(&cfg)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn handle_start(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let cfg = state
        .store
        .load()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    apply_flow(&state, &cfg)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn handle_stop(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    stop_flow(&state)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

// ── profiles ────────────────────────────────────────────

pub async fn handle_list_profiles(State(state): State<AppState>) -> Json<serde_json::Value> {
    let list = state.store.list_profiles().unwrap_or_default();
    Json(serde_json::to_value(list).unwrap_or(json!([])))
}

#[derive(Deserialize)]
pub struct UploadQuery {
    name: Option<String>,
}

/// 上传配置文件：?name=<文件名>，Body 为原始文件内容。
pub async fn handle_upload_profile(
    State(state): State<AppState>,
    Query(q): Query<UploadQuery>,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let name = q.name.unwrap_or_default();
    if name.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "缺少 name 参数"));
    }
    // 对齐 Go：filepath.Base 防路径穿越，返回值也用 basename。
    let name = state
        .store
        .profile_base_name(&name)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .store
        .write_profile(&name, &body)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.log.app("配置文件", &format!("已上传：{}", name));
    Ok(Json(json!({ "name": name })))
}

/// 下载配置文件（原始字节 + Content-Disposition，对齐 Go os.ReadFile）。
pub async fn handle_download_profile(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
) -> ApiResult<Response> {
    let name = state
        .store
        .profile_base_name(&name)
        .map_err(|e| err(StatusCode::NOT_FOUND, e.to_string()))?;
    match state.store.read_profile(&name) {
        Ok(content) => Ok((
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", name),
                ),
            ],
            content,
        )
            .into_response()),
        Err(_) => Err(err(StatusCode::NOT_FOUND, "配置文件不存在")),
    }
}

pub async fn handle_write_profile(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let name = state
        .store
        .profile_base_name(&name)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .store
        .write_profile(&name, &body)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn handle_delete_profile(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let name = state
        .store
        .profile_base_name(&name)
        .map_err(|e| err(StatusCode::NOT_FOUND, e.to_string()))?;
    match state.store.delete_profile(&name) {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(e) => Err(err(StatusCode::NOT_FOUND, e.to_string())),
    }
}

#[derive(Deserialize)]
pub struct RenameReq {
    name: String,
}

/// 重命名配置文件（同名冲突返回 409）。
pub async fn handle_rename_profile(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
    Json(body): Json<RenameReq>,
) -> ApiResult<Json<serde_json::Value>> {
    let old = state
        .store
        .profile_base_name(&name)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    // 对齐 Go：newName = filepath.Base(strings.TrimSpace(body.Name))
    let new_name = state
        .store
        .profile_base_name(body.name.trim())
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    if new_name == old {
        return Ok(Json(json!({ "name": new_name })));
    }
    match state.store.rename_profile(&old, &new_name) {
        Ok(()) => Ok(Json(json!({ "name": new_name }))),
        Err(e) => {
            // 同名文件已存在
            if e.to_string().contains("同名文件已存在") {
                Err(err(StatusCode::CONFLICT, e.to_string()))
            } else {
                Err(err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
            }
        }
    }
}

// ── logs ────────────────────────────────────────────────

pub async fn handle_app_log(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!(state.log.read_app()))
}

pub async fn handle_core_log(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!(state.log.read_core()))
}

pub async fn handle_clear_app_log(State(state): State<AppState>) -> Json<serde_json::Value> {
    let _ = state.log.clear_app();
    Json(json!({ "ok": true }))
}

pub async fn handle_clear_core_log(State(state): State<AppState>) -> Json<serde_json::Value> {
    let _ = state.log.clear_core();
    Json(json!({ "ok": true }))
}

/// SSE 实时推送 core 日志（对齐 Go 版 handleLogStream）。
pub async fn handle_log_stream(State(state): State<AppState>) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let initial = state.log.read_core();
    let rx = state.log.subscribe();
    use tokio_stream::{wrappers::BroadcastStream, StreamExt};
    let head = tokio_stream::iter(vec![Ok(Event::default().data(initial))]);
    let tail = BroadcastStream::new(rx).map(|res| {
        Ok(Event::default().data(res.unwrap_or_default()))
    });
    Sse::new(head.chain(tail))
}

// ── 应用流程（对齐 Go 版 app.Apply / Reload / Restart / Stop） ──

/// 按配置应用运行目录（settings.run_dir，空 = 默认 <数据目录>/run）。
fn apply_run_dir(cfg: &Config) -> anyhow::Result<()> {
    crate::paths::set_run_dir(&cfg.config.run_dir)?;
    std::fs::create_dir_all(crate::paths::run_dir())?;
    Ok(())
}

/// 对齐 App.Apply：启动核心 → 应用网络规则。
async fn apply_flow(state: &AppState, cfg: &Config) -> anyhow::Result<()> {
    if !cfg.config.enabled {
        state.log.app("App", "已禁用，停止服务。");
        return stop_flow(state).await;
    }
    state.log.app("App", "已启用，启动中。");
    // 先清理旧的网络规则（对齐 reload_service 的 cleanup）
    state.net.cleanup(cfg);
    apply_run_dir(cfg)?;
    state.core.start(cfg)?;
    if cfg.proxy.enabled {
        state.net.apply(cfg)?;
    } else {
        state.log.app("代理", "已禁用，跳过防火墙设置。");
    }
    Ok(())
}

/// 对齐 App.Reload：cleanup + start（含调度器刷新）。
async fn reload_flow(state: &AppState, cfg: &Config) -> anyhow::Result<()> {
    state.sched.reload(cfg);
    if !cfg.config.enabled {
        return stop_flow(state).await;
    }
    state.net.cleanup(cfg);
    apply_run_dir(cfg)?;
    state.core.restart(cfg).await?;
    if cfg.proxy.enabled {
        state.net.apply(cfg)?;
    }
    Ok(())
}

/// 对齐 App.Restart：重启核心并重应用网络。
async fn restart_flow(state: &AppState, cfg: &Config) -> anyhow::Result<()> {
    state.net.cleanup(cfg);
    apply_run_dir(cfg)?;
    state.core.restart(cfg).await?;
    if cfg.proxy.enabled {
        state.net.apply(cfg)?;
    }
    Ok(())
}

/// 停止核心 + 清理网络规则。
async fn stop_flow(state: &AppState) -> anyhow::Result<()> {
    let cfg = state.store.load().unwrap_or_default();
    state.core.stop()?;
    state.net.cleanup(&cfg);
    Ok(())
}
