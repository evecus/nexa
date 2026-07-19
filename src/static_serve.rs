//! 从内嵌的 web/dist 提供静态前端文件，支持 SPA 回退到 index.html。

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::response::Response;

use crate::web::DistFs;

/// 静态文件 handler：根据请求路径返回内嵌文件；未命中则回退到 index.html。
pub async fn serve(req: Request) -> Response {
    let uri_path = req.uri().path().to_string();

    // 规范化路径
    let mut path = uri_path.trim_start_matches('/').to_string();
    if path.is_empty() {
        path = "index.html".to_string();
    }

    // 先精确查找
    if let Some(file) = DistFs::get(&path) {
        return build_response(&path, file.data.as_ref());
    }
    // SPA 回退
    if let Some(file) = DistFs::get("index.html") {
        return build_response("index.html", file.data.as_ref());
    }
    (
        StatusCode::NOT_FOUND,
        "static asset not found",
    )
        .into_response()
}

fn build_response(path: &str, data: &[u8]) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        mime_for(path).parse().unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    (headers, Body::from(data.to_vec())).into_response()
}

fn mime_for(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else {
        "application/octet-stream"
    }
}
