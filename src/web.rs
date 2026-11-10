//! Web panel + HTTP API handlers (include split for maintainability)
//! Conceptually still a single panel module: handlers + embedded HTML/CSS/JS.
include!("web_api.inc.rs");
include!("web_ui.inc.rs");
