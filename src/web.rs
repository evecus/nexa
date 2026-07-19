//! 通过 rust-embed 把前端 dist 嵌入二进制。

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/dist/"]
pub struct DistFs;
