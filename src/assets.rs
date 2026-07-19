//! 内嵌运行时所需的静态资源（geoip 大陆 IP 集合等）。
//! 编译时打包进二进制，运行时若目标目录缺失则释放，避免用户手动准备文件。

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct GeoIpFs;
