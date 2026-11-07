// 内嵌 Web 面板资源（与 Go 版 web/dist 完全一致，含 CodeMirror 与图标）。
// 资源统一放在 assets/ 目录，通过 include_str!/include_bytes! 编译进二进制。

pub const INDEX_HTML: &str = include_str!("../assets/index.html");
pub const STYLE_CSS: &str = include_str!("../assets/style.css");
pub const APP_JS: &str = include_str!("../assets/app.js");
pub const MANIFEST: &str = include_str!("../assets/manifest.webmanifest");
pub const FAVICON_SVG: &str = include_str!("../assets/favicon.svg");

pub const CM_CSS: &str = include_str!("../assets/vendor/codemirror.min.css");
pub const CM_JS: &str = include_str!("../assets/vendor/codemirror.min.js");
pub const CM_YAML_JS: &str = include_str!("../assets/vendor/mode/yaml/yaml.min.js");
pub const CM_JSCRIPT_JS: &str = include_str!("../assets/vendor/mode/javascript/javascript.min.js");

pub const FAVICON_32_PNG: &[u8] = include_bytes!("../assets/favicon-32.png");
pub const APPLE_TOUCH_PNG: &[u8] = include_bytes!("../assets/apple-touch-icon.png");
pub const ICON_192_PNG: &[u8] = include_bytes!("../assets/icon-192.png");
pub const ICON_512_PNG: &[u8] = include_bytes!("../assets/icon-512.png");

/// 编译时内嵌的 geoip 集合文件（首次运行时释放到 <数据目录>/firewall/，已存在则不覆盖）。
pub const GEOIP_CN_NFT: &str = include_str!("../assets/geoip/geoip_cn.nft");
pub const GEOIP6_CN_NFT: &str = include_str!("../assets/geoip/geoip6_cn.nft");
