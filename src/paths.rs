//! 路径常量。与原 luci-app-proxy 的 include.sh 语义一致，仅改名 nexa。

use serde::Serialize;

pub const HOME_DIR: &str = "/etc/nexa";
pub const PROFILES_DIR: &str = "/etc/nexa/profiles";
pub const RUN_DIR: &str = "/etc/nexa/run";
pub const NFT_DIR: &str = "/etc/nexa/firewall";

pub const GEOIP_CN_NFT: &str = "/etc/nexa/firewall/geoip_cn.nft";
pub const GEOIP6_CN_NFT: &str = "/etc/nexa/firewall/geoip6_cn.nft";

pub const LOG_DIR: &str = "/var/log/nexa";
pub const APP_LOG_PATH: &str = "/var/log/nexa/app.log";
pub const CORE_LOG_PATH: &str = "/var/log/nexa/core.log";
pub const DEBUG_LOG_PATH: &str = "/var/log/nexa/debug.log";

pub const TEMP_DIR: &str = "/var/run/nexa";
pub const PID_FILE_PATH: &str = "/var/run/nexa/nexa.pid";

pub const DB_PATH: &str = "/etc/nexa/nexa.db";

// 标志文件
pub const BRIDGE_NF_CALL_IPTABLES_FLAG: &str = "/var/run/nexa/bridge_nf_call_iptables.flag";
pub const BRIDGE_NF_CALL_IP6TABLES_FLAG: &str = "/var/run/nexa/bridge_nf_call_ip6tables.flag";

/// Paths 返回给前端的路径信息（对齐原 ubus get_paths）。
#[derive(Debug, Serialize)]
pub struct Paths {
    pub home_dir: &'static str,
    pub profiles_dir: &'static str,
    pub run_dir: &'static str,
    pub nft_dir: &'static str,
    pub geoip_cn_nft: &'static str,
    pub geoip6_cn_nft: &'static str,
    pub log_dir: &'static str,
    pub app_log_path: &'static str,
    pub core_log_path: &'static str,
    pub debug_log_path: &'static str,
    pub temp_dir: &'static str,
    pub pid_file_path: &'static str,
    pub bridge_nf_call_iptables_flag_path: &'static str,
    pub bridge_nf_call_ip6tables_flag_path: &'static str,
}

pub fn get() -> Paths {
    Paths {
        home_dir: HOME_DIR,
        profiles_dir: PROFILES_DIR,
        run_dir: RUN_DIR,
        nft_dir: NFT_DIR,
        geoip_cn_nft: GEOIP_CN_NFT,
        geoip6_cn_nft: GEOIP6_CN_NFT,
        log_dir: LOG_DIR,
        app_log_path: APP_LOG_PATH,
        core_log_path: CORE_LOG_PATH,
        debug_log_path: DEBUG_LOG_PATH,
        temp_dir: TEMP_DIR,
        pid_file_path: PID_FILE_PATH,
        bridge_nf_call_iptables_flag_path: BRIDGE_NF_CALL_IPTABLES_FLAG,
        bridge_nf_call_ip6tables_flag_path: BRIDGE_NF_CALL_IP6TABLES_FLAG,
    }
}
