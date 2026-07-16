package paths

// 路径常量。与原 luci-app-proxy 的 include.sh 语义一致，仅改名 nexa。
const (
	HomeDir    = "/etc/nexa"
	ProfilesDir = HomeDir + "/profiles"
	RunDir     = HomeDir + "/run"
	NftDir     = HomeDir + "/firewall"

	GeoIPCnNft  = NftDir + "/geoip_cn.nft"
	GeoIP6CnNft = NftDir + "/geoip6_cn.nft"

	LogDir        = "/var/log/nexa"
	AppLogPath    = LogDir + "/app.log"
	CoreLogPath   = LogDir + "/core.log"
	DebugLogPath  = LogDir + "/debug.log"

	TempDir       = "/var/run/nexa"
	PidFilePath   = TempDir + "/nexa.pid"

	DBPath        = HomeDir + "/nexa.db"

	// 标志文件
	BridgeNfCallIptablesFlag  = TempDir + "/bridge_nf_call_iptables.flag"
	BridgeNfCallIp6tablesFlag = TempDir + "/bridge_nf_call_ip6tables.flag"
)

// Paths 返回给前端的路径信息（对齐原 ubus get_paths）。
type Paths struct {
	HomeDir    string `json:"home_dir"`
	ProfilesDir string `json:"profiles_dir"`
	RunDir     string `json:"run_dir"`
	NftDir     string `json:"nft_dir"`
	GeoIPCnNft string `json:"geoip_cn_nft"`
	GeoIP6CnNft string `json:"geoip6_cn_nft"`
	LogDir     string `json:"log_dir"`
	AppLogPath string `json:"app_log_path"`
	CoreLogPath string `json:"core_log_path"`
	DebugLogPath string `json:"debug_log_path"`
	TempDir    string `json:"temp_dir"`
	PidFilePath string `json:"pid_file_path"`
	BridgeNfCallIptablesFlag string `json:"bridge_nf_call_iptables_flag_path"`
	BridgeNfCallIp6tablesFlag string `json:"bridge_nf_call_ip6tables_flag_path"`
}

func Get() Paths {
	return Paths{
		HomeDir:    HomeDir,
		ProfilesDir: ProfilesDir,
		RunDir:     RunDir,
		NftDir:     NftDir,
		GeoIPCnNft: GeoIPCnNft,
		GeoIP6CnNft: GeoIP6CnNft,
		LogDir:     LogDir,
		AppLogPath: AppLogPath,
		CoreLogPath: CoreLogPath,
		DebugLogPath: DebugLogPath,
		TempDir:    TempDir,
		PidFilePath: PidFilePath,
		BridgeNfCallIptablesFlag: BridgeNfCallIptablesFlag,
		BridgeNfCallIp6tablesFlag: BridgeNfCallIp6tablesFlag,
	}
}
