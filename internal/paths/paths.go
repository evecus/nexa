package paths

// 路径变量。与原 luci-app-proxy 的 include.sh 语义一致，仅改名 nexa。
// 默认值对齐原来的常量；若通过 Init() 指定了自定义数据目录（-d 参数），
// 则 HomeDir 及其派生路径（含日志目录、运行时目录）会一并迁移到该目录下，
// 便于非 root/非 OpenWrt 环境下使用自定义数据目录运行。
var (
	HomeDir     = "/etc/nexa"
	ProfilesDir = HomeDir + "/profiles"
	RunDir      = HomeDir + "/run"
	NftDir      = HomeDir + "/firewall"

	GeoIPCnNft  = NftDir + "/geoip_cn.nft"
	GeoIP6CnNft = NftDir + "/geoip6_cn.nft"

	LogDir       = "/var/log/nexa"
	AppLogPath   = LogDir + "/app.log"
	CoreLogPath  = LogDir + "/core.log"
	DebugLogPath = LogDir + "/debug.log"

	TempDir     = "/var/run/nexa"
	PidFilePath = TempDir + "/nexa.pid"

	DBPath = HomeDir + "/nexa.db"

	// 标志文件
	BridgeNfCallIptablesFlag  = TempDir + "/bridge_nf_call_iptables.flag"
	BridgeNfCallIp6tablesFlag = TempDir + "/bridge_nf_call_ip6tables.flag"
)

// Init 使用自定义数据目录重新计算所有派生路径。
// dir 为空时保持默认值（/etc/nexa 等）不变。
// 必须在 app.New() / logger.New() / store.New() 等任何使用 paths 包的初始化之前调用。
func Init(dir string) {
	if dir == "" {
		return
	}

	HomeDir = dir
	ProfilesDir = HomeDir + "/profiles"
	RunDir = HomeDir + "/run"
	NftDir = HomeDir + "/firewall"

	GeoIPCnNft = NftDir + "/geoip_cn.nft"
	GeoIP6CnNft = NftDir + "/geoip6_cn.nft"

	LogDir = HomeDir + "/log"
	AppLogPath = LogDir + "/app.log"
	CoreLogPath = LogDir + "/core.log"
	DebugLogPath = LogDir + "/debug.log"

	TempDir = HomeDir + "/run_tmp"
	PidFilePath = TempDir + "/nexa.pid"

	DBPath = HomeDir + "/nexa.db"

	BridgeNfCallIptablesFlag = TempDir + "/bridge_nf_call_iptables.flag"
	BridgeNfCallIp6tablesFlag = TempDir + "/bridge_nf_call_ip6tables.flag"
}

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
