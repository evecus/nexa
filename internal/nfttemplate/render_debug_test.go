package nfttemplate

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/nexa-proxy/nexa/internal/config"
)

var geoipRe = regexp.MustCompile(`(?s)elements\s*=\s*\{([^}]*)\}`)

// chinaElementsForTest 与 netmanager.extractGeoIPElements 的清理逻辑保持一致：
// 逐行 trim、丢弃空行、单行逗号拼接（elements 块内的空行会导致 nft 报
// "syntax error, unexpected newline"）。
func chinaElementsForTest(data string) string {
	m := geoipRe.FindStringSubmatch(data)
	if m == nil {
		return ""
	}
	var entries []string
	for _, line := range strings.Split(m[1], "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		entries = append(entries, line)
	}
	return strings.Join(entries, ", ")
}

// 临时调试用：渲染 bypass 大陆 IP 开启时的完整 nft 规则到 /tmp/rules.nft。
func TestRenderBypassChina(t *testing.T) {
	cfg := config.Default()
	p := &cfg.Proxy
	p.Enabled = true
	p.RouterProxy = true
	p.IPv4Proxy = true
	p.IPv6Proxy = true
	p.TcpMode = "tproxy"
	p.UdpMode = "tproxy"
	p.BypassChinaMainlandIP = true
	p.BypassChinaMainlandIP6 = true

	els, err := os.ReadFile("/workspace/internal/assets/geoip_cn.nft")
	if err != nil {
		t.Fatal(err)
	}
	els6, err := os.ReadFile("/workspace/internal/assets/geoip6_cn.nft")
	if err != nil {
		t.Fatal(err)
	}
	m := Build(cfg, []string{"br-lan"}, 2)
	m.ChinaIPElements = chinaElementsForTest(string(els))
	m.ChinaIP6Elements = chinaElementsForTest(string(els6))
	out, err := Render(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/tmp/rules.nft", []byte(out), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("rendered %d bytes", len(out))
}
