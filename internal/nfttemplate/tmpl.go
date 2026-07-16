package nfttemplate

// tmplText 是 nftables 劫持表模板，规则文本 1:1 对齐原 hijack.ut。
// 使用 raw string 字面量保存，避免与 Go 语法冲突。
var tmplText = "{{- /* nft 模板，规则文本 1:1 对齐原 hijack.ut。 */ -}}\n" +
	"table inet nexa {\n" +
	"\tset dns_hijack_nfproto {\n" +
	"\t\ttype nf_proto\n" +
	"\t\tflags interval\n" +
	"\t\t{{ if lenGt0 .DnsHijackNFProto }}elements = {\n" +
	"\t\t\t{{ join \", \" .DnsHijackNFProto }}\n" +
	"\t\t}\n" +
	"\t\t{{ end -}}\n" +
	"\t}\n" +
	"\n" +
	"\tset proxy_nfproto {\n" +
	"\t\ttype nf_proto\n" +
	"\t\tflags interval\n" +
	"\t\t{{ if lenGt0 .ProxyNFProto }}elements = {\n" +
	"\t\t\t{{ join \", \" .ProxyNFProto }}\n" +
	"\t\t}\n" +
	"\t\t{{ end -}}\n" +
	"\t}\n" +
	"\n" +
	"\tset reserved_ip {\n" +
	"\t\ttype ipv4_addr\n" +
	"\t\tflags interval\n" +
	"\t\tauto-merge\n" +
	"\t\t{{ if lenGt0 .ReservedIP }}elements = {\n" +
	"\t\t\t{{ join \", \" .ReservedIP }}\n" +
	"\t\t}\n" +
	"\t\t{{ end -}}\n" +
	"\t}\n" +
	"\n" +
	"\tset reserved_ip6 {\n" +
	"\t\ttype ipv6_addr\n" +
	"\t\tflags interval\n" +
	"\t\tauto-merge\n" +
	"\t\t{{ if lenGt0 .ReservedIP6 }}elements = {\n" +
	"\t\t\t{{ join \", \" .ReservedIP6 }}\n" +
	"\t\t}\n" +
	"\t\t{{ end -}}\n" +
	"\t}\n" +
	"\n" +
	"\tset lan_inbound_device {\n" +
	"\t\ttype ifname\n" +
	"\t\tflags interval\n" +
	"\t\tauto-merge\n" +
	"\t\t{{ if lenGt0 .LanInboundDevice }}elements = {\n" +
	"\t\t\t{{ qjoin .LanInboundDevice }}\n" +
	"\t\t}\n" +
	"\t\t{{ end -}}\n" +
	"\t}\n" +
	"\n" +
	"\tset china_ip {\n" +
	"\t\ttype ipv4_addr\n" +
	"\t\tflags interval\n" +
	"\t\t{{ if .ChinaIPElements }}elements = {\n" +
	"\t\t\t{{ .ChinaIPElements }}\n" +
	"\t\t}\n" +
	"\t\t{{ end -}}\n" +
	"\t}\n" +
	"\n" +
	"\tset china_ip6 {\n" +
	"\t\ttype ipv6_addr\n" +
	"\t\tflags interval\n" +
	"\t\t{{ if .ChinaIP6Elements }}elements = {\n" +
	"\t\t\t{{ .ChinaIP6Elements }}\n" +
	"\t\t}\n" +
	"\t\t{{ end -}}\n" +
	"\t}\n" +
	"\n" +
	"\tset proxy_dport {\n" +
	"\t\ttype inet_proto . inet_service\n" +
	"\t\tflags interval\n" +
	"\t\tauto-merge\n" +
	"\t\t{{ if lenGt0 .ProxyDport }}elements = {\n" +
	"\t\t\t{{ join \", \" .ProxyDport }}\n" +
	"\t\t}\n" +
	"\t\t{{ end -}}\n" +
	"\t}\n" +
	"\n" +
	"\tset bypass_dscp {\n" +
	"\t\ttype dscp\n" +
	"\t\tflags interval\n" +
	"\t\tauto-merge\n" +
	"\t\t{{ if lenGt0 .BypassDscp }}elements = {\n" +
	"\t\t\t{{ join \", \" .BypassDscp }}\n" +
	"\t\t}\n" +
	"\t\t{{ end -}}\n" +
	"\t}\n" +
	"\n" +
	"\t{{ if .RouterProxy }}\n" +
	"\tchain router_dns_hijack {\n" +
	"\t\t{{ range .RouterAccessControls }}\n" +
	"\t\t{{ if lenEq0 .User }}{{ if lenEq0 .Group }}{{ if lenEq0 .Cgroup -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter {{ if .Dns }} redirect to :{{ $.DnsPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ else }}\n" +
	"\t\t{{ if lenGt0 .User -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } meta skuid { {{ join \", \" .User }} } th dport 53 counter {{ if .Dns }} redirect to :{{ $.DnsPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if lenGt0 .Group -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } meta skgid { {{ join \", \" .Group }} } th dport 53 counter {{ if .Dns }} redirect to :{{ $.DnsPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if eq $.CgroupsVersion 2 }}{{ if lenGt0 .Cgroup }}{{ range .Cgroup -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } socket cgroupv2 level {{ clen . }} {{ printf \"%q\" . }} th dport 53 counter {{ if .Dns }} redirect to :{{ $.DnsPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\n" +
	"\t{{ if eq .TcpMode \"redirect\" }}\n" +
	"\tchain router_redirect {\n" +
	"\t\t{{ range .RouterAccessControls }}\n" +
	"\t\t{{ if lenEq0 .User }}{{ if lenEq0 .Group }}{{ if lenEq0 .Cgroup -}}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto tcp counter {{ if .Proxy }} redirect to :{{ $.RedirPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ else }}\n" +
	"\t\t{{ if lenGt0 .User -}}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto tcp meta skuid { {{ join \", \" .User }} } counter {{ if .Proxy }} redirect to :{{ $.RedirPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if lenGt0 .Group -}}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto tcp meta skgid { {{ join \", \" .Group }} } counter {{ if .Proxy }} redirect to :{{ $.RedirPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if eq $.CgroupsVersion 2 }}{{ if lenGt0 .Cgroup }}{{ range .Cgroup -}}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto tcp socket cgroupv2 level {{ clen . }} {{ printf \"%q\" . }} counter {{ if .Proxy }} redirect to :{{ $.RedirPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\t{{ end }}\n" +
	"\n" +
	"\t{{ if or (eq .TcpMode \"tproxy\") (eq .UdpMode \"tproxy\") }}\n" +
	"\tchain router_tproxy {\n" +
	"\t\t{{ range .RouterAccessControls }}\n" +
	"\t\t{{ if lenEq0 .User }}{{ if lenEq0 .Group }}{{ if lenEq0 .Cgroup -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } {{ if .Proxy }} meta mark set meta mark & {{ $.TproxyFwUmask }} | {{ $.TproxyFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ else }}\n" +
	"\t\t{{ if lenGt0 .User -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } meta skuid { {{ join \", \" .User }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } meta skuid { {{ join \", \" .User }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TproxyFwUmask }} | {{ $.TproxyFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if lenGt0 .Group -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } meta skgid { {{ join \", \" .Group }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } meta skgid { {{ join \", \" .Group }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TproxyFwUmask }} | {{ $.TproxyFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if eq $.CgroupsVersion 2 }}{{ if lenGt0 .Cgroup }}{{ range .Cgroup -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } socket cgroupv2 level {{ clen . }} {{ printf \"%q\" . }} th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } socket cgroupv2 level {{ clen . }} {{ printf \"%q\" . }} {{ if .Proxy }} meta mark set meta mark & {{ $.TproxyFwUmask }} | {{ $.TproxyFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\t{{ end }}\n" +
	"\n" +
	"\t{{ if or (eq .TcpMode \"tun\") (eq .UdpMode \"tun\") }}\n" +
	"\tchain router_tun {\n" +
	"\t\t{{ range .RouterAccessControls }}\n" +
	"\t\t{{ if lenEq0 .User }}{{ if lenEq0 .Group }}{{ if lenEq0 .Cgroup -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } {{ if .Proxy }} meta mark set meta mark & {{ $.TunFwUmask }} | {{ $.TunFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ else }}\n" +
	"\t\t{{ if lenGt0 .User -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } meta skuid { {{ join \", \" .User }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } meta skuid { {{ join \", \" .User }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TunFwUmask }} | {{ $.TunFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if lenGt0 .Group -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } meta skgid { {{ join \", \" .Group }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } meta skgid { {{ join \", \" .Group }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TunFwUmask }} | {{ $.TunFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if eq $.CgroupsVersion 2 }}{{ if lenGt0 .Cgroup }}{{ range .Cgroup -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } socket cgroupv2 level {{ clen . }} {{ printf \"%q\" . }} th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } socket cgroupv2 level {{ clen . }} {{ printf \"%q\" . }} {{ if .Proxy }} meta mark set meta mark & {{ $.TunFwUmask }} | {{ $.TunFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\t{{ end }}\n" +
	"\t{{ end }}\n" +
	"\n" +
	"\t{{ if .LanProxy }}\n" +
	"\tchain lan_dns_hijack {\n" +
	"\t\t{{ range .LanAccessControls }}\n" +
	"\t\t{{ if lenEq0 .IP }}{{ if lenEq0 .IP6 }}{{ if lenEq0 .Mac -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter {{ if .Dns }} redirect to :{{ $.DnsPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ else }}\n" +
	"\t\t{{ if lenGt0 .IP }}{{ if $.DnsHijackNFProtoHas4 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip saddr { {{ join \", \" .IP }} } th dport 53 counter {{ if .Dns }} redirect to :{{ $.DnsPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if lenGt0 .IP6 }}{{ if $.DnsHijackNFProtoHas6 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip6 saddr { {{ join \", \" .IP6 }} } th dport 53 counter {{ if .Dns }} redirect to :{{ $.DnsPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if lenGt0 .Mac -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } ether saddr { {{ join \", \" .Mac }} } th dport 53 counter {{ if .Dns }} redirect to :{{ $.DnsPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\n" +
	"\t{{ if eq .TcpMode \"redirect\" }}\n" +
	"\tchain lan_redirect {\n" +
	"\t\t{{ range .LanAccessControls }}\n" +
	"\t\t{{ if lenEq0 .IP }}{{ if lenEq0 .IP6 }}{{ if lenEq0 .Mac -}}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto tcp counter {{ if .Proxy }} redirect to :{{ $.RedirPort }} {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ else }}\n" +
	"\t\t{{ if lenGt0 .IP }}{{ if $.ProxyNFProtoHas4 -}}\n" +
	"\t\tmeta l4proto tcp ip saddr { {{ join \", \" .IP }} } counter {{ if .Proxy }} redirect to :{{ $.RedirPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if lenGt0 .IP6 }}{{ if $.ProxyNFProtoHas6 -}}\n" +
	"\t\tmeta l4proto tcp ip6 saddr { {{ join \", \" .IP6 }} } counter {{ if .Proxy }} redirect to :{{ $.RedirPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if lenGt0 .Mac -}}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto tcp ether saddr { {{ join \", \" .Mac }} } counter {{ if .Proxy }} redirect to :{{ $.RedirPort }} {{ else }} return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\t{{ end }}\n" +
	"\n" +
	"\t{{ if or (eq .TcpMode \"tproxy\") (eq .UdpMode \"tproxy\") }}\n" +
	"\tchain lan_tproxy {\n" +
	"\t\t{{ range .LanAccessControls }}\n" +
	"\t\t{{ if lenEq0 .IP }}{{ if lenEq0 .IP6 }}{{ if lenEq0 .Mac -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } {{ if .Proxy }} meta mark set meta mark & {{ $.TproxyFwUmask }} | {{ $.TproxyFwMark }} tproxy to :{{ $.TproxyPort }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ else }}\n" +
	"\t\t{{ if lenGt0 .IP -}}\n" +
	"\t\t{{ if .Dns }}{{ if $.DnsHijackNFProtoHas4 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip saddr { {{ join \", \" .IP }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if $.ProxyNFProtoHas4 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip saddr { {{ join \", \" .IP }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TproxyFwUmask }} | {{ $.TproxyFwMark }} tproxy ip to :{{ $.TproxyPort }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if lenGt0 .IP6 -}}\n" +
	"\t\t{{ if .Dns }}{{ if $.DnsHijackNFProtoHas6 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip6 saddr { {{ join \", \" .IP6 }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if $.ProxyNFProtoHas6 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip6 saddr { {{ join \", \" .IP6 }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TproxyFwUmask }} | {{ $.TproxyFwMark }} tproxy ip6 to :{{ $.TproxyPort }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if lenGt0 .Mac -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } ether saddr { {{ join \", \" .Mac }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } ether saddr { {{ join \", \" .Mac }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TproxyFwUmask }} | {{ $.TproxyFwMark }} tproxy to :{{ $.TproxyPort }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\t{{ end }}\n" +
	"\n" +
	"\t{{ if or (eq .TcpMode \"tun\") (eq .UdpMode \"tun\") }}\n" +
	"\tchain lan_tun {\n" +
	"\t\t{{ range .LanAccessControls }}\n" +
	"\t\t{{ if lenEq0 .IP }}{{ if lenEq0 .IP6 }}{{ if lenEq0 .Mac -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } {{ if .Proxy }} meta mark set meta mark & {{ $.TunFwUmask }} | {{ $.TunFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ else }}\n" +
	"\t\t{{ if lenGt0 .IP -}}\n" +
	"\t\t{{ if .Dns }}{{ if $.DnsHijackNFProtoHas4 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip saddr { {{ join \", \" .IP }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if $.ProxyNFProtoHas4 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip saddr { {{ join \", \" .IP }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TunFwUmask }} | {{ $.TunFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if lenGt0 .IP6 -}}\n" +
	"\t\t{{ if .Dns }}{{ if $.DnsHijackNFProtoHas6 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip6 saddr { {{ join \", \" .IP6 }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if $.ProxyNFProtoHas6 -}}\n" +
	"\t\tmeta l4proto { tcp, udp } ip6 saddr { {{ join \", \" .IP6 }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TunFwUmask }} | {{ $.TunFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if lenGt0 .Mac -}}\n" +
	"\t\t{{ if .Dns -}}\n" +
	"\t\tmeta nfproto @dns_hijack_nfproto meta l4proto { tcp, udp } ether saddr { {{ join \", \" .Mac }} } th dport 53 counter return #\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta nfproto @proxy_nfproto meta l4proto { tcp, udp } ether saddr { {{ join \", \" .Mac }} } {{ if .Proxy }} meta mark set meta mark & {{ $.TunFwUmask }} | {{ $.TunFwMark }} counter accept {{ else }} counter return {{ end }} #\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}{{ end }}{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\t{{ end }}\n" +
	"\t{{ end }}\n" +
	"\n" +
	"\t{{ if .RouterProxy }}\n" +
	"\tchain nat_output {\n" +
	"\t\ttype nat hook output priority filter; policy accept;\n" +
	"\t\t{{ if .BypassCgroup }}{{ if eq .CgroupsVersion 1 -}}\n" +
	"\t\tmeta cgroup {{ .CgroupID }} counter return\n" +
	"\t\t{{ else if eq .CgroupsVersion 2 -}}\n" +
	"\t\tsocket cgroupv2 level 2 \"services/{{ .CgroupName }}\" counter return\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if and .BypassGid (ne .CoreGID \"\") -}}\n" +
	"\t\tmeta skgid {{ .CoreGID }} counter return\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if and .BypassMark (lenGt0 .BypassMarkValues) }}{{ range .BypassMarkValues -}}\n" +
	"\t\tmeta mark {{ . }} counter return\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\tjump router_dns_hijack\n" +
	"\t\t{{ if eq .TcpMode \"redirect\" -}}\n" +
	"\t\tfib daddr type { local, broadcast, anycast, multicast } counter return\n" +
	"\t\tct direction reply counter return\n" +
	"\t\tip daddr @reserved_ip {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tip6 daddr @reserved_ip6 {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\tip daddr @china_ip counter return\n" +
	"\t\tip6 daddr @china_ip6 counter return\n" +
	"\t\tmeta nfproto ipv4 meta l4proto . th dport != @proxy_dport {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tmeta nfproto ipv6 meta l4proto . th dport != @proxy_dport {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\tmeta l4proto { tcp, udp } ip dscp @bypass_dscp {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tmeta l4proto { tcp, udp } ip6 dscp @bypass_dscp {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\t{{ range .BypassFwmark -}}\n" +
	"\t\tmeta mark & {{ .Mask }} == {{ .Mark }} counter return\n" +
	"\t\t{{ end }}\n" +
	"\t\tjump router_redirect\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if .FakeIPPingHijack -}}\n" +
	"\t\t{{ if .FakeIPRange -}}\n" +
	"\t\ticmp type echo-request ip daddr {{ .FakeIPRange }} counter redirect\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if .FakeIP6Range -}}\n" +
	"\t\ticmpv6 type echo-request ip6 daddr {{ .FakeIP6Range }} counter redirect\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\n" +
	"\tchain mangle_output {\n" +
	"\t\ttype route hook output priority mangle; policy accept;\n" +
	"\t\t{{ if .BypassCgroup }}{{ if eq .CgroupsVersion 1 -}}\n" +
	"\t\tmeta cgroup {{ .CgroupID }} counter return\n" +
	"\t\t{{ else if eq .CgroupsVersion 2 -}}\n" +
	"\t\tsocket cgroupv2 level 2 \"services/{{ .CgroupName }}\" counter return\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\t{{ if and .BypassGid (ne .CoreGID \"\") -}}\n" +
	"\t\tmeta skgid {{ .CoreGID }} counter return\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if and .BypassMark (lenGt0 .BypassMarkValues) }}{{ range .BypassMarkValues -}}\n" +
	"\t\tmeta mark {{ . }} counter return\n" +
	"\t\t{{ end }}{{ end }}\n" +
	"\t\tfib daddr type { local, broadcast, anycast, multicast } counter return\n" +
	"\t\tct direction reply counter return\n" +
	"\t\tip daddr @reserved_ip {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tip6 daddr @reserved_ip6 {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\tip daddr @china_ip counter return\n" +
	"\t\tip6 daddr @china_ip6 counter return\n" +
	"\t\tmeta nfproto ipv4 meta l4proto . th dport != @proxy_dport {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tmeta nfproto ipv6 meta l4proto . th dport != @proxy_dport {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\tmeta l4proto { tcp, udp } ip dscp @bypass_dscp {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tmeta l4proto { tcp, udp } ip6 dscp @bypass_dscp {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\t{{ range .BypassFwmark -}}\n" +
	"\t\tmeta mark & {{ .Mask }} == {{ .Mark }} counter return\n" +
	"\t\t{{ end }}\n" +
	"\t\tmeta l4proto vmap { tcp: {{ if eq .TcpMode \"tproxy\" }} jump router_tproxy {{ else if eq .TcpMode \"tun\" }} jump router_tun {{ else }} continue {{ end }}, udp: {{ if eq .UdpMode \"tproxy\" }} jump router_tproxy {{ else if eq .UdpMode \"tun\" }} jump router_tun {{ else }} continue {{ end }} }\n" +
	"\t}\n" +
	"\n" +
	"\tchain mangle_prerouting_router {\n" +
	"\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n" +
	"\t\t{{ if or (eq .TcpMode \"tproxy\") (eq .UdpMode \"tproxy\") -}}\n" +
	"\t\tiifname lo meta l4proto { tcp, udp } meta mark & {{ .TproxyFwMask }} == {{ .TproxyFwMark }} tproxy to :{{ .TproxyPort }} counter accept\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if or (eq .TcpMode \"tun\") (eq .UdpMode \"tun\") -}}\n" +
	"\t\tiifname {{ printf \"%q\" .TunDevice }} meta l4proto { icmp, tcp, udp } counter accept\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\t{{ end }}\n" +
	"\n" +
	"\t{{ if .LanProxy }}\n" +
	"\tchain dstnat {\n" +
	"\t\ttype nat hook prerouting priority dstnat + 1; policy accept;\n" +
	"\t\tiifname @lan_inbound_device jump lan_dns_hijack\n" +
	"\t\t{{ if eq .TcpMode \"redirect\" -}}\n" +
	"\t\tfib daddr type { local, broadcast, anycast, multicast } counter return\n" +
	"\t\tct direction reply counter return\n" +
	"\t\tip daddr @reserved_ip {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tip6 daddr @reserved_ip6 {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\tip daddr @china_ip counter return\n" +
	"\t\tip6 daddr @china_ip6 counter return\n" +
	"\t\tmeta nfproto ipv4 meta l4proto . th dport != @proxy_dport {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tmeta nfproto ipv6 meta l4proto . th dport != @proxy_dport {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\tmeta l4proto { tcp, udp } ip dscp @bypass_dscp {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tmeta l4proto { tcp, udp } ip6 dscp @bypass_dscp {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\t{{ range .BypassFwmark -}}\n" +
	"\t\tmeta mark & {{ .Mask }} == {{ .Mark }} counter return\n" +
	"\t\t{{ end }}\n" +
	"\t\tiifname @lan_inbound_device jump lan_redirect\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if .FakeIPPingHijack -}}\n" +
	"\t\t{{ if .FakeIPRange -}}\n" +
	"\t\ticmp type echo-request ip daddr {{ .FakeIPRange }} counter redirect\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ if .FakeIP6Range -}}\n" +
	"\t\ticmpv6 type echo-request ip6 daddr {{ .FakeIP6Range }} counter redirect\n" +
	"\t\t{{ end }}\n" +
	"\t\t{{ end }}\n" +
	"\t}\n" +
	"\n" +
	"\tchain mangle_prerouting_lan {\n" +
	"\t\ttype filter hook prerouting priority mangle; policy accept;\n" +
	"\t\tfib daddr type { local, broadcast, anycast, multicast } counter return\n" +
	"\t\tct direction reply counter return\n" +
	"\t\tip daddr @reserved_ip {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tip6 daddr @reserved_ip6 {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\tip daddr @china_ip counter return\n" +
	"\t\tip6 daddr @china_ip6 counter return\n" +
	"\t\tmeta nfproto ipv4 meta l4proto . th dport != @proxy_dport {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tmeta nfproto ipv6 meta l4proto . th dport != @proxy_dport {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\tmeta l4proto { tcp, udp } ip dscp @bypass_dscp {{ if .FakeIPRange }} ip daddr != {{ .FakeIPRange }} {{ end }} counter return\n" +
	"\t\tmeta l4proto { tcp, udp } ip6 dscp @bypass_dscp {{ if .FakeIP6Range }} ip6 daddr != {{ .FakeIP6Range }} {{ end }} counter return\n" +
	"\t\t{{ range .BypassFwmark -}}\n" +
	"\t\tmeta mark & {{ .Mask }} == {{ .Mark }} counter return\n" +
	"\t\t{{ end }}\n" +
	"\t\tiifname @lan_inbound_device meta l4proto vmap { tcp: {{ if eq .TcpMode \"tproxy\" }} jump lan_tproxy {{ else if eq .TcpMode \"tun\" }} jump lan_tun {{ else }} continue {{ end }}, udp: {{ if eq .UdpMode \"tproxy\" }} jump lan_tproxy {{ else if eq .UdpMode \"tun\" }} jump lan_tun {{ else }} continue {{ end }} }\n" +
	"\t}\n" +
	"\t{{ end }}\n" +
	"}\n" +
	"\n" +
	"{{ if .BypassChinaMainlandIP -}}\n" +
	"include \"/etc/nexa/firewall/geoip_cn.nft\"\n" +
	"{{ end }}\n" +
	"{{ if .BypassChinaMainlandIP6 -}}\n" +
	"include \"/etc/nexa/firewall/geoip6_cn.nft\"\n" +
	"{{ end }}\n"
