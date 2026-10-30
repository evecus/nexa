// Package assets 内嵌运行时所需的静态资源（geoip 大陆 IP 集合等）。
// 编译时打包进二进制，运行时若目标目录缺失则释放，避免用户手动准备文件。
package assets

import "embed"

// GeoIPFS 内嵌 firewall 目录下的 nft 集合文件。
//
//go:embed geoip_cn.nft geoip6_cn.nft
var GeoIPFS embed.FS
