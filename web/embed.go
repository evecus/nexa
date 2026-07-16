// Package web 通过 go:embed 把前端 dist 嵌入二进制。
package web

import "embed"

//go:embed all:dist
var DistFS embed.FS
