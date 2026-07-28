// nexa 主程序：独立守护进程，./nexa 即可运行，默认监听 :9990。
// 提供 HTTP API + 内嵌 Web 面板。不依赖 luci/rpcd/ubus/UCI。
//
// 子命令：
//
//	./nexa on   使用磁盘中的数据配置完整的防火墙规则和策略路由，但不启动代理核心，执行后进程退出。
//	./nexa off  清理防火墙规则和策略路由，但不杀死代理核心进程，执行后进程退出。
//
// on/off 与是否指定 -p/-addr 端口参数无关，二者都只做网络规则配置/清理，不涉及 HTTP 服务。
package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nexa-proxy/nexa/internal/api"
	"github.com/nexa-proxy/nexa/internal/app"
	"github.com/nexa-proxy/nexa/internal/auth"
	"github.com/nexa-proxy/nexa/internal/paths"
	"github.com/nexa-proxy/nexa/web"
)

// version 由 ldflags -X main.version=... 注入，默认 dev。
var version = "dev"

func main() {
	addr := flag.String("addr", ":9990", "HTTP 监听地址（与 -p 同时指定时以 -p 为准）")
	dataDir := flag.String("d", "", "数据目录（默认 /etc/nexa，不指定则使用默认值）")
	port := flag.Int("p", 0, "Web 监听端口（默认 9990，不指定则使用默认值）")
	flag.Parse()

	// -d 指定数据目录，替换默认的 /etc/nexa 及其派生路径（日志、运行时目录等）。
	// 必须在 app.New() 之前调用，因为 app/store/logger 等模块都依赖 paths 包中的路径变量。
	paths.Init(*dataDir)

	// 子命令 on/off：只做网络规则配置/清理，不启动 HTTP 服务，不涉及核心进程的启动/杀死。
	// 无论是否指定了端口参数（-p/-addr），on/off 都只处理防火墙规则和策略路由。
	if args := flag.Args(); len(args) > 0 {
		switch args[0] {
		case "on":
			runOn()
			return
		case "off":
			runOff()
			return
		}
	}

	// -p 指定端口，优先于 -addr；不指定则使用默认端口 9990。
	listenAddr := *addr
	if *port > 0 {
		listenAddr = ":" + strconv.Itoa(*port)
	}

	a, err := app.New()
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}
	a.PrepareFiles()
	a.WritePid(os.Getpid())

	au := auth.New()
	api.Version = version
	router := api.New(a, au)

	mux := http.NewServeMux()
	mux.Handle("/api/", router.Routes())
	mux.Handle("/api/auth/", router.Routes())

	// 静态前端
	dist, _ := fs.Sub(web.DistFS, "dist")
	mux.Handle("/", http.FileServer(http.FS(dist)))

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 启动时拉起核心（对齐 init.d boot）
	go func() {
		if err := a.Boot(); err != nil {
			a.Log.App("App", "启动失败："+err.Error())
		}
	}()

	log.Printf("nexa listen 0.0.0.0%s，数据目录: %s", listenAddr, paths.HomeDir)

	// 信号处理：优雅关闭，清理网络规则并杀掉核心进程
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	cleanupDone := make(chan struct{})
	go func() {
		<-sigCh
		log.Println("收到退出信号，正在清理并关闭...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		// 完整清理：杀核心 + 清理网络规则
		_ = a.Stop()
		a.Sched.Stop()
		_ = a.Store.Close()
		log.Println("已清理完成，退出。")
		close(cleanupDone)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP 服务失败: %v", err)
	}
	// 等待信号处理完成清理后再退出，避免 main 提前退出导致 a.Stop() 未执行
	<-cleanupDone
}

// runOn 实现 `./nexa on`：仅使用磁盘中的数据（配置文件）配置完整的防火墙规则和策略路由，
// 不启动代理核心进程，执行完毕后进程退出。与是否指定 -p/-addr 端口参数无关。
func runOn() {
	a, err := app.New()
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}
	defer a.Store.Close()
	a.PrepareFiles()

	cfg, err := a.LoadConfig()
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}

	// 不受 config.enabled / proxy.enabled 影响：on 命令是纯粹的执行动作，
	// 只要磁盘里有配置就无条件下发防火墙规则和策略路由。
	// 先清理旧规则，避免残留导致重复插入（对齐 Apply 前的 cleanup 惯例）。
	a.Net.Cleanup(cfg)

	if err := a.Net.Apply(cfg); err != nil {
		log.Fatalf("配置防火墙规则和策略路由失败: %v", err)
	}
	log.Println("已根据磁盘配置完成防火墙规则和策略路由配置（未启动代理核心）。")
}

// runOff 实现 `./nexa off`：仅清理防火墙规则和策略路由，不杀死代理核心进程，
// 执行完毕后进程退出。与是否指定 -p/-addr 端口参数无关。
func runOff() {
	a, err := app.New()
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}
	defer a.Store.Close()
	a.PrepareFiles()

	cfg, err := a.LoadConfig()
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}

	a.Net.Cleanup(cfg)
	log.Println("已清理防火墙规则和策略路由（代理核心进程未被终止）。")
}
