// nexa 主程序：独立守护进程，./nexa 即可运行，默认监听 :9990。
// 提供 HTTP API + 内嵌 Web 面板。不依赖 luci/rpcd/ubus/UCI。
package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nexa-proxy/nexa/internal/api"
	"github.com/nexa-proxy/nexa/internal/app"
	"github.com/nexa-proxy/nexa/internal/auth"
	"github.com/nexa-proxy/nexa/web"
)

// version 由 ldflags -X main.version=... 注入，默认 dev。
var version = "dev"

func main() {
	addr := flag.String("addr", ":9990", "HTTP 监听地址")
	flag.Parse()

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
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 启动时拉起核心（对齐 init.d boot）
	go func() {
		if err := a.Boot(); err != nil {
			a.Log.App("App", "启动失败："+err.Error())
		}
	}()

	log.Printf("nexa 监听 %s（默认账户 admin/admin，请尽快修改）", *addr)

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
