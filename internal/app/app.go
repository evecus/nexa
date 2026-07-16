// Package app 是 nexa 的依赖容器，整合 store/core/netmanager/scheduler/logger，
// 并实现 Apply 流程（对齐 proxy.init 的 reload_service = cleanup + start）。
package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/nexa-proxy/nexa/internal/assets"
	"github.com/nexa-proxy/nexa/internal/config"
	"github.com/nexa-proxy/nexa/internal/core"
	"github.com/nexa-proxy/nexa/internal/logger"
	"github.com/nexa-proxy/nexa/internal/netmanager"
	"github.com/nexa-proxy/nexa/internal/paths"
	"github.com/nexa-proxy/nexa/internal/scheduler"
	"github.com/nexa-proxy/nexa/internal/store"
)

type App struct {
	Store  *store.Store
	Log    *logger.Logger
	Core   *core.Manager
	Net    *netmanager.Manager
	Sched  *scheduler.Scheduler
}

// New 创建并初始化所有组件（建目录、打开日志、启动调度器）。
func New() (*App, error) {
	if err := os.MkdirAll(paths.HomeDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(paths.ProfilesDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(paths.RunDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(paths.NftDir, 0755); err != nil {
		return nil, err
	}

	st, err := store.New()
	if err != nil {
		return nil, err
	}
	log, err := logger.New()
	if err != nil {
		return nil, err
	}
	mgr := core.New(log)
	net := netmanager.New(log)
	sch := scheduler.New(log, mgr)

	a := &App{Store: st, Log: log, Core: mgr, Net: net, Sched: sch}
	return a, nil
}

// LoadConfig 读取配置。
func (a *App) LoadConfig() (*config.Config, error) {
	return a.Store.Load()
}

// SaveConfig 保存配置（不触发 apply）。
func (a *App) SaveConfig(c *config.Config) error {
	return a.Store.Save(c)
}

// Boot 启动时调用：对齐 proxy.init boot_func → start。
// 先启动调度器；若 config.enabled=1 则 Apply（启动核心 + 网络）。
func (a *App) Boot() error {
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	a.Sched.Start()
	a.Sched.Reload(cfg)

	if !cfg.Config.Enabled {
		a.Log.App("App", "已禁用，退出。")
		return nil
	}

	// start_delay（对齐 proxy.init:17-20）
	if cfg.Config.StartDelay > 0 {
		a.Log.App("App", fmt.Sprintf("延迟 %d 秒后启动。", cfg.Config.StartDelay))
		time.Sleep(time.Duration(cfg.Config.StartDelay) * time.Second)
	}
	return a.Apply(cfg)
}

// Apply 对齐 proxy.init start_service 完整流程：
// 启动核心 → 应用网络规则。若核心已运行则先 Stop+Cleanup。
func (a *App) Apply(cfg *config.Config) error {
	if !cfg.Config.Enabled {
		a.Log.App("App", "已禁用，停止服务。")
		return a.Stop()
	}
	a.Log.App("App", "已启用，启动中。")

	// 先清理旧的网络规则（对齐 reload_service 的 cleanup）
	a.Net.Cleanup(cfg)

	// 启动核心
	if err := a.Core.Start(cfg); err != nil {
		return err
	}

	// 应用网络/防火墙
	if cfg.Proxy.Enabled {
		return a.Net.Apply(cfg)
	}
	a.Log.App("代理", "已禁用，跳过防火墙设置。")
	return nil
}

// Stop 停止核心 + 清理网络 + 停调度。
func (a *App) Stop() error {
	cfg, _ := a.LoadConfig()
	_ = a.Core.Stop()
	if cfg != nil {
		a.Net.Cleanup(cfg)
	}
	return nil
}

// Reload 对齐 proxy.init reload_service = cleanup + start。
func (a *App) Reload(cfg *config.Config) error {
	a.Sched.Reload(cfg)
	if !cfg.Config.Enabled {
		return a.Stop()
	}
	a.Net.Cleanup(cfg)
	if err := a.Core.Restart(cfg); err != nil {
		return err
	}
	if cfg.Proxy.Enabled {
		return a.Net.Apply(cfg)
	}
	return nil
}

// Restart 重启核心并重应用网络。
func (a *App) Restart(cfg *config.Config) error {
	a.Net.Cleanup(cfg)
	if err := a.Core.Restart(cfg); err != nil {
		return err
	}
	if cfg.Proxy.Enabled {
		return a.Net.Apply(cfg)
	}
	return nil
}

// HUPReload 仅发 HUP 信号快速重载核心（对齐 procd fast_reload）。
func (a *App) HUPReload() error {
	return a.Core.Reload()
}

// PID 返回核心 pid（无则 0）。
func (a *App) PID() int { return a.Core.PID() }

// PrepareFiles 确保 profile 目录等就绪，并释放内嵌的 geoip 集合文件（仅当目标不存在时）。
func (a *App) PrepareFiles() {
	_ = os.MkdirAll(paths.ProfilesDir, 0755)
	_ = os.MkdirAll(paths.RunDir, 0755)
	_ = os.MkdirAll(paths.TempDir, 0755)
	_ = os.MkdirAll(paths.NftDir, 0755)
	releaseEmbeddedGeoIP()
}

// releaseEmbeddedGeoIP 把编译时内嵌的 geoip_cn.nft / geoip6_cn.nft 释放到 /etc/nexa/firewall/。
// 仅当目标文件不存在时释放，已存在则保留用户文件（用户可自行更新）。
func releaseEmbeddedGeoIP() {
	for _, item := range []struct {
		embedPath string
		target    string
	}{
		{"geoip_cn.nft", paths.GeoIPCnNft},
		{"geoip6_cn.nft", paths.GeoIP6CnNft},
	} {
		if _, err := os.Stat(item.target); err == nil {
			continue // 已存在，不覆盖
		}
		data, err := assets.GeoIPFS.ReadFile(item.embedPath)
		if err != nil {
			continue
		}
		_ = os.WriteFile(item.target, data, 0644)
	}
}

// WritePid 写 nexa 自身 pid（区别于核心 pid）。
func (a *App) WritePid(pid int) {
	_ = os.WriteFile(filepath.Join(paths.TempDir, "nexa-daemon.pid"), []byte(strconv.Itoa(pid)), 0644)
}
