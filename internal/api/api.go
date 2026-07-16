// Package api 实现 nexa 的 HTTP API + WebSocket，路由对齐原 ubus luci.proxy / rc / 文件操作。
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nexa-proxy/nexa/internal/app"
	"github.com/nexa-proxy/nexa/internal/auth"
	"github.com/nexa-proxy/nexa/internal/config"
	"github.com/nexa-proxy/nexa/internal/identifiers"
	"github.com/nexa-proxy/nexa/internal/paths"
)

type Router struct {
	a    *app.App
	auth *auth.Auth
}

// Version 是二进制版本号，由 main 包在启动时通过 ldflags 注入的值设置。
var Version = "dev"

func New(a *app.App, au *auth.Auth) *Router {
	return &Router{a: a, auth: au}
}

// Routes 返回 API 路由组（已套 auth 中间件）。
func (r *Router) Routes() http.Handler {
	mux := chi.NewRouter()

	// auth 不需登录
	mux.Post("/api/auth/login", r.handleLogin)
	mux.Put("/api/auth/password", r.handleChangePassword)

	// 其余需登录
	mux.Group(func(m chi.Router) {
		m.Use(r.auth.Middleware)

		// 对齐 ubus luci.proxy
		m.Get("/api/paths", r.handlePaths)
		m.Get("/api/version", r.handleVersion)
		m.Get("/api/identifiers", r.handleIdentifiers)
		m.Post("/api/debug", r.handleDebug)

		// 配置（整体读写，对齐 UCI proxy）
		m.Get("/api/config", r.handleGetConfig)
		m.Put("/api/config", r.handlePutConfig)
		m.Post("/api/config/apply", r.handleApplyConfig)

		// 状态与控制（对齐 rc list / rc init）
		m.Get("/api/status", r.handleStatus)
		m.Post("/api/reload", r.handleReload)
		m.Post("/api/restart", r.handleRestart)
		m.Post("/api/start", r.handleStart)
		m.Post("/api/stop", r.handleStop)

		// profiles
		m.Get("/api/profiles", r.handleListProfiles)
		m.Post("/api/profiles", r.handleUploadProfile)
		m.Get("/api/profiles/{name}", r.handleDownloadProfile)
		m.Put("/api/profiles/{name}", r.handleWriteProfile)
		m.Delete("/api/profiles/{name}", r.handleDeleteProfile)

		// 日志
		m.Get("/api/logs/app", r.handleAppLog)
		m.Get("/api/logs/core", r.handleCoreLog)
		m.Post("/api/logs/app/clear", r.handleClearAppLog)
		m.Post("/api/logs/core/clear", r.handleClearCoreLog)
		m.Get("/api/logs/stream", r.handleLogStream)
	})

	return mux
}

// ── auth ───────────────────────────────────────────────

func (r *Router) handleLogin(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	tok, err := r.auth.Login(body.Username, body.Password)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func (r *Router) handleChangePassword(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Username == "" || body.Password == "" {
		writeErr(w, http.StatusBadRequest, "用户名和密码不能为空")
		return
	}
	if err := r.auth.ChangePassword(body.Username, body.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── 对齐 ubus luci.proxy ───────────────────────────────

func (r *Router) handlePaths(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, paths.Get())
}

func (r *Router) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"binary": Version,
		"app":    r.a.Store.Version(),
	})
}

func (r *Router) handleIdentifiers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, identifiers.Get())
}

func (r *Router) handleDebug(w http.ResponseWriter, _ *http.Request) {
	// 简化：收集系统信息写入 debug 日志（完整版后续补）
	go r.generateDebug()
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// ── config ─────────────────────────────────────────────

func (r *Router) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	cfg, err := r.a.LoadConfig()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (r *Router) handlePutConfig(w http.ResponseWriter, req *http.Request) {
	var cfg config.Config
	if err := json.NewDecoder(req.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := r.a.SaveConfig(&cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleApplyConfig 保存并应用（对齐 LuCI handleSaveApply：保存→apply→reload）。
func (r *Router) handleApplyConfig(w http.ResponseWriter, req *http.Request) {
	var cfg config.Config
	if err := json.NewDecoder(req.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := r.a.SaveConfig(&cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := r.a.Reload(&cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── status & control ───────────────────────────────────

func (r *Router) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"running": r.a.Core.Running(),
		"pid":     r.a.PID(),
	})
}

func (r *Router) handleReload(w http.ResponseWriter, _ *http.Request) {
	cfg, err := r.a.LoadConfig()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := r.a.Reload(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (r *Router) handleRestart(w http.ResponseWriter, _ *http.Request) {
	cfg, err := r.a.LoadConfig()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := r.a.Restart(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (r *Router) handleStart(w http.ResponseWriter, _ *http.Request) {
	cfg, err := r.a.LoadConfig()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := r.a.Apply(cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (r *Router) handleStop(w http.ResponseWriter, _ *http.Request) {
	if err := r.a.Stop(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── profiles ───────────────────────────────────────────

type profileEntry struct {
	Name  string `json:"name"`
	Mtime int64  `json:"mtime"`
	Size  int64  `json:"size"`
}

func (r *Router) handleListProfiles(w http.ResponseWriter, _ *http.Request) {
	entries, err := os.ReadDir(paths.ProfilesDir)
	if err != nil {
		writeJSON(w, http.StatusOK, []profileEntry{})
		return
	}
	var out []profileEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, profileEntry{
			Name:  e.Name(),
			Mtime: info.ModTime().Unix(),
			Size:  info.Size(),
		})
	}
	if out == nil {
		out = []profileEntry{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (r *Router) handleUploadProfile(w http.ResponseWriter, req *http.Request) {
	name := req.URL.Query().Get("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "缺少 name 参数")
		return
	}
	// 防路径穿越
	name = filepath.Base(name)
	data, err := io.ReadAll(req.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	dst := filepath.Join(paths.ProfilesDir, name)
	if err := os.WriteFile(dst, data, 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (r *Router) handleDownloadProfile(w http.ResponseWriter, req *http.Request) {
	name := filepath.Base(chi.URLParam(req, "name"))
	data, err := os.ReadFile(filepath.Join(paths.ProfilesDir, name))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (r *Router) handleWriteProfile(w http.ResponseWriter, req *http.Request) {
	name := filepath.Base(chi.URLParam(req, "name"))
	data, err := io.ReadAll(req.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(paths.ProfilesDir, name), data, 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (r *Router) handleDeleteProfile(w http.ResponseWriter, req *http.Request) {
	name := filepath.Base(chi.URLParam(req, "name"))
	if err := os.Remove(filepath.Join(paths.ProfilesDir, name)); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── logs ───────────────────────────────────────────────

func (r *Router) handleAppLog(w http.ResponseWriter, _ *http.Request) {
	data, err := r.a.Log.ReadApp()
	if err != nil {
		writeJSON(w, http.StatusOK, "")
		return
	}
	writeJSON(w, http.StatusOK, string(data))
}

func (r *Router) handleCoreLog(w http.ResponseWriter, _ *http.Request) {
	data, err := r.a.Log.ReadCore()
	if err != nil {
		writeJSON(w, http.StatusOK, "")
		return
	}
	writeJSON(w, http.StatusOK, string(data))
}

func (r *Router) handleClearAppLog(w http.ResponseWriter, _ *http.Request) {
	_ = r.a.Log.ClearAppLog()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (r *Router) handleClearCoreLog(w http.ResponseWriter, _ *http.Request) {
	_ = r.a.Log.ClearCoreLog()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── helpers ────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// handleLogStream 用 SSE 实时推送 core 日志行。
func (r *Router) handleLogStream(w http.ResponseWriter, req *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// 先推送当前已有日志尾部
	if data, err := r.a.Log.ReadCore(); err == nil {
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(data)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
	}

	ch := r.a.Log.Subscribe()
	defer r.a.Log.Unsubscribe(ch)

	ctx := req.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-ch:
			if !ok {
				return
			}
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write([]byte(line))
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}

// generateDebug 生成调试信息写入 debug.log（简化版，对齐 debug.sh 的输出结构）。
func (r *Router) generateDebug() {
	var b strings.Builder
	b.WriteString("# Nexa Debug Info\n\n")
	b.WriteString("## generated\n```\n" + time.Now().Format("2006-01-02 15:04:05") + "\n```\n\n")
	b.WriteString("## version\n```\n" + r.a.Store.Version() + "\n```\n\n")
	// config
	if cfg, err := r.a.LoadConfig(); err == nil {
		if js, err := json.MarshalIndent(cfg, "", "  "); err == nil {
			b.WriteString("## config\n```json\n" + string(js) + "\n```\n\n")
		}
	}
	_ = os.WriteFile(paths.DebugLogPath, []byte(b.String()), 0644)
}

// 占位：避免未使用导入
var _ = strconv.Itoa
