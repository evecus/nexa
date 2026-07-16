// Package core 管理外部代理核心的生命周期，对齐 proxy.init 的 procd 逻辑：
// spawn/respawn/pidfile/HUP/profile 复制/launcher。不假设核心类型。
package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nexa-proxy/nexa/internal/config"
	"github.com/nexa-proxy/nexa/internal/logger"
	"github.com/nexa-proxy/nexa/internal/paths"
)

type Manager struct {
	log *logger.Logger

	mu       sync.Mutex
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	pid      int
	running  bool
	stopFlag bool
	crashes  int // 连续快速退出计数

	onGiveUp func() // 核心放弃重启时回调（用于清理网络规则等）
}

func New(log *logger.Logger) *Manager {
	return &Manager{log: log}
}

// OnGiveUp 注册核心放弃重启时的回调。
func (m *Manager) OnGiveUp(fn func()) {
	m.onGiveUp = fn
}

// Running 是否运行中。
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// PID 当前核心 pid。
func (m *Manager) PID() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pid
}

// Start 启动核心。对齐 proxy.init start_service 第 83-130 行。
func (m *Manager) Start(cfg *config.Config) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("core already running")
	}
	m.mu.Unlock()

	// 清理残留的核心进程（nexa 非正常退出时 pidfile 可能残留）
	m.killStaleCore()

	c := &cfg.Config

	// 校验可执行文件
	if c.RunBinary == "" {
		m.log.App("App", "未配置可执行文件路径，退出。")
		return fmt.Errorf("run_binary empty")
	}
	if _, err := exec.LookPath(c.RunBinary); err != nil {
		m.log.App("App", fmt.Sprintf("可执行文件不存在或无执行权限：%s，退出。", c.RunBinary))
		return err
	}

	// 校验 profile
	if c.Profile == "" {
		m.log.App("配置文件", "未选择配置文件，退出。")
		return fmt.Errorf("profile empty")
	}
	profileSrc := filepath.Join(paths.ProfilesDir, c.Profile)
	if _, err := os.Stat(profileSrc); err != nil {
		m.log.App("配置文件", fmt.Sprintf("文件不存在：%s，退出。", c.Profile))
		return err
	}

	// 复制 profile → run/config.<ext>（对齐 proxy.init:103-111）
	ext := ""
	if i := strings.LastIndex(c.Profile, "."); i >= 0 {
		ext = c.Profile[i+1:]
	}
	var runProfile string
	if ext != "" {
		runProfile = filepath.Join(paths.RunDir, "config."+ext)
	} else {
		runProfile = filepath.Join(paths.RunDir, "config")
	}
	if err := os.MkdirAll(paths.RunDir, 0755); err != nil {
		return err
	}
	if err := copyFile(profileSrc, runProfile); err != nil {
		return err
	}
	m.log.App("配置文件", fmt.Sprintf("已复制：%s → %s", c.Profile, runProfile))

	// 启动参数（对齐 proxy.init:116-119 的 launcher，但直接 exec 避免引号问题）
	args := splitArgs(c.RunArgs)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, c.RunBinary, args...)
	cmd.Stdout = newLineWriter(m.log)
	cmd.Stderr = newLineWriter(m.log)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	m.log.App("核心", "启动中。")
	if err := cmd.Start(); err != nil {
		cancel()
		return err
	}

	m.mu.Lock()
	m.cmd = cmd
	m.cancel = cancel
	m.pid = cmd.Process.Pid
	m.running = true
	m.stopFlag = false
	m.mu.Unlock()

	// 写 pidfile
	_ = os.WriteFile(paths.PidFilePath, []byte(strconv.Itoa(m.pid)), 0644)

	// 关键：把核心进程放入指定 cgroup，否则 nft 规则里的
	// `socket cgroupv2 level 2 "services/<name>" counter return`（cgroup v2）
	// 或 `meta cgroup <id> counter return`（cgroup v1）匹配不到，
	// 会导致核心自身出站流量被自身规则再次劫持，连接数指数级增长，内存暴涨。
	if err := m.placeIntoCgroup(cfg); err != nil {
		m.log.App("核心", "警告：cgroup 设置失败："+err.Error()+"，防回环可能失效。")
	} else {
		m.log.App("核心", fmt.Sprintf("已将 PID %d 加入 cgroup。", m.pid))
	}

	// respawn 守护
	m.crashes = 0
	go m.watch(cfg)
	return nil
}

// placeIntoCgroup 把核心进程放入配置的 cgroup，对齐原 proxy.init 的 launcher 行为。
// cgroup v2：/sys/fs/cgroup/services/<name>/cgroup.procs
// cgroup v1：/sys/fs/cgroup/net_cls/<name>/cgroup.procs（同时写 net_cls.classid）
func (m *Manager) placeIntoCgroup(cfg *config.Config) error {
	name := cfg.Routing.CgroupName
	if name == "" {
		return nil
	}
	pid := strconv.Itoa(m.pid)
	switch cgroupsVersion() {
	case 2:
		cgPath := "/sys/fs/cgroup/services/" + name
		if err := os.MkdirAll(cgPath, 0755); err != nil {
			// 目录可能已存在或已被其他子进程占用，尝试直接写父级
			return writeCgroupProcs("/sys/fs/cgroup/services", pid)
		}
		return writeCgroupProcs(cgPath, pid)
	case 1:
		cgPath := "/sys/fs/cgroup/net_cls/" + name
		if err := os.MkdirAll(cgPath, 0755); err != nil {
			return err
		}
		if cfg.Routing.CgroupID != "" {
			_ = os.WriteFile(cgPath+"/net_cls.classid", []byte(cfg.Routing.CgroupID), 0644)
		}
		return writeCgroupProcs(cgPath, pid)
	}
	return nil
}

func writeCgroupProcs(path, pid string) error {
	return os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(pid), 0644)
}

// cgroupsVersion 判断 cgroup 版本。对齐 netmanager 的同名函数。
func cgroupsVersion() int {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return 2
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 {
			// cgroup v2：type 为 cgroup2
			if fields[2] == "cgroup2" {
				return 2
			}
			// cgroup v1：type 为 cgroup（含 net_cls 控制器）
			if fields[2] == "cgroup" && strings.Contains(fields[3], "net_cls") {
				return 1
			}
		}
	}
	// 默认按 v2 处理（现代 OpenWrt 都是 v2）
	return 2
}

// watch 对齐 procd respawn：进程退出后若非主动停止则重启。
// 若核心快速退出（5 秒内），视为启动失败，不再重试并清理网络规则。
func (m *Manager) watch(cfg *config.Config) {
	const maxCrashes = 1
	const crashWindow = 5 * time.Second
	for {
		m.mu.Lock()
		cmd := m.cmd
		m.mu.Unlock()
		if cmd == nil {
			return
		}
		startTime := time.Now()
		_ = cmd.Wait()
		elapsed := time.Since(startTime)

		m.mu.Lock()
		m.running = false
		m.pid = 0
		_ = os.Remove(paths.PidFilePath)
		if m.stopFlag {
			m.cmd = nil
			m.cancel = nil
			m.crashes = 0
			m.mu.Unlock()
			return
		}
		// 核心在 5 秒内退出视为异常崩溃
		if elapsed < crashWindow {
			m.crashes++
		} else {
			m.crashes = 0
		}
		crashes := m.crashes
		m.mu.Unlock()

		if crashes >= maxCrashes {
			m.log.App("核心", fmt.Sprintf("连续 %d 次启动后快速退出，停止重试。请检查配置或权限。", maxCrashes))
			if m.onGiveUp != nil {
				m.onGiveUp()
			}
			return
		}
		m.log.App("核心", "进程退出，1 秒后重启。")
		time.Sleep(time.Second)
		// 重启
		if err := m.Start(cfg); err != nil {
			m.log.App("核心", "重启失败："+err.Error())
			return
		}
	}
}

// Stop 停止核心。
func (m *Manager) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.stopFlag = true
	cmd := m.cmd
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		// 3 秒后强杀
		go func(p *os.Process) {
			time.Sleep(3 * time.Second)
			_ = p.Kill()
		}(cmd.Process)
	}
	return nil
}

// Reload HUP 信号快速重载（对齐 procd_set_param reload_signal HUP）。
func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running || m.cmd == nil || m.cmd.Process == nil {
		return fmt.Errorf("core not running")
	}
	return m.cmd.Process.Signal(syscall.SIGHUP)
}

// Restart = Stop + Start。
func (m *Manager) Restart(cfg *config.Config) error {
	if err := m.Stop(); err != nil {
		return err
	}
	// 等 stop 完成
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !m.Running() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return m.Start(cfg)
}

// killStaleCore 读取 pidfile，若其中有 pid 且对应进程仍在运行则杀掉。
// 处理 nexa 被 kill -9 后核心进程残留的情况。
func (m *Manager) killStaleCore() {
	data, err := os.ReadFile(paths.PidFilePath)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	// 发送信号 0 检测进程是否存活
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		// 进程不存在，仅清理 pidfile
		_ = os.Remove(paths.PidFilePath)
		return
	}
	m.log.App("核心", fmt.Sprintf("检测到残留核心进程 PID %d，正在终止。", pid))
	// 先 SIGTERM，等 2 秒再 SIGKILL
	_ = proc.Signal(syscall.SIGTERM)
	time.Sleep(500 * time.Millisecond)
	// 检测是否已退出
	if err := proc.Signal(syscall.Signal(0)); err == nil {
		time.Sleep(1500 * time.Millisecond)
		_ = proc.Kill()
	}
	_ = os.Remove(paths.PidFilePath)
	m.log.App("核心", "已清理残留核心进程。")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// splitArgs 简单按空格拆分启动参数（够用，复杂场景可后续换 shellwords）。
func splitArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// lineWriter 把字节流按行喂给 logger.Core。
type lineWriter struct {
	log  *logger.Logger
	buf  []byte
	mu   sync.Mutex
}

func newLineWriter(log *logger.Logger) *lineWriter {
	return &lineWriter{log: log}
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := strings.IndexByte(string(w.buf), '\n')
		if i < 0 {
			break
		}
		line := string(w.buf[:i+1])
		w.buf = w.buf[i+1:]
		w.log.Core(line)
	}
	return len(p), nil
}
