// Package scheduler 内置 cron 调度器，替代原 proxy.init 写 /etc/crontabs/root 的做法。
// 支持 5 字段 cron（minute hour dom month dow），每分钟整点触发一次。
package scheduler

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nexa-proxy/nexa/internal/config"
	"github.com/nexa-proxy/nexa/internal/core"
	"github.com/nexa-proxy/nexa/internal/logger"
	"github.com/nexa-proxy/nexa/internal/paths"
)

type Scheduler struct {
	log     *logger.Logger
	manager *core.Manager

	mu      sync.Mutex
	stopCh  chan struct{}
	jobs    []job
	running bool
}

type job struct {
	cron string
	fn   func()
	id   string
}

func New(log *logger.Logger, mgr *core.Manager) *Scheduler {
	return &Scheduler{log: log, manager: mgr}
}

// Start 启动调度循环。
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()
	go s.loop()
}

// Stop 停止调度。
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	close(s.stopCh)
	s.running = false
}

// Reload 按 cfg 重新设置任务（定时重启 + 日志清理）。
func (s *Scheduler) Reload(cfg *config.Config) {
	s.mu.Lock()
	s.jobs = s.jobs[:0]
	s.mu.Unlock()

	// 定时重启（对齐 proxy.init:134-138）
	if cfg.Config.ScheduledRestart && cfg.Config.ScheduledRestartCron != "" {
		cron := cfg.Config.ScheduledRestartCron
		mgr := s.manager
		s.add("restart", cron, func() {
			s.log.App("App", "定时重启触发。")
			_ = mgr.Restart(cfg)
		})
	}

	// 日志定时清理（对齐 proxy.init:139-143 + clear_logs）
	if cfg.Log.ScheduledClear && cfg.Log.ScheduledClearCron != "" {
		cron := cfg.Log.ScheduledClearCron
		lg := s.log
		limit := cfg.Log.ScheduledClearSizeLimit
		unit := cfg.Log.ScheduledClearSizeLimitUnit
		s.add("clear_logs", cron, func() {
			clearLogs(lg, limit, unit)
		})
	}
}

func (s *Scheduler) add(id, cron string, fn func()) {
	s.mu.Lock()
	s.jobs = append(s.jobs, job{id: id, cron: cron, fn: fn})
	s.mu.Unlock()
}

func (s *Scheduler) loop() {
	// 对齐到下一个整分钟
	now := time.Now()
	next := now.Truncate(time.Minute).Add(time.Minute)
	time.Sleep(next.Sub(now))
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	s.tick(time.Now())
	for {
		select {
		case <-s.stopCh:
			return
		case t := <-ticker.C:
			s.tick(t)
		}
	}
}

func (s *Scheduler) tick(t time.Time) {
	s.mu.Lock()
	jobs := make([]job, len(s.jobs))
	copy(jobs, s.jobs)
	s.mu.Unlock()
	for _, j := range jobs {
		if match(j.cron, t) {
			j := j
			go j.fn()
		}
	}
}

// clearLogs 对齐 proxy.init clear_logs()：日志超大小则清空。
func clearLogs(log *logger.Logger, limit int, unit string) {
	bytes := sizeToBytes(limit, unit)
	if bytes <= 0 {
		return
	}
	if info, err := os.Stat(paths.AppLogPath); err == nil && info.Size() >= bytes {
		_ = log.ClearAppLog()
		log.App("日志", "App 日志因超出大小限制已被定时清理。")
	}
	if info, err := os.Stat(paths.CoreLogPath); err == nil && info.Size() >= bytes {
		_ = log.ClearCoreLog()
		log.App("日志", "核心日志因超出大小限制已被定时清理。")
	}
}

func sizeToBytes(limit int, unit string) int64 {
	mul := int64(1)
	switch unit {
	case "B":
		mul = 1
	case "KB":
		mul = 1024
	case "MB":
		mul = 1024 * 1024
	case "GB":
		mul = 1024 * 1024 * 1024
	}
	return int64(limit) * mul
}

// ── 极简 5 字段 cron 匹配 ──────────────────────────────

// match 判断 cron 表达式是否匹配时间 t（5 字段：分 时 日 月 周）。
func match(expr string, t time.Time) bool {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return false
	}
	return matchField(fields[0], t.Minute(), 0, 59) &&
		matchField(fields[1], t.Hour(), 0, 23) &&
		matchField(fields[2], t.Day(), 1, 31) &&
		matchField(fields[3], int(t.Month()), 1, 12) &&
		matchField(fields[4], int(t.Weekday()), 0, 6)
}

// matchField 支持单个值、*、*/N、a-b、a,b 及组合。
func matchField(field string, val, lo, hi int) bool {
	parts := strings.Split(field, ",")
	for _, part := range parts {
		if matchPart(part, val, lo, hi) {
			return true
		}
	}
	return false
}

func matchPart(part string, val, lo, hi int) bool {
	// */N
	if strings.HasPrefix(part, "*/") {
		step, err := strconv.Atoi(part[2:])
		if err != nil || step <= 0 {
			return false
		}
		for i := lo; i <= hi; i += step {
			if i == val {
				return true
			}
		}
		return false
	}
	// a-b 或 a-b/N
	if strings.Contains(part, "/") {
		seg := strings.SplitN(part, "/", 2)
		base := seg[0]
		step, err := strconv.Atoi(seg[1])
		if err != nil || step <= 0 {
			return false
		}
		lo2, hi2, ok := parseRange(base, lo, hi)
		if !ok {
			return false
		}
		for i := lo2; i <= hi2; i += step {
			if i == val {
				return true
			}
		}
		return false
	}
	// a-b
	if lo2, hi2, ok := parseRange(part, lo, hi); ok && part != "*" {
		return val >= lo2 && val <= hi2
	}
	// *
	if part == "*" {
		return val >= lo && val <= hi
	}
	// 单值
	n, err := strconv.Atoi(part)
	if err != nil {
		return false
	}
	return n == val
}

func parseRange(s string, lo, hi int) (int, int, bool) {
	if s == "*" {
		return lo, hi, true
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		a, err1 := strconv.Atoi(s[:i])
		b, err2 := strconv.Atoi(s[i+1:])
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		return a, b, true
	}
	return 0, 0, false
}

// String 用于调试。
func (s *Scheduler) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("scheduler jobs=%d", len(s.jobs))
}
