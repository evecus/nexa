// Package logger 提供 app/core/debug 日志的文件写入 + WebSocket 实时推送。
package logger

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nexa-proxy/nexa/internal/paths"
)

type Logger struct {
	mu       sync.Mutex
	appFile  *os.File
	coreFile *os.File
	subs     map[chan string]struct{} // 订阅 core 日志的 ws 客户端
	subsMu   sync.RWMutex
}

func New() (*Logger, error) {
	if err := os.MkdirAll(paths.LogDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(paths.TempDir, 0755); err != nil {
		return nil, err
	}
	app, err := openLog(paths.AppLogPath)
	if err != nil {
		return nil, err
	}
	core, err := openLog(paths.CoreLogPath)
	if err != nil {
		return nil, err
	}
	return &Logger{
		appFile:  app,
		coreFile: core,
		subs:     make(map[chan string]struct{}),
	}, nil
}

func openLog(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

// App 写一行 app 日志，格式与原 include.sh log() 一致。
func (l *Logger) App(scope, msg string) {
	line := fmt.Sprintf("[%s] [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), scope, msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.appFile != nil {
		_, _ = l.appFile.WriteString(line)
	}
}

// Core 写一行 core 日志（外部核心 stdout/stderr）。
func (l *Logger) Core(line string) {
	l.mu.Lock()
	if l.coreFile != nil {
		_, _ = l.coreFile.WriteString(line)
	}
	l.mu.Unlock()
	l.broadcast(line)
}

// ReadApp 读全部 app 日志。
func (l *Logger) ReadApp() ([]byte, error)  { return os.ReadFile(paths.AppLogPath) }

// ReadCore 读全部 core 日志。
func (l *Logger) ReadCore() ([]byte, error) { return os.ReadFile(paths.CoreLogPath) }

// ClearAppLog 清空 app 日志。
func (l *Logger) ClearAppLog() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.appFile.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(paths.AppLogPath, nil, 0644); err != nil {
		return err
	}
	f, err := openLog(paths.AppLogPath)
	if err != nil {
		return err
	}
	l.appFile = f
	return nil
}

// ClearCoreLog 清空 core 日志。
func (l *Logger) ClearCoreLog() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.coreFile.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(paths.CoreLogPath, nil, 0644); err != nil {
		return err
	}
	f, err := openLog(paths.CoreLogPath)
	if err != nil {
		return err
	}
	l.coreFile = f
	return nil
}

// Subscribe 订阅 core 日志实时推送，返回一个 channel；取消时调用 Unsubscribe。
func (l *Logger) Subscribe() chan string {
	ch := make(chan string, 64)
	l.subsMu.Lock()
	l.subs[ch] = struct{}{}
	l.subsMu.Unlock()
	return ch
}

func (l *Logger) Unsubscribe(ch chan string) {
	l.subsMu.Lock()
	delete(l.subs, ch)
	l.subsMu.Unlock()
	close(ch)
}

func (l *Logger) broadcast(line string) {
	l.subsMu.RLock()
	defer l.subsMu.RUnlock()
	for ch := range l.subs {
		select {
		case ch <- line:
		default: // 满了丢弃，避免阻塞核心
		}
	}
}
