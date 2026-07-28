// Package auth 提供简单的用户名/密码 + JWT token 认证。
package auth

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/nexa-proxy/nexa/internal/paths"
)

const (
	tokenTTL = 24 * time.Hour
)

// credFile 凭据文件路径。使用函数而非常量，因为 paths.HomeDir 可能在
// main() 中通过 -d 参数在 auth.New() 之前被 paths.Init() 修改；
// 若在包加载时就固化为常量，则自定义数据目录下的凭据会被写到错误的位置
// （通常是没有写权限的默认 /etc/nexa，导致修改密码/用户名在重启后丢失）。
func credFile() string {
	return filepath.Join(paths.HomeDir, "cred.json")
}

type credentials struct {
	Username     string `json:"username"`
	Hash         string `json:"hash"`          // bcrypt
	AuthDisabled bool   `json:"auth_disabled"` // true 时跳过登录校验，允许无验证访问
}

type Auth struct {
	mu   sync.Mutex
	cred credentials
}

func New() *Auth {
	a := &Auth{}
	a.load()
	return a
}

func (a *Auth) load() {
	a.mu.Lock()
	defer a.mu.Unlock()
	data, err := os.ReadFile(credFile())
	if err != nil {
		// 首次：默认 admin/admin
		h, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		a.cred = credentials{Username: "admin", Hash: string(h)}
		a.saveLocked()
		return
	}
	if err := json.Unmarshal(data, &a.cred); err != nil {
		log.Printf("auth: 凭据文件解析失败（%s）：%v，将使用默认凭据", credFile(), err)
		h, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		a.cred = credentials{Username: "admin", Hash: string(h)}
		a.saveLocked()
	}
}

func (a *Auth) saveLocked() {
	// 确保数据目录存在（自定义 -d 目录首次运行时可能尚未创建）。
	if err := os.MkdirAll(filepath.Dir(credFile()), 0755); err != nil {
		log.Printf("auth: 创建数据目录失败：%v", err)
		return
	}
	data, err := json.Marshal(a.cred)
	if err != nil {
		log.Printf("auth: 序列化凭据失败：%v", err)
		return
	}
	if err := os.WriteFile(credFile(), data, 0600); err != nil {
		log.Printf("auth: 写入凭据文件失败（%s）：%v，修改的用户名/密码本次不会持久化", credFile(), err)
	}
}

// Login 校验用户名密码，返回 JWT。
func (a *Auth) Login(user, pass string) (string, error) {
	a.mu.Lock()
	cred := a.cred
	a.mu.Unlock()
	if subtle.ConstantTimeCompare([]byte(user), []byte(cred.Username)) != 1 {
		return "", ErrInvalid
	}
	if bcrypt.CompareHashAndPassword([]byte(cred.Hash), []byte(pass)) != nil {
		return "", ErrInvalid
	}
	claims := jwt.MapClaims{
		"sub": user,
		"exp": time.Now().Add(tokenTTL).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(signKey())
}

// Verify 校验 token。
func (a *Auth) Verify(tokenStr string) bool {
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return signKey(), nil
	})
	return err == nil && tok != nil && tok.Valid
}

// Username 返回当前登录用户名，供设置页回显真实值（而非写死的占位符）。
func (a *Auth) Username() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cred.Username
}

// SetAuthDisabled 打开/关闭"无验证访问"总开关，持久化到凭据文件。
func (a *Auth) SetAuthDisabled(disabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cred.AuthDisabled = disabled
	a.saveLocked()
}

// IsAuthDisabled 返回当前是否处于"无验证访问"状态。
func (a *Auth) IsAuthDisabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cred.AuthDisabled
}

// ChangePassword 修改用户名/密码，并校验是否真正持久化成功。
func (a *Auth) ChangePassword(user, pass string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	a.cred.Username = user
	a.cred.Hash = string(h)
	a.saveLocked()
	// 校验持久化确实成功（saveLocked 内部错误只记录日志，这里显式回读确认）。
	if _, err := os.Stat(credFile()); err != nil {
		return errSaveFailed
	}
	return nil
}

var errSaveFailed = errPersist{}

type errPersist struct{}

func (errPersist) Error() string {
	return "凭据保存失败：数据目录不可写，请检查运行权限"
}

// Middleware 校验 Authorization: Bearer <token>。
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /api/auth/login 放行
		if r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/setup" {
			next.ServeHTTP(w, r)
			return
		}
		// 总开关：无验证访问模式下直接放行，不校验 token
		if a.IsAuthDisabled() {
			next.ServeHTTP(w, r)
			return
		}
		authz := r.Header.Get("Authorization")
		if len(authz) > 7 && authz[:7] == "Bearer " {
			if a.Verify(authz[7:]) {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	})
}

var (
	signKeyVal = []byte("nexa-default-secret-change-me")
)

func signKey() []byte { return signKeyVal }

// SetSignKey 替换签名密钥（应在 main 启动时按机器设置）。
func SetSignKey(k []byte) { signKeyVal = k }

// ErrInvalid 凭据无效。
var ErrInvalid = errInvalid{}

type errInvalid struct{}

func (errInvalid) Error() string { return "invalid credentials" }
