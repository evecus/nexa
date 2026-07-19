// Package auth 提供简单的用户名/密码 + JWT token 认证。
package auth

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	credFile = "/etc/nexa/cred.json"
	tokenTTL = 24 * time.Hour
)

type credentials struct {
	Username     string `json:"username"`
	Hash         string `json:"hash"`         // bcrypt
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
	data, err := os.ReadFile(credFile)
	if err != nil {
		// 首次：默认 admin/admin
		h, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		a.cred = credentials{Username: "admin", Hash: string(h)}
		a.saveLocked()
		return
	}
	_ = json.Unmarshal(data, &a.cred)
}

func (a *Auth) saveLocked() {
	data, _ := json.Marshal(a.cred)
	_ = os.WriteFile(credFile, data, 0600)
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

// ChangePassword 修改用户名/密码。
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
	return nil
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
