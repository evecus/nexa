// Package auth 提供简单的用户名/密码 + JWT token 认证。
// 凭据与"无验证访问"开关持久化在 bbolt 数据库（nexa.db 的 auth bucket），
// 由 store 包统一管理。
package auth

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/nexa-proxy/nexa/internal/store"
)

const (
	tokenTTL = 24 * time.Hour
)

// defaultCred 生成默认凭据（admin/admin）。
func defaultCred() store.Credentials {
	h, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	return store.Credentials{Username: "admin", Hash: string(h)}
}

type Auth struct {
	mu   sync.Mutex
	st   *store.Store
	cred store.Credentials
}

// New 创建 Auth。st 为共享的 bbolt 存储实例（bbolt 文件锁不允许重复打开同一 DB）。
func New(st *store.Store) *Auth {
	a := &Auth{st: st}
	a.load()
	return a
}

func (a *Auth) load() {
	a.mu.Lock()
	defer a.mu.Unlock()

	c, err := a.st.LoadAuth()
	switch {
	case err != nil:
		// 数据库读取失败：使用默认凭据（不回写，避免覆盖已存数据）
		log.Printf("auth: 读取凭据失败：%v，本次使用默认凭据", err)
		a.cred = defaultCred()
	case c == nil:
		// 数据库无凭据（首次运行）：默认 admin/admin 并写入数据库
		a.cred = defaultCred()
		if err := a.st.SaveAuth(&a.cred); err != nil {
			log.Printf("auth: 凭据写入数据库失败：%v", err)
		}
	default:
		a.cred = *c
	}
}

func (a *Auth) saveLocked() {
	if err := a.st.SaveAuth(&a.cred); err != nil {
		log.Printf("auth: 凭据保存失败：%v，修改的用户名/密码/开关本次不会持久化", err)
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

// SetAuthDisabled 打开/关闭"无验证访问"总开关，持久化到数据库。
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

// ChangePassword 修改用户名/密码，持久化失败时返回错误。
func (a *Auth) ChangePassword(user, pass string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	a.cred.Username = user
	a.cred.Hash = string(h)
	if err := a.st.SaveAuth(&a.cred); err != nil {
		return errSaveFailed
	}
	return nil
}

var errSaveFailed = errPersist{}

type errPersist struct{}

func (errPersist) Error() string {
	return "凭据保存失败：数据库不可写，请检查运行权限"
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
