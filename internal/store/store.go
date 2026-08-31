// Package store 用 bbolt 持久化 nexa 配置，schema 对齐 UCI sections。
//
// 历史上这里使用 modernc.org/sqlite（纯 Go SQLite），但其依赖 modernc.org/libc
// 不支持 MIPS/mipsle/mips64/mips64le 架构（build constraints 排除了所有 MIPS），
// 导致 OpenWrt 路由器目标无法编译。bbolt 是纯 Go 单文件 KV 存储，支持所有
// GOARCH（含全部 MIPS 变体），ACID，足以承载本包极简的存储需求。
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nexa-proxy/nexa/internal/config"
	"github.com/nexa-proxy/nexa/internal/paths"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketMeta  = []byte("meta")
	bucketConf  = []byte("config_json")
	confRowID   = []byte("1")
	metaVersion = []byte("version")
)

type Store struct {
	db *bolt.DB
}

// New 打开/创建数据库并初始化 schema（bucket）。
func New() (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(paths.DBPath), 0755); err != nil {
		return nil, err
	}
	db, err := bolt.Open(paths.DBPath, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketMeta, bucketConf} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

// Load 读取配置；不存在则写入默认值并返回。
func (s *Store) Load() (*config.Config, error) {
	var raw []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(bucketConf); b != nil {
			raw = b.Get(confRowID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if raw == nil {
		def := config.Default()
		if e := s.Save(def); e != nil {
			return nil, e
		}
		return def, nil
	}
	var c config.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save 保存配置（整体覆盖）。
func (s *Store) Save(c *config.Config) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketConf)
		if err != nil {
			return err
		}
		return b.Put(confRowID, raw)
	})
}

// Version 返回 nexa 版本。
func (s *Store) Version() string {
	var v string
	_ = s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(bucketMeta); b != nil {
			if val := b.Get(metaVersion); val != nil {
				v = string(val)
			}
		}
		return nil
	})
	if v == "" {
		v = "1.0.0"
	}
	return v
}

// SetVersion 写入版本。
func (s *Store) SetVersion(v string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		if err := b.Put(metaVersion, []byte(v)); err != nil {
			return err
		}
		// 顺便记个时间
		return b.Put([]byte("version_set_at"), []byte(fmt.Sprintf("%d", 0)))
	})
	return err
}
