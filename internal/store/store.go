// Package store 用 SQLite 持久化 nexa 配置，schema 对齐 UCI sections。
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/nexa-proxy/nexa/internal/config"
	"github.com/nexa-proxy/nexa/internal/paths"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

// New 打开/创建数据库并初始化 schema。
func New() (*Store, error) {
	db, err := sql.Open("sqlite", paths.DBPath)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	schema := `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS config_json (
	id    INTEGER PRIMARY KEY CHECK (id = 1),
	value TEXT NOT NULL
);
`
	_, err := s.db.Exec(schema)
	return err
}

// Load 读取配置；不存在则写入默认值并返回。
func (s *Store) Load() (*config.Config, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM config_json WHERE id = 1`).Scan(&raw)
	if err == sql.ErrNoRows {
		def := config.Default()
		if e := s.Save(def); e != nil {
			return nil, e
		}
		return def, nil
	}
	if err != nil {
		return nil, err
	}
	var c config.Config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
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
	_, err = s.db.Exec(
		`INSERT INTO config_json(id, value) VALUES(1, ?)
		 ON CONFLICT(id) DO UPDATE SET value = excluded.value`,
		string(raw),
	)
	return err
}

// Version 返回 nexa 版本。
func (s *Store) Version() string {
	var v string
	_ = s.db.QueryRow(`SELECT value FROM meta WHERE key = 'version'`).Scan(&v)
	if v == "" {
		v = "1.0.0"
	}
	return v
}

// SetVersion 写入版本。
func (s *Store) SetVersion(v string) error {
	_, err := s.db.Exec(
		`INSERT INTO meta(key, value) VALUES('version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		v,
	)
	if err == nil {
		// 顺便记个时间
		_, _ = s.db.Exec(
			`INSERT INTO meta(key, value) VALUES('version_set_at', ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			fmt.Sprintf("%d", 0),
		)
	}
	return err
}
