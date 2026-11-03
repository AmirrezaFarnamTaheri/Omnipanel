package config

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"time"
)

type Config struct {
	ListenAddr              string
	DatabaseURL             string
	DatabaseMaxConns        int32
	DatabaseMinConns        int32
	DatabaseMaxConnLifetime time.Duration
	DatabaseMaxConnIdleTime time.Duration
	KEK                     []byte
	PublicURL               string
	SetupToken              string
	ReadTimeout             time.Duration
	WriteTimeout            time.Duration
	IdleTimeout             time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:              getEnv("OMNI_LISTEN_ADDR", ":8080"),
		DatabaseURL:             getEnv("DATABASE_URL", "postgres://omnipanel:omnipanel@localhost:5432/omnipanel?sslmode=disable"),
		DatabaseMaxConns:        parseInt32(getEnv("OMNI_DB_MAX_CONNS", "25"), 25),
		DatabaseMinConns:        parseInt32(getEnv("OMNI_DB_MIN_CONNS", "5"), 5),
		DatabaseMaxConnLifetime: parseDuration(getEnv("OMNI_DB_MAX_CONN_LIFETIME", "1h"), time.Hour),
		DatabaseMaxConnIdleTime: parseDuration(getEnv("OMNI_DB_MAX_CONN_IDLE_TIME", "30m"), 30*time.Minute),
		PublicURL:               getEnv("OMNI_PUBLIC_URL", ""),
		SetupToken:              getEnv("OMNI_SETUP_TOKEN", ""),
		ReadTimeout:             10 * time.Second,
		WriteTimeout:            10 * time.Second,
		IdleTimeout:             120 * time.Second,
	}

	kekStr := getEnv("OMNI_KEK", "")
	var err error
	cfg.KEK, err = decodeKEK(kekStr)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseInt32(s string, def int32) int32 {
	var v int32
	_, err := fmt.Sscanf(s, "%d", &v)
	if err != nil {
		return def
	}
	return v
}

func parseDuration(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

func decodeKEK(s string) ([]byte, error) {
	// Accept base64 or raw 32-byte key.
	if len(s) == 44 {
		// base64 of 32 bytes produces 44 chars
		b := make([]byte, 32)
		n, err := base64.StdEncoding.Decode(b, []byte(s))
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
	if len(s) == 32 {
		return []byte(s), nil
	}
	// Fallback: hash to 32 bytes (dev only)
	h := sha256.Sum256([]byte(s))
	return h[:], nil
}
