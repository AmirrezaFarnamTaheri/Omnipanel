package config

import (
	"os"
	"time"
)

type Config struct {
	ListenAddr     string
	ControlPlaneURL string
	StateDBPath    string
	NodeID         int
	NodeKey        string
	EnrollmentToken string
	Enrolled       bool
	PollInterval   time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:         getEnv("OMNI_AGENT_LISTEN_ADDR", ":9090"),
		ControlPlaneURL:    getEnv("OMNI_CONTROL_PLANE_URL", "http://localhost:8080"),
		StateDBPath:        getEnv("OMNI_AGENT_STATE_DB", ".data/agent-state.sqlite"),
		NodeID:             0,
		NodeKey:            "",
		EnrollmentToken:    getEnv("OMNI_ENROLLMENT_TOKEN", ""),
		Enrolled:           getEnv("OMNI_ENROLLMENT_TOKEN", "") != "",
		PollInterval:       parseDuration(getEnv("OMNI_AGENT_POLL_INTERVAL", "30s"), 30*time.Second),
		ReadTimeout:        10 * time.Second,
		WriteTimeout:       10 * time.Second,
		IdleTimeout:        120 * time.Second,
	}
	return cfg, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseDuration(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}
