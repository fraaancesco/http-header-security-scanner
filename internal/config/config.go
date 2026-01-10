package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server  ServerConfig
	Scanner ScannerConfig
}

type ServerConfig struct {
	Port string
	Mode string
}

type ScannerConfig struct {
	DefaultTimeout time.Duration
	Insecure       bool
}

func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port: getEnv("SERVER_PORT", "8081"),
			Mode: getEnv("GIN_MODE", "debug"),
		},
		Scanner: ScannerConfig{
			DefaultTimeout: getDurationEnv("SCANNER_TIMEOUT", 10*time.Second),
			Insecure:       getBoolEnv("SCANNER_INSECURE", false),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}
