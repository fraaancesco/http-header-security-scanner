package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	for _, k := range []string{"SERVER_PORT", "GIN_MODE", "SCANNER_TIMEOUT", "SCANNER_INSECURE"} {
		t.Setenv(k, "")
	}

	cfg := Load()

	if cfg.Server.Port != "8081" {
		t.Errorf("Port = %q, want 8081", cfg.Server.Port)
	}
	if cfg.Server.Mode != "debug" {
		t.Errorf("Mode = %q, want debug", cfg.Server.Mode)
	}
	if cfg.Scanner.DefaultTimeout != 10*time.Second {
		t.Errorf("DefaultTimeout = %v, want 10s", cfg.Scanner.DefaultTimeout)
	}
	if cfg.Scanner.Insecure {
		t.Error("Insecure = true, want false")
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("SERVER_PORT", "9000")
	t.Setenv("GIN_MODE", "release")
	t.Setenv("SCANNER_TIMEOUT", "30")
	t.Setenv("SCANNER_INSECURE", "true")

	cfg := Load()

	if cfg.Server.Port != "9000" {
		t.Errorf("Port = %q, want 9000", cfg.Server.Port)
	}
	if cfg.Server.Mode != "release" {
		t.Errorf("Mode = %q, want release", cfg.Server.Mode)
	}
	if cfg.Scanner.DefaultTimeout != 30*time.Second {
		t.Errorf("DefaultTimeout = %v, want 30s", cfg.Scanner.DefaultTimeout)
	}
	if !cfg.Scanner.Insecure {
		t.Error("Insecure = false, want true")
	}
}

func TestLoadInvalidValuesFallBack(t *testing.T) {
	t.Setenv("SCANNER_TIMEOUT", "ten")
	t.Setenv("SCANNER_INSECURE", "maybe")

	cfg := Load()

	if cfg.Scanner.DefaultTimeout != 10*time.Second {
		t.Errorf("DefaultTimeout = %v, want 10s", cfg.Scanner.DefaultTimeout)
	}
	if cfg.Scanner.Insecure {
		t.Error("Insecure = true, want false")
	}
}
