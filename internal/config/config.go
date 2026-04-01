package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/artifex/dfir/internal/models"
)

// DefaultConfig returns an AppConfig populated with safe defaults.
// All listeners bind to localhost only.
func DefaultConfig() models.AppConfig {
	return models.AppConfig{
		APIPort:       8080,
		CollectorPort: 8081,
		MCPPort:       8082,
		WorkerPort:    8083,
		BindAddress:   "127.0.0.1",
		DataDir:       "./data",
	}
}

// Load reads config.json from the given directory and merges it with defaults.
// If the file does not exist, the default configuration is returned.
func Load(configDir string) (models.AppConfig, error) {
	cfg := DefaultConfig()

	configPath := filepath.Join(configDir, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config file: %w", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config file: %w", err)
	}

	if err := Validate(cfg); err != nil {
		return cfg, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// Validate checks that the configuration values are acceptable.
// In particular, BindAddress must be 127.0.0.1 to prevent accidental
// exposure of the DFIR platform on a network interface.
func Validate(cfg models.AppConfig) error {
	if cfg.BindAddress != "127.0.0.1" {
		return fmt.Errorf("bind_address must be 127.0.0.1, got %q", cfg.BindAddress)
	}

	if cfg.APIPort <= 0 || cfg.APIPort > 65535 {
		return fmt.Errorf("api_port must be between 1 and 65535, got %d", cfg.APIPort)
	}
	if cfg.CollectorPort <= 0 || cfg.CollectorPort > 65535 {
		return fmt.Errorf("collector_port must be between 1 and 65535, got %d", cfg.CollectorPort)
	}
	if cfg.MCPPort <= 0 || cfg.MCPPort > 65535 {
		return fmt.Errorf("mcp_port must be between 1 and 65535, got %d", cfg.MCPPort)
	}
	if cfg.WorkerPort <= 0 || cfg.WorkerPort > 65535 {
		return fmt.Errorf("worker_port must be between 1 and 65535, got %d", cfg.WorkerPort)
	}

	if cfg.DataDir == "" {
		return fmt.Errorf("data_dir must not be empty")
	}

	switch cfg.LLM.Provider {
	case "", "anthropic", "gemini", "openai", "deepseek":
	default:
		return fmt.Errorf("llm.provider must be one of anthropic, gemini, openai, deepseek, or empty, got %q", cfg.LLM.Provider)
	}

	return nil
}
