package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// AppConfig defines runtime settings for Forge components.
type AppConfig struct {
	APIBindAddress string
	AIServiceURL   string
	BrowserServiceURL string
	DatabaseURL    string
	UsePostgres    bool
	BootstrapToken string
	AuthSigningKey string
	SessionTTLSeconds int
	RequestTimeout time.Duration
}

// Default returns safe baseline configuration.
func Default() AppConfig {
	return AppConfig{
		APIBindAddress: ":8081",
		AIServiceURL:   "http://127.0.0.1:8090",
		BrowserServiceURL: "http://127.0.0.1:8091",
		DatabaseURL:    "",
		UsePostgres:    false,
		BootstrapToken: "forge-bootstrap-change-me",
		AuthSigningKey: "forge-signing-key-change-me",
		SessionTTLSeconds: 43200,
		RequestTimeout: 10 * time.Second,
	}
}

// FromEnv loads runtime configuration from environment variables.
func FromEnv() AppConfig {
	cfg := Default()
	if value := strings.TrimSpace(os.Getenv("FORGE_API_BIND")); value != "" {
		cfg.APIBindAddress = value
	}
	if value := strings.TrimSpace(os.Getenv("FORGE_AI_SERVICE_URL")); value != "" {
		cfg.AIServiceURL = value
	}
	if value := strings.TrimSpace(os.Getenv("FORGE_BROWSER_SERVICE_URL")); value != "" {
		cfg.BrowserServiceURL = value
	}
	if value := strings.TrimSpace(os.Getenv("FORGE_DATABASE_URL")); value != "" {
		cfg.DatabaseURL = value
	}
	if value := strings.TrimSpace(os.Getenv("FORGE_BOOTSTRAP_TOKEN")); value != "" {
		cfg.BootstrapToken = value
	}
	if value := strings.TrimSpace(os.Getenv("FORGE_AUTH_SIGNING_KEY")); value != "" {
		cfg.AuthSigningKey = value
	}
	if value := strings.TrimSpace(os.Getenv("FORGE_USE_POSTGRES")); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			cfg.UsePostgres = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("FORGE_SESSION_TTL_SECONDS")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err == nil && parsed > 0 {
			cfg.SessionTTLSeconds = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("FORGE_REQUEST_TIMEOUT_SECONDS")); value != "" {
		seconds, err := strconv.Atoi(value)
		if err == nil && seconds > 0 {
			cfg.RequestTimeout = time.Duration(seconds) * time.Second
		}
	}
	return cfg
}
