package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-sdk-cve/nvd/shared/environment"
)

type Config struct {
	APIKey            string
	BaseURL           string
	HideSensitiveData bool
}

func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return fmt.Errorf("base URL is required")
	}
	return nil
}

type configFile struct {
	APIKey            string `json:"api_key"`
	BaseURL           string `json:"base_url"`
	HideSensitiveData bool   `json:"hide_sensitive_data"`
}

func LoadConfigFromFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var c configFile
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return &Config{
		APIKey:            c.APIKey,
		BaseURL:           c.BaseURL,
		HideSensitiveData: c.HideSensitiveData,
	}, nil
}

func ConfigFromEnv() *Config {
	return &Config{
		APIKey:            environment.GetEnv("NVD_API_KEY", ""),
		BaseURL:           environment.GetEnv("NVD_BASE_URL", "https://services.nvd.nist.gov"),
		HideSensitiveData: environment.GetEnvAsBool("HIDE_SENSITIVE_DATA", false),
	}
}
