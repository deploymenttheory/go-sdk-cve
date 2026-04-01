package config_test

import (
	"os"
	"testing"

	"github.com/deploymenttheory/go-sdk-cve/nvd/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &config.Config{
				BaseURL: "https://services.nvd.nist.gov",
				APIKey:  "test-key",
			},
			wantErr: false,
		},
		{
			name: "missing base URL",
			config: &config.Config{
				APIKey: "test-key",
			},
			wantErr: true,
		},
		{
			name: "valid without API key",
			config: &config.Config{
				BaseURL: "https://services.nvd.nist.gov",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigFromEnv(t *testing.T) {
	os.Setenv("NVD_API_KEY", "test-api-key")
	os.Setenv("NVD_BASE_URL", "https://test.nvd.nist.gov")
	os.Setenv("HIDE_SENSITIVE_DATA", "true")
	defer func() {
		os.Unsetenv("NVD_API_KEY")
		os.Unsetenv("NVD_BASE_URL")
		os.Unsetenv("HIDE_SENSITIVE_DATA")
	}()

	cfg := config.ConfigFromEnv()

	assert.Equal(t, "test-api-key", cfg.APIKey)
	assert.Equal(t, "https://test.nvd.nist.gov", cfg.BaseURL)
	assert.True(t, cfg.HideSensitiveData)
}

func TestLoadConfigFromFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	configJSON := `{
		"api_key": "file-api-key",
		"base_url": "https://file.nvd.nist.gov",
		"hide_sensitive_data": true
	}`

	_, err = tmpFile.WriteString(configJSON)
	require.NoError(t, err)
	tmpFile.Close()

	cfg, err := config.LoadConfigFromFile(tmpFile.Name())
	require.NoError(t, err)

	assert.Equal(t, "file-api-key", cfg.APIKey)
	assert.Equal(t, "https://file.nvd.nist.gov", cfg.BaseURL)
	assert.True(t, cfg.HideSensitiveData)
}

func TestLoadConfigFromFile_InvalidJSON(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("invalid json")
	require.NoError(t, err)
	tmpFile.Close()

	_, err = config.LoadConfigFromFile(tmpFile.Name())
	assert.Error(t, err)
}

func TestLoadConfigFromFile_NotFound(t *testing.T) {
	_, err := config.LoadConfigFromFile("/nonexistent/config.json")
	assert.Error(t, err)
}
