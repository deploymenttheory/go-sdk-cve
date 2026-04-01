package nvd

import (
	"fmt"

	"github.com/deploymenttheory/go-sdk-cve/nvd/client"
	"github.com/deploymenttheory/go-sdk-cve/nvd/config"
	"github.com/deploymenttheory/go-sdk-cve/nvd/cve_history"
	"github.com/deploymenttheory/go-sdk-cve/nvd/cves"
	"go.uber.org/zap"
)

type Client struct {
	transport  *client.Transport
	CVEs       *cves.CVEs
	CVEHistory *cve_history.CVEHistory
}

type Config = config.Config

func NewClient(cfg *Config, options ...ClientOption) (*Client, error) {
	transport, err := client.NewTransport(cfg, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}
	return &Client{
		transport:  transport,
		CVEs:       cves.NewCVEs(transport),
		CVEHistory: cve_history.NewCVEHistory(transport),
	}, nil
}

func NewClientFromEnv(options ...ClientOption) (*Client, error) {
	cfg := config.ConfigFromEnv()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config from env: %w", err)
	}
	return NewClient(cfg, options...)
}

func (c *Client) GetLogger() *zap.Logger {
	return c.transport.GetLogger()
}

func (c *Client) GetTransport() *client.Transport {
	return c.transport
}

func LoadConfigFromFile(path string) (*Config, error) {
	return config.LoadConfigFromFile(path)
}

func ConfigFromEnv() *Config {
	return config.ConfigFromEnv()
}

func IsNotFound(err error) bool {
	return client.IsNotFound(err)
}

func IsUnauthorized(err error) bool {
	return client.IsUnauthorized(err)
}

func IsBadRequest(err error) bool {
	return client.IsBadRequest(err)
}

func IsServerError(err error) bool {
	return client.IsServerError(err)
}

func IsRateLimited(err error) bool {
	return client.IsRateLimited(err)
}
