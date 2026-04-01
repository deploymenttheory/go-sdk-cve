package client

import (
	"crypto/tls"
	"net/http"
	"time"

	"go.uber.org/zap"
)

type ClientOption func(*TransportSettings) error

type TransportSettings struct {
	BaseURL            string
	Timeout            time.Duration
	RetryCount         int
	RetryWaitTime      time.Duration
	RetryMaxWaitTime   time.Duration
	Logger             *zap.Logger
	Debug              bool
	UserAgent          string
	GlobalHeaders      map[string]string
	ProxyURL           string
	TLSClientConfig    *tls.Config
	HTTPTransport      http.RoundTripper
	InsecureSkipVerify bool
	TotalRetryDuration time.Duration
}
