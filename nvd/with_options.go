package nvd

import (
	"crypto/tls"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/deploymenttheory/go-sdk-cve/nvd/client"
	"go.uber.org/zap"
)

type ClientOption = client.ClientOption

func WithBaseURL(baseURL string) ClientOption {
	return func(s *client.TransportSettings) error {
		s.BaseURL = baseURL
		return nil
	}
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(s *client.TransportSettings) error {
		s.Timeout = timeout
		return nil
	}
}

func WithRetryCount(count int) ClientOption {
	return func(s *client.TransportSettings) error {
		s.RetryCount = count
		return nil
	}
}

func WithRetryWaitTime(waitTime time.Duration) ClientOption {
	return func(s *client.TransportSettings) error {
		s.RetryWaitTime = waitTime
		return nil
	}
}

func WithRetryMaxWaitTime(maxWaitTime time.Duration) ClientOption {
	return func(s *client.TransportSettings) error {
		s.RetryMaxWaitTime = maxWaitTime
		return nil
	}
}

func WithLogger(logger *zap.Logger) ClientOption {
	return func(s *client.TransportSettings) error {
		if logger == nil {
			return fmt.Errorf("logger cannot be nil")
		}
		s.Logger = logger
		return nil
	}
}

func WithDebug() ClientOption {
	return func(s *client.TransportSettings) error {
		s.Debug = true
		return nil
	}
}

func WithUserAgent(userAgent string) ClientOption {
	return func(s *client.TransportSettings) error {
		s.UserAgent = userAgent
		return nil
	}
}

func WithGlobalHeader(key, value string) ClientOption {
	return func(s *client.TransportSettings) error {
		if s.GlobalHeaders == nil {
			s.GlobalHeaders = make(map[string]string)
		}
		s.GlobalHeaders[key] = value
		return nil
	}
}

func WithGlobalHeaders(headers map[string]string) ClientOption {
	return func(s *client.TransportSettings) error {
		if s.GlobalHeaders == nil {
			s.GlobalHeaders = make(map[string]string)
		}
		maps.Copy(s.GlobalHeaders, headers)
		return nil
	}
}

func WithProxy(proxyURL string) ClientOption {
	return func(s *client.TransportSettings) error {
		s.ProxyURL = proxyURL
		return nil
	}
}

func WithTLSClientConfig(tlsConfig *tls.Config) ClientOption {
	return func(s *client.TransportSettings) error {
		s.TLSClientConfig = tlsConfig
		return nil
	}
}

func WithTransport(transport http.RoundTripper) ClientOption {
	return func(s *client.TransportSettings) error {
		s.HTTPTransport = transport
		return nil
	}
}

func WithInsecureSkipVerify() ClientOption {
	return func(s *client.TransportSettings) error {
		s.InsecureSkipVerify = true
		return nil
	}
}

func WithTotalRetryDuration(d time.Duration) ClientOption {
	return func(s *client.TransportSettings) error {
		s.TotalRetryDuration = d
		return nil
	}
}
