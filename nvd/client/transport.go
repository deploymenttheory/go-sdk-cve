package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/deploymenttheory/go-sdk-cve/nvd/config"
	"github.com/deploymenttheory/go-sdk-cve/nvd/constants"
	"go.uber.org/zap"
	"resty.dev/v3"
)

type Transport struct {
	client             *resty.Client
	logger             *zap.Logger
	config             *config.Config
	BaseURL            string
	globalHeaders      map[string]string
	userAgent          string
	totalRetryDuration time.Duration
}

func (t *Transport) GetHTTPClient() *resty.Client {
	return t.client
}

func (t *Transport) GetLogger() *zap.Logger {
	return t.logger
}

func NewTransport(cfg *config.Config, opts ...ClientOption) (*Transport, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	settings := &TransportSettings{
		GlobalHeaders: make(map[string]string),
	}
	for _, opt := range opts {
		if err := opt(settings); err != nil {
			return nil, fmt.Errorf("failed to apply client option: %w", err)
		}
	}

	logger := settings.Logger
	if logger == nil {
		var err error
		logger, err = zap.NewProduction()
		if err != nil {
			return nil, fmt.Errorf("failed to create logger: %w", err)
		}
	}

	baseURL := settings.BaseURL
	if baseURL == "" {
		baseURL = cfg.BaseURL
	}
	if baseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	baseURL = trimTrailingSlash(baseURL)

	userAgent := settings.UserAgent
	if userAgent == "" {
		userAgent = fmt.Sprintf("%s/%s", UserAgentBase, constants.Version)
	}

	timeout := settings.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	retryCount := settings.RetryCount
	if retryCount == 0 {
		retryCount = MaxRetries
	}
	retryWait := settings.RetryWaitTime
	if retryWait == 0 {
		retryWait = RetryWaitTime
	}
	retryMaxWait := settings.RetryMaxWaitTime
	if retryMaxWait == 0 {
		retryMaxWait = RetryMaxWaitTime
	}

	restyClient := resty.New()
	restyClient.SetBaseURL(baseURL)
	restyClient.SetTimeout(timeout)
	restyClient.SetRetryCount(retryCount)
	restyClient.SetRetryWaitTime(retryWait)
	restyClient.SetRetryMaxWaitTime(retryMaxWait)
	restyClient.SetHeader("User-Agent", userAgent)

	restyClient.AddRetryConditions(retryCondition)
	restyClient.SetRetryStrategy(retryStrategyFunc)

	restyClient.AddRetryHooks(func(r *resty.Response, err error) {
		if r != nil {
			statusCode := r.StatusCode()
			if statusCode == 429 || (statusCode >= 500 && statusCode < 600) {
				waitTime, _ := retryStrategyFunc(r, err)
				
				if statusCode == 429 {
					logger.Warn("Rate limited, sleeping before retry",
						zap.Int("status_code", statusCode),
						zap.Int("attempt", r.Request.Attempt),
						zap.Int("max_retries", retryCount),
						zap.Duration("wait_time", waitTime),
					)
				} else {
					logger.Warn("Server error, sleeping before retry",
						zap.Int("status_code", statusCode),
						zap.Int("attempt", r.Request.Attempt),
						zap.Int("max_retries", retryCount),
						zap.Duration("wait_time", waitTime),
					)
				}
				
				if waitTime > 0 {
					time.Sleep(waitTime)
				}
			}
		}
	})

	if settings.Debug {
		restyClient.SetDebug(true)
	}

	if settings.InsecureSkipVerify {
		restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	} else if settings.TLSClientConfig != nil {
		restyClient.SetTLSClientConfig(settings.TLSClientConfig)
	}

	if settings.ProxyURL != "" {
		restyClient.SetProxy(settings.ProxyURL)
	}
	if settings.HTTPTransport != nil {
		restyClient.SetTransport(settings.HTTPTransport)
	}
	for k, v := range settings.GlobalHeaders {
		restyClient.SetHeader(k, v)
	}

	if cfg.APIKey != "" {
		restyClient.SetHeader("apiKey", cfg.APIKey)
	}

	transport := &Transport{
		client:             restyClient,
		logger:             logger,
		config:             cfg,
		BaseURL:            baseURL,
		globalHeaders:      settings.GlobalHeaders,
		userAgent:          userAgent,
		totalRetryDuration: settings.TotalRetryDuration,
	}

	logger.Info("NVD API transport created",
		zap.String("base_url", transport.BaseURL),
	)
	return transport, nil
}

func trimTrailingSlash(s string) string {
	if len(s) > 0 && s[len(s)-1] == '/' {
		return s[:len(s)-1]
	}
	return s
}

func (t *Transport) NewRequest(ctx context.Context) *RequestBuilder {
	return &RequestBuilder{
		req:      t.client.R().SetContext(ctx).SetResponseBodyUnlimitedReads(true),
		executor: t,
	}
}

func (t *Transport) execute(req *resty.Request, method, path string, _ any) (*resty.Response, error) {
	return t.executeRequest(req, method, path)
}

func (t *Transport) executeGetBytes(req *resty.Request, path string) (*resty.Response, []byte, error) {
	resp, err := t.executeRequest(req, "GET", path)
	if err != nil {
		return resp, nil, err
	}
	return resp, resp.Bytes(), nil
}

func (t *Transport) executeRequest(req *resty.Request, method, path string) (*resty.Response, error) {
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if t.totalRetryDuration > 0 {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, t.totalRetryDuration)
			defer cancel()
			req.SetContext(ctx)
		}
	}

	t.logger.Debug("Executing API request", zap.String("method", method), zap.String("path", path))

	resp, execErr := req.Execute(method, path)

	if execErr != nil {
		t.logger.Error("Request failed",
			zap.String("method", method),
			zap.String("path", path),
			zap.Error(execErr),
		)
		return resp, fmt.Errorf("request failed: %w", execErr)
	}

	if resp.IsError() {
		return resp, ParseErrorResponse(
			[]byte(resp.String()),
			resp.StatusCode(),
			resp.Status(),
			method,
			path,
			t.logger,
		)
	}

	duration := resp.Duration()

	t.logger.Info("Request completed",
		zap.String("method", method),
		zap.String("path", path),
		zap.Int("status_code", resp.StatusCode()),
		zap.Duration("duration", duration),
	)

	return resp, nil
}
