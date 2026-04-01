package client

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"resty.dev/v3"
)

type cloudflareError struct {
	RetryAfter int `json:"retry_after"`
}

func retryCondition(r *resty.Response, err error) bool {
	if err != nil {
		return false
	}

	if !isIdempotentMethod(r.Request.Method) {
		return false
	}

	statusCode := r.StatusCode()
	return statusCode == http.StatusTooManyRequests ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout ||
		statusCode == http.StatusBadGateway ||
		(statusCode >= 500 && statusCode < 600)
}

func retryStrategyFunc(resp *resty.Response, err error) (time.Duration, error) {
	if resp == nil {
		return 0, err
	}

	statusCode := resp.StatusCode()
	
	if statusCode == http.StatusTooManyRequests {
		if retryAfter := resp.Header().Get("Retry-After"); retryAfter != "" {
			if seconds, parseErr := strconv.Atoi(retryAfter); parseErr == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second, nil
			}
		}

		var cfError cloudflareError
		if parseErr := json.Unmarshal(resp.Bytes(), &cfError); parseErr == nil && cfError.RetryAfter > 0 {
			return time.Duration(cfError.RetryAfter) * time.Second, nil
		}

		return 30 * time.Second, nil
	}

	if statusCode >= 500 && statusCode < 600 {
		attempt := resp.Request.Attempt
		if attempt == 0 {
			attempt = 1
		}
		waitTime := time.Duration(1<<uint(attempt)) * time.Second
		if waitTime > 60*time.Second {
			waitTime = 60 * time.Second
		}
		return waitTime, nil
	}

	return 0, err
}

func isIdempotentMethod(method string) bool {
	return method == "GET" || method == "PUT" || method == "DELETE" || method == "HEAD" || method == "OPTIONS"
}
