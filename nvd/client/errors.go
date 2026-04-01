package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

type APIError struct {
	Code       string
	Message    string
	StatusCode int
	Status     string
	Endpoint   string
	Method     string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("NVD API error (%d %s) [%s] at %s %s: %s",
			e.StatusCode, e.Status, e.Code, e.Method, e.Endpoint, e.Message)
	}
	return fmt.Sprintf("NVD API error (%d %s) at %s %s: %s",
		e.StatusCode, e.Status, e.Method, e.Endpoint, e.Message)
}

type nvdErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func ParseErrorResponse(body []byte, statusCode int, status, method, endpoint string, logger *zap.Logger) error {
	apiError := &APIError{
		StatusCode: statusCode,
		Status:     status,
		Endpoint:   endpoint,
		Method:     method,
	}
	var parsed nvdErrorBody
	if err := json.Unmarshal(body, &parsed); err == nil && (parsed.Code != "" || parsed.Message != "") {
		apiError.Code = parsed.Code
		apiError.Message = parsed.Message
	} else {
		apiError.Message = string(body)
		if apiError.Message == "" {
			apiError.Message = defaultMessageForStatus(statusCode)
		}
	}
	logger.Error("API error response",
		zap.Int("status_code", statusCode),
		zap.String("method", method),
		zap.String("endpoint", endpoint),
		zap.String("message", apiError.Message))
	return apiError
}

func defaultMessageForStatus(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "The request could not be understood by the server due to malformed syntax."
	case http.StatusUnauthorized:
		return "The request has not been applied because it lacks valid authentication credentials for the target resource."
	case http.StatusForbidden:
		return "The server understood the request but refuses to authorize it."
	case http.StatusNotFound:
		return "The server has not found anything matching the Request-URI."
	case http.StatusTooManyRequests:
		return "The user has sent too many requests in a given amount of time (rate limiting)."
	case http.StatusInternalServerError:
		return "The server encountered an unexpected condition which prevented it from fulfilling the request."
	case http.StatusServiceUnavailable:
		return "The server is currently unable to handle the request due to a temporary overloading or maintenance of the server."
	default:
		return "Unknown error"
	}
}

func IsNotFound(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

func IsUnauthorized(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == http.StatusUnauthorized
	}
	return false
}

func IsBadRequest(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == http.StatusBadRequest
	}
	return false
}

func IsServerError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode >= http.StatusInternalServerError && apiErr.StatusCode < 600
	}
	return false
}

func IsRateLimited(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.StatusCode == http.StatusTooManyRequests
	}
	return false
}
