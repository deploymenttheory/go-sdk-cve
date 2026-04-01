package client

import "time"

const (
	UserAgentBase = "go-sdk-cve"
)

const (
	DefaultTimeout        = 30 * time.Second
	MaxRetries            = 5
	RetryWaitTime         = 6 * time.Second
	RetryMaxWaitTime      = 60 * time.Second
	DefaultResultsPerPage = 2000
)
