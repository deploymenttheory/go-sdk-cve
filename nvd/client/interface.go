package client

import (
	"context"

	"go.uber.org/zap"
)

type Client interface {
	NewRequest(ctx context.Context) *RequestBuilder
	GetLogger() *zap.Logger
}
