package client

import (
	"testing"
)

func TestIsIdempotentMethod(t *testing.T) {
	tests := []struct {
		method   string
		expected bool
	}{
		{"GET", true},
		{"PUT", true},
		{"DELETE", true},
		{"HEAD", true},
		{"OPTIONS", true},
		{"POST", false},
		{"PATCH", false},
	}

	for _, tt := range tests {
		result := isIdempotentMethod(tt.method)
		if result != tt.expected {
			t.Errorf("method %s: expected %v, got %v", tt.method, tt.expected, result)
		}
	}
}
