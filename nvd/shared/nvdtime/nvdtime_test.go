package nvdtime

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "RFC3339 with Z",
			input:     `"2021-08-04T13:00:00Z"`,
			wantError: false,
		},
		{
			name:      "RFC3339 with offset",
			input:     `"2021-08-04T13:00:00+01:00"`,
			wantError: false,
		},
		{
			name:      "Without timezone with milliseconds",
			input:     `"2005-11-22T11:03:00.000"`,
			wantError: false,
		},
		{
			name:      "Without timezone",
			input:     `"2021-08-04T13:00:00"`,
			wantError: false,
		},
		{
			name:      "RFC3339Nano",
			input:     `"2021-08-04T13:00:00.123456789Z"`,
			wantError: false,
		},
		{
			name:      "Empty string",
			input:     `""`,
			wantError: false,
		},
		{
			name:      "Invalid format",
			input:     `"not-a-date"`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nvdTime Time
			err := json.Unmarshal([]byte(tt.input), &nvdTime)

			if tt.wantError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.input == `""` && !nvdTime.IsZero() {
					t.Errorf("expected zero time for empty string")
				}
			}
		})
	}
}

func TestTime_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		time     Time
		expected string
	}{
		{
			name:     "Valid time",
			time:     Time{time.Date(2021, 8, 4, 13, 0, 0, 0, time.UTC)},
			expected: `"2021-08-04T13:00:00Z"`,
		},
		{
			name:     "Zero time",
			time:     Time{},
			expected: `null`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.time)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if string(data) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, string(data))
			}
		})
	}
}

func TestTime_RoundTrip(t *testing.T) {
	original := Time{time.Date(2021, 8, 4, 13, 30, 45, 0, time.UTC)}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded Time
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if !original.Equal(decoded.Time) {
		t.Errorf("round trip failed: original %v != decoded %v", original, decoded)
	}
}
