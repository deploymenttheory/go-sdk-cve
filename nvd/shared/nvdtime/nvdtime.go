package nvdtime

import (
	"encoding/json"
	"fmt"
	"time"
)

// Time wraps time.Time to handle NVD API's inconsistent timestamp formats.
// The NVD API returns timestamps in multiple formats:
// - With timezone: "2021-08-04T13:00:00.000Z" or "2021-08-04T13:00:00.000+01:00"
// - Without timezone: "2021-08-04T13:00:00.000"
type Time struct {
	time.Time
}

var supportedFormats = []string{
	time.RFC3339,              // "2006-01-02T15:04:05Z07:00"
	time.RFC3339Nano,          // "2006-01-02T15:04:05.999999999Z07:00"
	"2006-01-02T15:04:05.999", // Without timezone
	"2006-01-02T15:04:05",     // Without timezone or milliseconds
}

func (t *Time) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	if s == "" {
		t.Time = time.Time{}
		return nil
	}

	var parseErr error
	for _, format := range supportedFormats {
		parsed, err := time.Parse(format, s)
		if err == nil {
			t.Time = parsed
			return nil
		}
		parseErr = err
	}

	return fmt.Errorf("unable to parse time %q: %w", s, parseErr)
}

func (t Time) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.Time.Format(time.RFC3339))
}
