package cve_history

import (
	"fmt"
	"time"

	"github.com/deploymenttheory/go-sdk-cve/nvd/shared/nvdtime"
)

type CVEHistoryResponse struct {
	ResultsPerPage int          `json:"resultsPerPage"`
	StartIndex     int          `json:"startIndex"`
	TotalResults   int          `json:"totalResults"`
	Format         string       `json:"format"`
	Version        string       `json:"version"`
	Timestamp      nvdtime.Time `json:"timestamp"`
	CVEChanges     []CVEChange  `json:"cveChanges"`
}

type CVEChange struct {
	Change Change `json:"change"`
}

type Change struct {
	CVEID            string         `json:"cveId"`
	EventName        string         `json:"eventName"`
	CVEChangeID      string         `json:"cveChangeId"`
	SourceIdentifier string         `json:"sourceIdentifier"`
	Created          nvdtime.Time   `json:"created"`
	Details          []ChangeDetail `json:"details"`
}

type ChangeDetail struct {
	Action   string  `json:"action"`
	Type     string  `json:"type"`
	OldValue *string `json:"oldValue,omitempty"`
	NewValue *string `json:"newValue,omitempty"`
}

type ListRequest struct {
	ChangeStartDate *time.Time
	ChangeEndDate   *time.Time
	CVEID           string
	EventName       string
	ResultsPerPage  int
	StartIndex      int
}

func (r *ListRequest) ToQueryParams() map[string]string {
	params := make(map[string]string)

	if r.ChangeStartDate != nil {
		params["changeStartDate"] = r.ChangeStartDate.Format(time.RFC3339)
	}
	if r.ChangeEndDate != nil {
		params["changeEndDate"] = r.ChangeEndDate.Format(time.RFC3339)
	}
	if r.CVEID != "" {
		params["cveId"] = r.CVEID
	}
	if r.EventName != "" {
		params["eventName"] = r.EventName
	}
	if r.ResultsPerPage > 0 {
		params["resultsPerPage"] = fmt.Sprintf("%d", r.ResultsPerPage)
	}
	if r.StartIndex > 0 {
		params["startIndex"] = fmt.Sprintf("%d", r.StartIndex)
	}

	return params
}
