package cve_history

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-sdk-cve/nvd/client"
	"github.com/deploymenttheory/go-sdk-cve/nvd/constants"
	"resty.dev/v3"
)

type CVEHistory struct {
	client client.Client
}

func NewCVEHistory(client client.Client) *CVEHistory {
	return &CVEHistory{client: client}
}

func (s *CVEHistory) List(ctx context.Context, req *ListRequest) (*CVEHistoryResponse, *resty.Response, error) {
	var result CVEHistoryResponse

	endpoint := constants.EndpointCVEHistory

	var queryParams map[string]string
	if req != nil {
		queryParams = req.ToQueryParams()
	}

	mergePage := func(pageData []byte) error {
		var items []CVEChange
		if err := json.Unmarshal(pageData, &items); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		result.CVEChanges = append(result.CVEChanges, items...)
		return nil
	}

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetQueryParams(queryParams).
		GetPaginated(endpoint, mergePage)

	if err != nil {
		return nil, resp, fmt.Errorf("failed to list CVE history: %w", err)
	}

	result.TotalResults = len(result.CVEChanges)

	return &result, resp, nil
}

func (s *CVEHistory) GetByCVEID(ctx context.Context, cveID string) (*CVEHistoryResponse, *resty.Response, error) {
	if cveID == "" {
		return nil, nil, fmt.Errorf("CVE ID is required")
	}

	endpoint := constants.EndpointCVEHistory

	var result CVEHistoryResponse

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetQueryParam("cveId", cveID).
		SetResult(&result).
		Get(endpoint)

	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
