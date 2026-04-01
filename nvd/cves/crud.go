package cves

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-sdk-cve/nvd/client"
	"github.com/deploymenttheory/go-sdk-cve/nvd/constants"
	"resty.dev/v3"
)

type CVEs struct {
	client client.Client
}

func NewCVEs(client client.Client) *CVEs {
	return &CVEs{client: client}
}

func (s *CVEs) List(ctx context.Context, req *ListRequest) (*CVEResponse, *resty.Response, error) {
	var result CVEResponse

	endpoint := constants.EndpointCVEs

	var queryParams map[string]string
	if req != nil {
		queryParams = req.ToQueryParams()
	}

	mergePage := func(pageData []byte) error {
		var items []VulnerabilityItem
		if err := json.Unmarshal(pageData, &items); err != nil {
			return fmt.Errorf("failed to unmarshal page: %w", err)
		}
		result.Vulnerabilities = append(result.Vulnerabilities, items...)
		return nil
	}

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetQueryParams(queryParams).
		GetPaginated(endpoint, mergePage)

	if err != nil {
		return nil, resp, fmt.Errorf("failed to list CVEs: %w", err)
	}

	result.TotalResults = len(result.Vulnerabilities)

	return &result, resp, nil
}

func (s *CVEs) ListSingle(ctx context.Context, req *ListRequest) (*CVEResponse, *resty.Response, error) {
	var result CVEResponse

	endpoint := constants.EndpointCVEs

	var queryParams map[string]string
	if req != nil {
		queryParams = req.ToQueryParams()
	}

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetQueryParams(queryParams).
		SetResult(&result).
		Get(endpoint)

	if err != nil {
		return nil, resp, fmt.Errorf("failed to list CVEs: %w", err)
	}

	return &result, resp, nil
}

func (s *CVEs) GetByID(ctx context.Context, cveID string) (*VulnerabilityItem, *resty.Response, error) {
	if cveID == "" {
		return nil, nil, fmt.Errorf("CVE ID is required")
	}

	endpoint := constants.EndpointCVEs

	var result CVEResponse

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetQueryParam("cveId", cveID).
		Get(endpoint)

	if err != nil {
		return nil, resp, err
	}

	if len(result.Vulnerabilities) == 0 {
		return nil, resp, fmt.Errorf("CVE not found: %s", cveID)
	}

	return &result.Vulnerabilities[0], resp, nil
}
