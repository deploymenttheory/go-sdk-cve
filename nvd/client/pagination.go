package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"resty.dev/v3"
)

type nvdPaginatedPage struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities json.RawMessage `json:"vulnerabilities,omitempty"`
	CVEChanges      json.RawMessage `json:"cveChanges,omitempty"`
}

func (t *Transport) executePaginated(req *resty.Request, path string, mergePage func([]byte) error) (*resty.Response, error) {
	currentParams := make(map[string]string)
	for k, vs := range req.QueryParams {
		if len(vs) > 0 {
			currentParams[k] = vs[0]
		}
	}
	if currentParams["startIndex"] == "" {
		currentParams["startIndex"] = "0"
	}
	if currentParams["resultsPerPage"] == "" {
		currentParams["resultsPerPage"] = strconv.Itoa(DefaultResultsPerPage)
	}

	templateHeaders := make(map[string]string)
	for k, vs := range req.Header {
		if len(vs) > 0 {
			templateHeaders[k] = vs[0]
		}
	}

	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	var lastResp *resty.Response
	for {
		var pageResp nvdPaginatedPage
		pageReq := t.client.R().
			SetContext(ctx).
			SetResult(&pageResp).
			SetResponseBodyUnlimitedReads(true)
		for k, v := range currentParams {
			if v != "" {
				pageReq.SetQueryParam(k, v)
			}
		}
		for k, v := range templateHeaders {
			if v != "" {
				pageReq.SetHeader(k, v)
			}
		}

		resp, err := t.executeRequest(pageReq, "GET", path)
		lastResp = resp
		if err != nil {
			return lastResp, err
		}

		var resultsData json.RawMessage
		if len(pageResp.Vulnerabilities) > 0 {
			resultsData = pageResp.Vulnerabilities
		} else if len(pageResp.CVEChanges) > 0 {
			resultsData = pageResp.CVEChanges
		}

		if len(resultsData) > 0 {
			if err := mergePage(resultsData); err != nil {
				return lastResp, fmt.Errorf("merge page: %w", err)
			}
		}

		startIndex, _ := strconv.Atoi(currentParams["startIndex"])
		resultsPerPage, _ := strconv.Atoi(currentParams["resultsPerPage"])
		if resultsPerPage <= 0 {
			resultsPerPage = DefaultResultsPerPage
		}

		if len(resultsData) == 0 || startIndex+resultsPerPage >= pageResp.TotalResults {
			break
		}
		currentParams["startIndex"] = strconv.Itoa(startIndex + resultsPerPage)
	}
	return lastResp, nil
}
