package cves_test

import (
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-cve/nvd/cves"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListRequest_ToQueryParams(t *testing.T) {
	startDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

	req := &cves.ListRequest{
		KeywordSearch:    "Apache",
		CVSSV3Severity:   cves.SeverityCritical,
		NoRejected:       true,
		LastModStartDate: &startDate,
		LastModEndDate:   &endDate,
		ResultsPerPage:   100,
	}

	params := req.ToQueryParams()

	assert.Equal(t, "Apache", params["keywordSearch"])
	assert.Equal(t, "CRITICAL", params["cvssV3Severity"])
	assert.Equal(t, "", params["noRejected"])
	assert.Equal(t, "2024-01-01T00:00:00Z", params["lastModStartDate"])
	assert.Equal(t, "2024-12-31T23:59:59Z", params["lastModEndDate"])
	assert.Equal(t, "100", params["resultsPerPage"])
}

func TestListRequest_Helpers(t *testing.T) {
	startDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

	req := cves.NewListRequest().
		WithKeywordSearch("Apache").
		WithCVSSV3Severity(cves.SeverityCritical).
		WithNoRejected().
		WithLastModDateRange(startDate, endDate).
		WithResultsPerPage(100)

	assert.Equal(t, "Apache", req.KeywordSearch)
	assert.Equal(t, "CRITICAL", req.CVSSV3Severity)
	assert.True(t, req.NoRejected)
	assert.Equal(t, &startDate, req.LastModStartDate)
	assert.Equal(t, &endDate, req.LastModEndDate)
	assert.Equal(t, 100, req.ResultsPerPage)
}

func TestEnumConstants(t *testing.T) {
	assert.Equal(t, "LOW", cves.SeverityLow)
	assert.Equal(t, "MEDIUM", cves.SeverityMedium)
	assert.Equal(t, "HIGH", cves.SeverityHigh)
	assert.Equal(t, "CRITICAL", cves.SeverityCritical)

	assert.Equal(t, "disputed", cves.CVETagDisputed)
	assert.Equal(t, "including", cves.VersionTypeIncluding)
	assert.Equal(t, "excluding", cves.VersionTypeExcluding)
}

func TestListRequest_EmptyParams(t *testing.T) {
	req := &cves.ListRequest{}
	params := req.ToQueryParams()
	require.NotNil(t, params)
	assert.Empty(t, params)
}

func TestListRequest_BooleanParams(t *testing.T) {
	req := &cves.ListRequest{
		HasKEV:            true,
		HasCertAlerts:     true,
		NoRejected:        true,
		IsVulnerable:      true,
		KeywordExactMatch: true,
	}

	params := req.ToQueryParams()

	_, hasKEV := params["hasKev"]
	assert.True(t, hasKEV)

	_, hasCertAlerts := params["hasCertAlerts"]
	assert.True(t, hasCertAlerts)

	_, noRejected := params["noRejected"]
	assert.True(t, noRejected)

	_, isVulnerable := params["isVulnerable"]
	assert.True(t, isVulnerable)

	_, keywordExactMatch := params["keywordExactMatch"]
	assert.True(t, keywordExactMatch)
}
