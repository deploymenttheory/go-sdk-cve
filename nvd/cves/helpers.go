package cves

import "time"

func NewListRequest() *ListRequest {
	return &ListRequest{}
}

func (r *ListRequest) WithKeywordSearch(keyword string) *ListRequest {
	r.KeywordSearch = keyword
	return r
}

func (r *ListRequest) WithKeywordExactMatch() *ListRequest {
	r.KeywordExactMatch = true
	return r
}

func (r *ListRequest) WithCVSSV3Severity(severity string) *ListRequest {
	r.CVSSV3Severity = severity
	return r
}

func (r *ListRequest) WithNoRejected() *ListRequest {
	r.NoRejected = true
	return r
}

func (r *ListRequest) WithHasKEV() *ListRequest {
	r.HasKEV = true
	return r
}

func (r *ListRequest) WithLastModDateRange(start, end time.Time) *ListRequest {
	r.LastModStartDate = &start
	r.LastModEndDate = &end
	return r
}

func (r *ListRequest) WithPubDateRange(start, end time.Time) *ListRequest {
	r.PubStartDate = &start
	r.PubEndDate = &end
	return r
}

func (r *ListRequest) WithCPEName(cpeName string) *ListRequest {
	r.CPEName = cpeName
	return r
}

func (r *ListRequest) WithCWEID(cweID string) *ListRequest {
	r.CWEID = cweID
	return r
}

func (r *ListRequest) WithResultsPerPage(count int) *ListRequest {
	r.ResultsPerPage = count
	return r
}
