package cves

import (
	"fmt"
	"time"

	"github.com/deploymenttheory/go-sdk-cve/nvd/shared/nvdtime"
)

type CVEResponse struct {
	ResultsPerPage  int                 `json:"resultsPerPage"`
	StartIndex      int                 `json:"startIndex"`
	TotalResults    int                 `json:"totalResults"`
	Format          string              `json:"format"`
	Version         string              `json:"version"`
	Timestamp       nvdtime.Time        `json:"timestamp"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type VulnerabilityItem struct {
	CVE CVE `json:"cve"`
}

type CVE struct {
	ID                    string          `json:"id"`
	SourceIdentifier      string          `json:"sourceIdentifier"`
	Published             nvdtime.Time    `json:"published"`
	LastModified          nvdtime.Time    `json:"lastModified"`
	VulnStatus            string          `json:"vulnStatus"`
	EvaluatorComment      *string         `json:"evaluatorComment,omitempty"`
	EvaluatorImpact       *string         `json:"evaluatorImpact,omitempty"`
	EvaluatorSolution     *string         `json:"evaluatorSolution,omitempty"`
	CISAExploitAdd        *string         `json:"cisaExploitAdd,omitempty"`
	CISAActionDue         *string         `json:"cisaActionDue,omitempty"`
	CISARequiredAction    *string         `json:"cisaRequiredAction,omitempty"`
	CISAVulnerabilityName *string         `json:"cisaVulnerabilityName,omitempty"`
	CVETags               []CVETag        `json:"cveTags,omitempty"`
	Descriptions          []Description   `json:"descriptions"`
	Metrics               *Metrics        `json:"metrics,omitempty"`
	Weaknesses            []Weakness      `json:"weaknesses,omitempty"`
	Configurations        []Configuration `json:"configurations,omitempty"`
	References            []Reference     `json:"references"`
	VendorComments        []VendorComment `json:"vendorComments,omitempty"`
}

type CVETag struct {
	SourceIdentifier string   `json:"sourceIdentifier"`
	Tags             []string `json:"tags"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics struct {
	CVSSMetricV2  []CVSSMetricV2  `json:"cvssMetricV2,omitempty"`
	CVSSMetricV30 []CVSSMetricV30 `json:"cvssMetricV30,omitempty"`
	CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31,omitempty"`
	CVSSMetricV4  []CVSSMetricV4  `json:"cvssMetricV4,omitempty"`
}

type CVSSMetricV2 struct {
	Source                  string     `json:"source"`
	Type                    string     `json:"type"`
	CVSSData                CVSSDataV2 `json:"cvssData"`
	BaseSeverity            string     `json:"baseSeverity"`
	ExploitabilityScore     float64    `json:"exploitabilityScore"`
	ImpactScore             float64    `json:"impactScore"`
	ACInsufInfo             bool       `json:"acInsufInfo"`
	ObtainAllPrivilege      bool       `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool       `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool       `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool       `json:"userInteractionRequired"`
}

type CVSSDataV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
}

type CVSSMetricV30 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CVSSData            CVSSDataV30 `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
}

type CVSSDataV30 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

type CVSSMetricV31 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CVSSData            CVSSDataV31 `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
}

type CVSSDataV31 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

type CVSSMetricV4 struct {
	Source              string     `json:"source"`
	Type                string     `json:"type"`
	CVSSData            CVSSDataV4 `json:"cvssData"`
	ExploitabilityScore *float64   `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64   `json:"impactScore,omitempty"`
}

type CVSSDataV4 struct {
	Version                   string  `json:"version"`
	VectorString              string  `json:"vectorString"`
	AttackVector              string  `json:"attackVector"`
	AttackComplexity          string  `json:"attackComplexity"`
	AttackRequirements        string  `json:"attackRequirements"`
	PrivilegesRequired        string  `json:"privilegesRequired"`
	UserInteraction           string  `json:"userInteraction"`
	VulnConfidentialityImpact string  `json:"vulnConfidentialityImpact"`
	VulnIntegrityImpact       string  `json:"vulnIntegrityImpact"`
	VulnAvailabilityImpact    string  `json:"vulnAvailabilityImpact"`
	SubConfidentialityImpact  string  `json:"subConfidentialityImpact"`
	SubIntegrityImpact        string  `json:"subIntegrityImpact"`
	SubAvailabilityImpact     string  `json:"subAvailabilityImpact"`
	BaseScore                 float64 `json:"baseScore"`
	BaseSeverity              string  `json:"baseSeverity"`
}

type Weakness struct {
	Source      string        `json:"source"`
	Type        string        `json:"type"`
	Description []Description `json:"description"`
}

type Configuration struct {
	Nodes    []ConfigNode `json:"nodes"`
	Operator *string      `json:"operator,omitempty"`
	Negate   *bool        `json:"negate,omitempty"`
}

type ConfigNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type CPEMatch struct {
	Vulnerable            bool    `json:"vulnerable"`
	Criteria              string  `json:"criteria"`
	MatchCriteriaID       string  `json:"matchCriteriaId"`
	VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"`
}

type VendorComment struct {
	Organization string       `json:"organization"`
	Comment      string       `json:"comment"`
	LastModified nvdtime.Time `json:"lastModified"`
}

type ListRequest struct {
	CPEName            string
	CVEID              string
	CVETag             string
	CVSSV2Metrics      string
	CVSSV2Severity     string
	CVSSV3Metrics      string
	CVSSV3Severity     string
	CVSSV4Metrics      string
	CVSSV4Severity     string
	CWEID              string
	HasCertAlerts      bool
	HasCertNotes       bool
	HasKEV             bool
	HasOVAL            bool
	IsVulnerable       bool
	KeywordSearch      string
	KeywordExactMatch  bool
	LastModStartDate   *time.Time
	LastModEndDate     *time.Time
	PubStartDate       *time.Time
	PubEndDate         *time.Time
	KEVStartDate       *time.Time
	KEVEndDate         *time.Time
	NoRejected         bool
	ResultsPerPage     int
	StartIndex         int
	SourceIdentifier   string
	VirtualMatchString string
	VersionStart       string
	VersionStartType   string
	VersionEnd         string
	VersionEndType     string
}

func (r *ListRequest) ToQueryParams() map[string]string {
	params := make(map[string]string)

	if r.CPEName != "" {
		params["cpeName"] = r.CPEName
	}
	if r.CVEID != "" {
		params["cveId"] = r.CVEID
	}
	if r.CVETag != "" {
		params["cveTag"] = r.CVETag
	}
	if r.CVSSV2Metrics != "" {
		params["cvssV2Metrics"] = r.CVSSV2Metrics
	}
	if r.CVSSV2Severity != "" {
		params["cvssV2Severity"] = r.CVSSV2Severity
	}
	if r.CVSSV3Metrics != "" {
		params["cvssV3Metrics"] = r.CVSSV3Metrics
	}
	if r.CVSSV3Severity != "" {
		params["cvssV3Severity"] = r.CVSSV3Severity
	}
	if r.CVSSV4Metrics != "" {
		params["cvssV4Metrics"] = r.CVSSV4Metrics
	}
	if r.CVSSV4Severity != "" {
		params["cvssV4Severity"] = r.CVSSV4Severity
	}
	if r.CWEID != "" {
		params["cweId"] = r.CWEID
	}
	if r.HasCertAlerts {
		params["hasCertAlerts"] = ""
	}
	if r.HasCertNotes {
		params["hasCertNotes"] = ""
	}
	if r.HasKEV {
		params["hasKev"] = ""
	}
	if r.HasOVAL {
		params["hasOval"] = ""
	}
	if r.IsVulnerable {
		params["isVulnerable"] = ""
	}
	if r.KeywordSearch != "" {
		params["keywordSearch"] = r.KeywordSearch
	}
	if r.KeywordExactMatch {
		params["keywordExactMatch"] = ""
	}
	if r.LastModStartDate != nil {
		params["lastModStartDate"] = r.LastModStartDate.Format(time.RFC3339)
	}
	if r.LastModEndDate != nil {
		params["lastModEndDate"] = r.LastModEndDate.Format(time.RFC3339)
	}
	if r.PubStartDate != nil {
		params["pubStartDate"] = r.PubStartDate.Format(time.RFC3339)
	}
	if r.PubEndDate != nil {
		params["pubEndDate"] = r.PubEndDate.Format(time.RFC3339)
	}
	if r.KEVStartDate != nil {
		params["kevStartDate"] = r.KEVStartDate.Format(time.RFC3339)
	}
	if r.KEVEndDate != nil {
		params["kevEndDate"] = r.KEVEndDate.Format(time.RFC3339)
	}
	if r.NoRejected {
		params["noRejected"] = ""
	}
	if r.ResultsPerPage > 0 {
		params["resultsPerPage"] = fmt.Sprintf("%d", r.ResultsPerPage)
	}
	if r.StartIndex > 0 {
		params["startIndex"] = fmt.Sprintf("%d", r.StartIndex)
	}
	if r.SourceIdentifier != "" {
		params["sourceIdentifier"] = r.SourceIdentifier
	}
	if r.VirtualMatchString != "" {
		params["virtualMatchString"] = r.VirtualMatchString
	}
	if r.VersionStart != "" {
		params["versionStart"] = r.VersionStart
	}
	if r.VersionStartType != "" {
		params["versionStartType"] = r.VersionStartType
	}
	if r.VersionEnd != "" {
		params["versionEnd"] = r.VersionEnd
	}
	if r.VersionEndType != "" {
		params["versionEndType"] = r.VersionEndType
	}

	return params
}
