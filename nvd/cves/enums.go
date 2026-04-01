package cves

const (
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

const (
	CVETagDisputed                 = "disputed"
	CVETagUnsupportedWhenAssigned  = "unsupported-when-assigned"
	CVETagExclusivelyHostedService = "exclusively-hosted-service"
)

const (
	VersionTypeIncluding = "including"
	VersionTypeExcluding = "excluding"
)

const (
	VulnStatusAnalyzed           = "Analyzed"
	VulnStatusModified           = "Modified"
	VulnStatusAwaitingAnalysis   = "Awaiting Analysis"
	VulnStatusUndergoingAnalysis = "Undergoing Analysis"
	VulnStatusRejected           = "Rejected"
)
