package cve_history

const (
	EventCVEReceived         = "CVE Received"
	EventInitialAnalysis     = "Initial Analysis"
	EventReanalysis          = "Reanalysis"
	EventCVEModified         = "CVE Modified"
	EventModifiedAnalysis    = "Modified Analysis"
	EventCVETranslated       = "CVE Translated"
	EventVendorComment       = "Vendor Comment"
	EventCVESourceUpdate     = "CVE Source Update"
	EventCPEDeprecationRemap = "CPE Deprecation Remap"
	EventCWERemap            = "CWE Remap"
	EventReferenceTagUpdate  = "Reference Tag Update"
	EventCVERejected         = "CVE Rejected"
	EventCVEUnrejected       = "CVE Unrejected"
	EventCVECISAKEVUpdate    = "CVE CISA KEV Update"
)

const (
	ActionAdded   = "Added"
	ActionChanged = "Changed"
	ActionRemoved = "Removed"
)
