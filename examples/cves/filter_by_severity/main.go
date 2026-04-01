package main

import (
	"context"
	"fmt"
	"log"

	"github.com/deploymenttheory/go-sdk-cve/nvd"
	"github.com/deploymenttheory/go-sdk-cve/nvd/cves"
)

func main() {
	client, err := nvd.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		CVSSV3Severity: "CRITICAL",
		HasKEV:         true,
		NoRejected:     true,
		ResultsPerPage: 50,
	})
	if err != nil {
		log.Fatalf("Failed to list CVEs: %v", err)
	}

	fmt.Printf("Found %d CRITICAL CVEs in CISA KEV Catalog\n\n", resp.TotalResults)

	for i, vuln := range resp.Vulnerabilities {
		if i >= 20 {
			break
		}
		cve := vuln.CVE
		fmt.Printf("%s - %s\n", cve.ID, cve.Published.Format("2006-01-02"))

		if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
			score := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			severity := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
			fmt.Printf("  CVSS: %.1f (%s)\n", score, severity)
		}

		if cve.CISARequiredAction != nil {
			fmt.Printf("  CISA Action: %s\n", *cve.CISARequiredAction)
		}
		if cve.CISAActionDue != nil {
			fmt.Printf("  Due Date: %s\n", *cve.CISAActionDue)
		}
		fmt.Println()
	}
}
