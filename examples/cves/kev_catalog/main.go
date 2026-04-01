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
		HasKEV:         true,
		NoRejected:     true,
		ResultsPerPage: 100,
	})
	if err != nil {
		log.Fatalf("Failed to list CVEs: %v", err)
	}

	fmt.Printf("Found %d CVEs in CISA Known Exploited Vulnerabilities Catalog\n\n", resp.TotalResults)

	for i, vuln := range resp.Vulnerabilities {
		if i >= 20 {
			fmt.Printf("... and %d more\n", resp.TotalResults-20)
			break
		}

		cve := vuln.CVE
		fmt.Printf("CVE: %s\n", cve.ID)

		if cve.CISAVulnerabilityName != nil {
			fmt.Printf("  Name: %s\n", *cve.CISAVulnerabilityName)
		}
		if cve.CISARequiredAction != nil {
			fmt.Printf("  Required Action: %s\n", *cve.CISARequiredAction)
		}
		if cve.CISAActionDue != nil {
			fmt.Printf("  Due Date: %s\n", *cve.CISAActionDue)
		}
		if cve.CISAExploitAdd != nil {
			fmt.Printf("  Added to KEV: %s\n", *cve.CISAExploitAdd)
		}

		if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
			metric := cve.Metrics.CVSSMetricV31[0]
			fmt.Printf("  CVSS: %.1f (%s)\n",
				metric.CVSSData.BaseScore,
				metric.CVSSData.BaseSeverity)
		}
		fmt.Println()
	}
}
