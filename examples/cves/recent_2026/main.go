package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/deploymenttheory/go-sdk-cve/nvd"
	"github.com/deploymenttheory/go-sdk-cve/nvd/cves"
)

func main() {
	client, err := nvd.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Println("Searching for CVEs modified in March 2026...")
	fmt.Println()

	startDate := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC)

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		LastModStartDate: &startDate,
		LastModEndDate:   &endDate,
		ResultsPerPage:   20,
	})
	if err != nil {
		log.Fatalf("Failed to search CVEs: %v", err)
	}

	fmt.Printf("Found %d CVEs modified in March 2026\n\n", resp.TotalResults)

	if len(resp.Vulnerabilities) == 0 {
		fmt.Println("No CVEs found for this period.")
		return
	}

	for i, vuln := range resp.Vulnerabilities {
		cve := vuln.CVE
		fmt.Printf("%d. %s\n", i+1, cve.ID)
		fmt.Printf("   Published: %s\n", cve.Published.Format("2006-01-02 15:04:05"))
		fmt.Printf("   Status: %s\n", cve.VulnStatus)

		if len(cve.Descriptions) > 0 {
			desc := cve.Descriptions[0].Value
			if len(desc) > 150 {
				desc = desc[:150] + "..."
			}
			fmt.Printf("   Description: %s\n", desc)
		}

		if cve.Metrics != nil {
			if len(cve.Metrics.CVSSMetricV31) > 0 {
				metric := cve.Metrics.CVSSMetricV31[0]
				fmt.Printf("   CVSS v3.1: %.1f (%s)\n", metric.CVSSData.BaseScore, metric.CVSSData.BaseSeverity)
			} else if len(cve.Metrics.CVSSMetricV4) > 0 {
				metric := cve.Metrics.CVSSMetricV4[0]
				fmt.Printf("   CVSS v4.0: %.1f (%s)\n", metric.CVSSData.BaseScore, metric.CVSSData.BaseSeverity)
			}
		}

		if cve.CISAVulnerabilityName != nil {
			fmt.Printf("   ⚠️  CISA KEV: %s\n", *cve.CISAVulnerabilityName)
		}

		fmt.Println()
	}
}
