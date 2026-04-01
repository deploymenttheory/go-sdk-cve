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

	startDate := time.Now().AddDate(0, 0, -30)
	endDate := time.Now()

	req := cves.NewListRequest().
		WithKeywordSearch("Apache").
		WithCVSSV3Severity(cves.SeverityCritical).
		WithNoRejected().
		WithLastModDateRange(startDate, endDate).
		WithResultsPerPage(100)

	resp, _, err := client.CVEs.List(context.Background(), req)
	if err != nil {
		log.Fatalf("Failed to list CVEs: %v", err)
	}

	fmt.Printf("Found %d CRITICAL Apache CVEs modified in last 30 days\n\n", resp.TotalResults)

	for i, vuln := range resp.Vulnerabilities {
		if i >= 10 {
			break
		}
		cve := vuln.CVE
		fmt.Printf("%s - %s\n", cve.ID, cve.Published.Format("2006-01-02"))

		if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
			metric := cve.Metrics.CVSSMetricV31[0]
			fmt.Printf("  CVSS: %.1f (%s)\n",
				metric.CVSSData.BaseScore,
				metric.CVSSData.BaseSeverity)
		}

		if len(cve.Descriptions) > 0 {
			desc := cve.Descriptions[0].Value
			if len(desc) > 80 {
				desc = desc[:80] + "..."
			}
			fmt.Printf("  %s\n", desc)
		}
		fmt.Println()
	}
}
