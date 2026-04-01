package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/deploymenttheory/go-sdk-cve/nvd"
	"github.com/deploymenttheory/go-sdk-cve/nvd/cves"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}

	client, err := nvd.NewClient(
		nvd.ConfigFromEnv(),
		nvd.WithLogger(logger),
		nvd.WithTimeout(60*time.Second),
		nvd.WithRetryCount(5),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	startDate := time.Now().AddDate(0, 0, -7)
	endDate := time.Now()

	fmt.Printf("Fetching CVEs modified between %s and %s\n\n",
		startDate.Format("2006-01-02"),
		endDate.Format("2006-01-02"))

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		LastModStartDate: &startDate,
		LastModEndDate:   &endDate,
		NoRejected:       true,
	})
	if err != nil {
		log.Fatalf("Failed to list CVEs: %v", err)
	}

	fmt.Printf("Total CVEs modified: %d\n\n", resp.TotalResults)

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, vuln := range resp.Vulnerabilities {
		cve := vuln.CVE

		if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
			severity := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
			switch severity {
			case "CRITICAL":
				criticalCount++
			case "HIGH":
				highCount++
			case "MEDIUM":
				mediumCount++
			case "LOW":
				lowCount++
			}
		}
	}

	fmt.Printf("Severity Distribution:\n")
	fmt.Printf("  CRITICAL: %d\n", criticalCount)
	fmt.Printf("  HIGH: %d\n", highCount)
	fmt.Printf("  MEDIUM: %d\n", mediumCount)
	fmt.Printf("  LOW: %d\n", lowCount)
	fmt.Println()

	fmt.Printf("Sample CVEs:\n")
	for i, vuln := range resp.Vulnerabilities {
		if i >= 5 {
			break
		}
		cve := vuln.CVE
		fmt.Printf("\n%s\n", cve.ID)
		fmt.Printf("  Modified: %s\n", cve.LastModified.Format("2006-01-02 15:04:05"))

		if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
			metric := cve.Metrics.CVSSMetricV31[0]
			fmt.Printf("  Severity: %s (%.1f)\n",
				metric.CVSSData.BaseSeverity,
				metric.CVSSData.BaseScore)
		}

		if len(cve.Descriptions) > 0 {
			desc := cve.Descriptions[0].Value
			if len(desc) > 100 {
				desc = desc[:100] + "..."
			}
			fmt.Printf("  Description: %s\n", desc)
		}
	}
}
