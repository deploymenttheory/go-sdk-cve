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

	commonCWEs := map[string]string{
		"CWE-79":  "Cross-site Scripting (XSS)",
		"CWE-89":  "SQL Injection",
		"CWE-287": "Improper Authentication",
		"CWE-502": "Deserialization of Untrusted Data",
		"CWE-798": "Use of Hard-coded Credentials",
	}

	fmt.Println("Common Weakness Enumeration (CWE) Analysis")
	fmt.Println("==========================================")
	fmt.Println()

	for cweID, cweName := range commonCWEs {
		resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
			CWEID:          cweID,
			NoRejected:     true,
			ResultsPerPage: 100,
		})
		if err != nil {
			log.Printf("Error fetching %s: %v", cweID, err)
			continue
		}

		fmt.Printf("%s - %s\n", cweID, cweName)
		fmt.Printf("Total CVEs: %d\n", resp.TotalResults)

		if len(resp.Vulnerabilities) > 0 {
			severityCounts := make(map[string]int)
			kevCount := 0

			for _, vuln := range resp.Vulnerabilities {
				cve := vuln.CVE

				if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
					severity := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
					severityCounts[severity]++
				}

				if cve.CISARequiredAction != nil {
					kevCount++
				}
			}

			fmt.Printf("Severity breakdown:\n")
			for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
				if count, ok := severityCounts[sev]; ok {
					fmt.Printf("  %s: %d\n", sev, count)
				}
			}

			if kevCount > 0 {
				fmt.Printf("In CISA KEV: %d\n", kevCount)
			}

			fmt.Printf("\nRecent examples:\n")
			for i, vuln := range resp.Vulnerabilities {
				if i >= 3 {
					break
				}
				cve := vuln.CVE
				fmt.Printf("  - %s (%s)\n", cve.ID, cve.Published.Format("2006-01-02"))
			}
		}

		fmt.Println()
	}
}
