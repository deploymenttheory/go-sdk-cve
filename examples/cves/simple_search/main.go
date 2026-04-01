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

	fmt.Println("Searching for recent Apache Struts vulnerabilities...")
	fmt.Println()

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		KeywordSearch:  "Apache Struts",
		ResultsPerPage: 5,
	})
	if err != nil {
		log.Fatalf("Failed to search CVEs: %v", err)
	}

	fmt.Printf("Found %d total CVEs (showing first %d)\n\n", resp.TotalResults, len(resp.Vulnerabilities))

	for i, vuln := range resp.Vulnerabilities {
		cve := vuln.CVE
		fmt.Printf("%d. %s\n", i+1, cve.ID)
		fmt.Printf("   Published: %s\n", cve.Published.Format("2006-01-02"))
		fmt.Printf("   Status: %s\n", cve.VulnStatus)

		if len(cve.Descriptions) > 0 {
			desc := cve.Descriptions[0].Value
			if len(desc) > 100 {
				desc = desc[:100] + "..."
			}
			fmt.Printf("   Description: %s\n", desc)
		}

		if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
			metric := cve.Metrics.CVSSMetricV31[0]
			fmt.Printf("   CVSS: %.1f (%s)\n", metric.CVSSData.BaseScore, metric.CVSSData.BaseSeverity)
		}

		fmt.Println()
	}
}
