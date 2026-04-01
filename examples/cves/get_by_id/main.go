package main

import (
	"context"
	"fmt"
	"log"

	"github.com/deploymenttheory/go-sdk-cve/nvd"
)

func main() {
	client, err := nvd.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	vuln, _, err := client.CVEs.GetByID(context.Background(), "CVE-2019-1010218")
	if err != nil {
		log.Fatalf("Failed to get CVE: %v", err)
	}

	cve := vuln.CVE
	fmt.Printf("CVE ID: %s\n", cve.ID)
	fmt.Printf("Published: %s\n", cve.Published.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last Modified: %s\n", cve.LastModified.Format("2006-01-02 15:04:05"))
	fmt.Printf("Status: %s\n", cve.VulnStatus)
	fmt.Printf("Source: %s\n\n", cve.SourceIdentifier)

	if len(cve.Descriptions) > 0 {
		fmt.Printf("Description:\n%s\n\n", cve.Descriptions[0].Value)
	}

	if cve.Metrics != nil {
		if len(cve.Metrics.CVSSMetricV31) > 0 {
			metric := cve.Metrics.CVSSMetricV31[0]
			fmt.Printf("CVSS v3.1:\n")
			fmt.Printf("  Base Score: %.1f (%s)\n", metric.CVSSData.BaseScore, metric.CVSSData.BaseSeverity)
			fmt.Printf("  Vector: %s\n\n", metric.CVSSData.VectorString)
		}
	}

	if len(cve.Weaknesses) > 0 {
		fmt.Printf("Weaknesses:\n")
		for _, weakness := range cve.Weaknesses {
			for _, desc := range weakness.Description {
				fmt.Printf("  - %s (%s)\n", desc.Value, weakness.Source)
			}
		}
		fmt.Println()
	}

	if len(cve.References) > 0 {
		fmt.Printf("References (%d):\n", len(cve.References))
		for i, ref := range cve.References {
			if i >= 5 {
				fmt.Printf("  ... and %d more\n", len(cve.References)-5)
				break
			}
			fmt.Printf("  - %s\n", ref.URL)
		}
	}
}
