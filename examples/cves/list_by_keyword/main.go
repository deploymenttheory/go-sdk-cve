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
		KeywordSearch:  "Microsoft Windows",
		ResultsPerPage: 100,
		NoRejected:     true,
	})
	if err != nil {
		log.Fatalf("Failed to list CVEs: %v", err)
	}

	fmt.Printf("Found %d CVEs matching 'Microsoft Windows'\n\n", resp.TotalResults)

	for i, vuln := range resp.Vulnerabilities {
		if i >= 10 {
			break
		}
		cve := vuln.CVE
		fmt.Printf("CVE: %s\n", cve.ID)
		fmt.Printf("Published: %s\n", cve.Published.Format("2006-01-02"))
		fmt.Printf("Status: %s\n", cve.VulnStatus)
		if len(cve.Descriptions) > 0 {
			fmt.Printf("Description: %s\n", cve.Descriptions[0].Value)
		}
		fmt.Println("---")
	}
}
