package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/deploymenttheory/go-sdk-cve/nvd"
	"github.com/deploymenttheory/go-sdk-cve/nvd/cve_history"
)

func main() {
	client, err := nvd.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	startDate := time.Now().AddDate(0, 0, -30)
	endDate := time.Now()

	resp, _, err := client.CVEHistory.List(context.Background(), &cve_history.ListRequest{
		ChangeStartDate: &startDate,
		ChangeEndDate:   &endDate,
		EventName:       "Initial Analysis",
		ResultsPerPage:  100,
	})
	if err != nil {
		log.Fatalf("Failed to list CVE history: %v", err)
	}

	fmt.Printf("Found %d CVE changes (Initial Analysis) in last 30 days\n\n", resp.TotalResults)

	for i, change := range resp.CVEChanges {
		if i >= 10 {
			break
		}
		c := change.Change
		fmt.Printf("CVE: %s\n", c.CVEID)
		fmt.Printf("Event: %s\n", c.EventName)
		fmt.Printf("Date: %s\n", c.Created.Format("2006-01-02 15:04:05"))
		fmt.Printf("Source: %s\n", c.SourceIdentifier)

		if len(c.Details) > 0 {
			fmt.Printf("Changes:\n")
			for _, detail := range c.Details {
				fmt.Printf("  - %s: %s\n", detail.Action, detail.Type)
				if detail.NewValue != nil {
					fmt.Printf("    New: %s\n", *detail.NewValue)
				}
			}
		}
		fmt.Println("---")
	}
}
