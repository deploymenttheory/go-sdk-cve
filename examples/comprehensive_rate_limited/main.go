package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/deploymenttheory/go-sdk-cve/nvd"
	"github.com/deploymenttheory/go-sdk-cve/nvd/cve_history"
	"github.com/deploymenttheory/go-sdk-cve/nvd/cves"
	"go.uber.org/zap"
)

const requestDelay = 7 * time.Second

func main() {
	client, err := nvd.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Println("=== NVD CVE API SDK Comprehensive Example (Rate Limited) ===")
	fmt.Println()
	fmt.Println("This example adds 7-second delays between requests to respect")
	fmt.Println("the NVD API rate limit of 5 requests per 30 seconds (without API key).")
	fmt.Println("With an API key, you can reduce this delay to 0.6 seconds (50 req/30s).")
	fmt.Println()

	demonstrateGetByID(client)
	time.Sleep(requestDelay)

	demonstrateKeywordSearch(client)
	time.Sleep(requestDelay)

	demonstrateSeverityFiltering(client)
	time.Sleep(requestDelay)

	demonstrateKEVCatalog(client)
	time.Sleep(requestDelay)

	demonstrateDateRangeSearch(client)
	time.Sleep(requestDelay)

	demonstrateChangeHistory(client)
}

func demonstrateGetByID(client *nvd.Client) {
	fmt.Println("1. Get Specific CVE by ID")
	fmt.Println("-------------------------")

	vuln, _, err := client.CVEs.GetByID(context.Background(), "CVE-2023-12345")
	if err != nil {
		if nvd.IsNotFound(err) {
			fmt.Println("CVE not found (expected for demo)")
		} else {
			log.Printf("Error: %v", err)
		}
		return
	}

	fmt.Printf("CVE: %s\n", vuln.CVE.ID)
	fmt.Printf("Published: %s\n", vuln.CVE.Published.Format("2006-01-02"))
	fmt.Printf("Status: %s\n", vuln.CVE.VulnStatus)
	fmt.Println()
}

func demonstrateKeywordSearch(client *nvd.Client) {
	fmt.Println("2. Search CVEs by Keyword")
	fmt.Println("-------------------------")

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		KeywordSearch:  "Apache Struts",
		ResultsPerPage: 10,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Found %d CVEs matching 'Apache Struts'\n", resp.TotalResults)
	fmt.Printf("Showing first %d:\n", len(resp.Vulnerabilities))
	for i, vuln := range resp.Vulnerabilities {
		if i >= 3 {
			break
		}
		fmt.Printf("  - %s (Published: %s)\n",
			vuln.CVE.ID,
			vuln.CVE.Published.Format("2006-01-02"))
	}
	fmt.Println()
}

func demonstrateSeverityFiltering(client *nvd.Client) {
	fmt.Println("3. Filter by CVSS v3 Severity")
	fmt.Println("------------------------------")

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		CVSSV3Severity: cves.SeverityCritical,
		ResultsPerPage: 10,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Found %d CRITICAL severity CVEs\n", resp.TotalResults)
	fmt.Printf("Showing first %d:\n", len(resp.Vulnerabilities))
	for i, vuln := range resp.Vulnerabilities {
		if i >= 3 {
			break
		}
		cve := vuln.CVE
		score := 0.0
		if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
			score = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		}
		fmt.Printf("  - %s: CVSS %.1f\n", cve.ID, score)
	}
	fmt.Println()
}

func demonstrateKEVCatalog(client *nvd.Client) {
	fmt.Println("4. CISA Known Exploited Vulnerabilities")
	fmt.Println("---------------------------------------")

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		HasKEV:         true,
		ResultsPerPage: 10,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Found %d CVEs in CISA KEV catalog\n", resp.TotalResults)
	fmt.Printf("Showing first %d:\n", len(resp.Vulnerabilities))
	for i, vuln := range resp.Vulnerabilities {
		if i >= 3 {
			break
		}
		cve := vuln.CVE
		fmt.Printf("  - %s", cve.ID)
		if cve.CISAVulnerabilityName != nil {
			fmt.Printf(": %s", *cve.CISAVulnerabilityName)
		}
		fmt.Println()
	}
	fmt.Println()
}

func demonstrateDateRangeSearch(client *nvd.Client) {
	fmt.Println("5. Date Range Search (Last 7 Days)")
	fmt.Println("----------------------------------")

	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -7)

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		LastModStartDate: &startDate,
		LastModEndDate:   &endDate,
		ResultsPerPage:   10,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Found %d CVEs modified in last 7 days\n", resp.TotalResults)
	if len(resp.Vulnerabilities) > 0 {
		fmt.Printf("Most recent:\n")
		for i, vuln := range resp.Vulnerabilities {
			if i >= 3 {
				break
			}
			fmt.Printf("  - %s (Modified: %s)\n",
				vuln.CVE.ID,
				vuln.CVE.LastModified.Format("2006-01-02"))
		}
	}
	fmt.Println()
}

func demonstrateChangeHistory(client *nvd.Client) {
	fmt.Println("6. CVE Change History")
	fmt.Println("---------------------")

	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -7)

	resp, _, err := client.CVEHistory.List(context.Background(), &cve_history.ListRequest{
		ChangeStartDate: &startDate,
		ChangeEndDate:   &endDate,
		ResultsPerPage:  10,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Found %d change events in last 7 days\n", resp.TotalResults)
	if len(resp.CVEChanges) > 0 {
		fmt.Printf("Recent changes:\n")
		for i, change := range resp.CVEChanges {
			if i >= 3 {
				break
			}
			fmt.Printf("  - %s: %s (%s)\n",
				change.Change.CVEID,
				change.Change.EventName,
				change.Change.Created.Format("2006-01-02"))
		}
	}
	fmt.Println()
}

func init() {
	logger, _ := zap.NewProduction()
	zap.ReplaceGlobals(logger)
}
