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

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	cfg := nvd.ConfigFromEnv()
	client, err := nvd.NewClient(
		cfg,
		nvd.WithLogger(logger),
		nvd.WithTimeout(60*time.Second),
		nvd.WithRetryCount(5),
		nvd.WithRetryWaitTime(6*time.Second),
		nvd.WithRetryMaxWaitTime(60*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Println("=== NVD CVE API SDK Comprehensive Example ===")
	fmt.Println()
	fmt.Println("NOTE: This example makes multiple API requests and may hit rate limits")
	fmt.Println("without an API key (5 req/30s). The SDK will automatically retry with")
	fmt.Println("exponential backoff. For faster execution, set NVD_API_KEY environment")
	fmt.Println("variable (50 req/30s with key).")
	fmt.Println()

	demonstrateGetByID(client)
	demonstrateSearchByKeyword(client)
	demonstrateSeverityFiltering(client)
	demonstrateKEVCatalog(client)
	demonstrateDateRangeSearch(client)
	demonstrateChangeHistory(client)
}

func demonstrateGetByID(client *nvd.Client) {
	fmt.Println("1. Get Specific CVE by ID")
	fmt.Println("-------------------------")

	vuln, _, err := client.CVEs.GetByID(context.Background(), "CVE-2021-44228")
	if err != nil {
		if nvd.IsNotFound(err) {
			fmt.Println("CVE not found")
			return
		}
		log.Printf("Error: %v", err)
		return
	}

	cve := vuln.CVE
	fmt.Printf("CVE: %s\n", cve.ID)
	fmt.Printf("Published: %s\n", cve.Published.Format("2006-01-02"))
	fmt.Printf("Status: %s\n", cve.VulnStatus)

	if len(cve.Descriptions) > 0 {
		fmt.Printf("Description: %s\n", cve.Descriptions[0].Value)
	}

	if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
		metric := cve.Metrics.CVSSMetricV31[0]
		fmt.Printf("CVSS v3.1: %.1f (%s)\n",
			metric.CVSSData.BaseScore,
			metric.CVSSData.BaseSeverity)
	}
	fmt.Println()
}

func demonstrateSearchByKeyword(client *nvd.Client) {
	fmt.Println("2. Search CVEs by Keyword")
	fmt.Println("-------------------------")

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		KeywordSearch:  "Apache Struts",
		NoRejected:     true,
		ResultsPerPage: 50,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Found %d CVEs matching 'Apache Struts'\n", resp.TotalResults)
	fmt.Printf("Showing first 3:\n")

	for i, vuln := range resp.Vulnerabilities {
		if i >= 3 {
			break
		}
		cve := vuln.CVE
		fmt.Printf("  - %s (Published: %s)\n",
			cve.ID,
			cve.Published.Format("2006-01-02"))
	}
	fmt.Println()
}

func demonstrateSeverityFiltering(client *nvd.Client) {
	fmt.Println("3. Filter by CVSS v3 Severity")
	fmt.Println("------------------------------")

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		CVSSV3Severity: cves.SeverityCritical,
		NoRejected:     true,
		ResultsPerPage: 100,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Found %d CRITICAL severity CVEs\n", resp.TotalResults)

	if len(resp.Vulnerabilities) > 0 {
		cve := resp.Vulnerabilities[0].CVE
		fmt.Printf("Example: %s\n", cve.ID)
		if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
			metric := cve.Metrics.CVSSMetricV31[0]
			fmt.Printf("  Score: %.1f\n", metric.CVSSData.BaseScore)
			fmt.Printf("  Vector: %s\n", metric.CVSSData.VectorString)
		}
	}
	fmt.Println()
}

func demonstrateKEVCatalog(client *nvd.Client) {
	fmt.Println("4. CISA Known Exploited Vulnerabilities")
	fmt.Println("---------------------------------------")

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		HasKEV:         true,
		NoRejected:     true,
		ResultsPerPage: 50,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Found %d CVEs in CISA KEV Catalog\n", resp.TotalResults)
	fmt.Printf("Showing first 3 with required actions:\n")

	count := 0
	for _, vuln := range resp.Vulnerabilities {
		if count >= 3 {
			break
		}
		cve := vuln.CVE
		if cve.CISARequiredAction != nil {
			fmt.Printf("\n%s\n", cve.ID)
			if cve.CISAVulnerabilityName != nil {
				fmt.Printf("  Name: %s\n", *cve.CISAVulnerabilityName)
			}
			fmt.Printf("  Action: %s\n", *cve.CISARequiredAction)
			if cve.CISAActionDue != nil {
				fmt.Printf("  Due: %s\n", *cve.CISAActionDue)
			}
			count++
		}
	}
	fmt.Println()
}

func demonstrateDateRangeSearch(client *nvd.Client) {
	fmt.Println("5. Date Range Search (Last 7 Days)")
	fmt.Println("----------------------------------")

	startDate := time.Now().AddDate(0, 0, -7)
	endDate := time.Now()

	resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
		LastModStartDate: &startDate,
		LastModEndDate:   &endDate,
		NoRejected:       true,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("CVEs modified in last 7 days: %d\n", resp.TotalResults)

	severityCounts := make(map[string]int)
	for _, vuln := range resp.Vulnerabilities {
		if vuln.CVE.Metrics != nil && len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
			severity := vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
			severityCounts[severity]++
		}
	}

	fmt.Printf("Severity breakdown:\n")
	for severity, count := range severityCounts {
		fmt.Printf("  %s: %d\n", severity, count)
	}
	fmt.Println()
}

func demonstrateChangeHistory(client *nvd.Client) {
	fmt.Println("6. CVE Change History")
	fmt.Println("---------------------")

	startDate := time.Now().AddDate(0, 0, -30)
	endDate := time.Now()

	resp, _, err := client.CVEHistory.List(context.Background(), &cve_history.ListRequest{
		ChangeStartDate: &startDate,
		ChangeEndDate:   &endDate,
		EventName:       cve_history.EventInitialAnalysis,
		ResultsPerPage:  50,
	})
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("CVE changes (Initial Analysis) in last 30 days: %d\n", resp.TotalResults)
	fmt.Printf("Showing first 3:\n")

	for i, change := range resp.CVEChanges {
		if i >= 3 {
			break
		}
		c := change.Change
		fmt.Printf("\n%s\n", c.CVEID)
		fmt.Printf("  Date: %s\n", c.Created.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Source: %s\n", c.SourceIdentifier)
		fmt.Printf("  Changes: %d\n", len(c.Details))

		for j, detail := range c.Details {
			if j >= 2 {
				fmt.Printf("  ... and %d more changes\n", len(c.Details)-2)
				break
			}
			fmt.Printf("    - %s: %s\n", detail.Action, detail.Type)
		}
	}
	fmt.Println()
}
