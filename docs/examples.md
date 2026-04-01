# Examples

This document provides a comprehensive collection of examples for using the NVD CVE API SDK.

## Table of Contents

- [Basic Examples](#basic-examples)
- [Filtering Examples](#filtering-examples)
- [Advanced Examples](#advanced-examples)
- [Production Examples](#production-examples)

## Basic Examples

### Get a Single CVE

```go
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
        log.Fatal(err)
    }

    vuln, _, err := client.CVEs.GetByID(context.Background(), "CVE-2021-44228")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("CVE: %s\n", vuln.CVE.ID)
    fmt.Printf("Published: %s\n", vuln.CVE.Published)
    fmt.Printf("Description: %s\n", vuln.CVE.Descriptions[0].Value)
}
```

### Search by Keyword

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch: "Apache Log4j",
})

for _, vuln := range resp.Vulnerabilities {
    fmt.Printf("%s: %s\n", vuln.CVE.ID, vuln.CVE.Descriptions[0].Value)
}
```

## Filtering Examples

### By Severity

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CVSSV3Severity: cves.SeverityCritical,
    NoRejected:     true,
})
```

### By Date Range

```go
startDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
endDate := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    LastModStartDate: &startDate,
    LastModEndDate:   &endDate,
})
```

### By CPE

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CPEName: "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
})
```

### By CWE

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CWEID: "CWE-287",  // Improper Authentication
})
```

### CISA KEV Catalog

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    HasKEV:     true,
    NoRejected: true,
})

for _, vuln := range resp.Vulnerabilities {
    cve := vuln.CVE
    if cve.CISARequiredAction != nil {
        fmt.Printf("%s: %s (Due: %s)\n", 
            cve.ID, 
            *cve.CISARequiredAction,
            *cve.CISAActionDue)
    }
}
```

## Advanced Examples

### Fluent API

```go
startDate := time.Now().AddDate(0, 0, -30)
endDate := time.Now()

resp, _, err := client.CVEs.List(
    context.Background(),
    cves.NewListRequest().
        WithKeywordSearch("Apache").
        WithCVSSV3Severity(cves.SeverityCritical).
        WithNoRejected().
        WithHasKEV().
        WithLastModDateRange(startDate, endDate).
        WithResultsPerPage(100),
)
```

### Multiple Filters

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch:  "Windows",
    CVSSV3Severity: cves.SeverityHigh,
    HasKEV:         true,
    NoRejected:     true,
    CWEID:          "CWE-79",  // Cross-site Scripting
})
```

### Version Range Filtering

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    VirtualMatchString: "cpe:2.3:o:linux:linux_kernel",
    VersionStart:       "5.0",
    VersionStartType:   cves.VersionTypeIncluding,
    VersionEnd:         "5.10",
    VersionEndType:     cves.VersionTypeExcluding,
})
```

## Production Examples

### Incremental Sync

```go
func syncCVEs(client *nvd.Client, lastSync time.Time) error {
    now := time.Now()
    
    resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
        LastModStartDate: &lastSync,
        LastModEndDate:   &now,
        NoRejected:       true,
    })
    if err != nil {
        return err
    }
    
    for _, vuln := range resp.Vulnerabilities {
        if err := saveToDatabase(vuln); err != nil {
            return err
        }
    }
    
    return updateLastSyncTime(now)
}
```

### Monitoring Critical CVEs

```go
func monitorCriticalCVEs(client *nvd.Client) {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    
    for range ticker.C {
        startDate := time.Now().AddDate(0, 0, -1)
        endDate := time.Now()
        
        resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
            LastModStartDate: &startDate,
            LastModEndDate:   &endDate,
            CVSSV3Severity:   cves.SeverityCritical,
            NoRejected:       true,
        })
        if err != nil {
            log.Printf("Error: %v", err)
            continue
        }
        
        if resp.TotalResults > 0 {
            sendAlert(fmt.Sprintf("Found %d new CRITICAL CVEs", resp.TotalResults))
        }
    }
}
```

### Batch Processing

```go
func processCVEsBatch(client *nvd.Client, cveIDs []string) {
    const batchSize = 50
    const delayBetweenBatches = 30 * time.Second
    
    for i := 0; i < len(cveIDs); i += batchSize {
        end := i + batchSize
        if end > len(cveIDs) {
            end = len(cveIDs)
        }
        
        batch := cveIDs[i:end]
        
        for _, cveID := range batch {
            vuln, _, err := client.CVEs.GetByID(context.Background(), cveID)
            if err != nil {
                log.Printf("Error fetching %s: %v", cveID, err)
                continue
            }
            
            processCVE(vuln)
        }
        
        if end < len(cveIDs) {
            log.Printf("Processed %d/%d CVEs, waiting %s...", end, len(cveIDs), delayBetweenBatches)
            time.Sleep(delayBetweenBatches)
        }
    }
}
```

### Product Vulnerability Report

```go
func generateProductReport(client *nvd.Client, cpeName string) (*Report, error) {
    resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
        CPEName:    cpeName,
        NoRejected: true,
    })
    if err != nil {
        return nil, err
    }
    
    report := &Report{
        Product:    cpeName,
        ScanDate:   time.Now(),
        TotalCVEs:  resp.TotalResults,
        BySeverity: make(map[string]int),
    }
    
    for _, vuln := range resp.Vulnerabilities {
        cve := vuln.CVE
        
        if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
            severity := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
            report.BySeverity[severity]++
        }
        
        if cve.CISARequiredAction != nil {
            report.KEVCount++
        }
    }
    
    return report, nil
}
```

### Change Tracking

```go
func trackCVEChanges(client *nvd.Client, cveID string) error {
    resp, _, err := client.CVEHistory.GetByCVEID(context.Background(), cveID)
    if err != nil {
        return err
    }
    
    fmt.Printf("Change history for %s:\n", cveID)
    fmt.Printf("Total changes: %d\n\n", len(resp.CVEChanges))
    
    for _, change := range resp.CVEChanges {
        c := change.Change
        fmt.Printf("%s - %s\n", c.Created.Format("2006-01-02"), c.EventName)
        
        for _, detail := range c.Details {
            fmt.Printf("  %s: %s\n", detail.Action, detail.Type)
            if detail.NewValue != nil {
                fmt.Printf("    New: %s\n", *detail.NewValue)
            }
        }
    }
    
    return nil
}
```

### Error Handling with Retry

```go
func fetchWithRetry(client *nvd.Client, cveID string) (*cves.VulnerabilityItem, error) {
    maxRetries := 3
    var lastErr error
    
    for i := 0; i < maxRetries; i++ {
        vuln, _, err := client.CVEs.GetByID(context.Background(), cveID)
        if err == nil {
            return vuln, nil
        }
        
        lastErr = err
        
        if nvd.IsRateLimited(err) {
            waitTime := time.Duration(1<<uint(i)) * 30 * time.Second
            log.Printf("Rate limited, waiting %s...", waitTime)
            time.Sleep(waitTime)
            continue
        }
        
        if !nvd.IsServerError(err) {
            return nil, err
        }
        
        time.Sleep(time.Second * time.Duration(i+1))
    }
    
    return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}
```

### Parallel Fetching

```go
import "golang.org/x/sync/errgroup"

func fetchMultipleCVEs(client *nvd.Client, cveIDs []string) ([]cves.VulnerabilityItem, error) {
    g, ctx := errgroup.WithContext(context.Background())
    results := make([]cves.VulnerabilityItem, len(cveIDs))
    
    for i, cveID := range cveIDs {
        i, cveID := i, cveID
        g.Go(func() error {
            vuln, _, err := client.CVEs.GetByID(ctx, cveID)
            if err != nil {
                return err
            }
            results[i] = *vuln
            return nil
        })
        
        time.Sleep(100 * time.Millisecond)
    }
    
    if err := g.Wait(); err != nil {
        return nil, err
    }
    
    return results, nil
}
```

### CVE Enrichment

```go
type EnrichedCVE struct {
    CVE          cves.CVE
    CVSSScore    float64
    Severity     string
    IsKEV        bool
    ChangeCount  int
    LastAnalyzed time.Time
    References   int
    Weaknesses   []string
}

func enrichCVE(client *nvd.Client, cveID string) (*EnrichedCVE, error) {
    vuln, _, err := client.CVEs.GetByID(context.Background(), cveID)
    if err != nil {
        return nil, err
    }
    
    history, _, err := client.CVEHistory.GetByCVEID(context.Background(), cveID)
    if err != nil {
        return nil, err
    }
    
    enriched := &EnrichedCVE{
        CVE:          vuln.CVE,
        ChangeCount:  len(history.CVEChanges),
        LastAnalyzed: time.Now(),
        References:   len(vuln.CVE.References),
    }
    
    if vuln.CVE.Metrics != nil && len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
        metric := vuln.CVE.Metrics.CVSSMetricV31[0]
        enriched.CVSSScore = metric.CVSSData.BaseScore
        enriched.Severity = metric.CVSSData.BaseSeverity
    }
    
    enriched.IsKEV = vuln.CVE.CISARequiredAction != nil
    
    for _, weakness := range vuln.CVE.Weaknesses {
        for _, desc := range weakness.Description {
            enriched.Weaknesses = append(enriched.Weaknesses, desc.Value)
        }
    }
    
    return enriched, nil
}
```

### Daily Vulnerability Report

```go
func generateDailyReport(client *nvd.Client) error {
    yesterday := time.Now().AddDate(0, 0, -1)
    today := time.Now()
    
    resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
        PubStartDate: &yesterday,
        PubEndDate:   &today,
        NoRejected:   true,
    })
    if err != nil {
        return err
    }
    
    report := fmt.Sprintf("Daily CVE Report - %s\n", today.Format("2006-01-02"))
    report += fmt.Sprintf("Total new CVEs: %d\n\n", resp.TotalResults)
    
    severityCounts := make(map[string]int)
    kevCount := 0
    
    for _, vuln := range resp.Vulnerabilities {
        if vuln.CVE.Metrics != nil && len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
            severity := vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
            severityCounts[severity]++
        }
        
        if vuln.CVE.CISARequiredAction != nil {
            kevCount++
        }
    }
    
    report += "By Severity:\n"
    for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
        if count, ok := severityCounts[sev]; ok {
            report += fmt.Sprintf("  %s: %d\n", sev, count)
        }
    }
    
    if kevCount > 0 {
        report += fmt.Sprintf("\nCISA KEV: %d\n", kevCount)
    }
    
    return sendReport(report)
}
```

### Vulnerability Scanner

```go
func scanProduct(client *nvd.Client, cpeName string) (*ScanResult, error) {
    resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
        CPEName:    cpeName,
        NoRejected: true,
    })
    if err != nil {
        return nil, err
    }
    
    result := &ScanResult{
        Product:      cpeName,
        TotalCVEs:    resp.TotalResults,
        BySeverity:   make(map[string][]string),
        ByYear:       make(map[int]int),
    }
    
    for _, vuln := range resp.Vulnerabilities {
        cve := vuln.CVE
        
        year := cve.Published.Year()
        result.ByYear[year]++
        
        if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
            severity := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
            result.BySeverity[severity] = append(result.BySeverity[severity], cve.ID)
        }
    }
    
    return result, nil
}

type ScanResult struct {
    Product    string
    TotalCVEs  int
    BySeverity map[string][]string
    ByYear     map[int]int
}
```

## Working Examples

All examples are available in the `examples/` directory:

### CVE API Examples

- **list_by_keyword**: Search CVEs by keyword
- **get_by_id**: Retrieve specific CVE
- **filter_by_severity**: Filter by CVSS severity
- **date_range_sync**: Sync CVEs within date range
- **kev_catalog**: Work with CISA KEV catalog
- **fluent_api**: Use fluent request builder

### CVE History Examples

- **track_changes**: Monitor CVE changes over time

### Comprehensive Example

- **comprehensive**: Full-featured example demonstrating all capabilities

### Vulnerability Scanner

- **vulnerability_scanner**: Command-line tool for scanning products

Run any example:

```bash
cd examples/cves/list_by_keyword
export NVD_API_KEY="your-api-key"
go run main.go
```

Run the vulnerability scanner:

```bash
cd examples/vulnerability_scanner
export NVD_API_KEY="your-api-key"
go run main.go -keyword "Apache Log4j" -days 90
go run main.go -cpe "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*" -days 365
```
