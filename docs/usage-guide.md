# Usage Guide

This guide covers common use cases and patterns for the NVD CVE API SDK.

## Table of Contents

- [Basic Operations](#basic-operations)
- [Advanced Filtering](#advanced-filtering)
- [Working with CVSS](#working-with-cvss)
- [CISA KEV Catalog](#cisa-kev-catalog)
- [Change Tracking](#change-tracking)
- [Error Handling](#error-handling)
- [Production Patterns](#production-patterns)

## Basic Operations

### Get a Single CVE

The simplest operation is retrieving a specific CVE by its ID:

```go
vuln, resp, err := client.CVEs.GetByID(context.Background(), "CVE-2021-44228")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("CVE: %s\n", vuln.CVE.ID)
fmt.Printf("Status: %s\n", vuln.CVE.VulnStatus)
```

### Search by Keyword

Search CVE descriptions for specific terms:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch: "Apache Log4j",
})
```

Multiple keywords act as AND:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch: "Windows MacOS Linux",  // Matches CVEs mentioning all three
})
```

Exact phrase matching:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch:     "Microsoft Outlook",
    KeywordExactMatch: true,
})
```

## Advanced Filtering

### Filter by CPE (Common Platform Enumeration)

Get all CVEs for a specific product:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CPEName: "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
})
```

Broader CPE matching:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    VirtualMatchString: "cpe:2.3:o:linux:linux_kernel",
})
```

Filter by version range:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    VirtualMatchString: "cpe:2.3:o:linux:linux_kernel",
    VersionStart:       "2.6",
    VersionStartType:   cves.VersionTypeIncluding,
    VersionEnd:         "2.7",
    VersionEndType:     cves.VersionTypeExcluding,
})
```

### Filter by CWE (Common Weakness Enumeration)

Find CVEs with specific weakness types:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CWEID: "CWE-287",  // Improper Authentication
})
```

### Filter by Source

Get CVEs from a specific source:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    SourceIdentifier: "cve@mitre.org",
})
```

### Exclude Rejected CVEs

Always recommended for production use:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    NoRejected: true,
})
```

## Working with CVSS

### Filter by CVSS v3.1 Severity

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CVSSV3Severity: cves.SeverityCritical,
})
```

Available severity constants:
- `cves.SeverityLow`
- `cves.SeverityMedium`
- `cves.SeverityHigh`
- `cves.SeverityCritical`

### Filter by CVSS Vector String

Full vector string:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CVSSV3Metrics: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
})
```

Partial vector string:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CVSSV3Metrics: "AV:N/AC:L",  // Network accessible, low complexity
})
```

### Extract CVSS Information

```go
for _, vuln := range resp.Vulnerabilities {
    cve := vuln.CVE
    
    if cve.Metrics != nil {
        // CVSS v3.1 (preferred)
        if len(cve.Metrics.CVSSMetricV31) > 0 {
            metric := cve.Metrics.CVSSMetricV31[0]
            fmt.Printf("%s: %.1f (%s)\n", 
                cve.ID,
                metric.CVSSData.BaseScore,
                metric.CVSSData.BaseSeverity)
        }
        
        // CVSS v2 (legacy)
        if len(cve.Metrics.CVSSMetricV2) > 0 {
            metric := cve.Metrics.CVSSMetricV2[0]
            fmt.Printf("CVSSv2: %.1f\n", metric.CVSSData.BaseScore)
        }
    }
}
```

## CISA KEV Catalog

### Get All KEV CVEs

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    HasKEV:     true,
    NoRejected: true,
})
```

### Extract KEV Information

```go
for _, vuln := range resp.Vulnerabilities {
    cve := vuln.CVE
    
    if cve.CISAVulnerabilityName != nil {
        fmt.Printf("CVE: %s\n", cve.ID)
        fmt.Printf("Name: %s\n", *cve.CISAVulnerabilityName)
        
        if cve.CISARequiredAction != nil {
            fmt.Printf("Required Action: %s\n", *cve.CISARequiredAction)
        }
        
        if cve.CISAActionDue != nil {
            fmt.Printf("Due Date: %s\n", *cve.CISAActionDue)
        }
        
        if cve.CISAExploitAdd != nil {
            fmt.Printf("Added to KEV: %s\n", *cve.CISAExploitAdd)
        }
    }
}
```

### Filter KEV by Date Added

```go
startDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
endDate := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KEVStartDate: &startDate,
    KEVEndDate:   &endDate,
})
```

## Change Tracking

### Track All Changes in a Period

```go
startDate := time.Now().AddDate(0, 0, -7)
endDate := time.Now()

resp, _, err := client.CVEHistory.List(context.Background(), &cve_history.ListRequest{
    ChangeStartDate: &startDate,
    ChangeEndDate:   &endDate,
})

for _, change := range resp.CVEChanges {
    c := change.Change
    fmt.Printf("%s: %s on %s\n", c.CVEID, c.EventName, c.Created)
}
```

### Filter by Event Type

```go
resp, _, err := client.CVEHistory.List(context.Background(), &cve_history.ListRequest{
    EventName:       cve_history.EventInitialAnalysis,
    ChangeStartDate: &startDate,
    ChangeEndDate:   &endDate,
})
```

Available event constants:
- `cve_history.EventCVEReceived`
- `cve_history.EventInitialAnalysis`
- `cve_history.EventReanalysis`
- `cve_history.EventCVEModified`
- `cve_history.EventModifiedAnalysis`
- `cve_history.EventCVETranslated`
- `cve_history.EventVendorComment`
- `cve_history.EventCVESourceUpdate`
- `cve_history.EventCPEDeprecationRemap`
- `cve_history.EventCWERemap`
- `cve_history.EventReferenceTagUpdate`
- `cve_history.EventCVERejected`
- `cve_history.EventCVEUnrejected`
- `cve_history.EventCVECISAKEVUpdate`

### Get Complete History for a CVE

```go
resp, _, err := client.CVEHistory.GetByCVEID(context.Background(), "CVE-2021-44228")

for _, change := range resp.CVEChanges {
    c := change.Change
    fmt.Printf("Event: %s (%s)\n", c.EventName, c.Created.Format("2006-01-02"))
    
    for _, detail := range c.Details {
        fmt.Printf("  %s: %s\n", detail.Action, detail.Type)
        if detail.NewValue != nil {
            fmt.Printf("    New: %s\n", *detail.NewValue)
        }
        if detail.OldValue != nil {
            fmt.Printf("    Old: %s\n", *detail.OldValue)
        }
    }
}
```

## Error Handling

### Check Error Types

```go
resp, _, err := client.CVEs.GetByID(ctx, "CVE-2021-44228")
if err != nil {
    switch {
    case nvd.IsNotFound(err):
        fmt.Println("CVE not found")
    case nvd.IsRateLimited(err):
        fmt.Println("Rate limited - implement backoff")
        time.Sleep(30 * time.Second)
    case nvd.IsServerError(err):
        fmt.Println("Server error - retry later")
    case nvd.IsBadRequest(err):
        fmt.Println("Invalid request parameters")
    case nvd.IsUnauthorized(err):
        fmt.Println("Invalid or missing API key")
    default:
        log.Fatal(err)
    }
}
```

### Implement Retry Logic

```go
func fetchWithRetry(client *nvd.Client, cveID string, maxRetries int) (*cves.VulnerabilityItem, error) {
    var lastErr error
    
    for i := 0; i < maxRetries; i++ {
        vuln, _, err := client.CVEs.GetByID(context.Background(), cveID)
        if err == nil {
            return vuln, nil
        }
        
        lastErr = err
        
        if nvd.IsRateLimited(err) {
            waitTime := time.Duration(1<<uint(i)) * time.Second
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

## Production Patterns

### Incremental Sync Pattern

Keep a local database synchronized with NVD:

```go
func syncCVEs(client *nvd.Client, lastSyncTime time.Time) error {
    now := time.Now()
    
    resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
        LastModStartDate: &lastSyncTime,
        LastModEndDate:   &now,
        NoRejected:       true,
    })
    if err != nil {
        return fmt.Errorf("failed to fetch CVEs: %w", err)
    }
    
    for _, vuln := range resp.Vulnerabilities {
        if err := saveToDatabase(vuln); err != nil {
            return fmt.Errorf("failed to save CVE %s: %w", vuln.CVE.ID, err)
        }
    }
    
    if err := updateLastSyncTime(now); err != nil {
        return fmt.Errorf("failed to update sync time: %w", err)
    }
    
    return nil
}
```

### Batch Processing with Rate Limiting

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
            time.Sleep(delayBetweenBatches)
        }
    }
}
```

### Monitoring Recent Vulnerabilities

```go
func monitorRecentCriticalCVEs(client *nvd.Client) error {
    startDate := time.Now().AddDate(0, 0, -1)
    endDate := time.Now()
    
    resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
        LastModStartDate: &startDate,
        LastModEndDate:   &endDate,
        CVSSV3Severity:   cves.SeverityCritical,
        NoRejected:       true,
    })
    if err != nil {
        return err
    }
    
    if resp.TotalResults > 0 {
        sendAlert(fmt.Sprintf("Found %d new CRITICAL CVEs", resp.TotalResults))
        
        for _, vuln := range resp.Vulnerabilities {
            cve := vuln.CVE
            
            if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
                score := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
                if score >= 9.0 {
                    sendUrgentAlert(cve.ID, score)
                }
            }
        }
    }
    
    return nil
}
```

### Product Vulnerability Scanner

```go
func scanProductForVulnerabilities(client *nvd.Client, cpeName string) (*VulnerabilityReport, error) {
    resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
        CPEName:    cpeName,
        NoRejected: true,
    })
    if err != nil {
        return nil, err
    }
    
    report := &VulnerabilityReport{
        Product:      cpeName,
        ScanDate:     time.Now(),
        TotalCVEs:    resp.TotalResults,
        BySeverity:   make(map[string]int),
        ByYear:       make(map[int]int),
    }
    
    for _, vuln := range resp.Vulnerabilities {
        cve := vuln.CVE
        
        year := cve.Published.Year()
        report.ByYear[year]++
        
        if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
            severity := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
            report.BySeverity[severity]++
        }
    }
    
    return report, nil
}

type VulnerabilityReport struct {
    Product    string
    ScanDate   time.Time
    TotalCVEs  int
    BySeverity map[string]int
    ByYear     map[int]int
}
```

## Working with Dates

### Date Range Best Practices

The NVD API enforces a 120-day maximum range:

```go
func fetchCVEsInChunks(client *nvd.Client, start, end time.Time) ([]cves.VulnerabilityItem, error) {
    const maxDays = 120
    var allVulns []cves.VulnerabilityItem
    
    current := start
    for current.Before(end) {
        chunkEnd := current.AddDate(0, 0, maxDays)
        if chunkEnd.After(end) {
            chunkEnd = end
        }
        
        resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
            LastModStartDate: &current,
            LastModEndDate:   &chunkEnd,
            NoRejected:       true,
        })
        if err != nil {
            return nil, err
        }
        
        allVulns = append(allVulns, resp.Vulnerabilities...)
        current = chunkEnd.AddDate(0, 0, 1)
        
        time.Sleep(time.Second)
    }
    
    return allVulns, nil
}
```

### ISO-8601 Format

Dates must be in ISO-8601 format. The SDK handles this automatically:

```go
startDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
endDate := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    PubStartDate: &startDate,
    PubEndDate:   &endDate,
})
```

## Context and Cancellation

### Request Timeout

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

resp, _, err := client.CVEs.List(ctx, &cves.ListRequest{
    KeywordSearch: "Apache",
})
```

### Cancellation

```go
ctx, cancel := context.WithCancel(context.Background())

go func() {
    time.Sleep(5 * time.Second)
    cancel()
}()

resp, _, err := client.CVEs.List(ctx, &cves.ListRequest{
    KeywordSearch: "Windows",
})
```

## Fluent API Pattern

Chain request builders for cleaner code:

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

## Logging

### Production Logging

```go
logger, _ := zap.NewProduction()
client, err := nvd.NewClient(
    cfg,
    nvd.WithLogger(logger),
)
```

### Development Logging

```go
logger, _ := zap.NewDevelopment()
client, err := nvd.NewClient(
    cfg,
    nvd.WithLogger(logger),
    nvd.WithDebug(),
)
```

### Custom Log Fields

```go
logger := zap.NewProduction()
logger = logger.With(
    zap.String("service", "vulnerability-scanner"),
    zap.String("environment", "production"),
)

client, err := nvd.NewClient(cfg, nvd.WithLogger(logger))
```

## Performance Optimization

### Limit Results

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch:  "Windows",
    ResultsPerPage: 100,  // Limit to 100 results
})
```

### Use Specific Filters

More specific filters = faster responses:

```go
// Slower - broad search
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch: "Microsoft",
})

// Faster - specific filters
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CVEID: "CVE-2021-44228",
})
```

### Parallel Requests

When fetching multiple specific CVEs:

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
    }
    
    if err := g.Wait(); err != nil {
        return nil, err
    }
    
    return results, nil
}
```

## Testing

### Mock Client for Testing

```go
// In your tests
type mockNVDClient struct {
    cves map[string]*cves.VulnerabilityItem
}

func (m *mockNVDClient) GetCVE(id string) (*cves.VulnerabilityItem, error) {
    if vuln, ok := m.cves[id]; ok {
        return vuln, nil
    }
    return nil, fmt.Errorf("CVE not found")
}

func TestMyFunction(t *testing.T) {
    mock := &mockNVDClient{
        cves: map[string]*cves.VulnerabilityItem{
            "CVE-2021-44228": {
                CVE: cves.CVE{
                    ID: "CVE-2021-44228",
                    // ... other fields
                },
            },
        },
    }
    
    // Test your code with the mock
}
```

## Common Patterns

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
    for _, vuln := range resp.Vulnerabilities {
        if vuln.CVE.Metrics != nil && len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
            severity := vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
            severityCounts[severity]++
        }
    }
    
    report += "By Severity:\n"
    for severity, count := range severityCounts {
        report += fmt.Sprintf("  %s: %d\n", severity, count)
    }
    
    return sendReport(report)
}
```

### CVE Enrichment

```go
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
    }
    
    if vuln.CVE.Metrics != nil && len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
        enriched.CVSSScore = vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
        enriched.Severity = vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
    }
    
    enriched.IsKEV = vuln.CVE.CISARequiredAction != nil
    
    return enriched, nil
}

type EnrichedCVE struct {
    CVE          cves.CVE
    CVSSScore    float64
    Severity     string
    IsKEV        bool
    ChangeCount  int
    LastAnalyzed time.Time
}
```
