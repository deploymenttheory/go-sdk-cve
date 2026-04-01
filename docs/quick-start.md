# Quick Start Guide

This guide will help you get started with the NVD CVE API SDK.

## Installation

```bash
go get github.com/deploymenttheory/go-sdk-cve
```

## Authentication

The NVD API supports two modes:

1. **Without API Key**: 5 requests per 30 seconds
2. **With API Key**: 50 requests per 30 seconds (recommended)

Request an API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key).

## Your First API Call

### Option 1: Environment Variables

Set your API key:

```bash
export NVD_API_KEY="your-api-key-here"
export NVD_BASE_URL="https://services.nvd.nist.gov"
```

Create a simple program:

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

### Option 2: Config File

Create `config.json`:

```json
{
  "api_key": "your-api-key-here",
  "base_url": "https://services.nvd.nist.gov"
}
```

Use in your code:

```go
cfg, err := nvd.LoadConfigFromFile("config.json")
if err != nil {
    log.Fatal(err)
}

client, err := nvd.NewClient(cfg)
if err != nil {
    log.Fatal(err)
}
```

### Option 3: Programmatic

```go
cfg := &nvd.Config{
    APIKey:  "your-api-key-here",
    BaseURL: "https://services.nvd.nist.gov",
}

client, err := nvd.NewClient(cfg)
if err != nil {
    log.Fatal(err)
}
```

## Common Operations

### Search CVEs by Keyword

```go
import "github.com/deploymenttheory/go-sdk-cve/nvd/cves"

resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch: "Apache Log4j",
    NoRejected:    true,
})
```

### Filter by Severity

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CVSSV3Severity: "CRITICAL",
    NoRejected:     true,
})
```

### Get Recently Modified CVEs

```go
import "time"

startDate := time.Now().AddDate(0, 0, -7)
endDate := time.Now()

resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    LastModStartDate: &startDate,
    LastModEndDate:   &endDate,
})
```

### Get CVEs in CISA KEV Catalog

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    HasKEV:     true,
    NoRejected: true,
})

for _, vuln := range resp.Vulnerabilities {
    cve := vuln.CVE
    if cve.CISARequiredAction != nil {
        fmt.Printf("%s: %s\n", cve.ID, *cve.CISARequiredAction)
    }
}
```

### Track CVE Changes

```go
import "github.com/deploymenttheory/go-sdk-cve/nvd/cve_history"

startDate := time.Now().AddDate(0, 0, -30)
endDate := time.Now()

resp, _, err := client.CVEHistory.List(context.Background(), &cve_history.ListRequest{
    ChangeStartDate: &startDate,
    ChangeEndDate:   &endDate,
    EventName:       "Initial Analysis",
})

for _, change := range resp.CVEChanges {
    fmt.Printf("%s: %s on %s\n", 
        change.Change.CVEID,
        change.Change.EventName,
        change.Change.Created.Format("2006-01-02"))
}
```

## Error Handling

The SDK provides helper functions for common error types:

```go
resp, _, err := client.CVEs.GetByID(ctx, "CVE-2021-44228")
if err != nil {
    if nvd.IsNotFound(err) {
        fmt.Println("CVE not found")
    } else if nvd.IsRateLimited(err) {
        fmt.Println("Rate limited - wait before retrying")
    } else if nvd.IsServerError(err) {
        fmt.Println("Server error - retry later")
    } else {
        log.Fatal(err)
    }
}
```

## Production Configuration

```go
import (
    "time"
    "go.uber.org/zap"
)

logger, _ := zap.NewProduction()

client, err := nvd.NewClient(
    cfg,
    nvd.WithTimeout(60*time.Second),
    nvd.WithRetryCount(5),
    nvd.WithRetryWaitTime(3*time.Second),
    nvd.WithRetryMaxWaitTime(60*time.Second),
    nvd.WithLogger(logger),
    nvd.WithGlobalHeader("X-Application-Name", "MySecurityApp"),
)
```

## Pagination

The SDK automatically handles pagination for you. When you call `List()`, it fetches all pages:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch: "Windows",
})

// resp.Vulnerabilities contains ALL results, not just the first page
fmt.Printf("Total results: %d\n", len(resp.Vulnerabilities))
```

To limit results, use `ResultsPerPage`:

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    KeywordSearch:  "Windows",
    ResultsPerPage: 100,
})
```

## Rate Limiting

The NVD API enforces rate limits. The SDK automatically retries on 429 responses with exponential backoff.

**Best Practices:**

1. Always use an API key for production
2. Use date ranges to fetch only recently modified CVEs
3. Implement exponential backoff in your application layer for bulk operations
4. Monitor for rate limit errors and adjust request frequency

## Next Steps

- Explore the [examples directory](../examples/) for more use cases
- Read the [API documentation](https://nvd.nist.gov/developers/vulnerabilities)
- Check out the [GoDoc](https://pkg.go.dev/github.com/deploymenttheory/go-sdk-cve) for detailed API reference
