# Go SDK for NVD CVE API

[![Go Report Card](https://goreportcard.com/badge/github.com/deploymenttheory/go-sdk-cve)](https://goreportcard.com/report/github.com/deploymenttheory/go-sdk-cve)
[![GoDoc](https://pkg.go.dev/badge/github.com/deploymenttheory/go-sdk-cve)](https://pkg.go.dev/github.com/deploymenttheory/go-sdk-cve)
[![License](https://img.shields.io/github/license/deploymenttheory/go-sdk-cve)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/deploymenttheory/go-sdk-cve)](https://go.dev/)
![Status: Experimental](https://img.shields.io/badge/status-experimental-yellow)

A production-ready Go client library for the [NVD CVE API v2.0](https://nvd.nist.gov/developers/vulnerabilities), providing comprehensive access to the National Vulnerability Database with automatic pagination, intelligent retry logic, and enterprise-grade features.

## Features

- **Complete CVE API Coverage**: Full support for all CVE API v2.0 parameters and filters
- **CVE Change History API**: Track and audit changes to CVE records over time
- **Automatic Pagination**: Transparently handles offset-based pagination for large result sets (up to 341,616+ CVEs)
- **Intelligent Retry Logic**: Exponential backoff for transient errors (429, 503, 5xx) with configurable limits
- **Structured Logging**: Production-ready integration with zap for observability
- **Flexible Authentication**: Optional API key support (5 req/30s without key, 50 req/30s with key)
- **Multiple Config Methods**: Environment variables, JSON config files, or programmatic setup
- **Production-Ready Transport**: Configurable timeouts, retries, custom headers, proxy support, TLS configuration
- **Type-Safe API**: Strongly-typed request/response models with comprehensive field coverage
- **Robust Time Parsing**: Custom time type handles NVD API's inconsistent timestamp formats (with/without timezone)
- **Fluent Request Builder**: Chainable methods for clean, readable code
- **Error Handling Helpers**: Type-checking functions for common error scenarios

## Quick Start

### Installation

```bash
go get github.com/deploymenttheory/go-sdk-cve
```

### Get Your API Key

Request a free API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key) to get 50 requests per 30 seconds (vs 5 without a key).

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/deploymenttheory/go-sdk-cve/nvd"
    "github.com/deploymenttheory/go-sdk-cve/nvd/cves"
)

func main() {
    // Set environment variable: export NVD_API_KEY="your-key-here"
    client, err := nvd.NewClientFromEnv()
    if err != nil {
        log.Fatal(err)
    }

    // Search for CVEs by keyword
    resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
        KeywordSearch: "Microsoft Windows",
        ResultsPerPage: 100,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d CVEs\n", resp.TotalResults)
    for _, vuln := range resp.Vulnerabilities {
        fmt.Printf("- %s: %s\n", vuln.CVE.ID, vuln.CVE.Descriptions[0].Value)
    }
}
```

### Get Specific CVE

```go
vuln, _, err := client.CVEs.GetByID(context.Background(), "CVE-2021-44228")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("CVE: %s\n", vuln.CVE.ID)
fmt.Printf("Published: %s\n", vuln.CVE.Published)
fmt.Printf("Status: %s\n", vuln.CVE.VulnStatus)

// Access CVSS metrics
if vuln.CVE.Metrics != nil && len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
    metric := vuln.CVE.Metrics.CVSSMetricV31[0]
    fmt.Printf("CVSS: %.1f (%s)\n", metric.CVSSData.BaseScore, metric.CVSSData.BaseSeverity)
}
```

## Configuration

### Environment Variables

```bash
export NVD_API_KEY="your-api-key-here"
export NVD_BASE_URL="https://services.nvd.nist.gov"
export HIDE_SENSITIVE_DATA="false"
```

### From Config File

```go
cfg, err := nvd.LoadConfigFromFile("config.json")
if err != nil {
    log.Fatal(err)
}

client, err := nvd.NewClient(cfg)
```

Example `config.json`:

```json
{
  "api_key": "your-api-key-here",
  "base_url": "https://services.nvd.nist.gov",
  "hide_sensitive_data": false
}
```

### Programmatic Configuration

```go
import (
    "time"
    "go.uber.org/zap"
    "github.com/deploymenttheory/go-sdk-cve/nvd"
)

logger, _ := zap.NewProduction()
cfg := &nvd.Config{
    APIKey:  "your-api-key-here",
    BaseURL: "https://services.nvd.nist.gov",
}

client, err := nvd.NewClient(
    cfg,
    nvd.WithTimeout(30*time.Second),
    nvd.WithRetryCount(3),
    nvd.WithLogger(logger),
)
```

## API Examples

### Search CVEs by Date Range

```go
import "time"

startDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
endDate := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)

resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    PubStartDate: &startDate,
    PubEndDate:   &endDate,
    ResultsPerPage: 2000,
})
```

### Filter by CVSS Severity

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CVSSV3Severity: "CRITICAL",
    NoRejected:     true,
})
```

### Search by CPE

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CPEName: "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
})
```

### Get CVEs in CISA KEV Catalog

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    HasKEV: true,
})
```

### Search by CWE

```go
resp, _, err := client.CVEs.List(context.Background(), &cves.ListRequest{
    CWEID: "CWE-287", // Improper Authentication
})
```

### Get CVE Change History

```go
import "github.com/deploymenttheory/go-sdk-cve/nvd/cve_history"

startDate := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
endDate := time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC)

resp, _, err := client.CVEHistory.List(context.Background(), &cve_history.ListRequest{
    ChangeStartDate: &startDate,
    ChangeEndDate:   &endDate,
})

for _, change := range resp.CVEChanges {
    fmt.Printf("CVE: %s, Event: %s, Date: %s\n", 
        change.Change.CVEID, 
        change.Change.EventName, 
        change.Change.Created)
}
```

### Filter Change History by Event Type

```go
resp, _, err := client.CVEHistory.List(context.Background(), &cve_history.ListRequest{
    EventName: "Initial Analysis",
    ChangeStartDate: &startDate,
    ChangeEndDate:   &endDate,
})
```

## Advanced Configuration

### Custom Timeouts and Retries

```go
client, err := nvd.NewClient(
    cfg,
    nvd.WithTimeout(60*time.Second),
    nvd.WithRetryCount(5),
    nvd.WithRetryWaitTime(3*time.Second),
    nvd.WithRetryMaxWaitTime(60*time.Second),
    nvd.WithTotalRetryDuration(5*time.Minute),
)
```

### Proxy Support

```go
client, err := nvd.NewClient(
    cfg,
    nvd.WithProxy("http://proxy.example.com:8080"),
)
```

### Custom TLS Configuration

```go
import "crypto/tls"

tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
}

client, err := nvd.NewClient(
    cfg,
    nvd.WithTLSClientConfig(tlsConfig),
)
```

### Custom Headers

```go
client, err := nvd.NewClient(
    cfg,
    nvd.WithGlobalHeader("X-Application-Name", "MyApp"),
    nvd.WithGlobalHeaders(map[string]string{
        "X-Custom-Header": "value",
    }),
)
```

## API Reference

### CVE API Parameters

The CVE API supports extensive filtering options:

- **cpeName**: Filter by CPE name (e.g., `cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*`)
- **cveId**: Get specific CVE by ID (e.g., `CVE-2019-1010218`)
- **cveTag**: Filter by CVE tags (`disputed`, `unsupported-when-assigned`, `exclusively-hosted-service`)
- **cvssV2Metrics / cvssV3Metrics / cvssV4Metrics**: Filter by CVSS vector strings
- **cvssV2Severity / cvssV3Severity / cvssV4Severity**: Filter by severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- **cweId**: Filter by CWE ID (e.g., `CWE-287`)
- **hasCertAlerts**: Include only CVEs with US-CERT Technical Alerts
- **hasCertNotes**: Include only CVEs with CERT/CC Vulnerability Notes
- **hasKev**: Include only CVEs in CISA's Known Exploited Vulnerabilities Catalog
- **hasOval**: Include only CVEs with OVAL records
- **isVulnerable**: Filter CPE matches to only vulnerable configurations
- **keywordSearch**: Search CVE descriptions (multiple keywords act as AND)
- **keywordExactMatch**: Require exact phrase match for keyword search
- **lastModStartDate / lastModEndDate**: Filter by last modification date (120-day max range)
- **pubStartDate / pubEndDate**: Filter by publication date (120-day max range)
- **kevStartDate / kevEndDate**: Filter by KEV catalog addition date (120-day max range)
- **noRejected**: Exclude CVEs with REJECT/Rejected status
- **sourceIdentifier**: Filter by data source (e.g., `cve@mitre.org`)
- **virtualMatchString**: Broader CPE filtering than cpeName
- **versionStart / versionStartType / versionEnd / versionEndType**: Filter CPE version ranges

### CVE Change History API Parameters

- **changeStartDate / changeEndDate**: Filter by change date (120-day max range, both required)
- **cveId**: Get complete change history for specific CVE
- **eventName**: Filter by event type (see Event Types below)

### Event Types

- `CVE Received`
- `Initial Analysis`
- `Reanalysis`
- `CVE Modified`
- `Modified Analysis`
- `CVE Translated`
- `Vendor Comment`
- `CVE Source Update`
- `CPE Deprecation Remap`
- `CWE Remap`
- `Reference Tag Update`
- `CVE Rejected`
- `CVE Unrejected`
- `CVE CISA KEV Update`

## Rate Limiting

The NVD API enforces rate limits:

- **Without API Key**: 5 requests per 30 seconds
- **With API Key**: 50 requests per 30 seconds

To obtain an API key, request one from the [NVD](https://nvd.nist.gov/developers/request-an-api-key).

### Automatic Retry Handling

The SDK automatically handles rate limiting (429 errors) with intelligent retry logic:

- ✅ Respects `Retry-After` headers (30 seconds for NVD API)
- ✅ Exponential backoff for other retryable errors
- ✅ Configurable retry attempts (default: 5)
- ✅ Logs retry attempts at WARN level
- ✅ Maximum retry duration to prevent infinite loops

See the [Rate Limiting Guide](docs/rate-limiting.md) for detailed information and best practices.

## Best Practices

1. **Use Date Ranges**: Request only CVEs modified since your last sync
2. **API Key**: Always use an API key for production to get higher rate limits
3. **Add Delays**: For batch operations, add 1-7 second delays between requests
4. **Pagination**: Let the SDK handle pagination automatically with `List()` methods
5. **Error Handling**: Check for rate limiting with `nvd.IsRateLimited(err)`
6. **Logging**: Use structured logging in production with `WithLogger()`
7. **Retry Configuration**: Adjust retry settings based on your use case

## Documentation

- [Quick Start Guide](docs/quick-start.md)
- [API Reference](docs/api-reference.md)
- [Usage Guide](docs/usage-guide.md)
- [Rate Limiting Guide](docs/rate-limiting.md)
- [Architecture](docs/architecture.md)
- [Examples](examples/)
- [NVD CVE API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [GoDoc](https://pkg.go.dev/github.com/deploymenttheory/go-sdk-cve)

## Contributing

Contributions are welcome. Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/deploymenttheory/go-sdk-cve/issues)
- **NVD API docs**: [nvd.nist.gov/developers](https://nvd.nist.gov/developers/vulnerabilities)

## Project Structure

```
go-sdk-cve/
├── nvd/                           # Main SDK package
│   ├── nvd.go                     # Client entry point
│   ├── with_options.go            # Configuration options
│   ├── client/                    # HTTP transport layer
│   │   ├── transport.go           # Core HTTP client
│   │   ├── request_builder.go    # Request construction
│   │   ├── pagination.go          # Automatic pagination
│   │   ├── retry.go               # Retry logic
│   │   ├── errors.go              # Error handling
│   │   └── ...
│   ├── config/                    # Configuration management
│   │   └── config.go              # Config loading and validation
│   ├── constants/                 # SDK constants
│   │   ├── endpoints.go           # API endpoints
│   │   ├── mime.go                # Content types
│   │   └── version.go             # SDK version
│   ├── cves/                      # CVE API service
│   │   ├── crud.go                # API operations
│   │   ├── models.go              # Request/response types
│   │   ├── enums.go               # Constants and enums
│   │   └── helpers.go             # Fluent API builders
│   ├── cve_history/               # CVE Change History API
│   │   ├── crud.go                # API operations
│   │   ├── models.go              # Request/response types
│   │   └── enums.go               # Event type constants
│   └── shared/                    # Shared utilities
│       └── environment/           # Environment variable helpers
├── examples/                      # Working code examples
│   ├── cves/                      # CVE API examples
│   │   ├── list_by_keyword/
│   │   ├── get_by_id/
│   │   ├── filter_by_severity/
│   │   ├── date_range_sync/
│   │   ├── kev_catalog/
│   │   └── fluent_api/
│   ├── cve_history/               # Change History examples
│   │   └── track_changes/
│   └── comprehensive/             # Full-featured example
├── docs/                          # Documentation
│   ├── quick-start.md             # Getting started guide
│   ├── api-reference.md           # Complete API reference
│   └── usage-guide.md             # Common patterns and best practices
├── go.mod                         # Go module definition
├── Makefile                       # Build and test targets
├── README.md                      # This file
└── CHANGELOG.md                   # Version history
```

## Architecture

The SDK follows a layered architecture inspired by the AWS SDK for Go:

1. **Transport Layer** (`nvd/client`): HTTP client with retry logic, pagination, error handling
2. **Service Layer** (`nvd/cves`, `nvd/cve_history`): API-specific operations and business logic
3. **Model Layer** (`models.go`): Type-safe request/response structures
4. **Configuration Layer** (`nvd/config`): Flexible configuration management

### Design Principles

- **SSOT (Single Source of Truth)**: Each piece of data has one authoritative location
- **DRY (Don't Repeat Yourself)**: Shared logic is abstracted into reusable components
- **SOLID Principles**: Clean interfaces and separation of concerns
- **Fail-Fast**: Invalid configurations and requests fail immediately with clear errors

## Disclaimer

This is a community SDK and is not affiliated with or endorsed by NIST or the National Vulnerability Database.
