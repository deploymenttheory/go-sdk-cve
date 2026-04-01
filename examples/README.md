# Examples

This directory contains working examples demonstrating various features of the NVD CVE API SDK.

## Prerequisites

Before running any example, set your NVD API key:

```bash
export NVD_API_KEY="your-api-key-here"
```

You can request an API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key).

## CVE API Examples

### simple_search

Minimal example showing basic keyword search with clean output.

```bash
cd cves/simple_search
go run main.go
```

### list_by_keyword

Search CVEs by keyword in descriptions.

```bash
cd cves/list_by_keyword
go run main.go
```

### get_by_id

Retrieve a specific CVE by its ID.

```bash
cd cves/get_by_id
go run main.go
```

### filter_by_severity

Filter CVEs by CVSS v3 severity rating.

```bash
cd cves/filter_by_severity
go run main.go
```

### date_range_sync

Fetch CVEs modified within a date range (useful for incremental syncing).

```bash
cd cves/date_range_sync
go run main.go
```

### kev_catalog

Work with CISA's Known Exploited Vulnerabilities (KEV) Catalog.

```bash
cd cves/kev_catalog
go run main.go
```

### fluent_api

Demonstrates the fluent API pattern for building requests.

```bash
cd cves/fluent_api
go run main.go
```

## CVE Change History Examples

### track_changes

Monitor changes to CVE records over time.

```bash
cd cve_history/track_changes
go run main.go
```

## Comprehensive Examples

### comprehensive

Full-featured example demonstrating all major SDK capabilities.

```bash
cd comprehensive
go run main.go
```

### comprehensive_rate_limited

Same as comprehensive but adds delays between requests to avoid rate limiting.

```bash
cd comprehensive_rate_limited
go run main.go
```

**Recommended for users without an API key** - adds 7-second delays to respect the 5 req/30s limit.

### vulnerability_scanner

Command-line vulnerability scanner tool.

```bash
cd vulnerability_scanner

# Scan by keyword
go run main.go -keyword "Apache Log4j" -days 90

# Scan by CPE
go run main.go -cpe "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*" -days 365

# Save report to file
go run main.go -keyword "Windows" -days 30 -output report.txt
```

## Building All Examples

From the repository root:

```bash
make examples
```

Or manually:

```bash
cd examples/cves/list_by_keyword && go build
cd ../get_by_id && go build
cd ../filter_by_severity && go build
cd ../date_range_sync && go build
cd ../kev_catalog && go build
cd ../fluent_api && go build
cd ../../cve_history/track_changes && go build
cd ../../comprehensive && go build
cd ../../vulnerability_scanner && go build
```

## Customizing Examples

All examples use `nvd.NewClientFromEnv()` which reads from environment variables. You can modify them to use:

### Config File

```go
cfg, err := nvd.LoadConfigFromFile("config.json")
if err != nil {
    log.Fatal(err)
}
client, err := nvd.NewClient(cfg)
```

### Programmatic Config

```go
cfg := &nvd.Config{
    APIKey:  "your-api-key",
    BaseURL: "https://services.nvd.nist.gov",
}
client, err := nvd.NewClient(cfg)
```

## Rate Limiting

All examples respect NVD API rate limits:

- **Without API Key**: 5 requests per 30 seconds
- **With API Key**: 50 requests per 30 seconds

The SDK automatically handles rate limiting with exponential backoff.

## Need Help?

- Check the [Quick Start Guide](../docs/quick-start.md)
- Read the [API Reference](../docs/api-reference.md)
- Review the [Usage Guide](../docs/usage-guide.md)
- Open an [issue](https://github.com/deploymenttheory/go-sdk-cve/issues)
