# API Reference

## Client Creation

### NewClient

Creates a new NVD API client with the provided configuration.

```go
func NewClient(cfg *Config, options ...ClientOption) (*Client, error)
```

**Parameters:**
- `cfg`: Configuration containing API key and base URL
- `options`: Optional configuration functions

**Returns:**
- `*Client`: Configured client instance
- `error`: Error if configuration is invalid

**Example:**

```go
cfg := &nvd.Config{
    APIKey:  "your-api-key",
    BaseURL: "https://services.nvd.nist.gov",
}
client, err := nvd.NewClient(cfg)
```

### NewClientFromEnv

Creates a client using environment variables.

```go
func NewClientFromEnv(options ...ClientOption) (*Client, error)
```

**Environment Variables:**
- `NVD_API_KEY`: Your NVD API key (optional but recommended)
- `NVD_BASE_URL`: Base URL (default: `https://services.nvd.nist.gov`)
- `HIDE_SENSITIVE_DATA`: Hide API key in logs (default: `false`)

**Example:**

```go
client, err := nvd.NewClientFromEnv(
    nvd.WithTimeout(60*time.Second),
    nvd.WithLogger(logger),
)
```

## CVE API

### List

Retrieves CVEs matching the specified criteria with automatic pagination.

```go
func (s *CVEs) List(ctx context.Context, req *ListRequest) (*CVEResponse, *resty.Response, error)
```

**Parameters:**
- `ctx`: Context for request cancellation and timeouts
- `req`: Filter criteria (see ListRequest below)

**Returns:**
- `*CVEResponse`: Response containing all matching CVEs
- `*resty.Response`: Raw HTTP response
- `error`: Error if request fails

### GetByID

Retrieves a specific CVE by its ID.

```go
func (s *CVEs) GetByID(ctx context.Context, cveID string) (*VulnerabilityItem, *resty.Response, error)
```

**Parameters:**
- `ctx`: Context for request cancellation
- `cveID`: CVE identifier (e.g., "CVE-2021-44228")

**Returns:**
- `*VulnerabilityItem`: The CVE data
- `*resty.Response`: Raw HTTP response
- `error`: Error if CVE not found or request fails

## ListRequest Fields

### Filtering by CVE Properties

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `CVEID` | `string` | Specific CVE ID | `"CVE-2021-44228"` |
| `CVETag` | `string` | CVE tag filter | `"disputed"` |
| `SourceIdentifier` | `string` | Data source | `"cve@mitre.org"` |
| `NoRejected` | `bool` | Exclude rejected CVEs | `true` |

### Filtering by CVSS

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `CVSSV2Metrics` | `string` | CVSSv2 vector string | `"AV:N/AC:L/Au:N/C:C/I:C/A:C"` |
| `CVSSV2Severity` | `string` | CVSSv2 severity | `"HIGH"` |
| `CVSSV3Metrics` | `string` | CVSSv3 vector string | `"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `CVSSV3Severity` | `string` | CVSSv3 severity | `"CRITICAL"` |
| `CVSSV4Metrics` | `string` | CVSSv4 vector string | `"AV:N/AC:L/PR:N/UI:N"` |
| `CVSSV4Severity` | `string` | CVSSv4 severity | `"HIGH"` |

### Filtering by CPE

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `CPEName` | `string` | Exact CPE match | `"cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"` |
| `VirtualMatchString` | `string` | Broader CPE match | `"cpe:2.3:o:linux:linux_kernel"` |
| `IsVulnerable` | `bool` | Only vulnerable CPE configs | `true` |
| `VersionStart` | `string` | Starting version | `"2.6"` |
| `VersionStartType` | `string` | Include/exclude start | `"including"` |
| `VersionEnd` | `string` | Ending version | `"2.7"` |
| `VersionEndType` | `string` | Include/exclude end | `"excluding"` |

### Filtering by Weakness

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `CWEID` | `string` | CWE identifier | `"CWE-287"` |

### Filtering by External Catalogs

| Field | Type | Description |
|-------|------|-------------|
| `HasCertAlerts` | `bool` | Include only CVEs with US-CERT alerts |
| `HasCertNotes` | `bool` | Include only CVEs with CERT/CC notes |
| `HasKEV` | `bool` | Include only CVEs in CISA KEV catalog |
| `HasOVAL` | `bool` | Include only CVEs with OVAL records |

### Filtering by Date

| Field | Type | Description | Notes |
|-------|------|-------------|-------|
| `LastModStartDate` | `*time.Time` | Last modified start | Max 120-day range |
| `LastModEndDate` | `*time.Time` | Last modified end | Required with start |
| `PubStartDate` | `*time.Time` | Publication start | Max 120-day range |
| `PubEndDate` | `*time.Time` | Publication end | Required with start |
| `KEVStartDate` | `*time.Time` | KEV addition start | Max 120-day range |
| `KEVEndDate` | `*time.Time` | KEV addition end | Required with start |

### Keyword Search

| Field | Type | Description |
|-------|------|-------------|
| `KeywordSearch` | `string` | Search CVE descriptions (multiple words = AND) |
| `KeywordExactMatch` | `bool` | Require exact phrase match |

### Pagination

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `ResultsPerPage` | `int` | Results per page | 2000 (max) |
| `StartIndex` | `int` | Starting index (0-based) | 0 |

## CVE Change History API

### List

Retrieves CVE change history with automatic pagination.

```go
func (s *CVEHistory) List(ctx context.Context, req *ListRequest) (*CVEHistoryResponse, *resty.Response, error)
```

### GetByCVEID

Retrieves complete change history for a specific CVE.

```go
func (s *CVEHistory) GetByCVEID(ctx context.Context, cveID string) (*CVEHistoryResponse, *resty.Response, error)
```

## CVE History ListRequest Fields

| Field | Type | Description | Notes |
|-------|------|-------------|-------|
| `ChangeStartDate` | `*time.Time` | Change period start | Max 120-day range |
| `ChangeEndDate` | `*time.Time` | Change period end | Required with start |
| `CVEID` | `string` | Specific CVE ID | Returns complete history |
| `EventName` | `string` | Event type filter | See Event Types below |
| `ResultsPerPage` | `int` | Results per page | Default: 5000 (max) |
| `StartIndex` | `int` | Starting index | Default: 0 |

## Event Types

Use these constants from `cve_history` package:

```go
cve_history.EventCVEReceived           // "CVE Received"
cve_history.EventInitialAnalysis       // "Initial Analysis"
cve_history.EventReanalysis            // "Reanalysis"
cve_history.EventCVEModified           // "CVE Modified"
cve_history.EventModifiedAnalysis      // "Modified Analysis"
cve_history.EventCVETranslated         // "CVE Translated"
cve_history.EventVendorComment         // "Vendor Comment"
cve_history.EventCVESourceUpdate       // "CVE Source Update"
cve_history.EventCPEDeprecationRemap   // "CPE Deprecation Remap"
cve_history.EventCWERemap              // "CWE Remap"
cve_history.EventReferenceTagUpdate    // "Reference Tag Update"
cve_history.EventCVERejected           // "CVE Rejected"
cve_history.EventCVEUnrejected         // "CVE Unrejected"
cve_history.EventCVECISAKEVUpdate      // "CVE CISA KEV Update"
```

## Configuration Options

### WithTimeout

Sets request timeout.

```go
nvd.WithTimeout(60 * time.Second)
```

### WithRetryCount

Sets number of retry attempts.

```go
nvd.WithRetryCount(5)
```

### WithRetryWaitTime

Sets initial wait time between retries.

```go
nvd.WithRetryWaitTime(3 * time.Second)
```

### WithRetryMaxWaitTime

Sets maximum wait time between retries.

```go
nvd.WithRetryMaxWaitTime(60 * time.Second)
```

### WithLogger

Sets custom zap logger.

```go
logger, _ := zap.NewProduction()
nvd.WithLogger(logger)
```

### WithDebug

Enables debug mode (logs all requests/responses).

```go
nvd.WithDebug()
```

### WithProxy

Sets HTTP proxy.

```go
nvd.WithProxy("http://proxy.example.com:8080")
```

### WithTLSClientConfig

Sets custom TLS configuration.

```go
tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
nvd.WithTLSClientConfig(tlsConfig)
```

### WithGlobalHeader

Adds a header to all requests.

```go
nvd.WithGlobalHeader("X-Application-Name", "MyApp")
```

## Error Handling

The SDK provides helper functions for error type checking:

```go
if err != nil {
    if nvd.IsNotFound(err) {
        // Handle 404
    } else if nvd.IsRateLimited(err) {
        // Handle 429 - rate limited
    } else if nvd.IsServerError(err) {
        // Handle 5xx
    } else if nvd.IsBadRequest(err) {
        // Handle 400
    } else if nvd.IsUnauthorized(err) {
        // Handle 401
    }
}
```

## Response Structures

### CVEResponse

```go
type CVEResponse struct {
    ResultsPerPage  int
    StartIndex      int
    TotalResults    int
    Format          string
    Version         string
    Timestamp       time.Time
    Vulnerabilities []VulnerabilityItem
}
```

### VulnerabilityItem

```go
type VulnerabilityItem struct {
    CVE CVE
}
```

### CVE

```go
type CVE struct {
    ID                    string
    SourceIdentifier      string
    Published             time.Time
    LastModified          time.Time
    VulnStatus            string
    EvaluatorComment      *string
    EvaluatorImpact       *string
    EvaluatorSolution     *string
    CISAExploitAdd        *string
    CISAActionDue         *string
    CISARequiredAction    *string
    CISAVulnerabilityName *string
    CVETags               []CVETag
    Descriptions          []Description
    Metrics               *Metrics
    Weaknesses            []Weakness
    Configurations        []Configuration
    References            []Reference
    VendorComments        []VendorComment
}
```

## Best Practices

1. **Use API Keys**: Always use an API key in production for higher rate limits
2. **Date Ranges**: Use 120-day maximum ranges for date filters
3. **Pagination**: Let the SDK handle pagination automatically
4. **Error Handling**: Check for rate limiting and implement backoff
5. **Logging**: Use structured logging in production
6. **Context**: Always pass context for request cancellation
7. **Incremental Sync**: Use `LastModStartDate`/`LastModEndDate` to fetch only new/modified CVEs

## Rate Limits

| Mode | Rate Limit |
|------|------------|
| Without API Key | 5 requests / 30 seconds |
| With API Key | 50 requests / 30 seconds |

The SDK automatically handles 429 responses with exponential backoff.
