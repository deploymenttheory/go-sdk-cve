# Architecture

This document describes the architecture and design decisions of the NVD CVE API SDK.

## Overview

The SDK is built following a layered architecture inspired by the AWS SDK for Go and the Jamf Pro SDK, with clear separation of concerns and well-defined interfaces between layers.

## Layers

### 1. Transport Layer (`nvd/client`)

The transport layer handles all HTTP communication with the NVD API.

**Components:**

- **Transport** (`transport.go`): Core HTTP client wrapping resty
- **RequestBuilder** (`request_builder.go`): Fluent API for constructing requests
- **Pagination** (`pagination.go`): Automatic pagination for large result sets
- **Retry Logic** (`retry.go`): Exponential backoff for transient errors
- **Error Handling** (`errors.go`): Structured error types and parsing

**Responsibilities:**

- HTTP request/response handling
- Authentication (API key header)
- Retry logic with exponential backoff
- Automatic pagination
- Error parsing and wrapping
- Logging and observability
- Connection pooling and timeouts

**Key Features:**

- Retries only idempotent methods (GET, PUT, DELETE)
- Handles 429 (rate limit), 503 (service unavailable), and 5xx errors
- Configurable timeouts and retry parameters
- Structured logging with zap

### 2. Service Layer (`nvd/cves`, `nvd/cve_history`)

The service layer provides API-specific operations and business logic.

**Components:**

- **CVEs Service** (`cves/`): CVE API operations
- **CVEHistory Service** (`cve_history/`): Change History API operations

**Responsibilities:**

- API endpoint routing
- Request parameter validation
- Response unmarshaling
- Pagination coordination
- Service-specific error handling

**Pattern:**

Each service follows the same structure:
- `crud.go`: API operations (List, GetByID, etc.)
- `models.go`: Request/response types
- `enums.go`: Constants and enumeration values
- `helpers.go`: Fluent API builders (optional)

### 3. Model Layer

Type-safe request and response structures.

**Design Principles:**

- Strongly typed fields with appropriate Go types
- JSON tags for serialization
- Pointer types for optional fields
- Time types for dates (automatic ISO-8601 handling)
- Helper methods for common operations

**Examples:**

```go
type CVE struct {
    ID               string
    Published        time.Time
    LastModified     time.Time
    VulnStatus       string
    Descriptions     []Description
    Metrics          *Metrics
    // ... more fields
}
```

### 4. Configuration Layer (`nvd/config`)

Flexible configuration management supporting multiple sources.

**Configuration Sources:**

1. Environment variables
2. JSON config files
3. Programmatic configuration

**Features:**

- Validation on load
- Sensible defaults
- Secure credential handling
- Optional API key support

### 5. Constants Layer (`nvd/constants`)

Shared constants used across all layers.

**Contents:**

- API endpoints
- MIME types
- SDK version

**Benefits:**

- Single source of truth
- Easy to update
- No circular dependencies

## Design Patterns

### Dependency Injection

Services receive a `client.Client` interface, not a concrete type:

```go
type CVEs struct {
    client client.Client
}

func NewCVEs(client client.Client) *CVEs {
    return &CVEs{client: client}
}
```

This enables:
- Easy testing with mocks
- Flexibility to swap implementations
- Clear dependency boundaries

### Functional Options

Configuration uses the functional options pattern:

```go
client, err := nvd.NewClient(
    cfg,
    nvd.WithTimeout(60*time.Second),
    nvd.WithRetryCount(5),
    nvd.WithLogger(logger),
)
```

Benefits:
- Optional parameters without overloading
- Backward compatibility
- Clear intent
- Type safety

### Request Builder

Fluent API for constructing requests:

```go
resp, err := s.client.NewRequest(ctx).
    SetHeader("Accept", constants.ApplicationJSON).
    SetQueryParams(queryParams).
    GetPaginated(endpoint, mergePage)
```

Benefits:
- Readable code
- Chainable methods
- Type safety
- Separation of construction from execution

### Automatic Pagination

Transparent pagination handling:

```go
resp, _, err := client.CVEs.List(ctx, &cves.ListRequest{
    KeywordSearch: "Windows",
})
// resp.Vulnerabilities contains ALL results
```

The SDK:
1. Makes initial request
2. Checks `totalResults` vs `resultsPerPage`
3. Automatically fetches remaining pages
4. Merges results into single response

### Error Handling

Structured error types with helper functions:

```go
if err != nil {
    if nvd.IsRateLimited(err) {
        // Handle rate limiting
    } else if nvd.IsServerError(err) {
        // Handle server errors
    }
}
```

## Data Flow

### Typical Request Flow

1. **Application** creates request with parameters
2. **Service Layer** validates and converts to query params
3. **Request Builder** constructs HTTP request
4. **Transport** applies auth, retry, pagination
5. **HTTP Client** executes request
6. **Transport** parses response or error
7. **Service Layer** unmarshals into typed models
8. **Application** receives typed response

### Pagination Flow

1. Service calls `GetPaginated()` with merge function
2. Transport makes first request with `startIndex=0`
3. Transport checks if more pages exist
4. Transport increments `startIndex` and fetches next page
5. Merge function combines results
6. Repeat until all pages fetched
7. Return combined results

### Error Flow

1. HTTP error occurs (4xx, 5xx)
2. Transport parses error response
3. Transport creates `APIError` with details
4. Error propagates up through service layer
5. Application checks error type with helpers

## Thread Safety

- **Transport**: Safe for concurrent use
- **Client**: Safe for concurrent use
- **Services**: Safe for concurrent use
- **Request/Response Models**: Immutable after creation

## Performance Considerations

### Connection Pooling

The underlying `resty` client uses Go's `http.Client` which automatically pools connections.

### Memory Management

- Streaming responses for large payloads
- Pagination prevents loading entire dataset
- Efficient JSON unmarshaling

### Rate Limiting

- Automatic retry with exponential backoff
- Configurable retry parameters
- Respects NVD rate limits

## Testing Strategy

### Unit Tests

- Config validation
- Query parameter building
- Helper functions
- Error handling

### Integration Tests

- Can be added with real API calls
- Use test API keys
- Verify pagination
- Verify error handling

### Mock Testing

Services accept `client.Client` interface, enabling easy mocking:

```go
type mockClient struct {
    response []byte
}

func (m *mockClient) NewRequest(ctx context.Context) *RequestBuilder {
    // Return mock builder
}
```

## Extension Points

### Adding New API Endpoints

1. Add endpoint constant to `constants/endpoints.go`
2. Create service package with models
3. Implement CRUD operations
4. Add to main client struct
5. Write tests and examples

### Adding Configuration Options

1. Add field to `TransportSettings`
2. Create `With*` function
3. Apply in `NewTransport()`
4. Document

### Custom Transport Middleware

Access the underlying resty client:

```go
transport := client.GetTransport()
httpClient := transport.GetHTTPClient()
httpClient.OnBeforeRequest(func(c *resty.Client, r *resty.Request) error {
    // Custom logic
    return nil
})
```

## Dependencies

### Core Dependencies

- **resty.dev/v3**: HTTP client with retry and middleware support
- **go.uber.org/zap**: Structured logging

### Why These Dependencies?

- **resty**: Mature, well-tested HTTP client with excellent middleware support
- **zap**: High-performance structured logging, industry standard

## Design Principles

### SSOT (Single Source of Truth)

- Constants defined once in `constants/`
- Endpoint URLs centralized
- No duplicate logic

### DRY (Don't Repeat Yourself)

- Shared utilities in `shared/`
- Common patterns abstracted to base types
- Reusable helper functions

### SOLID Principles

- **Single Responsibility**: Each package has one clear purpose
- **Open/Closed**: Extensible via options and interfaces
- **Liskov Substitution**: Services depend on interfaces
- **Interface Segregation**: Minimal, focused interfaces
- **Dependency Inversion**: Depend on abstractions, not concretions

### KISS (Keep It Simple)

- Clear, readable code
- Minimal abstraction layers
- Straightforward data flow

### Fail-Fast

- Validate configuration at startup
- Return errors immediately
- Clear error messages

## Comparison with Jamf Pro SDK

This SDK is architecturally based on the Jamf Pro SDK v2 with adaptations for the NVD API:

### Similarities

- Layered architecture
- Transport/Service separation
- Functional options pattern
- Request builder pattern
- Automatic pagination
- Structured logging
- Error handling

### Differences

- **No Authentication Flow**: NVD uses simple API key header (vs OAuth2/Basic)
- **Simpler Pagination**: Offset-based only (vs page-based)
- **Read-Only API**: No Create/Update/Delete operations
- **No Token Management**: No token refresh or invalidation
- **Different Error Patterns**: NVD-specific error responses

## Future Enhancements

Potential areas for expansion:

1. **Additional APIs**: CPE API, CPE Match String API, Source API
2. **Caching Layer**: Local cache for frequently accessed CVEs
3. **Webhook Support**: If NVD adds webhook functionality
4. **Bulk Operations**: Optimized batch fetching
5. **Metrics**: Prometheus metrics for observability
6. **OpenTelemetry**: Distributed tracing support
