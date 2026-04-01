# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-01

### Added
- Initial SDK implementation for NVD CVE API v2.0
- Complete CVE API v2.0 support with all 30+ parameters
- Complete CVE Change History API v2.0 support
- Automatic pagination for large result sets (handles 341,616+ CVE records)
- Retry logic with exponential backoff for transient errors
- Rate limit handling (429 responses) with clear error messages
- Structured logging with zap (info, debug, error levels)
- API key authentication support
- Flexible configuration (environment variables, JSON files, programmatic)
- Type-safe request and response models
- Fluent request builder API for readable code
- Error type checking helpers (IsNotFound, IsRateLimited, IsBadRequest, etc.)
- Custom `nvdtime.Time` type to handle NVD API's inconsistent timestamp formats
- Configurable timeouts, retries, and HTTP transport settings
- Proxy support and custom TLS configuration
- 10 working examples demonstrating common use cases
- Comprehensive documentation (7 guides)
- Unit tests with 100% pass rate
- GitHub Actions CI/CD workflows (testing and linting)
- Makefile for common development tasks

### Technical Details
- Based on Jamf Pro SDK v2 architecture
- Uses `resty.dev/v3` for HTTP client with middleware support
- Uses `go.uber.org/zap` for structured logging
- Follows SOLID, DRY, KISS, and Fail-Fast principles
- Supports Go 1.25.0+
