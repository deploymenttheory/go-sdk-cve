# Contributing to go-sdk-cve

Thank you for your interest in contributing to the NVD CVE API SDK for Go!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/go-sdk-cve.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `make test`
6. Run linter: `make lint`
7. Commit your changes
8. Push to your fork
9. Open a Pull Request

## Development Setup

### Prerequisites

- Go 1.25.0 or later
- golangci-lint (for linting)

### Install Dependencies

```bash
go mod download
```

### Run Tests

```bash
make test
```

### Run Linter

```bash
make lint
```

### Build All Packages

```bash
make build
```

### Build Examples

```bash
make examples
```

## Code Style

This project follows standard Go conventions and principles:

- **SSOT (Single Source of Truth)**: Avoid duplication
- **YAGNI (You Aren't Gonna Need It)**: Don't add unused features
- **KISS (Keep It Simple, Stupid)**: Prefer simple solutions
- **DRY (Don't Repeat Yourself)**: Extract common logic
- **SOLID Principles**: Clean interfaces and separation of concerns

### Formatting

- Use `gofmt` for formatting (enforced by CI)
- Follow [Effective Go](https://golang.org/doc/effective_go.html) guidelines
- Use meaningful variable and function names
- Add comments for exported types and functions

### Testing

- Write unit tests for new functionality
- Maintain or improve code coverage
- Use table-driven tests where appropriate
- Mock external dependencies

## Project Structure

Follow the existing architecture:

- `nvd/client/`: HTTP transport and request handling
- `nvd/config/`: Configuration management
- `nvd/constants/`: Shared constants
- `nvd/cves/`: CVE API service
- `nvd/cve_history/`: CVE Change History API service
- `nvd/shared/`: Shared utilities
- `examples/`: Working code examples
- `docs/`: Documentation

## Adding New Features

### Adding a New API Endpoint

1. Add the endpoint constant to `nvd/constants/endpoints.go`
2. Create models in the appropriate service package
3. Implement CRUD operations following existing patterns
4. Add tests
5. Create an example in `examples/`
6. Update documentation

### Adding Configuration Options

1. Add the option to `client.TransportSettings` in `nvd/client/settings.go`
2. Create a `With*` function in `nvd/with_options.go`
3. Apply the option in `client.NewTransport()`
4. Document the option in README and docs

## Pull Request Guidelines

### PR Title

Use conventional commit format:

- `feat: add support for CPE API`
- `fix: correct pagination logic for large result sets`
- `docs: update quick start guide`
- `test: add unit tests for CVE filtering`
- `refactor: simplify error handling`
- `chore: update dependencies`

### PR Description

Include:

- **Summary**: What does this PR do?
- **Motivation**: Why is this change needed?
- **Testing**: How was this tested?
- **Breaking Changes**: Any breaking changes?
- **Related Issues**: Link to related issues

### Checklist

- [ ] Tests pass locally
- [ ] Linter passes
- [ ] Documentation updated
- [ ] Examples added/updated if needed
- [ ] CHANGELOG.md updated

## Contribution

Thanks for considering contributing to this project! We are really glad you are reading this, because we need volunteer developers to help this project come to fruition.

Please note we have a code of conduct, please follow it in all your interactions with the project.

## Issues

If you find any bugs, please file an issue in the [GitHub issues][GitHubIssues] page. Please fill out the provided template with the appropriate information.

If you are taking the time to mention a problem, even a seemingly minor one, it is greatly appreciated, and a totally valid contribution to this project. Thank you!

<!-- References -->

<!-- Local -->
[GitHubIssues]: <https://github.com/segraef/Template/issues>
[Contributing]: CONTRIBUTING.md
