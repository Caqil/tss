# Contributing to MPC-TSS

Thank you for your interest in contributing to MPC-TSS! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on what is best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check existing issues to avoid duplicates
2. Collect relevant information (Go version, OS, steps to reproduce)
3. Create a minimal reproducible example

When filing a bug report, include:
- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (Go version, OS, architecture)
- **Code samples** or error messages
- **Possible solution** if you have one

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear, descriptive title**
- **Provide detailed description** of the proposed functionality
- **Explain why this enhancement would be useful**
- **List any alternatives** you've considered
- **Include code examples** if applicable

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the coding standards** (see below)
3. **Add tests** for any new functionality
4. **Ensure all tests pass** locally
5. **Run linters** and fix any issues
6. **Update documentation** if needed
7. **Commit with descriptive messages**
8. **Submit the pull request**

#### Branch Naming

- Feature: `feature/description`
- Bug fix: `fix/description`
- Documentation: `docs/description`
- Performance: `perf/description`
- Security: `security/description`

#### Commit Messages

Follow conventional commits format:

```
type(scope): subject

body (optional)

footer (optional)
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `security`: Security improvements

Examples:
```
feat(keygen): implement Feldman VSS protocol

- Add polynomial generation
- Implement share distribution
- Add verification with commitments

Closes #123
```

```
fix(signing): prevent timing attack in scalar operations

Use constant-time comparison for all secret-dependent operations

Security issue reported by @username
```

## Development Setup

### Prerequisites

```bash
# Install Go 1.20+
go version

# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

### Clone and Build

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/mpc-tss.git
cd mpc-tss

# Add upstream remote
git remote add upstream https://github.com/Caqil/mpc-tss.git

# Install dependencies
go mod download

# Build
go build ./...

# Run tests
go test ./...
```

## Coding Standards

### Go Style Guide

Follow the official [Effective Go](https://golang.org/doc/effective_go.html) guidelines and:

1. **Formatting**: Use `gofmt` and `goimports`
2. **Naming**: Follow Go naming conventions
3. **Documentation**: All exported functions must have godoc comments
4. **Error handling**: Always check and handle errors
5. **Testing**: Maintain >90% test coverage

### Security Requirements

This is a security-critical library. All code must:

1. **Use constant-time operations** for secret data
2. **Zero sensitive data** after use
3. **Validate all inputs** thoroughly
4. **Handle errors securely** (no information leakage)
5. **Never log secrets** or sensitive information
6. **Follow security best practices**

Example of secure code:

```go
// ✅ GOOD: Constant-time comparison
func SecureCompare(a, b []byte) bool {
    return subtle.ConstantTimeCompare(a, b) == 1
}

// ❌ BAD: Timing leak
func InsecureCompare(a, b []byte) bool {
    return bytes.Equal(a, b)
}

// ✅ GOOD: Secure zeroing
defer security.SecureZero(secretData)

// ✅ GOOD: Input validation
if err := security.ValidateThreshold(t, n); err != nil {
    return err
}

// ✅ GOOD: Redacted logging
logger.Info().Str("key_id", logger.RedactSecret(keyID)).Msg("Key loaded")
```

### Testing Requirements

All code must include:

1. **Unit tests** for all functions
2. **Table-driven tests** for multiple cases
3. **Error case testing**
4. **Benchmark tests** for performance-critical code
5. **Security tests** for crypto operations

Example test structure:

```go
func TestScalarAdd(t *testing.T) {
    tests := []struct {
        name    string
        a       *big.Int
        b       *big.Int
        want    *big.Int
        wantErr bool
    }{
        {
            name: "valid addition",
            a:    big.NewInt(5),
            b:    big.NewInt(7),
            want: big.NewInt(12),
        },
        {
            name:    "nil input",
            a:       nil,
            b:       big.NewInt(5),
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ScalarAdd(tt.a, tt.b)
            if (err != nil) != tt.wantErr {
                t.Errorf("ScalarAdd() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !tt.wantErr && got.Cmp(tt.want) != 0 {
                t.Errorf("ScalarAdd() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Running Tests and Linters

```bash
# Run all tests
go test ./...

# Run tests with race detector
go test -race ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run linters
golangci-lint run

# Run security scanner
gosec ./...

# Format code
gofmt -s -w .
goimports -w .
```

## Documentation

### Code Documentation

- All exported types, functions, and constants must have godoc comments
- Comments should explain **why**, not just **what**
- Include examples for complex functionality
- Reference relevant papers or standards

Example:

```go
// GenerateRandomScalar generates a cryptographically secure random scalar
// in the range [1, max). This uses rejection sampling to ensure uniform
// distribution, as recommended by FIPS 186-4.
//
// The function never returns zero, as zero is not a valid scalar for
// cryptographic operations.
//
// Returns an error if max is nil, non-positive, or if random generation fails.
func GenerateRandomScalar(max *big.Int) (*big.Int, error) {
    // Implementation...
}
```

### Documentation Files

Keep these files up to date:
- `README.md` - Main project overview
- `ARCHITECTURE.md` - System design
- `SECURITY.md` - Security model
- `docs/` - Detailed guides

## Review Process

### Pull Request Review

All PRs require:
1. **One approval** from a maintainer
2. **Two approvals** for security-critical code
3. **All CI checks** must pass
4. **No unresolved comments**
5. **Up-to-date with main branch**

### What Reviewers Look For

- Code correctness and quality
- Security considerations
- Test coverage
- Documentation completeness
- Performance implications
- Breaking changes (require major version bump)

## Security Contributions

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email: **security@[your-domain].com**

Include:
- Detailed description
- Proof of concept
- Potential impact
- Suggested fix

### Security-Critical Changes

Changes to these areas require extra scrutiny:
- Cryptographic operations
- Key generation and handling
- Network protocols
- Input validation
- Random number generation

## Release Process

Releases follow semantic versioning (SemVer):
- **Major** (x.0.0): Breaking changes
- **Minor** (1.x.0): New features, backward compatible
- **Patch** (1.0.x): Bug fixes, backward compatible

Only maintainers can create releases.

## Getting Help

- **Questions**: Open a [GitHub Discussion](https://github.com/Caqil/mpc-tss/discussions)
- **Bugs**: Open an [Issue](https://github.com/Caqil/mpc-tss/issues)
- **Security**: Email security@[your-domain].com
- **Chat**: Join our Discord/Slack (if available)

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- GitHub contributors page

Significant contributions may be highlighted in the README.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to MPC-TSS! 🎉
