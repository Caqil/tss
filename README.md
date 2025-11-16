# MPC-TSS: Multi-Party Computation Threshold Signature Scheme

[![CI](https://github.com/Caqil/mpc-tss/workflows/CI/badge.svg)](https://github.com/Caqil/mpc-tss/actions)
[![Security](https://github.com/Caqil/mpc-tss/workflows/Security%20Audit/badge.svg)](https://github.com/Caqil/mpc-tss/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/Caqil/mpc-tss)](https://goreportcard.com/report/github.com/Caqil/mpc-tss)
[![GoDoc](https://godoc.org/github.com/Caqil/mpc-tss?status.svg)](https://godoc.org/github.com/Caqil/mpc-tss)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A **production-grade**, **security-first** implementation of Multi-Party Computation Threshold Signature Scheme (MPC-TSS) in Go. This library enables distributed key generation and threshold signing without requiring any single party to hold the complete private key.

## 🎯 Features

### Security First
- ✅ **Constant-time operations** for all secret data
- ✅ **Zero-knowledge proofs** for protocol correctness
- ✅ **Secure memory handling** with automatic zeroing
- ✅ **Side-channel resistance** (timing attack prevention)
- ✅ **Malicious adversary model** with identifiable abort
- ✅ **No secrets in logs** (automatic redaction)

### Cryptographic Protocols
- 🔐 **ECDSA GG20** threshold signatures
- 🔑 **Distributed Key Generation** (DKG) with Feldman VSS
- 📝 **Multi-round signing** protocol
- 🎲 **Presigning** for faster online phase
- 🔍 **Zero-knowledge proofs** (Schnorr, Range, Equality)

### Supported Curves
- **secp256k1** (Bitcoin/Ethereum)
- **P-256** (NIST standard)
- **Ed25519** (future support planned)

### Developer Experience
- 📚 **Comprehensive documentation**
- 🧪 **Extensive test suite** (>90% coverage)
- 🛡️ **Security-focused linting** (gosec, golangci-lint)
- 🚀 **Production-ready** with proper error handling
- 📊 **Structured logging** with zerolog
- 🔄 **CI/CD pipeline** with automated security scanning

## 📦 Installation

```bash
go get github.com/Caqil/mpc-tss
```

### Requirements

- Go 1.20 or higher
- Supported platforms: Linux, macOS, Windows

## 🚀 Quick Start

### Running Examples

We provide several complete, working examples:

```bash
# Run all working examples
./test-working-examples.sh

# Or test all examples with detailed reporting
./test-examples.sh

# Run individual examples
go run cmd/examples/simple_dkg/main.go         # DKG demo
go run cmd/examples/storage_demo/main.go       # Storage demo
go run cmd/examples/simple-signing/main.go     # Signing demo
go run cmd/examples/multi-party-demo/main.go   # Multi-party demo
go run cmd/examples/key-refresh/main.go        # Key refresh demo
```

### Available Examples

| Example | Description | Status |
|---------|-------------|--------|
| **simple_dkg** | 2-of-3 Distributed Key Generation | ✅ **Working** |
| **storage_demo** | Encrypted key share storage with AES-256-GCM | ✅ **Working** |
| **simple-signing** | 2-of-3 threshold signature generation | ✅ **Working** |
| **multi-party-demo** | 3-of-5 multi-signature Bitcoin wallet simulation | ✅ **Working** |
| **key-refresh** | Proactive security through share refresh | ✅ **Working** |

### Example: Simple DKG (2-of-3)

```go
package main

import (
    "fmt"
    "github.com/Caqil/mpc-tss/pkg/keygen"
    "github.com/Caqil/mpc-tss/pkg/crypto/curve"
)

func main() {
    threshold := 2
    totalParties := 3

    // Create DKG instances
    dkgs := make([]*keygen.DKGProtocol, totalParties)
    for i := 0; i < totalParties; i++ {
        dkg, _ := keygen.NewDKGProtocol(i, threshold, totalParties, curve.Secp256k1)
        dkgs[i] = dkg
    }

    // Round 1: Generate commitments
    round1Data := make([]*keygen.Round1Data, totalParties)
    for i := 0; i < totalParties; i++ {
        round1Data[i], _ = dkgs[i].Round1()
    }

    // Round 2: Exchange shares
    round2Data := make([][]*keygen.Round2Data, totalParties)
    for i := 0; i < totalParties; i++ {
        round2Data[i], _ = dkgs[i].Round2(round1Data)
    }

    // Round 3: Finalize key shares
    // ... (see cmd/examples/simple_dkg/main.go for complete code)

    fmt.Println("✓ DKG Complete!")
}
```

### Example: Secure Storage

```go
package main

import (
    "github.com/Caqil/mpc-tss/pkg/storage"
    "github.com/Caqil/mpc-tss/pkg/keygen"
)

func main() {
    // Create storage with encryption
    config := storage.DefaultStorageConfig("keyshare.enc")
    store, _ := storage.NewFileStorage(config)

    // Save encrypted key share
    password := "MySecurePassword123!"
    store.Save(keyShare, password)

    // Load encrypted key share
    loadedShare, _ := store.Load(password)

    // Features: backup, restore, password rotation, metadata access
}
```

See [cmd/examples/](cmd/examples/) for complete, runnable implementations.

## 📖 Documentation

### Core Documentation
- [Architecture](ARCHITECTURE.md) - System design and components
- [Security Model](SECURITY.md) - Threat model and security guarantees
- [API Reference](docs/API.md) - Complete API documentation
- [Examples](cmd/examples/) - Working code examples

### Quick Links
- [Installation Guide](docs/installation.md)
- [Usage Guide](docs/usage.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
└─────────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐      ┌──────▼──────┐    ┌─────▼─────┐
   │ Keygen  │      │   Signing   │    │  Storage  │
   └────┬────┘      └──────┬──────┘    └─────┬─────┘
        │                  │                  │
   ┌────▼──────────────────▼──────────────────▼─────┐
   │            Core Crypto Layer                    │
   │  ┌─────────┐  ┌──────┐  ┌────────┐            │
   │  │ Curves  │  │  ZK  │  │  Hash  │            │
   │  └─────────┘  └──────┘  └────────┘            │
   └─────────────────────────────────────────────────┘
                           │
   ┌───────────────────────▼───────────────────────┐
   │            Network Layer (P2P)                 │
   │        TLS 1.3 + Authenticated Encryption     │
   └───────────────────────────────────────────────┘
```

### Package Structure

```
mpc-tss/
├── pkg/                    # Public packages
│   ├── keygen/            # Distributed Key Generation
│   ├── signing/           # Threshold Signing
│   ├── crypto/            # Cryptographic primitives
│   │   ├── curve/         # Elliptic curve operations
│   │   ├── commitment/    # Commitment schemes
│   │   ├── hash/          # Hash functions
│   │   └── rand/          # Secure random generation
│   ├── zk/                # Zero-knowledge proofs
│   ├── network/           # P2P communication
│   ├── storage/           # Secure key storage
│   └── logger/            # Structured logging
├── internal/              # Internal packages
│   ├── math/              # Big number operations
│   └── security/          # Security utilities
├── cmd/examples/          # Example applications
├── tests/                 # Comprehensive test suite
└── docs/                  # Documentation
```

## 🔐 Security

### Threat Model

This library is designed to withstand:
- **Malicious adversaries** controlling up to `t-1` parties
- **Network eavesdropping** and active attacks
- **Timing attacks** and side-channel analysis
- **Protocol deviation** and cheating attempts

### Security Features

| Feature | Implementation |
|---------|----------------|
| Secret Protection | Constant-time operations, secure zeroing |
| Protocol Security | Zero-knowledge proofs, verifiable shares |
| Network Security | TLS 1.3, authenticated encryption |
| Attack Prevention | Replay protection, timeout mechanisms |
| Error Handling | Fail-safe, identifiable abort |

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email: **security@[your-domain].com**

See [SECURITY.md](SECURITY.md) for details.

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run integration tests
go test -tags=integration ./tests/integration/...

# Run security tests
go test ./tests/security/...

# Run benchmarks
go test -bench=. ./tests/benchmarks/...
```

## 📊 Performance

### Benchmarks (on M1 MacBook Pro)

| Operation | Parties | Threshold | Time | Memory |
|-----------|---------|-----------|------|--------|
| DKG | 3 | 2 | ~2.1s | ~28MB |
| DKG | 5 | 3 | ~3.8s | ~47MB |
| DKG | 7 | 5 | ~5.4s | ~76MB |
| Signing | 3 | 2 | ~0.9s | ~18MB |
| Signing | 5 | 3 | ~1.4s | ~27MB |
| Presigning | 5 | 3 | ~750ms | ~22MB |

### Performance Goals
- ✅ DKG: < 5 seconds for 5 parties
- ✅ Signing: < 2 seconds for 3-of-5
- ✅ Memory: < 100 MB per party
- ✅ Network: < 10 KB per round per party

## 🛠️ Development

### Prerequisites

```bash
# Install Go 1.20+
brew install go  # macOS
# or download from https://golang.org/dl/

# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

### Build

```bash
# Build library
go build ./...

# Build examples
cd cmd/examples/simple-dkg && go build
cd ../simple-signing && go build
```

### Linting

```bash
# Run all linters
golangci-lint run

# Run security scanner
gosec ./...

# Format code
gofmt -s -w .
goimports -w .
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests (maintain >90% coverage)
5. Run linters and tests
6. Commit with descriptive message
7. Push to your fork
8. Open a Pull Request

### Code Review Process

- All PRs require review from at least one maintainer
- Security-critical code requires review from two maintainers
- All CI checks must pass
- Test coverage must not decrease

## 📋 Roadmap

### v1.0.0 (Current)
- [x] Core cryptographic primitives
- [x] DKG protocol (Feldman VSS)
- [x] Threshold signing (GG20)
- [x] secp256k1 and P-256 support
- [x] Comprehensive test suite
- [x] Security auditing tools
- [ ] Professional security audit
- [ ] Production deployment guide

### v1.1.0 (Future)
- [ ] EdDSA FROST protocol
- [ ] Key resharing
- [ ] Proactive refresh
- [ ] BLS12-381 support
- [ ] Hardware security module (HSM) integration

### v2.0.0 (Future)
- [ ] Post-quantum cryptography
- [ ] Advanced protocols (BBS+, etc.)
- [ ] Formal verification
- [ ] Performance optimizations

## 📜 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

### Why Apache 2.0?

- **Patent protection**: Grants explicit patent rights
- **Enterprise-friendly**: Compatible with commercial use
- **Permissive**: Allows modification and distribution
- **Community standard**: Widely accepted in Go ecosystem

## 🙏 Acknowledgments

This implementation builds upon research and work from:

- **Gennaro & Goldfeder** - [GG20 Paper](https://eprint.iacr.org/2020/540)
- **Lindell** - [Fast Secure Two-Party ECDSA Signing](https://eprint.iacr.org/2017/552)
- **tss-lib** - Reference implementation insights
- **Go Crypto Libraries** - Standard library and x/crypto

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Caqil/mpc-tss/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Caqil/mpc-tss/discussions)
- **Security**: security@[your-domain].com
- **Email**: support@[your-domain].com

## ⚠️ Disclaimer

This library is provided "as is" without warranty. It has **not yet undergone a professional security audit**.

**DO NOT use in production with real funds until:**
1. Professional security audit completed
2. Extensive real-world testing performed
3. Peer review by cryptography experts

For production use, always:
- Conduct your own security audit
- Use in combination with other security measures
- Follow security best practices
- Keep dependencies updated
- Monitor for security advisories

---

**Built with ❤️ and ☕ by the MPC-TSS team**

**Star ⭐ this repo if you find it useful!**
