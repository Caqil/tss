# MPC-TSS Architecture

## Overview

This is a production-grade Multi-Party Computation Threshold Signature Scheme (MPC-TSS) implementation in Go. The library enables distributed key generation and threshold signing without requiring any single party to hold the complete private key.

## Cryptographic Scheme Selection

After analyzing existing implementations (tss-lib, multi-party-ecdsa, GG20), we've chosen:

**Primary Scheme: ECDSA with GG20 Protocol**
- **Reason**: Widely compatible with Bitcoin/Ethereum ecosystems
- **Security**: Proven secure in malicious adversary model
- **Performance**: Optimized 5-round signing protocol
- **Curve Support**: secp256k1, P-256, ed25519

**Alternative: EdDSA FROST** (future extension)
- Simpler protocol with 2-round signing
- Better performance characteristics
- Native ed25519 support

## Architecture Principles

1. **Security First**: All design decisions prioritize security over convenience
2. **Constant-Time Operations**: All secret data operations are constant-time
3. **Zero-Trust**: Every party assumes others may be malicious
4. **Fail-Safe**: System aborts on any anomaly detection
5. **Auditability**: Comprehensive logging without leaking secrets

## System Components

### Core Cryptographic Layer (`pkg/crypto/`)

**Responsibilities:**
- Elliptic curve operations (point arithmetic, scalar multiplication)
- Secure random number generation
- Hash functions and commitments
- Constant-time utilities

**Key Types:**
```go
type Point struct {
    X, Y *big.Int
    Curve Curve
}

type Scalar struct {
    Value *big.Int
    Curve Curve
}
```

### Key Generation Layer (`pkg/keygen/`)

**Protocol: Feldman VSS (Verifiable Secret Sharing)**

**Flow:**
1. **Round 1**: Each party generates polynomial and commitments
2. **Round 2**: Parties exchange and verify shares
3. **Round 3**: Complaint resolution (if needed)
4. **Round 4**: Compute final key shares

**Security Features:**
- Zero-knowledge proofs of correct share generation
- Verifiable commitments prevent cheating
- Complaint mechanism for malicious parties
- Abort on verification failure

### Signing Layer (`pkg/signing/`)

**Protocol: GG20 Threshold ECDSA**

**Phases:**
- **Presigning Phase** (offline): Generate signing nonces
- **Signing Phase** (online): Fast signature generation

**Flow:**
1. **Round 1**: Commit to nonces
2. **Round 2**: Reveal nonces and compute R
3. **Round 3**: Partial signature generation
4. **Round 4**: Signature aggregation
5. **Round 5**: Final signature assembly

### Zero-Knowledge Proofs (`pkg/zk/`)

**Implemented Proofs:**
- Schnorr Proof (knowledge of discrete log)
- Range Proofs (value in valid range)
- Equality Proofs (same value in different commitments)
- Paillier Proofs (correct encryption)

**Purpose:**
- Prevent malicious parties from corrupting protocol
- Enable verification without revealing secrets
- Provide abort-with-proof mechanism

### Network Layer (`pkg/network/`)

**Communication Patterns:**
- Point-to-point (P2P)
- Broadcast
- Request-response

**Security:**
- TLS 1.3 for transport security
- Authenticated encryption (AES-256-GCM)
- Message authentication (HMAC-SHA256)
- Replay attack prevention (nonce + timestamp)
- Perfect forward secrecy

**Interface:**
```go
type Network interface {
    Send(partyID int, msg *Message) error
    Broadcast(msg *Message) error
    Receive() (*Message, error)
    Close() error
}
```

### Storage Layer (`pkg/storage/`)

**Key Share Storage:**
- Encrypted at rest (AES-256-GCM)
- Password-based key derivation (Argon2id)
- Secure file permissions (0600)
- Atomic write operations

**Metadata Storage:**
- Public parameters
- Protocol state
- Audit logs

### Security Utilities (`internal/security/`)

**Memory Protection:**
- Secure zeroing of sensitive data
- Memory locking (prevents swap)
- Bounds checking

**Anti-Side-Channel:**
- Constant-time comparison
- Constant-time conditional selection
- Timing-resistant arithmetic

**Input Validation:**
- Parameter range checking
- Party ID validation
- Threshold validation

## Data Flow

### Distributed Key Generation (DKG)

```
Party 1          Party 2          Party 3
   |                |                |
   |--[Round1]----->|                |
   |                |--[Round1]----->|
   |<--[Round1]-----|                |
   |                |<--[Round1]-----|
   |                |                |
   |--[Round2]----->|                |
   |                |--[Round2]----->|
   |<--[Round2]-----|                |
   |                |<--[Round2]-----|
   |                |                |
   |--[Verify]----->|                |
   |                |--[Verify]----->|
   |                |                |
   v                v                v
[KeyShare1]    [KeyShare2]      [KeyShare3]
```

### Threshold Signing

```
Parties (threshold subset)
   |
   |--[Message Hash]
   |
   |--[Presigning Phase]
   |   └── Generate nonces (offline)
   |
   |--[Signing Phase]
   |   ├── Round 1: Nonce commitments
   |   ├── Round 2: Nonce reveal
   |   ├── Round 3: Partial signatures
   |   └── Round 4: Aggregate
   |
   v
[Complete Signature (r, s)]
```

## Security Model

### Threat Model

**Adversary Capabilities:**
- Control up to (t-1) parties in a t-of-n scheme
- Passive eavesdropping on network
- Active message injection/modification
- Timing analysis
- Memory inspection (side-channel)

**Adversary Cannot:**
- Break cryptographic primitives (ECDSA, AES, SHA-256)
- Control ≥ t parties simultaneously
- Access secure enclave (if used)
- Physically access hardware (out of scope)

### Security Guarantees

1. **Correctness**: Honest parties always produce valid signatures
2. **Unforgeability**: Adversary cannot forge signatures without t parties
3. **Robustness**: Protocol completes if ≥ t parties are honest
4. **Privacy**: No information about key shares leaked
5. **Identifiable Abort**: Malicious parties are detected

### Attack Prevention

| Attack Type | Prevention Mechanism |
|-------------|---------------------|
| Replay Attack | Nonce + timestamp validation |
| Man-in-the-Middle | TLS 1.3 + mutual authentication |
| Timing Attack | Constant-time operations |
| Memory Leak | Secure zeroing + memory locking |
| Invalid Share | Zero-knowledge proofs |
| Protocol Deviation | Verification at each round |
| DoS | Rate limiting + timeout |

## Performance Considerations

### Optimization Strategies

1. **Precomputation**: Generate nonces offline (presigning)
2. **Batch Operations**: Process multiple signatures together
3. **Parallel Verification**: Verify shares concurrently
4. **Efficient Serialization**: Use compact binary encoding
5. **Connection Pooling**: Reuse network connections

### Expected Performance

| Operation | Parties | Threshold | Time | Memory |
|-----------|---------|-----------|------|--------|
| DKG | 3 | 2 | ~2s | ~30MB |
| DKG | 5 | 3 | ~4s | ~50MB |
| DKG | 7 | 5 | ~6s | ~80MB |
| Signing | 3 | 2 | ~1s | ~20MB |
| Signing | 5 | 3 | ~1.5s | ~30MB |
| Presigning | 5 | 3 | ~800ms | ~25MB |

## Error Handling

### Error Categories

1. **Crypto Errors**: Invalid curve points, failed proofs
2. **Network Errors**: Timeout, disconnection, invalid message
3. **Protocol Errors**: Wrong round, missing data, verification failure
4. **System Errors**: Out of memory, file I/O failure

### Error Handling Strategy

```go
type ErrorType int

const (
    ErrCrypto ErrorType = iota
    ErrNetwork
    ErrProtocol
    ErrSystem
)

type Error struct {
    Type    ErrorType
    Message string
    Cause   error
    Abort   bool  // Should protocol abort?
}
```

**Abort Conditions:**
- Any verification failure
- Invalid zero-knowledge proof
- Timeout exceeded
- Malicious party detected

## Testing Strategy

### Test Levels

1. **Unit Tests**: Individual function correctness
2. **Integration Tests**: Full protocol flows
3. **Security Tests**: Attack resistance
4. **Fuzzing**: Random input handling
5. **Benchmarks**: Performance validation

### Test Coverage Goals

- Code coverage: >90%
- Branch coverage: >85%
- Critical paths: 100%

## Extensibility

### Future Extensions

1. **Additional Curves**: BLS12-381, Ristretto255
2. **FROST Protocol**: EdDSA threshold signatures
3. **Proactive Refresh**: Periodic key share updates
4. **Key Resharing**: Change threshold without DKG
5. **Batch Verification**: Verify multiple signatures at once

### Plugin Architecture

```go
type CurveProvider interface {
    Name() string
    ScalarSize() int
    PointSize() int
    // ... curve operations
}

// Register custom curves
RegisterCurve("custom-curve", customProvider)
```

## Dependencies

### Core Dependencies
- `crypto/rand` - Secure random generation
- `crypto/sha256` - Hashing
- `crypto/cipher` - AEAD encryption
- `math/big` - Arbitrary precision arithmetic

### External Dependencies
- `github.com/btcsuite/btcd/btcec/v2` - secp256k1 curve
- `golang.org/x/crypto` - Argon2, ChaCha20
- `filippo.io/edwards25519` - Ed25519 curve
- `github.com/rs/zerolog` - Structured logging

### Development Dependencies
- `github.com/stretchr/testify` - Testing utilities
- `github.com/golangci/golangci-lint` - Linting
- `github.com/securego/gosec` - Security scanning

## Compliance & Standards

### Cryptographic Standards
- FIPS 186-4: Digital Signature Standard
- RFC 6979: Deterministic ECDSA
- RFC 5869: HKDF key derivation
- RFC 8032: EdDSA signatures

### Security Best Practices
- OWASP Cryptographic Guidelines
- NIST SP 800-57: Key Management
- CWE Top 25: Vulnerability prevention

## Deployment Considerations

### Production Checklist
- [ ] Security audit completed
- [ ] Dependency scanning enabled
- [ ] Secrets management configured
- [ ] Monitoring and alerting setup
- [ ] Backup and recovery tested
- [ ] Incident response plan ready

### Monitoring Metrics
- Protocol success/failure rate
- Round completion time
- Network latency
- Memory usage
- Error rates by type

## License & Contributing

**License**: Apache 2.0 (permissive, patent-protected)

**Contribution Guidelines**: See CONTRIBUTING.md

**Security Disclosures**: See SECURITY.md
