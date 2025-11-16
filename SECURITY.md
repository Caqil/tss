# Security Policy

## Threat Model

### Adversary Model

This implementation assumes a **malicious adversary model** where:

- Up to `t-1` parties (in a `t-of-n` threshold scheme) may be malicious
- Adversaries can deviate arbitrarily from the protocol
- Network communication may be eavesdropped or manipulated
- Adversaries may attempt timing and side-channel attacks
- Adversaries may attempt to extract secrets through various means

### Out of Scope

The following are considered out of scope for this threat model:

- Physical attacks on hardware
- Compromise of the underlying operating system
- Backdoors in cryptographic primitives (we assume standard primitives are secure)
- Social engineering attacks
- Supply chain attacks on dependencies (though we use vendoring and checksums)

## Security Guarantees

### Cryptographic Security

1. **Unforgeability**: No adversary controlling fewer than `t` parties can forge a signature
2. **Key Privacy**: Private key shares reveal no information about the complete key
3. **Signature Privacy**: Threshold signatures are indistinguishable from regular signatures
4. **Forward Secrecy**: Compromise of long-term keys doesn't reveal past signatures

### Protocol Security

1. **Correctness**: Honest parties always produce valid signatures when ≥ t parties participate
2. **Robustness**: Protocol succeeds if at least `t` honest parties participate
3. **Identifiable Abort**: Malicious parties are detected and identified
4. **Verifiability**: All shares and intermediate values are verifiable via zero-knowledge proofs

## Security Features

### Constant-Time Operations

All operations involving secret data use constant-time implementations:

```go
// ✅ SECURE: Constant-time comparison
func SecureCompare(a, b []byte) bool {
    return subtle.ConstantTimeCompare(a, b) == 1
}

// ❌ INSECURE: Variable-time comparison (DO NOT USE)
func InsecureCompare(a, b []byte) bool {
    return bytes.Equal(a, b)  // Timing leak!
}
```

### Memory Protection

1. **Zeroing**: All sensitive data is securely zeroed after use
2. **Memory Locking**: Key material is locked in memory (no swap)
3. **No Copies**: Sensitive data is not unnecessarily copied

```go
// Automatic secure zeroing
defer security.SecureZero(secretData)
```

### Input Validation

All inputs are validated before use:

```go
// Validate threshold parameters
if threshold < 1 || threshold > parties {
    return ErrInvalidThreshold
}

// Validate party IDs
if partyID < 0 || partyID >= parties {
    return ErrInvalidPartyID
}

// Validate curve points
if !curve.IsOnCurve(point) {
    return ErrInvalidPoint
}
```

### Replay Attack Prevention

Every message includes:
- Unique nonce
- Timestamp
- Session ID
- Message sequence number

```go
type Message struct {
    Nonce      [32]byte
    Timestamp  int64
    SessionID  [32]byte
    SeqNum     uint64
    Payload    []byte
    MAC        [32]byte
}
```

### Zero-Knowledge Proofs

All parties prove correctness of their computations without revealing secrets:

- **Schnorr Proofs**: Prove knowledge of discrete logarithm
- **Range Proofs**: Prove values are in valid range
- **Equality Proofs**: Prove encrypted values match commitments

### Secure Communication

All network communication uses:
- **TLS 1.3** for transport encryption
- **Mutual authentication** via certificates
- **Perfect forward secrecy** (ephemeral keys)
- **AEAD encryption** (AES-256-GCM) for application layer

## Attack Prevention

### Timing Attacks

**Prevention:**
- All secret-dependent operations are constant-time
- No secret-dependent branches
- No secret-dependent memory access patterns

**Testing:**
```bash
# Run timing attack tests
go test -v ./tests/security -run TestTimingAttack
```

### Side-Channel Attacks

**Prevention:**
- Constant-time arithmetic operations
- No secret-dependent cache access
- Memory access pattern obfuscation

### Man-in-the-Middle Attacks

**Prevention:**
- Mutual TLS authentication
- Certificate pinning (optional)
- Message authentication codes (HMAC)

### Denial of Service

**Prevention:**
- Rate limiting on message processing
- Timeout mechanisms
- Resource limits (memory, CPU)
- Connection limits per party

### Invalid Share Attacks

**Prevention:**
- Zero-knowledge proofs of correct share generation
- Verifiable secret sharing (Feldman VSS)
- Share verification before use

### Malleability Attacks

**Prevention:**
- Authenticated encryption (AEAD)
- Message binding to session context
- Signature verification after aggregation

## Security Best Practices

### For Developers

1. **Never Log Secrets**: Use structured logging that automatically redacts sensitive fields
2. **Always Validate**: Verify all inputs, even from "trusted" parties
3. **Fail Securely**: Default to aborting on any anomaly
4. **Use Safe APIs**: Prefer high-level APIs over low-level crypto primitives
5. **Review Changes**: Security-critical code requires multiple reviewers

### For Users

1. **Secure Storage**: Store key shares in encrypted storage with strong passwords
2. **Secure Communication**: Use authenticated, encrypted channels
3. **Monitor Activity**: Enable audit logging and monitor for anomalies
4. **Regular Updates**: Keep the library updated for security patches
5. **Limit Exposure**: Run on isolated, dedicated infrastructure when possible

## Auditing

### Audit Logging

All security-relevant events are logged:
- Key generation initiation
- Signing requests
- Verification failures
- Protocol aborts
- Anomalies detected

**No secrets are ever logged**.

Example log entry:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event": "dkg_started",
  "party_id": 1,
  "threshold": 2,
  "parties": 3,
  "session_id": "abc123..."
}
```

### Security Audits

**Recommended Audit Schedule:**
- Code audit before initial release
- Annual security audits
- Audit after major changes
- Third-party penetration testing

**Previous Audits:** (None - initial release)

## Vulnerability Disclosure

### Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead, email: **security@[your-domain].com** (replace with actual contact)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **24 hours**: Initial response acknowledging receipt
- **7 days**: Preliminary assessment and severity classification
- **30 days**: Fix developed and tested
- **60 days**: Public disclosure (coordinated with reporter)

### Severity Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Key compromise possible | 24-48 hours |
| High | Protocol break, no key leak | 7 days |
| Medium | DoS or information leak | 14 days |
| Low | Minor issue, limited impact | 30 days |

## Known Limitations

1. **No Post-Quantum Security**: Uses classical elliptic curve cryptography
2. **Network Assumption**: Requires synchronous network for signing
3. **Honest Majority**: Requires ≥ t honest parties
4. **No Hardware Security**: Software-only implementation (no HSM integration yet)

## Compliance

### Standards Followed

- **FIPS 186-4**: Digital Signature Standard
- **NIST SP 800-57**: Key Management Recommendations
- **OWASP**: Cryptographic Storage Cheat Sheet
- **CWE Top 25**: Most Dangerous Software Weaknesses

### Cryptographic Primitives

All primitives use well-established, peer-reviewed algorithms:

| Primitive | Algorithm | Key Size |
|-----------|-----------|----------|
| Signature | ECDSA | 256-bit |
| Encryption | AES-GCM | 256-bit |
| Hashing | SHA-256 | 256-bit |
| KDF | Argon2id | - |
| MAC | HMAC-SHA256 | 256-bit |

## Security Checklist

Before deploying to production:

- [ ] All tests pass (including security tests)
- [ ] Static analysis clean (gosec, golangci-lint)
- [ ] Dependencies scanned for vulnerabilities
- [ ] Security audit completed
- [ ] Secure key storage configured
- [ ] Audit logging enabled
- [ ] Network security configured (TLS, firewalls)
- [ ] Incident response plan in place
- [ ] Backup and recovery tested
- [ ] Monitoring and alerting configured

## Security Updates

### Update Policy

- **Critical vulnerabilities**: Patch released within 48 hours
- **High severity**: Patch released within 7 days
- **Medium/Low severity**: Included in next regular release

### Notification Channels

- GitHub Security Advisories
- Email notification list (opt-in)
- Security mailing list

## Additional Resources

### Recommended Reading

1. "Practical Threshold Signatures" - Rosario Gennaro, Steven Goldfeder (GG20 paper)
2. "Fast Multiparty Threshold ECDSA with Fast Trustless Setup" - Gennaro & Goldfeder
3. "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems" - Gennaro et al.

### Security Tools

- **gosec**: Go security checker
- **nancy**: Dependency vulnerability scanner
- **golangci-lint**: Comprehensive linter with security checks

### Contact

For security concerns: **security@[your-domain].com**

For general questions: Open a GitHub issue

---

**Last Updated**: 2024-01-15
**Next Review**: 2024-04-15
