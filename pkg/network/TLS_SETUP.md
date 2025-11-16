# Production TLS 1.3 Setup Guide

## Overview

The MPC-TSS network layer now includes **production-grade TLS 1.3** with:

✅ **TLS 1.3 Only** - No downgrade attacks
✅ **Perfect Forward Secrecy (PFS)** - All cipher suites use (EC)DHE
✅ **Certificate Validation** - Full CA verification
✅ **Mutual TLS (mTLS)** - Both parties authenticate
✅ **Certificate Pinning** - Defense against compromised CAs
✅ **Strict Mode** - Additional security checks

---

## Quick Start

### 1. Generate Certificates

#### For Production (Use CA-signed certificates)

```bash
# Use Let's Encrypt (automated, free)
certbot certonly --standalone -d your-domain.com

# Or use your organization's CA
# Consult your security team
```

#### For Development/Testing Only

```bash
# Generate self-signed certificate (DO NOT use in production)
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -nodes \
  -subj "/CN=localhost"

# Generate CA certificate
openssl req -x509 -newkey rsa:4096 \
  -keyout ca-key.pem \
  -out ca-cert.pem \
  -days 365 \
  -nodes \
  -subj "/CN=Test CA"
```

### 2. Use in Your Code

```go
package main

import (
    "github.com/Caqil/mpc-tss/pkg/network"
)

func main() {
    // Create production TLS config
    tlsConfig, err := network.NewProductionTLSConfig(network.TLSConfigParams{
        CertPath:         "/path/to/cert.pem",
        KeyPath:          "/path/to/key.pem",
        CACertPath:       "/path/to/ca-cert.pem",
        EnableMutualTLS:  true,  // Both parties authenticate
        StrictValidation: true,  // Extra security checks
    })
    if err != nil {
        panic(err)
    }

    // Validate configuration
    if err := network.ValidateTLSConfig(tlsConfig); err != nil {
        panic(err)
    }

    // Use in transport
    transport, err := network.NewTLSTransport(&network.TransportConfig{
        PartyID:      0,
        TotalParties: 3,
        ListenAddr:   "0.0.0.0:8000",
        PeerAddrs: map[int]string{
            1: "peer1.example.com:8001",
            2: "peer2.example.com:8002",
        },
        TLSConfig: tlsConfig,
    })
    if err != nil {
        panic(err)
    }

    // Start transport
    transport.Start(context.Background())
}
```

---

## Security Features Explained

### TLS 1.3 Only

**Why it matters**:
- Prevents downgrade attacks (POODLE, BEAST, etc.)
- Removes weak ciphers
- Faster handshake (1-RTT)
- 0-RTT resumption option

**Implementation**:
```go
config.MinVersion = tls.VersionTLS13
config.MaxVersion = tls.VersionTLS13
```

### Perfect Forward Secrecy (PFS)

**Why it matters**:
- If server key is compromised later, past sessions remain secure
- Uses ephemeral (EC)DHE key exchange
- Industry best practice (required by PCI DSS 4.0)

**Cipher suites with PFS** (all enabled):
```go
tls.TLS_CHACHA20_POLY1305_SHA256  // Modern AEAD
tls.TLS_AES_256_GCM_SHA384        // AES-256
tls.TLS_AES_128_GCM_SHA256        // AES-128
```

**Note**: ALL TLS 1.3 cipher suites provide PFS by design.

### Mutual TLS (mTLS)

**Why it matters**:
- Both client and server authenticate
- Prevents man-in-the-middle attacks
- Required for zero-trust security

**Implementation**:
```go
config.ClientAuth = tls.RequireAndVerifyClientCert
config.ClientCAs = caCertPool
```

**Setup**:
1. Each party needs a certificate
2. All parties trust the same CA
3. Both sides verify peer certificates

### Certificate Pinning

**Why it matters**:
- Defense-in-depth against compromised CAs
- Ensures you're connecting to the right server
- Used by major apps (Chrome, Firefox)

**Implementation**:
```go
tlsConfig, err := network.NewProductionTLSConfig(network.TLSConfigParams{
    CertPath:           "/path/to/cert.pem",
    KeyPath:            "/path/to/key.pem",
    CACertPath:         "/path/to/ca-cert.pem",
    PinnedCertificates: [][]byte{expectedCertFingerprint},
})
```

### Strict Validation Mode

**Why it matters**:
- Additional checks beyond standard TLS
- Catches misconfigured connections early
- Prevents weak configurations

**What it checks**:
- ✅ TLS version is 1.3
- ✅ Cipher suite provides PFS
- ✅ Certificate validity period
- ✅ Certificate expiration warnings (< 30 days)
- ✅ Handshake completed successfully

---

## Configuration Options

### Full Parameter List

```go
type TLSConfigParams struct {
    // Required
    CertPath   string  // Path to certificate PEM file
    KeyPath    string  // Path to private key PEM file
    CACertPath string  // Path to CA certificate

    // Optional
    ServerName           string    // For SNI (Server Name Indication)
    EnableMutualTLS      bool      // Both parties authenticate (default: false)
    StrictValidation     bool      // Extra security checks (default: false)
    MinVersion           uint16    // Minimum TLS version (default: TLS 1.3)
    SessionTicketKey     []byte    // 32 bytes for session resumption
    PinnedCertificates   [][]byte  // Expected cert fingerprints
}
```

### Common Configurations

#### High Security (Financial, Government)

```go
tlsConfig, err := network.NewProductionTLSConfig(network.TLSConfigParams{
    CertPath:           "/etc/tss/cert.pem",
    KeyPath:            "/etc/tss/key.pem",
    CACertPath:         "/etc/tss/ca-cert.pem",
    EnableMutualTLS:    true,   // Both authenticate
    StrictValidation:   true,   // Extra checks
    PinnedCertificates: pins,   // Certificate pinning
})
```

#### Standard Security (Enterprise)

```go
tlsConfig, err := network.DefaultProductionTLSConfig(
    "/etc/tss/cert.pem",
    "/etc/tss/key.pem",
    "/etc/tss/ca-cert.pem",
)
```

#### Development Only (NOT for production)

```go
tlsConfig := network.InsecureDevTLSConfig()
// WARNING: This skips certificate validation!
// ONLY use for local development
```

---

## Certificate Management

### Best Practices

1. **Use CA-signed certificates**
   - Let's Encrypt (free, automated)
   - Internal CA (for private networks)
   - Commercial CA (DigiCert, GlobalSign)

2. **Certificate rotation**
   - Rotate every 90 days (Let's Encrypt default)
   - Automate with certbot
   - Monitor expiration dates

3. **Key management**
   - Store keys in secure location (0600 permissions)
   - Use HSM for high-value keys
   - Never commit keys to git

4. **Certificate revocation**
   - Implement OCSP stapling
   - Check CRL (Certificate Revocation List)
   - Have revocation procedure

### File Permissions

```bash
# Certificate (public) - readable by all
chmod 644 /etc/tss/cert.pem

# Private key - readable by owner only
chmod 600 /etc/tss/key.pem
chown tss:tss /etc/tss/key.pem

# CA certificate (public)
chmod 644 /etc/tss/ca-cert.pem
```

---

## Troubleshooting

### Common Errors

#### "x509: certificate signed by unknown authority"

**Cause**: CA certificate not trusted

**Solution**:
```bash
# Add CA cert to system trust store (Linux)
sudo cp ca-cert.pem /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Or specify in code
config.RootCAs = caCertPool
```

#### "tls: bad certificate"

**Cause**: Client certificate not provided or invalid

**Solution**:
- Ensure client has valid certificate
- Check certificate expiration
- Verify CA signed the certificate

#### "tls: first record does not look like a TLS handshake"

**Cause**: Trying to connect to non-TLS port

**Solution**:
- Ensure server is using TLS
- Check both sides use same TLS configuration

### Debug Mode

Enable TLS debugging:

```bash
export GODEBUG=tls13=1
export SSLKEYLOGFILE=/tmp/tls-keys.log
```

Then use Wireshark to decrypt TLS traffic (development only).

---

## Performance Optimization

### Session Resumption

Save TLS handshake time with session tickets:

```go
// Generate session ticket key (32 random bytes)
sessionKey := make([]byte, 32)
if _, err := rand.Read(sessionKey); err != nil {
    panic(err)
}

tlsConfig, err := network.NewProductionTLSConfig(network.TLSConfigParams{
    // ... other params ...
    SessionTicketKey: sessionKey,  // Enable session resumption
})
```

**Benefits**:
- Reduces latency (no full handshake)
- Decreases CPU usage
- Maintains security (forward secrecy preserved)

### Hardware Acceleration

Modern CPUs have AES-NI instructions:

```bash
# Check if AES-NI is available
grep aes /proc/cpuinfo
```

If available, AES-GCM cipher suites will be hardware-accelerated automatically.

### Cipher Suite Selection

```go
// For ARM/mobile devices - prefer ChaCha20
config.CipherSuites = []uint16{
    tls.TLS_CHACHA20_POLY1305_SHA256,  // Fast on ARM
    tls.TLS_AES_256_GCM_SHA384,        // Fallback
}

// For x86 with AES-NI - prefer AES-GCM
config.CipherSuites = []uint16{
    tls.TLS_AES_256_GCM_SHA384,        // Hardware accelerated
    tls.TLS_CHACHA20_POLY1305_SHA256,  // Fallback
}
```

---

## Compliance

This TLS configuration meets:

✅ **PCI DSS 4.0** - TLS 1.3, PFS required
✅ **NIST SP 800-52 Rev. 2** - Federal TLS guidance
✅ **HIPAA** - Encryption in transit requirements
✅ **SOC 2** - Security controls for data transmission
✅ **GDPR** - Data protection in transit

---

## Security Audit Checklist

Before production deployment:

- [ ] Using TLS 1.3 only (`MinVersion = tls.VersionTLS13`)
- [ ] All cipher suites provide PFS
- [ ] Certificate validation enabled (`InsecureSkipVerify = false`)
- [ ] Mutual TLS enabled (`ClientAuth = RequireAndVerifyClientCert`)
- [ ] Certificates signed by trusted CA
- [ ] Private keys stored securely (0600 permissions)
- [ ] Certificate rotation automated
- [ ] Monitoring for certificate expiration
- [ ] Session ticket keys rotated regularly
- [ ] Certificate pinning configured (for high-security)
- [ ] Validated with `ValidateTLSConfig()`

---

## Additional Resources

- [Go crypto/tls documentation](https://pkg.go.dev/crypto/tls)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [NIST TLS Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
- [Let's Encrypt](https://letsencrypt.org/)

---

**Questions?** File an issue on GitHub or consult your security team.

**Security Issue?** Email security@[your-domain].com (DO NOT file public issue)
