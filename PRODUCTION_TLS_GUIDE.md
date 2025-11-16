# Production TLS Deployment Guide

## Complete Step-by-Step Guide for Production Use

This guide shows you **exactly** how to deploy MPC-TSS with production-grade TLS 1.3 security.

---

## Table of Contents

1. [Certificate Setup](#1-certificate-setup)
2. [Server Configuration](#2-server-configuration)
3. [Code Implementation](#3-code-implementation)
4. [Multi-Party Setup](#4-multi-party-setup)
5. [Testing & Validation](#5-testing--validation)
6. [Production Deployment](#6-production-deployment)
7. [Monitoring & Maintenance](#7-monitoring--maintenance)

---

## 1. Certificate Setup

### Option A: Let's Encrypt (Recommended - Free & Automated)

**Best for**: Public-facing servers with domain names

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot

# Generate certificate (automatic renewal)
sudo certbot certonly --standalone \
  -d party1.yourdomain.com \
  --email admin@yourdomain.com \
  --agree-tos

# Certificates will be at:
# /etc/letsencrypt/live/party1.yourdomain.com/fullchain.pem  (certificate)
# /etc/letsencrypt/live/party1.yourdomain.com/privkey.pem    (private key)
# /etc/letsencrypt/live/party1.yourdomain.com/chain.pem      (CA certificate)

# Set up auto-renewal (runs twice daily)
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Copy certificates to your app directory
sudo cp /etc/letsencrypt/live/party1.yourdomain.com/fullchain.pem /etc/tss/cert.pem
sudo cp /etc/letsencrypt/live/party1.yourdomain.com/privkey.pem /etc/tss/key.pem
sudo cp /etc/letsencrypt/live/party1.yourdomain.com/chain.pem /etc/tss/ca.pem

# Set secure permissions
sudo chmod 644 /etc/tss/cert.pem
sudo chmod 600 /etc/tss/key.pem
sudo chmod 644 /etc/tss/ca.pem
sudo chown tss:tss /etc/tss/*.pem
```

### Option B: Internal CA (For Private Networks)

**Best for**: Internal deployments, private networks, testing

```bash
# 1. Generate CA private key
openssl genrsa -out ca-key.pem 4096

# 2. Generate CA certificate
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
  -subj "/C=US/ST=State/L=City/O=YourCompany/CN=MPC-TSS CA"

# 3. For each party, generate private key
openssl genrsa -out party1-key.pem 4096

# 4. Generate certificate signing request (CSR)
openssl req -new -key party1-key.pem -out party1.csr \
  -subj "/C=US/ST=State/L=City/O=YourCompany/CN=party1"

# 5. Create certificate extensions file
cat > party1-ext.cnf << EOF
subjectAltName = DNS:party1.internal,DNS:localhost,IP:10.0.1.1
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
EOF

# 6. Sign the certificate with CA
openssl x509 -req -in party1.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out party1-cert.pem -days 365 \
  -extfile party1-ext.cnf

# 7. Verify certificate
openssl verify -CAfile ca-cert.pem party1-cert.pem

# Repeat steps 3-7 for each party (party2, party3, etc.)
```

### Option C: Commercial CA

**Best for**: Enterprise deployments, compliance requirements

```bash
# 1. Generate private key
openssl genrsa -out party1-key.pem 4096

# 2. Generate CSR
openssl req -new -key party1-key.pem -out party1.csr

# 3. Submit CSR to CA (DigiCert, GlobalSign, etc.)
# 4. Download signed certificate
# 5. Download CA chain certificate
```

---

## 2. Server Configuration

### Directory Structure

```
/etc/tss/
├── certs/
│   ├── party1-cert.pem    # This party's certificate
│   ├── party1-key.pem     # This party's private key (0600)
│   └── ca-cert.pem        # CA certificate (for verifying peers)
├── config/
│   └── tss.yaml           # Configuration file
└── logs/
    └── tss.log            # Application logs
```

### Create Configuration File

```yaml
# /etc/tss/config/tss.yaml
party:
  id: 0
  total_parties: 3

network:
  listen_address: "0.0.0.0:8000"

  peers:
    1: "party2.yourdomain.com:8001"
    2: "party3.yourdomain.com:8002"

  tls:
    cert_path: "/etc/tss/certs/party1-cert.pem"
    key_path: "/etc/tss/certs/party1-key.pem"
    ca_cert_path: "/etc/tss/certs/ca-cert.pem"
    enable_mutual_tls: true
    strict_validation: true

  timeouts:
    send: "30s"
    receive: "30s"
    reconnect_interval: "5s"

  security:
    max_message_size: 10485760  # 10 MB
    enable_rate_limiting: true
    rate_limit: 100  # messages per second
    enable_encryption: true
```

---

## 3. Code Implementation

### Basic Setup

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/Caqil/mpc-tss/pkg/network"
    "gopkg.in/yaml.v3"
)

// Config structure matching tss.yaml
type Config struct {
    Party struct {
        ID           int `yaml:"id"`
        TotalParties int `yaml:"total_parties"`
    } `yaml:"party"`
    Network struct {
        ListenAddress string            `yaml:"listen_address"`
        Peers         map[int]string    `yaml:"peers"`
        TLS           struct {
            CertPath         string `yaml:"cert_path"`
            KeyPath          string `yaml:"key_path"`
            CACertPath       string `yaml:"ca_cert_path"`
            EnableMutualTLS  bool   `yaml:"enable_mutual_tls"`
            StrictValidation bool   `yaml:"strict_validation"`
        } `yaml:"tls"`
    } `yaml:"network"`
}

func main() {
    // Load configuration
    config := loadConfig("/etc/tss/config/tss.yaml")

    // Create TLS configuration
    tlsConfig, err := network.NewProductionTLSConfig(network.TLSConfigParams{
        CertPath:         config.Network.TLS.CertPath,
        KeyPath:          config.Network.TLS.KeyPath,
        CACertPath:       config.Network.TLS.CACertPath,
        EnableMutualTLS:  config.Network.TLS.EnableMutualTLS,
        StrictValidation: config.Network.TLS.StrictValidation,
    })
    if err != nil {
        log.Fatalf("Failed to create TLS config: %v", err)
    }

    // Validate TLS configuration
    if err := network.ValidateTLSConfig(tlsConfig); err != nil {
        log.Fatalf("TLS validation failed: %v", err)
    }

    log.Println("✓ TLS 1.3 configuration validated")

    // Create transport
    transport, err := network.NewTLSTransport(&network.TransportConfig{
        PartyID:              config.Party.ID,
        TotalParties:         config.Party.TotalParties,
        ListenAddr:           config.Network.ListenAddress,
        PeerAddrs:            config.Network.Peers,
        TLSConfig:            tlsConfig,
        MaxMessageSize:       10 * 1024 * 1024,
        SendTimeout:          30 * time.Second,
        ReceiveTimeout:       30 * time.Second,
        BufferSize:           1000,
        EnableRateLimiting:   true,
        DefaultRateLimit:     100,
        EnableEncryption:     true,
        ReconnectInterval:    5 * time.Second,
        MaxReconnectAttempts: 10,
    })
    if err != nil {
        log.Fatalf("Failed to create transport: %v", err)
    }

    // Start transport
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    if err := transport.Start(ctx); err != nil {
        log.Fatalf("Failed to start transport: %v", err)
    }

    log.Printf("✓ Secure transport started on %s", config.Network.ListenAddress)
    log.Println("✓ Mutual TLS enabled - all connections authenticated")

    // Wait for shutdown signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
    <-sigChan

    log.Println("Shutting down gracefully...")
    transport.Stop()
}

func loadConfig(path string) *Config {
    data, err := os.ReadFile(path)
    if err != nil {
        log.Fatalf("Failed to read config: %v", err)
    }

    var config Config
    if err := yaml.Unmarshal(data, &config); err != nil {
        log.Fatalf("Failed to parse config: %v", err)
    }

    return &config
}
```

### Advanced: With Certificate Pinning

```go
// For high-security deployments, pin expected certificates

// Load expected certificate fingerprints
pinnedCerts := [][]byte{
    loadCertificateFingerprint("/etc/tss/pins/party2.pin"),
    loadCertificateFingerprint("/etc/tss/pins/party3.pin"),
}

tlsConfig, err := network.NewProductionTLSConfig(network.TLSConfigParams{
    CertPath:           config.Network.TLS.CertPath,
    KeyPath:            config.Network.TLS.KeyPath,
    CACertPath:         config.Network.TLS.CACertPath,
    EnableMutualTLS:    true,
    StrictValidation:   true,
    PinnedCertificates: pinnedCerts,  // Add certificate pinning
})

func loadCertificateFingerprint(path string) []byte {
    data, err := os.ReadFile(path)
    if err != nil {
        log.Fatalf("Failed to load certificate pin: %v", err)
    }
    return data
}
```

### Advanced: With Session Resumption

```go
// Generate or load session ticket key (32 bytes)
// Store this securely and rotate periodically
sessionKey := loadOrGenerateSessionKey("/etc/tss/session.key")

tlsConfig, err := network.NewProductionTLSConfig(network.TLSConfigParams{
    CertPath:         config.Network.TLS.CertPath,
    KeyPath:          config.Network.TLS.KeyPath,
    CACertPath:       config.Network.TLS.CACertPath,
    EnableMutualTLS:  true,
    StrictValidation: true,
    SessionTicketKey: sessionKey,  // Enable session resumption
})

func loadOrGenerateSessionKey(path string) []byte {
    // Try to load existing key
    if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
        return data
    }

    // Generate new key
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        log.Fatalf("Failed to generate session key: %v", err)
    }

    // Save for next restart
    if err := os.WriteFile(path, key, 0600); err != nil {
        log.Printf("Warning: failed to save session key: %v", err)
    }

    return key
}
```

---

## 4. Multi-Party Setup

### 3-Party Deployment Example

**Party 1 (party1.yourdomain.com)**:
```yaml
party:
  id: 0
  total_parties: 3

network:
  listen_address: "0.0.0.0:8000"
  peers:
    1: "party2.yourdomain.com:8001"
    2: "party3.yourdomain.com:8002"
  tls:
    cert_path: "/etc/tss/certs/party1-cert.pem"
    key_path: "/etc/tss/certs/party1-key.pem"
    ca_cert_path: "/etc/tss/certs/ca-cert.pem"
```

**Party 2 (party2.yourdomain.com)**:
```yaml
party:
  id: 1
  total_parties: 3

network:
  listen_address: "0.0.0.0:8001"
  peers:
    0: "party1.yourdomain.com:8000"
    2: "party3.yourdomain.com:8002"
  tls:
    cert_path: "/etc/tss/certs/party2-cert.pem"
    key_path: "/etc/tss/certs/party2-key.pem"
    ca_cert_path: "/etc/tss/certs/ca-cert.pem"
```

**Party 3 (party3.yourdomain.com)**:
```yaml
party:
  id: 2
  total_parties: 3

network:
  listen_address: "0.0.0.0:8002"
  peers:
    0: "party1.yourdomain.com:8000"
    1: "party2.yourdomain.com:8001"
  tls:
    cert_path: "/etc/tss/certs/party3-cert.pem"
    key_path: "/etc/tss/certs/party3-key.pem"
    ca_cert_path: "/etc/tss/certs/ca-cert.pem"
```

### Firewall Configuration

```bash
# Allow incoming TLS connections on your party's port
sudo ufw allow 8000/tcp comment "MPC-TSS Party 1"

# Allow outgoing connections to peer parties
# (Usually allowed by default, but be explicit in restrictive environments)
sudo ufw allow out to party2.yourdomain.com port 8001 proto tcp
sudo ufw allow out to party3.yourdomain.com port 8002 proto tcp

# Enable firewall
sudo ufw enable
```

---

## 5. Testing & Validation

### Test TLS Connection

```bash
# Test TLS handshake to peer
openssl s_client -connect party2.yourdomain.com:8001 \
  -cert /etc/tss/certs/party1-cert.pem \
  -key /etc/tss/certs/party1-key.pem \
  -CAfile /etc/tss/certs/ca-cert.pem \
  -tls1_3

# You should see:
# - "Verify return code: 0 (ok)"
# - "Protocol: TLSv1.3"
# - Certificate chain details
```

### Verify Certificate

```bash
# Check certificate validity
openssl x509 -in /etc/tss/certs/party1-cert.pem -text -noout

# Check certificate expiration
openssl x509 -in /etc/tss/certs/party1-cert.pem -enddate -noout

# Verify certificate chain
openssl verify -CAfile /etc/tss/certs/ca-cert.pem \
  /etc/tss/certs/party1-cert.pem
```

### Test Code Validation

```go
// Add to your main.go for testing
func validateSetup() error {
    // Check files exist
    files := []string{
        "/etc/tss/certs/party1-cert.pem",
        "/etc/tss/certs/party1-key.pem",
        "/etc/tss/certs/ca-cert.pem",
    }

    for _, file := range files {
        if _, err := os.Stat(file); err != nil {
            return fmt.Errorf("missing file %s: %w", file, err)
        }
    }

    // Load and validate TLS config
    tlsConfig, err := network.NewProductionTLSConfig(network.TLSConfigParams{
        CertPath:         "/etc/tss/certs/party1-cert.pem",
        KeyPath:          "/etc/tss/certs/party1-key.pem",
        CACertPath:       "/etc/tss/certs/ca-cert.pem",
        EnableMutualTLS:  true,
        StrictValidation: true,
    })
    if err != nil {
        return fmt.Errorf("TLS config failed: %w", err)
    }

    if err := network.ValidateTLSConfig(tlsConfig); err != nil {
        return fmt.Errorf("TLS validation failed: %w", err)
    }

    log.Println("✓ All validation checks passed")
    return nil
}
```

---

## 6. Production Deployment

### Systemd Service

Create `/etc/systemd/system/mpc-tss.service`:

```ini
[Unit]
Description=MPC-TSS Threshold Signature Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tss
Group=tss
WorkingDirectory=/opt/mpc-tss
ExecStart=/opt/mpc-tss/bin/tss-server --config /etc/tss/config/tss.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/tss/logs

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

### Deploy and Start

```bash
# Create user
sudo useradd -r -s /bin/false tss

# Set up directories
sudo mkdir -p /opt/mpc-tss/bin
sudo mkdir -p /etc/tss/{certs,config,logs}

# Copy binary and config
sudo cp tss-server /opt/mpc-tss/bin/
sudo cp tss.yaml /etc/tss/config/

# Copy certificates
sudo cp party1-cert.pem /etc/tss/certs/
sudo cp party1-key.pem /etc/tss/certs/
sudo cp ca-cert.pem /etc/tss/certs/

# Set permissions
sudo chown -R tss:tss /opt/mpc-tss
sudo chown -R tss:tss /etc/tss
sudo chmod 600 /etc/tss/certs/*-key.pem
sudo chmod 644 /etc/tss/certs/*-cert.pem

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable mpc-tss
sudo systemctl start mpc-tss

# Check status
sudo systemctl status mpc-tss

# View logs
sudo journalctl -u mpc-tss -f
```

---

## 7. Monitoring & Maintenance

### Certificate Expiration Monitoring

```bash
# Check certificate expiration (run daily via cron)
cat > /usr/local/bin/check-tss-cert << 'EOF'
#!/bin/bash
CERT="/etc/tss/certs/party1-cert.pem"
DAYS_WARNING=30

# Get expiration date
EXPIRY=$(openssl x509 -in "$CERT" -enddate -noout | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))

if [ $DAYS_LEFT -lt $DAYS_WARNING ]; then
    echo "WARNING: Certificate expires in $DAYS_LEFT days!"
    # Send alert (email, Slack, PagerDuty, etc.)
    exit 1
fi

echo "Certificate OK: $DAYS_LEFT days remaining"
exit 0
EOF

chmod +x /usr/local/bin/check-tss-cert

# Add to crontab
echo "0 8 * * * /usr/local/bin/check-tss-cert" | sudo crontab -
```

### TLS Connection Monitoring

```go
// Add to your application
func monitorTLS(transport *network.TLSTransport) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        // Check peer connections
        metrics := transport.GetMetrics()

        log.Printf("TLS Metrics:")
        log.Printf("  Active connections: %d", metrics.ActiveConnections)
        log.Printf("  Failed connections: %d", metrics.FailedConnections)
        log.Printf("  Messages sent: %d", metrics.MessagesSent)
        log.Printf("  Messages received: %d", metrics.MessagesReceived)

        // Alert if too many failures
        if metrics.FailedConnections > 100 {
            // Send alert
            log.Printf("WARNING: High connection failure rate!")
        }
    }
}
```

### Log Monitoring

```bash
# Monitor for TLS errors
sudo journalctl -u mpc-tss -f | grep -i "tls\|certificate\|handshake"

# Check for certificate validation failures
sudo journalctl -u mpc-tss --since "1 hour ago" | \
  grep -i "certificate" | \
  grep -i "fail\|error\|invalid"
```

### Certificate Rotation

```bash
# Automated certificate rotation script
cat > /usr/local/bin/rotate-tss-cert << 'EOF'
#!/bin/bash
set -e

# Backup old certificate
cp /etc/tss/certs/party1-cert.pem /etc/tss/certs/party1-cert.pem.bak
cp /etc/tss/certs/party1-key.pem /etc/tss/certs/party1-key.pem.bak

# Get new certificate (Let's Encrypt example)
certbot renew --deploy-hook "systemctl reload mpc-tss"

# Copy new certificate
cp /etc/letsencrypt/live/party1.yourdomain.com/fullchain.pem \
   /etc/tss/certs/party1-cert.pem
cp /etc/letsencrypt/live/party1.yourdomain.com/privkey.pem \
   /etc/tss/certs/party1-key.pem

# Set permissions
chmod 600 /etc/tss/certs/party1-key.pem
chown tss:tss /etc/tss/certs/party1-*

echo "Certificate rotated successfully"
EOF

chmod +x /usr/local/bin/rotate-tss-cert
```

---

## Quick Reference

### Common Commands

```bash
# Check service status
systemctl status mpc-tss

# View logs
journalctl -u mpc-tss -f

# Restart service
systemctl restart mpc-tss

# Test TLS connection
openssl s_client -connect party2.yourdomain.com:8001 -tls1_3

# Check certificate
openssl x509 -in /etc/tss/certs/party1-cert.pem -text -noout

# Verify certificate chain
openssl verify -CAfile /etc/tss/certs/ca-cert.pem \
  /etc/tss/certs/party1-cert.pem
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "certificate signed by unknown authority" | Add CA cert to trusted store or config |
| "tls: bad certificate" | Check certificate expiration and validity |
| "connection refused" | Check firewall, port, and service status |
| "handshake failure" | Verify TLS versions match, check certificates |

---

## Security Checklist

Before going to production:

- [ ] Using CA-signed certificates (not self-signed)
- [ ] Private keys stored with 0600 permissions
- [ ] TLS 1.3 enforced (no TLS 1.2)
- [ ] Mutual TLS enabled
- [ ] Certificate validation enabled
- [ ] Certificates monitored for expiration
- [ ] Automatic renewal configured
- [ ] Firewall rules configured
- [ ] Service running as non-root user
- [ ] Logs monitored for errors
- [ ] Backup certificates stored securely

---

**Questions?** Refer to `pkg/network/TLS_SETUP.md` for detailed documentation.

**Security Issues?** Email security@[your-domain].com (do NOT file public issue)
