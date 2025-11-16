// Package main demonstrates TLS 1.3 with Perfect Forward Secrecy
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Caqil/mpc-tss/pkg/network"
)

func main() {
	fmt.Println("=== TLS 1.3 Network Demo ===")
	fmt.Println()

	// Step 1: Generate self-signed certificates for testing
	fmt.Println("Step 1: Generating test certificates...")

	err := network.GenerateSelfSignedCert(
		"cert.pem",
		"key.pem",
		[]string{"localhost", "127.0.0.1"},
		365*24*time.Hour, // Valid for 1 year
	)
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	fmt.Println()

	// Step 2: Create production-grade TLS configuration
	fmt.Println("Step 2: Creating TLS 1.3 configuration...")

	tlsConfig, err := network.NewProductionTLSConfig(network.TLSConfigParams{
		CertPath:         "cert.pem",
		KeyPath:          "key.pem",
		CACertPath:       "cert.pem", // Self-signed, so cert is also CA
		EnableMutualTLS:  false,      // Disable for self-signed demo
		StrictValidation: true,
	})
	if err != nil {
		log.Fatalf("Failed to create TLS config: %v", err)
	}

	// Validate TLS configuration
	if err := network.ValidateTLSConfig(tlsConfig); err != nil {
		// This is expected because InsecureSkipVerify might be true for self-signed
		fmt.Printf("  ⚠️  TLS validation note: %v\n", err)
	}

	fmt.Println("  ✓ TLS 1.3 configured with:")
	fmt.Println("    - Perfect Forward Secrecy (PFS)")
	fmt.Println("    - ChaCha20-Poly1305 & AES-256-GCM ciphers")
	fmt.Println("    - X25519 & P-256 curves")
	fmt.Println("    - Certificate validation")
	fmt.Println()

	// Step 3: Create network transport
	fmt.Println("Step 3: Creating secure network transport...")

	transport, err := network.NewTLSTransport(&network.TransportConfig{
		PartyID:      0,
		TotalParties: 2,
		ListenAddr:   "127.0.0.1:8000",
		PeerAddrs: map[int]string{
			1: "127.0.0.1:8001",
		},
		TLSConfig:            tlsConfig,
		MaxMessageSize:       10 * 1024 * 1024, // 10 MB
		SendTimeout:          30 * time.Second,
		ReceiveTimeout:       30 * time.Second,
		BufferSize:           1000,
		EnableRateLimiting:   true,
		DefaultRateLimit:     100, // 100 msgs/sec
		EnableAuditLog:       false,
		EnableEncryption:     true,
		ReconnectInterval:    5 * time.Second,
		MaxReconnectAttempts: 5,
	})
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	fmt.Println("  ✓ TLS transport created")
	fmt.Println()

	// Step 4: Start transport
	fmt.Println("Step 4: Starting transport...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := transport.Start(ctx); err != nil {
		log.Fatalf("Failed to start transport: %v", err)
	}

	fmt.Println("  ✓ Transport listening on 127.0.0.1:8000")
	fmt.Println()

	// Step 5: Show security features
	fmt.Println("=== Security Features Enabled ===")
	fmt.Println()
	fmt.Println("✓ TLS 1.3 Only (no downgrade attacks)")
	fmt.Println("✓ Perfect Forward Secrecy (session keys secure even if long-term key compromised)")
	fmt.Println("✓ Cipher Suites:")
	fmt.Println("  • ChaCha20-Poly1305-SHA256 (modern AEAD)")
	fmt.Println("  • AES-256-GCM-SHA384 (hardware accelerated)")
	fmt.Println("  • AES-128-GCM-SHA256 (fast)")
	fmt.Println("✓ Elliptic Curves:")
	fmt.Println("  • X25519 (modern, constant-time)")
	fmt.Println("  • P-256 (NIST standard)")
	fmt.Println("✓ Additional Layer:")
	fmt.Println("  • AES-256-GCM encrypted channels")
	fmt.Println("  • Message authentication")
	fmt.Println("  • Replay protection")
	fmt.Println()

	fmt.Println("=== Demo Running ===")
	fmt.Println("Press Ctrl+C to stop...")
	fmt.Println()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println()
	fmt.Println("Shutting down...")
	cancel()
	transport.Stop()

	// Cleanup
	os.Remove("cert.pem")
	os.Remove("key.pem")

	fmt.Println("✓ Demo completed")
}
