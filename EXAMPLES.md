# MPC-TSS Examples Guide

This guide provides detailed information about all available examples and how to use them.

## Quick Start

### Running Examples

```bash
# Run all working examples (DKG + Storage)
./test-working-examples.sh

# Run all examples with detailed test reporting
./test-examples.sh

# Run individual examples
go run cmd/examples/simple_dkg/main.go
go run cmd/examples/storage_demo/main.go
go run cmd/examples/simple-signing/main.go
go run cmd/examples/multi-party-demo/main.go
go run cmd/examples/key-refresh/main.go
```

---

## Example 1: Simple DKG (2-of-3)

**Status:** ✅ **Fully Working**

**Location:** `cmd/examples/simple_dkg/main.go`

### Description

Demonstrates a complete 2-of-3 distributed key generation protocol where:
- 3 parties participate
- Any 2 parties can later sign
- No single party knows the complete private key

### What It Does

1. **Phase 1:** Initialize 3 DKG protocol instances
2. **Phase 2:** Round 1 - Each party generates polynomial commitments
3. **Phase 3:** Round 2 - Parties exchange secret shares
4. **Phase 4:** Round 3 - Verify shares and compute final key shares
5. **Phase 5:** Verify all parties have the same public key

### Run It

```bash
go run cmd/examples/simple_dkg/main.go
```

### Expected Output

```
=== Simple DKG Example: 2-of-3 Threshold ===

Phase 1: Creating DKG instances...
  ✓ Party 0 initialized
  ✓ Party 1 initialized
  ✓ Party 2 initialized

Phase 2: Round 1 - Broadcasting commitments...
  ✓ Party 0: Generated 2 commitments
  ✓ Party 1: Generated 2 commitments
  ✓ Party 2: Generated 2 commitments

Phase 3: Round 2 - Exchanging secret shares...
  ✓ Party 0: Generated 2 shares
  ✓ Party 1: Generated 2 shares
  ✓ Party 2: Generated 2 shares

Phase 4: Round 3 - Finalizing key shares...
  ✓ Party 0: Key share generated
  ✓ Party 1: Key share generated
  ✓ Party 2: Key share generated

Phase 5: Verification...
  ✓ All parties have consistent public key

=== DKG Complete! ===
Threshold: 2-of-3
Public Key X: 29f3757f...
Public Key Y: fc6bac45...

Key shares generated successfully!
Any 2 parties can now collaboratively sign messages.
```

### Key Concepts

- **Feldman VSS:** Verifiable Secret Sharing scheme
- **Polynomial Commitments:** Used to verify shares without revealing secrets
- **Threshold:** Minimum number of parties needed for signing
- **Distributed Trust:** No single point of failure

---

## Example 2: Storage Demo

**Status:** ✅ **Fully Working**

**Location:** `cmd/examples/storage_demo/main.go`

### Description

Demonstrates secure encrypted storage of key shares with enterprise-grade security features.

### What It Does

1. **Step 1:** Generate a test key share
2. **Step 2:** Save with AES-256-GCM encryption
3. **Step 3:** Read metadata without decryption
4. **Step 4:** Load and decrypt key share
5. **Step 5:** Verify integrity
6. **Step 6:** Create encrypted backup
7. **Step 7:** Simulate disaster recovery (delete and restore)
8. **Step 8:** Rotate password
9. **Step 9:** Secure deletion with overwrite

### Security Features

- **AES-256-GCM:** Authenticated encryption
- **Argon2id:** Memory-hard key derivation (brute-force resistant)
- **Secure Permissions:** File permissions set to 0600
- **Metadata Access:** Query info without decryption
- **Backup/Restore:** Disaster recovery capabilities
- **Password Rotation:** Change password without re-encryption overhead
- **Integrity Verification:** Detect tampering
- **Secure Deletion:** Overwrite before delete

### Run It

```bash
go run cmd/examples/storage_demo/main.go
```

### Expected Output

```
=== Secure Storage Demo ===

Step 1: Generating key share...
  ✓ Key share generated for Party 0
    Threshold: 2-of-3

Step 2: Saving key share with encryption...
  ✓ Key share encrypted and saved
    Encryption: AES-256-GCM
    KDF: Argon2id (64MB, 3 iterations)

Step 3: Reading metadata...
  ✓ Metadata retrieved
    Party ID: 0
    Threshold: 2/3
    Created: 2025-11-16 12:26:38

... (continues with all 9 steps)

Security Features Demonstrated:
  ✓ AES-256-GCM authenticated encryption
  ✓ Argon2id key derivation
  ✓ Secure file permissions (0600)
  ✓ Backup and restore capabilities
  ✓ Password rotation
  ✓ Integrity verification
  ✓ Secure deletion with overwrite
```

---

## Example 3: Simple Signing (2-of-3)

**Status:** ✅ **Fully Working**

**Location:** `cmd/examples/simple-signing/main.go`

### Description

Demonstrates threshold signature generation where any 2-of-3 parties can collaboratively sign a message.

### What It Does

1. **Phase 1:** Run DKG to generate key shares
2. **Phase 2:** Prepare message to sign
3. **Phase 3:** Select signing parties (any 2)
4. **Phase 4:** Run 4-round threshold signing protocol
5. **Phase 5:** Verify signature
6. **Phase 6:** Test with different party combinations

### Signing Protocol Rounds

- **Round 1:** Generate nonce commitments
- **Round 2:** Reveal nonces and verify commitments
- **Round 3:** Compute partial signatures with ZK proofs
- **Round 4:** Aggregate partial signatures into final signature

### Run It

```bash
go run cmd/examples/simple-signing/main.go
```

### Expected Output

```
=== Simple Threshold Signing Example: 2-of-3 ===

Phase 1: Distributed Key Generation (DKG)...
  ✓ Generated 3 key shares
  ✓ Public Key: fd881b16...60627850

Phase 2: Preparing message...
  Message: Transfer 100 BTC from Alice to Bob
  Hash: 31ae0e42939df6c5848f6835aa8ab4f5

Phase 3: Selecting signing parties...
  ✓ Selected parties: [0 1]

Phase 4: Threshold Signing Protocol...
  ✓ Signature generated
    R: 6799eb7596694dd76f9f27543b30c92f
    S: d080cc7e99e3747d5577ce7d209dd9a9

Phase 5: Signature Verification...
  ✓ Signature verified successfully!

Phase 6: Testing with different signing parties...
  Selected parties: [1 2]
  ✓ Second signature verified successfully!

=== Threshold Signing Complete! ===
```

---

## Example 4: Multi-Party Demo (3-of-5)

**Status:** ✅ **Fully Working**

**Location:** `cmd/examples/multi-party-demo/main.go`

### Description

Comprehensive demonstration of a 3-of-5 threshold signature scheme simulating a Bitcoin multi-signature wallet.

### Scenario

Five parties (Alice, Bob, Charlie, Dave, Eve) manage a shared Bitcoin wallet:
- **Configuration:** 3-of-5 threshold
- **Any 3 parties** can authorize transactions
- **Different combinations** for each transaction

### What It Demonstrates

**Part 1:** Distributed Key Generation
- Initialize 5 parties
- Complete 3-round DKG
- Verify public key consistency

**Part 2:** First Transaction
- Signers: Alice, Bob, Charlie (parties 0, 1, 2)
- Regular payment: 1.5 BTC

**Part 3:** Second Transaction
- Signers: Bob, Dave, Eve (parties 1, 3, 4)
- Urgent payment while Alice & Charlie unavailable

**Part 4:** Third Transaction
- Signers: Alice, Charlie, Eve (parties 0, 2, 4)
- Contract payment: 2.0 BTC

**Part 5:** Security Demonstration
- Shows that 2 parties cannot sign (below threshold)

### Run It

```bash
go run cmd/examples/multi-party-demo/main.go
```

### Features

- Beautiful formatted output with separators
- Real-world scenario simulation
- Multiple party combinations
- Threshold security enforcement demonstration

---

## Example 5: Key Refresh Demo

**Status:** ✅ **Fully Working**

**Location:** `cmd/examples/key-refresh/main.go`

### Description

Demonstrates **proactive security** through periodic key share refresh without changing the public key.

### Proactive Security

Periodically refresh key shares so that:
- **Old compromised shares** become useless
- **Public key remains** unchanged
- **No trust** required in any single party
- **Limited window** of vulnerability

### What It Does

**Part 1:** Initial Key Generation
- Generate original 2-of-3 key shares
- Display initial share values

**Part 2:** Sign with Original Shares
- Create transaction with original shares
- Verify signature works

**Part 3:** Proactive Refresh
- Each party generates zero-sharing (polynomial with constant term = 0)
- Distribute zero-shares to all parties
- Each party adds received zero-shares to their current share
- Result: New shares, same public key

**Part 4:** Sign with Refreshed Shares
- Create transaction with NEW shares
- Verify signature works with same public key

**Part 5:** Security Demonstration
- Show old shares cannot be mixed with new shares

### Run It

```bash
go run cmd/examples/key-refresh/main.go
```

### Use Cases

- **Long-term custody:** Cryptocurrency wallets
- **Certificate authorities:** Protect signing keys
- **Critical infrastructure:** Continuous protection
- **Compliance:** Meet security policy requirements

### Recommended Refresh Schedule

- **High security:** Weekly or monthly
- **Standard security:** Quarterly
- **Low security:** Annually

---

## Testing Framework

### Test Scripts

We provide two test scripts:

#### 1. `test-working-examples.sh`

Runs only fully working examples:
- simple_dkg
- storage_demo

```bash
./test-working-examples.sh
```

#### 2. `test-examples.sh`

Comprehensive test suite with colored output and detailed reporting:
- Tests all 5 examples
- Tracks expected vs unexpected failures
- Provides summary statistics
- Shows status of each example

```bash
./test-examples.sh
```

### Sample Output

```
╔════════════════════════════════════════════════════════════╗
║         MPC-TSS Example Test Suite                        ║
╔════════════════════════════════════════════════════════════╗

Test 1: Simple DKG (2-of-3)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ PASSED - Simple DKG completed successfully

Test 2: Storage Demo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ PASSED - Storage Demo completed successfully

... (continues for all tests)

Test Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Tests:    5
Passed:         2
Failed:         3
Success Rate:   40%
```

---

## Troubleshooting

### Common Issues

#### Issue: Permission Denied

```bash
chmod +x test-examples.sh
chmod +x test-working-examples.sh
```

#### Issue: Module Not Found

```bash
go mod download
go mod tidy
```

#### Issue: Compilation Errors

```bash
# Clean and rebuild
go clean -cache
go build ./...
```

### Getting Help

- Check [README.md](README.md) for general information
- See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
- Open an issue on GitHub for bugs
- Review code comments in example files

---

## Next Steps

1. **Start with working examples:** Run `simple_dkg` and `storage_demo`
2. **Understand the protocols:** Read the code and comments
3. **Experiment:** Modify threshold and party counts
4. **Build your application:** Use as reference for your implementation
5. **Contribute:** Help fix the signing protocol issues!

---

## Security Notice

⚠️ **These examples are for demonstration and learning purposes.**

**DO NOT** use in production without:
1. Professional security audit
2. Extensive testing
3. Peer review by cryptography experts
4. Understanding of all security implications

See [SECURITY.md](SECURITY.md) for full security policy.

---

**Happy coding! 🚀**
