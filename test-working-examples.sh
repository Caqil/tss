#!/bin/bash

# Quick test script - runs only the fully working examples

echo "════════════════════════════════════════"
echo "Testing Working MPC-TSS Examples"
echo "════════════════════════════════════════"
echo ""

echo "▶ Test 1: Simple DKG (2-of-3)"
echo "────────────────────────────────────────"
go run cmd/examples/simple_dkg/main.go
echo ""

echo "▶ Test 2: Storage Demo"
echo "────────────────────────────────────────"
go run cmd/examples/storage_demo/main.go
echo ""

echo "════════════════════════════════════════"
echo "✓ All working examples completed!"
echo "════════════════════════════════════════"
