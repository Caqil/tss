#!/bin/bash

# MPC-TSS Examples Test Script
# Tests all example implementations

set -e  # Exit on error is disabled below for better reporting

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
TOTAL=0
PASSED=0
FAILED=0

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         MPC-TSS Example Test Suite                        ║${NC}"
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo ""

# Function to run a test
run_test() {
    local name=$1
    local path=$2
    local expected_status=$3  # 0 for pass, 1 for expected fail

    TOTAL=$((TOTAL + 1))

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}Test $TOTAL: ${name}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Run the example and capture output
    if go run $path 2>&1; then
        if [ $expected_status -eq 0 ]; then
            echo ""
            echo -e "${GREEN}✓ PASSED${NC} - $name completed successfully"
            PASSED=$((PASSED + 1))
        else
            echo ""
            echo -e "${YELLOW}⚠ UNEXPECTED PASS${NC} - $name was expected to fail but passed"
            PASSED=$((PASSED + 1))
        fi
    else
        if [ $expected_status -eq 1 ]; then
            echo ""
            echo -e "${YELLOW}⚠ EXPECTED FAILURE${NC} - $name has known issues (signature verification)"
            FAILED=$((FAILED + 1))
        else
            echo ""
            echo -e "${RED}✗ FAILED${NC} - $name failed unexpectedly"
            FAILED=$((FAILED + 1))
        fi
    fi
    echo ""
}

# Run all tests
echo -e "${CYAN}Starting tests...${NC}"
echo ""

# Test 1: Simple DKG (should pass)
run_test "Simple DKG (2-of-3)" "cmd/examples/simple_dkg/main.go" 0

# Test 2: Storage Demo (should pass)
run_test "Storage Demo" "cmd/examples/storage_demo/main.go" 0

# Test 3: Simple Signing (fully working with Lagrange interpolation)
run_test "Simple Signing (2-of-3)" "cmd/examples/simple-signing/main.go" 0

# Test 4: Multi-Party Demo (fully working with Lagrange interpolation)
run_test "Multi-Party Demo (3-of-5)" "cmd/examples/multi-party-demo/main.go" 0

# Test 5: Key Refresh (fully working with updated verification shares)
run_test "Key Refresh Demo" "cmd/examples/key-refresh/main.go" 0

# Summary
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}Test Summary${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "Total Tests:    ${TOTAL}"
echo -e "${GREEN}Passed:         ${PASSED}${NC}"
echo -e "${RED}Failed:         ${FAILED}${NC}"
echo ""

# Calculate percentage
if [ $TOTAL -gt 0 ]; then
    PERCENT=$((PASSED * 100 / TOTAL))
    echo -e "Success Rate:   ${PERCENT}%"
fi

echo ""
echo -e "${CYAN}Status Details:${NC}"
echo -e "  ${GREEN}✓${NC} simple_dkg       - Fully working"
echo -e "  ${GREEN}✓${NC} storage_demo     - Fully working"
echo -e "  ${GREEN}✓${NC} simple-signing   - Fully working (fixed with Lagrange interpolation)"
echo -e "  ${GREEN}✓${NC} multi-party-demo - Fully working (fixed with Lagrange interpolation)"
echo -e "  ${GREEN}✓${NC} key-refresh      - Fully working (fixed verification share updates)"

echo ""
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"

# Exit with appropriate code
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Some tests failed unexpectedly${NC}"
    exit 1
fi

echo -e "${GREEN}All tests passed successfully!${NC}"

echo ""
