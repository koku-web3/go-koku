#!/usr/bin/env bash
# tools/check_logs.sh
# Scans Go source files for logging specification violations.
# Exit 0 = all clear, exit 1 = violations found.

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ERRORS=0

echo "=== Scanning for logging violations ==="

# P0: sensitive fields in non-Debug logs
# "password", "secret", "token", "private_key", "mnemonic", "authorization", "privkey" (non-length), "dek" (non-length), "plaintext" (non-length)
echo -n "Checking sensitive fields in non-Debug logs... "
SENSITIVE=$(grep -rn 'log\.\(Info\|Warn\|Error\)\s*([^)]*,\s*"\(password\|secret\|token\|private_key\|mnemonic\|authorization\)\s*"\s*,\s*[a-zA-Z]' --include="*.go" . 2>/dev/null || true)
if [ -n "$SENSITIVE" ]; then
    echo "FAIL"
    echo "$SENSITIVE"
    ERRORS=$((ERRORS+1))
else
    echo "PASS"
fi

# P0: raw "signature" / "raw_data" / "message" / "plaintext" in Info/Warn/Error
echo -n "Checking semi-sensitive fields in non-Debug logs... "
SEMI_SENSITIVE=$(grep -rn 'log\.\(Info\|Warn\|Error\)\s*([^)]*,\s*"\(signature\|raw_data\|plaintext\)\s*"\s*,\s*[a-zA-Z]' --include="*.go" . 2>/dev/null || true)
if [ -n "$SEMI_SENSITIVE" ]; then
    echo "FAIL"
    echo "$SEMI_SENSITIVE"
    ERRORS=$((ERRORS+1))
else
    echo "PASS"
fi

# P2: fmt.Sprintf in log calls
echo -n "Checking fmt.Sprintf in log calls... "
SPRINTF=$(grep -rn 'log\.\(Info\|Warn\|Error\|Debug\)\s*([^)]*fmt\.Sprintf' --include="*.go" . 2>/dev/null || true)
if [ -n "$SPRINTF" ]; then
    echo "FAIL"
    echo "$SPRINTF"
    ERRORS=$((ERRORS+1))
else
    echo "PASS"
fi

# P2: %v / %+v in log calls (whole-object dump)
echo -n "Checking %v/%+v in log calls... "
PERCENT_V=$(grep -rn 'log\.\(Info\|Warn\|Error\|Debug\)\s*([^)]*%[+v]' --include="*.go" . 2>/dev/null || true)
if [ -n "$PERCENT_V" ]; then
    echo "FAIL"
    echo "$PERCENT_V"
    ERRORS=$((ERRORS+1))
else
    echo "PASS"
fi

# P2: whole-object dump "params", req
echo -n "Checking whole-object dump 'params', req... "
PARAMS=$(grep -rn 'log\.\(Info\|Warn\|Error\|Debug\)\s*([^)]*"\s*params\s*"\s*,\s*req\b' --include="*.go" . 2>/dev/null || true)
if [ -n "$PARAMS" ]; then
    echo "FAIL"
    echo "$PARAMS"
    ERRORS=$((ERRORS+1))
else
    echo "PASS"
fi

# P2: camelCase trace_Id (should be trace_id)
echo -n "Checking camelCase trace_Id... "
CAMEL=$(grep -rn '"\s*trace_[A-Z]' --include="*.go" . 2>/dev/null || true)
if [ -n "$CAMEL" ]; then
    echo "FAIL"
    echo "$CAMEL"
    ERRORS=$((ERRORS+1))
else
    echo "PASS"
fi

# P2: elapsed_ms (should be time_cost_ms)
echo -n "Checking elapsed_ms field... "
ELAPSED=$(grep -rn '"\s*elapsed_ms\b' --include="*.go" . 2>/dev/null || true)
if [ -n "$ELAPSED" ]; then
    echo "FAIL"
    echo "$ELAPSED"
    ERRORS=$((ERRORS+1))
else
    echo "PASS"
fi

# Summary
echo ""
if [ $ERRORS -gt 0 ]; then
    echo "FAILED: $ERRORS violation category(ies) found"
    exit 1
else
    echo "ALL CHECKS PASSED"
    exit 0
fi
