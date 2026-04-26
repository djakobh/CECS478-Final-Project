#!/bin/sh
set -e

PASS=0
FAIL=0

run_test() {
    name="$1"
    bin="$2"
    echo "--- Running $name ---"
    if "$bin"; then
        PASS=$((PASS + 1))
    else
        echo "FAILED: $name"
        FAIL=$((FAIL + 1))
    fi
}

run_test "test_http_validator"  ./tests/test_http_validator
run_test "test_dns_validator"   ./tests/test_dns_validator
run_test "test_detector"        ./tests/test_detector
run_test "test_feature_extract" ./tests/test_feature_extract

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
