#!/usr/bin/env bash
# de-voidlink — Integration test suite
# Tests C2 server endpoints, protocol behavior, and beacon integration
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
C2_BIN="$BUILD_DIR/c2server"
BEACON_BIN="$BUILD_DIR/phantom-beacon"
C2_PORT=18080
C2_ADDR="127.0.0.1:$C2_PORT"
C2_PID=""
PASS=0
FAIL=0
SKIP=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    if [[ -n "$C2_PID" ]] && kill -0 "$C2_PID" 2>/dev/null; then
        kill "$C2_PID" 2>/dev/null || true
        wait "$C2_PID" 2>/dev/null || true
    fi
    rm -f /tmp/phantom-link-test-*
}
trap cleanup EXIT

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1: $2"; FAIL=$((FAIL + 1)); }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1: $2"; SKIP=$((SKIP + 1)); }
log_section() { echo -e "\n=== $1 ==="; }

# Wait for server to be ready
wait_for_server() {
    local max_wait=5
    local waited=0
    while ! curl -s -o /dev/null -w "" "http://$C2_ADDR/api/v2/heartbeat" 2>/dev/null; do
        sleep 0.2
        ((waited++))
        if [[ $waited -ge $((max_wait * 5)) ]]; then
            echo "ERROR: C2 server failed to start within ${max_wait}s"
            return 1
        fi
    done
}

# ============================================================
# Phase 1: C2 Server Endpoint Tests
# ============================================================
test_c2_endpoints() {
    log_section "Phase 1: C2 Server Endpoint Tests"

    if [[ ! -x "$C2_BIN" ]]; then
        log_skip "C2 endpoint tests" "c2server binary not found at $C2_BIN (run 'make c2')"
        return
    fi

    # Start C2 server
    "$C2_BIN" --bind "$C2_ADDR" --mode voidlink --max-runtime 30 --verbose \
        > /tmp/phantom-link-test-c2.log 2>&1 &
    C2_PID=$!
    wait_for_server || { log_fail "C2 startup" "server did not start"; return; }

    # Test 1: POST /api/v2/handshake — valid registration
    local handshake_resp
    handshake_resp=$(curl -s -X POST "http://$C2_ADDR/api/v2/handshake" \
        -H "Content-Type: application/json" \
        -H "User-Agent: curl/8.4.0" \
        -d '{"hostname":"test-host","os":"linux","kernel":"6.1.0-test","arch":"x86_64","uid":1000,"cloud_provider":"","container":false,"edr_detected":[]}' \
        -w "\nHTTP_CODE:%{http_code}" -o /tmp/phantom-link-test-handshake)
    local handshake_code
    handshake_code=$(echo "$handshake_resp" | grep -oP 'HTTP_CODE:\K\d+')
    if [[ "$handshake_code" == "200" ]]; then
        log_pass "POST /api/v2/handshake — 200 OK"
    else
        log_fail "POST /api/v2/handshake" "expected 200, got $handshake_code"
    fi

    # Verify handshake response is non-empty (encrypted payload)
    local resp_size
    resp_size=$(wc -c < /tmp/phantom-link-test-handshake)
    if [[ "$resp_size" -gt 0 ]]; then
        log_pass "Handshake response body is non-empty ($resp_size bytes)"
    else
        log_fail "Handshake response body" "empty response"
    fi

    # Extract session_id from C2 server log (JSON structured log)
    sleep 0.5
    local session_id
    session_id=$(grep '"event":"handshake"' /tmp/phantom-link-test-c2.log | head -1 | grep -oP '"session_id":"[^"]+' | cut -d'"' -f4)
    if [[ -n "$session_id" ]]; then
        log_pass "Session ID generated: ${session_id:0:8}..."
    else
        log_fail "Session ID" "not found in server logs"
        session_id="unknown"
    fi

    # Test 2: GET /api/v2/heartbeat — with valid session
    local hb_code
    hb_code=$(curl -s -o /tmp/phantom-link-test-hb -w "%{http_code}" \
        -X GET "http://$C2_ADDR/api/v2/heartbeat" \
        -H "X-Session-ID: $session_id")
    if [[ "$hb_code" == "200" ]]; then
        log_pass "GET /api/v2/heartbeat — 200 OK (valid session)"
    else
        log_fail "GET /api/v2/heartbeat (valid)" "expected 200, got $hb_code"
    fi

    # Verify heartbeat JSON response
    if grep -q '"status":"ok"' /tmp/phantom-link-test-hb 2>/dev/null; then
        log_pass "Heartbeat response contains status:ok"
    else
        log_fail "Heartbeat response" "missing status:ok"
    fi

    # Test 3: GET /api/v2/heartbeat — with invalid session
    local hb_invalid_code
    hb_invalid_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X GET "http://$C2_ADDR/api/v2/heartbeat" \
        -H "X-Session-ID: invalid-session-id")
    if [[ "$hb_invalid_code" == "401" ]]; then
        log_pass "GET /api/v2/heartbeat — 401 (invalid session)"
    else
        log_fail "GET /api/v2/heartbeat (invalid)" "expected 401, got $hb_invalid_code"
    fi

    # Test 4: POST /api/v2/sync — valid session
    local sync_code
    sync_code=$(curl -s -o /tmp/phantom-link-test-sync -w "%{http_code}" \
        -X POST "http://$C2_ADDR/api/v2/sync" \
        -H "Content-Type: application/json" \
        -d "{\"session_id\":\"$session_id\",\"task_results\":[]}")
    if [[ "$sync_code" == "200" ]]; then
        log_pass "POST /api/v2/sync — 200 OK"
    else
        log_fail "POST /api/v2/sync" "expected 200, got $sync_code"
    fi

    # Test 5: POST /compile — SRC simulation
    local compile_code compile_size
    compile_code=$(curl -s -o /tmp/phantom-link-test-compile -w "%{http_code}" \
        -X POST "http://$C2_ADDR/compile" \
        -H "Content-Type: application/json" \
        -d '{"kernel_release":"6.1.0","hidden_ports":[4444,8080],"has_gcc":true}')
    compile_size=$(wc -c < /tmp/phantom-link-test-compile)
    if [[ "$compile_code" == "200" && "$compile_size" == "256" ]]; then
        log_pass "POST /compile — 200 OK, 256 bytes"
    else
        log_fail "POST /compile" "code=$compile_code, size=$compile_size (expected 200, 256)"
    fi

    # Test 6: GET /stage1.bin — ELF placeholder
    local stage1_code stage1_magic
    stage1_code=$(curl -s -o /tmp/phantom-link-test-stage1 -w "%{http_code}" \
        -X GET "http://$C2_ADDR/stage1.bin")
    stage1_magic=$(xxd -l 4 -p /tmp/phantom-link-test-stage1 2>/dev/null)
    if [[ "$stage1_code" == "200" && "$stage1_magic" == "7f454c46" ]]; then
        log_pass "GET /stage1.bin — 200 OK, valid ELF header"
    else
        log_fail "GET /stage1.bin" "code=$stage1_code, magic=$stage1_magic"
    fi

    # Test 7: GET /implant.bin — ELF placeholder
    local implant_code implant_size
    implant_code=$(curl -s -o /tmp/phantom-link-test-implant -w "%{http_code}" \
        -X GET "http://$C2_ADDR/implant.bin")
    implant_size=$(wc -c < /tmp/phantom-link-test-implant)
    if [[ "$implant_code" == "200" && "$implant_size" == "8192" ]]; then
        log_pass "GET /implant.bin — 200 OK, 8192 bytes"
    else
        log_fail "GET /implant.bin" "code=$implant_code, size=$implant_size"
    fi

    # Test 8: Method guard — wrong method rejected
    local wrong_method_code
    wrong_method_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X GET "http://$C2_ADDR/api/v2/handshake")
    if [[ "$wrong_method_code" == "405" ]]; then
        log_pass "Method guard — GET /api/v2/handshake returns 405"
    else
        log_fail "Method guard" "expected 405, got $wrong_method_code"
    fi

    # Test 9: Handshake with EDR detected — paranoid profile
    curl -s -X POST "http://$C2_ADDR/api/v2/handshake" \
        -H "Content-Type: application/json" \
        -d '{"hostname":"edr-host","os":"linux","kernel":"6.1.0","arch":"x86_64","uid":0,"cloud_provider":"aws","container":true,"edr_detected":["falcon-sensor","crowdstrike"]}' \
        -o /dev/null
    sleep 0.3
    if grep -q '"profile":"paranoid"' /tmp/phantom-link-test-c2.log; then
        log_pass "EDR detection triggers paranoid profile"
    else
        log_fail "EDR profile switch" "paranoid profile not found in logs"
    fi

    # Test 10: Kill switch
    local kill_code
    kill_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://$C2_ADDR/api/v2/kill")
    if [[ "$kill_code" == "200" ]]; then
        log_pass "POST /api/v2/kill — 200 OK"
    else
        log_fail "POST /api/v2/kill" "expected 200, got $kill_code"
    fi

    # Wait for server to exit
    sleep 1
    if ! kill -0 "$C2_PID" 2>/dev/null; then
        log_pass "Server exited after kill switch"
    else
        log_fail "Kill switch" "server still running after kill"
        kill "$C2_PID" 2>/dev/null || true
    fi
    C2_PID=""
}

# ============================================================
# Phase 2: Detection Rules Validation
# ============================================================
test_detection_rules() {
    log_section "Phase 2: Detection Rules Validation"

    # YARA rules
    if command -v yara >/dev/null 2>&1; then
        local yara_pass=0
        local yara_total=0
        for rule in "$PROJECT_ROOT"/detection/yara/*.yar; do
            yara_total=$((yara_total + 1))
            if yara --fail-on-warnings -w "$rule" /dev/null 2>/dev/null; then
                yara_pass=$((yara_pass + 1))
            else
                log_fail "YARA validation" "$(basename "$rule")"
            fi
        done
        if [[ $yara_pass -eq $yara_total ]]; then
            log_pass "All $yara_total YARA rule files validate"
        fi
    else
        log_skip "YARA validation" "yara not installed"
    fi

    # Sigma rules — check YAML syntax
    local sigma_count
    sigma_count=$(ls -1 "$PROJECT_ROOT"/detection/sigma/*.yml 2>/dev/null | wc -l)
    if [[ "$sigma_count" -gt 0 ]]; then
        log_pass "Sigma rules present: $sigma_count files"
    else
        log_fail "Sigma rules" "no .yml files found"
    fi

    # Aegis config — check JSON validity
    if python3 -c "import json; json.load(open('$PROJECT_ROOT/detection/aegis/voidlink_cadence.json'))" 2>/dev/null; then
        log_pass "Aegis config is valid JSON"
    else
        log_fail "Aegis config" "invalid JSON"
    fi
}

# ============================================================
# Phase 3: Arsenal Plugin Validation
# ============================================================
test_arsenal() {
    log_section "Phase 3: Arsenal Plugin Validation"

    local arsenal_dir="$BUILD_DIR/arsenal"
    if [[ ! -d "$arsenal_dir" ]]; then
        log_skip "Arsenal validation" "build/arsenal/ not found (run 'make arsenal')"
        return
    fi

    for obj in "$arsenal_dir"/*.o; do
        local basename_obj
        basename_obj=$(basename "$obj")
        # Check it's ET_REL (relocatable)
        local elf_type
        elf_type=$(readelf -h "$obj" 2>/dev/null | grep "Type:" | awk '{print $2}')
        if [[ "$elf_type" == "REL" ]]; then
            log_pass "Arsenal $basename_obj — ET_REL (relocatable)"
        else
            log_fail "Arsenal $basename_obj" "expected REL, got $elf_type"
        fi

        # Check for plugin API symbols (exec + init + info + cleanup)
        local sym_count
        sym_count=$(nm "$obj" 2>/dev/null | grep -cE "plugin_(exec|init|info|cleanup)" || echo 0)
        if [[ "$sym_count" -ge 3 ]]; then
            log_pass "Arsenal $basename_obj — has $sym_count plugin API symbols"
        else
            log_fail "Arsenal $basename_obj" "expected ≥3 plugin API symbols, found $sym_count"
        fi
    done
}

# ============================================================
# Phase 4: Beacon Integration Test (requires beacon binary)
# ============================================================
test_beacon_integration() {
    log_section "Phase 4: Beacon Integration Test"

    if [[ ! -x "$BEACON_BIN" ]]; then
        log_skip "Beacon integration" "phantom-beacon binary not found at $BEACON_BIN (run 'make core')"
        return
    fi

    # Start C2 server
    "$C2_BIN" --bind "$C2_ADDR" --mode voidlink --max-runtime 30 --verbose \
        > /tmp/phantom-link-test-c2-integ.log 2>&1 &
    C2_PID=$!
    wait_for_server || { log_fail "C2 startup (integration)" "server did not start"; return; }

    # Run beacon in live mode with safety env var
    PHANTOM_LINK_SAFETY=1 timeout 15 "$BEACON_BIN" \
        --c2-addr 127.0.0.1 \
        --c2-port "$C2_PORT" \
        --live \
        --max-iterations 3 \
        --max-runtime 10 \
        > /tmp/phantom-link-test-beacon.log 2>&1 || true

    sleep 2

    if grep -q '"event":"handshake"' /tmp/phantom-link-test-c2-integ.log; then
        log_pass "Beacon → C2 handshake completed"
    else
        log_fail "Beacon handshake" "no handshake event in C2 logs"
    fi

    if grep -q '"msg":"heartbeat"' /tmp/phantom-link-test-beacon.log 2>/dev/null; then
        log_pass "Beacon heartbeat loop executed"
    else
        log_fail "Beacon heartbeat loop" "no heartbeat entries in beacon log"
    fi

    if grep -q '"msg":"voidlink_sequence"' /tmp/phantom-link-test-beacon.log 2>/dev/null; then
        log_pass "Beacon VoidLink syscall sequence executed"
    else
        log_fail "Beacon VoidLink sequence" "syscall sequence not found in beacon log"
    fi

    # Clean up
    curl -s -X POST "http://$C2_ADDR/api/v2/kill" -o /dev/null 2>/dev/null || true
    sleep 1
    C2_PID=""
}

# ============================================================
# Main
# ============================================================
echo "================================================="
echo " de-voidlink Integration Test Suite"
echo " $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================="

test_c2_endpoints
test_detection_rules
test_arsenal
test_beacon_integration

echo ""
echo "================================================="
echo -e " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}"
echo "================================================="

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
