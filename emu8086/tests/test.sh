#!/bin/bash

set -e

cd "$(dirname "$0")"

../build.sh

# Test cases array
TEST_CASES=(
    # MOV instruction variants
    "mov_reg_reg"
    "mov_reg_mem"
    "mov_mem_reg"
    "mov_reg_imm"
    # "mov_mem_imm"
    # "mov_segreg"
    
    # ADD instruction variants
    # "add_reg_reg"
    # "add_reg_imm"
    # "add_reg_mem"
    # "add_mem_reg"
    # "add_mem_imm"
)

PASS_COUNT=0
FAIL_COUNT=0

run_test() {
    local test_name="$1"
    echo ""
    echo "=== Testing $test_name ==="

    local asm_file="$test_name.asm"
    local baseline_bin="$test_name.bin"
    local disasm_file="${test_name}_disasm.asm"
    local produced_bin="${test_name}_actual.bin"

    if [ ! -f "$asm_file" ]; then
        echo "Assembly file '$asm_file' is missing. Skipping."
        ((FAIL_COUNT++))
        return
    fi

    # Step 1: Build baseline binary from ASM using nasm
    if nasm -f bin "$asm_file" -o "$baseline_bin"; then
        echo "Built baseline -> $baseline_bin"
    else
        echo "Baseline assembly failed"
        ((FAIL_COUNT++))
        return
    fi

    # Step 2: Disassemble baseline binary using emu8086
    if ../_build/emu8086 "$baseline_bin" > "$disasm_file"; then
        echo "Disassembled -> $disasm_file"
    else
        echo "Disassembly failed"
        ((FAIL_COUNT++))
        return
    fi

    # Step 3: Assemble disassembled output
    if nasm -f bin "$disasm_file" -o "$produced_bin"; then
        echo "Assembled disassembled code -> $produced_bin"
    else
        echo "Re-assembly failed"
        ((FAIL_COUNT++))
        return
    fi

    echo "Baseline bytes (first 64):"
    head -c 64 "$baseline_bin" | hexdump -C
    echo ""
    echo "Produced bytes (first 64):"
    head -c 64 "$produced_bin" | hexdump -C

    # Step 4: Compare final binary with baseline
    if cmp -s "$baseline_bin" "$produced_bin"; then
        echo "✓ PASS (binaries identical): $test_name"
        ((PASS_COUNT++))
    else
        echo "✗ FAIL (binaries differ): $test_name"
        echo "--- diff (hex dump full) ---"
        echo "Baseline: $baseline_bin"
        hexdump -C "$baseline_bin" > "${test_name}_baseline.hex"
        echo "Produced: $produced_bin"
        hexdump -C "$produced_bin" > "${test_name}_actual.hex"
        # Show unified diff of hex dumps for easier visual comparison
        if command -v diff >/dev/null 2>&1; then
            diff -u "${test_name}_baseline.hex" "${test_name}_actual.hex" || true
        fi
        ((FAIL_COUNT++))
    fi
}

# Run all tests
for test in "${TEST_CASES[@]}"; do
    run_test "$test"
done

echo ""
echo "=== SUMMARY ==="
echo "PASSED: $PASS_COUNT"
echo "FAILED: $FAIL_COUNT"
echo "TOTAL:  $((PASS_COUNT + FAIL_COUNT))"

if [ $FAIL_COUNT -eq 0 ]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi
