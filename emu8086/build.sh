#!/bin/bash

# Compiler and flags
CC="clang-19"
CFLAGS="-g -Wall -Wextra -Wconversion -Wdouble-promotion"
CFLAGS+=" -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion"
CFLAGS+=" -fsanitize=undefined -fsanitize-trap=undefined"
CFLAGS+=" -std=c23"

# Debug flag
DEBUG=${DEBUG:-0}
if [[ $DEBUG -eq 1 ]]; then
    CFLAGS+=" -DDEBUG"
fi

# Source file and target executable
SRC="emu8086.c"
TARGET="emu8086"

# ANSI color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Build the target
build() {
    echo "Building $TARGET..."
    $CC $CFLAGS -o $TARGET $SRC
    if [[ $? -eq 0 ]]; then
        echo "Build successful!"
    else
        echo "Build failed."
        exit 1
    fi
}

# Run the target
run() {
    if [[ ! -f $TARGET ]]; then
        echo "Executable $TARGET not found. Building first..."
        build
    fi
    echo "Running $TARGET..."
    ./$TARGET
}

# Clean up
clean() {
    echo "Cleaning up..."
    rm -f $TARGET
    echo "Cleanup complete."
}

# Test cases
test_cases=(
    "listing_0037_single_register_mov"
    "listing_0038_many_register_mov"
    "listing_0039_more_movs"
    "listing_0040_challenge_movs"
)

# Check function
check() {
    echo "Build first..."
    build

    rm -rf ./tmp
    mkdir tmp
    
    echo "Testing..."

    for test_case in "${test_cases[@]}"; do
#        echo "Testing $test_case..."

        # Run the emulator and generate assembly
        ./$TARGET ./misc/$test_case > ./tmp/$test_case.asm

        # Assemble the generated assembly
        nasm -f bin -o ./tmp/$test_case ./tmp/$test_case.asm

        # Compare the output with the original binary
        cmp ./tmp/$test_case ./misc/$test_case

        if [[ $? -eq 0 ]]; then
            echo -e "$test_case: ${GREEN}OK${NC}"
        else
            echo -e "$test_case: ${RED}FAILED${NC}"
            exit 1
        fi
    done
}

# Main script logic
case "$1" in
    build)
        build
        ;;
    run)
        run
        ;;
    clean)
        clean
        ;;
    check)
        check
        ;;
    *)
        echo "Usage: $0 {build|run|clean|check}"
        exit 1
        ;;
esac

# Usage
#
#  Build the project
# DEBUG=1 ./build.sh build

# Run the project
# ./build.sh run

# Clean the project
# ./build.sh clean

# Run tests
# ./build.sh check
