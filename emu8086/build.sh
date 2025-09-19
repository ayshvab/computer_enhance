#!/bin/bash

set -e

CC="clang"
CFLAGS="-g -Wall -Wextra -Wconversion -Wdouble-promotion"
CFLAGS+=" -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion"
CFLAGS+=" -fsanitize=undefined -fsanitize-trap=undefined"
CFLAGS+=" -std=c89"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_DIR/_build"
SRC="$PROJECT_DIR/emu8086.c"
TARGET="$BUILD_DIR/emu8086"

# Debug flag
DEBUG=${DEBUG:-0}
if [[ $DEBUG -eq 1 ]]; then
    CFLAGS+=" -DDEBUG"
fi

# echo "Creating build directory: $BUILD_DIR"
mkdir -p "$BUILD_DIR"

$CC $CFLAGS -o "$TARGET" "$SRC"
