#!/bin/bash

set -e

# Directories
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$PROJECT_DIR/_build"

echo "Cleaning build directory..."
rm -rf "$BUILD_DIR"
echo "Cleanup complete."
