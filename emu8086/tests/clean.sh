#!/bin/bash

cd "$(dirname "$0")"

echo "Cleaning test artifacts..."

rm -f *.bin
rm -f *.hex

echo "Test artifacts cleaned."
