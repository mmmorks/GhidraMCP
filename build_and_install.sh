#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GHIDRA_EXT_BASE="$HOME/Library/ghidra"

# Find the latest Ghidra install by sorting version directories
LATEST_DIR=$(ls -d "$GHIDRA_EXT_BASE"/ghidra_*_PUBLIC 2>/dev/null | sort -V | tail -1)

if [ -z "$LATEST_DIR" ]; then
    echo "Error: No Ghidra installation found in $GHIDRA_EXT_BASE"
    exit 1
fi

DEST="$LATEST_DIR/Extensions/GhidraMCP/lib"

echo "Building GhidraMCP..."
mvn -f "$SCRIPT_DIR/pom.xml" package -DskipTests -q

echo "Installing to $DEST"
mkdir -p "$DEST"
cp "$SCRIPT_DIR/target/GhidraMCP.jar" "$DEST/GhidraMCP.jar"

echo "Done. Restart Ghidra to pick up changes."
