#!/usr/bin/env bash
set -euo pipefail

# Copy required Ghidra JARs to lib/ for compilation.
# Usage:
#   ./setup_ghidra_jars.sh                                          # macOS .app bundle
#   ./setup_ghidra_jars.sh /path/to/ghidra_11.3.1_PUBLIC            # extracted Ghidra
#   GHIDRA_INSTALL_DIR=/path/to/ghidra ./setup_ghidra_jars.sh       # via env var

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

# Resolve Ghidra installation directory
if [ -n "${1:-}" ]; then
    GHIDRA_DIR="$1"
elif [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
    GHIDRA_DIR="$GHIDRA_INSTALL_DIR"
elif [ -d "/Applications/Ghidra.app/Contents/app" ]; then
    GHIDRA_DIR="/Applications/Ghidra.app/Contents/app"
else
    echo "Error: Cannot find Ghidra installation."
    echo "Usage: $0 /path/to/ghidra"
    exit 1
fi

# Verify the directory looks like a Ghidra install
if [ ! -d "$GHIDRA_DIR/Ghidra/Framework" ]; then
    echo "Error: $GHIDRA_DIR does not appear to be a Ghidra installation"
    echo "(expected $GHIDRA_DIR/Ghidra/Framework to exist)"
    exit 1
fi

# Framework modules
FRAMEWORK_JARS="Generic SoftwareModeling Project Docking Utility Gui DB FileSystem"
# Feature modules
FEATURE_JARS="Base Decompiler"

mkdir -p "$LIB_DIR"

echo "Copying Ghidra JARs from $GHIDRA_DIR ..."

for jar in $FRAMEWORK_JARS; do
    src="$GHIDRA_DIR/Ghidra/Framework/$jar/lib/$jar.jar"
    if [ ! -f "$src" ]; then
        echo "Error: Missing $src"
        exit 1
    fi
    cp "$src" "$LIB_DIR/$jar.jar"
done

for jar in $FEATURE_JARS; do
    src="$GHIDRA_DIR/Ghidra/Features/$jar/lib/$jar.jar"
    if [ ! -f "$src" ]; then
        echo "Error: Missing $src"
        exit 1
    fi
    cp "$src" "$LIB_DIR/$jar.jar"
done

echo "Copied 10 JARs to lib/"
