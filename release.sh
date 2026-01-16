#!/bin/bash
# Release wrapper script - bypasses shell make alias
# Usage: ./release.sh 0.4.0

if [ -z "$1" ]; then
    echo "Usage: ./release.sh VERSION"
    echo "  Example: ./release.sh 0.4.0"
    exit 1
fi

/usr/bin/make release VERSION="$1"
