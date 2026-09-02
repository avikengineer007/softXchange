#!/usr/bin/env bash
set -euo pipefail

echo "Starting deployment..."
mkdir -p dist
cp -r src/* dist/
echo "Deployment successful."
