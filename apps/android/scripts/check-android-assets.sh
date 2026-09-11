#!/usr/bin/env bash
# softXchange Android — 3D Asset Budget Check
# Mirrors the web-side npm run check:assets.
# Fails with exit 1 if any .glb in res/raw exceeds the per-model budget.
#
# Called from app/build.gradle.kts preBuild task.
# Can also be run standalone: bash scripts/check-android-assets.sh

set -euo pipefail

RAW_DIR="$(dirname "$0")/../app/src/main/res/raw"
PER_MODEL_KB="${ASSET_BUDGET_KB:-80}"
TOTAL_KB="${TOTAL_BUDGET_KB:-2000}"
PER_MODEL_BYTES=$(( PER_MODEL_KB * 1024 ))
TOTAL_BYTES=$(( TOTAL_KB * 1024 ))

echo ""
echo " softXchange Android Asset Budget Check"
echo " Per-model limit : ${PER_MODEL_KB} KB"
echo " Total limit     : ${TOTAL_KB} KB"
echo ""
printf " %-20s %10s   %s\n" "File" "Size (KB)" "Status"
echo " $(printf '%.0s─' {1..48})"

total_bytes=0
failures=0

for f in "${RAW_DIR}"/*.glb; do
    [ -f "$f" ] || { echo " (no .glb files found in res/raw)"; continue; }
    name=$(basename "$f")
    bytes=$(wc -c < "$f")
    kb=$(awk "BEGIN { printf \"%.1f\", $bytes/1024 }")
    total_bytes=$(( total_bytes + bytes ))

    if [ "$bytes" -gt "$PER_MODEL_BYTES" ]; then
        printf " %-20s %10s KB   ✗ OVER %s KB limit\n" "$name" "$kb" "$PER_MODEL_KB"
        failures=$(( failures + 1 ))
    else
        printf " %-20s %10s KB   ✓\n" "$name" "$kb"
    fi
done

total_kb=$(awk "BEGIN { printf \"%.1f\", $total_bytes/1024 }")
echo " $(printf '%.0s─' {1..48})"
if [ "$total_bytes" -gt "$TOTAL_BYTES" ]; then
    printf " %-20s %10s KB   ✗ OVER %s KB limit\n" "TOTAL" "$total_kb" "$TOTAL_KB"
    failures=$(( failures + 1 ))
else
    printf " %-20s %10s KB   ✓\n" "TOTAL" "$total_kb"
fi

echo ""
if [ "$failures" -gt 0 ]; then
    echo " ✗ $failures budget violation(s). Reduce .glb size or raise limits via env vars."
    exit 1
else
    echo " ✓ All Android 3D assets within budget."
    echo ""
    exit 0
fi
