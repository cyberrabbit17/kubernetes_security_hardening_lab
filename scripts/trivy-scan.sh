#!/bin/bash
# Scans all images currently running in the cluster

set -e

OUTPUT_DIR="trivy"
mkdir -p "$OUTPUT_DIR"

echo "================================================"
echo " Trivy Security Scan - $(date)"
echo "================================================"
echo ""

# Get all unique images running in the cluster
IMAGES=$(kubectl get pods --all-namespaces \
  -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' \
  | sort -u \
  | grep -v "^$")

echo "Images to scan:"
echo "$IMAGES"
echo ""

# Scan each image
while IFS= read -r image; do
  echo "Scanning: $image"
  SAFE_NAME=$(echo "$image" | tr '/:' '--')
  trivy image "$image" \
    --db-repository ghcr.io/aquasecurity/trivy-db \
    --scanners vuln \
    --skip-db-update \
    --timeout 15m \
    --severity HIGH,CRITICAL \
    --format table \
    --output "$OUTPUT_DIR/${SAFE_NAME}.txt" 2>/dev/null \
    || true
  echo "  Saved to $OUTPUT_DIR/${SAFE_NAME}.txt"
done <<< "$IMAGES"

echo ""
echo "================================================"
echo " Scan complete. Results in $OUTPUT_DIR/"
echo "================================================"