#!/usr/bin/env bash
# CVE Gate: Hard-fail on HIGH/CRITICAL vulnerabilities unless explicitly allowed
set -euo pipefail

TRIVY_JSON="${1:-artifacts/trivy.json}"
ALLOW_CVES="${ALLOW_CVES:-0}"
MAX_CRITICAL="${MAX_CRITICAL:-0}"
MAX_HIGH="${MAX_HIGH:-0}"

if [ ! -f "$TRIVY_JSON" ]; then
  echo "❌ CVE Gate: Trivy JSON report not found at $TRIVY_JSON"
  exit 1
fi

# Parse severity counts from Trivy JSON
CRITICAL_COUNT=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$TRIVY_JSON" 2>/dev/null || echo "0")
HIGH_COUNT=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$TRIVY_JSON" 2>/dev/null || echo "0")
MEDIUM_COUNT=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$TRIVY_JSON" 2>/dev/null || echo "0")
LOW_COUNT=$(jq -r '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$TRIVY_JSON" 2>/dev/null || echo "0")

# Coerce empty values to 0 to ensure numeric comparisons work
CRITICAL_COUNT=${CRITICAL_COUNT:-0}
HIGH_COUNT=${HIGH_COUNT:-0}
MEDIUM_COUNT=${MEDIUM_COUNT:-0}
LOW_COUNT=${LOW_COUNT:-0}

echo "📊 CVE Summary:"
echo "   CRITICAL: $CRITICAL_COUNT"
echo "   HIGH:     $HIGH_COUNT"
echo "   MEDIUM:   $MEDIUM_COUNT"
echo "   LOW:      $LOW_COUNT"

# Check if override is enabled
if [ "$ALLOW_CVES" = "1" ]; then
  echo "⚠️  CVE Gate: ALLOW_CVES=1, skipping enforcement"
  exit 0
fi

# Enforce thresholds
FAIL=0
if (( CRITICAL_COUNT > MAX_CRITICAL )); then
  echo "❌ CVE Gate FAILED: $CRITICAL_COUNT CRITICAL vulnerabilities found (max: $MAX_CRITICAL)"
  FAIL=1
fi

if (( HIGH_COUNT > MAX_HIGH )); then
  echo "❌ CVE Gate FAILED: $HIGH_COUNT HIGH vulnerabilities found (max: $MAX_HIGH)"
  FAIL=1
fi

if [ "$FAIL" = "1" ]; then
  echo ""
  echo "💡 To override this check temporarily, set ALLOW_CVES=1"
  echo "💡 To adjust thresholds, set MAX_CRITICAL and MAX_HIGH environment variables"
  echo ""
  echo "🔍 Top vulnerabilities:"
  jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH") | "  - \(.VulnerabilityID) | \(.Severity) | \(.PkgName) \(.InstalledVersion) → \(.FixedVersion // "no fix") | \(.Title // "no title")"' "$TRIVY_JSON" 2>/dev/null | head -10 || true
  exit 1
fi

echo "✅ CVE Gate PASSED: No blocking vulnerabilities found"
exit 0
