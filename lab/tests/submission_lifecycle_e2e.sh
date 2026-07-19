#!/usr/bin/env bash
# submission_lifecycle_e2e.sh — PRD-0005 R-4 end-to-end acceptance.
#
# Drives the full self-service submission lifecycle over the real gateway,
# asserting each PRD-0005 control end to end:
#   submit (alice) -> automated scan (mcp_checker + SBOM) -> segregation-of-duties
#   (alice cannot approve her own) -> approve (carol, security_reviewer).
#
# This is the scriptable half of R-4. The Codex-driven half (generate the MCP
# server from the wizard answers + push to git) is a MANUAL step because it needs
# an interactive `codex mcp login mcp-gateway` — see lab/tests/README-r4-codex.md.
#
# Usage:  bash lab/tests/submission_lifecycle_e2e.sh
# Env:    BASE (default https://127.0.0.1:8443)
#         ALICE_PW (default from .env.lab DEX_ALICE_PASSWORD), CAROL_PW (labpassword)
set -uo pipefail

BASE="${BASE:-https://127.0.0.1:8443}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ALICE_PW="${ALICE_PW:-$(grep -E '^DEX_ALICE_PASSWORD=' "$ROOT/.env.lab" | cut -d= -f2)}"
CAROL_PW="${CAROL_PW:-labpassword}"
VULN_REPO="https://github.com/kenhuangus/mcp-vulnerable-server-demo"
WD="$(mktemp -d)"; trap 'rm -rf "$WD"' EXIT

PASS=0; FAIL=0
ok()   { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL+1)); }
chk()  { [ "$1" = "$2" ] && ok "$3 ($1)" || bad "$3 (want $2, got $1)"; }

# PKCE login helper -> writes cookie jar $2 for user $1
login() {
  local user="$1" pw="$2" jar="$WD/$1.jar"; rm -f "$jar"
  local page action redir
  page=$(curl -sk -c "$jar" -b "$jar" -L "$BASE/api/v1/auth/oidc/login?redirect=%2Fportal")
  action=$(echo "$page" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"$//;s/\&amp;/\&/g')
  redir=$(curl -sk -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' \
          -d "username=$user&password=$pw&credentialId=" "$action")
  [ -n "$redir" ] || { echo "LOGIN FAILED for $user"; return 1; }
  curl -sk -c "$jar" -b "$jar" -o /dev/null "$redir"
  echo "$jar"
}

jq_field() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }
db() { podman exec mcp-db psql -U mcp_app mcp_security -tAc "$1" 2>/dev/null; }

echo "== R-4 submission lifecycle E2E =="
AJAR=$(login alice "$ALICE_PW") || exit 1
CJAR=$(login carol "$CAROL_PW") || exit 1
ok "alice + carol logged in"

# 1. alice submits a repo-backed submission
NAME="e2e-$$-$(db "SELECT floor(random()*100000)::int")"
SID=$(curl -sk -b "$AJAR" -X POST "$BASE/api/v1/submissions" -H 'Content-Type: application/json' \
      -d "{\"name\":\"$NAME\",\"github_repo_url\":\"$VULN_REPO\"}" | jq_field server_id)
[ -n "$SID" ] && ok "draft created ($SID)" || { bad "draft create"; exit 1; }
curl -sk -b "$AJAR" -X POST "$BASE/api/v1/submissions/$SID/submit" -H 'Content-Type: application/json' -d '{}' >/dev/null
ok "submitted for review"

# 2. wait for scan, assert it ran and collected SBOM
for _ in $(seq 1 40); do
  st=$(db "SELECT scan_status FROM server_registry WHERE server_id='$SID'")
  [ "$st" != "pending" ] && [ "$st" != "running" ] && break; sleep 3
done
chk "$(db "SELECT scan_status FROM server_registry WHERE server_id='$SID'")" "passed" "scan reached passed"
chk "$(db "SELECT submission_status FROM server_registry WHERE server_id='$SID'")" "awaiting_review" "moved to awaiting_review"
findings=$(db "SELECT jsonb_array_length(COALESCE(scan_report,'[]'::jsonb)) FROM server_registry WHERE server_id='$SID'")
[ "${findings:-0}" -ge 1 ] && ok "mcp_checker surfaced findings ($findings)" || bad "expected MCP findings, got $findings"
declared=$(db "SELECT jsonb_array_length(COALESCE(sbom_components,'[]'::jsonb)) FROM server_registry WHERE server_id='$SID'")
[ "${declared:-0}" -ge 1 ] && ok "declared-dep SBOM collected ($declared)" || bad "no declared-dep SBOM"
chk "$(db "SELECT (sbom_cyclonedx IS NOT NULL) FROM server_registry WHERE server_id='$SID'")" "t" "CycloneDX SBOM generated"

# 3. segregation of duties: alice (submitter) cannot approve her own submission
code=$(curl -sk -b "$AJAR" -o /dev/null -w '%{http_code}' -X POST \
       "$BASE/api/v1/admin/submissions/$SID/approve" -H 'Content-Type: application/json' -d '{}')
chk "$code" "403" "SoD blocks self-approval by submitter"

# 4. carol (security_reviewer, not the submitter) approves
code=$(curl -sk -b "$CJAR" -o /dev/null -w '%{http_code}' -X POST \
       "$BASE/api/v1/admin/submissions/$SID/approve" -H 'Content-Type: application/json' -d '{"notes":"e2e approve"}')
[ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ] && ok "reviewer approved (HTTP $code)" || bad "reviewer approve HTTP $code"
final=$(db "SELECT submission_status FROM server_registry WHERE server_id='$SID'")
case "$final" in approved_pending_url|active|approved) ok "post-approval status = $final";; *) bad "unexpected post-approval status: $final";; esac

# 5. reviewer can download the CycloneDX SBOM
code=$(curl -sk -b "$CJAR" -o /dev/null -w '%{http_code}' "$BASE/api/v1/admin/submissions/$SID/sbom")
chk "$code" "200" "reviewer downloads CycloneDX SBOM"

# cleanup
db "UPDATE server_registry SET deleted_at=now() WHERE server_id='$SID'" >/dev/null
echo "== result: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
