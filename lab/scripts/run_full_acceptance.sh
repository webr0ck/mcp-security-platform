#!/usr/bin/env bash
# run_full_acceptance.sh — full AT0-AT3 acceptance run against the live lab.
#
# Usage: bash lab/scripts/run_full_acceptance.sh
#        make -f Makefile.lab lab-acceptance
#
# What it does:
#   1. Resolves DOCKER_HOST for the podman machine.
#   2. Brings the lab up if it isn't already (reuses Makefile.lab's lab-up /
#      lab-setup targets — does not reinvent health-wait logic).
#   3. Runs the AT3 gitea fixture setup (idempotent).
#   4. Creates lab/tests/acceptance/results/<UTC timestamp>/, runs pytest with
#      --junitxml + verbose output teed to run.log.
#   5. Writes REPORT.md summarizing pass/fail/skip per AT group with evidence.
#   6. Exits non-zero on any real failure (xfail/skip do not count as failure).
#
# Idempotent / re-runnable: submissions/tickets created by the suite use
# uuid-suffixed names (see test_at3_onboarding.py), so reruns never collide;
# the gitea fixture setup step is itself idempotent (409-tolerant repo
# create, cert regenerated fresh each run, git_providers row upserted).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

export DOCKER_HOST="${DOCKER_HOST:-unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')}"
echo "DOCKER_HOST=$DOCKER_HOST"

LAB_COMPOSE="podman-compose --env-file .env.lab -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml -f compose.wazuh.yml"

echo "== Checking lab stack =="
if ! curl -sk -o /dev/null -w '' --max-time 5 "https://127.0.0.1:8443/health" 2>/dev/null; then
  echo "  gateway not responding — bringing the lab up (make -f Makefile.lab lab-up)"
  make -f Makefile.lab lab-up
else
  echo "  gateway already up"
fi

# Wait for proxy health specifically (from inside its own network — see
# lab/tests/acceptance/conftest.py docstring on the SEC-05 ingress guard).
echo "== Waiting for proxy health =="
for _ in $(seq 1 30); do
  status=$(podman exec mcp-proxy curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/health 2>/dev/null || echo 000)
  [ "$status" = "200" ] && { echo "  proxy healthy"; break; }
  sleep 3
done

echo "== AT3 fixture setup (gitea-tls sidecar + repo push, idempotent) =="
bash lab/tests/acceptance/fixtures/setup_gitea_fixtures.sh

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="$ROOT/lab/tests/acceptance/results/$TS"
mkdir -p "$RESULTS_DIR"
echo "Results dir: $RESULTS_DIR"

echo "== Running acceptance suite =="
set +e
ACCEPT_RESULTS_DIR="$RESULTS_DIR" python3 -m pytest lab/tests/acceptance/ \
  --junitxml="$RESULTS_DIR/results.xml" -v --tb=short \
  2>&1 | tee "$RESULTS_DIR/run.log"
PYTEST_EXIT=${PIPESTATUS[0]:-$?}
set -e

echo "== Cleanup: soft-deleting AT3/AT4 submissions this run created =="
# AT4 (test_at4_apply_deploy_verify.py) also runs as part of this suite and
# creates its own uuid-suffixed 'at4-clean-*' fixture, same pattern as AT3 —
# it was missing here, which left stray-but-real (not soft-deleted) rows
# visible in the portal admin servers list after every run.
podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "UPDATE server_registry SET deleted_at=now() WHERE (name LIKE 'at3-malicious-%' OR name LIKE 'at3-clean-%' OR name LIKE 'at4-clean-%') AND deleted_at IS NULL;" \
  || echo "  (cleanup best-effort — non-fatal if it fails)"

echo "== Generating REPORT.md =="
python3 - "$RESULTS_DIR" "$PYTEST_EXIT" <<'PYEOF'
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

results_dir = Path(sys.argv[1])
pytest_exit = int(sys.argv[2])

xml_path = results_dir / "results.xml"
tree = ET.parse(xml_path)
root = tree.getroot()
suite = root if root.tag == "testsuite" else root.find("testsuite")

groups: dict[str, list[dict]] = {"AT0": [], "AT1": [], "AT2": [], "AT3": [], "OTHER": []}

for tc in suite.iter("testcase"):
    classname = tc.get("classname", "")
    name = tc.get("name", "")
    time_s = float(tc.get("time", "0"))
    outcome = "PASS"
    evidence = ""
    failure = tc.find("failure")
    error = tc.find("error")
    skipped = tc.find("skipped")
    if failure is not None:
        outcome = "FAIL"
        evidence = (failure.get("message") or "").splitlines()[0][:160]
    elif error is not None:
        outcome = "ERROR"
        evidence = (error.get("message") or "").splitlines()[0][:160]
    elif skipped is not None:
        msg = skipped.get("message") or skipped.get("type") or ""
        if skipped.get("type") == "pytest.xfail":
            outcome = "XFAIL"
        else:
            outcome = "SKIP"
        evidence = msg.splitlines()[0][:160] if msg else ""

    m = re.search(r"test_(at\d)", classname + name)
    group = f"AT{m.group(1)[2]}" if m else "OTHER"
    groups.setdefault(group, []).append({
        "name": name, "outcome": outcome, "time": time_s, "evidence": evidence,
    })

lines = []
lines.append(f"# Acceptance Run Report — {results_dir.name}\n")
lines.append(f"pytest exit status: **{pytest_exit}**\n")

totals = {"PASS": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0, "XFAIL": 0}
for group in ("AT0", "AT1", "AT2", "AT3", "OTHER"):
    tests = groups.get(group, [])
    if not tests:
        continue
    lines.append(f"\n## {group} — {len(tests)} test(s)\n")
    lines.append("| Test | Outcome | Duration | Evidence |")
    lines.append("|---|---|---|---|")
    for t in tests:
        totals[t["outcome"]] = totals.get(t["outcome"], 0) + 1
        lines.append(f"| {t['name']} | {t['outcome']} | {t['time']:.2f}s | {t['evidence']} |")

lines.append("\n## Totals\n")
lines.append("| Outcome | Count |")
lines.append("|---|---|")
for k in ("PASS", "FAIL", "ERROR", "SKIP", "XFAIL"):
    lines.append(f"| {k} | {totals.get(k, 0)} |")

(results_dir / "REPORT.md").write_text("\n".join(lines) + "\n")
print(f"REPORT.md written: {results_dir / 'REPORT.md'}")
PYEOF

echo "== Done. Results: $RESULTS_DIR =="
exit "$PYTEST_EXIT"
