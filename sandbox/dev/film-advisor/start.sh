#!/bin/bash
# start.sh — launch both the Film Advisor REST API and the MCP server
set -euo pipefail

echo "[film-advisor] Starting REST API on :8080 and MCP server on :8081"

# Start the film advisor REST API in the background
python /workspace/app.py &
API_PID=$!
echo "[film-advisor] REST API PID: ${API_PID}"

# Wait for the API to be ready (up to 10s)
for i in $(seq 1 20); do
    if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
        echo "[film-advisor] REST API ready"
        break
    fi
    sleep 0.5
done

# Start the MCP server (foreground so the container stays alive)
echo "[film-advisor] Starting MCP server on :8081"
python /workspace/mcp_server.py
