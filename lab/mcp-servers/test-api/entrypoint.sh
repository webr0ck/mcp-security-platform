#!/bin/sh
set -e
# Start the underlying policy API (read :9191, read+write :9292) in the
# background on loopback, then exec the MCP wrapper in the foreground so
# podman's signal handling / restart policy applies to the real long-lived
# process.
python3 /app/policy_api_server.py --host 127.0.0.1 --read-port 9191 --rw-port 9292 --bearer-token "${POLICY_BEARER_TOKEN:-security-token}" &
sleep 1
exec python3 /app/server.py
