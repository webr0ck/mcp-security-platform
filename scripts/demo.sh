#!/usr/bin/env bash
# demo.sh — a 60-second, no-full-stack demo of the platform's headline verifiable control.
#
# The thesis of this project is "mediate every call; isolate the backends." This demo proves the
# isolation half *statically* (no daemon, no containers running) by resolving the compose topology
# and asserting that backend MCP servers and the proxy cannot reach each other except on the exact
# pairwise networks they're supposed to.
#
# Run it:   bash scripts/demo.sh        (or: make demo)
# Record it: see docs/demo/README.md (vhs tape provided).
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"

cyan='\033[0;36m'; green='\033[0;32m'; dim='\033[0;90m'; bold='\033[1m'; reset='\033[0m'

echo -e "${bold}${cyan}MCP Security Platform — verifiable network isolation${reset}"
echo -e "${dim}# Static proof that MCP servers can't reach the proxy or each other.${reset}"
echo -e "${dim}# No daemon required — the compose topology is resolved and asserted.${reset}"
echo
echo -e "${cyan}\$ python3 scripts/check_network_isolation.py${reset}"
echo
python3 scripts/check_network_isolation.py 2>&1 | grep -vE '^INFO  Injecting gate-stub'
echo
echo -e "${green}${bold}✓ Backends are isolated by construction — regression-gated in 'make security-check'.${reset}"
echo -e "${dim}# Next: bring up the full lab (make -f Makefile.lab lab-up) and connect Claude Code${reset}"
echo -e "${dim}#       with zero API keys in config — see README 'Connecting Claude Code'.${reset}"
