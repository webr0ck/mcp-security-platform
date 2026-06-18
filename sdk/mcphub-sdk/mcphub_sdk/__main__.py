"""
Entry point for  python -m mcphub_sdk.scaffold

Delegates to scaffold.main() so the CLI works with:
    python -m mcphub_sdk.scaffold <name> [--service-name S] [--port P]

This module is intentionally thin — all logic lives in scaffold.py.
"""
from mcphub_sdk.scaffold import main

main()
