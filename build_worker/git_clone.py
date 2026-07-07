"""
build-worker's git clone helper — thin re-export of scanner_worker's
implementation.

Both build_worker and scanner_worker are plain Python packages on the same
host image (not installed as separate distributions), and this logic (host
allowlist / SSRF validation / clone URL construction) must stay in exact
lock-step between the two isolated workers — duplicating the whole module a
second time would just create a second place for it to drift. Per the WP-B3
plan (Task 2): "build_worker/git_clone.py can just be `from
scanner_worker.git_clone import *`".
"""
from __future__ import annotations

from scanner_worker.git_clone import *  # noqa: F401,F403
from scanner_worker.git_clone import (  # noqa: F401
    GitHostError,
    ProviderConfig,
    build_clone_url,
    load_providers,
    match_provider,
    provider_token,
    validate_host,
)
