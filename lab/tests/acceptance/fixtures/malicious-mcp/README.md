# malicious-mcp

AT3 "malicious onboarding" fixture. `server.py` plants a distinctive marker
string that a `scan-config.yaml` custom rule (added for this test suite —
see `acceptance_test_planted_marker` in that file) matches with `block: true`.
This makes the submission scanner deterministically block this repo without
needing a live/verifiable third-party secret.

Used by `lab/tests/acceptance/test_at3_onboarding.py` to prove: scan_status
ends up `blocked`, submission_status becomes `scan_blocked`, the reviewer's
approve is refused (409), and no tool from it is ever invocable.
