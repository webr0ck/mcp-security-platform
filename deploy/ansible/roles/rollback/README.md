# rollback

No default task list — always invoked with an explicit `tasks_from`:

- `tasks_from: record` — called by `playbooks/deploy.yml` BEFORE rendering
  the new digest. Reads the digest that is CURRENTLY live straight out of
  the running quadlet unit (not group_vars, so it's accurate even if
  group_vars already changed), and pushes it onto
  `{{ mcphub_rollback_state_dir }}/history.json` (capped at
  `mcphub_rollback_history` entries, oldest dropped).
- `tasks_from: restore` — called either by `playbooks/rollback.yml`
  (operator-invoked) or automatically from `deploy.yml`'s `rescue:` block
  when the post-deploy health/smoke gate fails. Pops the most recent
  history entry, re-renders the `mcphubd` quadlet at that digest (reusing
  the `mcphubd` role's own idempotent tasks), re-runs `health_check`, and
  advances the history pointer so a second rollback goes one generation
  further back rather than looping on the same digest.

## Why "record" reads the live unit instead of trusting group_vars

If a previous run's Vault lookup failed halfway through and left group_vars
out of sync with what's actually running, trusting group_vars for the
rollback point would roll back to the WRONG digest. Reading
`Image=...@sha256:...` out of the actual rendered `.container` file is the
one source of truth for "what is genuinely running right now."
