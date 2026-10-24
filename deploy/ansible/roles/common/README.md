# common

Base layer every other role depends on: installs podman, creates the
`mcphub` system account (no login shell, uid/gid fixed at 6420 so it's
stable across hosts for volume ownership), scaffolds `/etc/containers/systemd`
(the podman quadlet unit directory) and `/etc/mcphub`, `/var/lib/mcphub`,
`/var/log/mcphub`, and applies connection/fd sysctl tuning sized for the
20k req/s performance budget in `rs/ARCHITECTURE.md`.

Deliberately disables `podman-auto-update.timer` — this platform deploys by
pinned digest with an explicit, health-gated `deploy.yml` / `rollback.yml`,
never a silent background image pull.

## Variables

See `defaults/main.yml`. `mcphub_apply_sysctl_tuning: false` skips the
sysctl block (useful on a shared host where you don't own kernel tuning).

## Idempotence

All tasks use state-diffing modules (`apt`/`dnf`, `user`, `group`, `file`,
`systemd`, `ansible.posix.sysctl`) — no `command`/`shell` steps. A second run
reports `changed=0`.
