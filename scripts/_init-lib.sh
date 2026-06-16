#!/usr/bin/env bash
# _init-lib.sh — shared helpers for the tiered first-run bootstrap scripts.
#
# Sourced (not executed) by init-engine.sh / init-standard.sh / init-poc.sh to
# avoid three copies of the same secret-generation + env-upsert logic (a bug in
# the generator previously had to be fixed in three places). lab-init.sh is
# intentionally NOT a consumer: it generates a full self-contained .env.lab via
# openssl + heredoc and has different idempotency semantics (--force).
#
# A sourcing script may set these before `source`-ing this file:
#   _INIT_TAG   log prefix, e.g. "init-standard"   (default: "init")
#   ENV_FILE    target env file to upsert into      (default: ".env")

_INIT_TAG="${_INIT_TAG:-init}"
ENV_FILE="${ENV_FILE:-.env}"

# _gen20 — print a 20-char strong password from /dev/urandom.
# Fail-closed: returns non-zero (never a short/empty secret) if urandom is unusable.
_gen20() {
  local p
  p=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#%^&*_+=' </dev/urandom 2>/dev/null | head -c20 || true)
  if [[ ${#p} -lt 20 ]]; then
    echo "[${_INIT_TAG}] ERROR: /dev/urandom unavailable — cannot generate secure passwords" >&2
    return 1
  fi
  printf '%s' "$p"
}

# _gen64 — print a 64-char hex secret from /dev/urandom (fail-closed).
_gen64() {
  local p
  p=$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom 2>/dev/null | head -c64 || true)
  if [[ ${#p} -lt 64 ]]; then
    echo "[${_INIT_TAG}] ERROR: /dev/urandom unavailable — cannot generate secure secrets" >&2
    return 1
  fi
  printf '%s' "$p"
}

# _ensure_var NAME VALUE — append NAME=VALUE to ENV_FILE only if not already set.
# Idempotent: re-runs never overwrite an existing value.
_ensure_var() {
  local var="$1" val="$2"
  if grep -qE "^${var}=.+" "$ENV_FILE" 2>/dev/null; then
    echo "[${_INIT_TAG}] $var already set — skipping."
  else
    echo "${var}=${val}" >> "$ENV_FILE"
    echo "[${_INIT_TAG}] $var generated."
  fi
}
