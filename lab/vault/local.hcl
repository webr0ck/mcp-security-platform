# Lab Vault — PERSISTENT file-storage config (replaces the old in-memory `-dev` mode).
#
# Why this exists: dev-mode Vault keeps everything in memory, so a Vault restart
# wiped the broker master secret (KEK) and every credential injection failed until
# a manual re-seed. With file storage the encrypted barrier (incl. the KEK) persists
# on the `vault-data` volume across restarts. The KEK therefore lives ONLY inside
# Vault's AES-GCM-encrypted storage — never in a plaintext file on disk — which is
# the whole point of keeping the KMS boundary intact (a credential_store DB dump
# alone stays useless).
#
# Plain HTTP + disable_mlock are deliberate LAB choices: the listener is internal to
# the vault-net podman network, and disable_mlock avoids the rootless-Podman setcap
# crashloop (CAP_SETFCAP is unavailable in rootless user namespaces). Production must
# use TLS + a real auto-unseal seal (cloud KMS / transit / HSM) instead of the
# lab auto-unseal sidecar.

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

disable_mlock = true
ui            = false
