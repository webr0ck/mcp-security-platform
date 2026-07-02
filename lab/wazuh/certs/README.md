# Wazuh lab certificates

These are **self-signed demo certificates** for the optional Wazuh SIEM lab
overlay (`compose.wazuh.yml`). They are **not committed** — private keys never
belong in the repo. Generate them once before bringing the overlay up:

```bash
./scripts/gen-wazuh-certs.sh        # writes root-ca / indexer / manager / dashboard / admin certs here
podman compose -f podman-compose.lab.yml -f compose.wazuh.yml up -d
```

The generator runs Wazuh's official `wazuh-certs-tool.sh` against
[`config.yml`](config.yml) (the node manifest, which *is* committed). Everything
else in this directory is git-ignored. For a real deployment, generate your own
certificates — do not reuse demo material.
