"""Mint fresh grafana/gitea service tokens (Step A of the USR-04 re-provision).

Context: an acceptance-test run (USR-04) found grafana-query/gitea-repos service
credentials failing "not provisioned". Root cause was master-secret drift: the
stored credential_store blobs were encrypted under a master the proxy no longer
loads (the broker correctly fail-closes on an undecryptable blob — NOT a code bug).

Minting must happen here (this container is on lab-net and can reach
lab-grafana/lab-gitea), but the authoritative broker master lives with the proxy.
So this script ONLY mints fresh tokens and prints them as TOKEN:<service>:<value>
lines; the proxy then encrypts+upserts them under its own master (Step B).

Run in a one-off container from the lab-seeder image (same networks + env_file).
"""
import asyncio
import logging

import seed

logging.basicConfig(level=logging.WARNING)


async def main() -> None:
    for service_name, minter in [("grafana", seed.create_grafana_token),
                                 ("gitea", seed.create_gitea_token)]:
        token = await minter()
        if token:
            print(f"TOKEN:{service_name}:{token}", flush=True)
        else:
            print(f"TOKEN:{service_name}:FAILED", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
