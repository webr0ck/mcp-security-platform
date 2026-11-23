#!/usr/bin/env bash
# Build and pull every image the Dark Factory tier runs, on vm-dev (the lab's
# build host, which has the egress proxy), and write them to one archive plus
# a digest lock. vm-mcp loads the archive and pulls nothing: what was staged
# is exactly what runs, and the squid allowlist needs no registry for it.
#
#   HTTPS_PROXY=http://10.77.30.10:3128 bash stage-images.sh /path/images.tar
set -euo pipefail
OUT=${1:?usage: stage-images.sh <archive.tar>}
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE/../.."

podman build -t localhost/mcphub-sdk:base -f sdk/mcphub-sdk/Dockerfile.base sdk/mcphub-sdk
podman build -t localhost/mcp-echo:df lab/mcp-servers/echo
podman build -t localhost/mcp-security-proxy:df -f proxy/Dockerfile --target production .

mapfile -t IMAGES < <(python3 -c '
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
print("\n".join(sorted({s["image"] for s in d["services"].values()})))' "$HERE/compose.yml")
for img in "${IMAGES[@]}"; do
    [[ $img == localhost/* ]] || podman pull -q "$img" >/dev/null
done

rm -f "$OUT"   # docker-archive cannot be appended to
podman save --multi-image-archive -o "$OUT" "${IMAGES[@]}"
for img in "${IMAGES[@]}"; do
    printf '%s %s\n' "$img" "$(podman image inspect --format '{{.Id}}' "$img")"
done > "$OUT.lock"
echo "staged ${#IMAGES[@]} images -> $OUT ($(du -h "$OUT" | cut -f1)), lock $OUT.lock"
