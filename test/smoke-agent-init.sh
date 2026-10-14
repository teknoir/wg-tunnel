#!/usr/bin/env bash
# Runs `wg-agent init` the way the device Deployment does (root, only CHOWN and
# FOWNER, no-new-privileges) twice against a fresh 0755 host directory, then
# starts the agent as 65532 with a read-only root filesystem. Unit tests run as
# a fully privileged root and cannot catch capability problems.
set -euo pipefail
IMG=${1:?usage: smoke-agent-init.sh <wg-agent image>}
H=$(mktemp -d); trap 'docker run --rm -v "$H":/h alpine:3.22 rm -rf /h/wg-agent >/dev/null 2>&1 || true; rm -rf "$H"' EXIT
chmod 0755 "$H"
# Like the kubelet for a DirectoryOrCreate hostPath: root-owned 0755, created
# before the init container runs.
docker run --rm -v "$H":/h alpine:3.22 sh -c 'mkdir -p /h/wg-agent && chmod 0755 /h/wg-agent'
for _ in 1 2; do
  docker run --rm --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges -v "$H":/var/lib/teknoir "$IMG" \
    init --dir /var/lib/teknoir/wg-agent --uid 65532
done
[[ $(stat -c '%u:%g %a' "$H/wg-agent") == "65532:65532 711" ]] || { stat "$H/wg-agent"; echo "bad state dir"; exit 1; }
out=$(timeout 8 docker run --rm --user 65532:65532 --cap-drop ALL --read-only \
  -v "$H/wg-agent":/var/lib/teknoir/wg-agent -e DEVICE_ID=smoke -e NAMESPACE=smoke \
  -e DOMAIN=example.invalid "$IMG" run 2>&1 || true)
grep -q '"msg":"device identity"' <<<"$out" || { echo "$out"; echo "agent did not create its identity"; exit 1; }
fp1=$(grep -o '"fingerprint":"[^"]*"' <<<"$out" | head -1)

# Upgrade from a phase-1 agent: the state dir is 0700 (owned by 65532) with an
# existing identity. Root without DAC capabilities cannot open it; init must
# still bring it to 0711 and the agent must keep the same identity.
docker run --rm -v "$H":/h alpine:3.22 chmod 0700 /h/wg-agent
docker run --rm --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER \
  --security-opt no-new-privileges -v "$H":/var/lib/teknoir "$IMG" \
  init --dir /var/lib/teknoir/wg-agent --uid 65532
[[ $(stat -c '%u:%g %a' "$H/wg-agent") == "65532:65532 711" ]] || { stat "$H/wg-agent"; echo "phase-1 state dir not upgraded"; exit 1; }
out=$(timeout 8 docker run --rm --user 65532:65532 --cap-drop ALL --read-only \
  -v "$H/wg-agent":/var/lib/teknoir/wg-agent -e DEVICE_ID=smoke -e NAMESPACE=smoke \
  -e DOMAIN=example.invalid "$IMG" run 2>&1 || true)
fp2=$(grep -o '"fingerprint":"[^"]*"' <<<"$out" | head -1)
[[ -n "$fp1" && "$fp1" == "$fp2" ]] || { echo "$out"; echo "identity changed across the upgrade ($fp1 vs $fp2)"; exit 1; }
echo "agent init smoke test passed"
