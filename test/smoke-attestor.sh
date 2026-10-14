#!/usr/bin/env bash
# Runs `wg-agent attestor` the way the device Deployment does (root, ALL
# capabilities dropped, read-only root filesystem, read-only /etc/ssh with a
# root-owned 0600 host key) and checks the whole exchange: the attestation it
# writes verifies with `ssh-keygen -Y check-novalidate`, a request from the
# wrong owner is ignored, and signatures are rate limited. Unit tests run as an
# ordinary user and cannot catch capability or permission problems.
set -euo pipefail
IMG=${1:?usage: smoke-attestor.sh <wg-agent image>}
command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required on the host"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required on the host"; exit 1; }
NAME=attestor-smoke-$$
H=$(mktemp -d); chmod 0755 "$H"
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run --rm -v "$H":/h alpine:3.22 rm -rf /h/ssh /h/state /h/exch >/dev/null 2>&1 || true
  rm -rf "$H"
}
trap cleanup EXIT
root() { docker run --rm --user 0:0 -v "$H":/h alpine:3.22 sh -c "$1"; }
agent_uid() { docker run --rm --user 65532:65532 -v "$H":/h alpine:3.22 sh -c "$1"; }

# Host key: root-owned, 0600, like /etc/ssh/ssh_host_ed25519_key on a device.
mkdir -p "$H/ssh" "$H/state" "$H/exch"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$H/ssh/ssh_host_ed25519_key"
root 'chown 0:0 /h/ssh/ssh_host_ed25519_key /h/ssh/ssh_host_ed25519_key.pub && chmod 0600 /h/ssh/ssh_host_ed25519_key && chmod 0755 /h/ssh && chmod 0777 /h/exch'
if agent_uid 'cat /h/ssh/ssh_host_ed25519_key' >/dev/null 2>&1; then
  echo "test setup is wrong: uid 65532 can read the host key"; exit 1
fi
HOSTFP=$(ssh-keygen -lf "$H/ssh/ssh_host_ed25519_key.pub" | awk '{print $2}')

# State directory as the init container leaves it, then the agent (uid 65532)
# creates its identity and identity.pub. It cannot reach a hub, which is fine:
# the files exist before the first request.
root 'mkdir -p /h/state/wg-agent'
docker run --rm --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --security-opt no-new-privileges \
  -v "$H/state":/var/lib/teknoir "$IMG" init --dir /var/lib/teknoir/wg-agent --uid 65532
out=$(timeout 8 docker run --rm --user 65532:65532 --cap-drop ALL --read-only \
  -v "$H/state/wg-agent":/var/lib/teknoir/wg-agent -v "$H/exch":/run/wg-attest \
  -e DEVICE_ID=smoke -e NAMESPACE=smoke -e DOMAIN=example.invalid -e ATTEST_EXCHANGE=/run/wg-attest \
  "$IMG" run 2>&1 || true)
grep -q '"msg":"device identity"' <<<"$out" || { echo "$out"; echo "agent did not create its identity"; exit 1; }
[[ $(root 'stat -c "%a" /h/state/wg-agent') == 711 ]] || { echo "state dir is not 0711"; exit 1; }
[[ $(root 'stat -c "%a %u" /h/state/wg-agent/identity.pub') == "644 65532" ]] || { echo "identity.pub is not 0644 owned by 65532"; exit 1; }
[[ $(root 'stat -c "%a" /h/state/wg-agent/identity.key') == 600 ]] || { echo "identity.key is not 0600"; exit 1; }
IDPUB=$(root 'cat /h/state/wg-agent/identity.pub' | tr -d '\n')
IDFP="SHA256:$(printf '%s' "$IDPUB" | base64 -d | openssl dgst -sha256 -binary | base64 | tr -d '=\n')"

docker run -d --name "$NAME" --user 0:0 --cap-drop ALL --read-only --security-opt no-new-privileges \
  -v "$H/ssh":/etc/ssh:ro -v "$H/state/wg-agent":/var/lib/teknoir/wg-agent:ro -v "$H/exch":/run/wg-attest \
  -e NAMESPACE=smoke -e DEVICE_ID=smoke "$IMG" attestor >/dev/null
trap 'docker logs "$NAME" 2>&1 | tail -20; cleanup' ERR

put() { # put <owner uid> <nonce>
  docker run --rm --user "$1:$1" -v "$H":/h alpine:3.22 sh -c \
    "printf '{\"nonce\":\"%s\",\"epoch\":\"epoch-A\",\"generation\":3}' '$2' > /h/exch/request.json.tmp && mv /h/exch/request.json.tmp /h/exch/request.json && chmod 0644 /h/exch/request.json"
}
wait_response() { # wait_response <nonce> <seconds>
  for _ in $(seq 1 "$2"); do
    if [[ -r "$H/exch/response.json" ]] && python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("nonce")==sys.argv[2] else 1)' "$H/exch/response.json" "$1"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# 1. A request owned by root (not the agent user) is ignored.
put 0 nonce-bad
sleep 3
[[ ! -e "$H/exch/response.json" ]] || { echo "the attestor answered a request not owned by uid 65532"; exit 1; }
root 'rm -f /h/exch/request.json'

# 2. A request by the agent user is answered with a verifiable attestation.
put 65532 nonce-one
wait_response nonce-one 15 || { echo "no response"; exit 1; }
SIG=$(mktemp); STMT=$(mktemp)
printf 'teknoir-ztna-attest-v1\nsmoke/smoke\n%s\nepoch-A\n3\nnonce-one' "$IDFP" > "$STMT"
python3 -I - "$H/exch/response.json" "$HOSTFP" > "$SIG" <<'PY'
import base64, json, sys, textwrap
r = json.load(open(sys.argv[1]))
assert r.get("error") is None, r
assert r["hostKeyFingerprint"] == sys.argv[2], (r["hostKeyFingerprint"], sys.argv[2])
assert r["hostKeyType"] == "ssh-ed25519"
a = r["attestations"]; assert len(a) == 1 and a[0]["nonce"] == "nonce-one"
b64 = a[0]["signature"]
print("-----BEGIN SSH SIGNATURE-----"); print("\n".join(textwrap.wrap(b64, 70))); print("-----END SSH SIGNATURE-----")
PY
ssh-keygen -Y check-novalidate -n teknoir-ztna-attest-v1@teknoir.ai -s "$SIG" < "$STMT" >/dev/null \
  || { echo "ssh-keygen rejects the attestation"; exit 1; }
if ssh-keygen -Y check-novalidate -n teknoir-ztna-attest-v1@teknoir.ai -s "$SIG" < <(printf 'other') >/dev/null 2>&1; then
  echo "ssh-keygen accepted a different statement"; exit 1
fi
[[ $(root 'stat -c "%a %u" /h/exch/response.json') == "644 0" ]] || { echo "response.json is not 0644 root"; exit 1; }
rm -f "$SIG" "$STMT"

# 3. One signature per 10 seconds: an immediate second request waits.
put 65532 nonce-two
if wait_response nonce-two 5; then echo "the attestor signed twice within 5 s"; exit 1; fi
wait_response nonce-two 15 || { echo "rate limited request was never answered"; exit 1; }

# 4. The container logs never contain key material.
if docker logs "$NAME" 2>&1 | grep -q -e 'PRIVATE KEY' -e "$IDPUB"; then echo "attestor logged key material"; exit 1; fi
docker logs "$NAME" 2>&1 | grep -q 'host key attestation signed' || { echo "no log line for the signature"; exit 1; }
[[ $(docker inspect -f '{{.State.Running}}' "$NAME") == true ]] || { echo "attestor exited"; exit 1; }
echo "attestor smoke test passed"
