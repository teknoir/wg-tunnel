#!/usr/bin/env bash
# Plane B under the device container's real restrictions, on the throwaway k3d
# cluster: two pods in a scratch namespace run test/p2pprobe as uid 65532 with
# ALL capabilities dropped, a read-only root filesystem, no privilege escalation
# and the runtime-default seccomp profile (what the wg-agent Deployment has),
# punch a direct WireGuard path to each other over the pod network and echo a
# message over it. It proves that the plane-B socket, the interface listing and
# the netstack need no privileges. Usage:
#
#   test/smoke-p2p-k3d.sh            (context k3d-teknoir-dev, cluster teknoir-dev)
#
# The namespace and the image are removed at the end.
set -euo pipefail
CTX=${KUBE_CONTEXT:-k3d-teknoir-dev}
CLUSTER=${K3D_CLUSTER:-teknoir-dev}
NS=wgt-p2p-smoke
IMG=wgt-p2pprobe:smoke
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=$(sed -n 's/^ARG BASE_IMAGE=//p' "$ROOT/Dockerfile")
K="kubectl --context $CTX"
[[ $CTX == k3d-* ]] || { echo "refusing to run against $CTX: only a k3d context"; exit 1; }

W=$(mktemp -d)
cleanup() {
  $K delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  docker rmi "$IMG" >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT

(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$W/p2pprobe" ./test/p2pprobe)
cat >"$W/Dockerfile" <<DOCKER
FROM $BASE
COPY p2pprobe /usr/local/bin/p2pprobe
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/p2pprobe"]
DOCKER
docker build -q -t "$IMG" "$W" >/dev/null
k3d image import -c "$CLUSTER" "$IMG" >/dev/null

read -r PRIV_A PUB_A < <("$W/p2pprobe" keygen)
read -r PRIV_B PUB_B < <("$W/p2pprobe" keygen)

$K create namespace "$NS" >/dev/null
pod() { # pod <name> <role> <priv> <peer name> <peer pub> <self addr> <peer addr>
  cat <<YAML
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: $NS, labels: {app: p2pprobe}}
spec:
  hostname: $1
  subdomain: p2pprobe
  restartPolicy: Never
  securityContext:
    runAsUser: 65532
    runAsGroup: 65532
    runAsNonRoot: true
    seccompProfile: {type: RuntimeDefault}
  containers:
  - name: probe
    image: $IMG
    imagePullPolicy: Never
    args: ["-role=$2", "-self-priv=$3", "-peer=$4.p2pprobe.$NS.svc.cluster.local", "-peer-pub=$5", "-self-addr=$6", "-peer-addr=$7", "-wait=60s"]
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: {drop: [ALL]}
YAML
}
$K apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Service
metadata: {name: p2pprobe, namespace: $NS}
spec:
  clusterIP: None
  publishNotReadyAddresses: true
  selector: {app: p2pprobe}
  ports: [{name: x, port: 1}]
YAML
pod b b "$PRIV_B" a "$PUB_A" 100.97.0.20 100.97.0.10 | $K apply -f - >/dev/null
pod a a "$PRIV_A" b "$PUB_B" 100.97.0.10 100.97.0.20 | $K apply -f - >/dev/null

fail=0
for p in a b; do
  for _ in $(seq 1 90); do
    phase=$($K -n "$NS" get pod "$p" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [[ $phase == Succeeded || $phase == Failed ]] && break
    sleep 1
  done
  echo "--- pod $p ($phase)"
  $K -n "$NS" logs "$p" || true
  [[ $phase == Succeeded ]] || fail=1
done
$K -n "$NS" logs a | grep -q 'RESULT: ok path=direct-lan' || { echo "pod a did not report a direct-lan echo"; fail=1; }
[[ $fail == 0 ]] && echo "plane B smoke test passed under the device securityContext" || { echo "plane B smoke test FAILED"; exit 1; }
