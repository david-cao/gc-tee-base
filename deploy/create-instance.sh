#!/usr/bin/env bash
# Launch an attestable workload on a Confidential VM built from a gc-tee-base
# measured image. One command: the VM boots the measured launcher, which reads
# the workload from instance metadata, measures it into PCR 13, and serves
# attestation evidence on :8080.
#
# Usage:
#   deploy/create-instance.sh -i IMAGE -w WORKLOAD [options]
#     -i  GCE image name (from build-image.sh)              (required)
#     -w  workload image ref, pinned by digest               (required)
#         e.g. docker.io/library/busybox@sha256:...
#     -n  instance name                (default: gc-tee-<timestamp>)
#     -z  zone                         (default: us-central1-a)
#     -t  SEV_SNP | SEV | TDX          (default: SEV_SNP)
#     -c  workload cmd override, JSON array: '["sh","-c","..."]'
#     -e  env var override K=V (repeatable)
#     -r  restart policy: Always | OnFailure | Never
#
# Evidence port: open tcp:8080 to your verifier, e.g.
#   gcloud compute firewall-rules create allow-attestation --allow tcp:8080
set -euo pipefail

IMAGE="" WORKLOAD="" NAME="" ZONE=us-central1-a TECH=SEV_SNP CMD="" RESTART=""
ENVS=()

while getopts "i:w:n:z:t:c:e:r:" opt; do
  case "$opt" in
    i) IMAGE="$OPTARG" ;;
    w) WORKLOAD="$OPTARG" ;;
    n) NAME="$OPTARG" ;;
    z) ZONE="$OPTARG" ;;
    t) TECH="$OPTARG" ;;
    c) CMD="$OPTARG" ;;
    e) ENVS+=("$OPTARG") ;;
    r) RESTART="$OPTARG" ;;
    *) exit 2 ;;
  esac
done
[ -n "$IMAGE" ] && [ -n "$WORKLOAD" ] || { grep '^#' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
NAME=${NAME:-gc-tee-$(date +%Y%m%d-%H%M%S)}

case "$TECH" in
  SEV|SEV_SNP) MACHINE_TYPE=n2d-standard-2 ;;
  TDX)         MACHINE_TYPE=c3-standard-4 ;;
  *) echo "unknown confidential compute type $TECH" >&2; exit 2 ;;
esac

# Metadata values may contain commas (cmd JSON), so use gcloud's custom
# delimiter syntax: ^~^ makes '~' the list separator.
METADATA="^~^tee-image-reference=${WORKLOAD}"
[ -n "$CMD" ] && METADATA="${METADATA}~tee-cmd=${CMD}"
[ -n "$RESTART" ] && METADATA="${METADATA}~tee-restart-policy=${RESTART}"
for kv in ${ENVS[@]+"${ENVS[@]}"}; do
  METADATA="${METADATA}~tee-env-${kv%%=*}=${kv#*=}"
done

echo ">>> creating ${TECH} instance ${NAME} from image ${IMAGE}"
gcloud compute instances create "$NAME" \
  --zone "$ZONE" \
  --machine-type "$MACHINE_TYPE" \
  --confidential-compute-type="$TECH" \
  --maintenance-policy=TERMINATE \
  --image "$IMAGE" \
  --shielded-vtpm \
  --shielded-integrity-monitoring \
  --no-shielded-secure-boot \
  --nic-type=GVNIC \
  --metadata "$METADATA"

IP=$(gcloud compute instances describe "$NAME" --zone "$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo
echo "=== instance up ==="
echo "name: $NAME   ip: $IP"
echo "serial console: gcloud compute instances get-serial-port-output $NAME --zone $ZONE"
echo "verify:         go run ./cmd/verifier verify -host ${IP}:8080 \\"
echo "                  -policy policy.yaml -expected build-artifacts/${IMAGE}/expected-measurements.json"
