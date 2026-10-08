#!/usr/bin/env bash
# Boot a fresh gc-tee-base Confidential VM in provisioning mode. The VM
# carries NO workload configuration: the measured launcher generates a
# per-boot encryption key, serves attestation evidence on :8080, and waits.
# Deliver the workload with:
#
#   go run ./cmd/verifier provision -host <IP>:8080 \
#     -policy policy.yaml -payload payload.yaml \
#     -expected build-artifacts/<IMAGE>/expected-measurements.json
#
# Usage:
#   deploy/create-instance.sh -i IMAGE [options]
#     -i  GCE image name (from build-image.sh)              (required)
#     -n  instance name                (default: gc-tee-<timestamp>)
#     -z  zone                         (default: us-central1-a)
#     -t  TDX | SEV_SNP | SEV          (default: TDX)
#
# Evidence port: open tcp:8080 to your verifier, e.g.
#   gcloud compute firewall-rules create allow-attestation --allow tcp:8080
set -euo pipefail

IMAGE="" NAME="" ZONE=us-central1-a TECH=TDX

while getopts "i:n:z:t:" opt; do
  case "$opt" in
    i) IMAGE="$OPTARG" ;;
    n) NAME="$OPTARG" ;;
    z) ZONE="$OPTARG" ;;
    t) TECH="$OPTARG" ;;
    *) exit 2 ;;
  esac
done
[ -n "$IMAGE" ] || { grep '^#' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
NAME=${NAME:-gc-tee-$(date +%Y%m%d-%H%M%S)}

case "$TECH" in
  SEV|SEV_SNP) MACHINE_TYPE=n2d-standard-2 ;;
  TDX)         MACHINE_TYPE=c3-standard-4 ;;
  *) echo "unknown confidential compute type $TECH" >&2; exit 2 ;;
esac

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
  --network-interface=nic-type=GVNIC

IP=$(gcloud compute instances describe "$NAME" --zone "$ZONE" \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo
echo "=== instance up (provisioning mode) ==="
echo "name: $NAME   ip: $IP"
echo "serial console: gcloud compute instances get-serial-port-output $NAME --zone $ZONE"
echo "provision:      go run ./cmd/verifier provision -host ${IP}:8080 \\"
echo "                  -policy policy.yaml -payload payload.yaml \\"
echo "                  -expected build-artifacts/${IMAGE}/expected-measurements.json"
