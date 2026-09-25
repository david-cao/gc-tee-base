#!/usr/bin/env bash
# Build the gc-tee-base measured Confidential VM image on a throwaway GCE
# builder VM (mkosi needs Linux), create the GCE image, and emit
# expected-measurements-<image>.json for the verifier.
#
# Usage:
#   deploy/build-image.sh [-p PROFILE] [-z ZONE] [-b BUCKET] [-n IMAGE_NAME] [-k]
#     -p  mkosi profile: dev | prod        (default: prod)
#     -z  GCE zone                         (default: us-central1-a)
#     -b  GCS bucket for the disk tarball  (default: <project>-gc-tee-images)
#     -n  GCE image name                   (default: gc-tee-base-<profile>-<timestamp>)
#     -k  keep the builder VM on exit (debugging)
#
# Requires: gcloud (authenticated), go. Runs from the repo root.
set -euo pipefail

PROFILE=prod
ZONE=us-central1-a
BUCKET=""
IMAGE_NAME=""
KEEP_BUILDER=0
# mkosi is not on PyPI; it installs from the systemd GitHub repo by tag.
MKOSI_VERSION="${MKOSI_VERSION:-v26}"

while getopts "p:z:b:n:k" opt; do
  case "$opt" in
    p) PROFILE="$OPTARG" ;;
    z) ZONE="$OPTARG" ;;
    b) BUCKET="$OPTARG" ;;
    n) IMAGE_NAME="$OPTARG" ;;
    k) KEEP_BUILDER=1 ;;
    *) exit 2 ;;
  esac
done

case "$PROFILE" in dev|prod) ;; *) echo "profile must be dev or prod" >&2; exit 2 ;; esac

cd "$(dirname "$0")/.."
PROJECT=$(gcloud config get-value project 2>/dev/null)
[ -n "$PROJECT" ] || { echo "no gcloud project configured" >&2; exit 1; }
BUCKET=${BUCKET:-${PROJECT}-gc-tee-images}
IMAGE_NAME=${IMAGE_NAME:-gc-tee-base-${PROFILE}-$(date +%Y%m%d-%H%M%S)}
BUILDER="gc-tee-builder-$$"
ARTIFACTS="build-artifacts/${IMAGE_NAME}"

cleanup() {
  if [ "$KEEP_BUILDER" = 0 ]; then
    echo ">>> deleting builder VM ${BUILDER}"
    gcloud compute instances delete "$BUILDER" --zone "$ZONE" --quiet 2>/dev/null || true
  else
    echo ">>> keeping builder VM ${BUILDER} (delete with: gcloud compute instances delete $BUILDER --zone $ZONE)"
  fi
}
trap cleanup EXIT

echo ">>> cross-compiling launcher (linux/amd64, CGO-free)"
mkdir -p image/mkosi.extra/usr/bin
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o image/mkosi.extra/usr/bin/gc-tee-launcher ./cmd/launcher

echo ">>> ensuring GCS bucket gs://${BUCKET}"
gcloud storage buckets describe "gs://${BUCKET}" >/dev/null 2>&1 ||
  gcloud storage buckets create "gs://${BUCKET}" --location=US

echo ">>> creating builder VM ${BUILDER}"
gcloud compute instances create "$BUILDER" \
  --zone "$ZONE" \
  --machine-type e2-standard-4 \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 50GB \
  --scopes storage-rw

echo ">>> waiting for SSH"
for i in $(seq 1 30); do
  if gcloud compute ssh "$BUILDER" --zone "$ZONE" --command=true 2>/dev/null; then break; fi
  [ "$i" = 30 ] && { echo "builder never became reachable" >&2; exit 1; }
  sleep 5
done

echo ">>> copying image tree to builder"
gcloud compute scp --recurse --zone "$ZONE" image "$BUILDER":~/image

echo ">>> building image on builder (mkosi ${MKOSI_VERSION}, profile ${PROFILE})"
gcloud compute ssh "$BUILDER" --zone "$ZONE" --command "
  set -euo pipefail
  sudo apt-get update -q
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -qy \
    pipx python3 git debian-archive-keyring ubuntu-keyring \
    systemd-ukify systemd-boot-efi systemd-repart \
    erofs-utils dosfstools mtools cryptsetup-bin bubblewrap
  pipx install git+https://github.com/systemd/mkosi.git@${MKOSI_VERSION}
  cd ~/image
  sudo ~/.local/bin/mkosi --profile ${PROFILE} build
  ls -la
  # Package the disk for GCE: sparse tar named disk.raw, oldgnu format.
  RAW=\$(ls *.raw | head -1)
  sudo cp --sparse=always \"\$RAW\" disk.raw
  sudo tar --format=oldgnu -Sczf image.tar.gz disk.raw
  # Upload via the metadata-token GCS JSON API (no gcloud needed on builder).
  TOKEN=\$(curl -s -H 'Metadata-Flavor: Google' \
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"access_token\"])')
  curl -sf -X POST --data-binary @image.tar.gz \
    -H \"Authorization: Bearer \$TOKEN\" -H 'Content-Type: application/octet-stream' \
    'https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${IMAGE_NAME}.tar.gz' \
    > /dev/null
  echo 'upload done'
"

echo ">>> fetching split artifacts (UKI, roothash)"
mkdir -p "$ARTIFACTS"
gcloud compute scp --zone "$ZONE" \
  "$BUILDER:~/image/*.efi" "$BUILDER:~/image/*.roothash" "$ARTIFACTS/"

echo ">>> creating GCE image ${IMAGE_NAME}"
gcloud compute images create "$IMAGE_NAME" \
  --source-uri "gs://${BUCKET}/${IMAGE_NAME}.tar.gz" \
  --architecture=X86_64 \
  --guest-os-features=UEFI_COMPATIBLE,SEV_CAPABLE,SEV_SNP_CAPABLE,TDX_CAPABLE,GVNIC,VIRTIO_SCSI_MULTIQUEUE

echo ">>> predicting expected measurements"
UKI=$(ls "$ARTIFACTS"/*.efi | head -1)
ROOTHASH=""
[ -f "$ARTIFACTS"/*.roothash ] && ROOTHASH=$(cat "$ARTIFACTS"/*.roothash)
go run ./cmd/predict-measurements \
  -uki "$UKI" \
  -image "$IMAGE_NAME" \
  -roothash "$ROOTHASH" \
  -out "$ARTIFACTS/expected-measurements.json"

echo
echo "=== done ==="
echo "image:                 $IMAGE_NAME"
echo "expected measurements: $ARTIFACTS/expected-measurements.json"
echo "next: deploy/create-instance.sh -i $IMAGE_NAME -w <workload@sha256:...>"
