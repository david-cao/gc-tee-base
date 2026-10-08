#!/usr/bin/env bash
# Build the gc-tee-base measured Confidential VM image (NixOS, reproducible
# from flake.lock) on a throwaway GCE builder VM, create the GCE image, and
# emit expected-measurements.json for the verifier.
#
# Usage:
#   deploy/build-image.sh [-p PROFILE] [-z ZONE] [-b BUCKET] [-n IMAGE_NAME] [-k]
#     -p  variant: dev | prod              (default: prod)
#     -z  GCE zone                         (default: us-central1-a)
#     -b  GCS bucket for the disk tarball  (default: <project>-gc-tee-images)
#     -n  GCE image name                   (default: gc-tee-base-<profile>-<timestamp>)
#     -k  keep the builder VM on exit (debugging)
#     -B  reuse an existing builder VM by name (implies -k; skips creation)
#
# Requires: gcloud (authenticated), go, python3. Runs from the repo root.
set -euo pipefail

PROFILE=prod
ZONE=us-central1-a
BUCKET=""
IMAGE_NAME=""
KEEP_BUILDER=0
REUSE_BUILDER=""

while getopts "p:z:b:n:kB:" opt; do
  case "$opt" in
    p) PROFILE="$OPTARG" ;;
    z) ZONE="$OPTARG" ;;
    b) BUCKET="$OPTARG" ;;
    n) IMAGE_NAME="$OPTARG" ;;
    k) KEEP_BUILDER=1 ;;
    B) REUSE_BUILDER="$OPTARG"; KEEP_BUILDER=1 ;;
    *) exit 2 ;;
  esac
done

case "$PROFILE" in dev|prod) ;; *) echo "profile must be dev or prod" >&2; exit 2 ;; esac

cd "$(dirname "$0")/.."
PROJECT=$(gcloud config get-value project 2>/dev/null)
[ -n "$PROJECT" ] || { echo "no gcloud project configured" >&2; exit 1; }
BUCKET=${BUCKET:-${PROJECT}-gc-tee-images}
IMAGE_NAME=${IMAGE_NAME:-gc-tee-base-${PROFILE}-$(date +%Y%m%d-%H%M%S)}
BUILDER=${REUSE_BUILDER:-gc-tee-builder-$$}
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

echo ">>> ensuring GCS bucket gs://${BUCKET}"
gcloud storage buckets describe "gs://${BUCKET}" >/dev/null 2>&1 ||
  gcloud storage buckets create "gs://${BUCKET}" --location=US

if [ -z "$REUSE_BUILDER" ]; then
  echo ">>> creating builder VM ${BUILDER}"
  gcloud compute instances create "$BUILDER" \
    --zone "$ZONE" \
    --machine-type e2-standard-8 \
    --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
    --boot-disk-size 100GB \
    --scopes storage-rw
else
  echo ">>> reusing builder VM ${BUILDER}"
fi

echo ">>> waiting for SSH"
for i in $(seq 1 30); do
  if gcloud compute ssh "$BUILDER" --zone "$ZONE" --command=true 2>/dev/null; then break; fi
  [ "$i" = 30 ] && { echo "builder never became reachable" >&2; exit 1; }
  sleep 5
done

echo ">>> copying repo to builder (the flake builds the launcher from source)"
SRC_TAR=$(mktemp -t gc-tee-src.XXXXXX.tar.gz)
git ls-files -z | tar -czf "$SRC_TAR" --null -T -
gcloud compute scp --zone "$ZONE" "$SRC_TAR" "$BUILDER":~/src.tar.gz
rm -f "$SRC_TAR"

echo ">>> building image on builder (nix build .#image-${PROFILE})"
gcloud compute ssh "$BUILDER" --zone "$ZONE" --command "
  set -euo pipefail
  if ! command -v nix >/dev/null; then
    curl -fsSL https://install.determinate.systems/nix | sh -s -- install --no-confirm
  fi
  # Ubuntu 24.04 blocks unprivileged user namespaces via AppArmor by default;
  # the image.repart builder needs them (systemd-repart under unshare).
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
  # shellcheck disable=SC1091
  . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh 2>/dev/null || true
  export PATH=\"/nix/var/nix/profiles/default/bin:\$PATH\"
  rm -rf ~/gc-tee-base && mkdir ~/gc-tee-base && tar -xzf ~/src.tar.gz -C ~/gc-tee-base
  cd ~/gc-tee-base
  # CRITICAL: out-links go OUTSIDE the source tree. The builder repo is a
  # path flake (no .git), so an in-tree result symlink changes the source
  # hash between the two nix build invocations — the image and the UKI would
  # come from different evaluations and carry different usrhash/cmdlines.
  rm -f ~/result-image ~/result-uki
  nix build .#image-${PROFILE} -o ~/result-image -L
  nix build .#uki-${PROFILE} -o ~/result-uki -L
  ls -la ~/result-image/ ~/result-uki/
  RAW=\$(ls ~/result-image/*.raw | head -1)
  # Cross-check: the UKI inside the image's ESP must be byte-identical to
  # the standalone UKI output we predict measurements from. Guards against
  # the two nix invocations evaluating different sources.
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -qy mtools jq >/dev/null
  ESP_START=\$(sfdisk -J \"\$RAW\" | jq -r '.partitiontable.partitions[] | select(.type | ascii_downcase | startswith(\"c12a7328\")) | .start')
  mcopy -o -i \"\$RAW\"@@\$((ESP_START * 512)) ::/EFI/BOOT/BOOTX64.EFI /tmp/esp-uki.efi
  cmp /tmp/esp-uki.efi ~/result-uki/*.efi
  echo 'ESP UKI matches standalone UKI'
  # Package the disk for GCE: sparse tar named disk.raw, oldgnu format.
  cp --sparse=always \"\$RAW\" disk.raw
  tar --format=oldgnu -Sczf image.tar.gz disk.raw
  # Upload via the metadata-token GCS JSON API (no gcloud needed on builder).
  TOKEN=\$(curl -s -H 'Metadata-Flavor: Google' \
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"access_token\"])')
  curl -sf -X POST --data-binary @image.tar.gz \
    -H \"Authorization: Bearer \$TOKEN\" -H 'Content-Type: application/octet-stream' \
    'https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${IMAGE_NAME}.tar.gz' \
    > /dev/null
  echo 'upload done'
  # Stage artifacts for scp (result symlinks point into /nix/store; files
  # copied out are read-only, so clear leftovers from previous runs first).
  mkdir -p ~/artifacts && rm -f ~/artifacts/*
  install -m 0644 ~/result-uki/*.efi ~/artifacts/uki.efi
  install -m 0644 ~/result-image/repart-output.json ~/artifacts/ 2>/dev/null || true
"

echo ">>> fetching artifacts (UKI, repart-output.json)"
mkdir -p "$ARTIFACTS"
gcloud compute scp --zone "$ZONE" "$BUILDER:~/artifacts/*" "$ARTIFACTS/"

echo ">>> creating GCE image ${IMAGE_NAME}"
gcloud compute images create "$IMAGE_NAME" \
  --source-uri "gs://${BUCKET}/${IMAGE_NAME}.tar.gz" \
  --architecture=X86_64 \
  --guest-os-features=UEFI_COMPATIBLE,SEV_CAPABLE,SEV_SNP_CAPABLE,TDX_CAPABLE,GVNIC,VIRTIO_SCSI_MULTIQUEUE

echo ">>> predicting expected measurements"
# The usrhash is sealed in the UKI's .cmdline section (plaintext in the PE);
# reading it from the UKI itself is the ground truth — the intermediate
# image's repart JSON is only a cross-check artifact.
USRHASH=$(strings "$ARTIFACTS/uki.efi" | grep -oE 'usrhash=[0-9a-f]+' | head -1 | cut -d= -f2)
[ -n "$USRHASH" ] || { echo "no usrhash= found in UKI cmdline" >&2; exit 1; }
go run ./cmd/predict-measurements \
  -uki "$ARTIFACTS/uki.efi" \
  -image "$IMAGE_NAME" \
  -roothash "$USRHASH" \
  -out "$ARTIFACTS/expected-measurements.json"

echo
echo "=== done ==="
echo "image:                 $IMAGE_NAME"
echo "usrhash:               $USRHASH"
echo "expected measurements: $ARTIFACTS/expected-measurements.json"
echo "next: deploy/create-instance.sh -i $IMAGE_NAME   # boots in provisioning mode"
