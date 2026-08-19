#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_DIR="$ROOT_DIR/images"
ARCHIVE="$IMAGE_DIR/semscanner-ae-targets-amd64.tar.gz"

readonly IMAGES=(
    semscanner-ae-loan-management:1.0
    semscanner-ae-loan-db:1.0
    semscanner-ae-online-food-ordering:1.0
    semscanner-ae-e-learning:1.0
    semscanner-ae-e-learning-db:1.0
    semscanner-ae-changedetection:0.45.20
)

command -v docker >/dev/null 2>&1 || {
    printf 'ERROR: Docker is not installed.\n' >&2
    exit 1
}
command -v gzip >/dev/null 2>&1 || {
    printf 'ERROR: gzip is not installed.\n' >&2
    exit 1
}

mkdir -p "$IMAGE_DIR"

for image in "${IMAGES[@]}"; do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        printf 'ERROR: Required image %s has not been built.\n' "$image" >&2
        printf 'Run ./manage.sh build all first.\n' >&2
        exit 1
    fi
done

printf 'Exporting the packaged target images. This may take several minutes.\n'
docker save "${IMAGES[@]}" | gzip -9 > "$ARCHIVE"

printf 'Created %s\n' "$ARCHIVE"
du -h "$ARCHIVE"
