#!/usr/bin/env bash
set -euo pipefail

# Run from any directory; mount the folder containing this script.
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CONTAINER_NAME=sdb-dev
IMAGE_NAME=up25_image

command -v colima >/dev/null || { echo 'colima is required.' >&2; exit 1; }
command -v docker >/dev/null || { echo 'docker is required.' >&2; exit 1; }

# Reuse the existing x86-64 Colima VM and its Docker images.
colima start --arch x86_64
docker --context colima info >/dev/null

if docker --context colima container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    mounted_dir="$(docker --context colima inspect --format '{{range .Mounts}}{{if eq .Destination "/workspace/sdb"}}{{.Source}}{{end}}{{end}}' "$CONTAINER_NAME")"
    if [[ "$mounted_dir" != "$PROJECT_DIR" ]]; then
        echo "Existing $CONTAINER_NAME mounts '$mounted_dir', expected '$PROJECT_DIR'." >&2
        echo 'Resolve the container mount before restarting; no container was removed.' >&2
        exit 1
    fi
    docker --context colima start "$CONTAINER_NAME" >/dev/null
else
    if ! docker --context colima image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo "Image $IMAGE_NAME is missing from Colima. Restore or build it first." >&2
        exit 1
    fi

    # SDB needs ptrace access; full --privileged access is unnecessary.
    docker --context colima run -d \
        --name "$CONTAINER_NAME" \
        --cap-add SYS_PTRACE \
        --mount "type=bind,source=$PROJECT_DIR,target=/workspace/sdb" \
        --workdir /workspace/sdb \
        "$IMAGE_NAME" sleep infinity
fi

# Exit the shell without deleting the persistent development container.
exec docker --context colima exec -it --workdir /workspace/sdb "$CONTAINER_NAME" bash
