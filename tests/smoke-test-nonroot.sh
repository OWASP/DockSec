#!/usr/bin/env bash
# Smoke tests for non-root container hardening.
#
# These tests exercise the entrypoint.sh privilege-drop logic. They do NOT
# use --entrypoint to override the entrypoint, because doing so would bypass
# the very code path being tested.
set -euo pipefail

IMAGE="${IMAGE:-docksec:smoke-test}"
DOCKER_GID="$(stat -c '%g' /var/run/docker.sock 2>/dev/null || echo 999)"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cleanup() {
    docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Building image (DOCKER_GID=$DOCKER_GID)..."
docker build \
    --build-arg "DOCKER_GID=$DOCKER_GID" \
    -t "$IMAGE" "$REPO_ROOT"

echo "==> Test 1: standalone run must drop privileges (entrypoint.sh)"
OUT="$(docker run --rm "$IMAGE" --version 2>&1)"
echo "    $OUT" | head -3
if ! echo "$OUT" | grep -q "dropping privileges to 'docksec'"; then
    echo "FAIL: entrypoint.sh did not drop privileges in standalone mode" >&2
    exit 1
fi
echo "    OK: standalone run drops privileges"

echo "==> Test 2: CLI works as non-root"
docker run --rm "$IMAGE" --version >/dev/null
echo "    OK: --version"
docker run --rm "$IMAGE" --help >/dev/null
echo "    OK: --help"

echo "==> Test 3: GitHub Action mode (GITHUB_WORKSPACE set) must NOT drop"
GH_OUT="$(docker run --rm -e GITHUB_WORKSPACE=/github/workspace "$IMAGE" --version 2>&1)"
echo "    $GH_OUT" | head -3
if echo "$GH_OUT" | grep -q "dropping privileges"; then
    echo "FAIL: GH Action mode should NOT drop privileges" >&2
    exit 1
fi
echo "    OK: GH Action mode stays root"

echo "==> Test 4: explicit --user override"
docker run --rm --user 0 "$IMAGE" --version >/dev/null
echo "    OK: --user 0 override works"

echo ""
echo "All smoke tests passed."
