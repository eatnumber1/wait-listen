#!/bin/bash
# nektos/act with this repository's settings (README.md):
#
#   bazel run //third_party/act -- -j test
#   bazel run //third_party/act -- -j release --eventpath <event.json>
#
# Arguments after `--` go to act. It needs a container engine: Docker (a
# shell in the `docker` group) or rootless Podman (WL_ACT_PODMAN=1, which
# points act at the user's Podman socket). act only creates containers and
# volumes of its own (label wait-listen.owner=act) and removes them.
set -euo pipefail

# --- begin runfiles.bash initialization v3 ---
set +e
f=bazel_tools/tools/bash/runfiles/runfiles.bash
source "${RUNFILES_DIR:-/dev/null}/$f" 2>/dev/null ||
	source "$(grep -sm1 "^$f " "${RUNFILES_MANIFEST_FILE:-/dev/null}" | cut -f2- -d' ')" 2>/dev/null ||
	source "$0.runfiles/$f" 2>/dev/null ||
	source "$(grep -sm1 "^$f " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null ||
	source "$(grep -sm1 "^$f " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null ||
	{
		echo >&2 "cannot find $f"
		exit 1
	}
set -e
# --- end runfiles.bash initialization v3 ---

ACT="$(rlocation @ACT_RLOCATION@)"
IMAGE="$(cat "$(rlocation _main/third_party/act/runner_image.txt)")"

REPO="${BUILD_WORKSPACE_DIRECTORY:-$PWD}"
STATE="${WL_ACT_STATE:-$REPO/.act}"
mkdir -p "$STATE/actions" "$STATE/cache" "$STATE/artifacts"

if [ -n "${WL_ACT_PODMAN:-}" ]; then
	export DOCKER_HOST="unix://${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
fi
ENGINE=docker
command -v docker >/dev/null || ENGINE=podman
if ! "$ENGINE" image inspect "$IMAGE" >/dev/null 2>&1; then
	"$ENGINE" pull "$IMAGE"
fi

# The memory cap keeps a job's out-of-memory kill inside its own container.
OPTS="--label wait-listen.owner=act --memory ${WL_ACT_MEMORY:-6g}"

cd "$REPO"
exec "$ACT" \
	--platform "ubuntu-latest=$IMAGE" \
	--platform "ubuntu-24.04=$IMAGE" \
	--container-architecture linux/amd64 \
	--container-options "$OPTS" \
	--pull=false \
	--rm \
	--action-cache-path "$STATE/actions" \
	--cache-server-path "$STATE/cache" \
	--artifact-server-path "$STATE/artifacts" \
	--workflows .github/workflows/ci.yml \
	"$@"
