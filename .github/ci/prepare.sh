#!/bin/bash
# SPDX-License-Identifier: MIT
# Prepares a CI job (a GitHub-hosted runner, or act's container):
#   1. frees disk: the runner image's unused toolsets (the pinned LLVM
#      toolchain alone unpacks to ~6 GB; the runner's root has ~14 GB free);
#   2. installs the pinned Bazelisk as `bazel` (Bazel itself is pinned by
#      .bazelversion);
#   3. writes ~/.bazelrc: the disk and repository caches the workflow saves.
set -euo pipefail

# --- 1. disk -----------------------------------------------------------------
before=$(df -h --output=avail / | tail -1)
for d in /usr/share/dotnet /usr/local/lib/android /opt/ghc /opt/hostedtoolcache/CodeQL; do
	if [ -d "$d" ]; then
		sudo rm -rf "$d"
	fi
done
echo "free on /: $before -> $(df -h --output=avail / | tail -1)"

# --- 2. Bazelisk -------------------------------------------------------------
BAZELISK_VERSION=v1.29.0
BAZELISK_SHA256=5a408715e932c0250d28bd84555f12edbf70117de42f9181691c736eacc4a992
mkdir -p "$HOME/.local/bin"
curl -fsSL -o "$HOME/.local/bin/bazel" \
	"https://github.com/bazelbuild/bazelisk/releases/download/$BAZELISK_VERSION/bazelisk-linux-amd64"
echo "$BAZELISK_SHA256  $HOME/.local/bin/bazel" | sha256sum -c -
chmod 0755 "$HOME/.local/bin/bazel"
echo "$HOME/.local/bin" >>"$GITHUB_PATH"

# --- 3. caches ---------------------------------------------------------------
cat >"$HOME/.bazelrc" <<EOF
common --disk_cache=$HOME/.cache/wl-bazel/disk
common --repository_cache=$HOME/.cache/wl-bazel/repos
common --color=yes
test --test_output=errors
EOF
