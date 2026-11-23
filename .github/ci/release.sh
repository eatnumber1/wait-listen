#!/bin/bash
# SPDX-License-Identifier: MIT
# Builds the release binaries into DIR: wait-listen-<cpu> (static musl) and
# SHA256SUMS. Checks each is a static executable of the right architecture
# and runs (the x86-64 one, here: --help).
#   .github/ci/release.sh DIR
set -euo pipefail
dir=$1
mkdir -p "$dir"
for cpu in x86_64 armv7; do
	bazel build -c opt --strip=always "//:wait-listen_$cpu"
	src=$(bazel cquery -c opt --strip=always --output=files "//:wait-listen_$cpu" 2>/dev/null)
	install -m 0755 "$src" "$dir/wait-listen-$cpu"
done
file "$dir"/wait-listen-*
file "$dir/wait-listen-x86_64" | grep -q 'x86-64.*statically linked'
file "$dir/wait-listen-armv7" | grep -q 'ARM, EABI5.*statically linked'
"$dir/wait-listen-x86_64" --help
(cd "$dir" && sha256sum wait-listen-* >SHA256SUMS && cat SHA256SUMS)
