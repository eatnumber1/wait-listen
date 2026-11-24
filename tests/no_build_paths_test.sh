#!/bin/bash
# SPDX-License-Identifier: MIT
# The release binaries must not embed the build directory (Bazel's
# per-build sandbox path, a user's home, an output base): it would make the
# output differ from build to build and machine to machine, so nobody could
# check a release against its source. Uses only bash, to stay hermetic.
set -euo pipefail
fail=0
for f in "$@"; do
  # Read the binary as text with NULs dropped; look for absolute paths that
  # only a build directory produces.
  if hits=$(tr -d '\0' <"$f" | grep -aoE '(/[A-Za-z0-9._+-]+)*/(execroot|sandbox|bazel-out|_bazel_[a-z]+|\.cache/bazel)/' | sort -u | head -5) && [ -n "$hits" ]; then
    echo "FAIL: $f embeds build paths:" >&2
    printf '  %s\n' $hits >&2
    fail=1
  else
    echo "ok: $f"
  fi
done
exit $fail
