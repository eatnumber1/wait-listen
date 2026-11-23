#!/bin/bash
# SPDX-License-Identifier: MIT
# Boots a test VM: the pinned Debian QEMU (through its own pinned loader and
# libraries), the pinned kernel, and an initramfs whose /init is guest_init.
# Passes when the guest prints the PASS verdict; the console is kept in the
# test's undeclared outputs. Bazel's test timeout bounds a hung guest.
#   run_vm_test.sh LD QEMU KERNEL INITRD MACHINE-ARGS -- KERNEL-CMDLINE
set -euo pipefail
ld=$1 qemu=$2 kernel=$3 initrd=$4
shift 4
machine=()
while [ "$1" != "--" ]; do machine+=("$1"); shift; done
shift
cmdline="$*"

root=${ld%/usr/lib/*}
log=${TEST_UNDECLARED_OUTPUTS_DIR:-$(mktemp -d)}/console.log
"$ld" --library-path "$root/usr/lib/x86_64-linux-gnu" "$qemu" \
  -L "$root/usr/share/qemu" -L "$root/usr/share/seabios" -L "$root/usr/lib/ipxe/qemu" \
  "${machine[@]}" -m 512 -nodefaults -nographic -serial stdio -no-reboot \
  -kernel "$kernel" -initrd "$initrd" -append "panic=-1 quiet $cmdline" </dev/null >"$log" 2>&1 || true
tr -d '\r' <"$log" | grep -aE '^(TEST|WAIT-LISTEN-VM-TESTS)' || true
grep -aq 'WAIT-LISTEN-VM-TESTS: PASS' "$log" || { echo "no PASS verdict; console: $log"; tail -20 "$log"; exit 1; }
