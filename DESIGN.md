# wait-listen: design

## The event

`listen(2)` on an IPv4 or IPv6 TCP socket moves it to `TCP_LISTEN` in
`inet_csk_listen_start()`, which calls `inet_sk_state_store()`, which fires
the `sock:inet_sock_set_state` tracepoint (kernel 4.16+) in the context of
the process calling `listen()`.

Nothing else announces it. Netlink's socket diagnostics (`NETLINK_SOCK_DIAG`,
what `ss` uses) can list sockets, but its multicast groups only report
destroyed sockets (`SKNLGRP_INET_TCP_DESTROY` and friends). The audit
subsystem can report `listen()` calls, at the cost of system-wide audit
rules.

## Steps

1. Open a pidfd for `--pid`. The process exiting is then an event too.
2. Load and attach the BPF program to the *raw* tracepoint
   `inet_sock_set_state`. A raw tracepoint gets the tracepoint's arguments
   as an array of 64-bit values (`sk`, `oldstate`, `newstate`), whatever the
   kernel's architecture, so the program depends on no kernel struct
   layout, needs no BTF and no tracefs. It passes on an event (through a BPF
   ring buffer) only when `newstate` is `TCP_LISTEN` (10) and the calling
   thread belongs to `--pid` (its thread group id).
3. Only after attaching, check whether the process listens on `--port`:
   read its `/proc/PID/net/tcp` and `tcp6` (its own network namespace) for
   `LISTEN` entries on the port, and match their inodes against the
   `socket:[inode]` links in `/proc/PID/fd`. Attaching first means a
   `listen()` before the check is found by the check, and one after it
   produces an event; there is no window in between.
4. `epoll` on the ring buffer, the pidfd and (with `--timeout`) a timerfd.
   On a ring-buffer event, repeat the check of step 3 (the event says the
   process started listening on *some* socket; the check says whether it's
   the port). Exit on a positive check, on the process exiting, or on the
   timeout.

No step sleeps or polls. Matching the thread group id also keeps a process
in another network namespace that uses the same port from matching; the
check reads the target's own namespace.

## No BTF needed

Raspberry Pi kernels, among others, have no kernel BTF, so CO-RE
relocations aren't available, and a tracepoint's context struct differs
between architectures (it starts with a pointer). The raw tracepoint
sidesteps both: its arguments are the tracepoint's prototype, `(const
struct sock *sk, int oldstate, int newstate)`, as an array of `u64`, and the
program reads only `newstate`. libbpf loads the program's own BTF where the
kernel accepts it.

## Build

- Bazel module, hermetic: `toolchains_llvm` provides Clang (for the program
  and for `-target bpf`); libbpf, elfutils and zlib come from the Bazel
  Central Registry and are built from source.
- **libc: musl, linked statically**: one file that runs on any Linux,
  nothing to resolve at run time, and the program needs nothing static
  linking handles badly (no NSS, `dlopen` or locales). glibc discourages
  static linking; llvm-libc isn't a complete libc for 32-bit Arm yet.
- **Sysroots from Debian**, one per target (`@debian_sysroot_amd64`,
  `@debian_sysroot_armhf`): `musl-dev` and `linux-libc-dev` (the kernel UAPI
  headers, with each architecture's `asm/`), from snapshot.debian.org, each
  `.deb` pinned by URL and SHA-256 in `third_party/debian/lock.json`.
  `tools/debian_lock.py` writes that file from `lock-request.json`, trusting a
  hash only through Debian's signed `InRelease` (verified with gpgv against
  `third_party/debian/keys/`) and the `Packages` index it vouches for;
  `--check` fails if the lock is stale. The keys came from Ubuntu's
  `debian-archive-keyring` package, so they are vouched for by Ubuntu's own
  signed archive. snapshot.debian.org keeps every file forever, so the pins
  never rot. (Alpine was considered and rejected: its mirrors delete
  superseded package versions and keep no archive, so it can only be pinned
  by release branch.)
- toolchains_llvm only knows glibc targets and takes a sysroot as a
  repository of files; `third_party/debian/sysroot.bzl` unpacks the pinned
  packages into such repositories, and the toolchain's per-target flags
  select musl.
- The BPF object is compiled once (BPF bytecode is the same for every host
  architecture, and the raw tracepoint has no layout to differ) and
  embedded in the binary (C23 `#embed`).
- Targets: `x86_64-linux-musl` and `armv7-linux-musleabihf`.

## Tests

- `//:listening_test`: the "already listening" check against fixture `/proc`
  trees (IPv4, IPv6, other port, another process's socket, an established
  connection, no IPv6 in the namespace, a missing process).
- `//tests/vm:vm_test_{x86_64,armv7_jit,armv7_nojit}`: a VM per target
  (QEMU from Debian, run through its own pinned loader and libraries; Debian
  kernels 6.12, amd64 and armmp-lpae on a Cortex-A7, the Raspberry Pi 2's
  CPU), booting an initramfs (`tests/vm/mkcpio.c`, reproducible) whose /init
  is `tests/vm/guest_init.c` and which carries wait-listen, both static musl
  for that CPU. armv7 runs with the BPF JIT and without (`wl.jit=0`, as on
  Raspberry Pi kernels). Each scenario, as root, waits only on events (pipes,
  process exits; `--ready-fd` tells the guest when wait-listen is watching,
  `--verbose` when it handled a non-matching listen):
  - the process listens after wait-listen started watching: exit 0;
  - it was already listening: exit 0, never "ready" (the /proc path);
  - it exits without listening: exit 1;
  - another process holds the port, the target listens on another port
    (an event, handled, still waiting), then on the port over IPv6: exit 0;
  - `--timeout 1`: exit 2;
  - SIGTERM: exit 6; SIGKILL: killed;
  - after each: no BPF link left attached (`BPF_LINK_GET_NEXT_ID`).

## Teardown

The program is attached through a BPF link (a file descriptor). It is never
pinned in bpffs, and nothing inherits the descriptor (libbpf opens with
`O_CLOEXEC`; `wait-listen` never forks or execs), so the kernel detaches and
frees the program when the process exits, however it exits. Every orderly
exit, including SIGTERM, SIGINT and SIGHUP (received through a signalfd in the
same epoll set), also tears down explicitly: link first, then the ring
buffer, the object (program and maps) and the descriptors.
