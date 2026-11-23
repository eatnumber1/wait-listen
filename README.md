# wait-listen

Wait, without polling, until a process starts listening on a TCP port.

Many daemons have no way to tell their service manager they are ready: no
`sd_notify`, no socket activation. The usual workaround is a loop that
checks the port every second. `wait-listen` replaces that loop with an
event: a tiny eBPF program, compiled into the binary, watches the kernel's
`inet_sock_set_state` tracepoint and wakes up the moment the given
process puts a socket on the given port into the listening state.

```
wait-listen --pid PID --port PORT [--timeout SECONDS] [--ready-fd FD] [--verbose]
```

`--ready-fd FD` writes one byte to file descriptor FD, then closes it, once
the program is attached and the process isn't already listening: from then
on, a `listen()` can't be missed. `--verbose` also reports each `listen()` by
the process that wasn't on the port.

Typical use, in a systemd unit for a daemon that can't notify:

```ini
[Service]
Type=exec
ExecStart=/usr/sbin/some-daemon --foreground
ExecStartPost=/usr/local/bin/wait-listen --pid ${MAINPID} --port 9105
```

systemd treats the service as started only once `wait-listen` exits, so units
ordered `After=` it start only once the port really accepts connections.

Exit status:

| Status | Meaning |
|---|---|
| 0 | the process listens on the port (now, or already did) |
| 1 | the process exited without listening on the port |
| 2 | the timeout expired (default: none; it's an upper bound, not a wait) |
| 3 | usage error |
| 4 | the kernel can't do this (no BPF, no such tracepoint) |
| 5 | other error (including missing privileges) |
| 6 | stopped by SIGTERM, SIGINT or SIGHUP |

## Requirements

- Linux 5.8 or newer (BPF ring buffer) with `CONFIG_BPF_SYSCALL`,
  `CONFIG_BPF_EVENTS` and the `inet_sock_set_state` tracepoint. Kernel BTF
  is not needed, and neither is the BPF JIT: it works on 32-bit Arm kernels
  too. Tested on Debian's 6.1, 6.12 and 7.3 kernels, x86-64 and armv7.
- Root, or `CAP_BPF` and `CAP_PERFMON` (to load a tracing program; a user
  namespace's root doesn't count) and `CAP_SYS_PTRACE` or the target's own
  uid (to read its `/proc/PID/fd`). In a unit whose daemon runs
  unprivileged, use `ExecStartPost=+/usr/local/bin/wait-listen ...`.

## Teardown

The program is attached through a BPF link that is never pinned and never
inherited, so the kernel detaches it when `wait-listen` exits, however it
exits (even SIGKILL). On every normal exit, including SIGTERM, SIGINT and
SIGHUP (received through a signalfd), `wait-listen` also detaches and unloads
it explicitly first. The tests check that no program is left loaded after
each way of exiting.

## How it works

See [DESIGN.md](DESIGN.md).

## Building

Bazel, hermetic: every input is pinned, including the compiler, the
sysroots (Debian packages by SHA-256, `third_party/debian/lock.json`) and
libbpf.

```
bazel build //:wait-listen_x86_64 //:wait-listen_armv7   # static musl binaries
bazel test //...                                         # unit and VM tests
```

The VM tests boot pinned Debian kernels (6.1, 6.12, 7.3) in a pinned QEMU
(x86-64, and a 32-bit Cortex-A7 with and without the BPF JIT) and run every
scenario as root, each checked against what it stands for: a client can
connect when wait-listen says so, and couldn't before. Nothing on the host
needs root.

## License

MIT; see [LICENSE](LICENSE).
