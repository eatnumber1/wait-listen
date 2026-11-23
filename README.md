# wait-listen

Wait, without polling, until a process starts listening on a TCP port.

Many daemons have no way to tell their service manager they are ready: no
`sd_notify`, no socket activation. The usual workaround is a loop that
checks the port every second. `wait-listen` replaces that loop with an
event: a tiny eBPF program, compiled into the binary, watches the kernel's
`inet_sock_set_state` tracepoint and wakes up the moment the given
process puts a socket on the given port into the listening state.

```
wait-listen --pid PID --port PORT [--timeout SECONDS]
```

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
| 5 | other error |

## Requirements

- Linux 5.8 or newer (BPF ring buffer) with `CONFIG_BPF_SYSCALL`,
  `CONFIG_BPF_EVENTS` and the `inet_sock_set_state` tracepoint. Kernel BTF
  is not needed, and neither is the BPF JIT: it works on 32-bit Arm kernels
  too.
- Root, or `CAP_BPF` and `CAP_PERFMON` (to load the program), and read
  access to the target's `/proc/PID/fd`.

## How it works

See [DESIGN.md](DESIGN.md).

## Building

Bazel, hermetic: every input is pinned, including the compiler and libbpf.

```
bazel build //:wait-listen
bazel test //...
```

## License

MIT; see [LICENSE](LICENSE).
