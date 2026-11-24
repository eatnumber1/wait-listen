# wait-listen

Wait, without polling, until a process starts listening on a TCP port.

Many daemons have no way to tell their service manager they are ready: no
`sd_notify`, no socket activation. The usual workaround is a loop that
checks the port every second. `wait-listen` replaces that loop with an
event: a tiny eBPF program, compiled into the binary, wakes it up the moment
the given process puts a socket on the given port into the listening state.

```
wait-listen --pid PID --port PORT [--timeout SECONDS] [--ready-fd FD] [--verbose]
```

- `--timeout SECONDS`: give up after this long (exit 2). Off by default: it's
  an upper bound for a hang, not a wait.
- `--ready-fd FD`: write one byte to file descriptor FD, then close it, once
  wait-listen is watching and the process isn't already listening. From then
  on, a `listen()` can't be missed.
- `--verbose`: also report each `listen()` by the process that wasn't on the
  port.

| Exit status | Meaning |
|---|---|
| 0 | the process listens on the port (now, or already did) |
| 1 | the process exited without listening on the port |
| 2 | `--timeout` expired |
| 3 | usage error |
| 4 | the kernel can't do this (no BPF, no such tracepoint) |
| 5 | other error (including missing privileges) |
| 6 | stopped by SIGTERM, SIGINT or SIGHUP |

## Example: a systemd unit

```ini
[Unit]
Description=A daemon that can't tell systemd when it's ready

[Service]
Type=exec
User=example
ExecStart=/usr/sbin/example-daemon --foreground --port 9105
# The service counts as started only once this exits, i.e. once the daemon
# listens on 9105: units ordered After= it find the port open. The "+" runs
# wait-listen with full privileges although the daemon runs as "example".
# TimeoutStartSec= (default 90 s) bounds the wait.
ExecStartPost=+/usr/local/bin/wait-listen --pid ${MAINPID} --port 9105

[Install]
WantedBy=multi-user.target
```

`ExecStartPost=` runs while the daemon is already starting, so the daemon
may listen before wait-listen starts, while it starts, or after. All three
are fine: wait-listen starts watching *before* it looks whether the daemon
already listens (see "How it works"), so no `listen()` falls between the two.
If the daemon exits before it listens, wait-listen exits 1 and the start
fails, as it should.

## How it works

1. wait-listen opens a pidfd for the process, so its exit is an event too.
2. It loads two small BPF programs onto raw tracepoints. One, on
   `inet_sock_set_state` (any TCP socket changing state), notes the thread
   when a thread of the process moves a socket to `LISTEN`. The other, on
   `sys_exit` (any system call returning), passes on an event when a noted
   thread's system call returns: that's its `listen()` finishing, after the
   kernel has put the socket where connections (and `/proc`) can find it.
   The state change alone comes too early: reporting it, wait-listen could
   look before the socket was there and then wait forever.
3. Only then does it check whether the process is *already* listening on the
   port (its `/proc/PID/net/tcp{,6}`, matched against the sockets in its
   `/proc/PID/fd`). Watching first, then checking, means no `listen()` can
   fall between the two.
4. It sleeps in `epoll` on the BPF ring buffer, the pidfd, an optional timer
   and a signalfd. Each event re-runs the check of step 3, since the event
   says the process listened on *some* port. It exits on the first answer.

Nothing polls. Raw tracepoints hand a program the tracepoint's arguments as
plain integers, and these programs read nothing but the new state, so they
depend on no kernel struct layout or syscall numbering and need no kernel
BTF or BPF JIT: one binary works on any kernel from 5.8,
including 32-bit Arm kernels without BTF. More detail: [DESIGN.md](DESIGN.md).

The programs are attached through BPF links that are never pinned and never
inherited, so the kernel detaches it when wait-listen exits, however it
exits (even SIGKILL). Orderly exits also detach it explicitly first.

## Limitations

- **The process itself, not its children.** The BPF filter matches the
  thread group of `--pid`: a worker process the daemon forks, which then
  listens, isn't seen. Give the PID of the process that calls `listen()`
  (any of its threads is fine).
- **`listen()`, not sockets handed over.** A listening socket the process
  already holds when wait-listen starts is found (step 3), but one it
  receives *afterwards* without calling `listen()` itself (inherited from a
  parent, or passed over a Unix socket, as with systemd socket activation)
  isn't.
- **io_uring's asynchronous listen.** wait-listen notices a `listen()` when
  the calling thread's system call returns. io_uring's `IORING_OP_LISTEN`
  (Linux 6.11+) may run on an io_uring worker thread, which never returns to
  user space, so such a listen may go unnoticed. Plain `listen()`, from any
  number of threads at once, is fine.
- **TCP over IPv4 and IPv6 only.** Not UDP, Unix sockets or SCTP.
- **The port, on any address.** Listening on `127.0.0.1:9105` counts as
  listening on 9105, even if clients will come from elsewhere.
- **Listening isn't the same as ready.** A daemon may listen before it's
  ready to serve; wait-listen reports when connections can be made.
- **The initial PID namespace.** The kernel reports the thread group ID as
  seen from the initial PID namespace, and `--pid` is compared with it; run
  wait-listen there (as systemd units do), not inside a container with a PID
  namespace of its own.
- **Privileges.** Loading a tracing BPF program needs root, or `CAP_BPF` and
  `CAP_PERFMON` (a user namespace's root doesn't count), plus `CAP_SYS_PTRACE`
  or the target's own uid to read its `/proc/PID/fd`.
- **Linux 5.8 or newer** (the BPF ring buffer), with `CONFIG_BPF_SYSCALL`,
  `CONFIG_BPF_EVENTS` and the `inet_sock_set_state` and `sys_exit`
  tracepoints. While waiting, a tiny program (one hash lookup) runs on every
  system call return on the machine. Tested on
  Debian's 6.1, 6.12 and 7.3 kernels, on x86-64 and 32-bit Arm (Cortex-A7),
  with and without the BPF JIT.

## Installing

Nightly static builds (x86-64 and 32-bit Arm) are attached to the
[`nightly` release](https://github.com/eatnumber1/wait-listen/releases/tag/nightly):

```
curl -fLO https://github.com/eatnumber1/wait-listen/releases/download/nightly/wait-listen-x86_64
curl -fLO https://github.com/eatnumber1/wait-listen/releases/download/nightly/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
install -m 0755 wait-listen-x86_64 /usr/local/bin/wait-listen
```

## Building

Bazel, hermetic: every input is pinned, including the compiler (LLVM), the
sysroots (Debian packages by SHA-256, `third_party/debian/lock.json`) and
libbpf. The binaries are static (musl).

```
bazel build //:wait-listen_x86_64 //:wait-listen_armv7
bazel test //...
```

The VM tests boot pinned Debian kernels (6.1, 6.12, 7.3) in a pinned QEMU,
x86-64 and a 32-bit Cortex-A7 with and without the BPF JIT, and run every
scenario as root inside them, checking each answer against reality: a client
can connect when wait-listen says the port is open, and couldn't before.
Nothing on the host needs root or KVM.

CI (`.github/workflows/ci.yml`) runs the tests on every push and publishes
the nightly; it's checked locally with nektos/act first
(`bazel run //third_party/act -- -j test`, see
[third_party/act/README.md](third_party/act/README.md)).

## License

MIT; see [LICENSE](LICENSE).
