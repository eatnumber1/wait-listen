// SPDX-License-Identifier: MIT
// Reports when a thread of one process (the thread group target_tgid) puts a
// socket into TCP_LISTEN. Attached to the raw tracepoint inet_sock_set_state,
// whose arguments are (const struct sock *sk, int oldstate, int newstate),
// passed as an array of u64 on every architecture: no kernel struct layout,
// no BTF needed.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TCP_LISTEN 10

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Entry 0: the target's thread group id, written by user space after loading
// and before attaching (a map, not a global: no reliance on BTF for globals).
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} target SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} events SEC(".maps");

SEC("raw_tracepoint/inet_sock_set_state")
int on_set_state(struct bpf_raw_tracepoint_args *ctx) {
  if ((int)ctx->args[2] != TCP_LISTEN)
    return 0;
  __u32 zero = 0;
  __u32 *tgid = bpf_map_lookup_elem(&target, &zero);
  if (!tgid || (__u32)(bpf_get_current_pid_tgid() >> 32) != *tgid)
    return 0;
  // The content doesn't matter: user space re-checks /proc on any event.
  // If the buffer is full, an event is already pending, which is enough.
  __u32 *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e) {
    *e = *tgid;
    bpf_ringbuf_submit(e, 0);
  }
  return 0;
}
