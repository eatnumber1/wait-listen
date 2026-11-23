// SPDX-License-Identifier: MIT
// Reports when a thread of one process (the thread group in `target`) has
// put a socket into TCP_LISTEN and its listen() has returned.
//
// inet_sock_set_state fires inside inet_csk_listen_start() when the state
// becomes LISTEN, *before* the socket is hashed into the listening table, so
// neither /proc/net/tcp nor a connecting client sees it yet; reporting then
// let user space check too early and wait forever (seen in the VM tests on
// kernel 7.3, one CPU). So on_set_state only remembers the thread, and
// on_sys_exit reports when that thread's system call (the listen()) returns,
// by which time the socket is hashed.
//
// Both are raw tracepoints, whose arguments come as an array of u64 on every
// architecture; neither reads them beyond the new state, so no kernel struct
// layout, no syscall numbers, no BTF.
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

// Threads of the target between a socket becoming LISTEN and their system
// call returning.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u8);
} pending SEC(".maps");

static void report(__u32 tgid) {
  // The content doesn't matter: user space re-checks /proc on any event.
  // If the buffer is full, an event is already pending, which is enough.
  __u32 *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e) {
    *e = tgid;
    bpf_ringbuf_submit(e, 0);
  }
}

SEC("raw_tracepoint/inet_sock_set_state")
int on_set_state(struct bpf_raw_tracepoint_args *ctx) {
  if ((int)ctx->args[2] != TCP_LISTEN)
    return 0;
  __u32 zero = 0;
  __u32 *tgid = bpf_map_lookup_elem(&target, &zero);
  __u64 id = bpf_get_current_pid_tgid();
  if (!tgid || (__u32)(id >> 32) != *tgid)
    return 0;
  __u32 tid = (__u32)id;
  __u8 one = 1;
  // Should the map ever be full, report now rather than never.
  if (bpf_map_update_elem(&pending, &tid, &one, BPF_ANY))
    report(*tgid);
  return 0;
}

SEC("raw_tracepoint/sys_exit")
int on_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  __u32 tid = (__u32)id;
  if (!bpf_map_lookup_elem(&pending, &tid))
    return 0;
  bpf_map_delete_elem(&pending, &tid);
  report((__u32)(id >> 32));
  return 0;
}
