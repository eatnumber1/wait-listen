// SPDX-License-Identifier: MIT
// The few kernel UAPI definitions the BPF program needs, so that compiling it
// depends on no host headers (linux/bpf.h pulls in the host's asm/types.h).
// The values are kernel ABI and never change.
#ifndef WAIT_LISTEN_BPF_TYPES_H_
#define WAIT_LISTEN_BPF_TYPES_H_

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

enum bpf_map_type {
  BPF_MAP_TYPE_ARRAY = 2,
  BPF_MAP_TYPE_RINGBUF = 27,
};

struct bpf_raw_tracepoint_args {
  __u64 args[0];
};

#endif
