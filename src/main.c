// SPDX-License-Identifier: MIT
// wait-listen: wait, without polling, until a process listens on a TCP port.
// See DESIGN.md.
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "listening.h"

enum {
  EXIT_LISTENING = 0,
  EXIT_GONE = 1,
  EXIT_TIMEOUT = 2,
  EXIT_USAGE = 3,
  EXIT_KERNEL = 4,
  EXIT_ERROR = 5,
};

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434  // the same on every architecture
#endif

static const unsigned char bpf_object_bytes[] = {
#embed "wait_listen.bpf.o"
};

static int verbose;

static int libbpf_log(enum libbpf_print_level level, const char *fmt, va_list ap) {
  if (level == LIBBPF_DEBUG && !verbose)
    return 0;
  if (level == LIBBPF_INFO && !verbose)
    return 0;
  return vfprintf(stderr, fmt, ap);
}

static void usage(FILE *f) {
  fprintf(f,
          "usage: wait-listen --pid PID --port PORT [--timeout SECONDS] [--verbose]\n"
          "Exit: 0 listening, 1 process gone, 2 timeout, 3 usage, 4 kernel can't, 5 error.\n");
}

static int parse_uint(const char *s, unsigned long max, unsigned long *out) {
  char *end;
  errno = 0;
  unsigned long v = strtoul(s, &end, 10);
  if (errno || end == s || *end || s[0] == '-' || v > max)
    return -1;
  *out = v;
  return 0;
}

static int on_event(void *ctx, void *data, size_t size) {
  (void)data;
  (void)size;
  *(int *)ctx = 1;
  return 0;
}

// 1 listening, 0 not yet, -1 gone, -2 error.
static int check(pid_t pid, unsigned port) {
  int r = listens_on("/proc", pid, port);
  if (r >= 0)
    return r;
  if (errno == ESRCH)
    return -1;
  fprintf(stderr, "wait-listen: reading /proc/%d: %s\n", (int)pid, strerror(errno));
  return -2;
}

int main(int argc, char **argv) {
  static const struct option options[] = {
      {"pid", required_argument, NULL, 'p'},
      {"port", required_argument, NULL, 'P'},
      {"timeout", required_argument, NULL, 't'},
      {"verbose", no_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {0},
  };
  unsigned long pid = 0, port = 0, timeout = 0;
  int have_pid = 0, have_port = 0, c;
  while ((c = getopt_long(argc, argv, "", options, NULL)) != -1) {
    switch (c) {
      case 'p':
        if (parse_uint(optarg, INT_MAX, &pid) || pid == 0)
          goto bad;
        have_pid = 1;
        break;
      case 'P':
        if (parse_uint(optarg, 65535, &port) || port == 0)
          goto bad;
        have_port = 1;
        break;
      case 't':
        if (parse_uint(optarg, 86400 * 365, &timeout) || timeout == 0)
          goto bad;
        break;
      case 'v':
        verbose = 1;
        break;
      case 'h':
        usage(stdout);
        return EXIT_LISTENING;
      default:
        goto bad;
    }
  }
  if (optind != argc || !have_pid || !have_port)
    goto bad;

  libbpf_set_print(libbpf_log);

  // 1. The process exiting is an event.
  int pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
  if (pidfd < 0) {
    if (errno == ESRCH)
      return EXIT_GONE;
    fprintf(stderr, "wait-listen: pidfd_open(%lu): %s\n", pid, strerror(errno));
    return errno == ENOSYS ? EXIT_KERNEL : EXIT_ERROR;
  }

  // 2. Load and attach first, so no listen() can fall between check and watch.
  LIBBPF_OPTS(bpf_object_open_opts, opts, .object_name = "wait_listen");
  struct bpf_object *obj = bpf_object__open_mem(bpf_object_bytes, sizeof(bpf_object_bytes), &opts);
  if (!obj) {
    fprintf(stderr, "wait-listen: opening the BPF object: %s\n", strerror(errno));
    return EXIT_ERROR;
  }
  if (bpf_object__load(obj)) {
    int e = errno;
    fprintf(stderr, "wait-listen: loading the BPF program: %s\n", strerror(e));
    return (e == EPERM || e == EACCES) ? EXIT_ERROR : EXIT_KERNEL;
  }
  struct bpf_map *target = bpf_object__find_map_by_name(obj, "target");
  struct bpf_map *events = bpf_object__find_map_by_name(obj, "events");
  struct bpf_program *prog = bpf_object__find_program_by_name(obj, "on_set_state");
  if (!target || !events || !prog) {
    fprintf(stderr, "wait-listen: BPF object lacks its maps or program\n");
    return EXIT_ERROR;
  }
  __u32 zero = 0, tgid = (__u32)pid;
  if (bpf_map_update_elem(bpf_map__fd(target), &zero, &tgid, BPF_ANY)) {
    fprintf(stderr, "wait-listen: setting the target: %s\n", strerror(errno));
    return EXIT_ERROR;
  }
  int got_event = 0;
  struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(events), on_event, &got_event, NULL);
  if (!rb) {
    fprintf(stderr, "wait-listen: ring buffer: %s\n", strerror(errno));
    return EXIT_ERROR;
  }
  struct bpf_link *link = bpf_program__attach_raw_tracepoint(prog, "inet_sock_set_state");
  if (!link) {
    fprintf(stderr, "wait-listen: attaching to inet_sock_set_state: %s\n", strerror(errno));
    return EXIT_KERNEL;
  }

  // 3. Already listening?
  int r = check((pid_t)pid, (unsigned)port);
  if (r == 1)
    return EXIT_LISTENING;
  if (r == -1)
    return EXIT_GONE;
  if (r == -2)
    return EXIT_ERROR;

  // 4. Wait for the first of: a listen() by the process, its exit, the timeout.
  int ep = epoll_create1(EPOLL_CLOEXEC);
  int tfd = -1;
  if (ep < 0)
    goto fail;
  struct epoll_event ev = {.events = EPOLLIN};
  ev.data.fd = ring_buffer__epoll_fd(rb);
  if (epoll_ctl(ep, EPOLL_CTL_ADD, ev.data.fd, &ev))
    goto fail;
  ev.data.fd = pidfd;
  if (epoll_ctl(ep, EPOLL_CTL_ADD, pidfd, &ev))
    goto fail;
  if (timeout) {
    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    struct itimerspec its = {.it_value = {.tv_sec = (time_t)timeout}};
    if (tfd < 0 || timerfd_settime(tfd, 0, &its, NULL))
      goto fail;
    ev.data.fd = tfd;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, tfd, &ev))
      goto fail;
  }
  for (;;) {
    struct epoll_event got[3];
    int n = epoll_wait(ep, got, 3, -1);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      goto fail;
    }
    for (int i = 0; i < n; i++) {
      if (got[i].data.fd == pidfd) {
        // It exited; it may have listened just before (then the ring buffer
        // has the event, but its sockets are gone: either way, it's gone).
        return EXIT_GONE;
      }
      if (got[i].data.fd == tfd)
        return EXIT_TIMEOUT;
    }
    // A ring-buffer event: the process put *some* socket into LISTEN.
    got_event = 0;
    if (ring_buffer__consume(rb) < 0)
      goto fail;
    r = check((pid_t)pid, (unsigned)port);
    if (r == 1)
      return EXIT_LISTENING;
    if (r == -1)
      return EXIT_GONE;
    if (r == -2)
      return EXIT_ERROR;
  }

fail:
  fprintf(stderr, "wait-listen: %s\n", strerror(errno));
  return EXIT_ERROR;

bad:
  usage(stderr);
  return EXIT_USAGE;
}
