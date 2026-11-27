// SPDX-License-Identifier: MIT
// wait-listen: wait, without polling, until a process listens on a TCP port.
// See DESIGN.md.
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
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
  EXIT_SIGNAL = 6,
};

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434  // the same on every architecture
#endif

static const unsigned char bpf_object_bytes[] = {
#embed "wait_listen.bpf.o"
};

static int verbose;
static int ready_fd = -1;  // --ready-fd: one byte once attached and checked

static int libbpf_log(enum libbpf_print_level level, const char *fmt, va_list ap) {
  if (level == LIBBPF_DEBUG && !verbose)
    return 0;
  if (level == LIBBPF_INFO && !verbose)
    return 0;
  return vfprintf(stderr, fmt, ap);
}

static void usage(FILE *f) {
  fprintf(f,
          "usage: wait-listen --pid PID --port PORT [--timeout SECONDS] [--ready-fd FD]\n"
          "                   [--verbose]\n"
          "Exit: 0 listening, 1 process gone, 2 timeout, 3 usage, 4 kernel can't, 5 error,\n"
          "6 stopped by a signal.\n");
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
  (void)ctx;
  (void)data;
  (void)size;
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

// Everything that must be released, in the order it's released. The kernel
// detaches the program when the last reference to its link closes, on any
// exit (even SIGKILL), since it's never pinned and nothing inherits it; the
// explicit teardown makes that ordering visible and leaves nothing for the
// kernel to clean up.
struct state {
  struct bpf_link *link, *exit_link;
  struct ring_buffer *rb;
  struct bpf_object *obj;
  int pidfd, ep, tfd, sfd;
};

static void teardown(struct state *st) {
  bpf_link__destroy(st->link);  // detach first: no more events
  bpf_link__destroy(st->exit_link);
  ring_buffer__free(st->rb);
  bpf_object__close(st->obj);  // unloads the program and its maps
  if (st->sfd >= 0)
    close(st->sfd);
  if (st->tfd >= 0)
    close(st->tfd);
  if (st->ep >= 0)
    close(st->ep);
  if (st->pidfd >= 0)
    close(st->pidfd);
}

static int watch(int ep, int fd) {
  struct epoll_event ev = {.events = EPOLLIN, .data.fd = fd};
  return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
}

// Notes every current thread of pid in the BPF program's `pending` map. A
// full map is an error, never a silent gap.
static int seed_threads(struct bpf_object *obj, pid_t pid) {
  struct bpf_map *pending = bpf_object__find_map_by_name(obj, "pending");
  if (!pending) {
    errno = ENOENT;
    return -1;
  }
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/task", (int)pid);
  DIR *d = opendir(path);
  if (!d)
    return errno == ENOENT ? 0 : -1;  // gone: the pidfd says so next
  struct dirent *e;
  __u8 one = 1;
  int err = 0;
  while ((e = readdir(d))) {
    char *end;
    unsigned long tid = strtoul(e->d_name, &end, 10);
    if (*end || e->d_name[0] == '.')
      continue;
    __u32 key = (__u32)tid;
    if (bpf_map_update_elem(bpf_map__fd(pending), &key, &one, BPF_ANY)) {
      err = -1;
      break;
    }
  }
  closedir(d);
  return err;
}

static int run(struct state *st, pid_t pid, unsigned port, unsigned long timeout) {
  // Signals arrive through a signalfd, so a stopped unit leaves through
  // teardown() like every other exit.
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGTERM);
  sigaddset(&sigs, SIGINT);
  sigaddset(&sigs, SIGHUP);
  if (sigprocmask(SIG_BLOCK, &sigs, NULL) ||
      (st->sfd = signalfd(-1, &sigs, SFD_CLOEXEC)) < 0)
    goto fail;

  // 1. The process exiting is an event.
  st->pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
  if (st->pidfd < 0) {
    if (errno == ESRCH)
      return EXIT_GONE;
    fprintf(stderr, "wait-listen: pidfd_open(%d): %s\n", (int)pid, strerror(errno));
    return errno == ENOSYS ? EXIT_KERNEL : EXIT_ERROR;
  }

  // 2. Load and attach first, so no listen() can fall between check and watch.
  LIBBPF_OPTS(bpf_object_open_opts, opts, .object_name = "wait_listen");
  st->obj = bpf_object__open_mem(bpf_object_bytes, sizeof(bpf_object_bytes), &opts);
  if (!st->obj) {
    fprintf(stderr, "wait-listen: opening the BPF object: %s\n", strerror(errno));
    return EXIT_ERROR;
  }
  if (bpf_object__load(st->obj)) {
    int e = errno;
    fprintf(stderr, "wait-listen: loading the BPF program: %s\n", strerror(e));
    return (e == EPERM || e == EACCES) ? EXIT_ERROR : EXIT_KERNEL;
  }
  struct bpf_map *target = bpf_object__find_map_by_name(st->obj, "target");
  struct bpf_map *events = bpf_object__find_map_by_name(st->obj, "events");
  struct bpf_program *prog = bpf_object__find_program_by_name(st->obj, "on_set_state");
  struct bpf_program *exit_prog = bpf_object__find_program_by_name(st->obj, "on_sys_exit");
  if (!target || !events || !prog || !exit_prog) {
    fprintf(stderr, "wait-listen: BPF object lacks its maps or program\n");
    return EXIT_ERROR;
  }
  __u32 zero = 0, tgid = (__u32)pid;
  if (bpf_map_update_elem(bpf_map__fd(target), &zero, &tgid, BPF_ANY))
    goto fail;
  st->rb = ring_buffer__new(bpf_map__fd(events), on_event, NULL, NULL);
  if (!st->rb)
    goto fail;
  // sys_exit first: once on_set_state remembers a thread, the report on its
  // listen() returning mustn't be missed.
  st->exit_link = bpf_program__attach_raw_tracepoint(exit_prog, "sys_exit");
  if (!st->exit_link) {
    fprintf(stderr, "wait-listen: attaching to sys_exit: %s\n", strerror(errno));
    return EXIT_KERNEL;
  }
  st->link = bpf_program__attach_raw_tracepoint(prog, "inet_sock_set_state");
  if (!st->link) {
    fprintf(stderr, "wait-listen: attaching to inet_sock_set_state: %s\n", strerror(errno));
    return EXIT_KERNEL;
  }

  // A listen() already in progress when we attached set its socket's state
  // before on_set_state could note the thread, and its socket may not be
  // findable yet: note every existing thread now, so whichever of them is
  // inside listen() reports when it returns. One that returned before we
  // noted it has its socket in place already, for the check below.
  if (seed_threads(st->obj, pid))
    goto fail;

  // 3. Already listening?
  int r = check(pid, port);
  if (r != 0)
    return r == 1 ? EXIT_LISTENING : r == -1 ? EXIT_GONE : EXIT_ERROR;

  // Watching: tell whoever asked (a byte, then EOF), e.g. a test that only
  // then makes the process listen, so the event path is what it exercises.
  if (ready_fd >= 0) {
    if (write(ready_fd, "r", 1) != 1)
      goto fail;
    close(ready_fd);
    ready_fd = -1;
  }
  if (verbose)
    fprintf(stderr, "wait-listen: watching pid %d for port %u\n", (int)pid, port);

  // 4. Wait for the first of: a listen() by the process, its exit, the
  // timeout, a signal.
  // The ring buffer map's own descriptor (readable while it holds records),
  // not ring_buffer__epoll_fd(): that is libbpf's internal epoll instance,
  // and an epoll nested in ours depends on the kernel passing the inner
  // wakeup on, which kernel 7.3 on 32-bit Arm sometimes didn't (the VM tests
  // hung there, 3 runs in 6).
  int rbfd = bpf_map__fd(events);
  st->ep = epoll_create1(EPOLL_CLOEXEC);
  if (st->ep < 0 || watch(st->ep, rbfd) || watch(st->ep, st->pidfd) || watch(st->ep, st->sfd))
    goto fail;
  if (timeout) {
    struct itimerspec its = {.it_value = {.tv_sec = (time_t)timeout}};
    st->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (st->tfd < 0 || timerfd_settime(st->tfd, 0, &its, NULL) || watch(st->ep, st->tfd))
      goto fail;
  }
  for (;;) {
    struct epoll_event got[4];
    int n = epoll_wait(st->ep, got, 4, -1);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      goto fail;
    }
    int listened = 0;
    for (int i = 0; i < n; i++) {
      int fd = got[i].data.fd;
      if (fd == st->sfd)
        return EXIT_SIGNAL;
      if (fd == st->pidfd)
        return EXIT_GONE;  // its sockets are gone with it
      if (fd == st->tfd)
        return EXIT_TIMEOUT;
      listened = 1;
    }
    if (!listened)
      continue;
    // The process put *some* socket into LISTEN; is it the port?
    int records = ring_buffer__consume(st->rb);
    if (records < 0)
      goto fail;
    if (verbose)
      fprintf(stderr, "wait-listen: woken: %d ring buffer record(s)\n", records);
    r = check(pid, port);
    if (r != 0)
      return r == 1 ? EXIT_LISTENING : r == -1 ? EXIT_GONE : EXIT_ERROR;
    if (verbose)
      fprintf(stderr, "wait-listen: pid %d listened, but not on port %u yet\n", (int)pid, port);
  }

fail:
  fprintf(stderr, "wait-listen: %s\n", strerror(errno));
  return EXIT_ERROR;
}

int main(int argc, char **argv) {
  static const struct option options[] = {
      {"pid", required_argument, NULL, 'p'},
      {"port", required_argument, NULL, 'P'},
      {"timeout", required_argument, NULL, 't'},
      {"verbose", no_argument, NULL, 'v'},
      {"ready-fd", required_argument, NULL, 'r'},
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
      case 'r': {
        unsigned long fd;
        if (parse_uint(optarg, INT_MAX, &fd))
          goto bad;
        ready_fd = (int)fd;
        break;
      }
      case 'h':
        usage(stdout);
        return EXIT_LISTENING;
      default:
        goto bad;
    }
  }
  if (!have_port || !have_pid || optind != argc)
    goto bad;

  libbpf_set_print(libbpf_log);
  struct state st = {.pidfd = -1, .ep = -1, .tfd = -1, .sfd = -1};
  int status = run(&st, (pid_t)pid, (unsigned)port, timeout);
  teardown(&st);
  return status;

bad:
  usage(stderr);
  return EXIT_USAGE;
}
