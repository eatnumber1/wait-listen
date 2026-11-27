// SPDX-License-Identifier: MIT
// wait-listen's unprivileged mode: start COMMAND as our child, trace its
// system calls (ptrace: any user may trace their own child), and once a
// listen() by any of its threads has returned with the process listening on
// the port, detach from every thread and leave it running.
//
// Like the BPF mode, it reacts to the listen() itself, after it returned (the
// socket is hashed by then), and checks /proc for the port; nothing polls:
// waitpid() reports each stop, and epoll waits on a signalfd (SIGCHLD and
// the stopping signals) and the optional timer.
//
// Syscall stops are read with PTRACE_GET_SYSCALL_INFO (Linux 5.3), so no
// register layout; the syscall number is the libc's for the architecture.
#define _GNU_SOURCE
#include "trace.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include "listening.h"

// Exit statuses (as main.c's).
enum { T_LISTENING = 0, T_GONE = 1, T_TIMEOUT = 2, T_ERROR = 5, T_SIGNAL = 6 };

#define MAX_THREADS 4096

struct thread {
  pid_t tid;
  int in_listen;  // stopped at, or running, a listen() entry
};

static struct thread threads[MAX_THREADS];
static int nthreads;

static long pt(long request, pid_t tid, unsigned long addr, unsigned long data) {
  return syscall(SYS_ptrace, request, tid, addr, data);
}

static struct thread *find(pid_t tid) {
  for (int i = 0; i < nthreads; i++)
    if (threads[i].tid == tid)
      return &threads[i];
  return NULL;
}

static struct thread *add(pid_t tid) {
  struct thread *t = find(tid);
  if (t)
    return t;
  if (nthreads == MAX_THREADS)
    return NULL;
  threads[nthreads] = (struct thread){.tid = tid};
  return &threads[nthreads++];
}

static void forget(pid_t tid) {
  for (int i = 0; i < nthreads; i++)
    if (threads[i].tid == tid) {
      threads[i] = threads[--nthreads];
      return;
    }
}

// The signal a stop is delivering (0 for ptrace's own stops).
static int delivered(int status) {
  int sig = WSTOPSIG(status);
  if (sig == (SIGTRAP | 0x80) || (status >> 16) != 0)
    return 0;  // a syscall stop or a PTRACE_EVENT stop
  return sig;
}

// Detaches from every thread; `stopped` is in a stop now. Running threads
// are interrupted, and each detached as it reports its stop (still events).
static int detach_all(pid_t stopped, int status) {
  pt(PTRACE_DETACH, stopped, 0, (unsigned long)delivered(status));
  forget(stopped);
  for (int i = 0; i < nthreads; i++)
    pt(PTRACE_INTERRUPT, threads[i].tid, 0, 0);
  while (nthreads) {
    int st;
    pid_t tid = waitpid(-1, &st, __WALL);
    if (tid < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (WIFSTOPPED(st))
      pt(PTRACE_DETACH, tid, 0, (unsigned long)delivered(st));
    forget(tid);
  }
  return 0;
}

int trace_run(char **cmd, unsigned port, unsigned long timeout, int ready_fd, int pid_fd, int verbose) {
  // The signals epoll waits for; the child gets the original mask back.
  sigset_t mask, old;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGHUP);
  if (sigprocmask(SIG_BLOCK, &mask, &old))
    goto fail;
  int sfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
  int ep = epoll_create1(EPOLL_CLOEXEC);
  int go[2];
  if (sfd < 0 || ep < 0 || pipe2(go, O_CLOEXEC))
    goto fail;
  struct epoll_event ev = {.events = EPOLLIN, .data.fd = sfd};
  if (epoll_ctl(ep, EPOLL_CTL_ADD, sfd, &ev))
    goto fail;
  int tfd = -1;
  if (timeout) {
    struct itimerspec its = {.it_value = {.tv_sec = (time_t)timeout}};
    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    ev.data.fd = tfd;
    if (tfd < 0 || timerfd_settime(tfd, 0, &its, NULL) || epoll_ctl(ep, EPOLL_CTL_ADD, tfd, &ev))
      goto fail;
  }

  pid_t child = fork();
  if (child < 0)
    goto fail;
  if (child == 0) {
    // Wait until the parent traces us, so the exec is traced too.
    char b;
    close(go[1]);
    // wait-listen's own reporting descriptors aren't the command's: held
    // open by it (or a process it forks), they would never reach EOF.
    if (pid_fd >= 0)
      close(pid_fd);
    if (ready_fd >= 0)
      close(ready_fd);
    sigprocmask(SIG_SETMASK, &old, NULL);
    if (read(go[0], &b, 1) != 1)
      _exit(127);
    execvp(cmd[0], cmd);
    fprintf(stderr, "wait-listen: %s: %s\n", cmd[0], strerror(errno));
    _exit(127);
  }
  close(go[0]);
  // EXITKILL: should wait-listen die while tracing, the command dies with it
  // (a start that can't be confirmed fails). After the detach it's unaffected.
  if (pt(PTRACE_SEIZE, child, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL)) {
    int e = errno;
    kill(child, SIGKILL);
    fprintf(stderr, "wait-listen: tracing %s: %s\n", cmd[0], strerror(e));
    return T_ERROR;
  }
  // Stop it (it's blocked reading the pipe), so its next system calls,
  // execve first, report to us; then let it go on.
  if (pt(PTRACE_INTERRUPT, child, 0, 0) || !add(child) || write(go[1], "g", 1) != 1)
    goto fail;
  close(go[1]);
  if (ready_fd >= 0) {
    if (write(ready_fd, "r", 1) != 1)
      goto fail;
    close(ready_fd);
  }
  if (verbose)
    fprintf(stderr, "wait-listen: started %s as pid %d, waiting for port %u\n", cmd[0], (int)child, port);

  for (;;) {
    struct epoll_event got[2];
    int n = epoll_wait(ep, got, 2, -1);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      goto fail;
    }
    for (int i = 0; i < n; i++) {
      if (got[i].data.fd == tfd)
        return T_TIMEOUT;  // EXITKILL takes the command with us
      struct signalfd_siginfo si;
      while (read(sfd, &si, sizeof(si)) == sizeof(si)) {
        if (si.ssi_signo != SIGCHLD)
          return T_SIGNAL;
      }
    }
    // Every stop and exit there is now (SIGCHLD only says "some").
    for (;;) {
      int st;
      pid_t tid = waitpid(-1, &st, __WALL | WNOHANG);
      if (tid == 0 || (tid < 0 && errno == ECHILD))
        break;
      if (tid < 0) {
        if (errno == EINTR)
          continue;
        goto fail;
      }
      if (WIFEXITED(st) || WIFSIGNALED(st)) {
        forget(tid);
        if (tid == child)
          return T_GONE;  // never listened on the port
        continue;
      }
      struct thread *t = add(tid);  // a new thread may report before its clone event
      if (!t)
        goto fail;
      int sig = WSTOPSIG(st);
      if (sig == (SIGTRAP | 0x80)) {
        struct ptrace_syscall_info info;
        if (pt(PTRACE_GET_SYSCALL_INFO, tid, sizeof(info), (unsigned long)&info) < 0)
          goto fail;
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
          t->in_listen = info.entry.nr == SYS_listen;
        } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && t->in_listen) {
          t->in_listen = 0;
          if (!info.exit.is_error) {
            int r = listens_on("/proc", child, port);
            if (r == 1) {
              if (detach_all(tid, st))
                goto fail;
              if (verbose)
                fprintf(stderr, "wait-listen: pid %d listens on port %u\n", (int)child, port);
              if (pid_fd >= 0) {
                dprintf(pid_fd, "%d\n", (int)child);
                close(pid_fd);
              }
              return T_LISTENING;
            }
            if (verbose && r == 0)
              fprintf(stderr, "wait-listen: pid %d listened, but not on port %u yet\n", (int)child, port);
          }
        }
        sig = 0;
      } else if ((st >> 16) != 0) {
        sig = 0;  // clone, interrupt or group stop: nothing to deliver
      }
      // Resume, delivering the signal it was stopped for (if any).
      if (pt(PTRACE_SYSCALL, tid, 0, (unsigned long)sig) && errno != ESRCH)
        goto fail;
    }
  }

fail:
  fprintf(stderr, "wait-listen: %s\n", strerror(errno));
  return T_ERROR;
}
