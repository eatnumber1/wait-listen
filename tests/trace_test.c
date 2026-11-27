// SPDX-License-Identifier: MIT
// wait-listen's unprivileged mode (--port P -- COMMAND), as an ordinary user:
// each scenario's exit status, and against reality: a client can connect the
// moment it returns 0, the command keeps running untraced, and a command it
// gives up on is killed.
//   trace_test WAIT_LISTEN HELPER
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *wl, *helper;
static int failures;

static unsigned short free_port(void) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t n = sizeof(a);
  if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof(a)) || getsockname(s, (struct sockaddr *)&a, &n))
    exit(99);
  close(s);
  return ntohs(a.sin_port);
}

// Runs wait-listen (bounded by --timeout: a hang fails instead of stalling
// the suite); returns its exit status and the command's pid (--pid-fd).
// ignore_chld: start it with SIGCHLD ignored, as a careless launcher might.
static int run(unsigned short port, const char *timeout, const char *mode, const char *arg, int ignore_chld,
               pid_t *pid) {
  int p[2];
  char sport[8], fd[8];
  if (pipe(p))
    exit(99);
  snprintf(sport, sizeof(sport), "%u", port);
  snprintf(fd, sizeof(fd), "%d", p[1]);
  pid_t w = fork();
  if (w == 0) {
    close(p[0]);
    if (ignore_chld)
      signal(SIGCHLD, SIG_IGN);  // survives exec
    execl(wl, wl, "--port", sport, "--timeout", timeout ? timeout : "30", "--pid-fd", fd, "--", helper, mode,
          arg ? arg : sport, (char *)NULL);
    _exit(98);
  }
  close(p[1]);
  int st;
  waitpid(w, &st, 0);
  char buf[16] = {0};
  ssize_t r = read(p[0], buf, sizeof(buf) - 1);
  close(p[0]);
  *pid = r > 0 ? atoi(buf) : 0;
  return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

// Alive and not a zombie.
static int alive(pid_t pid) {
  char path[64], buf[512];
  snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = 0;
  char *state = strrchr(buf, ')');
  return state && state[2] != 'Z' && state[2] != 'X';
}

// Waits (up to limit_ms, a bound on a hang) for pid to exit: its pidfd
// turns readable then. EXITKILL's SIGKILL is asynchronous, so the command can
// still be dying when wait-listen has exited. Returns 1 once it's gone.
static int exits(pid_t pid, int limit_ms) {
  int fd = (int)syscall(434 /* pidfd_open, the same on every architecture */, pid, 0);
  if (fd < 0)
    return errno == ESRCH;
  struct pollfd p = {.fd = fd, .events = POLLIN};
  int r = poll(&p, 1, limit_ms);
  close(fd);
  return r == 1;
}

// Every thread of pid untraced: the count of traced ones.
static int traced_threads(pid_t pid) {
  char cmd[96];
  snprintf(cmd, sizeof(cmd), "grep -h '^TracerPid:' /proc/%d/task/*/status | grep -vc '\\s0$'", (int)pid);
  FILE *f = popen(cmd, "r");
  int n = -1;
  if (f && fscanf(f, "%d", &n) != 1)
    n = -1;
  if (f)
    pclose(f);
  return n;
}

static int connects(unsigned short port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  int ok = connect(s, (struct sockaddr *)&a, sizeof(a)) == 0;
  char b[2];
  ok = ok && read(s, b, 2) == 2 && !memcmp(b, "hi", 2);
  close(s);
  return ok;
}

static int tracer_of(pid_t pid) {
  char path[64], line[256];
  snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
  FILE *f = fopen(path, "r");
  int t = -1;
  while (f && fgets(line, sizeof(line), f))
    if (!strncmp(line, "TracerPid:", 10))
      t = atoi(line + 10);
  if (f)
    fclose(f);
  return t;
}

static void check(const char *name, int ok, const char *detail) {
  printf("%s %s%s%s\n", ok ? "PASS" : "FAIL", name, detail ? ": " : "", detail ? detail : "");
  failures += !ok;
}

int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  setvbuf(stdout, NULL, _IOLBF, 0);
  wl = argv[1], helper = argv[2];
  pid_t pid;
  char d[128];

  // Listens on another port first, then on the port from a second thread.
  unsigned short port = free_port();
  int st = run(port, NULL, "threads", NULL, 0, &pid);
  snprintf(d, sizeof(d), "exit %d, pid %d", st, (int)pid);
  check("threads: exit 0 with the pid", st == 0 && pid > 0, d);
  check("threads: a client connects at once", connects(port), NULL);
  check("threads: detached (no tracer)", tracer_of(pid) == 0 && traced_threads(pid) == 0, NULL);
  check("threads: still serving", connects(port), NULL);
  if (pid > 0)
    kill(pid, SIGKILL);

  st = run(free_port(), NULL, "exit", NULL, 0, &pid);
  snprintf(d, sizeof(d), "exit %d", st);
  check("exits first: 1", st == 1, d);

  // Gives up: exit 2, and the command is killed with it.
  char pidfile[] = "/tmp/wl-trace-XXXXXX";
  int pf = mkstemp(pidfile);
  if (pf < 0)
    return 99;
  close(pf);
  st = run(free_port(), "1", "never-pidfile", pidfile, 0, &pid);
  FILE *f = fopen(pidfile, "r");
  int helper_pid = 0;
  if (f && fscanf(f, "%d", &helper_pid) != 1)
    helper_pid = 0;
  if (f)
    fclose(f);
  unlink(pidfile);
  snprintf(d, sizeof(d), "exit %d, command pid %d", st, helper_pid);
  check("never listens: timeout 2, command killed", st == 2 && helper_pid > 0 && exits(helper_pid, 30000), d);

  // A forked child's listen isn't seen (documented): times out, and the
  // command (the parent) is killed with wait-listen; its orphaned child goes
  // on until the test's sandbox ends. Also: the pid pipe reaches EOF though
  // that orphan lives on (the command doesn't inherit wait-listen's fds).
  port = free_port();
  st = run(port, "2", "fork", NULL, 0, &pid);
  snprintf(d, sizeof(d), "exit %d", st);
  check("forked child listens: not seen, timeout 2", st == 2, d);

  // The main thread pthread_exit()s first: a zombie leader, which never
  // reports a stop while other threads live (the detach once waited for it).
  port = free_port();
  st = run(port, NULL, "leader-exits", NULL, 0, &pid);
  snprintf(d, sizeof(d), "exit %d, pid %d", st, (int)pid);
  check("leader exits first: exit 0", st == 0 && pid > 0, d);
  check("leader exits first: a client connects", connects(port), NULL);
  check("leader exits first: no thread traced", pid > 0 && traced_threads(pid) == 0, NULL);
  if (pid > 0)
    kill(pid, SIGKILL);

  // Threads keep being cloned while it listens: none may stay traced (with
  // EXITKILL, one would take the whole command down with wait-listen).
  port = free_port();
  st = run(port, NULL, "clone-burst", NULL, 0, &pid);
  snprintf(d, sizeof(d), "exit %d, pid %d", st, (int)pid);
  check("clone burst: exit 0", st == 0 && pid > 0, d);
  int traced = pid > 0 ? traced_threads(pid) : -1;
  snprintf(d, sizeof(d), "%d traced", traced);
  check("clone burst: no thread traced", traced == 0, d);
  check("clone burst: still alive and serving", pid > 0 && alive(pid) && connects(port), NULL);
  if (pid > 0)
    kill(pid, SIGKILL);

  // Started with SIGCHLD ignored: ptrace stops must still reach it.
  port = free_port();
  st = run(port, NULL, "threads", NULL, 1, &pid);
  snprintf(d, sizeof(d), "exit %d", st);
  check("SIGCHLD ignored by the launcher: exit 0", st == 0 && pid > 0 && connects(port), d);
  if (pid > 0)
    kill(pid, SIGKILL);

  printf("%s\n", failures ? "TRACE-TESTS: FAIL" : "TRACE-TESTS: PASS");
  return failures ? 1 : 0;
}
