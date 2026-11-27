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
#include <sys/socket.h>
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

// Runs wait-listen; returns its exit status and the command's pid (--pid-fd).
static int run(unsigned short port, const char *timeout, const char *mode, pid_t *pid) {
  int p[2];
  char sport[8], fd[8];
  if (pipe(p))
    exit(99);
  snprintf(sport, sizeof(sport), "%u", port);
  snprintf(fd, sizeof(fd), "%d", p[1]);
  pid_t w = fork();
  if (w == 0) {
    close(p[0]);
    if (timeout)
      execl(wl, wl, "--port", sport, "--timeout", timeout, "--pid-fd", fd, "--", helper, mode, sport, (char *)NULL);
    execl(wl, wl, "--port", sport, "--pid-fd", fd, "--", helper, mode, sport, (char *)NULL);
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
  int st = run(port, NULL, "threads", &pid);
  snprintf(d, sizeof(d), "exit %d, pid %d", st, (int)pid);
  check("threads: exit 0 with the pid", st == 0 && pid > 0, d);
  check("threads: a client connects at once", connects(port), NULL);
  check("threads: detached (no tracer)", tracer_of(pid) == 0, NULL);
  check("threads: still serving", connects(port), NULL);
  if (pid > 0)
    kill(pid, SIGKILL);

  st = run(free_port(), NULL, "exit", &pid);
  snprintf(d, sizeof(d), "exit %d", st);
  check("exits first: 1", st == 1, d);

  st = run(free_port(), "1", "never", &pid);
  snprintf(d, sizeof(d), "exit %d", st);
  check("never listens: timeout 2", st == 2, d);

  // A forked child's listen isn't seen (documented): times out, and the
  // command (the parent) is killed with wait-listen; its orphaned child goes
  // on until the test's sandbox ends. Also: the pid pipe reaches EOF though
  // that orphan lives on (the command doesn't inherit wait-listen's fds).
  port = free_port();
  st = run(port, "2", "fork", &pid);
  snprintf(d, sizeof(d), "exit %d", st);
  check("forked child listens: not seen, timeout 2", st == 2, d);

  printf("%s\n", failures ? "TRACE-TESTS: FAIL" : "TRACE-TESTS: PASS");
  return failures ? 1 : 0;
}
