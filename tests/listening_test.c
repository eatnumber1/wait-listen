// SPDX-License-Identifier: MIT
// listens_on() against fixture /proc trees.
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "listening.h"

static int failures;

#define EXPECT(cond, ...)                          \
  do {                                             \
    if (!(cond)) {                                 \
      fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
      fprintf(stderr, __VA_ARGS__);                \
      fputc('\n', stderr);                         \
      failures++;                                  \
    }                                              \
  } while (0)

static const char *HEADER =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
static const char *HEADER6 =
    "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

static char root[PATH_MAX];

static void write_file(const char *rel, const char *content) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/%s", root, rel);
  FILE *f = fopen(path, "w");
  if (!f || fputs(content, f) < 0 || fclose(f)) {
    perror(path);
    exit(2);
  }
}

static void mk(const char *rel) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/%s", root, rel);
  if (mkdir(path, 0755) && errno != EEXIST) {
    perror(path);
    exit(2);
  }
}

static void fd_link(int pid, int fd, const char *target) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/%d/fd/%d", root, pid, fd);
  if (symlink(target, path)) {
    perror(path);
    exit(2);
  }
}

// A process pid with the given tcp and tcp6 tables and fd links.
static void proc(int pid, const char *tcp, const char *tcp6) {
  char rel[64];
  snprintf(rel, sizeof(rel), "%d", pid);
  mk(rel);
  snprintf(rel, sizeof(rel), "%d/net", pid);
  mk(rel);
  snprintf(rel, sizeof(rel), "%d/fd", pid);
  mk(rel);
  char buf[4096];
  snprintf(rel, sizeof(rel), "%d/net/tcp", pid);
  snprintf(buf, sizeof(buf), "%s%s", HEADER, tcp);
  write_file(rel, buf);
  if (tcp6) {
    snprintf(rel, sizeof(rel), "%d/net/tcp6", pid);
    snprintf(buf, sizeof(buf), "%s%s", HEADER6, tcp6);
    write_file(rel, buf);
  }
}

int main(void) {
  snprintf(root, sizeof(root), "%s/listening_test.XXXXXX", getenv("TEST_TMPDIR") ? getenv("TEST_TMPDIR") : "/tmp");
  if (!mkdtemp(root)) {
    perror("mkdtemp");
    return 2;
  }

  // 9105 = 0x2391. Lines as the kernel writes them (real captures, inodes changed).
  const char *v4_listen_9105 =
      "   0: 0100007F:2391 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0\n";
  const char *v4_estab_9105 =
      "   1: 0100007F:2391 0100007F:D3A2 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 20 4 30 10 -1\n";
  const char *v4_listen_9104 =
      "   2: 00000000:2390 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000000000000000 100 0 0 10 0\n";
  const char *v6_listen_9105 =
      "   0: 00000000000000000000000001000000:2391 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1004 1 0000000000000000 100 0 0 10 0\n";

  // 100: listening on 9105 over IPv4, with the socket among its fds.
  proc(100, v4_listen_9105, "");
  fd_link(100, 3, "socket:[1001]");
  fd_link(100, 4, "/dev/null");
  EXPECT(listens_on(root, 100, 9105) == 1, "IPv4 listener");
  EXPECT(listens_on(root, 100, 9104) == 0, "other port");

  // 101: only IPv6.
  proc(101, "", v6_listen_9105);
  fd_link(101, 5, "socket:[1004]");
  EXPECT(listens_on(root, 101, 9105) == 1, "IPv6 listener");

  // 102: the namespace has a listener on 9105, but it's another process's
  // socket (not among 102's fds): not 102 listening.
  proc(102, v4_listen_9105, "");
  fd_link(102, 3, "socket:[9999]");
  EXPECT(listens_on(root, 102, 9105) == 0, "someone else's listener");

  // 103: connected (not listening) on 9105, listening on 9104.
  {
    char both[1024];
    snprintf(both, sizeof(both), "%s%s", v4_estab_9105, v4_listen_9104);
    proc(103, both, NULL);  // no tcp6 file: a namespace without IPv6
  }
  fd_link(103, 3, "socket:[1002]");
  fd_link(103, 4, "socket:[1003]");
  EXPECT(listens_on(root, 103, 9105) == 0, "established isn't listening");
  EXPECT(listens_on(root, 103, 9104) == 1, "listening on 9104, no tcp6 file");

  // 104: gone.
  errno = 0;
  EXPECT(listens_on(root, 104, 9105) == -1 && errno == ESRCH, "missing process: -1/ESRCH (errno %d)", errno);

  if (failures)
    fprintf(stderr, "%d failure(s); fixtures left in %s\n", failures, root);
  else
    printf("ok\n");
  return failures ? 1 : 0;
}
