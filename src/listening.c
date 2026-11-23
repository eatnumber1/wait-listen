// SPDX-License-Identifier: MIT
#include "listening.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TCP_LISTEN_HEX 0x0A
#define MAX_INODES 256

// Appends to inodes the inodes of sockets listening on port in one
// /proc/PID/net/tcp{,6} file. Returns the new count, or -1.
static int listening_inodes(const char *path, unsigned port, unsigned long *inodes, int n) {
  FILE *f = fopen(path, "re");
  if (!f)
    return errno == ENOENT ? n : -1;  // no IPv6 in this namespace: fine
  char line[512];
  if (!fgets(line, sizeof(line), f)) {  // header
    fclose(f);
    return n;
  }
  while (fgets(line, sizeof(line), f)) {
    // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
    char local[64];
    unsigned st;
    unsigned long inode;
    if (sscanf(line, " %*s %63s %*s %x %*s %*s %*s %*s %*s %lu", local, &st, &inode) != 3)
      continue;
    char *colon = strrchr(local, ':');
    if (!colon || st != TCP_LISTEN_HEX)
      continue;
    if (strtoul(colon + 1, NULL, 16) != port)
      continue;
    if (n < MAX_INODES)
      inodes[n++] = inode;
  }
  int err = ferror(f);
  fclose(f);
  if (err) {
    errno = EIO;
    return -1;
  }
  return n;
}

int listens_on(const char *proc, pid_t pid, unsigned port) {
  char path[PATH_MAX];
  unsigned long inodes[MAX_INODES];
  int n = 0;
  static const char *const files[] = {"tcp", "tcp6"};
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    snprintf(path, sizeof(path), "%s/%d/net/%s", proc, (int)pid, files[i]);
    n = listening_inodes(path, port, inodes, n);
    if (n < 0)
      return -1;
  }
  snprintf(path, sizeof(path), "%s/%d/fd", proc, (int)pid);
  DIR *d = opendir(path);
  if (!d) {
    if (errno == ENOENT)
      errno = ESRCH;
    return -1;
  }
  if (n == 0) {
    closedir(d);
    return 0;
  }
  int found = 0;
  struct dirent *e;
  while (!found && (e = readdir(d))) {
    if (e->d_name[0] == '.')
      continue;
    char link[64], target[64];
    snprintf(link, sizeof(link), "%.20s", e->d_name);
    char fdpath[PATH_MAX];
    snprintf(fdpath, sizeof(fdpath), "%s/%s", path, link);
    ssize_t len = readlink(fdpath, target, sizeof(target) - 1);
    if (len < 0)
      continue;  // closed meanwhile
    target[len] = '\0';
    unsigned long inode;
    if (sscanf(target, "socket:[%lu]", &inode) != 1)
      continue;
    for (int i = 0; i < n; i++)
      if (inodes[i] == inode)
        found = 1;
  }
  closedir(d);
  return found;
}
