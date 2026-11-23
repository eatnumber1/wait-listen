// SPDX-License-Identifier: MIT
#ifndef WAIT_LISTEN_LISTENING_H_
#define WAIT_LISTEN_LISTENING_H_

#include <sys/types.h>

// Does process pid have a TCP socket listening on port (IPv4 or IPv6), in its
// own network namespace? proc is the procfs mount ("/proc"; tests pass a
// fixture tree). Returns 1 (yes), 0 (no), -1 with errno set on error (ESRCH:
// the process is gone).
int listens_on(const char *proc, pid_t pid, unsigned port);

#endif
