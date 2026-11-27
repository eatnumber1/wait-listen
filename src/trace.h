// SPDX-License-Identifier: MIT
#ifndef WAIT_LISTEN_TRACE_H
#define WAIT_LISTEN_TRACE_H

// Starts cmd (argv, NULL-terminated) as a traced child and returns once it
// listens on port (0; it keeps running, untraced, and its pid is written to
// pid_fd if >= 0), or 1 if it exits first, 2 on timeout, 5 on error, 6 on a
// signal (in those cases the command is killed). Needs no privileges.
int trace_run(char **cmd, unsigned port, unsigned long timeout, int ready_fd, int pid_fd, int verbose);

#endif
