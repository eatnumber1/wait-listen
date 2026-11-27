// SPDX-License-Identifier: MIT
// Programs for tests/trace_test.c to start under wait-listen's unprivileged
// mode (--port P -- COMMAND):
//   threads PORT  listen on PORT+1 first, then on PORT from a second thread,
//                 then serve "hi" to every connection on PORT
//   exit          exit without listening
//   never         never listen (block)
//   fork PORT     a forked child listens on PORT (not traced: not seen)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int listener(unsigned short port) {
  int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                          .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof(a)) || listen(s, 8))
    _exit(3);
  return s;
}

static void serve(int s) {
  for (;;) {
    int c = accept(s, NULL, NULL);
    if (c >= 0) {
      if (write(c, "hi", 2) != 2) {}
      close(c);
    }
  }
}

static void *second(void *arg) {
  serve(listener((unsigned short)(unsigned long)arg));
  return NULL;
}

int main(int argc, char **argv) {
  if (argc >= 2 && !strcmp(argv[1], "exit"))
    return 0;
  if (argc >= 2 && !strcmp(argv[1], "never"))
    for (;;) pause();
  if (argc == 3 && !strcmp(argv[1], "threads")) {
    unsigned short port = (unsigned short)atoi(argv[2]);
    listener(port + 1);
    pthread_t t;
    pthread_create(&t, NULL, second, (void *)(unsigned long)port);
    pthread_join(t, NULL);
  }
  if (argc == 3 && !strcmp(argv[1], "fork")) {
    if (fork() == 0)
      serve(listener((unsigned short)atoi(argv[2])));
    for (;;) pause();
  }
  return 2;
}
