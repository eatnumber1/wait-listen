// SPDX-License-Identifier: MIT
// Programs for tests/trace_test.c to start under wait-listen's unprivileged
// mode (--port P -- COMMAND):
//   threads PORT  listen on PORT+1 first, then on PORT from a second thread,
//                 then serve "hi" to every connection on PORT
//   exit          exit without listening
//   never         never listen (block)
//   fork PORT     a forked child listens on PORT (not traced: not seen)
//   leader-exits PORT   a second thread listens and serves; the main thread
//                 calls pthread_exit() first (a zombie leader)
//   clone-burst PORT    a thread keeps starting threads while the main
//                 thread listens and serves (a clone right before the detach)
//   never-pidfile PATH  write our pid to PATH, then never listen
#include <arpa/inet.h>
#include <stdio.h>
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

static pthread_t leader;
static unsigned short leader_port;

// Listens only once the main thread has exited: pthread_join returns when
// the kernel has finished that thread's exit (it clears the thread id), so
// the leader is a zombie by the time listen() is called.
static void *after_leader(void *arg) {
  (void)arg;
  pthread_join(leader, NULL);
  serve(listener(leader_port));
  return NULL;
}

static void *idle(void *arg) {
  (void)arg;
  for (;;) pause();
  return NULL;
}

static void *spawner(void *arg) {
  (void)arg;
  for (int i = 0; i < 200; i++) {
    pthread_t t;
    pthread_create(&t, NULL, idle, NULL);
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "leader-exits")) {
    pthread_t t;
    leader = pthread_self();
    leader_port = (unsigned short)atoi(argv[2]);
    pthread_create(&t, NULL, after_leader, NULL);
    pthread_exit(NULL);
  }
  if (argc == 3 && !strcmp(argv[1], "clone-burst")) {
    pthread_t t;
    pthread_create(&t, NULL, spawner, NULL);
    serve(listener((unsigned short)atoi(argv[2])));
  }
  if (argc == 3 && !strcmp(argv[1], "never-pidfile")) {
    FILE *f = fopen(argv[2], "w");
    if (!f)
      return 4;
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
    for (;;) pause();
  }
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
