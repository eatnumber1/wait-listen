// SPDX-License-Identifier: MIT
// mkcpio OUT NAME=PATH...: writes an initramfs (cpio "newc") holding each
// PATH as /NAME, mode 0755, owned by root, mtime 0: reproducible, and no
// host cpio needed.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *what, const char *arg) {
  fprintf(stderr, "mkcpio: %s %s: %s\n", what, arg, strerror(errno));
  exit(1);
}

static void pad(FILE *out, long n) {
  while (n++ % 4)
    fputc(0, out);
}

static void entry(FILE *out, unsigned ino, unsigned mode, const char *name, const unsigned char *data,
                  size_t size) {
  size_t namesize = strlen(name) + 1;
  // magic, ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
  // rdevmajor, rdevminor, namesize, check
  fprintf(out, "070701%08X%08X%08X%08X%08X%08X%08zX%08X%08X%08X%08X%08zX%08X", ino, mode, 0, 0, 1, 0, size, 0,
          0, 0, 0, namesize, 0);
  fwrite(name, 1, namesize, out);
  pad(out, 110 + (long)namesize);
  if (size) {
    fwrite(data, 1, size, out);
    pad(out, (long)size);
  }
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: mkcpio OUT NAME=PATH...\n");
    return 2;
  }
  FILE *out = fopen(argv[1], "wb");
  if (!out)
    die("opening", argv[1]);
  for (int i = 2; i < argc; i++) {
    char *eq = strchr(argv[i], '=');
    if (!eq || eq == argv[i]) {
      fprintf(stderr, "mkcpio: not NAME=PATH: %s\n", argv[i]);
      return 2;
    }
    *eq = '\0';
    FILE *in = fopen(eq + 1, "rb");
    if (!in)
      die("opening", eq + 1);
    unsigned char *buf = NULL;
    size_t len = 0, cap = 0, n;
    do {
      if (len == cap && !(buf = realloc(buf, cap = cap ? cap * 2 : 1 << 20)))
        die("reading", eq + 1);
      n = fread(buf + len, 1, cap - len, in);
      len += n;
    } while (n);
    if (ferror(in))
      die("reading", eq + 1);
    fclose(in);
    entry(out, (unsigned)i, 0100755, argv[i], buf, len);
    free(buf);
  }
  entry(out, 0, 0, "TRAILER!!!", NULL, 0);
  if (fclose(out))
    die("writing", argv[1]);
  return 0;
}
