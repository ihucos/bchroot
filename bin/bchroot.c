
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "brtlib.h"

#define OPT "hu:g:n:m:e:E:"

void usage(){
    puts("USAGE: bchroot <options> rootfs cmd");
    puts("HINT: most options fail silently, debug with strace");
    puts("OPTIONS:");
    puts("-u uid: setuid");
    puts("-g gid: setgid");
    puts("-m dir: mount from host");
    puts("-e var: import this variable");
    puts("-E var: import all variables in this variable");
    puts("-n: don't unshare user namepsace");
}

int main (int argc, char **argv) {
  char **exec_argv;
  char *bindto;
  char *rootfs;
  int c;
  int has_env = 0;
  int has_mount = 0;
  int no_user_ns = 0;
  gid_t gid = 0;
  uid_t uid = 0;

  while ((c = getopt (argc, argv, OPT)) != -1)
    switch (c) {
      case 'h':
        usage();
        return 1;
      case 'u':
        uid = (uid_t) strtol(optarg, NULL, 10);
        break;
      case 'g':
        gid = (gid_t) strtol(optarg, NULL, 10);
        break;
      case 'n':
        no_user_ns = 1;
        break;
      case 'm':
        has_mount = 1;
        break;
      case 'e':
        has_env = 1;
        break;
      case 'E':
        has_env = 1;
        break;
      case '?':
        break;
    }
  if (! (rootfs = argv[optind])){
      usage();
      return 1;
  }
  exec_argv = argv + optind + 1;
  if (!*exec_argv){
      usage();
      return 1;
  }
  optind = 1;

  if (!no_user_ns){
      if (getuid()) brt_setup_user_ns();
  }
  if (has_mount) {
    brt_setup_mount_ns();
  }

  while ((c = getopt (argc, argv, OPT)) != -1)
    switch (c)
      {
      case 'e':
          brt_whitelist_env(optarg);
          break;
      case 'E':
          brt_whitelist_envs_from_env(optarg);
          break;
      case 'm':
        if (-1 == asprintf(&bindto, "%s/%s", rootfs, optarg)){
            perror("asprintf");
            return 1;
        }
        brt_bind_mount(optarg, bindto);
        break;
      case '?':
        break;

      case ':':
        puts("missing parameter");
        return 1;
      }

  if (has_env) brt_whitelist_env(NULL);

  brt_chroot(rootfs);

  if (gid) setgid(gid);
  if (uid) setuid(uid);

  execvp(exec_argv[0], exec_argv);
  fprintf(stderr, "execvp %s\n", exec_argv[0]);
  perror("");
  return 1;
}
