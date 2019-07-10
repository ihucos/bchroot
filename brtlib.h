#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>


char* brt_path(const char *relpath);

void brt_whitelist_env(char *env_name);

void brt_setup_user_ns();

int brt_fatal(char *format, ...);

void brt_whitelist_envs_from_env(const char *export_env);

void brt_bind_mount(const char* src, const char* dst);

void brt_setup_mount_ns();
