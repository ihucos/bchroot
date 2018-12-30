#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>

#define FATAL(...) {\
fprintf(stderr, "%s", "bchroot: ");\
fprintf(stderr, __VA_ARGS__);\
if (errno != 0){\
        fprintf(stderr, ": %s", strerror(errno));\
}\
fprintf(stderr, "\n");\
exit(1);\
}

#define PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define RBIND(src) {\
if (-1 == mount(src, "." src, "none", MS_MGC_VAL|MS_BIND|MS_REC, NULL)) \
        if (errno != ENOENT){ \
                FATAL("could not mount %s to %s%s", src, get_current_dir_name(), src); \
        } \
}

int printf_file(char *file, char *format, ...){
        FILE *fd;
	if (! (fd = fopen(file, "w")))
                return 0;
        va_list args;
        va_start(args, format);
        vfprintf(fd, format, args);
        va_end(args);
        if (errno)
                FATAL("could not write to %s", file);
        fclose(fd);
        return 1;
}

void whitelist_env(char *env_name){
        char *n, *v;
        static size_t env_counter = 0;
        if (!env_name)
                environ[env_counter++] = NULL;
        else{
                for(size_t i=env_counter; environ[i]; i++){
                        for(
                                        n = env_name, v = environ[i];
                                        *n && *v && *n == *v;
                                        n++, v++);
                        if (*v == '=' && *n == 0)
                                environ[env_counter++] = environ[i];
                }
        }
}

void setup_namespace(){
        uid_t uid = getuid();
        gid_t gid = getgid();
        if (uid == 0){
                if (-1 == unshare(CLONE_NEWNS))
                        FATAL("could not unshare");
        } else {
                if (-1 == unshare(CLONE_NEWNS | CLONE_NEWUSER))
                        FATAL("could not unshare");

                if (!printf_file("/proc/self/setgroups", "deny")){
                        if (errno != ENOENT) 
                                FATAL("could not open /proc/self/setgroups");
                };
                if (!printf_file("/proc/self/uid_map", "0 %u 1\n", uid)){
                        FATAL("could not open /proc/self/uid_map")
                }
                if (!printf_file("/proc/self/gid_map", "0 %u 1\n", gid)){
                        FATAL("could not open /proc/self/gid_map")
                }
        }
}

void bchroot(char* rootfs, char* cmd[]) {

        setup_namespace();

        char *origpwd;
        if (!(origpwd = get_current_dir_name()))
            FATAL("error calling get_current_dir_name")

        if (-1 == chdir(rootfs))
            FATAL("could not chdir to %s", rootfs)

        //
        // mount stuff
        //

        if (-1 == mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL))

            // ignore errno as it happens inside a chroot
            if (errno != EINVAL){
                FATAL("could not change propagation of /");
            } else {
                errno = 0;
            }
        RBIND("/dev");
        RBIND("/home");
        RBIND("/proc");
        RBIND("/root");
        RBIND("/sys");
        RBIND("/tmp");
        RBIND("/etc/resolv.conf"); // FIXME: check what happens if it's a symlink

        if (-1 == chroot("."))
                FATAL("could not chroot to %s", rootfs);

        if (-1 == chdir(origpwd)){
                if (-1 == chdir("/"))
                        FATAL("could not chdir")
        }

        char *token, *str;
        if (str = getenv("BCHROOT_EXPORT")) {
                str = strdup(str);
                token = strtok(str, ":");
                while(token){
                   whitelist_env(token);
                   token = strtok(NULL, ":");
                }
                free(str);
        }
        whitelist_env("TERM");
        whitelist_env("DISPLAY");
        whitelist_env("HOME");
	putenv("PATH=" PATH);
        whitelist_env("PATH");
        whitelist_env(NULL);

        if (-1 == execvp(cmd[0], cmd))
                FATAL("could not exec %s in %s", cmd[0], rootfs);
}

int main(int argc, char* argv[]) {
        setbuf(stdout, NULL); // why, remove? I think it was for debugging

	// basename destructs argv[0], that is ok because we overwrite it in
	// every case
	char *binaryname = basename(argv[0]);
        char *rootfs;

        if (0 == strcmp(binaryname, "bchroot")){
            if (argc <= 1){
                fprintf(stderr, "usage: bchroot ROOTFS [CMD1 [CMD2 ...]]\n");
                exit(EXIT_FAILURE);
            } else if (argc <= 2){
		rootfs = argv[1];
		argv[0] = "/bin/bash";
		argv[1] = NULL;
	    } else {
	    	argv++;
                rootfs = *argv++;
	    }
        } else {
	    argv[0] = binaryname;
	    if (NULL == (rootfs = realpath("/proc/self/exe", NULL)))
            	FATAL("could not call realpath(\"/proc/self/exe\")");
            if (-1 == asprintf(&rootfs, "%s/rootfs", dirname(rootfs)))
	    	FATAL("could not call asprintf (out of memory?)")
        }

	bchroot(rootfs, argv);
}
