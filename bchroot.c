#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
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


enum {
CHILD_NO_NEWUIDMAP = 0x01,
CHILD_NO_NEWGIDMAP = 0x02,
CHILD_FATAL = 0x04,
};


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

void pimped_chroot(char* rootfs) {

        char *origpwd;
        char *token, *str;

        if (!(origpwd = get_current_dir_name()))
            FATAL("error calling get_current_dir_name")

        if (-1 == chdir(rootfs))
            FATAL("could not chdir to %s", rootfs)

        //
        // mount stuff
        //
       if (-1 == unshare(CLONE_NEWNS))
                FATAL("could not unshare");
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
}

int parse_subid(const char *file, char **id_str, char **from, char **to){
        FILE *fd;
        struct passwd *pw;
        uid_t uid;
        size_t read, user_size = 0, from_size = 0, to_size = 0;
        char *label = NULL;

        // try to open file
	if (! (fd = fopen(file, "r"))){
                errno = 0;
                return 0;
        }

        // get username and uid
        uid = getuid();
        if (asprintf(id_str, "%d", uid) == -1) FATAL("asprintf")
        pw = getpwuid(uid);
        if (!pw)
                FATAL("could not find uid/gid")

        // parse it
        for (;;){
                if ((read = getdelim(&label, &user_size, ':', fd)) == -1) break;
                label[read-1] = 0;
                if ((read = getdelim(from, &from_size, ':', fd)) == -1) break;
                (*from)[read-1] = 0;
                if ((read = getdelim(to, &to_size, '\n', fd)) == -1) break;
                (*to)[read-1] = 0;

                if (0 == strcmp(pw->pw_name, label) || 0 == strcmp(*id_str, label)){
                        return 1;
                }
        }
        return 0;
}


void setup_user_ns(){
        int child_exit = 0;
        int sig;
        int status;
        pid_t child;
        int found_subuid, found_subgid;
        siginfo_t sinfo;

        char *uid_from = NULL;
        char *uid_str = NULL;
        char *uid_to = NULL;

        char *gid_from = NULL;
        char *gid_to = NULL;
        char *gid_str = NULL;

        found_subuid = parse_subid("/etc/subuid", &uid_str, &uid_from, &uid_to);
        found_subgid = parse_subid("/etc/subgid", &gid_str, &gid_from, &gid_to);

        char *pid_str;
        if (asprintf(&pid_str, "%d", getpid()) == -1) FATAL("asprintf");

        sigset_t sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGUSR1);
        sigprocmask(SIG_BLOCK, &sigset, NULL);

        if (-1 == (child = fork())) FATAL("fork")
        if (!child){
                sigwait(&sigset, &sig);


                child = fork();
                if (-1 == child) FATAL("fork");
                if (0 == child){
                        execlp("newuidmap", "newuidmap",
                                 pid_str, "0", uid_str, "1",
                                 "1", uid_from, uid_to, NULL);
                        if (errno == ENOENT) exit(127);
                        FATAL("execlp");
                }

                child = fork();
                if (-1 == child) FATAL("fork");
                if (0 == child){
                        sleep(1);
                        execlp("newgidmap", "newgidmap",
                                        pid_str, "0", gid_str, "1",
                                        "1", gid_from, gid_to, NULL);
                        if (errno == ENOENT) exit(127);
                        FATAL("execlp");
                }

                // wait for last forked child - the one that spawn newgidmap
                if (-1 == waitid(P_PID, child, &sinfo, WEXITED)) FATAL("waitid");
                switch (sinfo.si_status){
                        case 0: break;
                        case 127: child_exit |= CHILD_NO_NEWGIDMAP; break;
                        default: child_exit |= CHILD_FATAL; break;
                }

                // wait for the other one, that is newuidmap
                if (-1 == waitid(P_ALL, 0, &sinfo, WEXITED)) FATAL("waitid");
                switch (sinfo.si_status){
                        case 0: break;
                        case 127: child_exit |= CHILD_NO_NEWUIDMAP; break;
                        default: child_exit |= CHILD_FATAL; break;
                }


                exit(child_exit);
               
        }

        if (-1 == unshare(CLONE_NEWUSER)){
                        FATAL("could not unshare user namespace");
        }

        kill(child, SIGUSR1);
        if (-1 == waitid(P_PID, child, &sinfo, WEXITED)) FATAL("waitid");

        if (sinfo.si_status & CHILD_NO_NEWUIDMAP){
                if (!printf_file("/proc/self/uid_map", "0 %u 1\n", getuid())){
                        FATAL("could not open /proc/self/uid_map")
                }
        }
        if (sinfo.si_status  & CHILD_NO_NEWGIDMAP){
                if (!printf_file("/proc/self/setgroups", "deny")){
                        if (errno != ENOENT) 
                                FATAL("could not open /proc/self/setgroups");
                };
                if (!printf_file("/proc/self/gid_map", "0 %u 1\n", getgid())){
                        FATAL("could not open /proc/self/gid_map")
                }
        }
        if (sinfo.si_status & CHILD_FATAL){
                // error message comes from child
                FATAL("child died");
        }

        free(uid_from);
        free(uid_to);
        free(uid_str);
        free(gid_from);
        free(gid_to);
        free(gid_str);
}


int main(int argc, char* argv[]) {

	// basename destructs argv[0], that is ok because we overwrite it in
	// every case
	char *binaryname = basename(argv[0]);
        char *rootfs;

        argv[0] = binaryname;
        if (NULL == (rootfs = realpath("/proc/self/exe", NULL)))
            FATAL("could not call realpath(\"/proc/self/exe\")");
        if (-1 == asprintf(&rootfs, "%s/rootfs", dirname(rootfs)))
            FATAL("asprintf")

       setup_user_ns();
	pimped_chroot(rootfs);

        if (-1 == execvp(argv[0], argv))
                FATAL("could not exec %s in %s", argv[0], rootfs);
}
