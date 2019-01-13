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


#define PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define RBIND(src) {\
if (-1 == mount(src, "." src, "none", MS_MGC_VAL|MS_BIND|MS_REC, NULL)) \
        if (errno != ENOENT){ \
                brt_fatal("could not mount %s to %s%s", src, get_current_dir_name(), src); \
        } \
}


enum {
SETUP_NO_UID = 0x01,
SETUP_NO_GID = 0x02,
SETUP_ERROR = 0x04,
};

typedef struct {
        char *prog;
        char *id_str;
        char *pid_str;
        char *file;
        char *query1;
        char *query2;

} fork_exec_newmap_t;


int brt_fatal(char *format, ...){
        va_list args;
        va_start(args, format);
        va_end(args);
        fprintf(stderr, "bchroot: ");
        vfprintf(stderr, format, args);
        if (errno != 0) fprintf(stderr, ": %s", strerror(errno));
        fprintf(stderr, "\n");
        exit(1);
}

int brt_printf_file(char *file, char *format, ...){
        FILE *fd;
	if (! (fd = fopen(file, "w")))
                return 0;
        va_list args;
        va_start(args, format);
        vfprintf(fd, format, args);
        va_end(args);
        if (errno)
                brt_fatal("could not write to %s", file);
        fclose(fd);
        return 1;
}

void brt_whitelist_env(char *env_name){
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

void brt_chroot(char* rootfs) {

        char *origpwd;
        char *token, *str;

        if (!(origpwd = get_current_dir_name()))
            brt_fatal("error calling get_current_dir_name");

        if (-1 == chdir(rootfs))
            brt_fatal("could not chdir to %s", rootfs);

        //
        // mount stuff
        //
       if (-1 == unshare(CLONE_NEWNS))
                brt_fatal("could not unshare");
        if (-1 == mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL))

            // ignore errno as it happens inside a chroot
            if (errno != EINVAL){
                brt_fatal("could not change propagation of /");
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
                brt_fatal("could not chroot to %s", rootfs);

        if (-1 == chdir(origpwd)){
                if (-1 == chdir("/"))
                        brt_fatal("could not chdir");
        }

        if (str = getenv("BCHROOT_EXPORT")) {
                str = strdup(str);
                token = strtok(str, ":");
                while(token){
                   brt_whitelist_env(token);
                   token = strtok(NULL, ":");
                }
                free(str);
        }
        brt_whitelist_env("TERM");
        brt_whitelist_env("DISPLAY");
        brt_whitelist_env("HOME");
	putenv("PATH=" PATH);
        brt_whitelist_env("PATH");
        brt_whitelist_env(NULL);
}

int brt_parse_subid(const char *file, const char *query1, const char *query2, char **from, char **to){
        FILE *fd;
        size_t read, user_size = 0, from_size = 0, to_size = 0;
        char *label = NULL;

        // try to open file
	if (! (fd = fopen(file, "r"))){
                errno = 0;
                return 0;
        }

        // parse it
        for (;;){
                if ((read = getdelim(&label, &user_size, ':', fd)) == -1) break;
                label[read-1] = 0;
                if ((read = getdelim(from, &from_size, ':', fd)) == -1) break;
                (*from)[read-1] = 0;
                if ((read = getdelim(to, &to_size, '\n', fd)) == -1) break;
                (*to)[read-1] = 0;

                if (               (query1 && 0 == strcmp(query1, label))
                                || (query2 && 0 == strcmp(query2, label))){
                        free(label);
                        return 1;
                }
        }
        if (label) free(label);
        return 0;
}

int brt_fork_exec_newmap(fork_exec_newmap_t args){
        char *from = NULL;
        char *to = NULL;
        pid_t child = fork();
        if (child) return child;
        if (!brt_parse_subid(args.file, args.query2, args.query1, &from, &to)) exit(127);
        execlp(args.prog, args.prog,
                        args.pid_str, "0", args.id_str, "1",
                        "1", from, to, NULL);
        if (errno == ENOENT) exit(127);
        brt_fatal("execlp");
}


void brt_setup_user_ns(){

        //
        // declare and populate variables
        //

        int setup_report = 0;
        int sig;
        pid_t master_child, uid_child, gid_child;
        siginfo_t uid_child_sinfo, gid_child_sinfo, master_child_sinfo;

        uid_t uid;
        gid_t gid;
        char *uid_str;
        char *gid_str;
        char *pid_str;
        char *username;
        char *groupname;

        uid = getuid();
        gid = getgid();
        if (asprintf(&uid_str, "%d", uid) == -1) brt_fatal("asprintf");
        if (asprintf(&gid_str, "%d", gid) == -1) brt_fatal("asprintf");
        if (asprintf(&pid_str, "%d", getpid()) == -1) brt_fatal("asprintf");
        struct passwd *pw = getpwuid(uid);
        username = pw ? pw->pw_name : NULL;
        struct group *grp = getgrgid(gid);
        groupname = grp ? grp->gr_name : NULL;

        fork_exec_newmap_t map_uid = {
                .prog="newuidmap",
                .id_str=uid_str,
                .file="/etc/subuid",
                .query1=uid_str,
                .query2=username,
                .pid_str=pid_str};

        fork_exec_newmap_t map_gid = {
                .prog="newgidmap",
                .id_str=gid_str,
                .file="/etc/subgid",
                .query1=gid_str,
                .query2=groupname,
                .pid_str=pid_str};

        //
        // prepare signal mask for SIGUSR1
        //
        sigset_t sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGUSR1);
        sigprocmask(SIG_BLOCK, &sigset, NULL);

        //
        // start child, which calls newuidmap/newgidmap on its parent
        //
        if (-1 == (master_child = fork())) brt_fatal("fork");
        if (!master_child){

                // wait for parent's signal
                sigwait(&sigset, &sig);

                // fork then exec newuidmap
                uid_child = brt_fork_exec_newmap(map_uid);

                // fork then exec newgidmap
                gid_child = brt_fork_exec_newmap(map_gid);

                //
                // wait for children
                //
                if (-1 == waitid(P_PID, uid_child, &uid_child_sinfo, WEXITED)) brt_fatal("waitid");
                if (-1 == waitid(P_PID, gid_child, &gid_child_sinfo, WEXITED)) brt_fatal("waitid");

                //
                // combine exit statuses to master exit status
                //
                switch (uid_child_sinfo.si_status){
                        case 0: break;
                        case 127: setup_report |= SETUP_NO_UID; break;
                        default: setup_report |= SETUP_ERROR; break;
                }
                switch (gid_child_sinfo.si_status){
                        case 0: break;
                        case 127: setup_report |= SETUP_NO_GID; break;
                        default: setup_report |= SETUP_ERROR; break;
                }

                //
                // report child status to parent
                //
                exit(setup_report);
               
        }

        //
        // unshare our user namespace, so the child can change it
        //
        if (-1 == unshare(CLONE_NEWUSER)){
                        brt_fatal("could not unshare user namespace");
        }

        //
        // signal child to stop waiting and attempt to call newuidmap/newgidmap
        //
        kill(master_child, SIGUSR1);

        //
        // wait for childs exit status
        //
        if (-1 == waitid(P_PID, master_child, &master_child_sinfo, WEXITED)) brt_fatal("waitid");

        //
        // die if bad child exit status
        //
        if (master_child_sinfo.si_status & SETUP_ERROR){
                brt_fatal("child died badly");
        }

        //
        // fallback to this if newuidmap was unsuccessful
        //
        if (master_child_sinfo.si_status & SETUP_NO_UID){
                if (!brt_printf_file("/proc/self/uid_map", "0 %u 1\n", uid)){
                        brt_fatal("could not open /proc/self/uid_map");
                }
        }

        //
        // fallback to that if newgidmap was unsuccessful
        //
        if (master_child_sinfo.si_status  & SETUP_NO_GID){
                if (!brt_printf_file("/proc/self/setgroups", "deny")){
                        if (errno != ENOENT) 
                                brt_fatal("could not open /proc/self/setgroups");
                };
                if (!brt_printf_file("/proc/self/gid_map", "0 %u 1\n", gid)){
                        brt_fatal("could not open /proc/self/gid_map");
                }
        }


       //
       // free allocated space
       //
       free(uid_str);
       free(gid_str);
       free(pid_str);
}



int main(int argc, char* argv[]) {
	// basename destructs argv[0], that is ok because we overwrite it in
	// every case
	char *binaryname = basename(argv[0]);
        char *rootfs;

        argv[0] = binaryname;
        if (NULL == (rootfs = realpath("/proc/self/exe", NULL)))
            brt_fatal("could not call realpath(\"/proc/self/exe\")");
        if (-1 == asprintf(&rootfs, "%s/rootfs", dirname(rootfs)))
            brt_fatal("asprintf");

        brt_setup_user_ns();
	brt_chroot(rootfs);

        if (-1 == execvp(argv[0], argv))
                brt_fatal("could not exec %s in %s", argv[0], rootfs);
}
