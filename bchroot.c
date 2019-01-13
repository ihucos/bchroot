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


#define PRESET_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


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


int brt_printf_to_file(const char *file, const char *format, ...){
	FILE *fd;
	if (! (fd = fopen(file, "w")))
		return 0;
	va_list args;
	va_start(args, format);
	vfprintf(fd, format, args) >= 0 || brt_fatal("vfprintf %s", file);
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
	else {
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


int brt_parse_subid(
		    const char *file,
		    const char *query1,
		    const char *query2,
		    char **from,
		    char **to) {
	FILE *fd;
	size_t read, user_size = 0, from_size = 0, to_size = 0;
	char *label = NULL;
	// try to open file
	if (! (fd = fopen(file, "r"))){
		errno = 0;
		return 0;
	}
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
	if (!brt_parse_subid(args.file, args.query2, args.query1, &from, &to))
		exit(127);
	execlp(args.prog, args.prog,
	       args.pid_str, "0", args.id_str, "1",
	       "1", from, to, NULL);
	if (errno == ENOENT) exit(127);
	brt_fatal("execlp");
}


void brt_setup_user_ns(){

	int setup_report = 0;
	int sig;
	pid_t master_child,
	      uid_child,
	      gid_child;
	siginfo_t uid_child_sinfo,
	          gid_child_sinfo,
		  master_child_sinfo;

	uid_t uid;
	gid_t gid;
	char *uid_str;
	char *gid_str;
	char *pid_str;
	char *username;
	char *groupname;

	uid = getuid();
	gid = getgid();
	asprintf(&uid_str, "%u", uid
	        ) != -1 || brt_fatal("asprintf");
	asprintf(&gid_str, "%u", gid
	        ) != -1 || brt_fatal("asprintf");
	asprintf(&pid_str, "%u", getpid()
	        ) != -1 || brt_fatal("asprintf");
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

	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGUSR1);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	(master_child = fork()) != -1 || brt_fatal("fork");
	if (!master_child){

		// wait for parent's signal
		sigwait(&sigset, &sig);

		uid_child = brt_fork_exec_newmap(map_uid);
		gid_child = brt_fork_exec_newmap(map_gid);

		waitid(P_PID, uid_child, &uid_child_sinfo, WEXITED
		      ) != -1 || brt_fatal("waitid");
		waitid(P_PID, gid_child, &gid_child_sinfo, WEXITED
		      ) != -1 || brt_fatal("waitid");

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

		exit(setup_report);
	}

	unshare(CLONE_NEWUSER
	       ) != -1 || brt_fatal("could not unshare user namespace");

	kill(master_child, SIGUSR1);
	waitid(P_PID, master_child, &master_child_sinfo, WEXITED
	      ) != -1 || brt_fatal("waitid");

	if (master_child_sinfo.si_status & SETUP_ERROR){
		brt_fatal("child died badly");
	}
	if (master_child_sinfo.si_status & SETUP_NO_UID){
		brt_printf_to_file("/proc/self/uid_map", "0 %s 1\n", uid_str
		                  ) || brt_fatal("write /proc/self/uid_map");
	}
	if (master_child_sinfo.si_status & SETUP_NO_GID){
		if (!brt_printf_to_file("/proc/self/setgroups", "deny")){
			/* ignore file does not exist, as this happens in older
			* kernels*/
			if (errno != ENOENT)
				brt_fatal("write /proc/self/setgroups");
		};
		brt_printf_to_file("/proc/self/gid_map", "0 %s 1\n", gid_str
		                  ) || brt_fatal("write /proc/self/gid_map");
	}
	free(uid_str);
	free(gid_str);
	free(pid_str);
}


int main(int argc, char* argv[]) {
	char i;
	char *token,
	     *str,
	     *progpath = realpath("/proc/self/exe", NULL),
	     *origpwd = get_current_dir_name(),
	     *rootfs = dirname(strdup(progpath)); // FIXME: check for no memory error
	     char *mounts[] = {
	             "./dev",
		     "./home",
		     "./proc",
		     "./root",
		     "./sys",
		     "./tmp",
		     "./etc/resolv.conf"
		};

	if (!progpath) brt_fatal("realpath");
	if (!origpwd)  brt_fatal("get_current_dir_name");

	chdir(rootfs
	     ) != -1 || brt_fatal("cd %s", rootfs);
	chdir("./rootfs"
	     ) != -1 || brt_fatal("cd %s/rootfs", rootfs);

	/* give us "fake root" */
	brt_setup_user_ns();

	unshare(CLONE_NEWNS
	       ) != -1 || brt_fatal("unshare(CLONE_NEWNS)");

	/* mount stuff */
	if (-1 == mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL))
		if (errno != EINVAL){
			brt_fatal("could not change propagation of /");
		} else {
			errno = 0;
		}
	for(i = 0; i < sizeof(mounts) / sizeof(char*); i++){
		if (0 < mount(mounts[i]+1, mounts[i], "none",
		                MS_MGC_VAL|MS_BIND|MS_REC, NULL)){
			if (errno != ENOENT){
				brt_fatal("rbind %s to %s%s",
				          mounts[i]+1, origpwd, mounts[i]+1);
			}
		}
	}

	chroot("."
	      ) != -1 || brt_fatal("could not chroot to %s/rootfs",
	                           get_current_dir_name());

	/* chdir back or fallback to / */
	if (-1 == chdir(origpwd)){
		if (-1 == chdir("/"))
			brt_fatal("chdir(\"/\")");
	}

	/* setup environment fo exec */
	if (str = getenv("BCHROOT_EXPORT")) {
		str = strdup(str);
		token = strtok(str, ":");
		while(token){
			brt_whitelist_env(token);
			token = strtok(NULL, ":");
		}
		free(str);
	}
	putenv("PATH=" PRESET_PATH);
	brt_whitelist_env("TERM");
	brt_whitelist_env("DISPLAY");
	brt_whitelist_env("HOME");
	brt_whitelist_env("PATH");
	brt_whitelist_env(NULL);

	/* exec away */
	argv[0] = program_invocation_short_name;
	execvp(argv[0], argv
		) != -1 || brt_fatal("could not exec %s in %s", argv[0], rootfs);
}
