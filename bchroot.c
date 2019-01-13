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
#include "brtlib.c"


#define PRESET_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


int main(int argc, char* argv[]) {
	char i,
	     *token,
	     *str,
	     *progpath = realpath("/proc/self/exe", NULL),
	     *origpwd = get_current_dir_name(),
	     *rootfs = dirname(strdup(progpath)), // FIXME: check for no memory error
	     *mounts[] = {
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
	if (getuid()) brt_setup_user_ns();

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
		) != -1 || brt_fatal("chroot %s/rootfs %s", rootfs, argv[0]);
}
