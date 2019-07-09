#define _GNU_SOURCE
#include "brtlib.h"


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
	brt_setup_mount_propagation();
	for(i = 0; i < sizeof(mounts) / sizeof(char*); i++){
                brt_bind_mount(mounts[i]+1, mounts[i]);
	}

	chroot("."
	      ) != -1 || brt_fatal("could not chroot to %s/rootfs",
	                           get_current_dir_name());

	/* chdir back or fallback to / */
	if (-1 == chdir(origpwd)){
		if (-1 == chdir("/"))
			brt_fatal("chdir(\"/\")");
	}

	putenv("PATH=" PRESET_PATH);
	brt_whitelist_env("TERM");
	brt_whitelist_env("DISPLAY");
	brt_whitelist_env("HOME");
	brt_whitelist_env("PATH");
	brt_whitelist_env(NULL);
	brt_whitelist_envs_from_env("BCHROOT_EXPORT");

	/* exec away */
	argv[0] = program_invocation_short_name;
	execvp(argv[0], argv
		) != -1 || brt_fatal("chroot %s/rootfs %s", rootfs, argv[0]);
}
