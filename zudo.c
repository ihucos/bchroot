#include "brtlib.h"

int main(int argc, char* argv[]) {
	if (argc < 2){
		brt_fatal("usage: zudo CMD1 [CMD2 ...]");
	}
	if (getuid()) brt_setup_user_ns();
	argv++;
	execvp(argv[0], argv);
	brt_fatal("exec %s", argv[0]);
}
