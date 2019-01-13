#include "brtlib.c"

int main(int argc, char* argv[]) {
	if (argc < 2){
		brt_fatal("usage: zudo CMD1 [CMD2 ...]");
	}
	brt_setup_user_ns();
	argv++;
	execvp(argv[0], argv);
	brt_fatal("exec %s", argv[0]);
}
