CC=musl-gcc
CFLAGS=-static
bchroot: bchroot.c
	$(CC) $(CFLAGS) -o bchroot bchroot.c
