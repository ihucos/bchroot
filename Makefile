CC=musl-gcc
CFLAGS=-static

all: bchroot zudo

bchroot: bchroot.c brtlib.c
	$(CC) $(CFLAGS) -o bchroot bchroot.c brtlib.c

zudo: zudo.c brtlib.c
	$(CC) $(CFLAGS) -o zudo zudo.c brtlib.c

clean:
	rm zudo bchroot
