CC=musl-gcc
CFLAGS=-static

all: bchroot zudo

bchroot: bin/bchroot.c lib/brtlib.c
	$(CC) $(CFLAGS) -o dist/bchroot lib/bchroot.c lib/brtlib.c

zudo: bin/zudo.c lib/brtlib.c
	$(CC) $(CFLAGS) -o dist/zudo lib/zudo.c lib/brtlib.c

clean:
	rm dist/zudo dist/bchroot
