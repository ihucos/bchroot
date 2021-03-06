CC=musl-gcc
CFLAGS=-static -Ilib

all: bchroot zudo

bchroot: bin/bchroot.c lib/brtlib.c
	$(CC) $(CFLAGS) -o dist/bchroot bin/bchroot.c lib/brtlib.c

zudo: bin/zudo.c lib/brtlib.c
	$(CC) $(CFLAGS) -o dist/zudo bin/zudo.c lib/brtlib.c

clean:
	rm -rf dist/zudo dist/bchroot build

swig:
	swig -python lib/brtlib.i
