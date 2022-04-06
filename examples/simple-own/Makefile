.PHONY: all
all: example libpatch.so

example: example.c
	gcc -o example example.c

libpatch.so: libpatch.c
	gcc -o libpatch.so libpatch.c -fPIC -shared -I../../c/
