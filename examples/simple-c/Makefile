.PHONY: all
all: example libpatch.so

example:
	gcc -o example example.c

libpatch.so:
	gcc -o libpatch.so libpatch.c -fPIC -shared -I../../c/
