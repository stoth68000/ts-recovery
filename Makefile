
CFLAGS = -I../ltntstools-build-environment/target-root/usr/include
LIBS = -L../ltntstools-build-environment/target-root/usr/lib -lltntstools -ldvbpsi

all:	ts-combiner

ts-combiner:	ts-combiner.c
	gcc -g -Wall -std=c11 $(CFLAGS) $(@).c -o $(@) $(LIBS)

clean:
	rm -f ts-combiner
