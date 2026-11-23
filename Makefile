CC = gcc
CFLAGS = -g -Wall -Wextra
LDFLAGS = 
LDLIBS = 

main: main.o dns.o cache.o

main.o: main.c dns.h

cache.o: cache.o cache.h

dns.o: dns.c dns.h

.PHONY: clean
clean:
	rm -f *.o main

.PHONY: all
all:
	clean main