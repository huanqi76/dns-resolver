CC = gcc
CFLAGS = -g -Wall
LDFLAGS = 
LDLIBS = 

main: main.o dns.o

main.o: main.c dns.h

dns.o: dns.c dns.h

.PHONY: clean
clean:
	rm -f *.o main

.PHONY: all
all:
	clean main