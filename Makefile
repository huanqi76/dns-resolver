CC = gcc
CFLAGS = -g -Wall
LDFLAGS = 
LDLIBS = 

main: main.o

main.o: main.c

.PHONY: clean
clean:
	rm -f *.o main

.PHONY: all
all:
	clean main