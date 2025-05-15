# Makefile for GOT injection demo
CC = gcc
CFLAGS = -Wall -Wextra

all: target hook.so injector

target: target.c
	$(CC) $(CFLAGS) target.c -o target -no-pie -fno-pie

hook.so: hook.c
	$(CC) $(CFLAGS) -shared -fPIC hook.c -o hook.so -ldl

injector: injector.c
	$(CC) $(CFLAGS) injector.c -o injector -ldl

clean:
	rm -f target hook.so injector

.PHONY: all clean