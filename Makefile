# Makefile for GOT injection demo
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -ldl

all: target hook.so injector analyze_got direct_injector

target: target.c
	$(CC) $(CFLAGS) target.c -o target -no-pie -fno-pie

hook.so: hook.c
	$(CC) $(CFLAGS) -shared -fPIC hook.c -o hook.so $(LDFLAGS)

injector: injector.c
	$(CC) $(CFLAGS) injector.c -o injector $(LDFLAGS)

analyze_got: analyze_got.c
	$(CC) $(CFLAGS) analyze_got.c -o analyze_got $(LDFLAGS)

direct_injector: direct_injector.c
	$(CC) $(CFLAGS) direct_injector.c -o direct_injector $(LDFLAGS)

run: target
	./target

debug: target
	gdb ./target

analyze: analyze_got
	./analyze_got

clean:
	rm -f target hook.so injector analyze_got direct_injector

.PHONY: all clean run debug analyze