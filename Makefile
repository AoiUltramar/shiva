CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude -D_GNU_SOURCE
SRCS = src/main.c src/cli.c src/llock.c src/resolve.c
PREFIX ?= /usr/local

shiva: $(SRCS) include/cli.h include/llock.h include/resolve.h
	$(CC) $(CFLAGS) -o $@ $(SRCS)

install: shiva
	install -D -m 755 shiva $(DESTDIR)$(PREFIX)/bin/shiva

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/shiva

.PHONY: clean install uninstall
clean:
	rm -f shiva
