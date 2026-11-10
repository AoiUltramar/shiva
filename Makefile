CC ?= gcc
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Iinclude -D_GNU_SOURCE
SRCS = src/main.c src/cli.c src/llock.c src/resolve.c src/sfilter.c
HDRS = include/cli.h include/llock.h include/resolve.h include/sfilter.h
PREFIX ?= /usr/local

shiva: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS)

test: shiva
	./tests/run.sh

install: shiva
	install -D -m 755 shiva $(DESTDIR)$(PREFIX)/bin/shiva

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/shiva

.PHONY: clean install uninstall test
clean:
	rm -f shiva
