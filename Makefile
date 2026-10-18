CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude -D_GNU_SOURCE
SRCS = src/main.c src/cli.c src/llock.c

shiva: $(SRCS) include/cli.h include/llock.h
	$(CC) $(CFLAGS) -o $@ $(SRCS)

.PHONY: clean
clean:
	rm -f shiva
