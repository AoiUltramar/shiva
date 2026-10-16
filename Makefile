CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude -D_GNU_SOURCE
SRCS = src/main.c src/cli.c

shiva: $(SRCS) include/cli.h
	$(CC) $(CFLAGS) -o $@ $(SRCS)

.PHONY: clean
clean:
	rm -f shiva
